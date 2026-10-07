//! The existing daemon verification and deletion engine, with backup v2.
use super::*;
use envcloak_ipc::proto::{
    BackupBeginParams, BackupPlanFile, VerifyEntry, VerifyFile, VerifyParams,
};
use envcloak_ipc::view::EntryStatus;
use envcloak_scan::first_run::{backup_chunks, comment_assignments};
use envcloak_scan::{DeleteGate, DeleteStep, Remains, delete_plaintext};
use std::os::unix::fs::MetadataExt;

struct Selection {
    index: usize,
    name: String,
    slug: String,
    reference: String,
}
struct Cleanup<'a> {
    root: &'a ScanRoot,
    path: &'a Path,
    bytes: SecretBytes,
    stamp: FileStamp,
    findings: Vec<Found>,
    selected: Vec<Selection>,
    manifest: PathBuf,
    profile: Option<String>,
    after: SecretBytes,
    backup: Option<String>,
}
enum CleanupRefusal {
    Local(&'static str),
    Remote(Failure),
}
impl CleanupRefusal {
    fn reason(&self) -> &str {
        match self {
            Self::Local(reason) => reason,
            Self::Remote(remote) => remote.token(),
        }
    }
}
impl From<Failure> for CleanupRefusal {
    fn from(remote: Failure) -> Self {
        Self::Remote(remote)
    }
}
impl From<envcloak_ipc::ClientError> for CleanupRefusal {
    fn from(error: envcloak_ipc::ClientError) -> Self {
        Self::Remote(error.into())
    }
}
impl DeleteGate for Cleanup<'_> {
    type Refusal = CleanupRefusal;
    fn verify(&mut self) -> Result<(), CleanupRefusal> {
        let (bytes, stamp) = read_capped(self.root, self.path, MAX_DOTENV)
            .map_err(|_| cleanup_refusal("changed"))?;
        if stamp != self.stamp || !bytes.ct_eq_secret(&self.bytes) {
            return Err(cleanup_refusal("changed"));
        }
        let entries = self
            .selected
            .iter()
            .map(|s| {
                let value = self.findings[s.index]
                    .value
                    .as_ref()
                    .ok_or_else(|| cleanup_refusal("manual_assignment"))?;
                Ok(VerifyEntry {
                    line: s.index as u32 + 1,
                    name: s.name.clone(),
                    value: WireSecret::new(secret_copy(value)),
                })
            })
            .collect::<Result<Vec<_>, CleanupRefusal>>()?;
        let v = connect()?.import_verify(&VerifyParams {
            manifest: self.manifest.to_string_lossy().into_owned(),
            files: vec![VerifyFile {
                file: self.path.to_string_lossy().into_owned(),
                profile: self.profile.clone(),
                entries,
            }],
            claims: claims(),
        })?;
        if !v.recovery_confirmed {
            return Err(cleanup_refusal("recovery_kit_unconfirmed"));
        }
        if !v.resolves {
            return Err(cleanup_refusal("unresolved_reference"));
        }
        if v.files.len() != 1
            || !v.files[0].covered
            || v.files[0].entries.len() != self.selected.len()
            || v.files[0]
                .entries
                .iter()
                .zip(&self.selected)
                .any(|(e, s)| e.status != EntryStatus::Stored || e.line != s.index as u32 + 1)
        {
            return Err(cleanup_refusal("not_imported"));
        }
        Ok(())
    }
    fn remains(&self, _: usize) -> Remains {
        Remains::Bytes(secret_copy(&self.after))
    }
    fn backup(&mut self, _: &[usize]) -> Result<String, CleanupRefusal> {
        let path = self.root.path().join(self.path);
        let begin = connect()?.backup_v2_begin(&BackupBeginParams {
            purpose: "init".into(),
            files: vec![BackupPlanFile {
                path: path.to_string_lossy().into_owned(),
                size: self.bytes.len() as u64,
                mode: self.stamp.mode & 0o7777,
            }],
            claims: claims(),
        })?;
        if begin.chunk_size as usize != envcloak_core::file_backup_v2::CHUNK_V2 {
            return Err(cleanup_refusal("backup_failed"));
        }
        for (i, chunk) in backup_chunks(&self.bytes, begin.chunk_size as usize)
            .into_iter()
            .enumerate()
        {
            connect()?.backup_v2_put(&begin.id, 0, i as u32, chunk)?;
        }
        connect()?.backup_v2_commit(&begin.id)?;
        self.backup = Some(begin.id.clone());
        Ok(begin.id)
    }
}
fn cleanup_refusal(reason: &'static str) -> CleanupRefusal {
    CleanupRefusal::Local(reason)
}

fn copy_found(f: &Found) -> Found {
    Found {
        name: secret_copy(&f.name),
        value: f.value.as_ref().map(secret_copy),
        disposition: f.disposition,
        env_file: f.env_file,
        range: f.range.clone(),
        single_complete_line: f.single_complete_line,
        source: f.source.clone(),
        stamp: f.stamp,
    }
}

pub(super) fn run(
    groups: &[Group],
    machine: &[MachineEntry],
    plan: &ImportPlanView,
    r: &mut FirstRunReport,
) -> Result<(), Failure> {
    let mut files: BTreeMap<PathBuf, Vec<&MachineEntry>> = BTreeMap::new();
    for m in machine {
        if m.kind != MachineSource::McpConfig {
            files
                .entry(m.found.source.path.clone())
                .or_default()
                .push(m);
        }
    }
    for (path, entries) in files {
        let Some(g) = groups.iter().find(|g| path.starts_with(g.root.path())) else {
            r.fail(&path, "profile", "outside_root");
            continue;
        };
        let rel = path
            .strip_prefix(g.root.path())
            .map_err(|_| Failure::new("scan_root", "the source is outside its scan root"))?;
        let findings = entries
            .iter()
            .map(|m| copy_found(&m.found))
            .collect::<Vec<_>>();
        let selected = entries
            .iter()
            .enumerate()
            .filter_map(|(index, m)| {
                if !m.found.single_complete_line {
                    return None;
                }
                let item = plan
                    .items
                    .get(m.sent.and_then(|i| plan.entries.get(i))?.item? as usize)?;
                Some(Selection {
                    index,
                    name: assignment_name(&m.found)?,
                    slug: item.slug.clone(),
                    reference: item.reference.clone(),
                })
            })
            .collect::<Vec<_>>();
        if selected.is_empty() {
            continue;
        }
        let source_kind = kind(entries[0].kind);
        clean(&g.root, rel, findings, selected, None, None, source_kind, r)?;
    }
    for g in groups {
        for project in &g.projects {
            let directory = dir_of(&g.root, &project.rel_dir);
            let root = envcloak_scan::sources::absolute_root(&directory)
                .map_err(|_| Failure::new("scan_root", "the project changed during cleanup"))?;
            match super::super::super::init::delete(&root) {
                Ok((report, error)) => {
                    if let Some(id) = report.backup {
                        r.backups.push(id);
                    }
                    for kept in report.kept.iter().chain(&report.skipped) {
                        r.fail(&directory.join(&kept.path), "dotenv", &kept.reason);
                    }
                    if let Some(error) = error {
                        r.fail(&directory, "dotenv", error.token());
                    }
                }
                Err(error) => r.fail(&directory, "dotenv", error.token()),
            }
        }
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
fn clean(
    root: &ScanRoot,
    rel: &Path,
    findings: Vec<Found>,
    selected: Vec<Selection>,
    manifest: Option<PathBuf>,
    profile: Option<String>,
    source_kind: &str,
    r: &mut FirstRunReport,
) -> Result<(), Failure> {
    let path = root.path().join(rel);
    let selected_names = selected.iter().map(|s| s.name.clone()).collect::<Vec<_>>();
    let mut rewritten = false;
    let result = (|| -> Result<(), CleanupRefusal> {
        // The private manifest name must not hold a value or unsafe path text.
        if !rel.file_name().and_then(OsStr::to_str).is_some_and(|name| {
            name.len() <= 128
                && !looks_like_value(name)
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        }) {
            return Err(cleanup_refusal("unsafe_source_name"));
        }
        let (bytes, stamp) =
            read_capped(root, rel, MAX_DOTENV).map_err(|_| cleanup_refusal("changed"))?;
        if findings.iter().any(|f| f.stamp != Some(stamp)) {
            return Err(cleanup_refusal("changed"));
        }
        envcloak_scan::atomic::check_modifiable(root, rel, &stamp)
            .map_err(|e| cleanup_refusal(e.token()))?;
        let selection = selected
            .iter()
            .map(|s| (s.index, s.slug.as_str()))
            .collect::<Vec<_>>();
        let after = if source_kind == "dotenv" {
            envcloak_scan::without_entries(
                &bytes,
                &selected
                    .iter()
                    .map(|s| {
                        findings[s.index].range.start as usize..findings[s.index].range.end as usize
                    })
                    .collect::<Vec<_>>(),
            )
        } else {
            comment_assignments(&bytes, &findings, &selection).map_err(cleanup_refusal)?
        };
        // Slug comments can be longer than short assignments. Keep the file
        // when the result would exceed the read bound used by undo.
        if after.len() > MAX_DOTENV {
            return Err(cleanup_refusal("too_large"));
        }
        let parent = rel.parent().unwrap_or(Path::new(""));
        let manifest = match manifest {
            Some(m) => m,
            None => {
                let mut bindings = BTreeMap::new();
                for s in &selected {
                    let name =
                        EnvName::new(&s.name).map_err(|_| cleanup_refusal("invalid_name"))?;
                    if bindings
                        .insert(name, s.reference.clone())
                        .is_some_and(|prior| prior != s.reference)
                    {
                        return Err(cleanup_refusal("ambiguous_assignment"));
                    }
                }
                let text = new_manifest("imported-profile", &[(None, bindings)].into());
                let directory = format!(".envcloak-import-{}", project_name(rel));
                let (held, _) = root
                    .open_parent(rel)
                    .map_err(|_| cleanup_refusal("cleanup_manifest_refused"))?;
                match envcloak_sys::create_dir_beneath(&held, OsStr::new(&directory), 0o700) {
                    Ok(()) => held
                        .sync_all()
                        .map_err(|_| cleanup_refusal("cleanup_manifest_refused"))?,
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
                    Err(_) => return Err(cleanup_refusal("cleanup_manifest_refused")),
                }
                let directory_handle =
                    envcloak_sys::open_dir_beneath(&held, OsStr::new(&directory))
                        .map_err(|_| cleanup_refusal("cleanup_manifest_refused"))?;
                let metadata = directory_handle
                    .metadata()
                    .map_err(|_| cleanup_refusal("cleanup_manifest_refused"))?;
                if metadata.uid()
                    != root
                        .dir()
                        .metadata()
                        .map_err(|_| cleanup_refusal("cleanup_manifest_refused"))?
                        .uid()
                    || metadata.mode() & 0o077 != 0
                {
                    return Err(cleanup_refusal("cleanup_manifest_refused"));
                }
                let manifest = parent.join(&directory).join(MANIFEST_NAME);
                match read_plain(root, &manifest, 64 << 10) {
                    Ok((prior, _)) if prior == text.as_bytes() => (),
                    Err(e) if e.kind == envcloak_scan::ScanErrorKind::NotFound => {
                        create_atomically(root, &manifest, text.as_bytes(), 0o600)
                            .map_err(|_| cleanup_refusal("cleanup_manifest_refused"))?;
                    }
                    _ => {
                        r.source(&path, source_kind)["manual"] = json!(format!(
                            "Move the private manifest directory aside: {}. Keep its manifest and update earlier envcloak run commands to use the moved manifest, then rerun import.",
                            display_path(&root.path().join(parent).join(&directory))
                        ));
                        return Err(cleanup_refusal("cleanup_manifest_changed"));
                    }
                }
                root.path().join(manifest)
            }
        };
        let mut gate = Cleanup {
            root,
            path: rel,
            bytes,
            stamp,
            findings,
            selected,
            manifest: manifest.clone(),
            profile,
            after,
            backup: None,
        };
        // Authority is rechecked on both sides of the encrypted backup.
        gate.verify()?;
        let result = delete_plaintext(
            root,
            &[(rel.to_path_buf(), stamp)],
            &mut gate,
            &mut |step| {
                pause_point(match step {
                    DeleteStep::Verified => "first_run_verified",
                    DeleteStep::BackedUp => "first_run_backed_up",
                    DeleteStep::Reverified => "first_run_reverified",
                    DeleteStep::Staged(_) => "first_run_staged",
                    DeleteStep::Swapped(_) => "first_run_swapped",
                    DeleteStep::Rewritten(_) => "first_run_rewritten",
                    _ => "first_run_removed",
                })
            },
        );
        if let Some(id) = &gate.backup {
            r.backups.push(id.clone());
        }
        let done = result?;
        rewritten = !done.rewritten.is_empty();
        for (kept, reason) in &done.kept {
            r.fail(&root.path().join(kept), source_kind, reason.token());
            if !rewritten {
                for name in &selected_names {
                    r.keep(&path, source_kind, Some(name), reason.token());
                }
            }
        }
        if rewritten {
            r.source(&path, source_kind)["cleanup"] = json!("rewritten");
            r.source(&path, source_kind)["replacement"] = json!(format!(
                "envcloak run --manifest '{}' -- <command>",
                display_path(&manifest).replace('\'', "'\\''")
            ));
            let id = gate
                .backup
                .as_deref()
                .ok_or_else(|| cleanup_refusal("backup_failed"))?;
            connect()?.backup_v2_record_result(id, 0, &gate.after.sha256())?;
            r.source(&path, source_kind)["receipt"] = json!("confirmed");
            pause_point("first_run_recorded");
        }
        Ok(())
    })();
    if let Err(error) = result {
        if rewritten {
            r.incomplete.insert("backup_receipt_unconfirmed".into());
            r.source(&path, source_kind)["receipt"] = json!("unconfirmed");
            r.source(&path, source_kind)["receipt_reason"] = json!(error.reason());
        } else {
            r.fail(&path, source_kind, error.reason());
            for name in &selected_names {
                r.keep(&path, source_kind, Some(name), error.reason());
            }
        }
    }
    Ok(())
}
