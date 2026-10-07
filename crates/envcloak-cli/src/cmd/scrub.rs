//! Local transcript hygiene with encrypted backup v2 and proof-bound undo.
use envcloak_agents::locations::Locations;
use envcloak_client::claims::{claims, refuse_if_claimed};
use envcloak_client::connect::connect;
use envcloak_client::doctor_report::{DoctorReport, display_path};
use envcloak_client::fail::{FAILURE, Failure, refuse_if_traced, usage};
use envcloak_client::tty::{Terminal, read_secret_fd};
use envcloak_core::{SecretBuf, SecretBytes};
use envcloak_ipc::WireSecret;
use envcloak_ipc::proto::FileLeft;
use envcloak_ipc::proto::{
    BackupBeginParams, BackupPlanFile, CandidateForm, ExposedItem, MarkExposedParams,
    ScanCandidate, ScanMatchParams, ScanPurpose, ScanSource,
};
use envcloak_ipc::view::ExposureSourceView;
use envcloak_scan::candidates::{Budget, Candidate, Candidates, DistinctCandidate, Form};
use envcloak_scan::first_run::secret_copy;
use envcloak_scan::scrub::{self, Match, OpenFile};
use envcloak_scan::source::{ConfigFormat, ConfigSource, SourceKind};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "envcloak scrub [--path <path>]... [--yes] [--json] | --undo <ID> [--created-by-agent] [--unrecorded] [--passphrase-fd N] [--json]";
const LIMITS: &str = "Rotate exposed values first. Scrub rewrites local files only. Short values are neither found nor scrubbed, except registry-recognized values. SQLite stores are not scrubbed. Scrub cannot remove copies sent to model providers, cloud-synced transcripts, Time Machine backups or APFS snapshots, other machines, terminal scrollback, Spotlight's index, crash reports, or a running agent's context. Quit the agent first for recent, open or linked files.";
#[derive(Default)]
struct Options {
    paths: Vec<PathBuf>,
    yes: bool,
    json: bool,
    undo: Option<String>,
    agent: bool,
    unrecorded: bool,
    fd: Option<i32>,
}
fn options(args: &[&str]) -> Result<Options, ()> {
    let mut o = Options::default();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match *arg {
            "--path" if o.paths.len() < 64 => {
                let p = it
                    .next()
                    .filter(|s| !s.is_empty() && !s.starts_with("--"))
                    .ok_or(())?;
                o.paths.push(PathBuf::from(p));
            }
            "--yes" if !o.yes => o.yes = true,
            "--json" if !o.json => o.json = true,
            "--undo" if o.undo.is_none() => {
                o.undo = Some(it.next().ok_or(())?.to_string());
            }
            "--created-by-agent" if !o.agent => o.agent = true,
            "--unrecorded" if !o.unrecorded => o.unrecorded = true,
            "--passphrase-fd" if o.fd.is_none() => {
                o.fd = Some(it.next().ok_or(())?.parse().map_err(|_| ())?);
            }
            _ => return Err(()),
        }
    }
    if o.undo.is_some() {
        if o.yes || !o.paths.is_empty() {
            return Err(());
        }
    } else if o.agent || o.unrecorded || o.fd.is_some() {
        return Err(());
    }
    if o.fd.is_some_and(|fd| fd < 0) {
        return Err(());
    }
    Ok(o)
}
pub fn run(args: &[&str]) -> ExitCode {
    let o = match options(args) {
        Ok(o) => o,
        Err(()) => return usage(USAGE),
    };
    let result = refuse_if_traced().and_then(|()| {
        if let Some(id) = &o.undo {
            undo(id, &o)
        } else {
            execute(&o)
        }
    });
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(FAILURE),
        Err(e) => e.report(FAILURE),
    }
}
// The scanner's reasons become CLI tokens only through this fixed vocabulary.
// Unknown reasons still fail without echoing unregistered or input-derived text.
fn fail(reason: &'static str) -> Failure {
    Failure::new(
        match reason {
            "aside_changed" => "aside_changed",
            "backup_failed" => "backup_failed",
            "backup_unread" => "backup_unread",
            "binding" => "binding",
            "bounds" => "bounds",
            "cancelled" => "cancelled",
            "candidate_too_large" => "candidate_too_large",
            "changed" => "changed",
            "edited_since" => "edited_since",
            "exists" => "exists",
            "hard_linked" => "hard_linked",
            "incomplete" => "incomplete",
            "invalid_home" => "invalid_home",
            "invalid_json" => "invalid_json",
            "invalid_path" => "invalid_path",
            "invalid_response" => "invalid_response",
            "invalid_slug" => "invalid_slug",
            "invalid_text" => "invalid_text",
            "io" => "io",
            "items_changed" => "items_changed",
            "leftover" => "leftover",
            "limited" => "limited",
            "line_too_large" => "line_too_large",
            "mount_point" => "mount_point",
            "moved_aside" => "moved_aside",
            "no_such_backup" => "no_such_backup",
            "no_terminal" => "no_terminal",
            "not_a_profile_name" => "not_a_profile_name",
            "not_found" => "not_found",
            "not_owned" => "not_owned",
            "not_regular" => "not_regular",
            "not_removed" => "not_removed",
            "open_elsewhere" => "open_elsewhere",
            "overlap" => "overlap",
            "recently_changed" => "recently_changed",
            "refused" => "refused",
            "restore_refused" => "restore_refused",
            "result_unrecorded" => "result_unrecorded",
            "scan_failed" => "scan_failed",
            "statement_changed" => "statement_changed",
            "swap_unsupported" => "swap_unsupported",
            "symlink" => "symlink",
            "too_deep" => "too_deep",
            "too_large" => "too_large",
            "too_many_entries" => "too_many_entries",
            "unchecked" => "unchecked",
            "unreadable" => "unreadable",
            "unsupported" => "unsupported",
            "write_failed" => "write_failed",
            _ => "incomplete",
        },
        "scrub did not complete; the file was kept or its backup needs recovery",
    )
}
fn format_for(path: &Path, sources: &[ConfigSource]) -> ConfigFormat {
    if path.extension().is_some_and(|e| e == "jsonl") {
        return ConfigFormat::Jsonl;
    }
    if path.extension().is_some_and(|e| e == "json") {
        return ConfigFormat::Json;
    }
    sources
        .iter()
        .filter(|s| path == s.path || path.starts_with(&s.path))
        .find(|s| s.format == ConfigFormat::Json)
        .map_or(ConfigFormat::Mixed, |s| s.format)
}
fn execute(o: &Options) -> Result<bool, Failure> {
    let locations = Locations::from_env().map_err(|_| fail("invalid_home"))?;
    super::require_unlocked(&mut connect()?)?;
    let mut catalog = locations.transcript_sources();
    catalog.extend(locations.config_sources().into_iter().filter(|s| {
        matches!(
            s.source_kind,
            SourceKind::HostBackup | SourceKind::Credentials
        )
    }));
    let mut sources = if o.paths.is_empty() {
        catalog.clone()
    } else {
        catalog
            .iter()
            .filter(|s| {
                matches!(
                    s.source_kind,
                    SourceKind::Credentials | SourceKind::Database
                )
            })
            .cloned()
            .collect()
    };
    let cwd = std::env::current_dir().map_err(|_| fail("io"))?;
    for p in &o.paths {
        let path = if p.is_absolute() {
            p.clone()
        } else {
            cwd.join(p)
        };
        sources.push(ConfigSource {
            format: format_for(&path, &catalog),
            path,
            source_kind: SourceKind::Transcript,
            label: "scrub path".into(),
            names: None,
        });
    }
    let budget = Budget::default();
    let mut candidates = Candidates::new(budget).map_err(|_| fail("io"))?;
    let scan = envcloak_scan::transcript::scan_transcript_sources(&sources, budget, &mut |c| {
        candidates.insert(c)
    })
    .map_err(|_| fail("scan_failed"))?;
    let limited = candidates.limited();
    let entries = candidates.into_entries();
    let occurrences: Vec<_> = entries
        .iter()
        .flat_map(|e| {
            e.occurrences.iter().map(|o| Candidate {
                id: e.id,
                value: SecretBytes::copy_from(&[]),
                form: e.form,
                occurrence: o.clone(),
            })
        })
        .collect();
    let refs: Vec<_> = occurrences.iter().collect();
    let compare_entries: Vec<_> = entries.iter().collect();
    let matches = compare(&compare_entries)?;
    let mut plan = scrub::plan(&refs, &matches);
    let mut report = DoctorReport::default();
    for issue in &scan.issues {
        report.note(&issue.source.path, issue.reason, true);
    }
    for note in &scan.notes {
        report.note(&note.source.path, note.reason, true);
    }
    for p in &o.paths {
        let p = if p.is_absolute() {
            p.clone()
        } else {
            cwd.join(p)
        };
        if std::fs::symlink_metadata(&p).is_err() {
            report.note(&p, "not_found", true);
        }
    }
    if limited {
        report.fail("limited");
    }
    // Incomplete enumeration can hide an overlapping or encoded occurrence.
    for f in &mut plan.files {
        if limited
            || scan
                .issues
                .iter()
                .any(|i| f.path.starts_with(&i.source.path) || i.source.path.starts_with(&f.path))
        {
            f.refuse("incomplete");
        }
    }
    let items = connect()?.items_list(false)?.items;
    for f in &plan.files {
        for e in &f.edits {
            let item = items.iter().find(|i| i.id == e.item);
            report.item(
                &e.slug,
                item.and_then(|i| i.provider.as_deref()),
                &f.path,
                1,
            );
        }
    }
    // Show rotation destinations before asking to rewrite. JSON retains them
    // in the final report without mixing human text into stdout.
    if !o.json {
        print!("{}\n{}", LIMITS, report.human());
    }
    if !o.yes && !plan.files.is_empty() {
        let mut t = Terminal::open().map_err(|_| {
            Failure::new(
                "confirmation_required",
                "review with doctor, then run scrub --yes",
            )
        })?;
        t.say(LIMITS)?;
        t.say(&report.human())?;
        if !t
            .read_secret("Type yes to scrub the listed files: ")?
            .ct_eq(b"yes")
        {
            return Err(fail("cancelled"));
        }
    }
    envcloak_scan::pause_point("scrub_confirmed");
    let current = compare(&compare_entries)?;
    // Rebuild associations after the confirmation wait. Changed matches or
    // slugs invalidate the displayed plan instead of silently choosing new edits.
    let fresh = scrub::plan(&refs, &current);
    let mut files = Vec::new();
    for f in &plan.files {
        let mut row = json!({"display_path": display_path(&f.path), "state": "refused", "backup": null, "reason": null});
        let changed = fresh
            .files
            .iter()
            .find(|p| p.path == f.path)
            .is_none_or(|p| p.edits != f.edits || p.stamp != f.stamp);
        let result = if changed {
            Err(fail("items_changed"))
        } else if let Some(reason) = f.reasons.first() {
            Err(fail(reason))
        } else {
            apply_file(f, format_for(&f.path, &sources), &mut row, &compare_entries)
        };
        match result {
            Ok(()) => row["state"] = json!("scrubbed"),
            Err(e) => {
                row["reason"] = json!(e.token());
                report.fail("incomplete");
            }
        }
        files.push(row);
    }
    let mut after_scan = scrub::inspect_leftovers(&sources);
    for issue in &after_scan.issues {
        report.note(&issue.source.path, issue.reason, true);
    }
    after_scan.leftovers.extend(scan.leftovers);
    after_scan
        .leftovers
        .sort_by(|a, b| a.source.path.cmp(&b.source.path));
    after_scan
        .leftovers
        .dedup_by(|a, b| a.source.path == b.source.path);
    let leftovers: Vec<_> = after_scan
        .leftovers
        .iter()
        .map(|l| json!({"display_path": display_path(&l.source.path), "reason": l.inspection}))
        .collect();
    output(o, &files, &report, &leftovers);
    Ok(report.complete())
}
fn compare(entries: &[&DistinctCandidate]) -> Result<Vec<Match>, Failure> {
    let mut answer = Vec::new();
    let mut start = 0;
    while start < entries.len() {
        let mut batch = Vec::new();
        let mut bytes = 0;
        while start < entries.len() && batch.len() < envcloak_ipc::proto::MAX_SCAN_CANDIDATES {
            let c = &entries[start];
            if c.value.len() > 4096 {
                return Err(fail("candidate_too_large"));
            }
            if bytes + c.value.len() > 256 * 1024 {
                break;
            }
            bytes += c.value.len();
            start += 1;
            batch.push(ScanCandidate {
                id: u32::try_from(c.id).map_err(|_| fail("limited"))?,
                value: WireSecret::new(secret_copy(&c.value)),
                form: match c.form {
                    Form::Raw => CandidateForm::Raw,
                    Form::UrlPassword => CandidateForm::UrlPassword,
                    Form::DsnPassword => CandidateForm::DsnPassword,
                    Form::ConnPassword => CandidateForm::ConnPassword,
                },
            });
        }
        let result = connect()?.scan_match(&ScanMatchParams {
            candidates: batch,
            purpose: ScanPurpose::Scrub,
            source_kind: ScanSource::Mixed,
            claims: claims(),
        })?;
        if result.limited {
            return Err(fail("limited"));
        }
        for m in result.matches {
            answer.push(Match {
                candidate: u64::from(m.id),
                item: m.item,
                slug: m.slug,
            });
        }
    }
    Ok(answer)
}
fn apply_file(
    plan: &scrub::FilePlan,
    format: ConfigFormat,
    row: &mut Value,
    entries: &[&DistinctCandidate],
) -> Result<(), Failure> {
    let mut source = OpenFile::open(plan).map_err(fail)?;
    source.validate(plan, format).map_err(fail)?;
    let stamp = plan.stamp.ok_or_else(|| fail("binding"))?;
    let path = plan.path.to_str().ok_or_else(|| fail("invalid_path"))?;
    let begun = connect()?.backup_v2_begin(&BackupBeginParams {
        purpose: "scrub".into(),
        files: vec![BackupPlanFile {
            path: path.into(),
            size: stamp.size,
            mode: stamp.mode & 0o7777,
        }],
        claims: claims(),
    })?;
    row["backup"] = json!(begun.id);
    if begun.chunk_size as usize != envcloak_core::file_backup_v2::CHUNK_V2 {
        return Err(fail("backup_failed"));
    }
    let reader = source.reader().map_err(fail)?;
    let mut remaining = stamp.size;
    let mut index = 0;
    while remaining > 0 {
        let n = remaining.min(u64::from(begun.chunk_size)) as usize;
        let mut buffer = SecretBuf::with_capacity(n);
        buffer
            .read_exact_from(reader, n)
            .map_err(|_| fail("changed"))?;
        connect()?.backup_v2_put(&begun.id, 0, index, buffer.freeze())?;
        remaining -= n as u64;
        index += 1;
    }
    source.check().map_err(fail)?;
    connect()?.backup_v2_commit(&begun.id)?;
    envcloak_scan::pause_point("scrub_backed_up");
    let relevant: Vec<_> = entries
        .iter()
        .copied()
        .filter(|e| e.occurrences.iter().any(|o| o.source.path == plan.path))
        .collect();
    let current = compare(&relevant)?;
    let observations: Vec<_> = relevant
        .iter()
        .flat_map(|e| {
            e.occurrences
                .iter()
                .filter(|o| o.source.path == plan.path)
                .map(|o| Candidate {
                    id: e.id,
                    value: SecretBytes::copy_from(&[]),
                    form: e.form,
                    occurrence: o.clone(),
                })
        })
        .collect();
    let references: Vec<_> = observations.iter().collect();
    let fresh = scrub::plan(&references, &current);
    if fresh.files.len() != 1 || fresh.files[0].edits != plan.edits || !fresh.complete() {
        return Err(fail("items_changed"));
    }
    // Mark before the destructive step so even a crash just after rename
    // cannot leave a scrubbed item without its rotation flag.
    let mut counts = BTreeMap::new();
    for e in &plan.edits {
        *counts.entry(e.item.clone()).or_insert(0u64) += 1;
    }
    let marks: Vec<_> = counts
        .into_iter()
        .map(|(item, count)| ExposedItem {
            item,
            count,
            sources: vec![ExposureSourceView::Transcript],
        })
        .collect();
    for batch in marks.chunks(256) {
        let result = connect()?.items_mark_exposed(&MarkExposedParams {
            items: batch.to_vec(),
            claims: claims(),
        })?;
        if result.missing != 0 {
            return Err(fail("items_changed"));
        }
    }
    let digest = source.apply(plan, format).map_err(fail)?;
    envcloak_scan::pause_point("scrub_applied");
    connect()?.backup_v2_record_result(&begun.id, 0, &digest)?;
    Ok(())
}
fn output(o: &Options, files: &[Value], report: &DoctorReport, leftovers: &[Value]) {
    if o.json {
        let findings: Value = serde_json::from_str(&report.json()).unwrap_or(Value::Null);
        println!(
            "{}",
            json!({"files": files, "findings": findings, "leftovers": leftovers,
            "limits": LIMITS, "complete": report.complete()})
        );
    } else {
        for f in files {
            println!(
                "{}: {}{}{}",
                f["display_path"].as_str().unwrap_or("[hidden]"),
                f["state"].as_str().unwrap_or("refused"),
                f["reason"]
                    .as_str()
                    .map_or(String::new(), |r| format!(" ({r}); quit the agent first")),
                f["backup"]
                    .as_str()
                    .map_or(String::new(), |id| format!("; backup {id}"))
            );
        }
        for l in leftovers {
            println!("possible leftover: {} (report only)", l["display_path"]);
        }
        if !report.complete() {
            println!("scrub incomplete");
        }
    }
}
fn undo(id: &str, o: &Options) -> Result<bool, Failure> {
    if id.len() != 26
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b.is_ascii_uppercase() && !b"ILOU".contains(&b)))
    {
        return Err(fail("no_such_backup"));
    }
    let claims = refuse_if_claimed()?;
    super::require_unlocked(&mut connect()?)?;
    let shown = connect()?.files_show(id, &claims)?;
    let statement = format!(
        "Restore backup {id}\n{}\n{}\n",
        envcloak_client::render::made_by(shown.creator.as_ref()),
        shown
            .files
            .iter()
            .map(|f| display_path(Path::new(&f.path)))
            .collect::<Vec<_>>()
            .join("\n")
    );
    eprint!("{statement}");
    if shown.creator.as_ref().is_none_or(|c| c.kind != "terminal") && !o.agent {
        return Err(Failure::new(
            "created_by_agent",
            "this backup was not created by you; use --created-by-agent to restore it",
        ));
    }
    if shown.files.iter().any(|f| f.left.is_none()) && !o.unrecorded {
        return Err(Failure::new(
            "result_unrecorded",
            "EnvCloak does not know what the change left; recovery requires --unrecorded",
        ));
    }
    let pass = if let Some(fd) = o.fd {
        read_secret_fd(fd)?
    } else {
        let mut t = Terminal::open().map_err(|_| fail("no_terminal"))?;
        t.say(&statement)?;
        t.read_secret("Vault passphrase to restore: ")?
    };
    let lease = connect()?.backup_v2_open_restore(id, pass, o.agent, o.unrecorded, &claims)?;
    if lease.statement.purpose != "scrub"
        || lease.statement.files_total != 1
        || lease.statement.files.len() != 1
        || shown.files.len() != 1
    {
        return Err(fail("restore_refused"));
    }
    let file = &lease.statement.files[0];
    let after = match &shown.files[0].left {
        Some(FileLeft::Rewritten(h)) => Some(h.clone()),
        _ => None,
    };
    if file.path != shown.files[0].path
        || file.sha256_after != after
        || shown.creator.as_ref().is_none_or(|c| {
            c.kind != lease.statement.creator.kind || c.agent != lease.statement.creator.agent
        })
    {
        return Err(fail("statement_changed"));
    }
    let path = Path::new(&file.path);
    let root =
        envcloak_scan::sources::absolute_root(path.parent().ok_or_else(|| fail("invalid_path"))?)
            .map_err(|_| fail("invalid_path"))?;
    let rel = Path::new(path.file_name().ok_or_else(|| fail("invalid_path"))?);
    let digest = decode(&file.sha256)?;
    let restored = (|| -> Result<&'static str, Failure> {
        let current = scrub::current_digest(path).map_err(fail)?;
        let state = if current == digest {
            "unchanged"
        } else {
            let after = match &file.sha256_after {
                Some(h) => decode(h)?,
                None if o.unrecorded => current,
                None => return Err(fail("result_unrecorded")),
            };
            let backed = envcloak_scan::BackedUpFile {
                size: file.size,
                sha256: digest,
                sha256_after: after,
            };
            match envcloak_scan::restore_over_left(&root, rel, &backed, &mut |chunk| {
                connect()
                    .ok()?
                    .backup_v2_read(&lease.lease, file.file, u32::try_from(chunk).ok()?)
                    .ok()
                    .map(|c| c.data.into_inner())
            }) {
                Ok(_) => "restored",
                Err(e) => e.kind.token(),
            }
        };
        Ok(state)
    })();
    let state = match restored {
        Ok(state) => state,
        Err(e) => e.token(),
    };
    let ok = matches!(state, "restored" | "unchanged");
    let mut report = DoctorReport::default();
    if !ok {
        report.fail(state);
    }
    let sources = [ConfigSource {
        path: path.to_path_buf(),
        format: ConfigFormat::Raw,
        source_kind: SourceKind::Transcript,
        label: "restore leftovers".into(),
        names: None,
    }];
    // Existing scanner discovery reports both new and swap shapes without
    // reading their contents or claiming that the name proves ownership.
    let scan = scrub::inspect_leftovers(&sources);
    for issue in &scan.issues {
        // A candidate name is informational. Discovery failures still make
        // the restore report incomplete and its exit status nonzero.
        report.note(
            &issue.source.path,
            issue.reason,
            issue.reason != "possible_restore_leftover",
        );
    }
    let leftovers: Vec<_> = scan
        .leftovers
        .iter()
        .map(|l| json!({"display_path": display_path(&l.source.path), "reason": l.inspection}))
        .collect();
    output(
        o,
        &[
            json!({"display_path": display_path(path), "state": state, "backup": id, "reason": if ok { Value::Null } else { json!(state) }}),
        ],
        &report,
        &leftovers,
    );
    Ok(ok && report.complete())
}
fn decode(text: &str) -> Result<[u8; 32], Failure> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(fail("invalid_response"));
    }
    let mut out = [0; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&text[2 * i..2 * i + 2], 16)
            .map_err(|_| fail("invalid_response"))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate37_failure_tokens_are_fixed_and_unknown_reasons_stay_failures() {
        for reason in [
            "open_elsewhere",
            "recently_changed",
            "bounds",
            "invalid_json",
        ] {
            assert_eq!(fail(reason).token(), reason);
        }
        let unknown = fail("unrecognized fixture reason");
        assert_eq!(unknown.token(), "incomplete");
        assert!(!unknown.message().contains("unrecognized fixture reason"));
    }
}
