//! `envcloak init [--import] [--yes] [--delete-plaintext] [--agents-note]
//! [--json]` and `envcloak init --undo <ID> [--created-by-agent]
//! [--unrecorded] [--passphrase-fd N] [--json]` (SPEC §6.4, story S2).
//!
//! The project is the directory of the nearest `envcloak.toml` at or
//! above the working directory, or the working directory when there is
//! none. Its env files (`.env`, `.env.<profile>`, and templates for their
//! names) are scanned as `envcloak import` scans ([`super::import`]).
//!
//! - `init` alone writes a manifest with the project's name when there is
//!   none, and reports the env files it found, by name. It sends no value
//!   anywhere, but reads the files whole to parse them, so, like every
//!   mode, it refuses under a tracer before it reads anything.
//! - `--import` sends the files' values to the daemon for a plan and
//!   reports it: a dry run. With `--yes` the daemon commits that plan, and
//!   the manifest, `.gitignore` and the dry run of the references follow,
//!   as `envcloak import --yes` does.
//! - `--delete-plaintext` first makes the project's `.gitignore` ignore
//!   the env files and every temporary name a change of one may leave
//!   plaintext under ([`super::import::edit_gitignore`]), and deletes
//!   nothing when it cannot (`gitignore_refused`). It takes the imported
//!   entries out of the env files only after all four conditions of SPEC
//!   §6.4 hold, in the order of
//!   [`envcloak_scan::delete_plaintext`]: the daemon confirms each secret
//!   in each file is committed where the manifest binds its variable,
//!   every reference resolves, and the Recovery Kit is confirmed
//!   (`envcloak recovery confirm`); an encrypted backup of the files is
//!   written; the daemon confirms again, with the same entries held; then
//!   each file is changed, only if it is the file read, was not modified
//!   in the last two minutes, and is open nowhere else. Only the entries
//!   the daemon says the vault holds where the manifest binds them leave:
//!   a file whose every entry is held is removed; one that also holds
//!   entries that are not imported (configuration, an interpolated value,
//!   a reference, a short value an agent's request is never matched on)
//!   is rewritten to hold those, byte for byte as they were; one with no
//!   entry held is left as it is. Templates, references-only files and
//!   files with another hard link are never changed. The report names
//!   every entry that stays, and ends with the backup's id.
//! - `--undo <ID>` writes the files of that backup back, byte for byte,
//!   where they were. That hands plaintext back, so it is a proof: the
//!   passphrase, from `/dev/tty` or `--passphrase-fd`, in a terminal
//!   session with no agent in it. The statement before it names the
//!   project directory, who made the backup (as the daemon sealed it,
//!   `files.show`) and its files, and only env files directly in that
//!   directory are written: a backup names its paths, and any client can
//!   store one. A file is written back only while it is what the deletion
//!   left: the backup records that (the SHA-256 of what a rewrite leaves,
//!   or that the file was removed) when it is made, before any file
//!   changes (F-78). So a file there is replaced only when it is exactly
//!   that rewrite, checked again up to the moment the original takes its
//!   name (an edit made meanwhile is kept, `changed`; a file system that
//!   cannot swap two names writes nothing, `swap_unsupported`), and a
//!   missing file is made only when the deletion removed it. Any other is left as it is: one edited since, an entry
//!   added or taken out included (`exists`), one the deletion removed
//!   that is there again (`exists`), and one it rewrote that was deleted
//!   since (`deleted_since`). A backup that does not record what the
//!   deletion left (one an earlier EnvCloak made) is written back only
//!   with the recovery form `--unrecorded`, and then only where a file is
//!   missing; one an agent or an unknown process made, or that does not
//!   record who made it, only with `--created-by-agent`. Without them it
//!   is refused before the passphrase is asked for, after the statement
//!   naming who made it.
//!
//! Deletion removes the working copy only: a value that was committed to
//! git, synced or backed up elsewhere is still there, and the report says
//! to rotate it.
//!
//! `--agents-note` (SPEC §6.4 step 4, M2 plan M2-08) adds EnvCloak's
//! instruction block to the project's agent instruction file, as
//! `envcloak agents install --project` does (Map C §6: `CLAUDE.md` and
//! `AGENTS.md` where they exist, else a new `AGENTS.md`; never a new
//! `CLAUDE.md` beside a lone `AGENTS.md`), after a backup v2 of a file
//! that is there; not in a dry run of `--import`. Its results follow the
//! report (with `--json`, as a line of their own).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use envcloak_client::claims::{claims, refuse_if_claimed};
use envcloak_client::connect::connect;
use envcloak_client::fail::{FAILURE, Failure, refuse_if_traced, usage};
use envcloak_client::render::{looks_like_value, made_by, print};
use envcloak_client::tty::{Terminal, read_secret_fd};
use envcloak_core::SecretBytes;
use envcloak_ipc::WireSecret;
use envcloak_ipc::proto::{
    BackupFileParams, FileLeft, FilesBackupParams, FilesShown, VerifyEntry, VerifyFile,
    VerifyParams,
};
use envcloak_ipc::view::{
    DeleteReport, EntryStatus, FileChange, InitReport, SkipReason, SkippedPath, UndoFile,
    UndoReport, VerifyEntryView, VerifyView,
};
use envcloak_policy::{MANIFEST_NAME, escape_for_display, find_manifest};
use envcloak_scan::{
    DeleteGate, DeleteStep, DotenvEntry, EntryKind, FileKind, FileStamp, Inside, MAX_DOTENV,
    ModifyErrorKind, Remains, ScanErrorKind, ScanRoot, create_atomically, delete_plaintext,
    dotenv_kind, open_root, parse_dotenv, pause_point, read_capped, read_plain, restore_file,
    restore_over_observed, without_entries,
};

use super::import::{ReadFile, edit_gitignore, import, project_name, report, scan};
use super::{fd_number, require_unlocked};

const USAGE_TEXT: &str =
    "envcloak init [--import] [--yes] [--delete-plaintext] [--agents-note] [--json]
       envcloak init --undo <ID> [--created-by-agent] [--unrecorded] [--passphrase-fd N] [--json]";

/// The parsed command line.
#[derive(Debug, Default, PartialEq, Eq)]
struct InitArgs {
    import: bool,
    yes: bool,
    delete: bool,
    agents_note: bool,
    undo: Option<String>,
    /// `--created-by-agent`: the backup may be one an agent or an unknown
    /// process made.
    created_by_agent: bool,
    /// `--unrecorded`: the recovery form, for a backup that does not
    /// record what the deletion left.
    unrecorded: bool,
    passphrase_fd: Option<i32>,
    json: bool,
}

fn parse(args: &[&str]) -> Option<InitArgs> {
    let mut a = InitArgs::default();
    let mut it = args.iter();
    while let Some(&arg) = it.next() {
        match arg {
            "--import" if !a.import => a.import = true,
            "--yes" if !a.yes => a.yes = true,
            "--delete-plaintext" if !a.delete => a.delete = true,
            "--agents-note" if !a.agents_note => a.agents_note = true,
            "--json" if !a.json => a.json = true,
            "--undo" if a.undo.is_none() => a.undo = Some((*it.next()?).to_owned()),
            "--created-by-agent" if !a.created_by_agent => a.created_by_agent = true,
            "--unrecorded" if !a.unrecorded => a.unrecorded = true,
            "--passphrase-fd" if a.passphrase_fd.is_none() => {
                a.passphrase_fd = Some(fd_number(it.next()?)?);
            }
            _ => return None,
        }
    }
    let undo_only = a.undo.is_some() && !a.import && !a.yes && !a.delete && !a.agents_note;
    let no_undo =
        a.undo.is_none() && a.passphrase_fd.is_none() && !a.created_by_agent && !a.unrecorded;
    (undo_only || no_undo).then_some(a)
}

pub fn run(args: &[&str]) -> ExitCode {
    if args == ["--help"] || args == ["-h"] {
        println!("usage: {USAGE_TEXT}");
        return ExitCode::SUCCESS;
    }
    let Some(a) = parse(args) else {
        return usage(USAGE_TEXT);
    };
    let done = match &a.undo {
        Some(id) => undo(id, &a),
        None => init(&a),
    };
    done.unwrap_or_else(|f| f.report(FAILURE))
}

/// The project's directory: where the nearest manifest is, or here.
fn project_dir() -> Result<PathBuf, Failure> {
    let cwd = || {
        Failure::new(
            "io",
            "the working directory could not be read while looking for envcloak.toml",
        )
    };
    match find_manifest(Path::new(".")).map_err(|_| cwd())? {
        Some(m) => m.parent().map(Path::to_path_buf).ok_or_else(cwd),
        None => std::fs::canonicalize(".").map_err(|_| cwd()),
    }
}

fn init(a: &InitArgs) -> Result<ExitCode, Failure> {
    if a.delete && a.import && !a.yes {
        return Err(Failure::new(
            "confirmation_required",
            "--delete-plaintext after --import needs --yes: a dry run imports nothing",
        ));
    }
    // Every mode reads the env files whole, values and all, to report
    // them: not under a tracer (SPEC §5).
    refuse_if_traced()?;
    let dir = project_dir()?;
    let root = open_root(&dir)
        .map_err(|_| Failure::new("io", "the project directory could not be opened"))?;
    let (projects, skipped) = scan(&root, false);
    let out = if a.import {
        Some(import(&root, &projects, skipped, a.yes)?)
    } else if a.delete {
        None
    } else {
        let mut r = report(&root, &projects, None, &Vec::new(), skipped);
        r.projects.retain(|p| !p.files.is_empty());
        // A manifest with the project's name, where there is none.
        let text = format!(
            "# Written by `envcloak init`. Names only: the values are in the EnvCloak vault.\n\
             [project]\nname = \"{}\"\n\n[env]\n",
            project_name(root.path())
        );
        let change = match read_plain(&root, Path::new(MANIFEST_NAME), 64 * 1024) {
            Ok(_) => FileChange::Unchanged,
            Err(e) if e.kind == ScanErrorKind::NotFound => {
                create_atomically(&root, Path::new(MANIFEST_NAME), text.as_bytes(), 0o644)
                    .map_or(FileChange::Refused, |_| FileChange::Created)
            }
            Err(_) => FileChange::Refused,
        };
        if r.projects.is_empty() {
            r.projects.push(envcloak_ipc::view::ProjectReport {
                dir: root.path().to_string_lossy().into_owned(),
                name: project_name(root.path()),
                files: Vec::new(),
                manifest: None,
                conflicts: Vec::new(),
                gitignore: None,
                resolves: None,
            });
        }
        if let Some(p) = r.projects.first_mut() {
            p.manifest = Some(change);
        }
        Some(r)
    };
    let delete = match a.delete.then(|| delete(&root)).transpose() {
        Ok(d) => d,
        // The import was committed and its files written: its report
        // still comes out, before the deletion's failure.
        Err(f) => {
            if out.is_some() {
                print(
                    &InitReport {
                        import: out,
                        delete: None,
                    },
                    a.json,
                );
            }
            return Err(f);
        }
    };
    let refusal = delete.as_ref().and_then(|(_, r)| r.clone());
    let report = InitReport {
        import: out,
        delete: delete.map(|(d, _)| d),
    };
    print(&report, a.json);
    if let Some(f) = refusal {
        return Err(f);
    }
    if a.agents_note {
        if a.import && !a.yes {
            if !a.json {
                eprintln!(
                    "envcloak: dry run: the agent note was not written; run it again with --yes"
                );
            }
        } else {
            super::agents::project_note(&dir, a.json)?;
        }
    }
    let planned = report.import.as_ref().is_some_and(|r| !r.items.is_empty());
    if a.import && !a.yes && !a.json && planned {
        eprintln!("envcloak: dry run: nothing was imported; run it again with --yes to import");
    }
    Ok(ExitCode::SUCCESS)
}

/// Why the delete gate refused.
#[derive(Debug, Clone)]
enum Refusal {
    /// A condition does not hold; the report says which.
    Gate(Failure),
    Client(Failure),
}

/// One env file the deletion considers.
struct Candidate<'a> {
    file: &'a ReadFile,
    /// Its entries, as parsed when it was read.
    entries: &'a [DotenvEntry],
    /// The indices in `entries` of the plain entries sent to the daemon,
    /// in order: the daemon answers for each.
    sent: Vec<usize>,
}

/// The daemon's side of the gate, for the files in `files`.
struct Gate<'a> {
    root: &'a ScanRoot,
    manifest: String,
    files: Vec<Candidate<'a>>,
    last: Option<VerifyView>,
    /// For each file, whether the vault holds each entry, by the first
    /// answer; the second must be the same.
    held: Option<Vec<Vec<bool>>>,
    backup: Option<String>,
}

fn changed_meanwhile() -> Refusal {
    Refusal::Gate(Failure::new(
        "changed",
        "the vault or an env file changed while the env files were being deleted; nothing was \
         deleted",
    ))
}

impl Gate<'_> {
    fn params(&self) -> VerifyParams {
        VerifyParams {
            manifest: self.manifest.clone(),
            files: self
                .files
                .iter()
                .map(|c| {
                    // Fresh copies of the values: the same parse again.
                    let fresh = parse_dotenv(&c.file.bytes).unwrap_or_default();
                    VerifyFile {
                        file: c.file.file_name().to_owned(),
                        profile: c.file.profile.as_ref().map(|p| p.as_str().to_owned()),
                        entries: fresh
                            .into_iter()
                            .enumerate()
                            .filter(|(k, _)| c.sent.binary_search(k).is_ok())
                            .map(|(_, e)| VerifyEntry {
                                line: e.line,
                                name: e.name.as_str().to_owned(),
                                value: WireSecret::new(e.value),
                            })
                            .collect(),
                    }
                })
                .collect(),
            claims: claims(),
        }
    }

    /// Which entries of each file the vault holds, by `view`; `None` when
    /// the answer is not about the entries sent.
    fn held_by(&self, view: &VerifyView) -> Option<Vec<Vec<bool>>> {
        if view.files.len() != self.files.len() {
            return None;
        }
        let mut out = Vec::with_capacity(self.files.len());
        for (c, f) in self.files.iter().zip(&view.files) {
            if f.entries.len() != c.sent.len() {
                return None;
            }
            let mut held = vec![false; c.entries.len()];
            for (&k, e) in c.sent.iter().zip(&f.entries) {
                if c.entries.get(k)?.line != e.line {
                    return None;
                }
                held[k] = e.status == EntryStatus::Stored;
            }
            out.push(held);
        }
        Some(out)
    }
}

impl DeleteGate for Gate<'_> {
    type Refusal = Refusal;

    fn verify(&mut self) -> Result<(), Refusal> {
        let view = connect()
            .and_then(|mut c| c.import_verify(&self.params()).map_err(Failure::from))
            .map_err(Refusal::Client)?;
        let held = self.held_by(&view).ok_or_else(|| {
            Refusal::Client(Failure::new(
                "internal",
                "the daemon's answer is not about the env files sent; nothing was deleted",
            ))
        })?;
        let refusal = if view.files.iter().any(|f| !f.covered) {
            Some(Failure::new(
                "not_imported",
                "a secret in an env file is not in the vault where envcloak.toml binds it (the \
                 report says which); run `envcloak init --import --yes` first. Nothing was deleted",
            ))
        } else if !view.resolves {
            Some(Failure::new(
                "unresolved_reference",
                "a reference in envcloak.toml does not resolve (`envcloak check` says which); \
                 nothing was deleted",
            ))
        } else if !view.recovery_confirmed {
            Some(Failure::new(
                "recovery_kit_unconfirmed",
                "the Recovery Kit is not confirmed: run `envcloak recovery confirm` first, so a \
                 forgotten passphrase cannot lose what the files held. Nothing was deleted",
            ))
        } else {
            None
        };
        self.last = Some(view);
        if let Some(f) = refusal {
            return Err(Refusal::Gate(f));
        }
        match &self.held {
            None => self.held = Some(held),
            Some(first) if *first != held => return Err(changed_meanwhile()),
            Some(_) => {}
        }
        Ok(())
    }

    fn remains(&self, i: usize) -> Remains {
        let (Some(held), Some(c)) = (self.held.as_ref().and_then(|h| h.get(i)), self.files.get(i))
        else {
            return Remains::Everything;
        };
        if !held.iter().any(|&h| h) {
            Remains::Everything
        } else if held.iter().all(|&h| h) {
            Remains::Nothing
        } else {
            let spans: Vec<_> = c
                .entries
                .iter()
                .zip(held)
                .filter(|(_, h)| **h)
                .map(|(e, _)| e.span.clone())
                .collect();
            Remains::Bytes(without_entries(&c.file.bytes, &spans))
        }
    }

    fn backup(&mut self, which: &[usize]) -> Result<String, Refusal> {
        let mut files = Vec::with_capacity(which.len());
        for &i in which {
            let Some(c) = self.files.get(i) else {
                continue;
            };
            // What the deletion will leave of it, which the backup records
            // so that an undo writes it back only over exactly that (F-78).
            let left = match self.remains(i) {
                Remains::Nothing => FileLeft::Removed,
                Remains::Bytes(b) => FileLeft::Rewritten(hex(&b.sha256())),
                // A file the deletion leaves as it is is never backed up.
                Remains::Everything => return Err(changed_meanwhile()),
            };
            let f = c.file;
            // Read again, and only if it is still the file checked.
            let (bytes, stamp) =
                read_capped(self.root, &f.rel, MAX_DOTENV).map_err(|_| changed_meanwhile())?;
            if stamp != f.stamp {
                return Err(changed_meanwhile());
            }
            files.push(BackupFileParams {
                path: self.root.path().join(&f.rel).to_string_lossy().into_owned(),
                mode: stamp.mode & 0o7777,
                content: WireSecret::new(bytes),
                left,
            });
        }
        let view = connect()
            .and_then(|mut c| {
                c.files_backup(&FilesBackupParams {
                    files,
                    claims: claims(),
                })
                .map_err(|e| match e {
                    envcloak_ipc::ClientError::Frame(envcloak_ipc::FrameError::TooLarge) => {
                        too_large_to_back_up()
                    }
                    // The daemon takes a backup only when its restore's
                    // answer fits in a frame too.
                    envcloak_ipc::ClientError::Rpc(r)
                        if r.kind == envcloak_ipc::proto::ErrorKind::FrameTooLarge =>
                    {
                        too_large_to_back_up()
                    }
                    e => Failure::from(e),
                })
            })
            .map_err(Refusal::Client)?;
        self.backup = Some(view.id.clone());
        Ok(view.id)
    }
}

/// The env files are too large to back up, or to be given back, in one
/// frame.
fn too_large_to_back_up() -> Failure {
    Failure::new(
        "files_backup_failed",
        "the env files are too large to back up, and write back, in one request; nothing was \
         deleted",
    )
}

/// The name of a pause point for gate 16's test ([`pause_point`]).
fn step_name(s: DeleteStep) -> String {
    match s {
        DeleteStep::Verified => "verified".to_owned(),
        DeleteStep::BackedUp => "backed_up".to_owned(),
        DeleteStep::Reverified => "reverified".to_owned(),
        DeleteStep::MovedAside(i) => format!("moved_aside_{i}"),
        DeleteStep::Removed(i) => format!("removed_{i}"),
        DeleteStep::Staged(i) => format!("staged_{i}"),
        DeleteStep::Swapped(i) => format!("swapped_{i}"),
        DeleteStep::Rewritten(i) => format!("rewritten_{i}"),
    }
}

/// Adds to the report the entries the daemon was never sent (interpolated
/// values and references), which stay in their files, in line order.
fn add_unsent(report: &mut VerifyView, files: &[Candidate<'_>]) {
    for (c, f) in files.iter().zip(report.files.iter_mut()) {
        for e in c.entries {
            let why = match e.kind {
                EntryKind::Plain => continue,
                EntryKind::Template => SkipReason::Interpolated,
                EntryKind::Reference(_) => SkipReason::Reference,
            };
            f.entries.push(VerifyEntryView {
                line: e.line,
                name: (!looks_like_value(e.name.as_str())).then(|| e.name.as_str().to_owned()),
                status: EntryStatus::LeftOut,
                skipped: Some(why),
            });
        }
        f.entries.sort_by_key(|e| e.line);
    }
}

/// Takes the project's imported entries out of its env files. See the
/// module documentation. Returns the report, and the failure to end with
/// when the gate refused or a file was kept.
fn delete(root: &ScanRoot) -> Result<(DeleteReport, Option<Failure>), Failure> {
    let manifest = root.path().join(MANIFEST_NAME);
    if read_plain(root, Path::new(MANIFEST_NAME), 64 * 1024).is_err() {
        return Err(Failure::new(
            "no_manifest",
            "there is no envcloak.toml here to check the env files against; run `envcloak init \
             --import --yes` first. Nothing was deleted",
        ));
    }
    // Checked on a connection of its own: the scan and the gate's steps
    // take local time, and each step connects again (docs/IPC.md: an idle
    // connection is closed after 30 seconds).
    require_unlocked(&mut connect()?)?;
    refuse_if_traced()?;
    let (projects, mut skipped) = scan(root, false);
    let mut files: Vec<Candidate<'_>> = Vec::new();
    for f in projects.iter().flat_map(|p| p.files.iter()) {
        let why = match &f.parsed {
            _ if f.template || f.references_only() => continue,
            _ if f.hard_linked => "hard_linked",
            Err(_) => "invalid",
            Ok(entries) => {
                files.push(Candidate {
                    file: f,
                    entries,
                    sent: entries
                        .iter()
                        .enumerate()
                        .filter(|(_, e)| e.kind == EntryKind::Plain)
                        .map(|(k, _)| k)
                        .collect(),
                });
                continue;
            }
        };
        skipped.push(SkippedPath {
            path: f.rel.to_string_lossy().into_owned(),
            reason: why.to_owned(),
        });
    }
    let mut report = DeleteReport {
        project_dir: root.path().to_string_lossy().into_owned(),
        gitignore: None,
        verify: VerifyView {
            recovery_confirmed: false,
            resolves: false,
            files: Vec::new(),
        },
        backup: None,
        removed: Vec::new(),
        rewritten: Vec::new(),
        unchanged: Vec::new(),
        kept: Vec::new(),
        skipped,
    };
    if files.is_empty() {
        return Ok((report, None));
    }
    // A crash while a file changes leaves its plaintext under a temporary
    // name: git must ignore every such name, whatever its random digits,
    // before any file is looked at to change, or nothing is deleted. The
    // import this may follow wrote the line, unless its edit was refused
    // or the line was taken out since.
    for p in &projects {
        let names: Vec<&str> = files
            .iter()
            .filter(|c| c.file.rel.parent().unwrap_or(Path::new("")) == p.rel_dir)
            .map(|c| c.file.file_name())
            .collect();
        if names.is_empty() {
            continue;
        }
        let change = edit_gitignore(root, &p.rel_dir, &names, &p.hidden);
        report.gitignore = Some(change);
        if change == FileChange::Refused {
            return Ok((
                report,
                Some(Failure::new(
                    "gitignore_refused",
                    "the project's .gitignore could not be made to ignore the env files and the \
                     temporary names a deletion may leave plaintext under (it is a symlink, has \
                     another hard link, or changed while it was edited); nothing was deleted",
                )),
            ));
        }
    }
    let stamps: Vec<(PathBuf, FileStamp)> = files
        .iter()
        .map(|c| (c.file.rel.clone(), c.file.stamp))
        .collect();
    let mut gate = Gate {
        root,
        manifest: manifest.to_string_lossy().into_owned(),
        files,
        last: None,
        held: None,
        backup: None,
    };
    let outcome = delete_plaintext(root, &stamps, &mut gate, &mut |s| {
        pause_point(&step_name(s));
    });
    if let Some(mut v) = gate.last.take() {
        add_unsent(&mut v, &gate.files);
        report.verify = v;
    }
    report.backup = gate.backup.take();
    let paths = |v: &[PathBuf]| -> Vec<String> {
        v.iter().map(|p| p.to_string_lossy().into_owned()).collect()
    };
    match outcome {
        Err(Refusal::Gate(f)) => Ok((report, Some(f))),
        Err(Refusal::Client(f)) => Err(f),
        Ok(done) => {
            report.backup = done.backup;
            report.removed = paths(&done.removed);
            report.rewritten = paths(&done.rewritten);
            report.unchanged = paths(&done.unchanged);
            report.kept = done
                .kept
                .iter()
                .map(|(p, k)| SkippedPath {
                    path: p.to_string_lossy().into_owned(),
                    reason: k.token().to_owned(),
                })
                .collect();
            let failure = (!report.kept.is_empty()).then(|| {
                Failure::new(
                    "not_deleted",
                    "some env files were kept (the report says why); run it again later",
                )
            });
            Ok((report, failure))
        }
    }
}

/// Whether `id` has a file backup id's shape: 26 Crockford base32
/// characters. Checked before anything is asked for.
fn backup_id_shaped(id: &str) -> bool {
    id.len() == 26
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b.is_ascii_uppercase() && !b"ILOU".contains(&b)))
}

fn undo(id: &str, a: &InitArgs) -> Result<ExitCode, Failure> {
    if !backup_id_shaped(id) {
        return Err(Failure::new(
            "no_such_backup",
            "a backup id is 26 characters of 0-9 and A-Z (as `init --delete-plaintext` printed \
             it)",
        ));
    }
    refuse_if_traced()?;
    let claims_now = refuse_if_claimed()?;
    let dir = project_dir()?;
    let project = open_root(&dir)
        .map_err(|_| Failure::new("io", "the project directory could not be opened"))?;
    require_unlocked(&mut connect()?)?;
    // What the backup is, as the daemon sealed it, before the passphrase:
    // the statement names who made it (SPEC §6.4).
    let shown = connect()?.files_show(id, &claims_now)?;
    let statement = undo_statement(id, &project.path().to_string_lossy(), &shown, a);
    if let Some(f) = missing_form(&shown, a) {
        eprint!("{statement}");
        return Err(f);
    }
    let passphrase = match a.passphrase_fd {
        Some(fd) => {
            eprint!("{statement}");
            read_secret_fd(fd)?
        }
        None => {
            let mut t = Terminal::open().map_err(|_| {
                Failure::new(
                    "no_terminal",
                    "there is no terminal to type the passphrase on; pass it on a descriptor \
                     with --passphrase-fd",
                )
            })?;
            t.say(&statement)?;
            t.read_secret("Vault passphrase to write them back: ")?
        }
    };
    // The files come from the manifest the statement was read from: it
    // is sealed under the vault's `backup` subkey and bound to the
    // backup's id, which only the daemon writes, never two under one id.
    let restored = connect()?.files_restore(
        id,
        passphrase,
        a.created_by_agent,
        a.unrecorded,
        &claims_now,
    )?;
    let mut report = UndoReport {
        backup: id.to_owned(),
        creator: restored.creator,
        files: Vec::new(),
    };
    for f in restored.files {
        let state = write_back(
            &project,
            &f.path,
            f.mode,
            f.content.into_inner(),
            f.left.as_ref(),
            a.unrecorded,
        );
        report.files.push(UndoFile {
            path: f.path,
            state: state.to_owned(),
        });
    }
    print(&report, a.json);
    if report
        .files
        .iter()
        .all(|f| f.state == "restored" || f.state == "unchanged")
    {
        Ok(ExitCode::SUCCESS)
    } else {
        Err(Failure::new(
            "undo_incomplete",
            "some files were not written back (the report says why)",
        ))
    }
}

/// Whether the backup `shown` records who made it and what the deletion
/// left of every file: one that does not is written back only with the
/// recovery form `--unrecorded`.
fn recorded(shown: &FilesShown) -> bool {
    shown.creator.is_some() && shown.files.iter().all(|f| f.left.is_some())
}

/// Whether the daemon sealed the backup `shown` as a terminal's: any
/// other needs `--created-by-agent`.
fn by_terminal(shown: &FilesShown) -> bool {
    shown.creator.as_ref().is_some_and(|c| c.kind == "terminal")
}

/// The statement `init --undo` shows before the passphrase: the project
/// directory `dir`, who made backup `id` (`shown`, as the daemon sealed
/// it), its files, and what the forms the person gave mean for it.
fn undo_statement(id: &str, dir: &str, shown: &FilesShown, a: &InitArgs) -> String {
    let files: Vec<String> = shown
        .files
        .iter()
        .map(|f| escape_for_display(&f.path))
        .collect();
    let mut s = format!(
        "Write back the env files of backup {id} into {}. They hold plaintext secrets; a file \
         there now is replaced only when it is exactly what the deletion left of it, any other \
         is left alone, and nothing is written anywhere else.\nThe backup was {}; it holds {}.\n",
        escape_for_display(dir),
        made_by(shown.creator.as_ref()),
        files.join(", ")
    );
    if !recorded(shown) {
        s.push_str(
            "It does not record what the deletion left of every file, so such a file is \
             written back only with --unrecorded, and then only where it is missing: one there \
             is left as it is.\n",
        );
    }
    if !by_terminal(shown) && a.created_by_agent {
        s.push_str(
            "--created-by-agent: its bytes are written back as the process that made it stored \
             them.\n",
        );
    }
    s
}

/// The refusal, before the passphrase is asked for, of a backup whose
/// forms the person did not give, as the daemon would refuse it
/// (`restore_refused`): `--unrecorded` for one that does not record what
/// the deletion left or who made it, `--created-by-agent` for one not
/// sealed as a terminal's.
fn missing_form(shown: &FilesShown, a: &InitArgs) -> Option<Failure> {
    let unrecorded = !recorded(shown) && !a.unrecorded;
    let unticked = !by_terminal(shown) && !a.created_by_agent;
    let message = match (unrecorded, unticked) {
        (false, false) => return None,
        (true, false) => {
            "the backup does not record what the deletion left of every file (the statement \
             above says so), so it is written back only with the recovery form --unrecorded, and \
             then only where a file is missing; nothing was written"
        }
        (false, true) => {
            "the backup was not made from a terminal with no agent in it (the statement above \
             names who made it), and writing it back writes the bytes that process stored, so it \
             needs --created-by-agent; nothing was written"
        }
        (true, true) => {
            "the backup does not record what the deletion left, nor that it was made from a \
             terminal with no agent in it (the statement above says so): it is written back only \
             with --unrecorded --created-by-agent, and then only where a file is missing; nothing \
             was written"
        }
    };
    Some(Failure::new("restore_refused", message))
}

/// Lower-case hex of `b`.
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The SHA-256 a backup recorded of what a deletion's rewrite left: 64
/// lower-case hex digits (the daemon takes no other form), or `None`.
fn rewritten(left: Option<&FileLeft>) -> Option<[u8; 32]> {
    let Some(FileLeft::Rewritten(sha)) = left else {
        return None;
    };
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let b = sha.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = digit(b[2 * i])? << 4 | digit(b[2 * i + 1])?;
    }
    Some(out)
}

/// Writes one restored file where it was, only when that is an env file
/// (`.env` or `.env.<profile>`, as a deletion takes out) directly in
/// `project`, the directory `init --undo` runs for: a backup any client
/// can store names any path, and the passphrase statement names only that
/// directory. Another name is `not_env_file`, another directory
/// `elsewhere`. Otherwise it is written only while the file is what the
/// deletion left, by what its backup recorded (`left`, F-78; SPEC §6.4):
/// - a file there already is `unchanged` when it holds the same bytes,
///   replaced (`restored`) only when it is exactly the rewrite recorded,
///   by its SHA-256, and `exists` otherwise: edited since, an entry added
///   or taken out included, one the deletion removed that is there again,
///   and any file whose result is not recorded. The replacement checks
///   that SHA-256 again on the file it replaces, up to the moment the
///   original takes its name and on what the swap brought out
///   ([`restore_over_observed`]): an edit seen before the write is
///   `exists`, one made while it writes is kept and `changed`, and a file
///   system that cannot swap two names writes nothing (`swap_unsupported`);
/// - a missing file is made (`restored`) only when the deletion removed
///   it. One the deletion rewrote was deleted since (`deleted_since`), and
///   is left so: making it would bring back what the person deleted. One
///   whose result the backup does not record is made only under the
///   recovery form `unrecorded` (`unrecorded` otherwise).
fn write_back(
    project: &ScanRoot,
    path: &str,
    mode: u32,
    content: SecretBytes,
    left: Option<&FileLeft>,
    unrecorded: bool,
) -> &'static str {
    let p = Path::new(path);
    let (Some(dir), Some(name)) = (p.parent(), p.file_name()) else {
        return "invalid_path";
    };
    if !p.is_absolute() || path.chars().any(char::is_control) {
        return "invalid_path";
    }
    if !matches!(dotenv_kind(name), Some(Ok(FileKind::Dotenv { .. }))) {
        return "not_env_file";
    }
    let Ok(root) = open_root(dir) else {
        return "no_directory";
    };
    if root.identity() != project.identity() {
        return "elsewhere";
    }
    let rel = Path::new(name);
    match read_capped(&root, rel, content.len().max(MAX_DOTENV)) {
        Ok((now, _)) if now.ct_eq_secret(&content) => return "unchanged",
        Ok((now, _)) => {
            let Some(sha) = rewritten(left).filter(|sha| *sha == now.sha256()) else {
                return "exists";
            };
            // The last check before the original takes the file's name: a
            // test stops here to edit the file (F-78).
            let mut observe = |at| {
                if at == Inside::Checked {
                    pause_point("undo_checked");
                }
            };
            return match restore_over_observed(&root, rel, &content, &sha, &mut observe) {
                Ok(_) => "restored",
                Err(e) if e.kind == ModifyErrorKind::EditedSince => "exists",
                Err(e) => e.kind.token(),
            };
        }
        Err(e) if e.kind == ScanErrorKind::NotFound => {}
        Err(e) => return e.kind.token(),
    }
    // Missing: what the deletion left only when it removed the file.
    match left {
        Some(FileLeft::Removed) => {}
        Some(FileLeft::Rewritten(_)) => return "deleted_since",
        None if unrecorded => {}
        None => return "unrecorded",
    }
    match restore_file(&root, rel, &content, mode & 0o7777) {
        Ok(_) => "restored",
        Err(e) if e.kind == ModifyErrorKind::Exists => "exists",
        Err(e) => e.kind.token(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_lines_init_takes() {
        assert_eq!(parse(&[]).unwrap(), InitArgs::default());
        let a = parse(&["--import", "--yes", "--delete-plaintext", "--json"]).unwrap();
        assert!(a.import && a.yes && a.delete && a.json);
        let a = parse(&["--undo", "ID", "--passphrase-fd", "3"]).unwrap();
        assert_eq!(a.undo.as_deref(), Some("ID"));
        assert_eq!(a.passphrase_fd, Some(3));
        assert!(!a.created_by_agent);
        assert!(!a.unrecorded);
        let a = parse(&["--undo", "ID", "--created-by-agent"]).unwrap();
        assert!(a.created_by_agent && !a.unrecorded);
        let a = parse(&["--unrecorded", "--undo", "ID", "--created-by-agent"]).unwrap();
        assert!(a.created_by_agent && a.unrecorded);
        for bad in [
            &["--undo"][..],
            &["--undo", "a", "--import"],
            &["--passphrase-fd", "3"],
            &["--created-by-agent"],
            &["--unrecorded"],
            &["--import", "--created-by-agent"],
            &["--import", "--unrecorded"],
            &["--undo", "a", "--created-by-agent", "--created-by-agent"],
            &["--undo", "a", "--unrecorded", "--unrecorded"],
            &["--import", "--import"],
            &["--value", "x"],
            &["somewhere"],
        ] {
            assert!(parse(bad).is_none(), "{bad:?}");
        }
    }

    /// A backup can name any path: only an env file directly in the
    /// project directory is written back.
    #[test]
    fn undo_writes_only_env_files_in_the_project() {
        let d = tempfile::tempdir_in("/tmp").unwrap();
        let (project, other) = (d.path().join("project"), d.path().join("other"));
        for dir in [&project, &other] {
            std::fs::create_dir(dir).unwrap();
        }
        let root = open_root(&project).unwrap();
        let body = || SecretBytes::copy_from(b"A=1\n");
        let removed = Some(&FileLeft::Removed);
        let at = |dir: &Path, name: &str| dir.join(name).to_str().unwrap().to_owned();
        for (path, want) in [
            (at(&project, "run.plist"), "not_env_file"),
            (at(&project, ".zshrc"), "not_env_file"),
            (at(&project, ".env.example"), "not_env_file"),
            (at(&project, ".envrc"), "not_env_file"),
            (at(&other, ".env"), "elsewhere"),
            (at(&project.join("sub"), ".env"), "no_directory"),
            (".env".to_owned(), "invalid_path"),
        ] {
            assert_eq!(
                write_back(&root, &path, 0o600, body(), removed, false),
                want,
                "{path}"
            );
        }
        for dir in [&project, &other] {
            assert_eq!(std::fs::read_dir(dir).unwrap().count(), 0);
        }
        assert_eq!(
            write_back(
                &root,
                &at(&project, ".env.local"),
                0o600,
                body(),
                removed,
                false
            ),
            "restored"
        );
        assert_eq!(std::fs::read(project.join(".env.local")).unwrap(), b"A=1\n");
    }

    /// F-78: a file is written back only while it is what the deletion
    /// left, by what its backup recorded (SPEC §6.4). The cases of the M1
    /// audit's undo probe: the original there (`unchanged`), the exact
    /// leftover (`restored`, to the original), an ordinary edit after the
    /// deletion (a newline added) and a whole entry taken out after it
    /// (both `exists`, kept as they are); a value changed and a file the
    /// deletion removed that is there again (`exists`). Missing: a file
    /// the deletion removed is made (`restored`); one it rewrote was
    /// deleted since and stays deleted (`deleted_since`), the recovery
    /// form changing nothing for a result that is recorded. A backup that
    /// records no result: a file there is never replaced (`exists`), and
    /// a missing one is made only under the recovery form `--unrecorded`
    /// (`unrecorded` without it).
    ///
    /// Mutations: a missing file made whatever was recorded (the old
    /// behaviour: `deleted_since` and `unrecorded` restore); the recovery
    /// form taken for a recorded rewrite (`deleted_since` restores); an
    /// unrecorded file replaced under the recovery form.
    #[test]
    fn undo_writes_back_only_what_the_deletion_left() {
        let d = tempfile::tempdir_in("/tmp").unwrap();
        let original: &[u8] = b"TOKEN=aaaaaaaaaaaaaaaaaaaa\nMODE=bbb\nFLAG=ccc\n";
        // The deletion took the first entry out.
        let leftover: &[u8] = b"MODE=bbb\nFLAG=ccc\n";
        let rewritten = FileLeft::Rewritten(hex(&SecretBytes::copy_from(leftover).sha256()));
        let removed = FileLeft::Removed;
        // Each case: its name, the file there before the undo (none:
        // missing), what the backup recorded, whether the recovery form
        // was given, and the undo's state.
        type Case<'a> = (
            &'a str,
            Option<&'a [u8]>,
            Option<&'a FileLeft>,
            bool,
            &'a str,
        );
        let cases: [Case<'_>; 15] = [
            (
                "identical",
                Some(original),
                Some(&rewritten),
                false,
                "unchanged",
            ),
            (
                "leftover",
                Some(leftover),
                Some(&rewritten),
                false,
                "restored",
            ),
            (
                "edited",
                Some(b"MODE=bbb\nFLAG=ccc\n\n"),
                Some(&rewritten),
                false,
                "exists",
            ),
            (
                "entry_removed",
                Some(b"FLAG=ccc\n"),
                Some(&rewritten),
                false,
                "exists",
            ),
            (
                "value_changed",
                Some(b"MODE=bbx\nFLAG=ccc\n"),
                Some(&rewritten),
                false,
                "exists",
            ),
            (
                "made_again",
                Some(b"MODE=bbb\n"),
                Some(&removed),
                false,
                "exists",
            ),
            ("removed_missing", None, Some(&removed), false, "restored"),
            (
                "deleted_since",
                None,
                Some(&rewritten),
                false,
                "deleted_since",
            ),
            (
                "deleted_since_recovery",
                None,
                Some(&rewritten),
                true,
                "deleted_since",
            ),
            ("unrecorded", Some(leftover), None, false, "exists"),
            (
                "unrecorded_identical",
                Some(original),
                None,
                false,
                "unchanged",
            ),
            ("unrecorded_missing", None, None, false, "unrecorded"),
            ("unrecorded_recovery", None, None, true, "restored"),
            ("unrecorded_there", Some(leftover), None, true, "exists"),
            (
                "unrecorded_edited",
                Some(b"MODE=bbb\n"),
                None,
                true,
                "exists",
            ),
        ];
        for (name, now, left, unrecorded, want) in cases {
            let dir = d.path().join(name);
            std::fs::create_dir(&dir).unwrap();
            let root = open_root(&dir).unwrap();
            let path = dir.join(".env");
            if let Some(now) = now {
                std::fs::write(&path, now).unwrap();
            }
            let got = write_back(
                &root,
                path.to_str().unwrap(),
                0o600,
                SecretBytes::copy_from(original),
                left,
                unrecorded,
            );
            assert_eq!(got, want, "{name}");
            match (want, now) {
                ("restored", _) => {
                    assert!(std::fs::read(&path).unwrap() == original, "{name}");
                }
                (_, Some(now)) => assert!(std::fs::read(&path).unwrap() == now, "{name}"),
                (_, None) => assert!(!path.exists(), "{name}: made"),
            }
        }
    }

    /// A file backup as `files.show` answers it: made by `creator` (kind
    /// and label), with `.env` rewritten and `.env.short` removed, or,
    /// `recorded` false, recording nothing (an M1 build's).
    fn shown(creator: Option<(&str, Option<&str>)>, recorded: bool) -> FilesShown {
        use envcloak_ipc::proto::ShownFile;
        use envcloak_ipc::view::FileBackupCreatorView;
        let file = |path: &str, left: FileLeft| ShownFile {
            path: path.to_owned(),
            left: recorded.then_some(left),
        };
        FilesShown {
            creator: creator.map(|(kind, agent)| FileBackupCreatorView {
                kind: kind.to_owned(),
                agent: agent.map(str::to_owned),
            }),
            files: vec![
                file("/p/acme/.env", FileLeft::Rewritten("ab".repeat(32))),
                file("/p/acme/.env.short", FileLeft::Removed),
            ],
        }
    }

    /// Codex and verifier review, round 3 (SPEC §6.4: the restore
    /// statement names the creator): the statement before the passphrase
    /// names who made the backup as the daemon sealed it (each kind, an
    /// agent's label, and a backup that does not record it) and its
    /// files; a backup that does not record what the deletion left says
    /// so, and the tick is repeated only when it was given for a backup
    /// that needs it.
    ///
    /// Mutation: the statement built without the backup shown (the old
    /// generic text: no maker, no files).
    #[test]
    fn the_undo_statement_names_who_made_the_backup() {
        let a = |tick: bool, unrecorded: bool| InitArgs {
            undo: Some("ID".to_owned()),
            created_by_agent: tick,
            unrecorded,
            ..InitArgs::default()
        };
        for (creator, recorded, words) in [
            (
                Some(("terminal", None)),
                true,
                "The backup was made from a terminal;",
            ),
            (
                Some(("agent", Some("Claude Code"))),
                true,
                "The backup was made by an agent (Claude Code), not by you;",
            ),
            (
                Some(("unknown", Some("Codex"))),
                true,
                "The backup was made by a process EnvCloak could not identify (Codex), not by you;",
            ),
            (
                Some(("unknown", None)),
                true,
                "The backup was made by a process EnvCloak could not identify, not by you;",
            ),
            (
                None,
                false,
                "The backup was made before EnvCloak recorded who makes a backup;",
            ),
        ] {
            let b = shown(creator, recorded);
            let s = undo_statement("ID", "/p/acme", &b, &a(true, true));
            assert!(
                s.starts_with("Write back the env files of backup ID into /p/acme. "),
                "{s}"
            );
            assert!(s.contains(words), "{s}");
            assert!(
                s.contains("it holds /p/acme/.env, /p/acme/.env.short.\n"),
                "{s}"
            );
            assert_eq!(
                s.contains("It does not record what the deletion left"),
                !recorded,
                "{s}"
            );
            let by_terminal = creator.is_some_and(|(k, _)| k == "terminal");
            assert_eq!(s.contains("--created-by-agent:"), !by_terminal, "{s}");
            let unticked = undo_statement("ID", "/p/acme", &b, &a(false, true));
            assert!(!unticked.contains("--created-by-agent:"), "{unticked}");
        }
    }

    /// The forms a backup needs are asked for before the passphrase, as
    /// the daemon refuses without them: none for a terminal's recorded
    /// backup, `--created-by-agent` for an agent's or an unknown
    /// process's, `--unrecorded` for one with a result not recorded, and
    /// both for one that records nothing (an M1 build's), each refusal
    /// `restore_refused` saying which.
    ///
    /// Mutations: a backup that records no maker taken as a terminal's;
    /// results not looked at.
    #[test]
    fn an_undo_without_the_forms_its_backup_needs_is_refused_first() {
        let a = |tick: bool, unrecorded: bool| InitArgs {
            undo: Some("ID".to_owned()),
            created_by_agent: tick,
            unrecorded,
            ..InitArgs::default()
        };
        let terminal = shown(Some(("terminal", None)), true);
        let agent = shown(Some(("agent", Some("Claude Code"))), true);
        let mut partly = shown(Some(("terminal", None)), true);
        partly.files[1].left = None;
        let m1 = shown(None, false);
        let needs = |b: &FilesShown, tick: bool, unrecorded: bool| {
            missing_form(b, &a(tick, unrecorded)).map(|f| {
                assert_eq!(f.token(), "restore_refused");
                let m = f.message().to_owned();
                (m.contains("--unrecorded"), m.contains("--created-by-agent"))
            })
        };
        assert_eq!(needs(&terminal, false, false), None);
        assert_eq!(needs(&agent, false, false), Some((false, true)));
        assert_eq!(needs(&agent, true, false), None);
        assert_eq!(needs(&partly, false, false), Some((true, false)));
        assert_eq!(needs(&partly, false, true), None);
        assert_eq!(needs(&m1, false, false), Some((true, true)));
        assert_eq!(needs(&m1, true, false), Some((true, false)));
        assert_eq!(needs(&m1, false, true), Some((false, true)));
        assert_eq!(needs(&m1, true, true), None);
    }

    #[test]
    fn backup_ids_are_checked_before_anything_is_asked() {
        assert!(backup_id_shaped("01J8ZQ3V5X7Y9A0B2C4D6E8F0G"));
        for bad in [
            "",
            "01J8ZQ3V5X7Y9A0B2C4D6E8F0",
            "01J8ZQ3V5X7Y9A0B2C4D6E8F0I",
            "01j8zq3v5x7y9a0b2c4d6e8f0g",
        ] {
            assert!(!backup_id_shaped(bad), "{bad}");
        }
    }
}
