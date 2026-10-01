//! `envcloak init [--import] [--yes] [--delete-plaintext] [--json]` and
//! `envcloak init --undo <ID> [--passphrase-fd N] [--json]` (SPEC §6.4,
//! story S2).
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
//!   project directory, and only env files directly in it are written: a
//!   backup names its paths, and any client can store one. A file that
//!   exists is replaced only when it is what the deletion left of it (the
//!   original with some entries taken out, and nothing else changed); any
//!   other is left alone.
//!
//! Deletion removes the working copy only: a value that was committed to
//! git, synced or backed up elsewhere is still there, and the report says
//! to rotate it.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use envcloak_client::claims::{claims, refuse_if_claimed};
use envcloak_client::connect::connect;
use envcloak_client::fail::{FAILURE, Failure, refuse_if_traced, usage};
use envcloak_client::render::{looks_like_value, print};
use envcloak_client::tty::{Terminal, read_secret_fd};
use envcloak_core::SecretBytes;
use envcloak_ipc::WireSecret;
use envcloak_ipc::proto::{
    BackupFileParams, FilesBackupParams, VerifyEntry, VerifyFile, VerifyParams,
};
use envcloak_ipc::view::{
    DeleteReport, EntryStatus, FileChange, InitReport, SkipReason, SkippedPath, UndoFile,
    UndoReport, VerifyEntryView, VerifyView,
};
use envcloak_policy::{MANIFEST_NAME, escape_for_display, find_manifest};
use envcloak_scan::{
    DeleteGate, DeleteStep, DotenvEntry, EntryKind, FileKind, FileStamp, MAX_DOTENV,
    ModifyErrorKind, Remains, ScanErrorKind, ScanRoot, create_atomically, delete_plaintext,
    dotenv_kind, open_root, parse_dotenv, pause_point, read_capped, read_plain, restore_file,
    restore_over, trimmed_from, without_entries,
};

use super::import::{ReadFile, edit_gitignore, import, project_name, report, scan};
use super::{fd_number, require_unlocked};

const USAGE_TEXT: &str = "envcloak init [--import] [--yes] [--delete-plaintext] [--json]
       envcloak init --undo <ID> [--passphrase-fd N] [--json]";

/// The parsed command line.
#[derive(Debug, Default, PartialEq, Eq)]
struct InitArgs {
    import: bool,
    yes: bool,
    delete: bool,
    undo: Option<String>,
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
            "--json" if !a.json => a.json = true,
            "--undo" if a.undo.is_none() => a.undo = Some((*it.next()?).to_owned()),
            "--passphrase-fd" if a.passphrase_fd.is_none() => {
                a.passphrase_fd = Some(fd_number(it.next()?)?);
            }
            _ => return None,
        }
    }
    let undo_only = a.undo.is_some() && !a.import && !a.yes && !a.delete;
    let no_undo = a.undo.is_none() && a.passphrase_fd.is_none();
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
        for c in which.iter().filter_map(|&i| self.files.get(i)) {
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
                        Failure::new(
                            "files_backup_failed",
                            "the env files are too large to back up in one request; nothing was \
                             deleted",
                        )
                    }
                    e => Failure::from(e),
                })
            })
            .map_err(Refusal::Client)?;
        self.backup = Some(view.id.clone());
        Ok(view.id)
    }
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
    let statement = format!(
        "Write back the env files of backup {id} into {}. They hold plaintext secrets; a file \
         that exists there now is left alone, and nothing is written anywhere else.\n",
        escape_for_display(&project.path().to_string_lossy())
    );
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
    let restored = connect()?.files_restore(id, passphrase, &claims_now)?;
    let mut report = UndoReport {
        backup: id.to_owned(),
        files: Vec::new(),
    };
    for f in restored.files {
        let state = write_back(&project, &f.path, f.mode, f.content.into_inner());
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

/// Writes one restored file where it was, only when that is an env file
/// (`.env` or `.env.<profile>`, as a deletion takes out) directly in
/// `project`, the directory `init --undo` runs for: a backup any client
/// can store names any path, and the passphrase statement names only that
/// directory. Another name is `not_env_file`, another directory
/// `elsewhere`. A file there already is `unchanged` when it holds the same
/// bytes, replaced (`restored`) when it is what the deletion left of it
/// (the original with some entries taken out, nothing else changed), and
/// `exists` otherwise.
fn write_back(project: &ScanRoot, path: &str, mode: u32, content: SecretBytes) -> &'static str {
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
        Ok((now, stamp)) if trimmed_from(&content, &now) => {
            return match restore_over(&root, rel, &content, &stamp) {
                Ok(_) => "restored",
                Err(e) => e.kind.token(),
            };
        }
        Ok(_) => return "exists",
        Err(e) if e.kind == ScanErrorKind::NotFound => {}
        Err(e) => return e.kind.token(),
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
        for bad in [
            &["--undo"][..],
            &["--undo", "a", "--import"],
            &["--passphrase-fd", "3"],
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
            assert_eq!(write_back(&root, &path, 0o600, body()), want, "{path}");
        }
        for dir in [&project, &other] {
            assert_eq!(std::fs::read_dir(dir).unwrap().count(), 0);
        }
        assert_eq!(
            write_back(&root, &at(&project, ".env.local"), 0o600, body()),
            "restored"
        );
        assert_eq!(std::fs::read(project.join(".env.local")).unwrap(), b"A=1\n");
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
