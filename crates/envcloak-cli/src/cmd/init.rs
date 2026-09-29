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
//!   none, and reports the env files it found. It reads no value.
//! - `--import` sends the files' values to the daemon for a plan and
//!   reports it: a dry run. With `--yes` the daemon commits that plan, and
//!   the manifest, `.gitignore` and the dry run of the references follow,
//!   as `envcloak import --yes` does.
//! - `--delete-plaintext` deletes the imported env files, only after all
//!   four conditions of SPEC §6.4 hold, in the order of
//!   [`envcloak_scan::delete_plaintext`]: the daemon confirms each secret
//!   in each file is committed where the manifest binds its variable,
//!   every reference resolves, and the Recovery Kit is confirmed
//!   (`envcloak recovery confirm`); an encrypted backup of the files is
//!   written; the daemon confirms again; then each file is removed, only
//!   if it is the file read, was not modified in the last two minutes, and
//!   is open nowhere else. Templates, references-only files and files
//!   with another hard link are never deleted. Entries that are not
//!   secrets (a port, a flag) go with the file and stay in its backup; the
//!   report names them. The report ends with the backup's id.
//! - `--undo <ID>` writes the files of that backup back, byte for byte,
//!   where they were. That hands plaintext back, so it is a proof: the
//!   passphrase, from `/dev/tty` or `--passphrase-fd`, in a terminal
//!   session with no agent in it. A file that exists is never replaced.
//!
//! Deletion removes the working copy only: a value that was committed to
//! git, synced or backed up elsewhere is still there, and the report says
//! to rotate it.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use envcloak_core::SecretBytes;
use envcloak_ipc::WireSecret;
use envcloak_ipc::proto::{
    BackupFileParams, FilesBackupParams, VerifyEntry, VerifyFile, VerifyParams,
};
use envcloak_ipc::view::{
    DeleteReport, FileChange, InitReport, SkippedPath, UndoFile, UndoReport, VerifyView,
};
use envcloak_policy::{MANIFEST_NAME, find_manifest};
use envcloak_scan::{
    DeleteGate, EntryKind, FileStamp, MAX_DOTENV, ModifyErrorKind, ScanErrorKind, ScanRoot,
    create_atomically, delete_plaintext, open_root, parse_dotenv, read_capped, read_plain,
    restore_file,
};

use super::import::{ReadFile, import, project_name, report, scan};
use super::{claims, fd_number, refuse_if_claimed, require_unlocked};
use crate::connect::connect;
use crate::fail::{FAILURE, Failure, refuse_if_traced, usage};
use crate::render::print;
use crate::tty::{Terminal, read_secret_fd};

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
    let delete = if a.delete { Some(delete(&root)?) } else { None };
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

/// The daemon's side of the gate, for the files in `files`.
struct Gate<'a> {
    root: &'a ScanRoot,
    manifest: String,
    files: Vec<&'a ReadFile>,
    last: Option<VerifyView>,
    backup: Option<String>,
}

impl Gate<'_> {
    fn params(&self) -> VerifyParams {
        VerifyParams {
            manifest: self.manifest.clone(),
            files: self
                .files
                .iter()
                .map(|f| VerifyFile {
                    file: f.file_name().to_owned(),
                    profile: f.profile.as_ref().map(|p| p.as_str().to_owned()),
                    entries: parse_dotenv(&f.bytes)
                        .map(|entries| {
                            entries
                                .into_iter()
                                .filter(|e| e.kind == EntryKind::Plain)
                                .map(|e| VerifyEntry {
                                    line: e.line,
                                    name: e.name.as_str().to_owned(),
                                    value: WireSecret::new(e.value),
                                })
                                .collect()
                        })
                        .unwrap_or_default(),
                })
                .collect(),
        }
    }
}

impl DeleteGate for Gate<'_> {
    type Refusal = Refusal;

    fn verify(&mut self) -> Result<(), Refusal> {
        let view = connect()
            .and_then(|mut c| c.import_verify(&self.params()).map_err(Failure::from))
            .map_err(Refusal::Client)?;
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
        refusal.map_or(Ok(()), |f| Err(Refusal::Gate(f)))
    }

    fn backup(&mut self) -> Result<String, Refusal> {
        let changed = || {
            Refusal::Gate(Failure::new(
                "changed",
                "an env file changed while it was being deleted; nothing was deleted",
            ))
        };
        let mut files = Vec::with_capacity(self.files.len());
        for f in &self.files {
            // Read again, and only if it is still the file checked.
            let (bytes, stamp) =
                read_capped(self.root, &f.rel, MAX_DOTENV).map_err(|_| changed())?;
            if stamp != f.stamp {
                return Err(changed());
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

/// Deletes the project's imported env files. See the module
/// documentation. Returns the report, and the failure to end with when
/// the gate refused or a file was kept.
fn delete(root: &ScanRoot) -> Result<(DeleteReport, Option<Failure>), Failure> {
    let manifest = root.path().join(MANIFEST_NAME);
    if read_plain(root, Path::new(MANIFEST_NAME), 64 * 1024).is_err() {
        return Err(Failure::new(
            "no_manifest",
            "there is no envcloak.toml here to check the env files against; run `envcloak init \
             --import --yes` first. Nothing was deleted",
        ));
    }
    let mut client = connect()?;
    require_unlocked(&mut client)?;
    refuse_if_traced()?;
    let (projects, mut skipped) = scan(root, false);
    let mut files: Vec<&ReadFile> = Vec::new();
    for f in projects.iter().flat_map(|p| p.files.iter()) {
        let why = if f.template || f.references_only() {
            continue;
        } else if f.hard_linked {
            "hard_linked"
        } else if f.parsed.is_err() {
            "invalid"
        } else {
            files.push(f);
            continue;
        };
        skipped.push(SkippedPath {
            path: f.rel.to_string_lossy().into_owned(),
            reason: why.to_owned(),
        });
    }
    let mut report = DeleteReport {
        project_dir: root.path().to_string_lossy().into_owned(),
        verify: VerifyView {
            recovery_confirmed: false,
            resolves: false,
            files: Vec::new(),
        },
        backup: None,
        removed: Vec::new(),
        kept: Vec::new(),
        skipped,
    };
    if files.is_empty() {
        return Ok((report, None));
    }
    let stamps: Vec<(PathBuf, FileStamp)> =
        files.iter().map(|f| (f.rel.clone(), f.stamp)).collect();
    let mut gate = Gate {
        root,
        manifest: manifest.to_string_lossy().into_owned(),
        files,
        last: None,
        backup: None,
    };
    let outcome = delete_plaintext(root, &stamps, &mut gate, &mut |_| {});
    if let Some(v) = gate.last.take() {
        report.verify = v;
    }
    report.backup = gate.backup.take();
    match outcome {
        Err(Refusal::Gate(f)) => Ok((report, Some(f))),
        Err(Refusal::Client(f)) => Err(f),
        Ok(done) => {
            report.backup = Some(done.backup);
            report.removed = done
                .removed
                .iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect();
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
    require_unlocked(&mut connect()?)?;
    let statement = format!(
        "Write back the files of backup {id}. They hold plaintext secrets, and are written \
         where they were; a file that exists there now is left alone.\n"
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
        let state = write_back(&f.path, f.mode, f.content.into_inner());
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

/// Writes one restored file where it was, unless a file is there: then
/// `unchanged` when it holds the same bytes, `exists` otherwise.
fn write_back(path: &str, mode: u32, content: SecretBytes) -> &'static str {
    let p = Path::new(path);
    let (Some(dir), Some(name)) = (p.parent(), p.file_name()) else {
        return "invalid_path";
    };
    if !p.is_absolute() || path.chars().any(char::is_control) {
        return "invalid_path";
    }
    let Ok(root) = open_root(dir) else {
        return "no_directory";
    };
    let rel = Path::new(name);
    match read_capped(&root, rel, content.len().max(MAX_DOTENV)) {
        Ok((now, _)) if now.ct_eq_secret(&content) => return "unchanged",
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
