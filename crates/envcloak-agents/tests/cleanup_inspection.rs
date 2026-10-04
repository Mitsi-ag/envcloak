//! Cleanup that could not be confirmed makes install and uninstall
//! incomplete (F123: a directory that could not be listed was read as
//! empty, and the report said complete while a leftover of a stopped
//! write, which can hold part of a config, was still there).
//!
//! An independent oracle through the public API only (`install::apply`
//! and `install::uninstall` with the real writer, a journal and backups
//! that count). A config the writer was writing has its stopped write's
//! record; the directory holding it is then made unlistable, removed,
//! replaced by a file, left as it is with nothing there, or holding a
//! file of the temporary name's shape that is not EnvCloak's. Ten cases,
//! install and project uninstall for each, with these expectations:
//!
//! | The directory | Complete |
//! |---|---|
//! | cannot be listed | no, the record kept; complete once it can be |
//! | not there | yes |
//! | a file, not a directory | no, the record kept; complete once it is one |
//! | listed, nothing left | yes |
//! | holding a foreign file of that shape | no, the file named and kept |
//!
//! Each case checks its own capability first (the mode stops a listing,
//! the directory is gone), the install's or uninstall's own work, that the
//! config and the foreign bytes are kept, and that the retry completes
//! where one is expected to.
//!
//! Mutation checked: `Writer::cleanup_inspection` reading a directory it
//! cannot list as empty: the unlistable and the replaced cases report
//! complete, and this fails.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use envcloak_agents::install::{self, Context, Options, Plan, ProjectPlan, Step, StepKind};
use envcloak_agents::locations::Locations;
use envcloak_agents::writer::{Backups, Journal, Refusal, State, Writer};

fn temp(dir: &Path, name: &str, what: &str, hex: &str) -> PathBuf {
    dir.join(format!(".{name}.envcloak-{what}-{hex}.tmp"))
}

#[derive(Default)]
struct Counter {
    saves: usize,
    backups: usize,
    records: usize,
}

impl Journal for Counter {
    fn save(&mut self, _: &State) -> Result<(), Refusal> {
        self.saves += 1;
        Ok(())
    }
}

impl Backups for Counter {
    fn back_up(&mut self, _: &Path, _: &[u8], _: u32) -> Result<String, Refusal> {
        self.backups += 1;
        Ok("synthetic-backup".to_owned())
    }
    fn record(&mut self, _: &str, _: &[u8]) -> Result<(), Refusal> {
        self.records += 1;
        Ok(())
    }
}

/// Gives a directory its mode back however the case ends.
struct RestoreMode {
    path: PathBuf,
    mode: u32,
}

impl Drop for RestoreMode {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(self.mode));
    }
}

fn operate(
    ctx: &Context<'_>,
    active: &Path,
    uninstall: bool,
    state: &mut State,
    journal: &mut Counter,
    backups: &mut Counter,
) -> install::Report {
    let mut writer = Writer {
        state,
        journal,
        backups,
        now: SystemTime::now(),
    };
    if uninstall {
        install::uninstall(
            &Options {
                project: Some(active.to_path_buf()),
                ..Options::default()
            },
            &mut writer,
        )
    } else {
        let plan = Plan {
            hosts: Vec::new(),
            project: Some(ProjectPlan {
                dir: active.to_path_buf(),
                notes: Vec::new(),
                readers: Vec::new(),
                steps: vec![Step {
                    what: "owned fixture note".to_owned(),
                    path: active.join("note.md"),
                    kind: StepKind::OwnFile {
                        content: "fixture-note\n".to_owned(),
                    },
                }],
            }),
        };
        install::apply(ctx, &plan, &mut writer)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Unlistable,
    Missing,
    NotADirectory,
    Empty,
    Foreign,
}

const MODES: [Mode; 5] = [
    Mode::Unlistable,
    Mode::Missing,
    Mode::NotADirectory,
    Mode::Empty,
    Mode::Foreign,
];

/// One case; `false` when this user cannot be stopped from listing a
/// directory (root), so there is nothing to measure.
fn run_case(parent: &Path, id: usize, uninstall: bool, mode: Mode) -> bool {
    let root = parent.join(format!("cleanup-{id}"));
    std::fs::create_dir(&root).unwrap();
    let active = root.join("active");
    std::fs::create_dir(&active).unwrap();
    let dir = root.join("pending");
    std::fs::create_dir(&dir).unwrap();
    let marker: String = (0..40)
        .map(|n| char::from(b'a' + ((n * 7 + id) % 26) as u8))
        .collect();
    let full = format!("{{\"fixture\":\"{marker}\"}}\n").into_bytes();
    let target = dir.join("config.json");
    std::fs::write(&target, &full).unwrap();
    let artifact = temp(&dir, "config.json", "new", "1234567890abcdef");
    let partial = full[..full.len() - 2].to_vec();
    let (mut state, mut journal, mut backups) =
        (State::default(), Counter::default(), Counter::default());
    let home = root.clone().into_os_string();
    let env = move |k: &str| (k == "HOME").then(|| home.clone());
    let ctx = Context {
        locations: Locations::new(&env).unwrap(),
        envcloak: root.join("envcloak"),
        data_dir: root.join("data"),
        socket: root.join("socket"),
        path: std::ffi::OsString::new(),
        env: &env,
    };
    if uninstall {
        // Positive control: the note uninstall takes out is installed.
        let report = operate(&ctx, &active, false, &mut state, &mut journal, &mut backups);
        assert!(report.complete(), "{id}: {report:?}");
        assert_eq!(
            std::fs::read(active.join("note.md")).unwrap(),
            b"fixture-note\n"
        );
    }
    let key = target.to_string_lossy().into_owned();
    state
        .leftovers
        .insert(key.clone(), vec![install::digest(&full)]);
    let original = if mode == Mode::Foreign {
        b"foreign-content".to_vec()
    } else {
        partial.clone()
    };
    if mode != Mode::Empty {
        std::fs::write(&artifact, &original).unwrap();
    }
    let restore = RestoreMode {
        path: dir.clone(),
        mode: 0o700,
    };
    match mode {
        Mode::Unlistable => {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
            if std::fs::read_dir(&dir).is_ok() {
                drop(restore);
                std::fs::remove_dir_all(&root).unwrap();
                return false;
            }
            assert_eq!(
                std::fs::read_dir(&dir).unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            );
        }
        Mode::Missing => {
            std::fs::remove_dir_all(&dir).unwrap();
            assert_eq!(
                std::fs::read_dir(&dir).unwrap_err().kind(),
                std::io::ErrorKind::NotFound
            );
        }
        Mode::NotADirectory => {
            std::fs::remove_dir_all(&dir).unwrap();
            std::fs::write(&dir, b"person-owned").unwrap();
            assert!(std::fs::read_dir(&dir).is_err());
        }
        Mode::Empty | Mode::Foreign => {}
    }
    let report = operate(
        &ctx,
        &active,
        uninstall,
        &mut state,
        &mut journal,
        &mut backups,
    );
    let pending = state.leftovers.contains_key(&key);
    // The run's own work was done.
    if uninstall {
        assert!(!active.join("note.md").exists(), "{id}");
    } else {
        assert_eq!(
            std::fs::read(active.join("note.md")).unwrap(),
            b"fixture-note\n"
        );
    }
    drop(restore);
    // The config, the person's file and the foreign bytes kept.
    match mode {
        Mode::NotADirectory => assert_eq!(std::fs::read(&dir).unwrap(), b"person-owned"),
        Mode::Missing => assert!(!dir.exists()),
        _ => assert_eq!(std::fs::read(&target).unwrap(), full),
    }
    if artifact.exists() {
        assert_eq!(std::fs::read(&artifact).unwrap(), original, "{id}");
    }
    let expected_complete = matches!(mode, Mode::Missing | Mode::Empty);
    assert_eq!(
        report.complete(),
        expected_complete,
        "{id} {mode:?}: {report:?}"
    );
    match mode {
        Mode::Unlistable => {
            assert!(
                artifact.exists() && pending && report.leftovers.is_empty(),
                "{id}"
            );
            assert_eq!(report.cleanup_unconfirmed, vec![dir.clone()], "{id}");
        }
        Mode::NotADirectory => {
            assert!(pending && report.leftovers.is_empty(), "{id}");
            assert_eq!(report.cleanup_unconfirmed, vec![dir.clone()], "{id}");
        }
        Mode::Foreign => {
            assert!(artifact.exists() && pending, "{id}");
            assert_eq!(report.leftovers, vec![artifact.clone()], "{id}");
            assert!(report.cleanup_unconfirmed.is_empty(), "{id}");
        }
        Mode::Missing | Mode::Empty => {
            assert!(report.leftovers.is_empty() && report.cleanup_unconfirmed.is_empty());
        }
    }
    // Access back, the directory a directory again: the retry completes.
    if matches!(mode, Mode::Unlistable | Mode::NotADirectory) {
        if mode == Mode::NotADirectory {
            std::fs::remove_file(&dir).unwrap();
            std::fs::create_dir(&dir).unwrap();
            std::fs::write(&target, &full).unwrap();
            std::fs::write(&artifact, &partial).unwrap();
        }
        let retry = operate(
            &ctx,
            &active,
            uninstall,
            &mut state,
            &mut journal,
            &mut backups,
        );
        assert!(retry.complete(), "{id}: {retry:?}");
        assert!(!artifact.exists(), "{id}");
        assert!(!state.leftovers.contains_key(&key), "{id}");
        assert_eq!(std::fs::read(&target).unwrap(), full);
    }
    std::fs::remove_dir_all(&root).unwrap();
    true
}

#[test]
fn cleanup_that_cannot_be_confirmed_leaves_install_and_uninstall_incomplete() {
    let dir = tempfile::tempdir().unwrap();
    let parent = std::fs::canonicalize(dir.path()).unwrap();
    let mut measured = 0;
    for (id, (uninstall, mode)) in [false, true]
        .into_iter()
        .flat_map(|u| MODES.into_iter().map(move |m| (u, m)))
        .enumerate()
    {
        if run_case(&parent, id, uninstall, mode) {
            measured += 1;
        }
    }
    // Only the unlistable cases are skipped as root.
    assert!(measured >= 8, "{measured}");
}
