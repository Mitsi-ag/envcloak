//! The order of gate 16 (SPEC §15.2) in [`delete_plaintext`]: nothing is
//! removed until the gate has verified, the backup is written, and the
//! gate has verified again; a refusal at any of them removes nothing. The
//! daemon's answers to the gate, and `kill -9` at every step, are tested
//! with the real daemon in `crates/envcloak-cli/tests/import.rs`.
#![allow(clippy::unwrap_used)]

use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use envcloak_scan::{
    DeleteGate, DeleteStep, FileStamp, MAX_DOTENV, ModifyErrorKind, delete_plaintext, open_root,
    read_capped,
};

/// A gate that answers from a script and records what it was asked.
struct Scripted {
    /// Answers to verify, in order.
    verify: Vec<bool>,
    backup: bool,
    calls: Vec<&'static str>,
}

impl DeleteGate for Scripted {
    type Refusal = &'static str;

    fn verify(&mut self) -> Result<(), &'static str> {
        self.calls.push("verify");
        if self.verify.remove(0) {
            Ok(())
        } else {
            Err("verify refused")
        }
    }

    fn backup(&mut self) -> Result<String, &'static str> {
        self.calls.push("backup");
        if self.backup {
            Ok("BACKUP1".to_owned())
        } else {
            Err("backup failed")
        }
    }
}

fn setup() -> (tempfile::TempDir, Vec<(PathBuf, FileStamp)>) {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let r = open_root(d.path()).unwrap();
    let mut files = Vec::new();
    for name in [".env", ".env.short"] {
        let p = d.path().join(name);
        std::fs::write(&p, b"A=1\n").unwrap();
        File::options()
            .write(true)
            .open(&p)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(600))
            .unwrap();
        let (_, s) = read_capped(&r, Path::new(name), MAX_DOTENV).unwrap();
        files.push((PathBuf::from(name), s));
    }
    (d, files)
}

#[test]
fn every_refusal_removes_nothing() {
    for (verify, backup, calls, why) in [
        (vec![false], true, vec!["verify"], "verify refused"),
        (vec![true], false, vec!["verify", "backup"], "backup failed"),
        (
            vec![true, false],
            true,
            vec!["verify", "backup", "verify"],
            "verify refused",
        ),
    ] {
        let (d, files) = setup();
        let r = open_root(d.path()).unwrap();
        let mut gate = Scripted {
            verify,
            backup,
            calls: Vec::new(),
        };
        let mut steps = Vec::new();
        let e = delete_plaintext(&r, &files, &mut gate, &mut |s| steps.push(s)).unwrap_err();
        assert_eq!(e, why);
        assert_eq!(gate.calls, calls);
        for (rel, _) in &files {
            assert!(d.path().join(rel).exists(), "{rel:?}");
        }
        assert!(!steps.iter().any(|s| matches!(s, DeleteStep::Removed(_))));
    }
}

#[test]
fn files_go_only_after_verify_backup_and_verify() {
    let (d, files) = setup();
    let r = open_root(d.path()).unwrap();
    let mut gate = Scripted {
        verify: vec![true, true],
        backup: true,
        calls: Vec::new(),
    };
    let mut steps = Vec::new();
    let out = delete_plaintext(&r, &files, &mut gate, &mut |s| steps.push(s)).unwrap();
    assert_eq!(gate.calls, ["verify", "backup", "verify"]);
    assert_eq!(
        steps,
        [
            DeleteStep::Verified,
            DeleteStep::BackedUp,
            DeleteStep::Reverified,
            DeleteStep::Removed(0),
            DeleteStep::Removed(1),
        ]
    );
    assert_eq!(out.backup, "BACKUP1");
    assert_eq!(out.removed.len(), 2);
    assert!(out.kept.is_empty());
    for (rel, _) in &files {
        assert!(!d.path().join(rel).exists());
    }
}

#[test]
fn a_file_changed_since_it_was_read_is_kept() {
    let (d, files) = setup();
    std::fs::write(d.path().join(".env.short"), b"A=2\n").unwrap();
    let r = open_root(d.path()).unwrap();
    let mut gate = Scripted {
        verify: vec![true, true],
        backup: true,
        calls: Vec::new(),
    };
    let out = delete_plaintext(&r, &files, &mut gate, &mut |_| {}).unwrap();
    assert_eq!(out.removed, [PathBuf::from(".env")]);
    assert_eq!(
        out.kept,
        [(PathBuf::from(".env.short"), ModifyErrorKind::Changed)]
    );
    assert_eq!(
        std::fs::read(d.path().join(".env.short")).unwrap(),
        b"A=2\n"
    );
}
