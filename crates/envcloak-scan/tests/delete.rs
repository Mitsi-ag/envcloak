//! The order of gate 16 (SPEC §15.2) in [`delete_plaintext`]: nothing is
//! changed until the gate has verified, the backup is written, and the
//! gate has verified again; a refusal at any of them changes nothing. Only
//! the entries the vault holds leave a file: a file is removed when the
//! vault holds all of them, rewritten to hold the rest when it holds some,
//! and left as it is (and not backed up) when it holds none. The daemon's
//! answers to the gate, and `kill -9` at every step, are tested with the
//! real daemon and CLI in `crates/envcloak-cli/tests/import.rs`.
#![allow(clippy::unwrap_used)]

use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use envcloak_core::SecretBytes;
use envcloak_scan::{
    DeleteGate, DeleteStep, FileStamp, MAX_DOTENV, ModifyErrorKind, Remains, delete_plaintext,
    open_root, read_capped,
};

/// What the scripted gate says a file keeps.
#[derive(Clone, Copy)]
enum Keep {
    Nothing,
    Some(&'static [u8]),
    Everything,
}

/// A gate that answers from a script and records what it was asked.
struct Scripted {
    /// Answers to verify, in order.
    verify: Vec<bool>,
    backup: bool,
    keep: Vec<Keep>,
    calls: Vec<String>,
}

impl DeleteGate for Scripted {
    type Refusal = &'static str;

    fn verify(&mut self) -> Result<(), &'static str> {
        self.calls.push("verify".into());
        if self.verify.remove(0) {
            Ok(())
        } else {
            Err("verify refused")
        }
    }

    fn remains(&self, i: usize) -> Remains {
        match self.keep[i] {
            Keep::Nothing => Remains::Nothing,
            Keep::Some(b) => Remains::Bytes(SecretBytes::copy_from(b)),
            Keep::Everything => Remains::Everything,
        }
    }

    fn backup(&mut self, which: &[usize]) -> Result<String, &'static str> {
        self.calls.push(format!("backup {which:?}"));
        if self.backup {
            Ok("BACKUP1".to_owned())
        } else {
            Err("backup failed")
        }
    }
}

fn gate(verify: Vec<bool>, backup: bool, keep: Vec<Keep>) -> Scripted {
    Scripted {
        verify,
        backup,
        keep,
        calls: Vec::new(),
    }
}

const BODY: &[u8] = b"KEY=k1\nPORT=8080\n";

fn setup(names: &[&str]) -> (tempfile::TempDir, Vec<(PathBuf, FileStamp)>) {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let r = open_root(d.path()).unwrap();
    let mut files = Vec::new();
    for name in names {
        let p = d.path().join(name);
        std::fs::write(&p, BODY).unwrap();
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
fn every_refusal_changes_nothing() {
    for (verify, backup, calls, why) in [
        (vec![false], true, vec!["verify"], "verify refused"),
        (
            vec![true],
            false,
            vec!["verify", "backup [0, 1]"],
            "backup failed",
        ),
        (
            vec![true, false],
            true,
            vec!["verify", "backup [0, 1]", "verify"],
            "verify refused",
        ),
    ] {
        let (d, files) = setup(&[".env", ".env.short"]);
        let r = open_root(d.path()).unwrap();
        let mut g = gate(
            verify,
            backup,
            vec![Keep::Some(b"PORT=8080\n"), Keep::Nothing],
        );
        let mut steps = Vec::new();
        let e = delete_plaintext(&r, &files, &mut g, &mut |s| steps.push(s)).unwrap_err();
        assert_eq!(e, why);
        assert_eq!(g.calls, calls);
        for (rel, _) in &files {
            assert_eq!(std::fs::read(d.path().join(rel)).unwrap(), BODY, "{rel:?}");
        }
        assert!(!steps.iter().any(|s| matches!(
            s,
            DeleteStep::Removed(_)
                | DeleteStep::Rewritten(_)
                | DeleteStep::MovedAside(_)
                | DeleteStep::Staged(_)
        )));
    }
}

#[test]
fn files_change_only_after_verify_backup_and_verify() {
    let (d, files) = setup(&[".env", ".env.local", ".env.short"]);
    let r = open_root(d.path()).unwrap();
    let mut g = gate(
        vec![true, true],
        true,
        vec![Keep::Some(b"PORT=8080\n"), Keep::Everything, Keep::Nothing],
    );
    let mut steps = Vec::new();
    let out = delete_plaintext(&r, &files, &mut g, &mut |s| steps.push(s)).unwrap();
    // The file that keeps everything is neither backed up nor touched.
    assert_eq!(g.calls, ["verify", "backup [0, 2]", "verify"]);
    assert_eq!(
        steps,
        [
            DeleteStep::Verified,
            DeleteStep::BackedUp,
            DeleteStep::Reverified,
            DeleteStep::Staged(0),
            DeleteStep::Rewritten(0),
            DeleteStep::MovedAside(2),
            DeleteStep::Removed(2),
        ]
    );
    assert_eq!(out.backup.as_deref(), Some("BACKUP1"));
    assert_eq!(out.rewritten, [PathBuf::from(".env")]);
    assert_eq!(out.removed, [PathBuf::from(".env.short")]);
    assert_eq!(out.unchanged, [PathBuf::from(".env.local")]);
    assert!(out.kept.is_empty());
    assert_eq!(
        std::fs::read(d.path().join(".env")).unwrap(),
        b"PORT=8080\n"
    );
    assert_eq!(std::fs::read(d.path().join(".env.local")).unwrap(), BODY);
    assert!(!d.path().join(".env.short").exists());
}

#[test]
fn nothing_to_take_out_writes_no_backup() {
    let (d, files) = setup(&[".env"]);
    let r = open_root(d.path()).unwrap();
    let mut g = gate(vec![true], true, vec![Keep::Everything]);
    let out = delete_plaintext(&r, &files, &mut g, &mut |_| {}).unwrap();
    assert_eq!(g.calls, ["verify"]);
    assert_eq!(out.backup, None);
    assert_eq!(out.unchanged, [PathBuf::from(".env")]);
    assert_eq!(std::fs::read(d.path().join(".env")).unwrap(), BODY);
}

#[test]
fn a_file_changed_since_it_was_read_is_kept() {
    let (d, files) = setup(&[".env", ".env.short"]);
    std::fs::write(d.path().join(".env.short"), b"A=2\n").unwrap();
    std::fs::write(d.path().join(".env"), b"A=3\n").unwrap();
    let r = open_root(d.path()).unwrap();
    let mut g = gate(
        vec![true, true],
        true,
        vec![Keep::Some(b"PORT=8080\n"), Keep::Nothing],
    );
    let out = delete_plaintext(&r, &files, &mut g, &mut |_| {}).unwrap();
    assert!(out.removed.is_empty() && out.rewritten.is_empty());
    assert_eq!(
        out.kept,
        [
            (PathBuf::from(".env"), ModifyErrorKind::Changed),
            (PathBuf::from(".env.short"), ModifyErrorKind::Changed),
        ]
    );
    assert_eq!(std::fs::read(d.path().join(".env")).unwrap(), b"A=3\n");
    assert_eq!(
        std::fs::read(d.path().join(".env.short")).unwrap(),
        b"A=2\n"
    );
}
