//! Making a backup opens `backups/` itself, through the data directory,
//! and never acts on a path resolved before it was opened (L-11; the class
//! of the M2-05 review's finding: a path resolved before a no-follow
//! check). A test build stops a child process right after the path checks
//! and before `backups/` is opened (`ENVCLOAK_TEST_PAUSE=backups.open`);
//! the parent moves `backups/`, or the data directory that holds it, away
//! and puts a symlink to it in its place, then lets the child go on. A v1
//! file backup, a backup v2's begin and a vault backup each fail
//! (`Path(Symlink)`), and nothing in the moved directory changes: no
//! backup or staging directory is made there, and no temporary file an
//! interrupted backup left there is removed.
#![allow(clippy::unwrap_used)]

mod common;

use std::io::{BufRead, BufReader, Read};
use std::path::Path;

use common::{KitFixture, read_stdin, spawn_self};
use envcloak_core::SecretBytes;
use envcloak_core::crypto::Vmk;
use envcloak_core::file_backup::{BackupFile, FileBackupCreator};
use envcloak_core::file_backup_v2::{
    BackupCreator, BackupOwner, BackupPurpose, CreatorKind, PlannedFile,
};
use envcloak_core::vault::{LockedVault, VaultPaths};

const DATA: &str = "ENVCLOAK_BACKUPS_RACE_DATA";
const WHICH: &str = "ENVCLOAK_BACKUPS_RACE_WHICH";

/// Runs only as the child the test below starts: opens the vault with the
/// VMK it reads from stdin, makes the backup `WHICH` names, and prints the
/// error kind it got (`None` when it went through).
#[test]
fn backups_race_child() {
    let Some(data) = std::env::var_os(DATA) else {
        return;
    };
    let vmk = Vmk::import_for_testing(&read_stdin()).unwrap();
    let paths = VaultPaths::under(std::path::PathBuf::from(data));
    let v = LockedVault::open(&paths)
        .unwrap()
        .unlock(vmk)
        .map_err(|(_, e)| e)
        .unwrap();
    let kind = match std::env::var(WHICH).unwrap().as_str() {
        "v1" => v
            .backup_files(
                &[BackupFile {
                    path: "/p/.env".into(),
                    mode: 0o600,
                    content: SecretBytes::copy_from(b"A=1\n"),
                    left: None,
                }],
                &FileBackupCreator {
                    kind: CreatorKind::Terminal,
                    agent: None,
                },
            )
            .map(drop),
        "v2" => v
            .begin_file_backup_v2(
                BackupPurpose::Init,
                BackupCreator {
                    kind: CreatorKind::Terminal,
                    evidence_digest: [1; 32],
                    agent: None,
                    owner: BackupOwner {
                        pid: 1234,
                        start_time: 1,
                        token: None,
                        boot: None,
                    },
                    chain: Vec::new(),
                },
                vec![PlannedFile {
                    path: "/p/.env".into(),
                    mode: 0o600,
                    size: 4,
                }],
                1_790_000_000,
            )
            // Kept open while the result is printed: a staging directory
            // made through the symlink would still be there.
            .map(|w| {
                println!("@@result None");
                std::mem::forget(w);
            }),
        "vault" => v.create_backup().map(drop),
        other => panic!("{other}"),
    }
    .err()
    .map(|e| e.kind());
    println!("@@result {kind:?}");
}

/// Makes the backup `which` in a child stopped before `backups/` opens,
/// with `swapped` (`backups/` or the data directory) moved away and a
/// symlink to it put in its place meanwhile.
fn race(which: &str, swap_data_dir: bool) {
    let (f, v) = KitFixture::create();
    let backups = f.paths.backups_dir.clone();
    v.backup_files(
        &[BackupFile {
            path: "/p/.env".into(),
            mode: 0o600,
            content: SecretBytes::copy_from(b"B=2\n"),
            left: None,
        }],
        &FileBackupCreator {
            kind: CreatorKind::Terminal,
            agent: None,
        },
    )
    .unwrap();
    std::fs::write(
        backups.join(".vault-20260901T000000Z-00000000.ecbackup.tmp"),
        b"what an interrupted vault backup left",
    )
    .unwrap();
    std::fs::write(
        backups.join(".files-20260901T000000Z-A.ecfiles.tmp"),
        b"what an interrupted file backup left",
    )
    .unwrap();
    // The child takes the vault's lock.
    drop(v);
    let before = common::tree(&backups);
    let release = f.home.root().join("release");
    let data = f.paths.data_dir.to_str().unwrap().to_owned();
    let mut child = spawn_self(
        &f.home,
        "backups_race_child",
        &[
            (DATA, &data),
            (WHICH, which),
            ("ENVCLOAK_TEST_PAUSE", "backups.open"),
            ("ENVCLOAK_TEST_PAUSE_RELEASE", release.to_str().unwrap()),
        ],
        &f.vmk,
    );
    let mut err = BufReader::new(child.stderr.take().unwrap());
    let mut line = String::new();
    loop {
        line.clear();
        assert!(
            err.read_line(&mut line).unwrap() > 0,
            "{which}: the child never stopped before backups/ opened"
        );
        if line.contains("paused at backups.open") {
            break;
        }
    }
    let swapped = if swap_data_dir {
        f.paths.data_dir.clone()
    } else {
        backups.clone()
    };
    let elsewhere = f.home.root().join("elsewhere");
    std::fs::rename(&swapped, &elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &swapped).unwrap();
    std::fs::write(&release, b"").unwrap();
    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    let mut rest = String::new();
    let _ = err.read_to_string(&mut rest);
    assert!(child.wait().unwrap().success(), "{which}: {rest}");
    let moved = if swap_data_dir {
        elsewhere.join("backups")
    } else {
        elsewhere.clone()
    };
    assert_eq!(
        common::tree(&moved),
        before,
        "{which}: a backup acted through a symlink put in place of {}",
        Path::new(&swapped).display()
    );
    let result = out
        .lines()
        .find_map(|l| l.find("@@result ").map(|at| l[at + 9..].trim()))
        .unwrap();
    assert_eq!(result, "Some(Path(Symlink))", "{which}");
    std::fs::remove_file(&swapped).unwrap();
    std::fs::rename(&elsewhere, &swapped).unwrap();
}

#[test]
fn a_file_backup_opens_backups_itself() {
    race("v1", false);
    race("v1", true);
}

#[test]
fn a_backup_v2_opens_backups_itself() {
    race("v2", false);
    race("v2", true);
}

#[test]
fn a_vault_backup_opens_backups_itself() {
    race("vault", false);
    race("vault", true);
}
