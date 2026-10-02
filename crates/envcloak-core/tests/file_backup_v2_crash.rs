//! `kill -9` at each pause point of a file backup v2's begin, put and
//! commit leaves no listed partial backup (M2 plan M2-05): before the
//! staging directory takes its final name nothing is listed, and from then
//! on the backup listed is whole, reads back byte for byte and holds no
//! plaintext. Whatever the kill left, the backups directory holds no
//! fixture.
//!
//! The writer is this test binary, re-run as a child: it opens the vault
//! with the VMK it reads from stdin, writes a backup of two files (three
//! chunks and one), printing each step it passes, and stops at the step
//! the parent names until it is killed there.
//!
//! A result is published whole or not at all: a child records one file's
//! result and is killed at each step of it. At every step, while the
//! child holds there, another reader finds the result absent or whole,
//! never damaged; after the kill the backup still opens, the result is
//! absent before its link and whole from it on, an absent one can be
//! recorded again, and the purge removes whatever the kill left.
#![allow(clippy::unwrap_used)]

mod common;

use std::io::BufReader;

use common::{Fixture, kill_child, read_stdin, spawn_self, wait_for};
use envcloak_core::SecretBytes;
use envcloak_core::crypto::Vmk;
use envcloak_core::file_backup::FileBackupId;
use envcloak_core::file_backup_v2::{
    BackupCreator, BackupOwner, BackupPurpose, CHUNK_V2, CreatorKind, PlannedFile, ResultStepV2,
    StepV2, age_file_backup_v2_for_testing, chunk_len, chunks_of, list_file_backups_v2,
    purge_file_backups_v2,
};
use envcloak_core::vault::{LockedVault, VaultPaths};
use envcloak_testkit::{Canary, assert_no_canary, canaries, fresh_seed};

const WRITER: &str = "ENVCLOAK_BACKUP_V2_CRASH_DATA";
const HOLD: &str = "ENVCLOAK_BACKUP_V2_CRASH_HOLD";
const SEED: &str = "ENVCLOAK_BACKUP_V2_CRASH_SEED";
const RESULT_DATA: &str = "ENVCLOAK_BACKUP_V2_RESULT_DATA";
const RESULT_ID: &str = "ENVCLOAK_BACKUP_V2_RESULT_ID";

/// The steps in the order a backup passes them; a chunk step is reported
/// once per chunk (the hold is at the second one).
const STEPS: [&str; 7] = [
    "staged",
    "started",
    "chunk",
    "metadata",
    "synced",
    "installed",
    "done",
];
/// From this step on, the backup is in place.
const INSTALLED: usize = 5;

fn step_name(s: StepV2) -> &'static str {
    match s {
        StepV2::Staged => "staged",
        StepV2::Started => "started",
        StepV2::Chunk => "chunk",
        StepV2::MetadataWritten => "metadata",
        StepV2::Synced => "synced",
        StepV2::Installed => "installed",
        StepV2::Done => "done",
    }
}

fn creator() -> BackupCreator {
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
    }
}

/// The two files: every fixture of `seed` in each, one across a chunk
/// boundary.
fn bodies(cs: &[Canary]) -> [Vec<u8>; 2] {
    let mut a: Vec<u8> = (0..2 * CHUNK_V2 + 7).map(|i| (i % 251) as u8).collect();
    let mut at = CHUNK_V2 - 10;
    for c in cs {
        let v = c.value();
        a[at..at + v.len()].copy_from_slice(v);
        at += v.len() + 1;
    }
    let b: Vec<u8> = cs.iter().flat_map(|c| c.value().to_vec()).collect();
    [a, b]
}

/// Runs only as the child the test below starts.
#[test]
fn backup_v2_writer_child() {
    let Some(data) = std::env::var_os(WRITER) else {
        return;
    };
    let seed: u64 = std::env::var(SEED).unwrap().parse().unwrap();
    let hold = std::env::var(HOLD).unwrap();
    let cs = canaries(seed);
    let vmk = Vmk::import_for_testing(&read_stdin()).unwrap();
    let paths = VaultPaths::under(std::path::PathBuf::from(data));
    let v = LockedVault::open(&paths)
        .unwrap()
        .unlock(vmk)
        .map_err(|(_, e)| e)
        .unwrap();
    let files = bodies(&cs);
    let plan = files
        .iter()
        .enumerate()
        .map(|(i, b)| PlannedFile {
            path: format!("/h/.claude/projects/p/{i}.jsonl"),
            mode: 0o600,
            size: b.len() as u64,
        })
        .collect();
    let creator = creator();
    let mut chunks = 0;
    let mut w = v
        .begin_file_backup_v2_observed(
            BackupPurpose::Scrub,
            creator,
            plan,
            1_790_000_000,
            move |s| {
                let name = step_name(s);
                println!("@@step {name}");
                if s == StepV2::Chunk {
                    chunks += 1;
                }
                if name == hold && (s != StepV2::Chunk || chunks == 2) {
                    println!("@@hold");
                    std::thread::sleep(std::time::Duration::from_secs(120));
                }
            },
        )
        .unwrap();
    for (i, b) in files.iter().enumerate() {
        for c in 0..chunks_of(b.len() as u64) {
            let start = c as usize * CHUNK_V2;
            let end = start + chunk_len(b.len() as u64, c).unwrap();
            w.put(i, c, &SecretBytes::copy_from(&b[start..end]))
                .unwrap();
        }
    }
    w.commit().unwrap();
    println!("@@finished");
}

#[test]
fn a_kill_at_any_step_leaves_no_listed_partial_backup() {
    if std::env::var_os(WRITER).is_some() {
        return;
    }
    let seed = fresh_seed();
    let cs = canaries(seed);
    let [a, b] = bodies(&cs);
    for (k, step) in STEPS.iter().enumerate() {
        let (f, v) = Fixture::create();
        drop(v);
        let mut child = spawn_self(
            &f.home,
            "backup_v2_writer_child",
            &[(WRITER, &f.data()), (HOLD, step), (SEED, &seed.to_string())],
            &f.vmk,
        );
        let mut out = BufReader::new(child.stdout.take().unwrap());
        assert!(
            wait_for(&mut out, "@@hold").is_some(),
            "the child never reached {step}"
        );
        kill_child(&mut child, step);
        let v = f.unlock();
        let listed = list_file_backups_v2(v.paths()).unwrap();
        if k < INSTALLED {
            assert!(listed.is_empty(), "{step}: {listed:?}");
        } else {
            assert_eq!(listed.len(), 1, "{step}");
            let r = v.open_file_backup_v2(&listed[0].id).unwrap();
            r.verify().unwrap();
            for (i, body) in [&a, &b].into_iter().enumerate() {
                let size = body.len() as u64;
                for c in 0..chunks_of(size) {
                    let (data, _) = r.chunk(i, c).unwrap();
                    let start = c as usize * CHUNK_V2;
                    let end = start + chunk_len(size, c).unwrap();
                    assert!(data.ct_eq(&body[start..end]), "{step}: {i}/{c}");
                }
            }
        }
        // Ciphertext only, whatever was left.
        let mut all = Vec::new();
        let mut dirs = vec![v.paths().backups_dir.clone()];
        while let Some(d) = dirs.pop() {
            for e in std::fs::read_dir(&d).unwrap() {
                let e = e.unwrap();
                if e.file_type().unwrap().is_dir() {
                    dirs.push(e.path());
                } else {
                    all.extend(std::fs::read(e.path()).unwrap());
                }
            }
        }
        assert!(k < INSTALLED || all.len() > 2 * CHUNK_V2, "{step}");
        assert_no_canary(&all, &cs);
        drop(v);
        f.home.assert_clean(&cs);
    }
}

/// The steps of recording a result, in order.
const RESULT_STEPS: [&str; 6] = [
    "created",
    "written",
    "synced",
    "published",
    "unlinked",
    "done",
];
/// From this step on, the result is recorded.
const PUBLISHED: usize = 3;
/// What the change left, as the child records it for file 0.
const AFTER: [u8; 32] = [0x3c; 32];

fn result_step_name(s: ResultStepV2) -> &'static str {
    match s {
        ResultStepV2::Created => "created",
        ResultStepV2::Written => "written",
        ResultStepV2::Synced => "synced",
        ResultStepV2::Published => "published",
        ResultStepV2::Unlinked => "unlinked",
        ResultStepV2::Done => "done",
    }
}

/// Runs only as the child the test below starts: records file 0's result
/// of the backup the parent names, holding at the step it names.
#[test]
fn backup_v2_result_child() {
    let Some(data) = std::env::var_os(RESULT_DATA) else {
        return;
    };
    let hold = std::env::var(HOLD).unwrap();
    let id = FileBackupId::parse(&std::env::var(RESULT_ID).unwrap()).unwrap();
    let vmk = Vmk::import_for_testing(&read_stdin()).unwrap();
    let paths = VaultPaths::under(std::path::PathBuf::from(data));
    let v = LockedVault::open(&paths)
        .unwrap()
        .unlock(vmk)
        .map_err(|(_, e)| e)
        .unwrap();
    let r = v.open_file_backup_v2(&id).unwrap();
    r.record_result_observed(0, &AFTER, |s| {
        let name = result_step_name(s);
        println!("@@step {name}");
        if name == hold {
            println!("@@hold");
            std::thread::sleep(std::time::Duration::from_secs(120));
        }
    })
    .unwrap();
    println!("@@finished");
}

#[test]
fn a_kill_at_any_step_of_a_result_leaves_it_absent_or_whole() {
    if std::env::var_os(WRITER).is_some() || std::env::var_os(RESULT_DATA).is_some() {
        return;
    }
    let seed = fresh_seed();
    let cs = canaries(seed);
    let [a, b] = bodies(&cs);
    for (k, step) in RESULT_STEPS.iter().enumerate() {
        let (f, v) = Fixture::create();
        let plan = [&a, &b]
            .iter()
            .enumerate()
            .map(|(i, body)| PlannedFile {
                path: format!("/h/.claude/projects/p/{i}.jsonl"),
                mode: 0o600,
                size: body.len() as u64,
            })
            .collect();
        let mut w = v
            .begin_file_backup_v2(BackupPurpose::Scrub, creator(), plan, 1_790_000_000)
            .unwrap();
        for (i, body) in [&a, &b].into_iter().enumerate() {
            for c in 0..chunks_of(body.len() as u64) {
                let start = c as usize * CHUNK_V2;
                let end = start + chunk_len(body.len() as u64, c).unwrap();
                w.put(i, c, &SecretBytes::copy_from(&body[start..end]))
                    .unwrap();
            }
        }
        let id = w.commit().unwrap().id;
        // Another reader, kept open while the child records.
        let r = v.open_file_backup_v2(&id).unwrap();
        let paths = v.paths().clone();
        drop(v);
        let mut child = spawn_self(
            &f.home,
            "backup_v2_result_child",
            &[
                (RESULT_DATA, &f.data()),
                (HOLD, step),
                (RESULT_ID, &id.to_string()),
            ],
            &f.vmk,
        );
        let mut out = BufReader::new(child.stdout.take().unwrap());
        assert!(
            wait_for(&mut out, "@@hold").is_some(),
            "the child never reached {step}"
        );
        // Read while the child holds: absent or whole, never damaged.
        let seen = r.results().unwrap_or_else(|e| panic!("{step}: {e:?}"));
        let want = if k < PUBLISHED { None } else { Some(AFTER) };
        assert_eq!(seen, vec![want, None], "{step}, while held");
        kill_child(&mut child, step);
        // After the kill: the backup opens, the result as before.
        let v = f.unlock();
        let again = v.open_file_backup_v2(&id).unwrap();
        assert_eq!(again.results().unwrap(), vec![want, None], "{step}");
        // An absent result is recorded again; a whole one only once.
        let second = again.record_result(0, &AFTER);
        if k < PUBLISHED {
            second.unwrap();
        } else {
            assert_eq!(
                second.unwrap_err().kind(),
                envcloak_core::vault::VaultErrorKind::AlreadyExists,
                "{step}"
            );
        }
        assert_eq!(again.results().unwrap(), vec![Some(AFTER), None]);
        // The purge removes the backup, temporary names included.
        let dir = list_file_backups_v2(&paths).unwrap().remove(0).dir;
        age_file_backup_v2_for_testing(&dir, 1).unwrap();
        assert_eq!(purge_file_backups_v2(&paths, 1_790_000_000).unwrap(), 1);
        assert!(!dir.exists(), "{step}: the purge left {dir:?}");
        drop(r);
        drop(v);
        f.home.assert_clean(&cs);
    }
}
