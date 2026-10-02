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
#![allow(clippy::unwrap_used)]

mod common;

use std::io::BufReader;

use common::{Fixture, kill_child, read_stdin, spawn_self, wait_for};
use envcloak_core::SecretBytes;
use envcloak_core::crypto::Vmk;
use envcloak_core::file_backup_v2::{
    BackupCreator, BackupOwner, BackupPurpose, CHUNK_V2, CreatorKind, PlannedFile, StepV2,
    chunk_len, chunks_of, list_file_backups_v2,
};
use envcloak_core::vault::{LockedVault, VaultPaths};
use envcloak_testkit::{Canary, assert_no_canary, canaries, fresh_seed};

const WRITER: &str = "ENVCLOAK_BACKUP_V2_CRASH_DATA";
const HOLD: &str = "ENVCLOAK_BACKUP_V2_CRASH_HOLD";
const SEED: &str = "ENVCLOAK_BACKUP_V2_CRASH_SEED";

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
    let creator = BackupCreator {
        kind: CreatorKind::Terminal,
        evidence_digest: [1; 32],
        agent: None,
        owner: BackupOwner {
            pid: 1234,
            start_time: 1,
            token: None,
        },
    };
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
