//! Gate 11 over file backup v2 chunks: writing a backup chunk by chunk,
//! opening it, checking it, reading every chunk back and recording a
//! result never free a block that still holds a fixture.
//!
//! `ProbeMode::Unwiped` turns the allocator's own wipe off, so it checks
//! that the backup code wipes every buffer it fills with a file's bytes
//! (each chunk, the hasher's state); the `ProbeMode::Wiping` pass is the
//! gate as written. The fixtures sit inside chunks and across a chunk
//! boundary, and each file ends with one in the last part of a block its
//! SHA-256 has not taken yet, which the hasher keeps in its own state.
//!
//! The writer is boxed as the daemon keeps it (`Arc<Mutex<Option<Box<
//! FileBackupV2Writer>>>>`), so its hasher's state is in a block the probe
//! sees freed; on the stack it never would be (Codex, M2-05 round 12: the
//! probe passed whatever the hasher left). Writers are dropped committed,
//! sealed and not put in place, and part written, each holding a file's
//! last bytes in its hasher's state; the reader is shared as the daemon's
//! lease shares it. A negative control shows the probe sees a hasher's
//! state freed without its wipe. One test, so no other test's allocations
//! run while the probe is armed.
#![allow(clippy::unwrap_used)]

mod common;

use std::mem::ManuallyDrop;
use std::sync::{Arc, Mutex};

use common::Fixture;
use envcloak_core::SecretBytes;
use envcloak_core::file_backup_v2::{
    BackupCreator, BackupOwner, BackupPurpose, CHUNK_V2, CreatorKind, FileBackupV2Writer,
    PlannedFile, chunk_len, chunks_of,
};
use envcloak_testkit::{
    Canary, ProbeAllocator, ProbeMode, by_label, canaries, fresh_seed, labels, probe_canaries,
};
use sha2::{Digest, Sha256};

#[global_allocator]
static ALLOCATOR: ProbeAllocator = ProbeAllocator;

/// How far a backup's writer gets before it is dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Until {
    /// Committed.
    Committed,
    /// Sealed, never put in place.
    Sealed,
    /// Its first file whole and the first chunk of its second, then
    /// dropped.
    PartWritten,
}

/// The files of a backup: a short one of fixtures alone, and one of three
/// chunks with every fixture, one across the first boundary; each ends
/// with `tail` in the last part of a block of 64 bytes (the SHA-256
/// block), so that its hasher keeps `tail` in its own state once the file
/// is in, and while the next file's first chunk (whole blocks) goes in.
fn bodies(cs: &[Canary], tail: &[u8]) -> [Vec<u8>; 2] {
    let mut big = vec![b'.'; 2 * CHUNK_V2 + 64];
    let mut at = CHUNK_V2 - 20;
    for c in cs {
        big[at..at + c.value().len()].copy_from_slice(c.value());
        at += c.value().len();
    }
    big.extend_from_slice(tail);
    let mut small: Vec<u8> = cs.iter().flat_map(|c| c.value().to_vec()).collect();
    small.resize(small.len().next_multiple_of(64), b'.');
    small.extend_from_slice(tail);
    [small, big]
}

/// Each file's chunks, made before the probe is armed, as a client's would
/// arrive; each is wiped when it is dropped.
fn chunks_of_files(files: &[Vec<u8>]) -> Vec<Vec<SecretBytes>> {
    files
        .iter()
        .map(|b| {
            let size = b.len() as u64;
            (0..chunks_of(size))
                .map(|c| {
                    let start = c as usize * CHUNK_V2;
                    let end = start + chunk_len(size, c).unwrap();
                    SecretBytes::copy_from(&b[start..end])
                })
                .collect()
        })
        .collect()
}

fn creator() -> BackupCreator {
    BackupCreator {
        kind: CreatorKind::Agent,
        evidence_digest: [2; 32],
        agent: Some("Codex".into()),
        owner: BackupOwner {
            pid: 7,
            start_time: 8,
            token: None,
            boot: None,
        },
        chain: Vec::new(),
    }
}

/// Writes a backup of `chunks` (files of `sizes`) as far as `until`, the
/// writer held as the daemon holds it, and drops it there; once
/// committed, opens the backup as a lease does, checks it, reads every
/// chunk back and records a result.
fn back_up(
    v: &envcloak_core::vault::Vault,
    sizes: &[u64],
    chunks: &[Vec<SecretBytes>],
    until: Until,
) {
    let plan = sizes
        .iter()
        .enumerate()
        .map(|(i, s)| PlannedFile {
            path: format!("/h/.codex/sessions/{i}.jsonl"),
            mode: 0o600,
            size: *s,
        })
        .collect();
    let w = v
        .begin_file_backup_v2(BackupPurpose::Scrub, creator(), plan, 1_790_000_000)
        .unwrap();
    let held: Arc<Mutex<Option<Box<FileBackupV2Writer>>>> = Arc::new(Mutex::new(Some(Box::new(w))));
    let done = {
        let mut g = held.lock().unwrap();
        let w = g.as_mut().unwrap();
        for (i, file) in chunks.iter().enumerate() {
            for (c, chunk) in file.iter().enumerate() {
                if until == Until::PartWritten && i == 1 && c == 1 {
                    break;
                }
                w.put(i, c as u64, chunk).unwrap();
            }
        }
        match until {
            Until::Committed => Some(w.commit().unwrap()),
            Until::Sealed => {
                w.seal().unwrap();
                None
            }
            Until::PartWritten => None,
        }
    };
    drop(held);
    let Some(done) = done else {
        return;
    };
    let r = Arc::new(v.open_file_backup_v2(&done.id).unwrap());
    r.verify().unwrap();
    for (i, s) in sizes.iter().enumerate() {
        for c in 0..chunks_of(*s) {
            drop(r.chunk(i, c).unwrap());
        }
    }
    r.record_result(0, &[9; 32]).unwrap();
    drop(r.results().unwrap());
    drop(r);
}

#[test]
fn backup_chunks_leave_no_fixture_in_freed_memory() {
    let cs = canaries(fresh_seed());
    let tail = by_label(&cs, labels::GITHUB_TOKEN).value().to_vec();
    assert!(
        (envcloak_testkit::PROBE_WINDOW..56).contains(&tail.len()),
        "the tail must fit one block's last part with its padding"
    );

    // Negative control: this binary's probe is armed and sees a plain copy.
    let session = probe_canaries(&cs, ProbeMode::Unwiped);
    drop(std::hint::black_box(tail.clone()));
    assert!(session.finish().released_with_needle >= 1);

    // Negative control: a hasher's state freed without its wipe (its drop
    // skipped) is seen, holding the last bytes it has not taken yet: what
    // a writer whose hasher stopped wiping would leave.
    let mut h = Box::new(ManuallyDrop::new(Sha256::new()));
    h.update(vec![b'.'; 64 * 3]);
    h.update(&tail);
    let session = probe_canaries(&cs, ProbeMode::Unwiped);
    drop(std::hint::black_box(h));
    assert!(
        session.finish().released_with_needle >= 1,
        "the probe did not see a hasher's state freed unwiped"
    );

    let (_f, v) = Fixture::create();
    for mode in [ProbeMode::Unwiped, ProbeMode::Wiping] {
        for until in [Until::Committed, Until::Sealed, Until::PartWritten] {
            let files = bodies(&cs, &tail);
            let sizes = [files[0].len() as u64, files[1].len() as u64];
            let chunks = chunks_of_files(&files);
            for f in files {
                drop(SecretBytes::from_vec(f));
            }
            let session = probe_canaries(&cs, mode);
            back_up(&v, &sizes, &chunks, until);
            drop(chunks);
            let report = session.finish();
            assert!(report.freed > 0, "{mode:?} {until:?} {report:?}");
            assert_eq!(
                report.released_with_needle, 0,
                "{mode:?} {until:?} {report:?}"
            );
            if mode == ProbeMode::Wiping {
                assert_eq!(report.not_zeroed, 0, "{mode:?} {until:?} {report:?}");
            }
        }
    }
}
