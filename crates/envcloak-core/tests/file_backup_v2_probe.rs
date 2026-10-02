//! Gate 11 over file backup v2 chunks: writing a backup chunk by chunk,
//! opening it, checking it, reading every chunk back and recording a
//! result never free a block that still holds a fixture.
//!
//! `ProbeMode::Unwiped` turns the allocator's own wipe off, so it checks
//! that the backup code wipes every buffer it fills with a file's bytes
//! (each chunk, the hasher's state); the `ProbeMode::Wiping` pass is the
//! gate as written. The fixtures sit inside chunks and across a chunk
//! boundary. One test, so no other test's allocations run while the probe
//! is armed.
#![allow(clippy::unwrap_used)]

mod common;

use common::Fixture;
use envcloak_core::SecretBytes;
use envcloak_core::file_backup_v2::{
    BackupCreator, BackupOwner, BackupPurpose, CHUNK_V2, CreatorKind, PlannedFile, chunk_len,
    chunks_of,
};
use envcloak_testkit::{
    ProbeAllocator, ProbeMode, by_label, canaries, fresh_seed, labels, probe_canaries,
};

#[global_allocator]
static ALLOCATOR: ProbeAllocator = ProbeAllocator;

#[test]
fn backup_chunks_leave_no_fixture_in_freed_memory() {
    let cs = canaries(fresh_seed());

    // Negative control: this binary's probe is armed and sees a plain copy.
    let session = probe_canaries(&cs, ProbeMode::Unwiped);
    drop(std::hint::black_box(
        by_label(&cs, labels::GITHUB_TOKEN).value().to_vec(),
    ));
    assert!(session.finish().released_with_needle >= 1);

    let (_f, v) = Fixture::create();
    for mode in [ProbeMode::Unwiped, ProbeMode::Wiping] {
        // A file of three chunks with every fixture, one across the first
        // boundary, and a short one of fixtures alone (its hasher state
        // holds the tail of the last).
        let mut big = vec![b'.'; 2 * CHUNK_V2 + 99];
        let mut at = CHUNK_V2 - 20;
        for c in &cs {
            big[at..at + c.value().len()].copy_from_slice(c.value());
            at += c.value().len();
        }
        let small: Vec<u8> = cs.iter().flat_map(|c| c.value().to_vec()).collect();
        // The chunks are made before the probe is armed, as a client's
        // would arrive, and the plain copies wiped; each chunk is wiped
        // when it is dropped.
        let sizes = [big.len() as u64, small.len() as u64];
        let chunks: Vec<Vec<SecretBytes>> = [&big, &small]
            .iter()
            .zip(sizes)
            .map(|(b, size)| {
                (0..chunks_of(size))
                    .map(|c| {
                        let start = c as usize * CHUNK_V2;
                        let end = start + chunk_len(size, c).unwrap();
                        SecretBytes::copy_from(&b[start..end])
                    })
                    .collect()
            })
            .collect();
        drop(SecretBytes::from_vec(big));
        drop(SecretBytes::from_vec(small));
        let session = probe_canaries(&cs, mode);
        {
            let plan = sizes
                .iter()
                .enumerate()
                .map(|(i, s)| PlannedFile {
                    path: format!("/h/.codex/sessions/{i}.jsonl"),
                    mode: 0o600,
                    size: *s,
                })
                .collect();
            let creator = BackupCreator {
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
            };
            let mut w = v
                .begin_file_backup_v2(BackupPurpose::Scrub, creator, plan, 1_790_000_000)
                .unwrap();
            for (i, file) in chunks.iter().enumerate() {
                for (c, chunk) in file.iter().enumerate() {
                    w.put(i, c as u64, chunk).unwrap();
                }
            }
            let done = w.commit().unwrap();
            drop(w);
            let r = v.open_file_backup_v2(&done.id).unwrap();
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
        drop(chunks);
        let report = session.finish();
        assert!(report.freed > 0, "{mode:?} {report:?}");
        assert_eq!(report.released_with_needle, 0, "{mode:?} {report:?}");
        if mode == ProbeMode::Wiping {
            assert_eq!(report.not_zeroed, 0, "{mode:?} {report:?}");
        }
    }
}
