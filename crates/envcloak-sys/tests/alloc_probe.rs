//! The inspection allocator and the wiping algorithm it shares with
//! `WipingAllocator` (gate 11 harness). This binary installs the probe as its
//! global allocator.
#![allow(unsafe_code, clippy::unwrap_used)]

use std::alloc::{Layout, alloc, dealloc, realloc};

use envcloak_sys::testing::{ProbeAllocator, ProbeMode, ProbeReport, ProbeSession};
use zeroize::Zeroizing;

#[global_allocator]
static ALLOCATOR: ProbeAllocator = ProbeAllocator;

const WINDOW: usize = 12;

/// A needle built at runtime, distinct per call site.
fn needle(tag: u8) -> Vec<u8> {
    (0..48u8)
        .map(|i| b'A' + (i.wrapping_mul(7) ^ tag) % 26)
        .collect()
}

fn probe(needle: &[u8], mode: ProbeMode, f: impl FnOnce()) -> ProbeReport {
    let session = ProbeSession::start(&[needle], WINDOW, mode);
    f();
    session.finish()
}

#[test]
fn wiping_mode_wipes_a_freed_block_that_held_the_needle() {
    let n = needle(1);
    let mut v = Vec::with_capacity(n.len());
    let report = probe(&n, ProbeMode::Wiping, || {
        v.extend_from_slice(&n);
        drop(std::hint::black_box(v));
    });
    assert!(
        report.held_needle >= 1,
        "the probe must see the needle: {report:?}"
    );
    assert_eq!(report.not_zeroed, 0, "{report:?}");
    assert_eq!(report.released_with_needle, 0, "{report:?}");
}

#[test]
fn realloc_growth_wipes_the_old_block() {
    let n = needle(2);
    let mut v: Vec<u8> = Vec::with_capacity(n.len());
    v.extend_from_slice(&n);
    let report = probe(&n, ProbeMode::Wiping, || {
        // Exceeds the capacity: realloc moves the needle to a new block.
        v.extend_from_slice(b"grow past the original capacity");
    });
    assert_eq!(&v[..n.len()], &n[..], "realloc must keep the contents");
    assert!(
        report.held_needle >= 1,
        "the old block held the needle: {report:?}"
    );
    assert_eq!(report.not_zeroed, 0, "{report:?}");
    assert_eq!(report.released_with_needle, 0, "{report:?}");
}

#[test]
fn realloc_shrink_wipes_the_old_block() {
    let n = needle(3);
    let mut v: Vec<u8> = Vec::with_capacity(4 * n.len());
    v.extend_from_slice(&n);
    let report = probe(&n, ProbeMode::Wiping, || v.shrink_to_fit());
    assert_eq!(v, n);
    assert!(report.held_needle >= 1, "{report:?}");
    assert_eq!(report.not_zeroed, 0, "{report:?}");
    assert_eq!(report.released_with_needle, 0, "{report:?}");
}

#[test]
fn unwiped_mode_catches_a_growing_buffer() {
    // Negative control: without the allocator's wipe, plain Vec growth
    // releases the old block with the needle in it, and the probe says so.
    let n = needle(4);
    let report = probe(&n, ProbeMode::Unwiped, || {
        let mut v = Vec::with_capacity(n.len());
        v.extend_from_slice(&n);
        v.extend_from_slice(b"forces a moving reallocation");
        drop(std::hint::black_box(v));
    });
    assert!(report.released_with_needle >= 2, "{report:?}");
}

#[test]
fn unwiped_mode_accepts_code_that_wipes_its_own_buffers() {
    let n = needle(5);
    let report = probe(&n, ProbeMode::Unwiped, || {
        let mut v = Zeroizing::new(Vec::with_capacity(n.len()));
        v.extend_from_slice(&n);
        drop(std::hint::black_box(v));
    });
    assert_eq!(report.released_with_needle, 0, "{report:?}");
}

#[test]
fn window_matches_partial_copies_only_at_full_width() {
    let n = needle(6);
    let hit = probe(&n, ProbeMode::Unwiped, || {
        drop(std::hint::black_box(n[10..10 + WINDOW].to_vec()));
    });
    assert_eq!(hit.released_with_needle, 1, "{hit:?}");
    let miss = probe(&n, ProbeMode::Unwiped, || {
        drop(std::hint::black_box(n[10..10 + WINDOW - 1].to_vec()));
    });
    assert_eq!(miss.released_with_needle, 0, "{miss:?}");
}

#[test]
fn every_block_and_every_grown_region_starts_zeroed() {
    // The F-10 lesson: the probe may only inspect initialized memory.
    let layout = Layout::from_size_align(64, 8).unwrap();
    // SAFETY: the layout is non-zero-sized; each block is read within its
    // size and freed once with its current layout.
    unsafe {
        let p = alloc(layout);
        assert!(!p.is_null());
        assert!(std::slice::from_raw_parts(p, 64).iter().all(|b| *b == 0));
        p.write_bytes(0xAB, 64);
        let q = realloc(p, layout, 4096);
        assert!(!q.is_null());
        let grown = std::slice::from_raw_parts(q, 4096);
        assert!(grown[..64].iter().all(|b| *b == 0xAB));
        assert!(grown[64..].iter().all(|b| *b == 0));
        dealloc(q, Layout::from_size_align(4096, 8).unwrap());
    }
}

#[test]
fn realloc_keeps_alignment() {
    for align in [1usize, 16, 64, 256, 4096] {
        let layout = Layout::from_size_align(24, align).unwrap();
        // SAFETY: as above.
        unsafe {
            let p = alloc(layout);
            assert!(!p.is_null());
            p.write_bytes(0x5A, 24);
            let q = realloc(p, layout, 10_000);
            assert_eq!(q.addr() % align, 0, "align {align}");
            assert!(std::slice::from_raw_parts(q, 24).iter().all(|b| *b == 0x5A));
            let r = realloc(q, Layout::from_size_align(10_000, align).unwrap(), 8);
            assert_eq!(r.addr() % align, 0, "align {align}");
            assert!(std::slice::from_raw_parts(r, 8).iter().all(|b| *b == 0x5A));
            dealloc(r, Layout::from_size_align(8, align).unwrap());
        }
    }
}

#[test]
fn disarmed_probe_counts_nothing() {
    let n = needle(7);
    let session = ProbeSession::start(&[&n], WINDOW, ProbeMode::Unwiped);
    let report = session.finish();
    drop(std::hint::black_box(n.clone()));
    assert_eq!(report.released_with_needle, 0);
}
