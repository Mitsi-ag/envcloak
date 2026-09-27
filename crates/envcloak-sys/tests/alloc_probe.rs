//! The inspection allocator and the wiping algorithm it shares with
//! `WipingAllocator` (gate 11 harness). This binary installs the probe as its
//! global allocator.
#![allow(unsafe_code, clippy::unwrap_used)]

use std::alloc::{Layout, alloc, dealloc, realloc};

use envcloak_sys::testing::{
    INSPECT_CHUNK, ProbeAllocator, ProbeMode, ProbeReport, ProbeSession, read_own_memory,
};
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
fn a_window_is_found_at_every_block_offset_and_needle_offset() {
    const BLOCK: usize = 40;
    let n = needle(8);
    let released = |f: &dyn Fn(&mut [u8])| {
        probe(&n, ProbeMode::Unwiped, || {
            let mut block = vec![0u8; BLOCK];
            f(&mut block);
            drop(std::hint::black_box(block));
        })
        .released_with_needle
    };
    for start in 0..=n.len() - WINDOW {
        let piece = &n[start..start + WINDOW];
        for at in 0..=BLOCK - WINDOW {
            let put = |b: &mut [u8]| b[at..at + WINDOW].copy_from_slice(piece);
            assert_eq!(released(&put), 1, "needle[{start}..] at {at}");
            // One changed byte anywhere in the window: no match. Needle
            // bytes are uppercase letters; the flip makes one lowercase.
            for flip in 0..WINDOW {
                let near = |b: &mut [u8]| {
                    put(b);
                    b[at + flip] ^= 0x20;
                };
                assert_eq!(released(&near), 0, "needle[{start}..] at {at}, flip {flip}");
            }
        }
        // A window cut short by either end of the block: no match.
        let head = |b: &mut [u8]| b[..WINDOW - 1].copy_from_slice(&piece[1..]);
        let tail = |b: &mut [u8]| b[BLOCK - (WINDOW - 1)..].copy_from_slice(&piece[..WINDOW - 1]);
        assert_eq!(released(&head), 0, "needle[{start}..] cut at the start");
        assert_eq!(released(&tail), 0, "needle[{start}..] cut at the end");
    }
}

#[test]
fn blocks_with_uninitialized_padding_are_inspected() {
    // Typed writes leave the padding bytes of these structs uninitialized.
    // The probe must inspect such blocks without loading those bytes in Rust
    // or C (F-16): it searches a copy the kernel makes.
    #[repr(C)]
    struct Padded {
        tag: u8,
        value: u64,
        tail: u16,
    }
    let n = needle(9);
    for mode in [ProbeMode::Wiping, ProbeMode::Unwiped] {
        let report = probe(&n, mode, || {
            let v: Vec<Padded> = (0..64u8)
                .map(|i| Padded {
                    tag: i,
                    value: u64::from(i),
                    tail: 7,
                })
                .collect();
            drop(std::hint::black_box(v));
            drop(std::hint::black_box(Box::new(Padded {
                tag: 1,
                value: 2,
                tail: 3,
            })));
        });
        assert!(report.freed >= 2, "{mode:?}: {report:?}");
        assert_eq!(report.released_with_needle, 0, "{mode:?}: {report:?}");
        assert_eq!(report.not_zeroed, 0, "{mode:?}: {report:?}");
    }
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

#[test]
fn windows_across_inspection_chunks_are_found() {
    // The probe copies a block out in chunks of INSPECT_CHUNK bytes, each
    // starting WINDOW - 1 bytes before the previous one ended, so a window
    // that straddles a chunk boundary lies whole in the next chunk.
    const BLOCK: usize = 3 * INSPECT_CHUNK + 77;
    let n = needle(10);
    let piece = &n[5..5 + WINDOW];
    let released = |at: usize, flip: Option<usize>| {
        probe(&n, ProbeMode::Unwiped, || {
            let mut block = vec![0u8; BLOCK];
            block[at..at + WINDOW].copy_from_slice(piece);
            if let Some(f) = flip {
                block[at + f] ^= 0x20;
            }
            drop(std::hint::black_box(block));
        })
        .released_with_needle
    };
    let step = INSPECT_CHUNK - (WINDOW - 1);
    let mut edges = vec![BLOCK - WINDOW];
    for k in 1..=3 {
        // Where chunk k starts, and where chunk k - 1 ends.
        edges.push(k * step);
        edges.push((k - 1) * step + INSPECT_CHUNK);
    }
    for edge in edges {
        for at in edge.saturating_sub(WINDOW + 1)..=(edge + 1).min(BLOCK - WINDOW) {
            assert_eq!(released(at, None), 1, "window at {at}");
            assert_eq!(released(at, Some(WINDOW / 2)), 0, "flipped window at {at}");
        }
    }
}

#[test]
fn the_kernel_copy_reads_padding_and_reports_unmapped_memory() {
    #[repr(C)]
    struct Padded {
        tag: u8,
        value: u64,
    }
    let p = Padded { tag: 7, value: 9 };
    let mut out = [0xEEu8; std::mem::size_of::<Padded>()];
    read_own_memory(std::ptr::from_ref(&p).cast(), &mut out).unwrap();
    assert_eq!(out[0], 7);
    assert_eq!(&out[8..], &9u64.to_ne_bytes());

    // Across a chunk-sized buffer, byte for byte.
    let src: Vec<u8> = (0..INSPECT_CHUNK + 5).map(|i| (i % 251) as u8).collect();
    let mut copy = vec![0u8; src.len()];
    read_own_memory(src.as_ptr(), &mut copy).unwrap();
    assert_eq!(copy, src);

    // The kernel checks the source range; this process never touches it.
    assert!(read_own_memory(std::ptr::null(), &mut out).is_err());
}
