//! The wiping allocator as the binaries install it, over the system
//! allocator and compiled with optimizations (the workspace profile builds
//! envcloak-sys, tests included, at opt-level 3, as release builds are): a
//! freed block no longer holds what was written into it. At opt-level 0
//! even plain writes before `free` survive, so only an optimized build shows
//! whether the wipe could be dropped as a dead store. `zeroize`'s volatile
//! writes cannot be; a wipe rewritten with `ptr::write_bytes` fails here.
//!
//! The freed range is read back through the kernel
//! (`testing::read_own_memory`), never by a Rust load. A positive control
//! frees the same kind of block straight to the system allocator, unwiped,
//! and must find the pattern still there, or the check would pass
//! vacuously. macOS clears small blocks on free by itself, so only sizes
//! where the control keeps the pattern count, and at least one must.
//!
//! It has its own `main` (no test harness), so no other thread allocates
//! between a free and its read-back.
#![allow(unsafe_code, clippy::unwrap_used)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;

use envcloak_sys::testing::read_own_memory;
use envcloak_sys::{WipingAllocator, wiping_allocator_active};

#[global_allocator]
static ALLOCATOR: WipingAllocator = WipingAllocator;

/// Block sizes: small (glibc tcache, macOS tiny), medium, and two that
/// macOS keeps on free.
const SIZES: [usize; 4] = [256, 4000, 20_000, 100_000];
/// Compared in aligned pieces of this many bytes.
const PIECE: usize = 16;

/// Bytes that no allocator writes by itself, from a runtime seed.
fn pattern(len: usize) -> Vec<u8> {
    let mut x = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
        | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            0x80 | (x as u8)
        })
        .collect()
}

/// How many aligned pieces of `pattern` are still at their offsets in the
/// `readback.len()` bytes at `addr`. An unmapped range (the allocator gave
/// the memory back) holds none. Does not allocate.
fn pieces_kept(addr: *const u8, pattern: &[u8], readback: &mut [u8]) -> usize {
    if read_own_memory(addr, readback).is_err() {
        return 0;
    }
    readback
        .chunks_exact(PIECE)
        .zip(pattern.chunks_exact(PIECE))
        .filter(|(a, b)| a == b)
        .count()
}

/// Control: a block freed to the system allocator without any wipe.
fn kept_unwiped(pattern: &[u8], readback: &mut [u8]) -> usize {
    let layout = Layout::from_size_align(pattern.len(), 16).unwrap();
    // SAFETY: a non-zero-sized layout; the block is written within its
    // size and freed once with the same layout. Volatile writes keep the
    // pattern from being dropped as a dead store before the free.
    let p = unsafe {
        let p = System.alloc(layout);
        assert!(!p.is_null());
        for (i, b) in pattern.iter().enumerate() {
            p.add(i).write_volatile(*b);
        }
        System.dealloc(black_box(p), layout);
        p
    };
    pieces_kept(p, pattern, readback)
}

/// A buffer filled with plain writes and dropped, so the global
/// `WipingAllocator` frees it.
fn kept_wiped(pattern: &[u8], readback: &mut [u8]) -> usize {
    let mut v: Vec<u8> = Vec::with_capacity(pattern.len());
    v.extend_from_slice(pattern);
    let addr = v.as_ptr();
    drop(black_box(v));
    pieces_kept(addr, pattern, readback)
}

fn main() {
    assert!(wiping_allocator_active());
    let mut controls = 0;
    for size in SIZES {
        let pat = pattern(size);
        let mut readback = vec![0u8; size];
        let control = kept_unwiped(&pat, &mut readback);
        let wiped = kept_wiped(&pat, &mut readback);
        println!(
            "freed_memory: {size} bytes: control kept {control} of {} pieces, wiped kept {wiped}",
            size / PIECE
        );
        assert_eq!(
            wiped, 0,
            "a {size}-byte block kept its contents after the wiping free"
        );
        if control > 0 {
            controls += 1;
        }
    }
    assert!(
        controls > 0,
        "control: the system allocator cleared every unwiped block, so this check proves nothing here"
    );
    println!("freed_memory: ok");
}
