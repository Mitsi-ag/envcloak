//! `WipingAllocator` as a real global allocator: it must behave like the
//! system allocator (contents, alignment, zeroed allocations) while wiping,
//! and its realloc must always move. What it leaves in freed memory is
//! checked by `alloc_probe.rs`, which runs this same `GlobalAlloc` impl over
//! an inspecting backing.
#![allow(unsafe_code, clippy::unwrap_used)]

use std::alloc::{Layout, alloc, alloc_zeroed, dealloc, realloc};
use std::collections::HashMap;

use envcloak_sys::{WipingAllocator, wiping_allocator_active};

#[global_allocator]
static ALLOCATOR: WipingAllocator = WipingAllocator;

#[test]
fn reports_itself_active() {
    assert!(wiping_allocator_active());
}

#[test]
fn realloc_keeps_contents_and_alignment() {
    for align in [1usize, 8, 64, 4096] {
        let layout = Layout::from_size_align(40, align).unwrap();
        // SAFETY: non-zero-sized layouts; each block is used within its
        // size and freed once with its current layout.
        unsafe {
            let p = alloc(layout);
            assert!(!p.is_null());
            for i in 0..40 {
                p.add(i).write(i as u8);
            }
            let q = realloc(p, layout, 100_000);
            assert!(!q.is_null());
            assert_eq!(q.addr() % align, 0, "align {align}");
            for i in 0..40 {
                assert_eq!(q.add(i).read(), i as u8);
            }
            let r = realloc(q, Layout::from_size_align(100_000, align).unwrap(), 16);
            assert!(!r.is_null());
            assert_eq!(r.addr() % align, 0, "align {align}");
            for i in 0..16 {
                assert_eq!(r.add(i).read(), i as u8);
            }
            dealloc(r, Layout::from_size_align(16, align).unwrap());
        }
    }
}

#[test]
fn realloc_always_moves() {
    // An in-place realloc would leave the old bytes where they were, never
    // wiped. The moving realloc allocates the new block while the old one is
    // still live, so the address always changes. The system allocator
    // reuses the block for most of these size changes (same size class,
    // shrinking a large block), so a realloc that delegates to it fails here.
    let sizes = [
        (16, 24),
        (24, 17),
        (32, 31),
        (64, 65),
        (4096, 4000),
        (100_000, 100_008),
        (100_000, 50_000),
    ];
    for (from, to) in sizes {
        let layout = Layout::from_size_align(from, 8).unwrap();
        // SAFETY: non-zero-sized layouts; each block is freed once with its
        // current layout. The old pointer is only compared, never used.
        unsafe {
            let p = alloc(layout);
            assert!(!p.is_null());
            p.write_bytes(0x42, from);
            let q = realloc(p, layout, to);
            assert!(!q.is_null());
            assert_ne!(p.addr(), q.addr(), "realloc {from} -> {to} stayed in place");
            dealloc(q, Layout::from_size_align(to, 8).unwrap());
        }
    }
}

#[test]
fn alloc_zeroed_is_zeroed() {
    let layout = Layout::from_size_align(1 << 16, 16).unwrap();
    // SAFETY: non-zero-sized layout; read within size; freed once.
    unsafe {
        let p = alloc_zeroed(layout);
        assert!(!p.is_null());
        assert!(
            std::slice::from_raw_parts(p, 1 << 16)
                .iter()
                .all(|b| *b == 0)
        );
        dealloc(p, layout);
    }
}

#[test]
fn ordinary_collections_work() {
    let mut map = HashMap::new();
    let mut v = Vec::new();
    for i in 0..10_000u32 {
        map.insert(i, i.to_string());
        v.push(i);
    }
    assert_eq!(map.len(), 10_000);
    assert_eq!(v.iter().map(|x| u64::from(*x)).sum::<u64>(), 49_995_000);
    let s: String = (0..1000)
        .map(|i| char::from(b'a' + (i % 26) as u8))
        .collect();
    assert_eq!(s.len(), 1000);
}

#[test]
fn threads_allocate_concurrently() {
    let handles: Vec<_> = (0..8)
        .map(|t| {
            std::thread::spawn(move || {
                let mut total = 0usize;
                for i in 0..2000 {
                    let v = vec![t as u8; 1 + (i % 300)];
                    total += v.len();
                }
                total
            })
        })
        .collect();
    for h in handles {
        assert!(h.join().unwrap() > 0);
    }
}
