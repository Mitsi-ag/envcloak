//! Regression probe for memory hygiene: no buffer holding secret bytes may be
//! released without being wiped. A custom allocator forces every reallocation
//! to move and inspects each block just before it is freed.
#![allow(unsafe_code, clippy::unwrap_used)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use envcloak_redact::RedactorBuilder;

const NEEDLE: &[u8] = b"sk-proj-ALLOCPROBE-0123456789abcdefghijKLMNOP";
/// A freed block containing any 12-byte run of the needle counts as a leak.
const WINDOW: usize = 12;

static ARMED: AtomicBool = AtomicBool::new(false);
static LEAKS: AtomicUsize = AtomicUsize::new(0);
/// Tests in this binary share the allocator counters; run them one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

struct Probe;

fn contains_needle_run(block: &[u8]) -> bool {
    NEEDLE
        .windows(WINDOW)
        .any(|run| block.windows(WINDOW).any(|w| w == run))
}

unsafe impl GlobalAlloc for Probe {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::SeqCst) && layout.size() >= WINDOW {
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            if contains_needle_run(block) {
                LEAKS.fetch_add(1, Ordering::SeqCst);
            }
        }
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // Always move, so in-place growth bugs show up as freed copies.
        let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
        let new_ptr = unsafe { self.alloc(new_layout) };
        if !new_ptr.is_null() {
            unsafe {
                std::ptr::copy_nonoverlapping(ptr, new_ptr, layout.size().min(new_size));
                self.dealloc(ptr, layout);
            }
        }
        new_ptr
    }
}

#[global_allocator]
static ALLOCATOR: Probe = Probe;

fn measure(f: impl FnOnce()) -> usize {
    LEAKS.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    f();
    ARMED.store(false, Ordering::SeqCst);
    LEAKS.load(Ordering::SeqCst)
}

#[test]
fn probe_detects_an_unwiped_growing_buffer() {
    let _guard = SERIAL.lock().unwrap();
    let leaks = measure(|| {
        let mut v = Vec::with_capacity(NEEDLE.len());
        v.extend_from_slice(NEEDLE);
        v.extend_from_slice(b"forces a moving reallocation");
        drop(v);
    });
    assert!(leaks >= 1, "the probe must catch the bug it guards against");
}

#[test]
fn stream_redactor_frees_no_unwiped_secret_bytes() {
    let _guard = SERIAL.lock().unwrap();
    let (redactor, _) = RedactorBuilder::new().secret("probe", NEEDLE).build();
    let mut text = b"prefix noise ".to_vec();
    text.extend_from_slice(NEEDLE);
    text.extend_from_slice(b" suffix noise");
    let splits: Vec<(Vec<u8>, Vec<u8>)> = (0..=text.len())
        .map(|i| (text[..i].to_vec(), text[i..].to_vec()))
        .collect();
    let mut outputs: Vec<Vec<u8>> = Vec::with_capacity(splits.len());

    let leaks = measure(|| {
        for (a, b) in &splits {
            let mut out = Vec::new();
            let mut s = redactor.stream();
            s.push(a, &mut out);
            s.flush_idle(&mut out);
            s.push(b, &mut out);
            s.finish(&mut out);
            outputs.push(out);
        }
    });

    assert_eq!(leaks, 0, "a buffer holding secret bytes was freed unwiped");
    for out in &outputs {
        assert!(!out.windows(NEEDLE.len()).any(|w| w == NEEDLE));
    }
}
