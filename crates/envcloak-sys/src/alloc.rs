//! The wiping global allocator.
//!
//! Every block is zeroed with volatile writes (`zeroize`) before it goes back
//! to the system allocator, and `realloc` never grows or shrinks in place: it
//! allocates a new block, copies, wipes the old block and frees it. A buffer
//! that once held a secret therefore never returns to the free list with the
//! secret still in it, whichever crate allocated it: the redactor's
//! Aho-Corasick automata, serde_json buffers, or the C-string copies std
//! makes for `Command::env`.
//!
//! Not covered: stack and register copies, memory owned by non-Rust
//! allocators, and the bytes a block holds while it is still live.

use std::alloc::{GlobalAlloc, Layout, System};
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};

use zeroize::Zeroize;

/// A global allocator that wipes every block when it is freed.
///
/// Install it in every binary:
///
/// ```ignore
/// #[global_allocator]
/// static ALLOCATOR: envcloak_sys::WipingAllocator = envcloak_sys::WipingAllocator;
/// ```
///
/// Allocation is delegated to the system allocator unchanged. `dealloc`
/// zeroes the whole block first. `realloc` always moves: allocate, copy
/// `min(old, new)` bytes, wipe the old block, free it. Alignment is kept
/// because the new block uses the old layout's alignment.
#[derive(Debug, Clone, Copy, Default)]
pub struct WipingAllocator;

/// Set by the first free that goes through [`WipingAllocator`].
static ACTIVE: AtomicBool = AtomicBool::new(false);

/// Returns true when this process frees memory through [`WipingAllocator`],
/// that is, when a binary installed it as the global allocator.
pub fn wiping_allocator_active() -> bool {
    // Make sure at least one free has happened before looking.
    drop(std::hint::black_box(vec![0u8; 16]));
    ACTIVE.load(Ordering::Relaxed)
}

#[inline(always)]
fn mark_active() {
    // Load first so the cache line stays shared after the first free.
    if !ACTIVE.load(Ordering::Relaxed) {
        ACTIVE.store(true, Ordering::Relaxed);
    }
}

/// Where blocks come from and go to, with hooks around the wipe. The
/// production backing is the system allocator with no hooks; the test
/// probe (`testing::ProbeAllocator`) zero-initializes every block and
/// inspects blocks around the wipe, running the same wipe and realloc code.
pub(crate) trait Backing {
    /// # Safety
    /// As [`GlobalAlloc::alloc`].
    unsafe fn allocate(&self, layout: Layout) -> *mut u8;

    /// Returns a block to the system without wiping it.
    ///
    /// # Safety
    /// As [`GlobalAlloc::dealloc`].
    unsafe fn release(&self, ptr: *mut u8, layout: Layout);

    /// Called just before the block is wiped.
    ///
    /// # Safety
    /// `ptr` is valid for reads of `size` bytes.
    #[inline(always)]
    unsafe fn before_wipe(&self, _ptr: *const u8, _size: usize) {}

    /// Called just after the block is wiped.
    ///
    /// # Safety
    /// `ptr` is valid for reads of `size` bytes.
    #[inline(always)]
    unsafe fn after_wipe(&self, _ptr: *const u8, _size: usize) {}
}

struct SystemBacking;

impl Backing for SystemBacking {
    #[inline(always)]
    unsafe fn allocate(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded from the caller's GlobalAlloc contract.
        unsafe { System.alloc(layout) }
    }

    #[inline(always)]
    unsafe fn release(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded from the caller's GlobalAlloc contract.
        unsafe { System.dealloc(ptr, layout) }
    }
}

/// Zeroes `size` bytes at `ptr` with volatile writes the compiler cannot
/// remove as dead stores, even though the block is freed right after.
///
/// # Safety
/// `ptr` must be valid for writes of `size` bytes. The bytes may be
/// uninitialized: they are only written, through `MaybeUninit<u8>`.
#[inline]
pub(crate) unsafe fn wipe(ptr: *mut u8, size: usize) {
    // SAFETY: the caller guarantees `ptr` is valid for `size` bytes, and any
    // byte pattern is a valid `MaybeUninit<u8>`, so no read of uninitialized
    // memory happens. `size <= isize::MAX` holds for every `Layout`, so
    // zeroize's internal size checks cannot panic.
    let block = unsafe { std::slice::from_raw_parts_mut(ptr.cast::<MaybeUninit<u8>>(), size) };
    block.zeroize();
}

/// Wipes a block, then returns it to the backing allocator.
///
/// # Safety
/// As [`GlobalAlloc::dealloc`].
#[inline]
pub(crate) unsafe fn free_wiped<B: Backing>(backing: &B, ptr: *mut u8, layout: Layout) {
    let size = layout.size();
    // SAFETY: `ptr` is a live block of `size` bytes owned by the caller.
    unsafe {
        backing.before_wipe(ptr, size);
        wipe(ptr, size);
        backing.after_wipe(ptr, size);
        backing.release(ptr, layout);
    }
}

/// Moves a block to a new allocation of `new_size` bytes with the same
/// alignment, then wipes and frees the old one. On failure it returns null
/// and leaves the old block untouched, as [`GlobalAlloc::realloc`] requires.
///
/// # Safety
/// As [`GlobalAlloc::realloc`].
#[inline]
pub(crate) unsafe fn realloc_moving<B: Backing>(
    backing: &B,
    ptr: *mut u8,
    layout: Layout,
    new_size: usize,
) -> *mut u8 {
    let Ok(new_layout) = Layout::from_size_align(new_size, layout.align()) else {
        return std::ptr::null_mut();
    };
    // SAFETY: `new_layout` has a non-zero size (the GlobalAlloc contract
    // requires `new_size > 0`) and a valid alignment.
    let new_ptr = unsafe { backing.allocate(new_layout) };
    if new_ptr.is_null() {
        return new_ptr;
    }
    // SAFETY: both blocks are live, distinct, and at least
    // `min(old, new)` bytes long; the old block is freed exactly once.
    unsafe {
        std::ptr::copy_nonoverlapping(ptr, new_ptr, layout.size().min(new_size));
        free_wiped(backing, ptr, layout);
    }
    new_ptr
}

// SAFETY: allocation is delegated to `System`, which upholds the
// GlobalAlloc contract; `dealloc` and `realloc` only add a wipe of memory
// the caller still owns before handing it back. Nothing here allocates,
// panics (see `wipe`), locks or logs.
unsafe impl GlobalAlloc for WipingAllocator {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded from the caller.
        unsafe { System.alloc(layout) }
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded from the caller.
        unsafe { System.alloc_zeroed(layout) }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        mark_active();
        // SAFETY: forwarded from the caller.
        unsafe { free_wiped(&SystemBacking, ptr, layout) }
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        mark_active();
        // SAFETY: forwarded from the caller.
        unsafe { realloc_moving(&SystemBacking, ptr, layout, new_size) }
    }
}
