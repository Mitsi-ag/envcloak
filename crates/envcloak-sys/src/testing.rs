//! Test support, behind the `testing` feature. Release binaries never enable
//! it.
//!
//! [`ProbeAllocator`] is the inspection allocator for the allocator probe
//! (SPEC §15.2 gate 11). A test binary installs it as its global allocator
//! and brackets the code under test with a [`ProbeSession`]:
//!
//! ```ignore
//! #[global_allocator]
//! static ALLOCATOR: envcloak_sys::testing::ProbeAllocator = envcloak_sys::testing::ProbeAllocator;
//!
//! let session = ProbeSession::start(&[canary], 12, ProbeMode::Wiping);
//! code_under_test();
//! let report = session.finish();
//! assert_eq!(report.not_zeroed, 0);
//! ```
//!
//! Every block the probe hands out is zero-initialized, including the grown
//! region of a reallocation, so inspecting a whole block before it is freed
//! never reads memory that was never written (the F-10 lesson). One caveat
//! stays: a typed write of a struct with padding makes those padding bytes
//! formally uninitialized again. The probe reads them as bytes anyway; it is
//! a test instrument and is not run under Miri.
//!
//! Outside [`ProbeMode::Unwiped`], every call goes through the very
//! `GlobalAlloc` impl the binaries install, [`crate::WipingAllocator`],
//! instantiated over the probe's backing. A broken wipe, a skipped wipe or
//! an in-place realloc there shows up as `not_zeroed`, as a freed block the
//! probe never saw, or as memory that was not zero-initialized.
//! [`ProbeMode::Unwiped`] turns the allocator's wipe off to check that the
//! code under test wipes its own buffers.

use std::alloc::{GlobalAlloc, Layout, System};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::WipingAllocator;
use crate::alloc::Backing;

/// Maximum number of needles a session can watch for.
pub const MAX_NEEDLES: usize = 32;
/// Maximum length of one needle.
pub const MAX_NEEDLE_LEN: usize = 512;

/// How the probe treats freed blocks while a session is armed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeMode {
    /// Frees go through the same wipe as [`crate::WipingAllocator`]. The
    /// probe records blocks that held a needle before the wipe and checks
    /// that every block is all zeros after it.
    Wiping,
    /// The allocator does not wipe. A block released with a needle in it was
    /// left unwiped by the code under test.
    Unwiped,
}

/// What a session saw. Counts only; the probe never copies block contents.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProbeReport {
    /// Blocks freed while the session was armed, by any thread.
    pub freed: usize,
    /// Freed blocks that held a needle before any allocator wipe.
    pub held_needle: usize,
    /// Blocks that were not all zeros after the allocator's wipe
    /// ([`ProbeMode::Wiping`] only).
    pub not_zeroed: usize,
    /// Blocks returned to the system allocator with a needle still in them.
    pub released_with_needle: usize,
}

/// The inspection allocator. See the module documentation.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProbeAllocator;

static ARMED: AtomicBool = AtomicBool::new(false);
static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);
static MODE_UNWIPED: AtomicBool = AtomicBool::new(false);

static NEEDLE_COUNT: AtomicUsize = AtomicUsize::new(0);
static WINDOW: AtomicUsize = AtomicUsize::new(0);
static NEEDLE_LENS: [AtomicUsize; MAX_NEEDLES] = [const { AtomicUsize::new(0) }; MAX_NEEDLES];
static NEEDLE_BYTES: [AtomicU8; MAX_NEEDLES * MAX_NEEDLE_LEN] =
    [const { AtomicU8::new(0) }; MAX_NEEDLES * MAX_NEEDLE_LEN];
/// One bit per byte pair that starts a needle window: a cheap prefilter.
static PAIRS: [AtomicU64; 1024] = [const { AtomicU64::new(0) }; 1024];

static FREED: AtomicUsize = AtomicUsize::new(0);
static HELD: AtomicUsize = AtomicUsize::new(0);
static NOT_ZEROED: AtomicUsize = AtomicUsize::new(0);
static RELEASED: AtomicUsize = AtomicUsize::new(0);

/// Sessions share the counters, so they run one at a time.
static SESSION: Mutex<()> = Mutex::new(());

/// An armed probe. Only one exists at a time; [`ProbeSession::start`] waits
/// for the previous one to finish. Dropping a session disarms the probe.
#[derive(Debug)]
pub struct ProbeSession {
    _serial: MutexGuard<'static, ()>,
}

impl ProbeSession {
    /// Arms the probe. A freed block counts as holding a needle when it
    /// contains any `window` consecutive bytes of one (the whole needle when
    /// it is shorter than `window`).
    ///
    /// # Panics
    /// When there are more than [`MAX_NEEDLES`] needles, a needle is shorter
    /// than 2 or longer than [`MAX_NEEDLE_LEN`] bytes, or `window < 2`. The
    /// message never includes needle bytes.
    pub fn start(needles: &[&[u8]], window: usize, mode: ProbeMode) -> Self {
        assert!(needles.len() <= MAX_NEEDLES, "too many probe needles");
        assert!(window >= 2, "probe window must be at least 2 bytes");
        for n in needles {
            assert!(
                (2..=MAX_NEEDLE_LEN).contains(&n.len()),
                "probe needle length out of range"
            );
        }
        let serial = SESSION.lock().unwrap_or_else(PoisonError::into_inner);
        disarm();

        for p in &PAIRS {
            p.store(0, Ordering::Relaxed);
        }
        for (k, n) in needles.iter().enumerate() {
            let base = k * MAX_NEEDLE_LEN;
            for (i, b) in n.iter().enumerate() {
                NEEDLE_BYTES[base + i].store(*b, Ordering::Relaxed);
            }
            NEEDLE_LENS[k].store(n.len(), Ordering::Relaxed);
            let win = window.min(n.len());
            for j in 0..=n.len() - win {
                let pair = usize::from(n[j]) << 8 | usize::from(n[j + 1]);
                PAIRS[pair >> 6].fetch_or(1 << (pair & 63), Ordering::Relaxed);
            }
        }
        NEEDLE_COUNT.store(needles.len(), Ordering::Relaxed);
        WINDOW.store(window, Ordering::Relaxed);
        MODE_UNWIPED.store(mode == ProbeMode::Unwiped, Ordering::Relaxed);
        for c in [&FREED, &HELD, &NOT_ZEROED, &RELEASED] {
            c.store(0, Ordering::Relaxed);
        }
        ARMED.store(true, Ordering::SeqCst);
        ProbeSession { _serial: serial }
    }

    /// Disarms the probe and returns what it saw.
    pub fn finish(self) -> ProbeReport {
        disarm();
        ProbeReport {
            freed: FREED.load(Ordering::SeqCst),
            held_needle: HELD.load(Ordering::SeqCst),
            not_zeroed: NOT_ZEROED.load(Ordering::SeqCst),
            released_with_needle: RELEASED.load(Ordering::SeqCst),
        }
    }
}

impl Drop for ProbeSession {
    fn drop(&mut self) {
        disarm();
        // Leave no needle bytes behind in static memory.
        for b in &NEEDLE_BYTES {
            b.store(0, Ordering::Relaxed);
        }
        NEEDLE_COUNT.store(0, Ordering::Relaxed);
    }
}

/// Stops inspection and waits until no free is still inspecting, so the
/// needle table can be rewritten safely.
fn disarm() {
    ARMED.store(false, Ordering::SeqCst);
    while IN_FLIGHT.load(Ordering::SeqCst) != 0 {
        std::hint::spin_loop();
    }
}

/// Whether the block holds a window of any needle.
///
/// # Safety
/// `ptr` is valid for reads of `size` bytes, all of them written at least
/// once (every probe block starts zeroed).
unsafe fn holds_needle(ptr: *const u8, size: usize) -> bool {
    if size < 2 {
        return false;
    }
    // SAFETY: guaranteed by the caller.
    let block = unsafe { std::slice::from_raw_parts(ptr, size) };
    let count = NEEDLE_COUNT.load(Ordering::Relaxed);
    let window = WINDOW.load(Ordering::Relaxed);
    for i in 0..size - 1 {
        let pair = usize::from(block[i]) << 8 | usize::from(block[i + 1]);
        if PAIRS[pair >> 6].load(Ordering::Relaxed) & (1 << (pair & 63)) == 0 {
            continue;
        }
        for (k, slot) in NEEDLE_LENS.iter().enumerate().take(count) {
            let len = slot.load(Ordering::Relaxed);
            let win = window.min(len);
            if i + win > size {
                continue;
            }
            let base = k * MAX_NEEDLE_LEN;
            'start: for j in 0..=len - win {
                for t in 0..win {
                    if NEEDLE_BYTES[base + j + t].load(Ordering::Relaxed) != block[i + t] {
                        continue 'start;
                    }
                }
                return true;
            }
        }
    }
    false
}

/// # Safety
/// `ptr` is valid for reads of `size` bytes.
unsafe fn all_zero(ptr: *const u8, size: usize) -> bool {
    // SAFETY: guaranteed by the caller; the block was just wiped.
    unsafe { std::slice::from_raw_parts(ptr, size) }
        .iter()
        .all(|b| *b == 0)
}

/// Zero-initializing backing that inspects blocks around the wipe when armed.
struct ProbeBacking {
    armed: bool,
}

impl Backing for ProbeBacking {
    unsafe fn allocate(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded from the caller.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn allocate_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded from the caller.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn release(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded from the caller.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn before_wipe(&self, ptr: *const u8, size: usize) {
        // SAFETY: forwarded from the caller.
        if self.armed && unsafe { holds_needle(ptr, size) } {
            HELD.fetch_add(1, Ordering::Relaxed);
        }
    }

    unsafe fn after_wipe(&self, ptr: *const u8, size: usize) {
        if !self.armed {
            return;
        }
        // SAFETY: forwarded from the caller.
        if !unsafe { all_zero(ptr, size) } {
            NOT_ZEROED.fetch_add(1, Ordering::Relaxed);
            // SAFETY: as above.
            if unsafe { holds_needle(ptr, size) } {
                RELEASED.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Runs `f` with inspection enabled when a session is armed. The in-flight
/// count lets `disarm` wait for inspections that already started.
#[inline]
fn with_armed<R>(f: impl FnOnce(bool, bool) -> R) -> R {
    IN_FLIGHT.fetch_add(1, Ordering::SeqCst);
    let armed = ARMED.load(Ordering::SeqCst);
    let unwiped = armed && MODE_UNWIPED.load(Ordering::Relaxed);
    let r = f(armed, unwiped);
    IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
    r
}

/// Frees without wiping, recording a needle as released.
///
/// # Safety
/// As [`GlobalAlloc::dealloc`].
unsafe fn free_unwiped(ptr: *mut u8, layout: Layout) {
    // SAFETY: `ptr` is a live block of `layout.size()` bytes.
    if unsafe { holds_needle(ptr, layout.size()) } {
        HELD.fetch_add(1, Ordering::Relaxed);
        RELEASED.fetch_add(1, Ordering::Relaxed);
    }
    // SAFETY: forwarded from the caller.
    unsafe { System.dealloc(ptr, layout) }
}

/// The production allocator's `GlobalAlloc` impl over the probe's backing.
#[inline]
fn production(armed: bool) -> WipingAllocator<ProbeBacking> {
    WipingAllocator::with_backing(ProbeBacking { armed })
}

// SAFETY: every block comes from `System.alloc_zeroed` (through
// `ProbeBacking`) and goes back to `System.dealloc` with the layout it was
// allocated with. Inspection only reads blocks the caller still owns.
// Nothing here allocates, locks or logs.
unsafe impl GlobalAlloc for ProbeAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded from the caller.
        unsafe { production(false).alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded from the caller.
        unsafe { production(false).alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        with_armed(|armed, unwiped| {
            if armed {
                FREED.fetch_add(1, Ordering::Relaxed);
            }
            if unwiped {
                // SAFETY: forwarded from the caller.
                unsafe { free_unwiped(ptr, layout) }
            } else {
                // SAFETY: forwarded from the caller.
                unsafe { production(armed).dealloc(ptr, layout) }
            }
        });
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        with_armed(|armed, unwiped| {
            if armed {
                FREED.fetch_add(1, Ordering::Relaxed);
            }
            if !unwiped {
                // SAFETY: forwarded from the caller.
                return unsafe { production(armed).realloc(ptr, layout, new_size) };
            }
            // Unwiped mode still always moves, so in-place growth cannot hide
            // a stale copy, and the new block is zeroed so its grown region
            // is initialized.
            let Ok(new_layout) = Layout::from_size_align(new_size, layout.align()) else {
                return std::ptr::null_mut();
            };
            // SAFETY: `new_layout` is valid and non-zero-sized.
            let new_ptr = unsafe { System.alloc_zeroed(new_layout) };
            if !new_ptr.is_null() {
                // SAFETY: both blocks are live and distinct; the old block is
                // freed once.
                unsafe {
                    std::ptr::copy_nonoverlapping(ptr, new_ptr, layout.size().min(new_size));
                    free_unwiped(ptr, layout);
                }
            }
            new_ptr
        })
    }
}

/// Asks the kernel to let the parent process trace this one
/// (`PTRACE_TRACEME` on Linux, `PT_TRACE_ME` on macOS). Used to test
/// [`crate::tracer_present`] from a child process. Never call it in a
/// process that will exec or receive signals: the parent must then handle
/// ptrace stops.
#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
pub fn trace_me() -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    // SAFETY: PTRACE_TRACEME ignores its other arguments.
    let rc = unsafe {
        libc::ptrace(
            libc::PTRACE_TRACEME,
            0 as libc::pid_t,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    #[cfg(target_os = "macos")]
    // SAFETY: PT_TRACE_ME ignores its other arguments.
    let rc = unsafe { libc::ptrace(libc::PT_TRACE_ME, 0, std::ptr::null_mut(), 0) };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Linux: attaches to `pid` with `PTRACE_ATTACH`, waits for the attach
/// stop and detaches again. Returns the attach error when the kernel
/// refuses, which is what gate 19 expects for a non-dumpable process.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn try_attach(pid: i32) -> io::Result<()> {
    let null = std::ptr::null_mut::<libc::c_void>();
    // SAFETY: PTRACE_ATTACH takes a pid and ignores addr and data.
    if unsafe { libc::ptrace(libc::PTRACE_ATTACH, pid, null, null) } == -1 {
        return Err(io::Error::last_os_error());
    }
    let mut status = 0;
    // SAFETY: `status` is writable; we wait only for the attach stop.
    if unsafe { libc::waitpid(pid, &mut status, libc::__WALL) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the tracee is in a ptrace stop; data 0 delivers no signal.
    if unsafe { libc::ptrace(libc::PTRACE_DETACH, pid, null, null) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
