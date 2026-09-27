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
//! region of a reallocation (the F-10 lesson). That alone does not make a
//! freed block safe to read from Rust: a typed write of a struct with
//! padding leaves the padding bytes uninitialized again, and loading them as
//! `u8` is undefined behavior (F-16). So Rust code here never loads a byte of
//! a block before it is wiped. The needle search runs in C, through libc's
//! `memmem` and `memcmp`, where reading indeterminate `unsigned char` values
//! is defined; Rust only sees the pointer or comparison result. After the
//! wipe every byte has been written with a zero, and Rust reads the block
//! directly to check that.
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
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
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
/// Needle `k` starts at `k * MAX_NEEDLE_LEN`. Written only while the probe is
/// disarmed and no inspection is in flight, and read by C code (`memmem`,
/// `memcmp`) only while it is armed, so the accesses never race.
static NEEDLE_BYTES: [AtomicU8; MAX_NEEDLES * MAX_NEEDLE_LEN] =
    [const { AtomicU8::new(0) }; MAX_NEEDLES * MAX_NEEDLE_LEN];

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

        for (k, n) in needles.iter().enumerate() {
            let base = k * MAX_NEEDLE_LEN;
            for (i, b) in n.iter().enumerate() {
                NEEDLE_BYTES[base + i].store(*b, Ordering::Relaxed);
            }
            NEEDLE_LENS[k].store(n.len(), Ordering::Relaxed);
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
/// Rust never loads a byte of the block: it may hold uninitialized padding
/// (see the module documentation). libc's `memmem` finds anchors, and
/// `memcmp` confirms whole windows around each anchor hit. For a window of
/// `w` bytes, anchors of `a = ceil(w / 2)` bytes every `w - a + 1` bytes of
/// the needle guarantee that every window of the needle contains one whole
/// anchor.
///
/// # Safety
/// `ptr` is valid for reads of `size` bytes.
unsafe fn holds_needle(ptr: *const u8, size: usize) -> bool {
    let count = NEEDLE_COUNT.load(Ordering::Relaxed);
    let window = WINDOW.load(Ordering::Relaxed);
    // AtomicU8 has the same in-memory representation as u8.
    let table = NEEDLE_BYTES.as_ptr().cast::<u8>();
    for (k, slot) in NEEDLE_LENS.iter().enumerate().take(count) {
        let len = slot.load(Ordering::Relaxed);
        let win = window.min(len);
        if win == 0 || size < win {
            continue;
        }
        // SAFETY: needle `k` occupies `len <= MAX_NEEDLE_LEN` bytes of the
        // table from this offset.
        let needle = unsafe { table.add(k * MAX_NEEDLE_LEN) };
        let anchor = win.div_ceil(2);
        let stride = win - anchor + 1;
        let mut a = 0;
        while a + anchor <= len {
            // SAFETY: `a + anchor <= len`, so the anchor lies in the needle;
            // the caller guarantees the block.
            if unsafe { window_at_anchor(ptr, size, needle, len, win, a, anchor) } {
                return true;
            }
            a += stride;
        }
    }
    false
}

/// Whether the block holds a `win`-byte window of the needle (`len` bytes at
/// `needle`) that contains the needle's anchor `needle[a..a + anchor]`.
///
/// # Safety
/// `ptr` is valid for reads of `size` bytes and `needle` for `len` bytes,
/// with `a + anchor <= len`, `anchor >= 1` and `win <= len`.
unsafe fn window_at_anchor(
    ptr: *const u8,
    size: usize,
    needle: *const u8,
    len: usize,
    win: usize,
    a: usize,
    anchor: usize,
) -> bool {
    // Needle windows `[i, i + win)` that contain the anchor.
    let first = (a + anchor).saturating_sub(win);
    let last = a.min(len - win);
    let mut from = 0;
    while from + anchor <= size {
        // SAFETY: the haystack is the block's last `size - from` bytes and
        // the anchor lies inside the needle; memmem only reads them.
        let hit = unsafe {
            libc::memmem(
                ptr.add(from).cast(),
                size - from,
                needle.add(a).cast(),
                anchor,
            )
        };
        if hit.is_null() {
            return false;
        }
        let h = hit.cast::<u8>().addr() - ptr.addr();
        for i in first..=last {
            // The window starts `a - i` bytes before the anchor hit.
            let Some(start) = h.checked_sub(a - i) else {
                continue;
            };
            if start + win > size {
                continue;
            }
            // SAFETY: both ranges are in bounds, as checked above.
            if unsafe { libc::memcmp(ptr.add(start).cast(), needle.add(i).cast(), win) } == 0 {
                return true;
            }
        }
        from = h + 1;
    }
    false
}

/// # Safety
/// `ptr` is valid for reads of `size` bytes, all of them written (the block
/// was just wiped), so Rust may load them.
unsafe fn all_zero(ptr: *const u8, size: usize) -> bool {
    // SAFETY: guaranteed by the caller.
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

/// Linux: the calling thread's kernel thread id.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn current_tid() -> i32 {
    // SAFETY: gettid has no preconditions.
    unsafe { libc::gettid() }
}

/// Linux: waits for a ptrace stop of `tid`, retrying on EINTR. Returns the
/// wait status.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn wait_stop(tid: i32) -> io::Result<i32> {
    let mut status = 0;
    loop {
        // SAFETY: `status` is writable; __WALL also waits for tracees that
        // are threads of another process.
        if unsafe { libc::waitpid(tid, &mut status, libc::__WALL) } != -1 {
            break;
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
    if libc::WIFSTOPPED(status) {
        Ok(status)
    } else {
        Err(io::Error::other("the tracee exited instead of stopping"))
    }
}

/// Linux: attaches to thread `tid` (of any process, or a process's main
/// thread) with `PTRACE_ATTACH` and waits for its attach stop. The thread
/// stays stopped and traced until [`detach`]; if this process exits first,
/// the kernel detaches it.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn attach(tid: i32) -> io::Result<()> {
    let null = std::ptr::null_mut::<libc::c_void>();
    // SAFETY: PTRACE_ATTACH takes a thread id and ignores addr and data.
    if unsafe { libc::ptrace(libc::PTRACE_ATTACH, tid, null, null) } == -1 {
        return Err(io::Error::last_os_error());
    }
    wait_stop(tid).map(drop)
}

/// Linux: detaches from thread `tid`, which must be in a ptrace stop, and
/// lets it run without delivering a signal.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn detach(tid: i32) -> io::Result<()> {
    let null = std::ptr::null_mut::<libc::c_void>();
    // SAFETY: the tracee is in a ptrace stop; data 0 delivers no signal.
    if unsafe { libc::ptrace(libc::PTRACE_DETACH, tid, null, null) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Linux: attaches to `pid` with `PTRACE_ATTACH`, waits for the attach
/// stop and detaches again. Returns the attach error when the kernel
/// refuses, which is what gate 19 expects for a non-dumpable process.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn try_attach(pid: i32) -> io::Result<()> {
    attach(pid)?;
    detach(pid)
}

/// Linux: spawns `cmd` traced by this process from its first instruction:
/// the child calls `PTRACE_TRACEME` before `exec`, and this process waits
/// for the exec stop and continues it. The child stays traced; this process
/// is its parent, so `Child::wait` sees its exit. Only for programs that do
/// not exec again or receive stopping signals, whose ptrace stops nobody
/// would continue. `SIGKILL` is fine.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn spawn_traced(cmd: &mut std::process::Command) -> io::Result<std::process::Child> {
    use std::os::unix::process::CommandExt;

    // SAFETY: the hook runs between fork and exec and only makes the
    // ptrace system call, which is async-signal-safe and does not allocate.
    unsafe { cmd.pre_exec(trace_me) };
    let mut child = cmd.spawn()?;
    let pid = i32::try_from(child.id()).map_err(io::Error::other)?;
    let started = wait_stop(pid).and_then(|status| {
        if libc::WSTOPSIG(status) != libc::SIGTRAP {
            return Err(io::Error::other("expected the exec stop"));
        }
        let null = std::ptr::null_mut::<libc::c_void>();
        // SAFETY: the tracee is in its exec stop; data 0 delivers no signal.
        if unsafe { libc::ptrace(libc::PTRACE_CONT, pid, null, null) } == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    });
    if let Err(e) = started {
        let _ = child.kill();
        let _ = child.wait();
        return Err(e);
    }
    Ok(child)
}
