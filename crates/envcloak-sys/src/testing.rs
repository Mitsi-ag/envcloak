//! Test support, behind the `testing` feature. Release binaries never enable
//! it.
//!
//! [`sync_counts`] is the counting shim for durable writes: how many
//! `F_FULLFSYNC` and `fsync` calls [`crate::sync_file`] made on this thread.
//! [`record_syncs`] and [`take_synced`] name the files it flushed, and
//! [`fail_sync_after`] makes one of its calls fail.
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
//! freed block safe to read: a typed write of a struct with padding leaves
//! the padding bytes uninitialized again, and loading them is undefined
//! behavior, in Rust and equally in a C library call such as `memcmp`
//! (F-16). So neither Rust nor C code here reads a block before it is
//! wiped. The probe asks the kernel to copy the block into an initialized
//! buffer ([`read_own_memory`]: `process_vm_readv` on Linux,
//! `mach_vm_read_overwrite` on macOS). The kernel copies bytes, not typed
//! values, outside both languages' abstract machines, and what it writes
//! into the buffer is initialized, as with `read(2)`. The needle search
//! runs on that copy, in chunks of [`INSPECT_CHUNK`] bytes that overlap by
//! one byte less than the window, so no window is split. After the wipe
//! every byte has been written with a zero, and Rust reads the block
//! directly to check that. A block the kernel refuses to copy makes
//! [`ProbeSession::finish`] panic rather than pass unseen.
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

/// The command line of the test binaries with their own `main`.
pub mod libtest;

/// The exit code of a PTY monitor (built with this feature) that found a
/// string prepared for the command still there after it wiped them:
/// `SessionMonitor::finish` returns it instead of the monitor's own.
pub use crate::pty_monitor::PREPARED_KEPT_EXIT;

/// Set by [`force_descriptor_fallback`]: the PTY monitor passes over its
/// primary way of closing descriptors (`close_range` on Linux,
/// `proc_pidinfo` on macOS).
pub(crate) static DESCRIPTOR_FALLBACK: AtomicBool = AtomicBool::new(false);

/// Makes the PTY monitors this process forks from now on close their
/// inherited descriptors the second way (Linux: the `/proc/self/fd`
/// listing; macOS has none, so they refuse to start the command), for the
/// test of what happens where the first way fails.
pub fn force_descriptor_fallback() {
    DESCRIPTOR_FALLBACK.store(true, Ordering::Relaxed);
}

/// Set by [`force_no_group_signal`].
#[cfg(target_os = "linux")]
pub(crate) static NO_GROUP_SIGNAL: AtomicBool = AtomicBool::new(false);

/// While `on`, this process's `OwnedSession` deliveries act as on a Linux
/// kernel before 6.9, whose `pidfd_send_signal` refuses
/// `PIDFD_SIGNAL_PROCESS_GROUP` with `EINVAL`: nothing is sent and the
/// delivery reports `NoJob::Unsupported`, so `forward_signal` narrows
/// SIGTERM and SIGHUP as it does there. For the test of that route on any
/// kernel.
#[cfg(target_os = "linux")]
pub fn force_no_group_signal(on: bool) {
    NO_GROUP_SIGNAL.store(on, Ordering::SeqCst);
}

/// How a test makes a process have its children reaped by the kernel on
/// their own, as a parent or a library may leave it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildReaping {
    /// SIGCHLD ignored (`SIG_IGN`). Linux reaps on its own, set in the
    /// process or inherited across `exec`. macOS 26.4.1 (measured): when
    /// the process sets it itself, the kernel reaps on its own and
    /// `sigaction` reads back `SA_NOCLDWAIT` set as well; when it was
    /// inherited across `exec`, the kernel does not reap on its own.
    Ignored,
    /// The default action with `SA_NOCLDWAIT`, set in the process (it does
    /// not survive `exec`).
    NoWait,
}

/// Sets this process's SIGCHLD as `how` says (as another library in the
/// process might). Async-signal-safe: `sigaction` only.
///
/// # Errors
/// `sigaction`'s.
pub fn set_sigchld(how: ChildReaping) -> io::Result<()> {
    // SAFETY: sigaction is plain data; zeroed is an empty mask and no
    // flags.
    let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
    match how {
        ChildReaping::Ignored => act.sa_sigaction = libc::SIG_IGN,
        ChildReaping::NoWait => {
            act.sa_sigaction = libc::SIG_DFL;
            act.sa_flags = libc::SA_NOCLDWAIT;
        }
    }
    // SAFETY: `act` is initialized.
    if unsafe { libc::sigaction(libc::SIGCHLD, &act, std::ptr::null_mut()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Makes the child `cmd` starts begin with SIGCHLD ignored, which `exec`
/// keeps: for tests of a process that inherited it. (`SA_NOCLDWAIT` with
/// the default action does not survive `exec`; [`set_sigchld`] sets it
/// in the process itself.)
pub fn sigchld_ignored_on_spawn(cmd: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: the closure calls only sigaction, through set_sigchld, which
    // is async-signal-safe, and allocates nothing.
    unsafe {
        cmd.pre_exec(|| set_sigchld(ChildReaping::Ignored));
    }
}

/// This process's SIGCHLD setup: (ignored, `SA_NOCLDWAIT` set).
pub fn sigchld_setup() -> (bool, bool) {
    // SAFETY: sigaction is plain data; a null new action only reads the
    // current one into `old`.
    let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    let rc = unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut old) };
    assert_eq!(rc, 0, "sigaction: {}", io::Error::last_os_error());
    (
        old.sa_sigaction == libc::SIG_IGN,
        old.sa_flags & libc::SA_NOCLDWAIT != 0,
    )
}

/// Maximum number of needles a session can watch for.
pub const MAX_NEEDLES: usize = 32;
/// Maximum length of one needle.
pub const MAX_NEEDLE_LEN: usize = 512;
/// How many bytes of a freed block the probe copies out and searches at a
/// time. Consecutive chunks overlap by `window - 1` bytes.
pub const INSPECT_CHUNK: usize = 4096;

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
/// Blocks the kernel would not copy out, so the probe could not inspect.
static UNREADABLE: AtomicUsize = AtomicUsize::new(0);

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
    /// than 1 or longer than [`MAX_NEEDLE_LEN`] bytes, or `window < 1`. The
    /// message never includes needle bytes.
    pub fn start(needles: &[&[u8]], window: usize, mode: ProbeMode) -> Self {
        assert!(needles.len() <= MAX_NEEDLES, "too many probe needles");
        assert!(window >= 1, "probe window must be at least 1 byte");
        for n in needles {
            assert!(
                (1..=MAX_NEEDLE_LEN).contains(&n.len()),
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
        for c in [&FREED, &HELD, &NOT_ZEROED, &RELEASED, &UNREADABLE] {
            c.store(0, Ordering::Relaxed);
        }
        ARMED.store(true, Ordering::SeqCst);
        ProbeSession { _serial: serial }
    }

    /// Disarms the probe and returns what it saw.
    ///
    /// # Panics
    /// When the kernel refused to copy out a freed block, so the probe could
    /// not inspect it (never seen in practice; see [`read_own_memory`]).
    pub fn finish(self) -> ProbeReport {
        disarm();
        let unreadable = UNREADABLE.load(Ordering::SeqCst);
        assert!(
            unreadable == 0,
            "the probe could not copy {unreadable} freed block(s) out through the kernel, so it cannot vouch for them"
        );
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

/// Copies `dst.len()` bytes of this process's memory at `addr` into `dst`
/// through the kernel: `process_vm_readv` on this process on Linux,
/// `mach_vm_read_overwrite` on this task on macOS. The kernel copies raw
/// bytes, so the source may hold uninitialized bytes (struct padding), and
/// `dst` comes back initialized. Nothing in this process dereferences
/// `addr`: an unmapped range is an error (EFAULT, KERN_INVALID_ADDRESS),
/// not a fault. A range another thread writes during the call may be
/// copied torn. Neither allocates nor panics, so the probe calls it from
/// inside the allocator.
///
/// # Errors
/// When the kernel refuses or copies fewer bytes.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn read_own_memory(addr: *const u8, dst: &mut [u8]) -> io::Result<()> {
    // SAFETY: getpid has no preconditions.
    let pid = unsafe { libc::getpid() };
    let mut done = 0usize;
    while done < dst.len() {
        let rest = dst.len() - done;
        let local = libc::iovec {
            iov_base: dst.as_mut_ptr().wrapping_add(done).cast(),
            iov_len: rest,
        };
        let remote = libc::iovec {
            iov_base: addr.wrapping_add(done).cast_mut().cast(),
            iov_len: rest,
        };
        // SAFETY: `local` describes the last `rest` bytes of `dst`, which
        // are writable. The kernel reads the remote range itself and
        // reports an unmapped one as EFAULT; this process never
        // dereferences it.
        let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        done += n.unsigned_abs();
    }
    Ok(())
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    /// `<mach/mach_vm.h>`: copies `size` bytes at `address` in
    /// `target_task` to `data` in this task.
    fn mach_vm_read_overwrite(
        target_task: libc::vm_map_t,
        address: libc::mach_vm_address_t,
        size: libc::mach_vm_size_t,
        data: libc::mach_vm_address_t,
        outsize: *mut libc::mach_vm_size_t,
    ) -> libc::kern_return_t;

    /// `<mach/mach_init.h>`: this task's port, what `mach_task_self()`
    /// returns.
    static mach_task_self_: libc::mach_port_t;
}

/// Copies `dst.len()` bytes of this process's memory at `addr` into `dst`
/// through the kernel. See the Linux version.
///
/// # Errors
/// When the kernel refuses or copies fewer bytes.
#[cfg(target_os = "macos")]
pub fn read_own_memory(addr: *const u8, dst: &mut [u8]) -> io::Result<()> {
    if dst.is_empty() {
        return Ok(());
    }
    let len = dst.len() as libc::mach_vm_size_t;
    let mut copied: libc::mach_vm_size_t = 0;
    // SAFETY: `mach_task_self_` is a port name set before main and never
    // written again. The destination is `dst`, writable for `len` bytes;
    // the kernel reads the source range itself and reports an unmapped one
    // as an error.
    let kr = unsafe {
        mach_vm_read_overwrite(
            mach_task_self_,
            addr.addr() as libc::mach_vm_address_t,
            len,
            dst.as_mut_ptr().addr() as libc::mach_vm_address_t,
            &mut copied,
        )
    };
    if kr != libc::KERN_SUCCESS {
        return Err(io::ErrorKind::Other.into());
    }
    if copied != len {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(())
}

/// Whether the block holds a window of any needle.
///
/// Neither Rust nor C reads the block itself: it may hold uninitialized
/// padding (see the module documentation). Each chunk is first copied out
/// by the kernel, and the search runs on the copy. A block the kernel does
/// not copy counts as unreadable, which fails the session.
///
/// # Safety
/// `ptr` is valid for reads of `size` bytes.
unsafe fn holds_needle(ptr: *const u8, size: usize) -> bool {
    let overlap = WINDOW
        .load(Ordering::Relaxed)
        .min(MAX_NEEDLE_LEN)
        .saturating_sub(1);
    let mut buf = [0u8; INSPECT_CHUNK];
    let mut off = 0usize;
    loop {
        let n = (size - off).min(INSPECT_CHUNK);
        let Some(chunk) = buf.get_mut(..n) else {
            return false;
        };
        if read_own_memory(ptr.wrapping_add(off), chunk).is_err() {
            UNREADABLE.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        if copy_holds_needle(chunk) {
            return true;
        }
        if off + n >= size {
            return false;
        }
        // A window of at most `overlap + 1` bytes that did not fit in this
        // chunk starts within its last `overlap` bytes.
        off += n - overlap;
    }
}

/// Whether `copy`, an initialized copy of (part of) a block, holds a window
/// of any needle. libc's `memmem` finds anchors, and `memcmp` confirms
/// whole windows around each anchor hit. For a window of `w` bytes,
/// anchors of `a = ceil(w / 2)` bytes every `w - a + 1` bytes of the needle
/// guarantee that every window of the needle contains one whole anchor.
fn copy_holds_needle(copy: &[u8]) -> bool {
    let count = NEEDLE_COUNT.load(Ordering::Relaxed);
    let window = WINDOW.load(Ordering::Relaxed);
    // AtomicU8 has the same in-memory representation as u8.
    let table = NEEDLE_BYTES.as_ptr().cast::<u8>();
    for (k, slot) in NEEDLE_LENS.iter().enumerate().take(count) {
        let len = slot.load(Ordering::Relaxed);
        let win = window.min(len);
        if win == 0 || copy.len() < win {
            continue;
        }
        // SAFETY: needle `k` occupies `len <= MAX_NEEDLE_LEN` bytes of the
        // table from this offset.
        let needle = unsafe { table.add(k * MAX_NEEDLE_LEN) };
        let anchor = win.div_ceil(2);
        let stride = win - anchor + 1;
        let mut a = 0;
        while a + anchor <= len {
            // SAFETY: `a + anchor <= len`, so the anchor lies in the needle,
            // and `copy` is an initialized slice.
            if unsafe { window_at_anchor(copy.as_ptr(), copy.len(), needle, len, win, a, anchor) } {
                return true;
            }
            a += stride;
        }
    }
    false
}

/// Whether the copy (`size` bytes at `ptr`) holds a `win`-byte window of the
/// needle (`len` bytes at `needle`) that contains the needle's anchor
/// `needle[a..a + anchor]`.
///
/// # Safety
/// `ptr` is valid for reads of `size` initialized bytes and `needle` for
/// `len` bytes, with `a + anchor <= len`, `anchor >= 1` and `win <= len`.
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
        // SAFETY: the haystack is the copy's last `size - from` bytes, all
        // initialized, and the anchor lies inside the needle; memmem only
        // reads them.
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

/// How many times [`crate::sync_file`] made each call on one thread.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncCounts {
    /// Successful `fcntl(F_FULLFSYNC)` calls (macOS).
    pub full_fsync: u64,
    /// Successful `fsync` calls.
    pub fsync: u64,
}

thread_local! {
    static SYNCS: core::cell::Cell<SyncCounts> = const {
        core::cell::Cell::new(SyncCounts { full_fsync: 0, fsync: 0 })
    };
}

/// The successful [`crate::sync_file`] calls this thread has made so far,
/// by kind: the counting shim a test reads before and after a write path.
pub fn sync_counts() -> SyncCounts {
    SYNCS.with(core::cell::Cell::get)
}

pub(crate) fn note_sync(m: crate::SyncMethod, f: &std::fs::File) {
    SYNCS.with(|c| {
        let mut n = c.get();
        match m {
            crate::SyncMethod::FullFsync => n.full_fsync += 1,
            crate::SyncMethod::Fsync => n.fsync += 1,
        }
        c.set(n);
    });
    SYNCED.with(|r| {
        if let Some(v) = r.borrow_mut().as_mut() {
            use std::os::unix::fs::MetadataExt;
            // A file that cannot be stat'ed is recorded as (0, 0), which
            // names no file, so a test expecting it fails.
            let id = f.metadata().map_or((0, 0), |m| (m.dev(), m.ino()));
            v.push(id);
        }
    });
}

thread_local! {
    /// The files [`crate::sync_file`] flushed on this thread since
    /// [`record_syncs`], or `None` when it is not recording.
    static SYNCED: core::cell::RefCell<Option<Vec<(u64, u64)>>> =
        const { core::cell::RefCell::new(None) };
    /// How many more [`crate::sync_file`] calls on this thread run before
    /// one fails ([`fail_sync_after`]).
    static FAIL_SYNC_AFTER: core::cell::Cell<Option<u32>> = const { core::cell::Cell::new(None) };
}

/// Starts recording, on this thread, the device and inode of every file
/// and directory [`crate::sync_file`] flushes, so a test can show which
/// directory entries a write path made durable. Starting again discards
/// what was recorded.
pub fn record_syncs() {
    SYNCED.with(|r| *r.borrow_mut() = Some(Vec::new()));
}

/// What this thread recorded since [`record_syncs`], in order, as
/// (device, inode); recording stops. Empty when it was not recording.
pub fn take_synced() -> Vec<(u64, u64)> {
    SYNCED.with(|r| r.borrow_mut().take().unwrap_or_default())
}

/// Lets this thread's next `n` [`crate::sync_file`] calls run and makes the
/// one after fail with `EIO` without flushing, as a failing drive would.
/// The failed call is neither counted nor recorded.
pub fn fail_sync_after(n: u32) {
    FAIL_SYNC_AFTER.with(|c| c.set(Some(n)));
}

/// Whether this [`crate::sync_file`] call is the one [`fail_sync_after`]
/// asked to fail.
pub(crate) fn sync_fails_now() -> bool {
    FAIL_SYNC_AFTER.with(|c| match c.get() {
        None => false,
        Some(0) => {
            c.set(None);
            true
        }
        Some(n) => {
            c.set(Some(n - 1));
            false
        }
    })
}

/// Linux: whether [`crate::peer_identity`] skips `SO_PEERPIDFD` and takes
/// the `SO_PEERCRED` fallback, as on kernels before 6.5.
static PEERCRED_FALLBACK: AtomicBool = AtomicBool::new(false);

/// Linux: makes [`crate::peer_identity`] take the `SO_PEERCRED` fallback
/// (true) or use `SO_PEERPIDFD` where the kernel has it (false, the
/// default), so tests cover both paths on one kernel. Process-wide.
pub fn force_peercred_fallback(on: bool) {
    PEERCRED_FALLBACK.store(on, Ordering::SeqCst);
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn peercred_fallback_forced() -> bool {
    PEERCRED_FALLBACK.load(Ordering::SeqCst)
}

/// Linux: a pid that [`crate::process_start_time`] reports as a live
/// process with the given start time, and the start time.
static REUSED_PID: Mutex<Option<(i32, crate::StartTime)>> = Mutex::new(None);

/// Linux: makes [`crate::process_start_time`], and so the start time
/// [`crate::peer_identity`] reads, report `pid` as a live process that
/// started at `start`: the pid of a peer that exited, taken over by another
/// process, without waiting for the kernel to reuse it. `None` turns it
/// off. Process-wide.
pub fn pretend_pid_reused(reused: Option<(i32, crate::StartTime)>) {
    *REUSED_PID.lock().unwrap_or_else(PoisonError::into_inner) = reused;
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn pretended_start_time(pid: i32) -> Option<crate::StartTime> {
    match *REUSED_PID.lock().unwrap_or_else(PoisonError::into_inner) {
        Some((p, start)) if p == pid => Some(start),
        _ => None,
    }
}

/// Sends `sig` to the calling thread only, with `pthread_kill`. A signal
/// the thread blocks then stays pending for it, where
/// [`crate::TerminationSignals::wait`] collects it, instead of reaching
/// another thread.
pub fn signal_this_thread(sig: i32) -> io::Result<()> {
    // SAFETY: pthread_self is valid for the calling thread, and pthread_kill
    // with a valid signal number only queues the signal.
    let rc = unsafe { libc::pthread_kill(libc::pthread_self(), sig) };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }
    Ok(())
}

/// Does what the installed [`crate::SignalRelay`]'s handler does with a
/// signal that finds the relay's pipe full (review F-71): keeps `sig`,
/// sent by a process or not (`by_process`), aside for the reader, and
/// wakes it. Nothing is signalled, so a test chooses exactly which signal
/// was kept and between which marks. Does nothing while no relay is
/// installed.
pub fn keep_as_if_the_relay_was_full(sig: i32, by_process: bool) {
    crate::child::keep_as_if_full(sig, by_process);
}

/// Blocks `sig` for the calling thread, as a signal mask inherited
/// through `exec` blocks it for the thread a program starts on (review
/// R-8). Returns whether the thread blocked it already.
pub fn block_on_this_thread(sig: i32) -> io::Result<bool> {
    Ok(!crate::child::mask_signals(libc::SIG_BLOCK, &[sig])?.is_empty())
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
    spawn_traced_with_fds(cmd, &[])
}

/// Linux: [`spawn_traced`], with descriptors of this process given to the
/// child at chosen numbers: each `(from, to)` becomes the child's
/// descriptor `to`, open to what `from` is open to (the same offset), as
/// a shell's `3<file` does. `from` stays close-on-exec here, so no other
/// child gets it.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn spawn_traced_with_fds(
    cmd: &mut std::process::Command,
    fds: &[(std::os::fd::BorrowedFd<'_>, i32)],
) -> io::Result<std::process::Child> {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;

    let pairs: Vec<(i32, i32)> = fds.iter().map(|(f, to)| (f.as_raw_fd(), *to)).collect();
    // SAFETY: the hook runs between fork and exec. It only calls dup2 and
    // ptrace, which are async-signal-safe, reads `pairs` (allocated before
    // the fork) and allocates nothing. A descriptor dup2 makes has no
    // close-on-exec flag, so the program gets it.
    unsafe {
        cmd.pre_exec(move || {
            for &(from, to) in &pairs {
                if from != to && libc::dup2(from, to) == -1 {
                    return Err(io::Error::last_os_error());
                }
            }
            trace_me()
        });
    }
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

/// Makes the calling process the leader of a new session with no
/// controlling terminal (`setsid(2)`), as a program escaping its
/// session does. Fails with `EPERM` in a process group leader.
pub fn setsid() -> io::Result<()> {
    // SAFETY: setsid has no preconditions; it fails without effect when
    // the caller leads a process group.
    if unsafe { libc::setsid() } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The pseudo-terminal [`enter_terminal_session`] made this process's
/// controlling terminal, both ends, held open for the life of the
/// process; or the error of the one attempt.
static TERMINAL: std::sync::OnceLock<Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd), i32>> =
    std::sync::OnceLock::new();

/// Makes the calling process the leader of a new session whose
/// controlling terminal is a new pseudo-terminal, as a shell in a terminal
/// window is. The daemon then sees the process (without an agent above
/// it) as a terminal subject, the only kind that may give a proof (SPEC
/// §10b), whatever terminal the tests were started from, or none as in
/// CI. Both ends stay open for the life of the process, and nothing reads
/// or writes them. Runs once; later calls give the first call's result.
///
/// # Errors
/// When the process leads a process group but not its session
/// (`setsid` fails), or no pseudo-terminal can be opened or made the
/// controlling one.
pub fn enter_terminal_session() -> io::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    let made = TERMINAL.get_or_init(|| {
        let errno = || {
            io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO)
        };
        // SAFETY: getsid(0) and getpid have no preconditions.
        let leads = unsafe { libc::getsid(0) == libc::getpid() };
        if !leads {
            setsid().map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        }
        let (mut m, mut s): (libc::c_int, libc::c_int) = (-1, -1);
        // SAFETY: `m` and `s` are writable; a null name, termios and window
        // size are allowed and leave the defaults.
        let rc = unsafe {
            libc::openpty(
                &mut m,
                &mut s,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if rc == -1 {
            return Err(errno());
        }
        // SAFETY: openpty returned two open descriptors that nothing else
        // owns.
        let (master, slave) = unsafe { (OwnedFd::from_raw_fd(m), OwnedFd::from_raw_fd(s)) };
        // SAFETY: `slave` is an open terminal and this process leads a
        // session without one; argument 0 steals no terminal.
        if unsafe { libc::ioctl(slave.as_raw_fd(), libc::TIOCSCTTY as _, 0) } == -1 {
            return Err(errno());
        }
        Ok((master, slave))
    });
    made.as_ref()
        .map(drop)
        .map_err(|e| io::Error::from_raw_os_error(*e))
}

/// Names the [`crate::panic_point`] a test build panics at.
pub const PANIC_SITE: &str = "ENVCLOAK_TEST_PANIC";
/// Names a file whose contents the injected panic's message holds.
pub const PANIC_FILE: &str = "ENVCLOAK_TEST_PANIC_FILE";

/// Panics when [`PANIC_SITE`] names `site`, with the contents of the file
/// [`PANIC_FILE`] names (read as text, lossily) in the message: gate 12's
/// injected panic, whose message holds a fixture the panic hook must not
/// show. The panic's place is the caller's.
#[track_caller]
pub(crate) fn panic_point(site: &str) {
    if std::env::var_os(PANIC_SITE).is_none_or(|s| s != site) {
        return;
    }
    let payload = std::env::var_os(PANIC_FILE)
        .and_then(|p| std::fs::read(p).ok())
        .unwrap_or_default();
    panic!(
        "injected panic at {site}, holding: {}",
        String::from_utf8_lossy(&payload)
    );
}

/// Names the [`crate::pause_point`] a test build stops at.
pub const PAUSE_SITE: &str = "ENVCLOAK_TEST_PAUSE";
/// Names the file whose existence lets a stopped [`crate::pause_point`] go
/// on.
pub const PAUSE_RELEASE: &str = "ENVCLOAK_TEST_PAUSE_RELEASE";

/// Stops at `site` when [`PAUSE_SITE`] names it, until the file
/// [`PAUSE_RELEASE`] names exists (at most a minute).
pub(crate) fn pause_point(site: &str) {
    if std::env::var_os(PAUSE_SITE).is_none_or(|s| s != site) {
        return;
    }
    let Some(release) = std::env::var_os(PAUSE_RELEASE).map(std::path::PathBuf::from) else {
        return;
    };
    if release.exists() {
        return;
    }
    {
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), "envcloak test: paused at {site}");
    }
    let end = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while !release.exists() && std::time::Instant::now() < end {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// Names the time, in milliseconds, a test build of `envcloakd` waits for
/// a frame to start on an open connection, in place of its bound
/// ([`crate::idle_connection_override`]).
pub const IDLE_CONNECTION_MS: &str = "ENVCLOAK_TEST_IDLE_CONNECTION_MS";

/// [`IDLE_CONNECTION_MS`] as a duration: 1 to 600000 milliseconds, in
/// ASCII digits; anything else is no override.
pub(crate) fn idle_connection() -> Option<std::time::Duration> {
    let v = std::env::var_os(IDLE_CONNECTION_MS)?;
    let v = v.to_str()?;
    if v.is_empty() || v.len() > 6 || !v.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let ms: u64 = v.parse().ok()?;
    (1..=600_000)
        .contains(&ms)
        .then(|| std::time::Duration::from_millis(ms))
}

/// Names the switch of a test build's trace ([`crate::test_trace`]): `1`
/// turns it on, anything else leaves it off.
pub const TRACE: &str = "ENVCLOAK_TEST_TRACE";

/// Whether [`TRACE`] is `1`.
pub(crate) fn trace() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os(TRACE).is_some_and(|v| v == "1"))
}

/// Names the [`crate::fail_point`] at which a test build fails.
pub const FAIL_SITE: &str = "ENVCLOAK_TEST_FAIL";

/// An error, of kind [`std::io::ErrorKind::Other`], when [`FAIL_SITE`]
/// names `site`.
pub(crate) fn fail_point(site: &str) -> std::io::Result<()> {
    if std::env::var_os(FAIL_SITE).is_some_and(|s| s == site) {
        return Err(std::io::Error::other("an injected failure"));
    }
    Ok(())
}

/// The memory a process holds now and the most it has held since it
/// started, in KiB ([`process_memory`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessMemory {
    pub now_kib: u64,
    pub peak_kib: u64,
}

/// The memory process `pid` holds now and the most it has held since it
/// started, as the kernel counts them: on Linux its resident set and that
/// set's high-water mark (`VmRSS` and `VmHWM` in `/proc/<pid>/status`), so
/// no peak between two samples is missed. A test bounds a daemon's memory
/// with it.
///
/// # Errors
/// When the process is gone or its status cannot be read or parsed.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn process_memory(pid: i32) -> io::Result<ProcessMemory> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
    let field = |name: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .and_then(|v| v.trim().strip_suffix("kB"))
            .and_then(|v| v.trim().parse::<u64>().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no such status field"))
    };
    Ok(ProcessMemory {
        now_kib: field("VmRSS:")?,
        peak_kib: field("VmHWM:")?,
    })
}

/// The memory process `pid` holds now and the most it has held since it
/// started, as the kernel counts them: on macOS its physical footprint
/// (what Activity Monitor shows as its memory: the pages it wrote, resident
/// or compressed) and that footprint's lifetime maximum
/// (`proc_pid_rusage`, `RUSAGE_INFO_V4`), so no peak between two samples is
/// missed. A test bounds a daemon's memory with it.
///
/// # Errors
/// When the process is gone or this user may not ask about it.
#[cfg(target_os = "macos")]
pub fn process_memory(pid: i32) -> io::Result<ProcessMemory> {
    let mut info = std::mem::MaybeUninit::<libc::rusage_info_v4>::zeroed();
    // SAFETY: `info` is a writable `rusage_info_v4`, the struct the
    // `RUSAGE_INFO_V4` flavor fills, and lives for the call.
    let r = unsafe {
        libc::proc_pid_rusage(
            pid,
            libc::RUSAGE_INFO_V4,
            info.as_mut_ptr().cast::<libc::rusage_info_t>(),
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: zeroed before the call, which filled it; every field is an
    // integer, so any bytes are a valid value.
    let info = unsafe { info.assume_init() };
    Ok(ProcessMemory {
        now_kib: info.ri_phys_footprint / 1024,
        peak_kib: info.ri_lifetime_max_phys_footprint / 1024,
    })
}
