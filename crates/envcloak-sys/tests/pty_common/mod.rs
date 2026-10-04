//! What the PTY tests share (`pty.rs`, `pty_topology.rs`,
//! `pty_signals.rs`): the allocator that aborts after a fork, a reader of a
//! PTY's master side that waits for what it expects up to a deadline (a
//! barrier, never a sleep), and the roles a copy of the test binary plays.
#![allow(dead_code, unsafe_code, clippy::unwrap_used)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Write;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

/// The variable that names the role a copy of the test binary plays.
pub const ROLE: &str = "ENVCLOAK_PTY_ROLE";
/// The directory a role writes its counters or reports into.
pub const DIR: &str = "ENVCLOAK_PTY_DIR";
/// A scenario, for the roles that have several.
pub const SCENARIO: &str = "ENVCLOAK_PTY_SCENARIO";

/// How long a test waits for what it expects before it fails.
pub const DEADLINE: Duration = Duration::from_secs(20);

/// The process that may allocate: the one that called
/// [`own_allocations`]. Any other (a child of `fork` that has not exec'd,
/// such as the PTY monitor) aborts on its first allocation.
static OWNER: AtomicI32 = AtomicI32::new(0);

/// A global allocator that aborts when called from any process but the
/// one that installed it (the PTY monitor and the command between `fork`
/// and `exec` must never allocate: M2 plan M2-17).
pub struct OwnPidOnly;

fn check() {
    let owner = OWNER.load(Ordering::Relaxed);
    // SAFETY: getpid has no preconditions.
    if owner != 0 && owner != unsafe { libc::getpid() } {
        const MSG: &[u8] = b"pty test: an allocation after fork\n";
        // SAFETY: writes a static message, then ends the process.
        unsafe {
            libc::write(2, MSG.as_ptr().cast(), MSG.len());
            libc::abort();
        }
    }
}

// SAFETY: every call goes to the system allocator unchanged, after a check
// that may only abort.
unsafe impl GlobalAlloc for OwnPidOnly {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        check();
        // SAFETY: the caller's contract, passed on.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        check();
        // SAFETY: as above.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        check();
        // SAFETY: as above.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        check();
        // SAFETY: as above.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

/// Makes this process the one that may allocate. Every `main` of a PTY
/// test binary calls it first.
pub fn own_allocations() {
    // SAFETY: getpid has no preconditions.
    OWNER.store(unsafe { libc::getpid() }, Ordering::Relaxed);
}

/// Writes `bytes` to `fd`, all of them.
pub fn put(fd: BorrowedFd<'_>, bytes: &[u8]) {
    let mut f = std::fs::File::from(fd.try_clone_to_owned().unwrap());
    f.write_all(bytes).unwrap();
}

/// What a PTY's master side has shown so far, read as it comes.
pub struct Screen {
    master: OwnedFd,
    seen: Vec<u8>,
    ended: bool,
}

impl Screen {
    pub fn new(master: OwnedFd) -> Self {
        Screen {
            master,
            seen: Vec::new(),
            ended: false,
        }
    }

    pub fn master(&self) -> BorrowedFd<'_> {
        use std::os::fd::AsFd;
        self.master.as_fd()
    }

    /// Types `bytes` on the terminal.
    pub fn type_bytes(&self, bytes: &[u8]) {
        put(self.master(), bytes);
    }

    pub fn seen(&self) -> &[u8] {
        &self.seen
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.seen).into_owned()
    }

    /// How many times `needle` has been shown.
    pub fn count(&self, needle: &str) -> usize {
        let n = needle.as_bytes();
        self.seen.windows(n.len()).filter(|w| *w == n).count()
    }

    /// Reads what comes until `done` holds for everything shown, the
    /// terminal ends, or [`DEADLINE`] passes. Returns whether `done`
    /// holds.
    pub fn wait_for(&mut self, done: impl Fn(&Screen) -> bool) -> bool {
        self.wait_for_within(DEADLINE, done)
    }

    pub fn wait_for_within(&mut self, limit: Duration, done: impl Fn(&Screen) -> bool) -> bool {
        let end = Instant::now() + limit;
        loop {
            if done(self) {
                return true;
            }
            if self.ended {
                return false;
            }
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            let mut p = libc::pollfd {
                fd: self.master.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // Short slices, so a condition on something else than the
            // screen (a child's exit) is looked at again.
            let ms = libc::c_int::try_from(left.as_millis().clamp(1, 50)).unwrap_or(50);
            // SAFETY: one initialized pollfd for an open descriptor.
            let rc = unsafe { libc::poll(&mut p, 1, ms) };
            if rc <= 0 {
                continue;
            }
            let mut buf = [0u8; 4096];
            // SAFETY: `buf` is writable for its length.
            let n =
                unsafe { libc::read(self.master.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            match usize::try_from(n) {
                Ok(0) => self.ended = true,
                Ok(n) => self.seen.extend_from_slice(&buf[..n]),
                Err(_) => {
                    let e = std::io::Error::last_os_error();
                    if e.kind() != std::io::ErrorKind::Interrupted {
                        // EIO: every slave descriptor is closed.
                        self.ended = true;
                    }
                }
            }
        }
    }

    /// Reads until the terminal ends (every descriptor on its slave side
    /// closed), up to [`DEADLINE`]; returns whether it did.
    pub fn wait_for_end(&mut self) -> bool {
        self.wait_for(|_| false);
        self.ended
    }

    /// The monitor's next event, reading the terminal meanwhile as the CLI
    /// does (the monitor waits, at the command's exit, until what the
    /// command wrote has been read), up to [`DEADLINE`]; `None` when no
    /// event came. Panics on a monitor lost.
    pub fn next_event(
        &mut self,
        monitor: &mut envcloak_sys::pty::SessionMonitor,
    ) -> Option<envcloak_sys::pty::MonitorEvent> {
        let end = Instant::now() + DEADLINE;
        while Instant::now() < end {
            if let Some(event) = monitor.next_event(Some(Duration::from_millis(10))).unwrap() {
                return Some(event);
            }
            self.wait_for_within(Duration::from_millis(10), |_| false);
        }
        None
    }

    /// Waits until `needle` has been shown `times` times.
    pub fn expect(&mut self, needle: &str, times: usize, what: &str) {
        let ok = self.wait_for(|s| s.count(needle) >= times);
        assert!(
            ok,
            "{what}: {needle:?} was not shown {times} time(s); the terminal showed:\n{}",
            self.text()
        );
    }
}

/// A copy of this test binary in `role`, with a cleared environment but
/// for `PATH` and the role's own variables.
pub fn role(role: &str) -> std::process::Command {
    let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
    cmd.env_clear().env("PATH", "/usr/bin:/bin").env(ROLE, role);
    cmd
}

/// Reads the role this process plays, if any.
pub fn my_role() -> Option<String> {
    std::env::var(ROLE).ok()
}

/// Waits for `child` (this process's own, unreaped) to change state as
/// `options` asks (`WEXITED`, `WSTOPPED`, `WCONTINUED`, with `WNOWAIT` to
/// leave it as it is), up to [`DEADLINE`]; returns `(si_code, si_status)`
/// or `None` when nothing changed in time. Polls without blocking, so a
/// test fails rather than hangs.
pub fn wait_child(pid: i32, options: libc::c_int) -> Option<(i32, i32)> {
    wait_child_within(pid, options, DEADLINE)
}

pub fn wait_child_within(pid: i32, options: libc::c_int, limit: Duration) -> Option<(i32, i32)> {
    let end = Instant::now() + limit;
    loop {
        // SAFETY: siginfo_t is plain data; waitid fills it in.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: `info` is writable; `pid` is this process's own child.
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                libc::id_t::try_from(pid).unwrap(),
                &mut info,
                options | libc::WNOHANG,
            )
        };
        // SAFETY: waitid filled `info` in or left it zeroed.
        if rc == 0 && unsafe { info.si_pid() } == pid {
            // SAFETY: as above.
            return Some((info.si_code, unsafe { info.si_status() }));
        }
        if Instant::now() >= end {
            return None;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Whether this process's own child `pid` has exited, without reaping it.
pub fn has_exited(pid: i32) -> bool {
    wait_child_within(pid, libc::WEXITED | libc::WNOWAIT, Duration::ZERO).is_some()
}

/// A short private directory for counters and reports.
pub fn short_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("ecpty")
        .tempdir_in("/tmp")
        .unwrap()
}

/// Lines in `path`, 0 when it does not exist.
pub fn lines(path: &std::path::Path) -> usize {
    std::fs::read(path).map_or(0, |b| b.iter().filter(|c| **c == b'\n').count())
}

/// Waits until `path` has at least `n` lines, up to `limit`.
pub fn wait_lines(path: &std::path::Path, n: usize, limit: Duration) -> bool {
    let end = Instant::now() + limit;
    while lines(path) < n {
        if Instant::now() >= end {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    true
}

/// Runs the binary's cases as `cargo test` asks: filters, `--skip`,
/// `--exact`, `--list` and `--help` read as libtest reads them, anything
/// else refused before a case runs (review F-126).
pub use envcloak_sys::testing::libtest::run_cases;
