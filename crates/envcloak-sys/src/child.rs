//! What `envcloak run` needs to keep a child it redacts (SPEC §6.1 step 8):
//! signals it passes on, and the child's exit seen without reaping it.
//!
//! - [`SignalRelay`] catches a set of signals for as long as it lives and
//!   hands each one to a thread that reads [`SignalRelay::next`]. The
//!   handler only writes the signal's number to a pipe, which is
//!   async-signal-safe; the code that acts on it is ordinary code on an
//!   ordinary thread. A caught signal, unlike an ignored one, is reset to
//!   its default action by `exec`, so the child the runner starts gets the
//!   usual dispositions.
//! - [`wait_for_exit`] waits until a child has exited and leaves it a
//!   zombie (`waitid` with `WNOWAIT`), so its pid cannot be handed to
//!   another process until the caller reaps it. A thread that sends the
//!   child signals checks, under the same lock, that it has not exited
//!   yet, and so never signals a pid that has been reused.
//! - [`signal_process`] and [`signal_group`]: `kill` for one process, or
//!   for every process in a group.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

/// Sends `sig` to process `pid`.
///
/// # Errors
/// [`io::ErrorKind::InvalidInput`] for a pid below 1 (which `kill` would
/// read as a group or every process), and `kill`'s own errors: `ESRCH`
/// when no such process exists.
pub fn signal_process(pid: i32, sig: i32) -> io::Result<()> {
    if pid < 1 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    // SAFETY: kill has no memory effects; `pid` names one process.
    if unsafe { libc::kill(pid, sig) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Sends `sig` to every process in process group `pgid`.
///
/// # Errors
/// [`io::ErrorKind::InvalidInput`] for a group id below 2 (1 is `init`'s,
/// and `kill(-1)` would signal every process the user owns), and `kill`'s
/// own errors: `ESRCH` when the group is empty.
pub fn signal_group(pgid: i32, sig: i32) -> io::Result<()> {
    if pgid < 2 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    // SAFETY: kill has no memory effects; `-pgid` names one group.
    if unsafe { libc::kill(-pgid, sig) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Waits until child `pid` has exited or been killed, and leaves it
/// waitable: `waitid(P_PID, pid, WEXITED | WNOWAIT)`. Its pid stays in use
/// until the caller reaps it (`Child::wait`). Restarts after a signal.
///
/// # Errors
/// [`io::ErrorKind::InvalidInput`] for a pid below 1, and `waitid`'s own
/// errors: `ECHILD` when `pid` is not a child of this process.
pub fn wait_for_exit(pid: i32) -> io::Result<()> {
    let id = libc::id_t::try_from(pid)
        .ok()
        .filter(|_| pid >= 1)
        .ok_or(io::ErrorKind::InvalidInput)?;
    loop {
        // SAFETY: siginfo_t is plain data; waitid fills it in.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: `info` is a writable siginfo_t; WNOWAIT leaves the child
        // as it is.
        let rc = unsafe { libc::waitid(libc::P_PID, id, &mut info, libc::WEXITED | libc::WNOWAIT) };
        if rc == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// The pipe every [`SignalRelay`] writes to and reads from: created once,
/// both ends non-blocking and close-on-exec, and never closed, so a
/// handler still running on another thread when a relay ends never writes
/// to a descriptor number that has been reused.
struct RelayPipe {
    read: OwnedFd,
    write: OwnedFd,
}

static PIPE: OnceLock<io::Result<RelayPipe>> = OnceLock::new();
/// The write end, for the handler: -1 while no relay is installed.
static WRITE_FD: AtomicI32 = AtomicI32::new(-1);
/// A relay is installed; there is at most one per process.
static ACTIVE: AtomicBool = AtomicBool::new(false);

fn pipe() -> io::Result<&'static RelayPipe> {
    PIPE.get_or_init(|| {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `fds` has room for the two descriptors pipe returns.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: pipe just created both descriptors, and nothing else owns
        // them.
        let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        for fd in [read.as_raw_fd(), write.as_raw_fd()] {
            // SAFETY: fcntl on descriptors this process owns; F_SETFD and
            // F_SETFL take plain integer flags.
            let ok = unsafe {
                libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) == 0
                    && libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) == 0
            };
            if !ok {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(RelayPipe { read, write })
    })
    .as_ref()
    .map_err(|e| io::Error::from(e.kind()))
}

#[cfg(target_os = "macos")]
fn errno_location() -> *mut libc::c_int {
    // SAFETY: __error returns the calling thread's errno slot.
    unsafe { libc::__error() }
}

#[cfg(target_os = "linux")]
fn errno_location() -> *mut libc::c_int {
    // SAFETY: __errno_location returns the calling thread's errno slot.
    unsafe { libc::__errno_location() }
}

extern "C" fn relay_handler(sig: libc::c_int) {
    let fd = WRITE_FD.load(Ordering::SeqCst);
    if fd < 0 {
        return;
    }
    // Signal numbers fit in a byte; 0 is the stop mark and never a signal.
    let byte = u8::try_from(sig).unwrap_or(0);
    if byte == 0 {
        return;
    }
    let errno = errno_location();
    // SAFETY: the handler may interrupt code between a failed call and its
    // read of errno, so errno is put back after the write. `errno` points
    // at this thread's slot, and write is async-signal-safe; a full pipe
    // (EAGAIN) drops the byte, since one of the same signal is pending.
    unsafe {
        let saved = *errno;
        libc::write(fd, (&raw const byte).cast(), 1);
        *errno = saved;
    }
}

/// Signals caught and handed to a reading thread while the value lives.
/// The previous dispositions come back on drop. At most one exists at a
/// time in a process.
pub struct SignalRelay {
    saved: Vec<(i32, libc::sigaction)>,
    pipe: &'static RelayPipe,
}

impl core::fmt::Debug for SignalRelay {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let signals: Vec<i32> = self.saved.iter().map(|(s, _)| *s).collect();
        f.debug_struct("SignalRelay")
            .field("signals", &signals)
            .finish_non_exhaustive()
    }
}

impl SignalRelay {
    /// Catches each of `signals` with a handler that records it for
    /// [`SignalRelay::next`]. `SA_RESTART` is set, so a blocking read or
    /// write on another thread is restarted rather than failing; `poll`
    /// and `waitid` may still return `EINTR`.
    ///
    /// # Errors
    /// [`io::ErrorKind::AlreadyExists`] while another relay is installed,
    /// [`io::ErrorKind::InvalidInput`] for a signal outside 1 to 255, and
    /// the errors of `pipe` and `sigaction`. Nothing stays installed after
    /// an error.
    pub fn install(signals: &[i32]) -> io::Result<SignalRelay> {
        if signals.iter().any(|s| !(1..=255).contains(s)) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let pipe = pipe()?;
        if ACTIVE.swap(true, Ordering::SeqCst) {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        // Whatever an earlier relay left unread is not this one's.
        let mut stale = [0u8; 64];
        // SAFETY: `stale` is writable for its length; the read end is
        // non-blocking, so this stops at EAGAIN.
        while unsafe {
            libc::read(
                pipe.read.as_raw_fd(),
                stale.as_mut_ptr().cast(),
                stale.len(),
            )
        } > 0
        {}
        WRITE_FD.store(pipe.write.as_raw_fd(), Ordering::SeqCst);
        let mut relay = SignalRelay {
            saved: Vec::with_capacity(signals.len()),
            pipe,
        };
        for &sig in signals {
            // SAFETY: sigaction is plain data; every field is set below or
            // stays zero, which is a valid empty value.
            let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
            act.sa_sigaction = relay_handler as extern "C" fn(libc::c_int) as libc::sighandler_t;
            act.sa_flags = libc::SA_RESTART;
            // SAFETY: `act.sa_mask` is a writable sigset_t.
            if unsafe { libc::sigemptyset(&mut act.sa_mask) } != 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: sigaction is plain data, filled in by the call.
            let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
            // SAFETY: `sig` is in range; `act` is initialized and `old` is
            // writable. On failure `relay` drops and restores the others.
            if unsafe { libc::sigaction(sig, &act, &mut old) } != 0 {
                return Err(io::Error::last_os_error());
            }
            relay.saved.push((sig, old));
        }
        Ok(relay)
    }

    /// Waits for the next relayed signal and returns its number, or `None`
    /// once [`SignalRelay::stop`] was called. Meant for one reading thread.
    ///
    /// # Errors
    /// When `poll` or `read` fails for another reason than a signal.
    pub fn next(&self) -> io::Result<Option<i32>> {
        let fd = self.pipe.read.as_raw_fd();
        loop {
            let mut byte = 0u8;
            // SAFETY: `byte` is one writable byte; the descriptor is open for
            // the life of the process.
            let n = unsafe { libc::read(fd, (&raw mut byte).cast(), 1) };
            if n == 1 {
                return Ok((byte != 0).then_some(i32::from(byte)));
            }
            let err = io::Error::last_os_error();
            match err.kind() {
                io::ErrorKind::Interrupted => {}
                io::ErrorKind::WouldBlock => {
                    let mut p = libc::pollfd {
                        fd,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    // SAFETY: `p` is one initialized pollfd.
                    if unsafe { libc::poll(&mut p, 1, -1) } < 0 {
                        let err = io::Error::last_os_error();
                        if err.kind() != io::ErrorKind::Interrupted {
                            return Err(err);
                        }
                    }
                }
                _ => return Err(err),
            }
        }
    }

    /// Makes [`SignalRelay::next`] return `None` once it has handed out
    /// the signals that came before. Callable from any thread.
    ///
    /// # Errors
    /// When the stop mark cannot be written.
    pub fn stop(&self) -> io::Result<()> {
        let byte = 0u8;
        loop {
            // SAFETY: `byte` is one readable byte; the descriptor is open for
            // the life of the process.
            let n =
                unsafe { libc::write(self.pipe.write.as_raw_fd(), (&raw const byte).cast(), 1) };
            if n == 1 {
                return Ok(());
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }
}

impl Drop for SignalRelay {
    fn drop(&mut self) {
        for (sig, old) in self.saved.drain(..).rev() {
            // SAFETY: `old` is the disposition sigaction returned for `sig`;
            // the previous one is not wanted.
            unsafe { libc::sigaction(sig, &old, std::ptr::null_mut()) };
        }
        WRITE_FD.store(-1, Ordering::SeqCst);
        ACTIVE.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The relay is process-wide, so its tests take turns.
    static TURN: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn raise(sig: i32) {
        // SAFETY: raise delivers `sig` to this thread; a relay catches it.
        assert_eq!(unsafe { libc::raise(sig) }, 0);
    }

    fn disposition(sig: i32) -> libc::sighandler_t {
        // SAFETY: sigaction is plain data, filled in by the call.
        let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: a null new action only reads the current one.
        let rc = unsafe { libc::sigaction(sig, std::ptr::null(), &mut old) };
        assert_eq!(rc, 0);
        old.sa_sigaction
    }

    #[test]
    fn signals_are_handed_on_in_order_until_stopped() {
        let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
        let before = disposition(libc::SIGUSR1);
        let relay = SignalRelay::install(&[libc::SIGUSR1, libc::SIGUSR2]).unwrap();
        assert_eq!(
            SignalRelay::install(&[libc::SIGUSR1]).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        raise(libc::SIGUSR1);
        raise(libc::SIGUSR2);
        raise(libc::SIGUSR1);
        relay.stop().unwrap();
        assert_eq!(relay.next().unwrap(), Some(libc::SIGUSR1));
        assert_eq!(relay.next().unwrap(), Some(libc::SIGUSR2));
        assert_eq!(relay.next().unwrap(), Some(libc::SIGUSR1));
        assert_eq!(relay.next().unwrap(), None);
        drop(relay);
        // The old disposition is back, and a new relay starts empty.
        assert_eq!(disposition(libc::SIGUSR1), before);
        let relay = SignalRelay::install(&[libc::SIGUSR2]).unwrap();
        relay.stop().unwrap();
        assert_eq!(relay.next().unwrap(), None);
    }

    #[test]
    fn a_reader_blocked_in_next_gets_a_signal_from_another_thread() {
        let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
        let relay = SignalRelay::install(&[libc::SIGUSR2]).unwrap();
        std::thread::scope(|s| {
            let reader = s.spawn(|| relay.next().unwrap());
            // SAFETY: kill to this process's own pid.
            assert_eq!(unsafe { libc::kill(libc::getpid(), libc::SIGUSR2) }, 0);
            assert_eq!(reader.join().unwrap(), Some(libc::SIGUSR2));
        });
    }

    #[test]
    fn out_of_range_signals_and_pids_are_refused() {
        let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(
            SignalRelay::install(&[0]).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            SignalRelay::install(&[256]).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        for pid in [0, -1, -5] {
            assert_eq!(
                signal_process(pid, 0).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(
                wait_for_exit(pid).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        for pgid in [1, 0, -1] {
            assert_eq!(
                signal_group(pgid, 0).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }
}
