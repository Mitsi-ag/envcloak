//! What `envcloak run` needs to keep a child it redacts (SPEC §6.1 step 8):
//! signals it passes on, and the child's exit seen without reaping it.
//!
//! - [`SignalRelay`] catches a set of signals for as long as it lives and
//!   hands each one to a thread that reads [`SignalRelay::next`]. The
//!   handler only writes the signal's number to a pipe, with whether a
//!   process sent it ([`Relayed::Signal`]), which is async-signal-safe;
//!   the code that acts on it is ordinary code on an ordinary thread.
//!   [`SignalRelay::mark`] puts a mark in the same stream, so the reader
//!   knows which signals were caught before a moment and which after. A
//!   caught signal, unlike an ignored one, is reset to its default action
//!   by `exec`, so the child the runner starts gets the usual
//!   dispositions.
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
/// This process's session when the relay was installed, for the handler
/// (macOS; see [`sent_by_process`]).
#[cfg(target_os = "macos")]
static SESSION: AtomicI32 = AtomicI32::new(-1);

/// A byte in the relay pipe: the signal's number in the low seven bits,
/// and this bit when a process sent it. Alone, the bit is a
/// [`SignalRelay::mark`]; 0 is the stop mark.
const BY_PROCESS: u8 = 0x80;
/// The byte [`SignalRelay::mark`] writes.
const MARK: u8 = BY_PROCESS;
/// The byte [`SignalRelay::stop`] writes.
const STOP: u8 = 0;
/// The highest signal a relay catches: its number must leave
/// [`BY_PROCESS`] free. Every signal on Linux and macOS is below it.
const MAX_SIGNAL: i32 = 0x7f;

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

/// Whether the signal `info` describes was sent by a process (`kill`,
/// `sigqueue`, `tgkill`), as opposed to the kernel: a terminal's Ctrl-C and
/// Ctrl-\ (sent to its foreground process group) or a hangup.
///
/// Linux says so in `si_code`: `SI_USER`, `SI_QUEUE` or `SI_TKILL` for a
/// process, `SI_KERNEL` for a terminal. Called from the signal handler.
#[cfg(target_os = "linux")]
fn sent_by_process(info: &libc::siginfo_t) -> bool {
    matches!(
        info.si_code,
        libc::SI_USER | libc::SI_QUEUE | libc::SI_TKILL
    )
}

/// Whether the signal `info` describes was sent by a process, as far as
/// macOS shows it.
///
/// macOS reports a terminal's Ctrl-C exactly as it reports `kill`:
/// `si_code` 0, and `si_pid` the process that wrote the keystroke to the
/// terminal (the terminal emulator, `sshd`, `tmux`, a pty driver). That
/// process holds the terminal open, so it is still there, and it is
/// outside the session the terminal controls. So a signal counts as sent
/// by a process when its sender is in this process's session (a parent
/// such as `timeout --foreground`, a harness started from the same
/// terminal, the command itself), or is already gone (`kill(1)`, which
/// exits once it has sent). A live sender in another session (`kill`
/// typed in another terminal's shell) cannot be told from the terminal,
/// and does not count. `getsid` is one system call with no lock; `errno`
/// is put back by the caller. Called from the signal handler.
#[cfg(target_os = "macos")]
fn sent_by_process(info: &libc::siginfo_t) -> bool {
    let own = SESSION.load(Ordering::SeqCst);
    let pid = info.si_pid;
    if own <= 0 || pid <= 0 {
        return false;
    }
    // SAFETY: getsid has no memory effects; for a pid that is gone it
    // fails with ESRCH, read from this thread's errno slot.
    let (session, gone) = unsafe { (libc::getsid(pid), *errno_location() == libc::ESRCH) };
    session == own || (session < 0 && gone)
}

extern "C" fn relay_handler(
    sig: libc::c_int,
    info: *mut libc::siginfo_t,
    _context: *mut libc::c_void,
) {
    let fd = WRITE_FD.load(Ordering::SeqCst);
    if fd < 0 {
        return;
    }
    // Only signals 1 to MAX_SIGNAL are installed; the check keeps the byte
    // from ever reading as a mark.
    let Some(number) = u8::try_from(sig)
        .ok()
        .filter(|n| (1..=MAX_SIGNAL).contains(&i32::from(*n)))
    else {
        return;
    };
    let errno = errno_location();
    // SAFETY: the handler may interrupt code between a failed call and its
    // read of errno, so errno is put back after the calls. `errno` points
    // at this thread's slot. `info` is the siginfo_t the kernel passes an
    // SA_SIGINFO handler, valid for the call, or null. sent_by_process
    // makes at most one system call; write is async-signal-safe, and a
    // full pipe (EAGAIN) drops the byte, since one of the same signal is
    // pending.
    unsafe {
        let saved = *errno;
        let by_process = info.as_ref().is_some_and(sent_by_process);
        let byte = if by_process {
            number | BY_PROCESS
        } else {
            number
        };
        libc::write(fd, (&raw const byte).cast(), 1);
        *errno = saved;
    }
}

/// What [`SignalRelay::next`] hands on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relayed {
    /// A caught signal: its number, and whether a process sent it
    /// (`kill`, `sigqueue`) rather than the kernel (a terminal's Ctrl-C or
    /// Ctrl-\, a hangup). On macOS, which reports both alike, a sender
    /// counts as a process only when it is in this process's session or
    /// already gone; any other signal reads as the kernel's.
    Signal {
        /// The signal's number.
        number: i32,
        /// A process sent it.
        by_process: bool,
    },
    /// Where [`SignalRelay::mark`] was called: the signals before it were
    /// caught before the call, and those after it after.
    Mark,
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
    /// Catches each of `signals` with a handler that records it, and
    /// whether a process sent it, for [`SignalRelay::next`]. `SA_RESTART`
    /// is set, so a blocking read or write on another thread is restarted
    /// rather than failing; `poll` and `waitid` may still return `EINTR`.
    ///
    /// # Errors
    /// [`io::ErrorKind::AlreadyExists`] while another relay is installed,
    /// [`io::ErrorKind::InvalidInput`] for a signal outside 1 to 127, and
    /// the errors of `pipe` and `sigaction`. Nothing stays installed after
    /// an error.
    pub fn install(signals: &[i32]) -> io::Result<SignalRelay> {
        if signals.iter().any(|s| !(1..=MAX_SIGNAL).contains(s)) {
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
        #[cfg(target_os = "macos")]
        {
            // SAFETY: getsid(0) asks about this process and has no memory
            // effects.
            let session = unsafe { libc::getsid(0) };
            SESSION.store(session, Ordering::SeqCst);
        }
        WRITE_FD.store(pipe.write.as_raw_fd(), Ordering::SeqCst);
        let mut relay = SignalRelay {
            saved: Vec::with_capacity(signals.len()),
            pipe,
        };
        for &sig in signals {
            // SAFETY: sigaction is plain data; every field is set below or
            // stays zero, which is a valid empty value.
            let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
            act.sa_sigaction = relay_handler
                as extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void)
                as libc::sighandler_t;
            act.sa_flags = libc::SA_RESTART | libc::SA_SIGINFO;
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

    /// Waits for the next relayed signal or mark and returns it, or `None`
    /// once [`SignalRelay::stop`] was called. Meant for one reading thread.
    ///
    /// # Errors
    /// When `poll` or `read` fails for another reason than a signal.
    pub fn next(&self) -> io::Result<Option<Relayed>> {
        let fd = self.pipe.read.as_raw_fd();
        loop {
            let mut byte = 0u8;
            // SAFETY: `byte` is one writable byte; the descriptor is open for
            // the life of the process.
            let n = unsafe { libc::read(fd, (&raw mut byte).cast(), 1) };
            if n == 1 {
                return Ok(match byte {
                    STOP => None,
                    MARK => Some(Relayed::Mark),
                    b => Some(Relayed::Signal {
                        number: i32::from(b & !BY_PROCESS),
                        by_process: b & BY_PROCESS != 0,
                    }),
                });
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
        self.put(STOP)
    }

    /// Puts [`Relayed::Mark`] in the stream [`SignalRelay::next`] reads: a
    /// signal whose handler ran before this call comes before it, and one
    /// caught after the call comes after it. Callable from any thread.
    ///
    /// # Errors
    /// When the mark cannot be written.
    pub fn mark(&self) -> io::Result<()> {
        self.put(MARK)
    }

    /// Writes one of the relay's own bytes to the pipe.
    fn put(&self, byte: u8) -> io::Result<()> {
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

    /// A signal this process sent itself.
    fn own(number: i32) -> Option<Relayed> {
        Some(Relayed::Signal {
            number,
            by_process: true,
        })
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
        assert_eq!(relay.next().unwrap(), own(libc::SIGUSR1));
        assert_eq!(relay.next().unwrap(), own(libc::SIGUSR2));
        assert_eq!(relay.next().unwrap(), own(libc::SIGUSR1));
        assert_eq!(relay.next().unwrap(), None);
        drop(relay);
        // The old disposition is back, and a new relay starts empty.
        assert_eq!(disposition(libc::SIGUSR1), before);
        let relay = SignalRelay::install(&[libc::SIGUSR2]).unwrap();
        relay.stop().unwrap();
        assert_eq!(relay.next().unwrap(), None);
    }

    /// A mark sits between the signals caught before it and those caught
    /// after it.
    #[test]
    fn a_mark_divides_the_signals_caught_before_it_from_those_after() {
        let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
        let relay = SignalRelay::install(&[libc::SIGUSR1, libc::SIGUSR2]).unwrap();
        raise(libc::SIGUSR1);
        relay.mark().unwrap();
        raise(libc::SIGUSR2);
        relay.mark().unwrap();
        relay.stop().unwrap();
        assert_eq!(relay.next().unwrap(), own(libc::SIGUSR1));
        assert_eq!(relay.next().unwrap(), Some(Relayed::Mark));
        assert_eq!(relay.next().unwrap(), own(libc::SIGUSR2));
        assert_eq!(relay.next().unwrap(), Some(Relayed::Mark));
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
            assert_eq!(reader.join().unwrap(), own(libc::SIGUSR2));
        });
    }

    /// Starts `sh -c 'kill -<sig> <this pid> && read _'`, in this process's
    /// session or (`new_session`) in a session of its own. The sender stays
    /// until its standard input is closed, so it is still there when the
    /// handler asks about it.
    fn sender(sig: &str, new_session: bool) -> std::process::Child {
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.args([
            "-c",
            "kill -\"$1\" \"$2\" && { read _ || :; }",
            "sender",
            sig,
            &std::process::id().to_string(),
        ])
        .stdin(std::process::Stdio::piped());
        if new_session {
            use std::os::unix::process::CommandExt;
            // SAFETY: setsid is async-signal-safe and touches no memory of
            // the parent.
            unsafe {
                cmd.pre_exec(|| {
                    if libc::setsid() < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        cmd.spawn().unwrap()
    }

    /// Lets a [`sender`] go, and reaps it.
    fn release(mut child: std::process::Child) {
        drop(child.stdin.take());
        assert!(child.wait().unwrap().success());
    }

    /// A signal another process sends with `kill` is marked as sent by a
    /// process: on Linux from anywhere (`si_code` is `SI_USER`); on macOS,
    /// which reports a terminal's Ctrl-C the same way, from a live sender
    /// only when it is in this process's session (see `sent_by_process`).
    /// Each sender waits to be let go, so it is there when the handler
    /// asks about it.
    #[test]
    fn a_signal_from_another_process_is_marked_by_its_sender() {
        let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
        let relay = SignalRelay::install(&[libc::SIGUSR1, libc::SIGUSR2]).unwrap();
        let same = sender("USR1", false);
        assert_eq!(relay.next().unwrap(), own(libc::SIGUSR1));
        release(same);
        let other = sender("USR2", true);
        assert_eq!(
            relay.next().unwrap(),
            Some(Relayed::Signal {
                number: libc::SIGUSR2,
                by_process: cfg!(target_os = "linux"),
            })
        );
        release(other);
        relay.stop().unwrap();
        assert_eq!(relay.next().unwrap(), None);
    }

    /// What the handler reads from a `siginfo_t`: Linux's `si_code` for a
    /// process's `kill`, `sigqueue` and `tgkill` against the kernel's own
    /// (a terminal's signals are `SI_KERNEL`).
    #[cfg(target_os = "linux")]
    #[test]
    fn only_a_process_sent_si_code_counts_as_sent_by_a_process() {
        for (code, by_process) in [
            (libc::SI_USER, true),
            (libc::SI_QUEUE, true),
            (libc::SI_TKILL, true),
            (libc::SI_KERNEL, false),
            (libc::SI_TIMER, false),
            (1, false),
        ] {
            // SAFETY: siginfo_t is plain data; zero is a valid value.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            info.si_code = code;
            assert_eq!(sent_by_process(&info), by_process, "si_code {code}");
        }
    }

    /// What the handler reads from a `siginfo_t` on macOS: a sender in this
    /// process's session, or one that is gone (a pid no process has), and
    /// not a live sender elsewhere (`launchd`) or none.
    #[cfg(target_os = "macos")]
    #[test]
    fn only_a_sender_in_this_session_or_gone_counts_as_sent_by_a_process() {
        let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
        let relay = SignalRelay::install(&[libc::SIGUSR1]).unwrap();
        // SAFETY: getpid has no preconditions.
        let me = unsafe { libc::getpid() };
        for (pid, by_process) in [(me, true), (i32::MAX, true), (0, false), (1, false)] {
            // SAFETY: siginfo_t is plain data; zero is a valid value.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            info.si_pid = pid;
            assert_eq!(sent_by_process(&info), by_process, "si_pid {pid}");
        }
        drop(relay);
    }

    #[test]
    fn out_of_range_signals_and_pids_are_refused() {
        let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
        for sig in [0, 128, 256, -1] {
            assert_eq!(
                SignalRelay::install(&[sig]).unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "{sig}"
            );
        }
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
