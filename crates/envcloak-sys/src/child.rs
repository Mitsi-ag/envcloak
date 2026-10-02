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
//!   signal that finds the pipe full (a flood of signals not read yet) is
//!   kept aside instead, one of each signal and sender, and handed on all
//!   the same, on its side of the marks (review F-71). A caught signal,
//!   unlike an ignored one, is reset to its default action by `exec`, so
//!   the child the runner starts gets the usual dispositions. A signal
//!   mask survives `exec`, so a program can start the runner with a
//!   signal blocked, which would then never be caught: the installing
//!   thread unblocks the relay's signals (review R-8).
//! - [`wait_for_exit`] waits until a child has exited and leaves it a
//!   zombie (`waitid` with `WNOWAIT`), so its pid cannot be handed to
//!   another process until the caller reaps it. A thread that sends the
//!   child signals checks, under the same lock, that it has not exited
//!   yet, and so never signals a pid that has been reused.
//!   [`has_exited`] asks the same without waiting.
//! - [`signal_process`] and [`signal_group`]: `kill` for one process, or
//!   for every process in a group.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};

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

/// Whether child `pid` has exited (or been killed), without waiting and
/// without reaping it: `waitid(P_PID, pid, WEXITED | WNOHANG | WNOWAIT)`.
/// The runner asks it before it passes a signal on, so a signal that comes
/// once the child is gone is never passed to what it left behind as if the
/// child still ran. Restarts after a signal.
///
/// # Errors
/// [`io::ErrorKind::InvalidInput`] for a pid below 1, and `waitid`'s own
/// errors: `ECHILD` when `pid` is not a child of this process.
pub fn has_exited(pid: i32) -> io::Result<bool> {
    let id = libc::id_t::try_from(pid)
        .ok()
        .filter(|_| pid >= 1)
        .ok_or(io::ErrorKind::InvalidInput)?;
    loop {
        // SAFETY: siginfo_t is plain data; waitid fills it in, and leaves
        // si_pid 0 when no child has changed state.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: `info` is a writable siginfo_t; WNOWAIT leaves the child
        // as it is and WNOHANG returns at once.
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                id,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if rc == 0 {
            // SAFETY: waitid filled `info` in for an exited child, or left
            // it zeroed; si_pid is set in both cases.
            return Ok(unsafe { info.si_pid() } != 0);
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
/// How many handlers are running now: a relay's drop waits for them, so
/// none writes into the pipe, or keeps a signal, for the next relay.
static IN_HANDLER: AtomicU32 = AtomicU32::new(0);
/// How many marks the relay has written into the pipe.
static MARKS: AtomicU32 = AtomicU32::new(0);
/// The signals kept aside because the pipe was full (review F-71), by the
/// byte the handler could not write: bit `m` is set for one caught when
/// [`MARKS`] was `m` (marks from the 31st on share bit 31). So a kept
/// signal is one of each signal, sender and stretch between two marks,
/// whatever else fills the pipe, and never merges with one on the other
/// side of a mark.
static KEPT: [AtomicU32; 256] = [const { AtomicU32::new(0) }; 256];
/// A signal was kept since the reader last looked at [`KEPT`].
static KEPT_SINCE: AtomicBool = AtomicBool::new(false);

/// A byte in the relay pipe: the signal's number in the low seven bits,
/// and this bit when a process sent it. Alone, the bit is a
/// [`SignalRelay::mark`]; 0 is the stop mark.
const BY_PROCESS: u8 = 0x80;
/// The byte [`SignalRelay::mark`] writes.
const MARK: u8 = BY_PROCESS;
/// The byte [`SignalRelay::stop`] writes.
const STOP: u8 = 0;
/// The byte a handler writes after keeping a signal aside, so a reader
/// about to wait on an empty pipe looks at [`KEPT`] again. It carries
/// nothing else.
const WAKE: u8 = 0x7f;
/// How long [`SignalRelay::mark`] and [`SignalRelay::stop`] wait for room
/// in a full pipe (a flood of signals not read yet) before they fail, in
/// milliseconds.
const ROOM_WAIT_MS: libc::c_int = 100;
/// The highest signal a relay catches: its number must leave
/// [`BY_PROCESS`] and [`WAKE`] free. Every signal on Linux and macOS is
/// below it.
const MAX_SIGNAL: i32 = 0x7e;
/// Set while [`SignalRelay::put`] waits for room: the unit tests drain
/// the pipe once it does.
#[cfg(test)]
static PUT_WAITING: AtomicBool = AtomicBool::new(false);
/// Set when [`SignalRelay::next`] is about to wait on an empty pipe: the
/// unit tests keep a signal aside once it is.
#[cfg(test)]
static NEXT_WAITING: AtomicBool = AtomicBool::new(false);
/// The unit tests' pause inside the handler, after it has read the write
/// end: [`PAUSE_ARMED`] makes the next handler stop there
/// ([`PAUSE_INSIDE`]) until the test sets [`PAUSE_OFF`].
#[cfg(test)]
static HANDLER_PAUSE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(PAUSE_OFF);
#[cfg(test)]
const PAUSE_OFF: u8 = 0;
#[cfg(test)]
const PAUSE_ARMED: u8 = 1;
#[cfg(test)]
const PAUSE_INSIDE: u8 = 2;

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
    // Counted before the write end is read, so a relay's drop, which
    // clears the write end and then waits for the count to reach 0, sees
    // this handler or makes it find no write end.
    IN_HANDLER.fetch_add(1, Ordering::SeqCst);
    let fd = WRITE_FD.load(Ordering::SeqCst);
    #[cfg(test)]
    if HANDLER_PAUSE
        .compare_exchange(
            PAUSE_ARMED,
            PAUSE_INSIDE,
            Ordering::SeqCst,
            Ordering::SeqCst,
        )
        .is_ok()
    {
        while HANDLER_PAUSE.load(Ordering::SeqCst) == PAUSE_INSIDE {
            std::hint::spin_loop();
        }
    }
    // Only signals 1 to MAX_SIGNAL are installed; the check keeps the byte
    // from ever reading as a mark, the stop or a wake-up.
    let number = u8::try_from(sig)
        .ok()
        .filter(|n| (1..=MAX_SIGNAL).contains(&i32::from(*n)));
    if let (true, Some(number)) = (fd >= 0, number) {
        let errno = errno_location();
        // SAFETY: the handler may interrupt code between a failed call and
        // its read of errno, so errno is put back after the calls. `errno`
        // points at this thread's slot. `info` is the siginfo_t the kernel
        // passes an SA_SIGINFO handler, valid for the call, or null.
        // sent_by_process makes at most one system call; write is
        // async-signal-safe. A full pipe (EAGAIN) takes no byte, and the
        // signal is kept aside instead (review F-71): the pipe may be full
        // of other signals, so this one is not known to be there already.
        unsafe {
            let saved = *errno;
            let by_process = info.as_ref().is_some_and(sent_by_process);
            let byte = if by_process {
                number | BY_PROCESS
            } else {
                number
            };
            if libc::write(fd, (&raw const byte).cast(), 1) != 1 {
                keep(fd, byte);
            }
            *errno = saved;
        }
    }
    IN_HANDLER.fetch_sub(1, Ordering::SeqCst);
}

/// Keeps aside the signal whose `byte` did not fit in the pipe `fd`, for
/// the stretch between marks it was caught in, and writes [`WAKE`]. Called
/// from the signal handler: it only uses atomics, which Rust provides only
/// where they are lock-free, and one non-blocking write.
///
/// The wake-up closes a gap: the reader may have looked at [`KEPT`] and
/// found nothing just before this, and be about to wait on a pipe it has
/// emptied since. When the wake-up does not fit either, the pipe is full,
/// so the reader is not waiting: it reads, and looks again.
fn keep(fd: libc::c_int, byte: u8) {
    let marks = MARKS.load(Ordering::SeqCst).min(31);
    KEPT[usize::from(byte)].fetch_or(1 << marks, Ordering::SeqCst);
    KEPT_SINCE.store(true, Ordering::SeqCst);
    let wake = WAKE;
    // SAFETY: `wake` is one readable byte and `fd` the relay's write end,
    // open for the life of the process; the result does not matter.
    unsafe { libc::write(fd, (&raw const wake).cast(), 1) };
}

/// [`keep`], for a signal the tests say did not fit: `sig`, and whether a
/// process sent it. Does nothing while no relay is installed or for a
/// signal a relay cannot catch.
#[cfg(any(test, feature = "testing"))]
pub(crate) fn keep_as_if_full(sig: i32, by_process: bool) {
    let fd = WRITE_FD.load(Ordering::SeqCst);
    let Some(number) = u8::try_from(sig)
        .ok()
        .filter(|n| (1..=MAX_SIGNAL).contains(&i32::from(*n)))
    else {
        return;
    };
    if fd >= 0 {
        keep(
            fd,
            if by_process {
                number | BY_PROCESS
            } else {
                number
            },
        );
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
    /// The thread that installed the relay, and which of its signals that
    /// thread blocked before: blocked again when the relay is dropped
    /// there.
    thread: libc::pthread_t,
    reblock: Vec<i32>,
    /// How many marks [`SignalRelay::next`] has handed out: a signal kept
    /// aside is due once the reader is past the marks written before it.
    marks_read: AtomicU32,
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
    /// The calling thread stops blocking `signals` (a mask inherited
    /// through `exec` may block them), so a signal sent to the process
    /// reaches the handler on it, or on a thread it starts afterwards,
    /// which inherits its mask. Dropped on that thread, the relay blocks
    /// again those the thread blocked before, ahead of the old
    /// dispositions (review R-8).
    ///
    /// # Errors
    /// [`io::ErrorKind::AlreadyExists`] while another relay is installed,
    /// [`io::ErrorKind::InvalidInput`] for a signal outside 1 to 126, and
    /// the errors of `pipe`, `sigaction` and `pthread_sigmask`. Nothing
    /// stays installed after an error.
    pub fn install(signals: &[i32]) -> io::Result<SignalRelay> {
        if signals.iter().any(|s| !(1..=MAX_SIGNAL).contains(s)) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let pipe = pipe()?;
        if ACTIVE.swap(true, Ordering::SeqCst) {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        // Whatever an earlier relay left unread, or kept aside, is not this
        // one's. Its drop waited for its last handler, so nothing of it is
        // still on its way.
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
        for kept in &KEPT {
            kept.store(0, Ordering::SeqCst);
        }
        KEPT_SINCE.store(false, Ordering::SeqCst);
        MARKS.store(0, Ordering::SeqCst);
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
            // SAFETY: pthread_self has no preconditions.
            thread: unsafe { libc::pthread_self() },
            reblock: Vec::new(),
            marks_read: AtomicU32::new(0),
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
        relay.reblock = mask_signals(libc::SIG_UNBLOCK, signals)?;
        Ok(relay)
    }

    /// Waits for the next relayed signal or mark and returns it, or `None`
    /// once [`SignalRelay::stop`] was called. Meant for one reading thread.
    ///
    /// A signal kept aside because the pipe was full (review F-71) is
    /// handed out once, with its sender, as soon as this sees it: it may
    /// come before signals caught before it, but never on the other side
    /// of a mark than its handler (one caught while [`SignalRelay::mark`]
    /// runs may come on either side, as through the pipe), and every one
    /// kept before the stop comes before `None`.
    ///
    /// # Errors
    /// When `poll` or `read` fails for another reason than a signal.
    pub fn next(&self) -> io::Result<Option<Relayed>> {
        let fd = self.pipe.read.as_raw_fd();
        loop {
            // Before every byte: a signal kept since then goes first. One
            // kept before a mark or the stop was written is seen here before
            // that byte is read: its wake-up is ahead of it in the pipe, or,
            // when the pipe was full, the byte read to make room for it was.
            if let Some(kept) = self.take_kept() {
                return Ok(Some(kept));
            }
            let mut byte = 0u8;
            // SAFETY: `byte` is one writable byte; the descriptor is open for
            // the life of the process.
            let n = unsafe { libc::read(fd, (&raw mut byte).cast(), 1) };
            if n == 1 {
                match byte {
                    STOP => return Ok(None),
                    MARK => {
                        self.marks_read.fetch_add(1, Ordering::SeqCst);
                        // Signals kept after this mark are due from now on.
                        KEPT_SINCE.store(true, Ordering::SeqCst);
                        return Ok(Some(Relayed::Mark));
                    }
                    WAKE => continue,
                    b => {
                        return Ok(Some(Relayed::Signal {
                            number: i32::from(b & !BY_PROCESS),
                            by_process: b & BY_PROCESS != 0,
                        }));
                    }
                }
            }
            let err = io::Error::last_os_error();
            match err.kind() {
                io::ErrorKind::Interrupted => {}
                io::ErrorKind::WouldBlock => {
                    #[cfg(test)]
                    NEXT_WAITING.store(true, Ordering::SeqCst);
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

    /// Takes one signal kept aside that is due: caught before the marks
    /// handed out so far, or between the last of them and now. Looks only
    /// when a handler has kept one, or a mark became due, since the last
    /// look: a handler sets [`KEPT_SINCE`] after its bit, so a bit this
    /// misses is looked for again at the next call.
    fn take_kept(&self) -> Option<Relayed> {
        if !KEPT_SINCE.swap(false, Ordering::SeqCst) {
            return None;
        }
        let read = self.marks_read.load(Ordering::SeqCst);
        // Bits 0 to `read`: the stretches up to the one after the last mark
        // handed out.
        let due = if read >= 31 {
            u32::MAX
        } else {
            (2u32 << read) - 1
        };
        for &(sig, _) in &self.saved {
            let Ok(number) = u8::try_from(sig) else {
                continue;
            };
            for byte in [number, number | BY_PROCESS] {
                let slot = &KEPT[usize::from(byte)];
                let pending = slot.load(Ordering::SeqCst) & due;
                if pending == 0 {
                    continue;
                }
                let bit = pending & pending.wrapping_neg();
                if slot.fetch_and(!bit, Ordering::SeqCst) & bit != 0 {
                    // There may be more: look again at the next call.
                    KEPT_SINCE.store(true, Ordering::SeqCst);
                    return Some(Relayed::Signal {
                        number: sig,
                        by_process: byte & BY_PROCESS != 0,
                    });
                }
            }
        }
        None
    }

    /// Makes [`SignalRelay::next`] return `None` once it has handed out
    /// the signals that came before. Callable from any thread.
    ///
    /// # Errors
    /// When the stop mark cannot be written: the pipe stayed full (of
    /// signals the reader has not read yet) for 100 ms.
    pub fn stop(&self) -> io::Result<()> {
        self.put(STOP)
    }

    /// Puts [`Relayed::Mark`] in the stream [`SignalRelay::next`] reads: a
    /// signal whose handler ran before this call comes before it, and one
    /// caught after the call comes after it, including one kept aside for
    /// a full pipe. Callable from any thread.
    ///
    /// # Errors
    /// When the mark cannot be written: the pipe stayed full for 100 ms.
    pub fn mark(&self) -> io::Result<()> {
        self.put(MARK)?;
        // Counted once the mark is in the pipe, so a signal kept from now
        // on is due only after the reader has handed this mark out, and a
        // mark that could not be written leaves nothing waiting for it.
        MARKS.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    /// Writes one of the relay's own bytes to the pipe, waiting once, up
    /// to [`ROOM_WAIT_MS`], for room.
    fn put(&self, byte: u8) -> io::Result<()> {
        let fd = self.pipe.write.as_raw_fd();
        let mut waited = false;
        loop {
            // SAFETY: `byte` is one readable byte; the descriptor is open for
            // the life of the process.
            let n = unsafe { libc::write(fd, (&raw const byte).cast(), 1) };
            if n == 1 {
                return Ok(());
            }
            let err = io::Error::last_os_error();
            match err.kind() {
                io::ErrorKind::Interrupted => {}
                io::ErrorKind::WouldBlock if !waited => {
                    waited = true;
                    #[cfg(test)]
                    PUT_WAITING.store(true, Ordering::SeqCst);
                    let mut p = libc::pollfd {
                        fd,
                        events: libc::POLLOUT,
                        revents: 0,
                    };
                    // SAFETY: `p` is one initialized pollfd. Whatever poll
                    // returns (room, the timeout, EINTR), the write is tried
                    // once more.
                    unsafe { libc::poll(&mut p, 1, ROOM_WAIT_MS) };
                }
                _ => return Err(err),
            }
        }
    }
}

/// Blocks or unblocks (`how`: `SIG_BLOCK`, `SIG_UNBLOCK`) `signals` for
/// the calling thread, and returns those of them it blocked before.
pub(crate) fn mask_signals(how: libc::c_int, signals: &[i32]) -> io::Result<Vec<i32>> {
    // SAFETY: sigset_t is plain data; sigemptyset initializes `set`, and
    // pthread_sigmask fills in `old`.
    let (mut set, mut old): (libc::sigset_t, libc::sigset_t) =
        unsafe { (std::mem::zeroed(), std::mem::zeroed()) };
    // SAFETY: `set` is a writable sigset_t.
    if unsafe { libc::sigemptyset(&mut set) } != 0 {
        return Err(io::Error::last_os_error());
    }
    for &sig in signals {
        // SAFETY: `set` is an initialized sigset_t; an invalid signal
        // fails with EINVAL.
        if unsafe { libc::sigaddset(&mut set, sig) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    // SAFETY: `set` is initialized and `old` writable; the call changes
    // only the calling thread's mask.
    let rc = unsafe { libc::pthread_sigmask(how, &set, &mut old) };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }
    Ok(signals
        .iter()
        .copied()
        // SAFETY: `old` holds the mask pthread_sigmask returned.
        .filter(|&sig| unsafe { libc::sigismember(&old, sig) } == 1)
        .collect())
}

impl Drop for SignalRelay {
    fn drop(&mut self) {
        // SAFETY: pthread_self has no preconditions; pthread_equal compares
        // two thread ids.
        let installer = unsafe { libc::pthread_equal(self.thread, libc::pthread_self()) } != 0;
        if installer && !self.reblock.is_empty() {
            // Before the old dispositions come back, so a signal arriving
            // meanwhile waits, as it did before the relay. Cannot fail:
            // the same signals were unblocked at install.
            let _ = mask_signals(libc::SIG_BLOCK, &self.reblock);
        }
        for (sig, old) in self.saved.drain(..).rev() {
            // SAFETY: `old` is the disposition sigaction returned for `sig`;
            // the previous one is not wanted.
            unsafe { libc::sigaction(sig, &old, std::ptr::null_mut()) };
        }
        WRITE_FD.store(-1, Ordering::SeqCst);
        // A handler that counted itself before the write end was cleared
        // may still write or keep a signal: wait for it, so nothing of this
        // relay reaches the next one. A handler never blocks, so this is
        // short.
        while IN_HANDLER.load(Ordering::SeqCst) != 0 {
            std::thread::yield_now();
        }
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

    /// Whether the relay's pipe has room for one more byte, found by
    /// writing one, without blocking, as the handler does: `sig` sent by
    /// this process, so a byte that fits reads as one more of it. It looks
    /// at the pipe itself, not at what the handler kept aside.
    fn room_for(relay: &SignalRelay, sig: i32) -> bool {
        let byte = u8::try_from(sig).unwrap() | BY_PROCESS;
        // SAFETY: `byte` is one readable byte; the write end is open for
        // the life of the process, and non-blocking.
        let n = unsafe { libc::write(relay.pipe.write.as_raw_fd(), (&raw const byte).cast(), 1) };
        if n == 1 {
            return true;
        }
        let err = io::Error::last_os_error();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock, "{err}");
        false
    }

    /// Raises `sig` until the relay's pipe is full: a write of the same
    /// byte finds no room. Nothing reads the pipe meanwhile, so it stays
    /// full until the test reads it. Fullness is seen in the pipe, not in
    /// what the handler kept (review F-71), so a handler that loses the
    /// signals it cannot write still fills it, and the test fails where a
    /// signal goes missing.
    fn fill_with(relay: &SignalRelay, sig: i32) {
        for _ in 0..1 << 20 {
            raise(sig);
            if !room_for(relay, sig) {
                return;
            }
        }
        panic!("the relay's pipe never filled");
    }

    /// Reads up to `n` bytes straight from the relay's pipe, as a reader
    /// making room would, and returns them.
    fn read_raw(relay: &SignalRelay, n: usize) -> Vec<u8> {
        let mut got = vec![0u8; n];
        let mut at = 0;
        while at < n {
            // SAFETY: `got[at..]` is writable for its length; the read end
            // is non-blocking.
            let r = unsafe {
                libc::read(
                    relay.pipe.read.as_raw_fd(),
                    got[at..].as_mut_ptr().cast(),
                    n - at,
                )
            };
            match usize::try_from(r) {
                Ok(0) | Err(_) => break,
                Ok(r) => at += r,
            }
        }
        got.truncate(at);
        got
    }

    /// Everything `relay` hands out until the stop, which this thread
    /// writes as soon as the reader makes room for it.
    fn read_to_stop(relay: &SignalRelay) -> Vec<Relayed> {
        std::thread::scope(|s| {
            let reader = s.spawn(|| {
                let mut got = Vec::new();
                while let Some(r) = relay.next().unwrap() {
                    got.push(r);
                }
                got
            });
            while relay.stop().is_err() && !reader.is_finished() {}
            reader.join().unwrap()
        })
    }

    /// Review R-13: a mark and the stop written into a pipe full of
    /// signals not read yet wait for room rather than fail at once. The
    /// room is made by another thread once the write is waiting (not
    /// before, so the first try meets a full pipe); a drain that comes
    /// only after the 100 ms is tried again, as it says nothing about the
    /// wait. The mark reads after the signals caught before it, and the
    /// stop after those caught after the mark.
    #[test]
    fn a_mark_and_the_stop_wait_for_room_in_a_full_pipe() {
        let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
        let relay = SignalRelay::install(&[libc::SIGUSR1]).unwrap();
        let usr1 = u8::try_from(libc::SIGUSR1).unwrap() | BY_PROCESS;
        type Put = fn(&SignalRelay) -> io::Result<()>;
        let puts: [(&str, Put); 2] = [("mark", SignalRelay::mark), ("stop", SignalRelay::stop)];
        for (name, put) in puts {
            let mut late = 0;
            loop {
                fill_with(&relay, libc::SIGUSR1);
                PUT_WAITING.store(false, Ordering::SeqCst);
                let done = AtomicBool::new(false);
                let (result, returned, drained) = std::thread::scope(|s| {
                    let drainer = s.spawn(|| {
                        while !PUT_WAITING.load(Ordering::SeqCst) && !done.load(Ordering::SeqCst) {
                            std::thread::yield_now();
                        }
                        if !PUT_WAITING.load(Ordering::SeqCst) {
                            return None;
                        }
                        let bytes = read_raw(&relay, 1 << 14);
                        Some((bytes, std::time::Instant::now()))
                    });
                    let result = put(&relay);
                    let returned = std::time::Instant::now();
                    done.store(true, Ordering::SeqCst);
                    (result, returned, drainer.join().unwrap())
                });
                let Some((bytes, at)) = drained else {
                    panic!("the {name} gave up at once in a full pipe: {result:?}");
                };
                assert!(!bytes.is_empty(), "{name}: nothing to drain");
                assert!(
                    bytes.iter().all(|b| *b == usr1 || *b == WAKE),
                    "{name}: the pipe held other bytes"
                );
                if result.is_ok() {
                    break;
                }
                // The wait ended before the room came: the drainer was late.
                assert!(at > returned, "{name} failed with room made in time");
                late += 1;
                assert!(late < 10, "{name}: the drainer was late {late} times");
            }
        }
        // Everything left, in order: signals, the mark, signals, the stop.
        let mut got = Vec::new();
        while let Some(r) = relay.next().unwrap() {
            got.push(r);
        }
        let mark = got.iter().position(|r| *r == Relayed::Mark).unwrap();
        assert!(mark > 0, "no signal before the mark");
        assert!(mark < got.len() - 1, "no signal after the mark");
        for (i, r) in got.iter().enumerate() {
            if i != mark {
                assert_eq!(Some(*r), own(libc::SIGUSR1), "at {i}");
            }
        }
    }

    /// Review F-71: a pipe full of one signal (65,536 raised and not read
    /// yet) still hands on a different one raised after it. The handler
    /// cannot write it, so it keeps it aside; it used to drop it, as if
    /// the pipe held another of the same. Every ordered pair of the
    /// runner's four signals.
    #[test]
    fn a_different_signal_behind_a_full_pipe_is_handed_on() {
        let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
        let four = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];
        for flood in four {
            for then in four.into_iter().filter(|s| *s != flood) {
                let relay = SignalRelay::install(&four).unwrap();
                fill_with(&relay, flood);
                raise(then);
                assert!(
                    !room_for(&relay, flood),
                    "the pipe full of {flood} had room again"
                );
                let got = read_to_stop(&relay);
                let count = |sig| got.iter().filter(|r| Some(**r) == own(sig)).count();
                assert_eq!(count(then), 1, "{then} after a pipe full of {flood}");
                assert!(count(flood) > 1 << 12, "{flood}: {}", count(flood));
                assert_eq!(count(flood) + 1, got.len());
                drop(relay);
            }
        }
    }

    /// Review F-71: a signal kept aside keeps its sender, so the
    /// terminal's SIGINT and a process's SIGINT, both kept, are two
    /// things to hand on (the runner treats them differently), and a
    /// signal kept twice between the same marks is handed on once.
    #[test]
    fn kept_signals_keep_their_sender() {
        let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
        let relay = SignalRelay::install(&[libc::SIGINT]).unwrap();
        keep_as_if_full(libc::SIGINT, false);
        keep_as_if_full(libc::SIGINT, true);
        keep_as_if_full(libc::SIGINT, true);
        relay.stop().unwrap();
        let mut got = Vec::new();
        while let Some(r) = relay.next().unwrap() {
            got.push(r);
        }
        got.sort_by_key(|r| {
            matches!(
                r,
                Relayed::Signal {
                    by_process: true,
                    ..
                }
            )
        });
        assert_eq!(
            got,
            [
                Relayed::Signal {
                    number: libc::SIGINT,
                    by_process: false
                },
                Relayed::Signal {
                    number: libc::SIGINT,
                    by_process: true
                },
            ]
        );
    }

    /// Review F-71: a signal kept aside comes on its own side of a mark:
    /// one kept before the mark before it, one kept after it after it,
    /// though both are handed on only once the pipe is read.
    #[test]
    fn a_kept_signal_stays_on_its_side_of_a_mark() {
        let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
        let relay = SignalRelay::install(&[libc::SIGTERM, libc::SIGHUP]).unwrap();
        keep_as_if_full(libc::SIGTERM, true);
        relay.mark().unwrap();
        keep_as_if_full(libc::SIGHUP, true);
        relay.mark().unwrap();
        keep_as_if_full(libc::SIGTERM, true);
        relay.stop().unwrap();
        assert_eq!(relay.next().unwrap(), own(libc::SIGTERM));
        assert_eq!(relay.next().unwrap(), Some(Relayed::Mark));
        assert_eq!(relay.next().unwrap(), own(libc::SIGHUP));
        assert_eq!(relay.next().unwrap(), Some(Relayed::Mark));
        assert_eq!(relay.next().unwrap(), own(libc::SIGTERM));
        assert_eq!(relay.next().unwrap(), None);
    }

    /// Review R-22: a mark that could not be written (the pipe stayed full
    /// of signals not read yet) leaves nothing waiting for it. A signal
    /// kept aside after it is handed on once the pipe is read, before the
    /// stop, and no mark comes. Had the lost mark been counted, that
    /// signal would wait for a mark that never comes, and be lost.
    #[test]
    fn a_lost_mark_leaves_no_kept_signal_waiting_for_it() {
        let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
        let relay = SignalRelay::install(&[libc::SIGUSR1, libc::SIGTERM]).unwrap();
        fill_with(&relay, libc::SIGUSR1);
        assert!(relay.mark().is_err(), "the mark found room in a full pipe");
        keep_as_if_full(libc::SIGTERM, true);
        let got = read_to_stop(&relay);
        assert!(!got.contains(&Relayed::Mark), "a lost mark was read");
        let count = |sig| got.iter().filter(|r| Some(**r) == own(sig)).count();
        assert_eq!(
            count(libc::SIGTERM),
            1,
            "the signal kept after the lost mark"
        );
        assert_eq!(count(libc::SIGUSR1) + 1, got.len());
    }

    /// Review F-71: a reader already waiting on an empty pipe wakes for a
    /// signal kept aside after it looked (the handler writes a wake-up
    /// once it has kept one), and one kept just before the stop comes
    /// before `None`. A reader that is not woken is let go by the stop,
    /// and the test fails.
    #[test]
    fn a_waiting_reader_wakes_for_a_kept_signal() {
        let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
        let relay = SignalRelay::install(&[libc::SIGTERM]).unwrap();
        NEXT_WAITING.store(false, Ordering::SeqCst);
        std::thread::scope(|s| {
            let reader = s.spawn(|| relay.next().unwrap());
            while !NEXT_WAITING.load(Ordering::SeqCst) {
                std::thread::yield_now();
            }
            keep_as_if_full(libc::SIGTERM, true);
            let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while !reader.is_finished() {
                if std::time::Instant::now() > end {
                    relay.stop().unwrap();
                    panic!("the waiting reader was not woken");
                }
                std::thread::yield_now();
            }
            assert_eq!(reader.join().unwrap(), own(libc::SIGTERM));
        });
        keep_as_if_full(libc::SIGTERM, true);
        relay.stop().unwrap();
        assert_eq!(relay.next().unwrap(), own(libc::SIGTERM));
        assert_eq!(relay.next().unwrap(), None);
    }

    /// Review F-71: a new relay starts empty, whatever the last one left:
    /// signals in the pipe, signals kept aside, and a handler that was
    /// still running when it was dropped (its drop waits for it, so its
    /// byte never lands in the next relay's pipe).
    #[test]
    fn a_new_relay_gets_nothing_of_the_last_one() {
        let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
        let relay = SignalRelay::install(&[libc::SIGUSR1, libc::SIGUSR2]).unwrap();
        raise(libc::SIGUSR1);
        keep_as_if_full(libc::SIGUSR2, true);
        drop(relay);
        let relay = SignalRelay::install(&[libc::SIGUSR1, libc::SIGUSR2]).unwrap();
        // The reader looks for kept signals at every mark.
        relay.mark().unwrap();
        relay.stop().unwrap();
        assert_eq!(relay.next().unwrap(), Some(Relayed::Mark));
        assert_eq!(relay.next().unwrap(), None);

        // A handler paused after it read the write end, on another thread.
        HANDLER_PAUSE.store(PAUSE_ARMED, Ordering::SeqCst);
        let returned_while_inside = std::thread::scope(|s| {
            let handler = s.spawn(|| raise(libc::SIGUSR1));
            while HANDLER_PAUSE.load(Ordering::SeqCst) != PAUSE_INSIDE {
                std::thread::yield_now();
            }
            let dropping = s.spawn(move || {
                drop(relay);
                HANDLER_PAUSE.load(Ordering::SeqCst) == PAUSE_INSIDE
            });
            // Long enough for a drop that does not wait to return; the
            // drop that waits returns only after the handler goes on.
            let end = std::time::Instant::now() + std::time::Duration::from_millis(200);
            while !dropping.is_finished() && std::time::Instant::now() < end {
                std::thread::yield_now();
            }
            HANDLER_PAUSE.store(PAUSE_OFF, Ordering::SeqCst);
            handler.join().unwrap();
            dropping.join().unwrap()
        });
        assert!(
            !returned_while_inside,
            "the drop returned while a handler was running"
        );
        let relay = SignalRelay::install(&[libc::SIGUSR1]).unwrap();
        relay.stop().unwrap();
        assert_eq!(relay.next().unwrap(), None);
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

    /// Review R-8: a signal the installing thread blocks, as a mask
    /// inherited through `exec` blocks it, is caught all the same, and is
    /// blocked again once the relay is gone. The stop is written first,
    /// so a signal that was not caught makes `next` return `None` rather
    /// than wait.
    #[test]
    fn a_signal_the_thread_blocks_is_caught_and_blocked_again_after() {
        let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            mask_signals(libc::SIG_BLOCK, &[libc::SIGUSR1])
                .unwrap()
                .is_empty()
        );
        let relay = SignalRelay::install(&[libc::SIGUSR1, libc::SIGUSR2]).unwrap();
        raise(libc::SIGUSR1);
        relay.stop().unwrap();
        assert_eq!(relay.next().unwrap(), own(libc::SIGUSR1));
        assert_eq!(relay.next().unwrap(), None);
        drop(relay);
        // SIGUSR1 is blocked again; SIGUSR2, which was not, is not.
        assert_eq!(
            mask_signals(libc::SIG_UNBLOCK, &[libc::SIGUSR1, libc::SIGUSR2]).unwrap(),
            [libc::SIGUSR1]
        );
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
        sh(
            &[
                "-c",
                "kill -\"$1\" \"$2\" && { read _ || :; }",
                "sender",
                sig,
                &std::process::id().to_string(),
            ],
            new_session,
        )
    }

    /// `/bin/sh <args>` with a pipe for its standard input, in this
    /// process's session or (`new_session`) in a session of its own.
    fn sh(args: &[&str], new_session: bool) -> std::process::Child {
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.args(args).stdin(std::process::Stdio::piped());
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

    /// Starts `sh -c 'read _'`, in this process's session or
    /// (`new_session`) in a session of its own: a live process, there until
    /// its standard input is closed ([`release`]).
    #[cfg(target_os = "macos")]
    fn idle(new_session: bool) -> std::process::Child {
        sh(&["-c", "read _ || :"], new_session)
    }

    /// What the handler reads from a `siginfo_t` on macOS: a sender in this
    /// process's session (itself, or a child that stayed there), or one
    /// that is gone (a pid no process has), and not a live sender in a
    /// session of its own or none. The live sender elsewhere is a child
    /// that left this session, not `launchd`: a test started by `launchd`
    /// (`launchctl submit`, a CI runner's service) is in its session,
    /// where pid 1 counts as a sender in this session, as it should.
    #[cfg(target_os = "macos")]
    #[test]
    fn only_a_sender_in_this_session_or_gone_counts_as_sent_by_a_process() {
        let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
        let relay = SignalRelay::install(&[libc::SIGUSR1]).unwrap();
        // SAFETY: getpid has no preconditions.
        let me = unsafe { libc::getpid() };
        let here = idle(false);
        let elsewhere = idle(true);
        let pid_of = |c: &std::process::Child| i32::try_from(c.id()).unwrap();
        for (pid, by_process) in [
            (me, true),
            (pid_of(&here), true),
            (i32::MAX, true),
            (pid_of(&elsewhere), false),
            (0, false),
        ] {
            // SAFETY: siginfo_t is plain data; zero is a valid value.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            info.si_pid = pid;
            assert_eq!(sent_by_process(&info), by_process, "si_pid {pid}");
        }
        release(here);
        release(elsewhere);
        drop(relay);
    }

    /// Signals outside 1 to 126 are refused: 127 would read as the
    /// wake-up, and 128 on as a mark or a process's signal.
    #[test]
    fn out_of_range_signals_and_pids_are_refused() {
        let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
        for sig in [0, 127, 128, 256, -1] {
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
