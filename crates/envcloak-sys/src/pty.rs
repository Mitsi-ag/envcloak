//! Pseudo-terminals for `envcloak run --pty` (SPEC §6.1 steps 7 and 8; M2
//! plan D-19, D-35, D-34; reviews F-76, CR-4).
//!
//! - [`open_pty`]: a new PTY, its slave side starting with the outer
//!   terminal's settings (so a remapped or disabled suspend character
//!   carries over) and size. Both sides are close-on-exec.
//! - [`spawn_session`]: forks the PTY monitor (`crate::pty_monitor`),
//!   which leads a new session on the slave and starts the command in a
//!   process group of its own, the slave's foreground group. The command
//!   never leads the session: its parent, the monitor, is in it, so its
//!   group is not orphaned and the suspend character stops it. The
//!   returned [`SessionMonitor`] owns the monitor ([`OwnedChild`]) and the
//!   CLI's end of the control channel: [`MonitorEvent`]s come in
//!   (`Stopped`, `Continued`, `Exited`), [`MonitorCommand`]s go out
//!   (`Resume`, `Suspend`, `Signal`).
//! - [`forward_signal`]: SIGINT, SIGQUIT, SIGTERM and SIGHUP sent to the
//!   CLI by another process go to the slave's actual foreground job, which
//!   is a nested shell's job when one runs, along the route the M2-17
//!   spike measured for that signal on this system ([`signal_route`],
//!   `crates/envcloak-sys/tests/pty_signals.rs`):
//!
//!   | Signal | Linux | macOS |
//!   |---|---|---|
//!   | SIGINT, SIGQUIT | `TIOCSIG` on the master | `TIOCSIG` on the master |
//!   | SIGTERM, SIGHUP | `OwnedSession` (`TIOCSIG` refuses them, `EINVAL`) | `TIOCSIG` on the master |
//!
//!   With `TIOCSIG` the kernel resolves the foreground group itself.
//!   macOS flushes the terminal's queues with it unless `NOFLSH` is set,
//!   so input not yet read and output not yet relayed are lost, never
//!   passed through. No signal is narrowed to the command's own group on
//!   either system ([`SignalRoute::CommandGroup`] stays for a system where
//!   the spike finds one). EnvCloak never signals a group number it read
//!   from the terminal: `TIOCGPGRP` is only a filter in `OwnedSession`.
//!
//! The PTY's output passes through the slave's line discipline, which maps
//! NL to CR NL (`ONLCR`): the redactor matches the CR LF form of every
//! value holding LF (`RedactorBuilder::crlf_variants`, D-19). EnvCloak's
//! own writer never sends VEOF when it closes.

use std::ffi::{OsStr, c_char};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::owned::OwnedChild;
#[cfg(target_os = "linux")]
use crate::owned::OwnedSession;
use crate::pty_monitor::{self, FRAME, Report};
use crate::termios::{TerminalSettings, WindowSize};

/// A new pseudo-terminal: the master side, which the CLI reads and writes,
/// and the slave side, which becomes the command's terminal.
pub struct Pty {
    pub master: OwnedFd,
    pub slave: OwnedFd,
}

impl core::fmt::Debug for Pty {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pty").finish_non_exhaustive()
    }
}

/// Opens a new PTY (`openpty`). The slave side starts with `settings`
/// (the outer terminal's, [`crate::TerminalGuard::saved`]) and `size`
/// when given, the system's defaults otherwise. Both descriptors are made
/// close-on-exec at once.
///
/// # Errors
/// When no PTY can be opened.
pub fn open_pty(size: Option<WindowSize>, settings: Option<&TerminalSettings>) -> io::Result<Pty> {
    let (mut m, mut s): (libc::c_int, libc::c_int) = (-1, -1);
    let mut t = settings.map(|s| s.0);
    let mut ws = size.map(WindowSize::to_raw);
    let tp = t.as_mut().map_or(std::ptr::null_mut(), std::ptr::from_mut);
    let wp = ws.as_mut().map_or(std::ptr::null_mut(), std::ptr::from_mut);
    // SAFETY: `m` and `s` are writable; `tp` and `wp` are null or point to
    // initialized values that live across the call; a null name is
    // allowed.
    let rc = unsafe { libc::openpty(&mut m, &mut s, std::ptr::null_mut(), tp.cast(), wp.cast()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openpty returned two open descriptors that nothing else owns.
    let (master, slave) = unsafe { (OwnedFd::from_raw_fd(m), OwnedFd::from_raw_fd(s)) };
    for fd in [master.as_raw_fd(), slave.as_raw_fd()] {
        // SAFETY: F_SETFD on a descriptor this process owns.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(Pty { master, slave })
}

/// What the monitor reports about the command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorEvent {
    /// The command stopped, on this signal; the monitor holds the slave's
    /// foreground until [`MonitorCommand::Resume`].
    Stopped(i32),
    /// The command continued.
    Continued,
    /// The command exited, with this status. It stays unreaped (its group
    /// still the monitor's to signal) until the channel closes.
    Exited(ExitStatus),
}

/// What the CLI asks of the monitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorCommand {
    /// Give the slave back to the command's group, then continue it.
    Resume,
    /// Stop the command's group (SIGTSTP).
    Suspend,
    /// Send this signal (SIGINT, SIGQUIT, SIGTERM, SIGHUP, SIGKILL or
    /// SIGCONT) to the command's group.
    Signal(i32),
}

/// Why [`spawn_session`] started no command.
#[derive(Debug)]
pub enum SessionError {
    /// EnvCloak's own failure: the control channel, the fork, or the
    /// monitor's session, descriptors or terminal.
    Setup(io::Error),
    /// The command could not be executed: `ENOENT` when no candidate path
    /// exists, `EACCES` when one was refused, or the error of the last
    /// `execve`.
    Exec(io::Error),
}

impl core::fmt::Display for SessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SessionError::Setup(e) => write!(f, "the PTY session could not be set up: {e}"),
            SessionError::Exec(e) => write!(f, "the command could not be executed: {e}"),
        }
    }
}

impl std::error::Error for SessionError {}

/// The CLI's hold on a PTY monitor and its command.
pub struct SessionMonitor {
    monitor: Option<OwnedChild>,
    control: Option<OwnedFd>,
    command: u32,
    buf: [u8; FRAME],
    filled: usize,
}

impl core::fmt::Debug for SessionMonitor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionMonitor")
            .field("monitor", &self.monitor)
            .field("command", &self.command)
            .finish_non_exhaustive()
    }
}

/// The search path when the command's environment has no `PATH`, as
/// `execvp` has it on macOS.
const DEFAULT_PATH: &[u8] = b"/usr/bin:/bin";

/// A NUL-terminated copy, wiped when dropped.
fn c_string(bytes: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
    if bytes.contains(&0) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut v = Zeroizing::new(Vec::with_capacity(bytes.len() + 1));
    v.extend_from_slice(bytes);
    v.push(0);
    Ok(v)
}

/// The paths to try for `program`, as `execvp` tries them: the name itself
/// when it holds a `/`, otherwise each directory of `path` in turn (an
/// empty entry is the current directory).
fn candidates(program: &[u8], path: &[u8]) -> io::Result<Vec<Zeroizing<Vec<u8>>>> {
    if program.is_empty() {
        return Err(io::Error::from_raw_os_error(libc::ENOENT));
    }
    if program.contains(&b'/') {
        return Ok(vec![c_string(program)?]);
    }
    path.split(|b| *b == b':')
        .map(|dir| {
            let mut full = Vec::with_capacity(dir.len() + 1 + program.len());
            if !dir.is_empty() {
                full.extend_from_slice(dir);
                full.push(b'/');
            }
            full.extend_from_slice(program);
            let c = c_string(&full);
            zeroize::Zeroize::zeroize(&mut full);
            c
        })
        .collect()
}

fn socket_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1 as libc::c_int; 2];
    #[cfg(target_os = "linux")]
    let kind = libc::SOCK_STREAM | libc::SOCK_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let kind = libc::SOCK_STREAM;
    // SAFETY: `fds` has room for the two descriptors socketpair returns.
    if unsafe { libc::socketpair(libc::AF_UNIX, kind, 0, fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socketpair just created both descriptors; nothing else owns
    // them.
    let (a, b) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    #[cfg(not(target_os = "linux"))]
    for fd in [a.as_raw_fd(), b.as_raw_fd()] {
        // SAFETY: F_SETFD on a descriptor this process owns.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    #[cfg(target_os = "macos")]
    {
        let on: libc::c_int = 1;
        // SAFETY: SO_NOSIGPIPE takes one int; a write to a channel whose
        // other end is gone then fails with EPIPE instead of a SIGPIPE.
        let rc = unsafe {
            libc::setsockopt(
                a.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                (&raw const on).cast(),
                libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>()).unwrap_or(4),
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok((a, b))
}

/// Starts `argv` on the PTY whose slave side is `slave`, under a PTY
/// monitor that leads the session (see the module documentation and
/// `crate::pty_monitor`). `env` is the command's whole environment; its
/// `PATH` (or `/usr/bin:/bin`) finds a program named without a `/`. The C
/// strings built for the exec, values included, are wiped when this
/// returns. The slave is closed in this process; the command, the monitor
/// and their descendants hold it. Returns once the command has been
/// executed.
///
/// # Errors
/// [`SessionError::Exec`] when the command could not be executed;
/// [`SessionError::Setup`] for everything else. A NUL byte in `argv` or
/// `env` is [`io::ErrorKind::InvalidInput`], under `Setup`.
pub fn spawn_session(
    argv: &[&OsStr],
    env: &[(&OsStr, &OsStr)],
    slave: OwnedFd,
) -> Result<SessionMonitor, SessionError> {
    let (program, _) = argv
        .split_first()
        .ok_or_else(|| SessionError::Exec(io::Error::from_raw_os_error(libc::ENOENT)))?;
    let path = env
        .iter()
        .rev()
        .find(|(name, _)| name.as_bytes() == b"PATH")
        .map_or(DEFAULT_PATH, |(_, v)| v.as_bytes());
    let programs = candidates(program.as_bytes(), path).map_err(SessionError::Setup)?;
    let args = argv
        .iter()
        .map(|a| c_string(a.as_bytes()))
        .collect::<io::Result<Vec<_>>>()
        .map_err(SessionError::Setup)?;
    let vars = env
        .iter()
        .map(|(name, value)| {
            let (name, value) = (name.as_bytes(), value.as_bytes());
            if name.is_empty() || name.contains(&b'=') {
                return Err(io::Error::from(io::ErrorKind::InvalidInput));
            }
            let mut pair = Zeroizing::new(Vec::with_capacity(name.len() + value.len() + 1));
            pair.extend_from_slice(name);
            pair.push(b'=');
            pair.extend_from_slice(value);
            c_string(&pair)
        })
        .collect::<io::Result<Vec<_>>>()
        .map_err(SessionError::Setup)?;
    let pointers = |list: &[Zeroizing<Vec<u8>>]| -> Vec<*const c_char> {
        list.iter()
            .map(|c| c.as_ptr().cast::<c_char>())
            .chain(std::iter::once(std::ptr::null()))
            .collect()
    };
    let program_ptrs = pointers(&programs);
    let argv_ptrs = pointers(&args);
    let envp_ptrs = pointers(&vars);
    let (ours, theirs) = socket_pair().map_err(SessionError::Setup)?;
    let prepared = pty_monitor::Prepared {
        slave: slave.as_raw_fd(),
        control: theirs.as_raw_fd(),
        programs: program_ptrs.as_ptr(),
        program_count: programs.len(),
        argv: argv_ptrs.as_ptr(),
        envp: envp_ptrs.as_ptr(),
    };
    // SAFETY: fork has no preconditions. The child runs only
    // `monitor_main`, which calls async-signal-safe functions, never
    // allocates and never returns, so the locks other threads of this
    // process held at the fork do not matter there.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(SessionError::Setup(io::Error::last_os_error()));
    }
    if pid == 0 {
        // SAFETY: a new child of fork; `prepared`'s pointers point into this
        // process's copy of the parent's memory, valid until it execs or
        // exits.
        unsafe { pty_monitor::monitor_main(&prepared) };
    }
    let monitor = OwnedChild::from_fork(pid);
    // The monitor and the command hold the slave and their end of the
    // channel now; this process keeps neither.
    drop(theirs);
    drop(slave);
    drop((program_ptrs, argv_ptrs, envp_ptrs));
    drop((programs, args, vars));
    let mut session = SessionMonitor {
        monitor: Some(monitor),
        control: Some(ours),
        command: 0,
        buf: [0; FRAME],
        filled: 0,
    };
    match session.next_report(None) {
        Ok(Some(Report::Started(pid))) => {
            session.command = pid.unsigned_abs();
            Ok(session)
        }
        Ok(Some(Report::ExecFailed(e))) => {
            session.reap_now();
            Err(SessionError::Exec(io::Error::from_raw_os_error(e)))
        }
        Ok(Some(Report::SetupFailed(e))) => {
            session.reap_now();
            Err(SessionError::Setup(io::Error::from_raw_os_error(e)))
        }
        Ok(_) => {
            session.reap_now();
            Err(SessionError::Setup(io::ErrorKind::InvalidData.into()))
        }
        Err(e) => {
            session.reap_now();
            Err(SessionError::Setup(e))
        }
    }
}

impl SessionMonitor {
    /// The monitor's pid, which is the session's id: for display and for
    /// reading what the kernel reports; never a signal target outside the
    /// monitor's handle.
    pub fn monitor_id(&self) -> u32 {
        self.monitor.as_ref().map_or(0, OwnedChild::id)
    }

    /// The command's pid, which is its process group's id: for display and
    /// for reading what the kernel reports, never a signal target.
    pub fn command_id(&self) -> u32 {
        self.command
    }

    /// The CLI's end of the control channel, to wait on with `poll`.
    pub fn control(&self) -> Option<BorrowedFd<'_>> {
        self.control.as_ref().map(AsFd::as_fd)
    }

    /// The session the monitor leads (Linux), for D-34's session-scoped
    /// delivery; `None` once the monitor was reaped.
    #[cfg(target_os = "linux")]
    pub fn session(&self) -> Option<OwnedSession<'_>> {
        self.monitor.as_ref().map(OwnedSession::from_monitor)
    }

    /// The next event, waiting at most `timeout` (forever with `None`);
    /// `Ok(None)` when none came in time.
    ///
    /// # Errors
    /// [`io::ErrorKind::UnexpectedEof`] when the monitor is gone (the
    /// channel closed: `pty_monitor_lost` unless an exit was reported
    /// before), [`io::ErrorKind::InvalidData`] for a report that is not
    /// one, and `poll`'s and `read`'s errors.
    pub fn next_event(&mut self, timeout: Option<Duration>) -> io::Result<Option<MonitorEvent>> {
        Ok(match self.next_report(timeout)? {
            None => None,
            Some(Report::Stopped(sig)) => Some(MonitorEvent::Stopped(sig)),
            Some(Report::Continued) => Some(MonitorEvent::Continued),
            Some(Report::Exited(status)) => {
                Some(MonitorEvent::Exited(ExitStatus::from_raw(status)))
            }
            Some(_) => return Err(io::ErrorKind::InvalidData.into()),
        })
    }

    fn next_report(&mut self, timeout: Option<Duration>) -> io::Result<Option<Report>> {
        let end = timeout.map(|t| Instant::now() + t);
        let control = self
            .control
            .as_ref()
            .ok_or(io::ErrorKind::UnexpectedEof)?
            .as_raw_fd();
        loop {
            let ms = match end {
                None => -1,
                Some(end) => {
                    let left = end.saturating_duration_since(Instant::now());
                    libc::c_int::try_from(left.as_millis().max(u128::from(!left.is_zero())))
                        .unwrap_or(libc::c_int::MAX)
                }
            };
            let mut p = libc::pollfd {
                fd: control,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: `p` is one initialized pollfd for an open descriptor.
            let rc = unsafe { libc::poll(&mut p, 1, ms) };
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            if rc == 0 {
                return Ok(None);
            }
            let free = self.buf.get_mut(self.filled..).unwrap_or_default();
            // SAFETY: `free` is writable for its length; the descriptor is
            // open.
            let n = unsafe { libc::read(control, free.as_mut_ptr().cast(), free.len()) };
            match usize::try_from(n) {
                Ok(0) => {
                    return Err(if self.filled == 0 {
                        io::ErrorKind::UnexpectedEof.into()
                    } else {
                        io::ErrorKind::InvalidData.into()
                    });
                }
                Ok(n) => {
                    self.filled = self.filled.saturating_add(n).min(FRAME);
                    if self.filled == FRAME {
                        self.filled = 0;
                        return pty_monitor::decode_report(&self.buf)
                            .map(Some)
                            .ok_or_else(|| io::ErrorKind::InvalidData.into());
                    }
                }
                Err(_) => {
                    let err = io::Error::last_os_error();
                    if err.kind() != io::ErrorKind::Interrupted {
                        return Err(err);
                    }
                }
            }
        }
    }

    /// Sends `command` to the monitor.
    ///
    /// # Errors
    /// [`io::ErrorKind::InvalidInput`] for a signal the monitor does not
    /// send; [`io::ErrorKind::BrokenPipe`] when the monitor is gone; and
    /// `write`'s other errors.
    pub fn send(&mut self, command: MonitorCommand) -> io::Result<()> {
        let command = match command {
            MonitorCommand::Resume => pty_monitor::Command::Resume,
            MonitorCommand::Suspend => pty_monitor::Command::Suspend,
            MonitorCommand::Signal(sig) if pty_monitor::signal_allowed(sig) => {
                pty_monitor::Command::Signal(sig)
            }
            MonitorCommand::Signal(_) => return Err(io::ErrorKind::InvalidInput.into()),
        };
        let frame = pty_monitor::encode_command(command);
        let control = self
            .control
            .as_ref()
            .ok_or(io::ErrorKind::BrokenPipe)?
            .as_raw_fd();
        let mut done = 0usize;
        while let Some(rest) = frame.get(done..).filter(|r| !r.is_empty()) {
            #[cfg(target_os = "linux")]
            // SAFETY: `rest` is readable for its length; MSG_NOSIGNAL turns a
            // closed channel into EPIPE rather than SIGPIPE.
            let n = unsafe {
                libc::send(
                    control,
                    rest.as_ptr().cast(),
                    rest.len(),
                    libc::MSG_NOSIGNAL,
                )
            };
            #[cfg(not(target_os = "linux"))]
            // SAFETY: `rest` is readable for its length; the socket has
            // SO_NOSIGPIPE set.
            let n = unsafe { libc::write(control, rest.as_ptr().cast(), rest.len()) };
            match usize::try_from(n) {
                Ok(n) if n > 0 => done = done.saturating_add(n),
                Ok(_) => return Err(io::ErrorKind::WriteZero.into()),
                Err(_) => {
                    let err = io::Error::last_os_error();
                    if err.kind() != io::ErrorKind::Interrupted {
                        return Err(err);
                    }
                }
            }
        }
        Ok(())
    }

    /// Ends the session: closes the channel, so the monitor reaps the
    /// command (hanging it up first if it still runs) and exits, and reaps
    /// the monitor. Returns the monitor's own status (0 after a reported
    /// exit). Call it after [`MonitorEvent::Exited`]; before, it waits for
    /// the hung-up command to end.
    ///
    /// # Errors
    /// `waitpid`'s errors.
    pub fn finish(mut self) -> io::Result<ExitStatus> {
        self.control = None;
        match self.monitor.take() {
            Some(m) => m.reap(),
            None => Err(io::ErrorKind::NotFound.into()),
        }
    }

    fn reap_now(&mut self) {
        self.control = None;
        if let Some(m) = self.monitor.take() {
            let _ = m.reap();
        }
    }
}

impl Drop for SessionMonitor {
    /// A session dropped without [`SessionMonitor::finish`] (an error path):
    /// the channel is closed and the monitor killed and reaped. As the
    /// session's leader exits, the kernel hangs the terminal up for the
    /// command's group.
    fn drop(&mut self) {
        self.control = None;
        if let Some(m) = self.monitor.take() {
            let _ = m.kill_and_reap();
        }
    }
}

/// How a forwarded signal reaches the slave's foreground job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalRoute {
    /// `TIOCSIG` on the master: the kernel signals the slave's foreground
    /// process group.
    Tiocsig,
    /// `OwnedSession` (Linux): each process of the monitor's session in
    /// the slave's foreground group, through a pidfd of its own.
    Session,
    /// [`MonitorCommand::Signal`]: the command's own group only, for a
    /// signal narrowed on a system. None is, on Linux or macOS.
    CommandGroup,
}

/// The route [`forward_signal`] takes for `sig` on this system (the M2-17
/// spike's result, `crates/envcloak-sys/tests/pty_signals.rs`), or `None`
/// for a signal that is not forwarded.
pub fn signal_route(sig: i32) -> Option<SignalRoute> {
    match sig {
        libc::SIGINT | libc::SIGQUIT => Some(SignalRoute::Tiocsig),
        libc::SIGTERM | libc::SIGHUP if cfg!(target_os = "linux") => Some(SignalRoute::Session),
        libc::SIGTERM | libc::SIGHUP => Some(SignalRoute::Tiocsig),
        _ => None,
    }
}

/// How a forwarded signal went: its route, and for [`SignalRoute::Session`]
/// how many processes it was sent to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Forwarded {
    pub route: SignalRoute,
    pub processes: Option<usize>,
}

/// Sends `sig` to the slave's foreground process group with `TIOCSIG` on
/// the master side `master`: the kernel picks the group. Linux accepts
/// only SIGINT, SIGQUIT and SIGTSTP (`EINVAL` otherwise); macOS any signal,
/// and flushes the terminal's queues unless `NOFLSH` is set.
///
/// # Errors
/// `ioctl`'s errors.
pub fn signal_foreground_job(master: BorrowedFd<'_>, sig: i32) -> io::Result<()> {
    // SAFETY: TIOCSIG takes the signal's number by value; on a descriptor
    // that is not a PTY's master side it fails without effect.
    if unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSIG as _, sig) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Forwards `sig`, which another process sent the CLI, to the slave's
/// foreground job along [`signal_route`]'s route for it.
///
/// # Errors
/// [`io::ErrorKind::InvalidInput`] for a signal that is not forwarded; the
/// route's own errors.
pub fn forward_signal(
    monitor: &mut SessionMonitor,
    master: BorrowedFd<'_>,
    sig: i32,
) -> io::Result<Forwarded> {
    let route = signal_route(sig).ok_or(io::ErrorKind::InvalidInput)?;
    let processes = match route {
        SignalRoute::Tiocsig => {
            signal_foreground_job(master, sig)?;
            None
        }
        SignalRoute::Session => Some(session_signal(monitor, master, sig)?),
        SignalRoute::CommandGroup => {
            monitor.send(MonitorCommand::Signal(sig))?;
            None
        }
    };
    Ok(Forwarded { route, processes })
}

#[cfg(target_os = "linux")]
fn session_signal(monitor: &SessionMonitor, master: BorrowedFd<'_>, sig: i32) -> io::Result<usize> {
    monitor
        .session()
        .ok_or(io::ErrorKind::NotFound)?
        .signal_foreground(master, sig)
}

#[cfg(not(target_os = "linux"))]
fn session_signal(_: &SessionMonitor, _: BorrowedFd<'_>, _: i32) -> io::Result<usize> {
    Err(io::ErrorKind::Unsupported.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_program_is_looked_up_as_execvp_does() {
        let names = |p: &[u8], path: &[u8]| -> Vec<Vec<u8>> {
            candidates(p, path)
                .unwrap()
                .iter()
                .map(|c| c[..c.len() - 1].to_vec())
                .collect()
        };
        assert_eq!(names(b"/bin/cat", b"/x:/y"), vec![b"/bin/cat".to_vec()]);
        assert_eq!(names(b"./cat", b"/x"), vec![b"./cat".to_vec()]);
        assert_eq!(
            names(b"cat", b"/x::/y/"),
            vec![b"/x/cat".to_vec(), b"cat".to_vec(), b"/y//cat".to_vec()]
        );
        assert!(candidates(b"", b"/x").is_err());
        assert_eq!(
            candidates(b"c\0t", b"/x").unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn every_forwarded_signal_has_a_route_and_nothing_else_does() {
        for sig in [libc::SIGINT, libc::SIGQUIT, libc::SIGTERM, libc::SIGHUP] {
            assert!(signal_route(sig).is_some(), "{sig}");
        }
        for sig in [
            libc::SIGKILL,
            libc::SIGSTOP,
            libc::SIGTSTP,
            libc::SIGUSR1,
            0,
        ] {
            assert_eq!(signal_route(sig), None, "{sig}");
        }
    }
}
