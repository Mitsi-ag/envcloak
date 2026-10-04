//! Processes EnvCloak owns, and the only signals it sends them (M2 plan
//! D-34; review F-73, CR-4).
//!
//! [`OwnedChild`] is a child this process started and has not reaped. A
//! child's pid cannot be given to another process until its parent reaps
//! it, so while the handle lives the pid, and the process group the child
//! leads, still name what this process started: signals go only there.
//! Exit is observed without reaping ([`OwnedChild::has_exited`]), and
//! [`OwnedChild::reap`] consumes the handle, after which no signal call
//! exists. On Linux the handle also holds a pidfd, taken while the child
//! was unreaped, and signals the child through it (`pidfd_send_signal`
//! fails with `ESRCH` once the child is gone rather than reaching another
//! process). macOS has no pidfd: ownership alone carries the guarantee.
//!
//! Ownership holds only while no wait happens behind the handle's back.
//! A process whose SIGCHLD is set to be ignored (`SIG_IGN`) or carries
//! `SA_NOCLDWAIT` may have its children reaped by the kernel the moment
//! they exit, their numbers free for reuse at once (POSIX `wait` leaves
//! `SIG_IGN` to the system; review cycle 365). Linux reaps so for both,
//! a `SIG_IGN` inherited across `exec` included. On macOS 26.4.1 it was
//! measured for `SA_NOCLDWAIT` and for `SIG_IGN` set in the process
//! itself, and not for a `SIG_IGN` inherited across `exec` (XNU marks the
//! process when `sigaction` sets it; `crates/envcloak-sys/tests/pty.rs`
//! prints what each setup does). So [`keep_children_unreaped`] runs
//! before every fork that makes an `OwnedChild`, whichever setup the
//! process has (it gives SIGCHLD its default action back, or refuses),
//! and every signal sent by number, rather than through a pidfd, checks
//! first that this process still does not reap on its own and that the
//! child is still its own, unreaped one (`waitid` with `WNOWAIT`).
//!
//! This is the part of the owned-handle API the PTY monitor needs
//! (`crate::pty`, M2 task M2-17): the CLI's handle on the monitor it
//! forks. M2 task M2-27 extends it (spawning through `Command`, its
//! `ProcessOps` seam and the clippy ban on `kill` elsewhere).
//!
//! `OwnedSession` (Linux) is D-34's one bounded exception, for the PTY
//! monitor's session: it signals the terminal's foreground job when that
//! job is a process group of the session the monitor leads, as one
//! operation of the kernel. A process enters a session only by being
//! created in it (`setsid` makes a new one), a process group never spans
//! two sessions (`setpgid` joins only a group of the caller's own
//! session, and `setsid` leaves the group), and the monitor's pid, which
//! is the session's id, cannot be reused while the monitor is unreaped. So
//! a pidfd is opened on the process whose pid is the foreground group's
//! number (the group's leader), and only then is that process's session
//! read and checked to be the monitor's: a process that is in the session
//! has been in it all its life, so every group it created, its own, is in
//! it too. The signal then goes through that pidfd to the group the
//! process leads or led (`PIDFD_SIGNAL_PROCESS_GROUP`, Linux 6.9), which
//! the kernel resolves by the group's identity, never its number, and
//! signals at the moment of delivery: a member that left the group or the
//! session before then (`setpgid`, `setsid`) gets nothing, and a number
//! reused since the read names no member of it. The group number read
//! from the terminal (`TIOCGPGRP`) only says whose pidfd to open; it is
//! never a signal target.

use std::io;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;

#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

/// A child process this process started and has not reaped.
pub struct OwnedChild {
    pid: libc::pid_t,
    #[cfg(target_os = "linux")]
    pidfd: Option<OwnedFd>,
}

impl core::fmt::Debug for OwnedChild {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OwnedChild")
            .field("pid", &self.pid)
            .finish_non_exhaustive()
    }
}

impl OwnedChild {
    /// Takes ownership of `pid`, a child `fork` just returned and nothing
    /// has waited for, in a process that called [`keep_children_unreaped`]
    /// before the fork. On Linux a pidfd is opened at once, while the child
    /// cannot have been reaped; where `pidfd_open` is not available the
    /// handle signals by pid, which ownership keeps valid.
    pub(crate) fn from_fork(pid: libc::pid_t) -> Self {
        OwnedChild {
            pid,
            #[cfg(target_os = "linux")]
            pidfd: pidfd_open(pid).ok(),
        }
    }

    /// Takes ownership of `pid`, a child `fork` just returned, without a
    /// pidfd: the PTY monitor's handle on its command, where a descriptor
    /// would be one more than the slave and the control channel, and which
    /// signals only by ownership (the monitor alone waits for the child,
    /// reaps it only through [`OwnedChild::reap`], and handles SIGCHLD
    /// without `SA_NOCLDWAIT`). Allocates nothing.
    pub(crate) fn from_fork_without_pidfd(pid: libc::pid_t) -> Self {
        OwnedChild {
            pid,
            #[cfg(target_os = "linux")]
            pidfd: None,
        }
    }

    /// The child's pid, for display and for reading what the kernel
    /// reports about it; never a signal target outside this handle.
    pub fn id(&self) -> u32 {
        self.pid.unsigned_abs()
    }

    /// Sends `sig` to the child: through its pidfd on Linux, otherwise by
    /// number, once [`kill_owned`]'s checks say the number is still the
    /// child's. Allocates nothing.
    ///
    /// # Errors
    /// `ESRCH` when the child has exited and the kernel says so (Linux);
    /// `ECHILD` when the number may no longer be the child's (this process
    /// reaps its children on its own, or the child was reaped); and the
    /// other errors of `pidfd_send_signal` or `kill`.
    pub fn signal(&self, sig: i32) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        if let Some(fd) = &self.pidfd {
            return pidfd_send_signal(fd.as_raw_fd(), sig);
        }
        kill_owned(&mut SysKill, self.pid, false, sig)
    }

    /// Sends `sig` to the process group the child leads. Only a child that
    /// leads its group (one that called `setsid` or `setpgid(0, 0)`) has
    /// one; the group's number is the child's pid, which cannot be reused
    /// while the child is unreaped, and [`kill_owned`] checks that it is.
    /// Allocates nothing.
    ///
    /// # Errors
    /// `ECHILD` as for [`OwnedChild::signal`]; `ESRCH` when the group is
    /// empty, and `kill`'s other errors.
    pub fn signal_group(&self, sig: i32) -> io::Result<()> {
        kill_owned(&mut SysKill, self.pid, true, sig)
    }

    /// Whether the child has exited, without waiting and without reaping
    /// it.
    ///
    /// # Errors
    /// `waitid`'s errors.
    pub fn has_exited(&self) -> io::Result<bool> {
        crate::has_exited(self.pid)
    }

    /// Waits until the child has exited, and leaves it unreaped.
    ///
    /// # Errors
    /// `waitid`'s errors.
    pub fn wait_exit(&self) -> io::Result<()> {
        crate::wait_for_exit(self.pid)
    }

    /// Waits for the child to exit and reaps it, consuming the handle.
    ///
    /// # Errors
    /// `waitpid`'s errors.
    pub fn reap(self) -> io::Result<ExitStatus> {
        let mut status: libc::c_int = 0;
        loop {
            // SAFETY: `status` is writable; the child is this process's own
            // and unreaped.
            let rc = unsafe { libc::waitpid(self.pid, &mut status, 0) };
            if rc == self.pid {
                return Ok(ExitStatus::from_raw(status));
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }

    /// Kills the child with SIGKILL and reaps it.
    ///
    /// # Errors
    /// `waitpid`'s errors; a child that has exited already is reaped.
    pub fn kill_and_reap(self) -> io::Result<ExitStatus> {
        let _ = self.signal(libc::SIGKILL);
        self.reap()
    }
}

/// How this process has SIGCHLD set up, as far as reaping goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChildSignal {
    /// SIGCHLD's action is `SIG_IGN`.
    pub ignored: bool,
    /// `SA_NOCLDWAIT` is set.
    pub no_wait: bool,
}

impl ChildSignal {
    /// Whether the kernel reaps this process's children on its own.
    pub fn reaps_on_its_own(self) -> bool {
        self.ignored || self.no_wait
    }
}

/// Reading and changing SIGCHLD's setup, so a recording model can stand in
/// for the process's signal table in tests.
pub(crate) trait SigchldOps {
    /// SIGCHLD's setup now.
    fn read(&mut self) -> io::Result<ChildSignal>;
    /// Stops the kernel reaping children on its own: an ignored SIGCHLD
    /// gets its default action back (which ignores the signal without
    /// reaping), `SA_NOCLDWAIT` is cleared, and a handler is kept.
    fn stop_reaping_on_its_own(&mut self) -> io::Result<()>;
}

/// [`keep_children_unreaped`] against `ops`.
pub(crate) fn keep_unreaped<O: SigchldOps>(ops: &mut O) -> io::Result<()> {
    if !ops.read()?.reaps_on_its_own() {
        return Ok(());
    }
    ops.stop_reaping_on_its_own()?;
    if ops.read()?.reaps_on_its_own() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "this process's children would be reaped without a wait",
        ));
    }
    Ok(())
}

/// Makes sure the kernel does not reap this process's children on its
/// own, so a child stays unreaped (and its pid and group number its own)
/// until this process waits for it: a SIGCHLD inherited ignored, or set
/// with `SA_NOCLDWAIT`, gets its default action back (a handler is kept).
/// Called before every fork that makes an [`OwnedChild`]. EnvCloak never
/// sets SIGCHLD to be ignored itself.
///
/// # Errors
/// When SIGCHLD cannot be read or changed, or still reaps on its own after
/// the change: then no child may be started with an owned handle.
pub fn keep_children_unreaped() -> io::Result<()> {
    keep_unreaped(&mut SysSigchld)
}

/// The real signal table. Async-signal-safe (`sigaction` only).
struct SysSigchld;

fn sigchld_action() -> io::Result<libc::sigaction> {
    // SAFETY: sigaction is plain data; sigaction(2) fills it in.
    let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: a null new action only reads the current one into `old`.
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut old) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(old)
}

impl SigchldOps for SysSigchld {
    fn read(&mut self) -> io::Result<ChildSignal> {
        let act = sigchld_action()?;
        Ok(ChildSignal {
            ignored: act.sa_sigaction == libc::SIG_IGN,
            no_wait: act.sa_flags & libc::SA_NOCLDWAIT != 0,
        })
    }

    fn stop_reaping_on_its_own(&mut self) -> io::Result<()> {
        let mut act = sigchld_action()?;
        if act.sa_sigaction == libc::SIG_IGN {
            act.sa_sigaction = libc::SIG_DFL;
        }
        act.sa_flags &= !libc::SA_NOCLDWAIT;
        // SAFETY: `act` is the current action, initialized by sigaction(2),
        // with SIG_IGN and SA_NOCLDWAIT taken out.
        if unsafe { libc::sigaction(libc::SIGCHLD, &act, std::ptr::null_mut()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// What a signal sent by number checks and does, so a recording model can
/// stand in for the system in tests.
pub(crate) trait KillOps {
    /// Whether this process's children are reaped on their own now.
    fn reaps_on_its_own(&mut self) -> io::Result<bool>;
    /// `Ok` while `pid` is a child of this process that nothing has reaped
    /// (it may have exited); `ECHILD` once it is not.
    fn unreaped(&mut self, pid: i32) -> io::Result<()>;
    /// `kill(target, sig)`.
    fn kill(&mut self, target: i32, sig: i32) -> io::Result<()>;
}

/// Sends `sig` to the owned child `pid` (or the group it leads, with
/// `group`) by number, only after checking that the number is still the
/// child's: this process does not reap on its own, and `pid` is its own
/// unreaped child. A reap that happened anyway (an ignored SIGCHLD set by
/// another library after the fork) ends in `ECHILD` here, not in a signal
/// to whatever took the number. Allocates nothing, so the PTY monitor uses
/// it after `fork`.
pub(crate) fn kill_owned<O: KillOps>(
    ops: &mut O,
    pid: i32,
    group: bool,
    sig: i32,
) -> io::Result<()> {
    if pid < 2 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    if ops.reaps_on_its_own()? {
        return Err(io::Error::from_raw_os_error(libc::ECHILD));
    }
    ops.unreaped(pid)?;
    ops.kill(if group { -pid } else { pid }, sig)
}

/// The real system for [`kill_owned`]: `sigaction`, `waitid` with
/// `WNOWAIT` and `kill`, all async-signal-safe.
struct SysKill;

impl KillOps for SysKill {
    fn reaps_on_its_own(&mut self) -> io::Result<bool> {
        SysSigchld.read().map(ChildSignal::reaps_on_its_own)
    }

    fn unreaped(&mut self, pid: i32) -> io::Result<()> {
        crate::has_exited(pid).map(|_| ())
    }

    fn kill(&mut self, target: i32, sig: i32) -> io::Result<()> {
        // SAFETY: kill has no memory effects; the caller checked that
        // `target` names its own unreaped child or the group it leads.
        if unsafe { libc::kill(target, sig) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn pidfd_open(pid: libc::pid_t) -> io::Result<OwnedFd> {
    // SAFETY: pidfd_open takes a pid and flags and returns a new
    // descriptor, or fails without effect.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = libc::c_int::try_from(fd).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    // SAFETY: the kernel just created `fd` (close-on-exec, as pidfd_open
    // always makes it) and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(target_os = "linux")]
fn pidfd_send_signal(pidfd: libc::c_int, sig: i32) -> io::Result<()> {
    pidfd_send_signal_with(pidfd, sig, 0)
}

/// Sends `sig` through a pidfd, with `flags` (0: the process;
/// [`PIDFD_SIGNAL_PROCESS_GROUP`]: the group it leads or led).
#[cfg(target_os = "linux")]
fn pidfd_send_signal_with(pidfd: libc::c_int, sig: i32, flags: libc::c_uint) -> io::Result<()> {
    // SAFETY: pidfd_send_signal with a null siginfo sends `sig` as kill
    // would, to what `pidfd` and `flags` name.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd,
            sig,
            std::ptr::null::<libc::siginfo_t>(),
            flags,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `pidfd_send_signal`'s flag that sends to the process group whose
/// identity is the pidfd's process (the group it leads or led), as
/// `kill_pgrp` does for the terminal's own signals: Linux 6.9
/// (`include/uapi/linux/pidfd.h`; `kernel/signal.c`,
/// `do_pidfd_send_signal`, which hands the pidfd's `struct pid` to
/// `kill_pgrp_info` as the group). Older kernels refuse the flag with
/// `EINVAL`.
#[cfg(target_os = "linux")]
const PIDFD_SIGNAL_PROCESS_GROUP: libc::c_uint = 1 << 2;

/// Why `OwnedSession` reached no foreground job. It is always an error,
/// never a delivery to nobody (lesson L-08); [`NoJob::of`] reads it back
/// from the `io::Error` that carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoJob {
    /// The terminal's foreground group is the monitor's own: the command is
    /// stopped and the monitor holds the terminal.
    MonitorHolds,
    /// No process has the foreground group's number as its pid any more:
    /// the group's leader has exited and been reaped (the first command of
    /// a pipeline that ended before the others), so nothing holds the
    /// group's identity to signal it through.
    NoLeader,
    /// The process whose pid is the group's number is not in the monitor's
    /// session: the number no longer names the job that was read.
    OutsideSession,
    /// The group had no process left when the signal was sent.
    Empty,
    /// The kernel cannot signal a process group through a pidfd
    /// (`PIDFD_SIGNAL_PROCESS_GROUP`, Linux 6.9) or has no `pidfd_open`
    /// (Linux 5.3); nothing was sent.
    Unsupported,
}

impl NoJob {
    /// The reason an error from `OwnedSession` carries, if it is one.
    pub fn of(e: &io::Error) -> Option<NoJob> {
        e.get_ref()?.downcast_ref::<NoJob>().copied()
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn error(self) -> io::Error {
        let kind = match self {
            NoJob::Unsupported => io::ErrorKind::Unsupported,
            _ => io::ErrorKind::NotFound,
        };
        io::Error::new(kind, self)
    }
}

impl core::fmt::Display for NoJob {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            NoJob::MonitorHolds => "the PTY monitor holds the terminal: the command is stopped",
            NoJob::NoLeader => "the terminal's foreground group has no leader to signal it through",
            NoJob::OutsideSession => {
                "the terminal's foreground group number names a process outside the session"
            }
            NoJob::Empty => "the terminal's foreground group has no process left",
            NoJob::Unsupported => "this kernel cannot signal a process group through a pidfd",
        })
    }
}

impl std::error::Error for NoJob {}

/// What `OwnedSession` reads and does, so a recording model can stand in
/// for the process table in tests: a handle on a process (a pidfd), the
/// session of the process that has a pid, and a signal to the process
/// group whose identity a handle holds.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) trait GroupTable {
    type Handle;
    /// A handle on the process that has `pid` as its pid now; `Ok(None)`
    /// when none has (it is gone, or the number names only a group whose
    /// leader was reaped).
    fn open(&mut self, pid: i32) -> io::Result<Option<Self::Handle>>;
    /// The session of the process that has `pid` now, read by pid, so
    /// possibly of another process than one a handle was opened on before;
    /// `Ok(None)` when no process has it.
    fn session_of(&mut self, pid: i32) -> io::Result<Option<i32>>;
    /// Sends `sig`, as one operation of the kernel, to every process that
    /// is then in the process group whose identity is the handle's process
    /// (the group it leads or led): `ESRCH` when that group has no
    /// process, `EINVAL` where the kernel cannot (Linux before 6.9), and
    /// `EPERM` when no member could be signalled. Success means at least
    /// one member was (`kill(2)`'s contract for a group).
    fn signal_group(&mut self, handle: &Self::Handle, sig: i32) -> io::Result<()>;
}

/// Binds the job in the foreground group `foreground` of the terminal of
/// the session `session` (the monitor's pid): a handle is opened on the
/// process whose pid is the group's number, and only after that is that
/// process's session read and checked to be `session`. Opened in this
/// order, the session read is the handle's process's own whenever that
/// process still has the number; if the number was given to another
/// process in between, the handle's process had left nothing behind (a
/// number is free only once no process, group or session uses it), so its
/// group is empty and the signal reaches no one. A process whose session
/// is `session` has been in it all its life, so the group it leads or led
/// is in it too: the leader need not still be in that group, nor alive.
///
/// # Errors
/// [`NoJob::MonitorHolds`] when `foreground` is the session's own group;
/// [`NoJob::NoLeader`] when no process has the number as its pid;
/// [`NoJob::OutsideSession`] when the process that has it is in another
/// session; [`NoJob::Unsupported`] without `pidfd_open`;
/// [`io::ErrorKind::InvalidInput`] for a number below 2; and the table's
/// own errors.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn bind_job<T: GroupTable>(
    table: &mut T,
    session: i32,
    foreground: i32,
) -> io::Result<T::Handle> {
    if session < 2 || foreground < 2 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    if foreground == session {
        return Err(NoJob::MonitorHolds.error());
    }
    let handle = match table.open(foreground) {
        Ok(Some(handle)) => handle,
        Ok(None) => return Err(NoJob::NoLeader.error()),
        Err(e) if e.raw_os_error() == Some(libc::ENOSYS) => return Err(NoJob::Unsupported.error()),
        Err(e) => return Err(e),
    };
    match table.session_of(foreground)? {
        Some(sid) if sid == session => Ok(handle),
        Some(_) => Err(NoJob::OutsideSession.error()),
        // Reaped since the handle was opened: its group's members, if it
        // has any, can no longer be shown to be in the session by it.
        None => Err(NoJob::NoLeader.error()),
    }
}

/// Signals the job [`bind_job`] bound, as one operation: every process in
/// its group at that moment, and no other.
///
/// # Errors
/// [`NoJob::Empty`] when the group has no process left (`ESRCH`);
/// [`NoJob::Unsupported`] where the kernel cannot signal a group through
/// a pidfd (`EINVAL`); `EPERM` when no member could be signalled.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn signal_job<T: GroupTable>(
    table: &mut T,
    handle: &T::Handle,
    sig: i32,
) -> io::Result<()> {
    match table.signal_group(handle, sig) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::ESRCH) => Err(NoJob::Empty.error()),
        Err(e) if e.raw_os_error() == Some(libc::EINVAL) => Err(NoJob::Unsupported.error()),
        Err(e) => Err(e),
    }
}

/// The session a PTY monitor leads, for signalling its foreground job
/// (Linux; D-34's bounded exception, D-35).
#[cfg(target_os = "linux")]
pub struct OwnedSession<'a> {
    monitor: &'a OwnedChild,
}

#[cfg(target_os = "linux")]
impl core::fmt::Debug for OwnedSession<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OwnedSession")
            .field("leader", &self.monitor.pid)
            .finish()
    }
}

/// The foreground job of an [`OwnedSession`], bound: a pidfd on the
/// process whose pid is the job's group number, checked to be in the
/// session after it was opened (Linux).
#[cfg(target_os = "linux")]
pub struct ForegroundJob<'a> {
    leader: OwnedFd,
    group: i32,
    _session: core::marker::PhantomData<&'a OwnedChild>,
}

#[cfg(target_os = "linux")]
impl core::fmt::Debug for ForegroundJob<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ForegroundJob")
            .field("group", &self.group)
            .finish_non_exhaustive()
    }
}

#[cfg(target_os = "linux")]
impl<'a> OwnedSession<'a> {
    /// The session `monitor` leads. The monitor called `setsid`, so its
    /// pid is the session's id, and while the handle is unreaped (it is
    /// borrowed here, so it is) no other session can have that id.
    pub fn from_monitor(monitor: &'a OwnedChild) -> Self {
        OwnedSession { monitor }
    }

    /// Binds the foreground job of the terminal whose master side is
    /// `master` (`TIOCGPGRP`), as [`bind_job`] has it.
    ///
    /// # Errors
    /// `ECHILD` when the monitor is no longer this process's own unreaped
    /// child (this process reaps on its own, or something reaped it); an
    /// error carrying a [`NoJob`] when there is no job of the session to
    /// bind; `TIOCGPGRP`'s, `pidfd_open`'s and `/proc`'s other errors.
    pub fn foreground_job(&self, master: BorrowedFd<'_>) -> io::Result<ForegroundJob<'a>> {
        // The session's id is the monitor's pid only while the monitor is
        // unreaped (the borrow says it is not reaped through its handle;
        // this says nothing else reaped it).
        if SysSigchld.read()?.reaps_on_its_own() {
            return Err(io::Error::from_raw_os_error(libc::ECHILD));
        }
        crate::has_exited(self.monitor.pid)?;
        let group = crate::pty::foreground_group(master)?;
        let leader = bind_job(&mut ProcTable, self.monitor.pid, group)?;
        Ok(ForegroundJob {
            leader,
            group,
            _session: core::marker::PhantomData,
        })
    }

    /// Sends `sig` to the foreground job of the terminal whose master side
    /// is `master`: [`OwnedSession::foreground_job`], then
    /// [`ForegroundJob::signal`].
    ///
    /// # Errors
    /// Theirs.
    pub fn signal_foreground(&self, master: BorrowedFd<'_>, sig: i32) -> io::Result<()> {
        self.foreground_job(master)?.signal(sig)
    }
}

#[cfg(target_os = "linux")]
impl ForegroundJob<'_> {
    /// The job's process group number, for display and for reading what
    /// the kernel reports; never a signal target.
    pub fn group_id(&self) -> u32 {
        self.group.unsigned_abs()
    }

    /// Sends `sig` to every process in the job's group at the moment of
    /// delivery, through the leader's pidfd (`PIDFD_SIGNAL_PROCESS_GROUP`):
    /// one operation of the kernel, which reads the group's members under
    /// its task-list lock, so a member that left the group or the session
    /// since the job was bound gets nothing. A member this process may not
    /// signal (one that changed to another user) gets nothing either, and,
    /// as with `kill(2)` of a group, the call succeeds when another member
    /// received the signal.
    ///
    /// # Errors
    /// An error carrying [`NoJob::Empty`] or [`NoJob::Unsupported`]
    /// ([`signal_job`]); `EPERM` when no member could be signalled.
    pub fn signal(&self, sig: i32) -> io::Result<()> {
        signal_job(&mut ProcTable, &self.leader, sig)
    }
}

/// The live process table: `/proc`, pidfds.
#[cfg(target_os = "linux")]
struct ProcTable;

#[cfg(target_os = "linux")]
impl GroupTable for ProcTable {
    type Handle = OwnedFd;

    fn open(&mut self, pid: i32) -> io::Result<Option<OwnedFd>> {
        match pidfd_open(pid) {
            Ok(fd) => Ok(Some(fd)),
            // No task has the number as its pid: `ESRCH` (gone or reaped);
            // `ENOENT` (Linux 6.9 on) or `EINVAL` (before) for a number a
            // process group or a thread holds but no process.
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(libc::ESRCH | libc::ENOENT | libc::EINVAL)
                ) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    fn session_of(&mut self, pid: i32) -> io::Result<Option<i32>> {
        let stat = match std::fs::read(format!("/proc/{pid}/stat")) {
            Ok(stat) => stat,
            Err(e)
                if e.kind() == io::ErrorKind::NotFound || e.raw_os_error() == Some(libc::ESRCH) =>
            {
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        let f = crate::parse_proc_stat(&stat).ok_or(io::ErrorKind::InvalidData)?;
        if f.pid != pid {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(Some(f.session))
    }

    fn signal_group(&mut self, handle: &OwnedFd, sig: i32) -> io::Result<()> {
        pidfd_send_signal_with(handle.as_raw_fd(), sig, PIDFD_SIGNAL_PROCESS_GROUP)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    /// A process's identity: its pid and which incarnation of that pid it
    /// is (a pidfd names one incarnation).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct Id {
        pid: i32,
        birth: u32,
    }

    /// One process of the model: its identity, its session, and its
    /// group's identity (the process that created the group).
    #[derive(Clone, Copy, Debug)]
    struct Proc {
        id: Id,
        sid: i32,
        group: Id,
    }

    /// A change to the process table, made by the model between two calls.
    #[derive(Clone, Copy, Debug)]
    enum Change {
        /// The process with this pid exits and is reaped.
        Gone(i32),
        /// It calls `setsid`: a new session and group of its own.
        Setsid(i32),
        /// It joins the group the process with the second pid created, in
        /// its own session.
        Join(i32, i32),
        /// The first pid forks a child with the second pid, in its group.
        Fork(i32, i32),
        /// A new process takes this pid, in this session, leading a new
        /// group of its own or (with `Some`) in the group the process with
        /// that pid created. The model refuses it while the number is in
        /// use, as the kernel does.
        Born(i32, i32, Option<i32>),
    }

    #[derive(Default)]
    struct Model {
        procs: Vec<Proc>,
        births: u32,
        /// Changes made right after the n-th call (1-based) to the table.
        after_call: BTreeMap<usize, Vec<Change>>,
        calls: usize,
        /// Every process each signal reached.
        signalled: Vec<(Id, i32)>,
        open_errno: Option<i32>,
        signal_errno: Option<i32>,
    }

    impl Model {
        fn new() -> Self {
            Model::default()
        }

        fn find(&self, pid: i32) -> Option<Proc> {
            self.procs.iter().copied().find(|p| p.id.pid == pid)
        }

        fn in_use(&self, n: i32) -> bool {
            self.procs
                .iter()
                .any(|p| p.id.pid == n || p.group.pid == n || p.sid == n)
        }

        fn born(&mut self, pid: i32, sid: i32, group: Option<i32>) -> Id {
            assert!(!self.in_use(pid), "the kernel never gives out {pid} now");
            self.births += 1;
            let id = Id {
                pid,
                birth: self.births,
            };
            let group = group.map_or(id, |g| self.find(g).unwrap().group);
            self.procs.push(Proc { id, sid, group });
            id
        }

        fn apply(&mut self, change: Change) {
            match change {
                Change::Gone(pid) => self.procs.retain(|p| p.id.pid != pid),
                Change::Setsid(pid) => {
                    let p = self.procs.iter_mut().find(|p| p.id.pid == pid).unwrap();
                    p.sid = pid;
                    p.group = p.id;
                }
                Change::Join(pid, leader) => {
                    let target = self.find(leader).unwrap();
                    let p = self.procs.iter_mut().find(|p| p.id.pid == pid).unwrap();
                    assert_eq!(p.sid, target.sid, "setpgid stays in the session");
                    p.group = target.group;
                }
                Change::Fork(parent, pid) => {
                    let parent = self.find(parent).unwrap();
                    self.born(pid, parent.sid, Some(parent.id.pid));
                }
                Change::Born(pid, sid, group) => {
                    self.born(pid, sid, group);
                }
            }
        }

        fn tick(&mut self) {
            self.calls += 1;
            for change in self.after_call.remove(&self.calls).unwrap_or_default() {
                self.apply(change);
            }
        }

        fn hit(&self) -> BTreeSet<i32> {
            self.signalled.iter().map(|(id, _)| id.pid).collect()
        }
    }

    impl GroupTable for Model {
        type Handle = Id;
        fn open(&mut self, pid: i32) -> io::Result<Option<Id>> {
            let result = match self.open_errno {
                Some(e) => Err(io::Error::from_raw_os_error(e)),
                None => Ok(self.find(pid).map(|p| p.id)),
            };
            self.tick();
            result
        }
        fn session_of(&mut self, pid: i32) -> io::Result<Option<i32>> {
            let sid = self.find(pid).map(|p| p.sid);
            self.tick();
            Ok(sid)
        }
        fn signal_group(&mut self, handle: &Id, sig: i32) -> io::Result<()> {
            self.tick();
            if let Some(e) = self.signal_errno {
                return Err(io::Error::from_raw_os_error(e));
            }
            let members: Vec<Id> = self
                .procs
                .iter()
                .filter(|p| p.group == *handle)
                .map(|p| p.id)
                .collect();
            if members.is_empty() {
                return Err(io::Error::from_raw_os_error(libc::ESRCH));
            }
            self.signalled.extend(members.iter().map(|id| (*id, sig)));
            Ok(())
        }
    }

    const MONITOR: i32 = 500;
    const SHELL: i32 = 501;
    const LEADER: i32 = 510;
    const PEER: i32 = 511;
    const OTHER: i32 = 520;
    const OTHER_PEER: i32 = 521;

    /// The monitor's session: the monitor, a nested shell, the job (a
    /// leader and a peer in its group), and a second job of the shell's in
    /// a group of its own (for a delivery that must still go through).
    fn session() -> Model {
        let mut m = Model::new();
        m.born(MONITOR, MONITOR, None);
        m.born(SHELL, MONITOR, None);
        m.born(LEADER, MONITOR, None);
        m.born(PEER, MONITOR, Some(LEADER));
        m.born(OTHER, MONITOR, None);
        m.born(OTHER_PEER, MONITOR, Some(OTHER));
        m
    }

    fn deliver(m: &mut Model, foreground: i32, sig: i32) -> io::Result<()> {
        let job = bind_job(m, MONITOR, foreground)?;
        signal_job(m, &job, sig)
    }

    fn no_job(r: &io::Result<()>) -> Option<NoJob> {
        r.as_ref().err().and_then(NoJob::of)
    }

    /// The job's group, as one: its leader and its peer, not the nested
    /// shell, the monitor or the shell's other job.
    #[test]
    fn the_foreground_job_and_nothing_else_is_signalled() {
        let mut m = session();
        deliver(&mut m, LEADER, libc::SIGTERM).unwrap();
        assert_eq!(m.hit(), BTreeSet::from([LEADER, PEER]));
        assert!(m.signalled.iter().all(|(_, s)| *s == libc::SIGTERM));
    }

    /// Membership is read at the delivery, not at the binding (Codex's
    /// review of PR #27): a member that left the session with `setsid`,
    /// or moved to another group of it, after the job was bound gets
    /// nothing; a child forked into the group meanwhile gets the signal,
    /// in the session as it is. A delivery that checks each member first
    /// and signals it after (the design before this one) signals the two
    /// that left.
    #[test]
    fn membership_is_what_it_is_at_the_delivery() {
        for (change, expected) in [
            (Change::Setsid(PEER), vec![LEADER]),
            (Change::Join(PEER, OTHER), vec![LEADER]),
            (Change::Fork(LEADER, 530), vec![LEADER, PEER, 530]),
        ] {
            let mut m = session();
            let job = bind_job(&mut m, MONITOR, LEADER).unwrap();
            m.apply(change);
            signal_job(&mut m, &job, libc::SIGHUP).unwrap();
            assert_eq!(m.hit(), expected.into_iter().collect(), "{change:?}");
            if let Change::Join(..) = change {
                assert!(!m.hit().contains(&OTHER), "the group it joined");
            }
        }
    }

    /// The leader may leave its own group for another of the session: the
    /// group it created is still signalled by its identity, and only its
    /// members.
    #[test]
    fn the_leader_need_not_still_be_in_its_group() {
        let mut m = session();
        m.apply(Change::Join(LEADER, OTHER));
        deliver(&mut m, LEADER, libc::SIGTERM).unwrap();
        assert_eq!(m.hit(), BTreeSet::from([PEER]));
    }

    /// A group whose leader was reaped (a pipeline's first command that
    /// ended first) has nothing to signal it through: `NoLeader` and
    /// nothing sent, before the handle or between the handle and the read
    /// (the read then finds no process, and cannot show the members in the
    /// session).
    #[test]
    fn a_group_whose_leader_was_reaped_is_not_signalled_by_number() {
        let mut m = session();
        m.apply(Change::Gone(LEADER));
        assert_eq!(no_job(&deliver(&mut m, LEADER, 15)), Some(NoJob::NoLeader));
        let mut m = session();
        m.after_call.insert(1, vec![Change::Gone(LEADER)]);
        assert_eq!(no_job(&deliver(&mut m, LEADER, 15)), Some(NoJob::NoLeader));
        assert!(m.signalled.is_empty(), "{:?}", m.signalled);
    }

    /// The three birth-identity schedules of an independent review oracle
    /// (cycle 368), re-derived for a delivery by group identity: the job
    /// ends and its number is given to a new process right after the
    /// handle is opened, (1) in another session in a group of the same
    /// number, (2) in the same session in another group, (3) in the same
    /// session leading a new group of the same number. The new process and
    /// its group get nothing: (1) is refused by the session read, and (2)
    /// and (3) bind the old job, whose group is empty (`Empty`). In each,
    /// the shell's other job is then signalled as a control, so a
    /// delivery that reaches no one at all fails too. Read the session
    /// before opening the handle and (1) signals the outsider.
    #[test]
    fn a_number_given_to_another_process_between_the_calls_reaches_no_one() {
        let outsider_session = 899;
        for (case, born, refused) in [
            (
                1,
                Change::Born(LEADER, outsider_session, None),
                NoJob::OutsideSession,
            ),
            (2, Change::Born(LEADER, MONITOR, Some(SHELL)), NoJob::Empty),
            (3, Change::Born(LEADER, MONITOR, None), NoJob::Empty),
        ] {
            let mut m = session();
            if case == 1 {
                // The outsider's session is a real one.
                m.born(outsider_session, outsider_session, None);
            }
            m.after_call
                .insert(1, vec![Change::Gone(PEER), Change::Gone(LEADER), born]);
            assert_eq!(
                no_job(&deliver(&mut m, LEADER, libc::SIGTERM)),
                Some(refused),
                "case {case}"
            );
            assert!(m.signalled.is_empty(), "case {case}: {:?}", m.signalled);
            deliver(&mut m, OTHER, libc::SIGTERM).unwrap();
            assert_eq!(m.hit(), BTreeSet::from([OTHER, OTHER_PEER]), "case {case}");
        }
    }

    /// The same after the read: the job ends and an outsider takes its
    /// number with a group of its own before the signal. The signal names
    /// the old group, now empty: `Empty`, and the outsider gets nothing.
    #[test]
    fn a_number_given_to_an_outsider_before_the_signal_reaches_no_one() {
        let mut m = session();
        m.born(899, 899, None);
        m.after_call.insert(
            2,
            vec![
                Change::Gone(PEER),
                Change::Gone(LEADER),
                Change::Born(LEADER, 899, None),
            ],
        );
        assert_eq!(
            no_job(&deliver(&mut m, LEADER, libc::SIGHUP)),
            Some(NoJob::Empty)
        );
        assert!(m.signalled.is_empty(), "{:?}", m.signalled);
    }

    /// A number that names a process outside the session (a hostile or a
    /// stale reading of the terminal) is refused before anything is sent,
    /// even when that process reports the same group number. Drop the
    /// session check and it is signalled.
    #[test]
    fn a_process_outside_the_session_with_the_same_group_number_gets_nothing() {
        let mut m = session();
        m.born(900, 899, None);
        m.born(901, 899, Some(900));
        assert_eq!(
            no_job(&deliver(&mut m, 900, libc::SIGTERM)),
            Some(NoJob::OutsideSession)
        );
        assert!(m.signalled.is_empty(), "{:?}", m.signalled);
    }

    /// The monitor's own group (it holds the terminal while the command is
    /// stopped) and nonsense numbers select nothing, as errors.
    #[test]
    fn the_monitors_own_group_and_bad_numbers_are_errors_not_deliveries() {
        let mut m = session();
        assert_eq!(
            no_job(&deliver(&mut m, MONITOR, 15)),
            Some(NoJob::MonitorHolds)
        );
        for fg in [0, 1, -LEADER] {
            let r = deliver(&mut m, fg, 15);
            assert_eq!(r.unwrap_err().kind(), io::ErrorKind::InvalidInput, "{fg}");
        }
        let r = bind_job(&mut m, 0, LEADER).map(|_| ());
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert!(m.signalled.is_empty());
        assert_eq!(m.calls, 0, "nothing was even looked at");
    }

    /// A kernel without `pidfd_open` (`ENOSYS`) or without the process
    /// group flag (`EINVAL`, before Linux 6.9): `Unsupported` before
    /// anything is sent. `EPERM` from the delivery (no member could be
    /// signalled) and other errors pass through as errors, never success.
    #[test]
    fn kernels_that_cannot_and_refusals_are_errors() {
        let mut m = session();
        m.open_errno = Some(libc::ENOSYS);
        let r = deliver(&mut m, LEADER, 15);
        assert_eq!(no_job(&r), Some(NoJob::Unsupported));
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::Unsupported);
        let mut m = session();
        m.signal_errno = Some(libc::EINVAL);
        assert_eq!(
            no_job(&deliver(&mut m, LEADER, 15)),
            Some(NoJob::Unsupported)
        );
        for errno in [libc::EPERM, libc::EMFILE] {
            let mut m = session();
            if errno == libc::EMFILE {
                m.open_errno = Some(errno);
            } else {
                m.signal_errno = Some(errno);
            }
            let r = deliver(&mut m, LEADER, 15);
            assert_eq!(r.unwrap_err().raw_os_error(), Some(errno));
            assert!(m.signalled.is_empty());
        }
    }

    /// Every error `OwnedSession` reports names its reason, and the
    /// `Unsupported` one alone has that kind.
    #[test]
    fn each_reason_reads_back_from_its_error() {
        for why in [
            NoJob::MonitorHolds,
            NoJob::NoLeader,
            NoJob::OutsideSession,
            NoJob::Empty,
            NoJob::Unsupported,
        ] {
            let e = why.error();
            assert_eq!(NoJob::of(&e), Some(why));
            assert_eq!(
                e.kind() == io::ErrorKind::Unsupported,
                why == NoJob::Unsupported
            );
            assert!(!e.to_string().is_empty());
        }
        assert_eq!(NoJob::of(&io::Error::from(io::ErrorKind::NotFound)), None);
    }

    /// A recording SIGCHLD table.
    struct Sigchld {
        now: ChildSignal,
        /// What a change leaves (a system that refuses it keeps `now`).
        after_change: Option<ChildSignal>,
        changes: usize,
    }

    impl SigchldOps for Sigchld {
        fn read(&mut self) -> io::Result<ChildSignal> {
            Ok(self.now)
        }
        fn stop_reaping_on_its_own(&mut self) -> io::Result<()> {
            self.changes += 1;
            match self.after_change {
                Some(next) => {
                    self.now = next;
                    Ok(())
                }
                None => Err(io::Error::from_raw_os_error(libc::EINVAL)),
            }
        }
    }

    const DEFAULT: ChildSignal = ChildSignal {
        ignored: false,
        no_wait: false,
    };

    /// A process that inherited SIGCHLD ignored, or has `SA_NOCLDWAIT`,
    /// gets the default back before it forks an owned child; one with the
    /// default is left alone; one where the change fails or does not hold
    /// starts nothing. Skip the change and the ignored case fails.
    #[test]
    fn an_ignored_sigchld_is_given_its_default_back_before_a_fork_or_refused() {
        for start in [
            ChildSignal {
                ignored: true,
                no_wait: false,
            },
            ChildSignal {
                ignored: false,
                no_wait: true,
            },
        ] {
            let mut ops = Sigchld {
                now: start,
                after_change: Some(DEFAULT),
                changes: 0,
            };
            keep_unreaped(&mut ops).unwrap();
            assert_eq!((ops.now, ops.changes), (DEFAULT, 1), "{start:?}");
        }
        let mut ops = Sigchld {
            now: DEFAULT,
            after_change: None,
            changes: 0,
        };
        keep_unreaped(&mut ops).unwrap();
        assert_eq!(ops.changes, 0, "the default is left as it is");
        let ignored = ChildSignal {
            ignored: true,
            no_wait: false,
        };
        let mut refused = Sigchld {
            now: ignored,
            after_change: None,
            changes: 0,
        };
        assert!(keep_unreaped(&mut refused).is_err());
        let mut kept = Sigchld {
            now: ignored,
            after_change: Some(ignored),
            changes: 0,
        };
        assert!(
            keep_unreaped(&mut kept).is_err(),
            "a change that did not hold"
        );
    }

    /// An independent review oracle (cycle 369), adopted: each of the four
    /// setups of the two flags against five behaviours of the system (the
    /// change holds; it does not hold; the first read fails; the second
    /// read fails; the change fails), with the result, the number of reads
    /// and changes, and the setup left written down apart from the code:
    /// twenty cases, seven of them successes. Leave the ignored flag
    /// unchecked, skip the read after the change, or ignore a failed
    /// change, and cases fail.
    #[test]
    fn every_setup_against_every_system_behaviour_gives_the_written_result() {
        struct Sys {
            before: ChildSignal,
            after: ChildSignal,
            scenario: u8,
            reads: usize,
            sets: usize,
        }
        impl SigchldOps for Sys {
            fn read(&mut self) -> io::Result<ChildSignal> {
                self.reads += 1;
                if (self.scenario == 2 && self.reads == 1)
                    || (self.scenario == 3 && self.reads == 2)
                {
                    return Err(io::ErrorKind::Other.into());
                }
                Ok(if self.sets == 0 {
                    self.before
                } else {
                    self.after
                })
            }
            fn stop_reaping_on_its_own(&mut self) -> io::Result<()> {
                self.sets += 1;
                if self.scenario == 4 {
                    return Err(io::ErrorKind::Other.into());
                }
                if self.scenario != 1 {
                    self.after = DEFAULT;
                }
                Ok(())
            }
        }
        let (mut failed, mut successes) = (Vec::new(), 0);
        for bits in 0u8..4 {
            for scenario in 0u8..5 {
                let before = ChildSignal {
                    ignored: bits & 1 != 0,
                    no_wait: bits & 2 != 0,
                };
                let mut sys = Sys {
                    before,
                    after: before,
                    scenario,
                    reads: 0,
                    sets: 0,
                };
                let got = keep_unreaped(&mut sys).map_err(|e| match e.kind() {
                    io::ErrorKind::PermissionDenied => 1,
                    _ => 2,
                });
                let reaps = bits != 0;
                let expected = if scenario == 2 {
                    Err(2)
                } else if !reaps || scenario == 0 {
                    Ok(())
                } else if scenario == 1 {
                    Err(1)
                } else {
                    Err(2)
                };
                let sets = usize::from(reaps && scenario != 2);
                let reads = if reaps && scenario != 2 && scenario != 4 {
                    2
                } else {
                    1
                };
                let left = if reaps && matches!(scenario, 0 | 3) {
                    DEFAULT
                } else {
                    before
                };
                if got != expected || sys.sets != sets || sys.reads != reads || sys.after != left {
                    failed.push(bits * 5 + scenario);
                } else if expected.is_ok() {
                    successes += 1;
                }
            }
        }
        assert!(failed.is_empty(), "cases {failed:?}");
        assert_eq!(successes, 7);
    }

    /// A recording system for a signal sent by number.
    struct Kills {
        auto_reap: bool,
        reaped: bool,
        killed: Vec<(i32, i32)>,
    }

    impl KillOps for Kills {
        fn reaps_on_its_own(&mut self) -> io::Result<bool> {
            Ok(self.auto_reap)
        }
        fn unreaped(&mut self, _pid: i32) -> io::Result<()> {
            if self.reaped {
                return Err(io::Error::from_raw_os_error(libc::ECHILD));
            }
            Ok(())
        }
        fn kill(&mut self, target: i32, sig: i32) -> io::Result<()> {
            self.killed.push((target, sig));
            Ok(())
        }
    }

    /// A signal by number goes to the owned child or the group it leads
    /// only while the number is still its own: not once SIGCHLD reaps on
    /// its own (set ignored after the fork, by another library), and not
    /// once the child was reaped behind the handle's back (`ECHILD`). Drop
    /// either check and the number, perhaps another process's by then, is
    /// signalled.
    #[test]
    fn a_signal_by_number_needs_the_child_unreaped_and_no_reaping_on_its_own() {
        let mut ok = Kills {
            auto_reap: false,
            reaped: false,
            killed: Vec::new(),
        };
        kill_owned(&mut ok, 4242, false, libc::SIGTERM).unwrap();
        kill_owned(&mut ok, 4242, true, libc::SIGKILL).unwrap();
        assert_eq!(
            ok.killed,
            vec![(4242, libc::SIGTERM), (-4242, libc::SIGKILL)]
        );
        for (auto_reap, reaped) in [(true, false), (false, true)] {
            let mut ops = Kills {
                auto_reap,
                reaped,
                killed: Vec::new(),
            };
            for group in [false, true] {
                let err = kill_owned(&mut ops, 4242, group, libc::SIGTERM).unwrap_err();
                assert_eq!(
                    err.raw_os_error(),
                    Some(libc::ECHILD),
                    "{auto_reap} {reaped}"
                );
            }
            assert!(ops.killed.is_empty(), "{:?}", ops.killed);
        }
        let mut ops = Kills {
            auto_reap: false,
            reaped: false,
            killed: Vec::new(),
        };
        for pid in [0, 1, -4242] {
            assert!(kill_owned(&mut ops, pid, true, libc::SIGKILL).is_err());
        }
        assert!(
            ops.killed.is_empty(),
            "kill(0) or kill(-1) reaches everyone"
        );
    }
}
