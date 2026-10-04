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
//! A process whose SIGCHLD is ignored (`SIG_IGN`, inherited across `exec`
//! from whatever started it) or set with `SA_NOCLDWAIT` has its children
//! reaped by the kernel the moment they exit, and their numbers are free
//! for reuse at once (POSIX `wait`; review cycle 365). So
//! [`keep_children_unreaped`] runs before every fork that makes an
//! `OwnedChild` (it gives SIGCHLD its default action back, or refuses),
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
//! monitor's session: it signals the processes of the session the monitor
//! leads that are in the slave's foreground process group, each through a
//! pidfd of its own, opened before its session and group are read and
//! checked to be alive after. A process enters a session only by being
//! created in it (`setsid` makes a new one; `setpgid` moves a process only
//! within its own), and the monitor's pid, which is the session's id,
//! cannot be reused while the monitor is unreaped, so the authority comes
//! from the owned session, never from a number: the foreground group
//! number read from the terminal (`TIOCGPGRP`) only selects among
//! processes already shown to be in that session.

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
    // SAFETY: pidfd_send_signal with a null siginfo and no flags sends
    // `sig` as kill would, to the process `pidfd` refers to.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd,
            sig,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// What `OwnedSession` reads and does, so a recording model can stand in
/// for the process table in tests: the candidate pids, a handle (a pidfd)
/// per process, each process's session and group, whether the process a
/// handle names still lives, and a signal through a handle.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) trait SessionTable {
    type Handle;
    /// Every pid that may be in the session.
    fn pids(&mut self) -> io::Result<Vec<i32>>;
    /// A handle on the process that has `pid` now; `Ok(None)` when no
    /// process has it (`ESRCH`).
    fn open(&mut self, pid: i32) -> io::Result<Option<Self::Handle>>;
    /// The session and process group of the process that has `pid` now
    /// (read by pid, so possibly another process than a handle taken
    /// before); `Ok(None)` when no process has it.
    fn ids(&mut self, pid: i32) -> io::Result<Option<(i32, i32)>>;
    /// Whether the process the handle names has not exited. While it has
    /// not, its pid was not given to another, so what was read by pid in
    /// between was its own.
    fn alive(&mut self, handle: &Self::Handle) -> io::Result<bool>;
    /// Sends `sig` through the handle.
    fn send(&mut self, handle: &Self::Handle, sig: i32) -> io::Result<()>;
}

/// A session-scoped delivery that failed for some processes of the
/// foreground job (and may have reached others): an error, never a
/// success (lesson L-08). The error that carries it has the kind of the
/// first failure.
#[derive(Debug)]
pub struct PartialDelivery {
    /// The processes the signal was sent to.
    pub signalled: usize,
    /// The processes it could not be sent to, or that could not be
    /// checked.
    pub failed: usize,
    /// The first failure.
    pub first: io::Error,
}

impl core::fmt::Display for PartialDelivery {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "the signal was sent to {} process(es) of the terminal's foreground job and failed \
             for {}: {}",
            self.signalled, self.failed, self.first
        )
    }
}

impl std::error::Error for PartialDelivery {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.first)
    }
}

/// Signals, through its own handle, every process of `table` whose session
/// is `session` and whose process group is `foreground`, except the
/// session's leader itself; returns how many. For each candidate pid, in
/// this order: a handle is opened, the ids are read by pid, and the
/// handle's process is checked to be alive, so the ids read were that
/// process's (a pid is not reused while its process lives). A
/// `foreground` equal to `session` (the leader's own group: the monitor
/// took the terminal back) or below 2 selects nothing.
///
/// Every candidate is tried. A failure (a handle that cannot be opened, ids
/// that cannot be read, a liveness check or a send that fails for another
/// reason than the process having gone) does not stop the others; the
/// result is then an error carrying [`PartialDelivery`]. A system without
/// `pidfd_open` (`ENOSYS`) is that error itself, before anything is sent.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn deliver_in_session<T: SessionTable>(
    table: &mut T,
    session: i32,
    foreground: i32,
    sig: i32,
) -> io::Result<usize> {
    if session < 2 || foreground < 2 || foreground == session {
        return Ok(0);
    }
    let mut signalled = 0usize;
    let mut failed = 0usize;
    let mut first: Option<io::Error> = None;
    let mut fail = |e: io::Error, failed: &mut usize| {
        *failed += 1;
        first.get_or_insert(e);
    };
    for pid in table.pids()? {
        if pid == session || pid < 2 {
            continue;
        }
        let handle = match table.open(pid) {
            Ok(Some(handle)) => handle,
            // No process has the pid any more.
            Ok(None) => continue,
            Err(e) if e.raw_os_error() == Some(libc::ENOSYS) && signalled == 0 && failed == 0 => {
                return Err(e);
            }
            Err(e) => {
                fail(e, &mut failed);
                continue;
            }
        };
        let ids = table.ids(pid);
        match table.alive(&handle) {
            Ok(true) => {}
            // Exited since the handle was taken: what was read may belong
            // to a process that took the pid after it.
            Ok(false) => continue,
            Err(e) => {
                fail(e, &mut failed);
                continue;
            }
        }
        let (sid, pgrp) = match ids {
            Ok(Some(ids)) => ids,
            // Gone between the read and the check cannot be: it is alive.
            Ok(None) => {
                fail(io::ErrorKind::NotFound.into(), &mut failed);
                continue;
            }
            Err(e) => {
                fail(e, &mut failed);
                continue;
            }
        };
        if sid != session || pgrp != foreground {
            continue;
        }
        match table.send(&handle, sig) {
            Ok(()) => signalled += 1,
            // Exited since the check.
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {}
            Err(e) => fail(e, &mut failed),
        }
    }
    match first {
        None => Ok(signalled),
        Some(first) => Err(io::Error::new(
            first.kind(),
            PartialDelivery {
                signalled,
                failed,
                first,
            },
        )),
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

#[cfg(target_os = "linux")]
impl<'a> OwnedSession<'a> {
    /// The session `monitor` leads. The monitor called `setsid`, so its
    /// pid is the session's id, and while the handle is unreaped (it is
    /// borrowed here, so it is) no other session can have that id.
    pub fn from_monitor(monitor: &'a OwnedChild) -> Self {
        OwnedSession { monitor }
    }

    /// Sends `sig` to every process of the session that is in the
    /// foreground process group of the terminal whose master side is
    /// `master` (`TIOCGPGRP`), each through a pidfd opened before its
    /// session and group were read and checked to be alive after, and
    /// never to the monitor itself. Returns how many processes were
    /// signalled.
    ///
    /// # Errors
    /// When the foreground group cannot be read or `/proc` cannot be
    /// listed; `ENOSYS` (kind `Unsupported`) when the kernel has no
    /// `pidfd_open`, before anything is sent; `ECHILD` when the monitor is
    /// no longer this process's own unreaped child; otherwise an error
    /// carrying [`PartialDelivery`] once every candidate was tried, when a
    /// process could not be checked or signalled.
    pub fn signal_foreground(&self, master: BorrowedFd<'_>, sig: i32) -> io::Result<usize> {
        // The session's id is the monitor's pid only while the monitor is
        // unreaped (the borrow says it is not reaped through its handle;
        // this says nothing else reaped it).
        if SysSigchld.read()?.reaps_on_its_own() {
            return Err(io::Error::from_raw_os_error(libc::ECHILD));
        }
        crate::has_exited(self.monitor.pid)?;
        let mut pgrp: libc::pid_t = 0;
        // SAFETY: TIOCGPGRP writes one pid_t into `pgrp`; on a PTY's
        // master side it reports the slave's foreground group.
        if unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCGPGRP as _, &mut pgrp) } != 0 {
            return Err(io::Error::last_os_error());
        }
        deliver_in_session(&mut ProcTable, self.monitor.pid, pgrp, sig)
    }
}

/// The live process table: `/proc`, pidfds.
#[cfg(target_os = "linux")]
struct ProcTable;

#[cfg(target_os = "linux")]
impl SessionTable for ProcTable {
    type Handle = OwnedFd;

    fn pids(&mut self) -> io::Result<Vec<i32>> {
        let mut pids = Vec::new();
        for entry in std::fs::read_dir("/proc")? {
            let name = entry?.file_name();
            if let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) {
                pids.push(pid);
            }
        }
        Ok(pids)
    }

    fn open(&mut self, pid: i32) -> io::Result<Option<OwnedFd>> {
        match pidfd_open(pid) {
            Ok(fd) => Ok(Some(fd)),
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn ids(&mut self, pid: i32) -> io::Result<Option<(i32, i32)>> {
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
        Ok(Some((f.session, f.pgrp)))
    }

    fn alive(&mut self, handle: &OwnedFd) -> io::Result<bool> {
        loop {
            let mut p = libc::pollfd {
                fd: handle.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: `p` is one initialized pollfd; a zero timeout only
            // looks. A pidfd is readable once its process has exited.
            let rc = unsafe { libc::poll(&mut p, 1, 0) };
            if rc == 0 {
                return Ok(true);
            }
            if rc > 0 {
                if p.revents & libc::POLLNVAL != 0 {
                    return Err(io::ErrorKind::InvalidInput.into());
                }
                // POLLIN (exited) or POLLHUP (reaped).
                return Ok(false);
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }

    fn send(&mut self, handle: &OwnedFd, sig: i32) -> io::Result<()> {
        pidfd_send_signal(handle.as_raw_fd(), sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    /// One process in the model table: its session and group as `/proc`
    /// shows them, and whether it still lives.
    #[derive(Clone, Copy, Debug)]
    struct Proc {
        sid: i32,
        pgrp: i32,
        alive: bool,
    }

    /// What happens to a pid's process right after the model answers a
    /// call about it (the race the order of calls must survive).
    #[derive(Clone, Copy, Debug)]
    enum Then {
        /// The process exits and another one takes its pid at once.
        Reused(Proc),
        /// The process exits; nothing takes the pid.
        Exits,
    }

    /// When the event fires: after the first call that touches the pid, or
    /// after the `ids` read.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum After {
        FirstTouch,
        IdsRead,
    }

    /// A process table where a pid can name one process after another:
    /// each pid has a list of incarnations, the last one current. A handle
    /// names the incarnation that was current when it was opened; `ids`
    /// reads the current one; `alive` reports on the handle's.
    #[derive(Default)]
    struct Model {
        procs: BTreeMap<i32, Vec<Proc>>,
        events: BTreeMap<i32, (After, Then)>,
        touched: BTreeSet<i32>,
        /// (pid, incarnation, signal) for every signal sent.
        signalled: Vec<(i32, usize, i32)>,
        /// Failures to inject: `open` or `send` for a pid returns this
        /// errno.
        open_errors: BTreeMap<i32, i32>,
        send_errors: BTreeMap<i32, i32>,
        alive_errors: BTreeSet<i32>,
        ids_errors: BTreeSet<i32>,
    }

    impl Model {
        fn insert(&mut self, pid: i32, sid: i32, pgrp: i32) {
            self.procs.insert(
                pid,
                vec![Proc {
                    sid,
                    pgrp,
                    alive: true,
                }],
            );
        }

        fn fire(&mut self, pid: i32, when: After) {
            let first = self.touched.insert(pid);
            let due = match self.events.get(&pid) {
                Some((After::FirstTouch, _)) => first,
                Some((After::IdsRead, _)) => when == After::IdsRead,
                None => false,
            };
            if !due {
                return;
            }
            let Some((_, then)) = self.events.remove(&pid) else {
                return;
            };
            let list = self.procs.get_mut(&pid).unwrap();
            list.last_mut().unwrap().alive = false;
            if let Then::Reused(next) = then {
                list.push(next);
            }
        }

        fn current(&self, pid: i32) -> Option<(usize, Proc)> {
            let list = self.procs.get(&pid)?;
            let p = *list.last()?;
            p.alive.then(|| (list.len() - 1, p))
        }

        /// The processes signalled: (pid, incarnation).
        fn hit(&self) -> BTreeSet<(i32, usize)> {
            self.signalled.iter().map(|(p, i, _)| (*p, *i)).collect()
        }
    }

    impl SessionTable for Model {
        type Handle = (i32, usize);
        fn pids(&mut self) -> io::Result<Vec<i32>> {
            Ok(self.procs.keys().copied().collect())
        }
        fn open(&mut self, pid: i32) -> io::Result<Option<(i32, usize)>> {
            if let Some(e) = self.open_errors.get(&pid) {
                return Err(io::Error::from_raw_os_error(*e));
            }
            let handle = self.current(pid).map(|(i, _)| (pid, i));
            self.fire(pid, After::FirstTouch);
            Ok(handle)
        }
        fn ids(&mut self, pid: i32) -> io::Result<Option<(i32, i32)>> {
            if self.ids_errors.contains(&pid) {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let ids = self.current(pid).map(|(_, p)| (p.sid, p.pgrp));
            self.fire(pid, After::FirstTouch);
            self.fire(pid, After::IdsRead);
            Ok(ids)
        }
        fn alive(&mut self, h: &(i32, usize)) -> io::Result<bool> {
            if self.alive_errors.contains(&h.0) {
                return Err(io::Error::from_raw_os_error(libc::EBADF));
            }
            Ok(self.procs[&h.0][h.1].alive)
        }
        fn send(&mut self, h: &(i32, usize), sig: i32) -> io::Result<()> {
            if let Some(e) = self.send_errors.get(&h.0) {
                return Err(io::Error::from_raw_os_error(*e));
            }
            // A process that exited but is not reaped takes a signal
            // without complaint, as a zombie does: recorded all the same.
            self.signalled.push((h.0, h.1, sig));
            Ok(())
        }
    }

    const MONITOR: i32 = 500;
    const SHELL: i32 = 501;
    const JOB: i32 = 510;

    fn table() -> Model {
        let mut m = Model::default();
        m.insert(MONITOR, MONITOR, MONITOR);
        m.insert(SHELL, MONITOR, SHELL);
        m.insert(JOB, MONITOR, JOB);
        m.insert(JOB + 1, MONITOR, JOB);
        m
    }

    fn partial(e: &io::Error) -> &PartialDelivery {
        e.get_ref()
            .and_then(|inner| inner.downcast_ref::<PartialDelivery>())
            .unwrap_or_else(|| panic!("not a partial delivery: {e:?}"))
    }

    /// Only the session's members in the foreground group are signalled,
    /// each through its own handle: the job's two processes, not the
    /// nested shell and not the monitor.
    #[test]
    fn the_foreground_job_of_the_session_and_nothing_else_is_signalled() {
        let mut m = table();
        let n = deliver_in_session(&mut m, MONITOR, JOB, libc::SIGTERM).unwrap();
        assert_eq!(n, 2);
        assert_eq!(
            m.signalled,
            vec![(JOB, 0, libc::SIGTERM), (JOB + 1, 0, libc::SIGTERM)]
        );
    }

    /// A process outside the monitor's session that reports the same
    /// group number gets nothing, nor does a process that left the session
    /// with `setsid` (its session is its own now, its group number too or
    /// one that matches).
    #[test]
    fn a_process_outside_the_session_with_the_same_group_number_gets_nothing() {
        let mut m = table();
        let outside = 900;
        m.insert(outside, 899, JOB);
        let left = 901;
        m.insert(left, left, JOB);
        deliver_in_session(&mut m, MONITOR, JOB, libc::SIGHUP).unwrap();
        let hit = m.hit();
        assert!(!hit.contains(&(outside, 0)), "outside the session: {hit:?}");
        assert!(!hit.contains(&(left, 0)), "left the session: {hit:?}");
        assert_eq!(hit, BTreeSet::from([(JOB, 0), (JOB + 1, 0)]));
    }

    /// The job's process exits right after the first call about its pid,
    /// and a process outside the session with the same group number takes
    /// the pid. It gets nothing: the handle was opened on the job's
    /// process before its ids were read, so the ids read are the
    /// newcomer's (outside the session) and the handle's process is dead.
    /// Read the ids before opening the handle and the newcomer is
    /// signalled (the mutation this test is for).
    #[test]
    fn a_pid_reused_by_an_outsider_between_the_calls_is_never_signalled() {
        let mut m = table();
        let outsider = Proc {
            sid: 899,
            pgrp: JOB,
            alive: true,
        };
        m.events
            .insert(JOB, (After::FirstTouch, Then::Reused(outsider)));
        let n = deliver_in_session(&mut m, MONITOR, JOB, libc::SIGTERM).unwrap();
        assert!(
            !m.hit().contains(&(JOB, 1)),
            "the process that took the pid was signalled: {:?}",
            m.signalled
        );
        assert_eq!(m.hit(), BTreeSet::from([(JOB + 1, 0)]));
        assert_eq!(n, 1);
    }

    /// A process whose handle shows it exited between the `/proc` read and
    /// the liveness check is skipped: its pid may be another process's by
    /// then, and what was read may be that one's. Skip the check and the
    /// exited process is counted (and, had the pid been reused before the
    /// read, the ids would be another's).
    #[test]
    fn a_process_that_exits_between_the_read_and_the_check_is_skipped() {
        let mut m = table();
        m.events.insert(JOB, (After::IdsRead, Then::Exits));
        let n = deliver_in_session(&mut m, MONITOR, JOB, libc::SIGTERM).unwrap();
        assert_eq!(n, 1);
        assert_eq!(m.signalled, vec![(JOB + 1, 0, libc::SIGTERM)]);
    }

    /// The monitor's own group (it took the terminal back while the command
    /// is stopped) and nonsense group numbers select nothing.
    #[test]
    fn the_monitors_own_group_and_bad_numbers_select_nothing() {
        for fg in [MONITOR, 0, 1, -JOB] {
            let mut m = table();
            assert_eq!(deliver_in_session(&mut m, MONITOR, fg, 15).unwrap(), 0);
            assert!(m.signalled.is_empty(), "{fg}");
        }
    }

    /// A member the signal cannot be sent to (`EPERM`: a setuid program's
    /// process in the job) comes before a permitted one: the permitted one
    /// is still signalled, and the delivery is an error that says one was
    /// signalled and one failed, never a success. Stop at the first error
    /// and the permitted member gets nothing.
    #[test]
    fn a_refused_member_does_not_stop_the_others_and_the_result_is_an_error() {
        let mut m = table();
        m.send_errors.insert(JOB, libc::EPERM);
        let err = deliver_in_session(&mut m, MONITOR, JOB, libc::SIGTERM).unwrap_err();
        assert_eq!(m.signalled, vec![(JOB + 1, 0, libc::SIGTERM)]);
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        let p = partial(&err);
        assert_eq!((p.signalled, p.failed), (1, 1), "{p}");
        assert_eq!(p.first.raw_os_error(), Some(libc::EPERM));
    }

    /// A kernel without `pidfd_open` (`ENOSYS`, before Linux 5.3): an
    /// `Unsupported` error before anything is sent, not "sent to 0
    /// processes", so the caller can narrow the signal or report it.
    #[test]
    fn no_pidfd_open_is_an_error_not_a_delivery_to_nobody() {
        let mut m = table();
        for pid in [MONITOR, SHELL, JOB, JOB + 1] {
            m.open_errors.insert(pid, libc::ENOSYS);
        }
        let err = deliver_in_session(&mut m, MONITOR, JOB, libc::SIGHUP).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported, "{err:?}");
        assert_eq!(err.raw_os_error(), Some(libc::ENOSYS));
        assert!(m.signalled.is_empty());
    }

    /// A candidate that cannot be checked (a handle that cannot be opened
    /// for another reason, a liveness check or a `/proc` read that fails)
    /// is a failure in the result, never skipped as if it were not in the
    /// job; the others are still signalled.
    #[test]
    fn a_candidate_that_cannot_be_checked_is_a_failure_not_a_skip() {
        for inject in 0..3 {
            let mut m = table();
            match inject {
                0 => {
                    m.open_errors.insert(JOB, libc::EMFILE);
                }
                1 => {
                    m.alive_errors.insert(JOB);
                }
                _ => {
                    m.ids_errors.insert(JOB);
                }
            }
            let err = deliver_in_session(&mut m, MONITOR, JOB, libc::SIGTERM).unwrap_err();
            let p = partial(&err);
            assert_eq!((p.signalled, p.failed), (1, 1), "case {inject}: {p}");
            assert_eq!(m.signalled, vec![(JOB + 1, 0, libc::SIGTERM)], "{inject}");
        }
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
