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
//! This is the part of the owned-handle API the PTY monitor needs
//! (`crate::pty`, M2 task M2-17): the CLI's handle on the monitor it
//! forks. M2 task M2-27 extends it (spawning through `Command`, its
//! `ProcessOps` seam and the clippy ban on `kill` elsewhere).
//!
//! `OwnedSession` (Linux) is D-34's one bounded exception, for the PTY
//! monitor's session: it signals the processes of the session the monitor
//! leads that are in the slave's foreground process group, each through a
//! pidfd of its own, verified after its session and group were read. A
//! process enters a session only by being created in it (`setsid` makes a
//! new one; `setpgid` moves a process only within its own), and the
//! monitor's pid, which is the session's id, cannot be reused while the
//! monitor is unreaped, so the authority comes from the owned session,
//! never from a number: the foreground group number read from the terminal
//! (`TIOCGPGRP`) only selects among processes already shown to be in that
//! session.

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
    /// has waited for. On Linux a pidfd is opened at once, while the child
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
    /// and reaps it only through [`OwnedChild::reap`]). Allocates nothing.
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

    /// Sends `sig` to the child.
    ///
    /// # Errors
    /// `ESRCH` when the child has exited and the kernel says so (Linux),
    /// and the other errors of `pidfd_send_signal` or `kill`.
    pub fn signal(&self, sig: i32) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        if let Some(fd) = &self.pidfd {
            return pidfd_send_signal(fd.as_raw_fd(), sig);
        }
        // SAFETY: kill has no memory effects; the child is unreaped, so
        // `pid` names it.
        if unsafe { libc::kill(self.pid, sig) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Sends `sig` to the process group the child leads. Only a child that
    /// leads its group (one that called `setsid` or `setpgid(0, 0)`) has
    /// one; the group's number is the child's pid, which cannot be reused
    /// while the child is unreaped.
    ///
    /// # Errors
    /// `ESRCH` when the group is empty, and `kill`'s other errors.
    pub fn signal_group(&self, sig: i32) -> io::Result<()> {
        // SAFETY: kill has no memory effects; `-pid` names the group the
        // unreaped child leads.
        if unsafe { libc::kill(-self.pid, sig) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
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
    /// A handle on the process that has `pid` now; `None` when there is
    /// none.
    fn open(&mut self, pid: i32) -> Option<Self::Handle>;
    /// The session and process group of the process that has `pid` now
    /// (read by pid, so possibly another process than the handle's).
    fn ids(&mut self, pid: i32) -> Option<(i32, i32)>;
    /// Whether the process the handle names has not exited. When it has
    /// not, the pid read before named it.
    fn alive(&mut self, handle: &Self::Handle) -> bool;
    /// Sends `sig` through the handle.
    fn send(&mut self, handle: &Self::Handle, sig: i32) -> io::Result<()>;
}

/// Signals, through its own handle, every process of `table` whose session
/// is `session` and whose process group is `foreground`, except the
/// session's leader itself; returns how many. A process's ids are read
/// after its handle was taken and trusted only if the handle's process
/// still lives afterwards. A `foreground` equal to `session` (the leader's
/// own group: the monitor took the terminal back) or below 2 selects
/// nothing.
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
    let mut sent = 0usize;
    for pid in table.pids()? {
        if pid == session {
            continue;
        }
        let Some(handle) = table.open(pid) else {
            continue;
        };
        let Some((sid, pgrp)) = table.ids(pid) else {
            continue;
        };
        if !table.alive(&handle) {
            // Exited since the handle was taken: what was read may belong
            // to a process that took the pid after it.
            continue;
        }
        if sid != session || pgrp != foreground {
            continue;
        }
        match table.send(&handle, sig) {
            Ok(()) => sent += 1,
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(sent)
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
    /// `master` (`TIOCGPGRP`), each through a pidfd verified after its
    /// session and group were read, and never to the monitor itself.
    /// Returns how many processes were signalled.
    ///
    /// # Errors
    /// When the foreground group cannot be read, `/proc` cannot be listed,
    /// or a signal fails for another reason than the process having
    /// exited.
    pub fn signal_foreground(&self, master: BorrowedFd<'_>, sig: i32) -> io::Result<usize> {
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

    fn open(&mut self, pid: i32) -> Option<OwnedFd> {
        pidfd_open(pid).ok()
    }

    fn ids(&mut self, pid: i32) -> Option<(i32, i32)> {
        let stat = std::fs::read(format!("/proc/{pid}/stat")).ok()?;
        let f = crate::parse_proc_stat(&stat)?;
        (f.pid == pid).then_some((f.session, f.pgrp))
    }

    fn alive(&mut self, handle: &OwnedFd) -> bool {
        let mut p = libc::pollfd {
            fd: handle.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `p` is one initialized pollfd; a zero timeout only looks.
        // A pidfd is readable once its process has exited.
        let rc = unsafe { libc::poll(&mut p, 1, 0) };
        rc == 0
    }

    fn send(&mut self, handle: &OwnedFd, sig: i32) -> io::Result<()> {
        pidfd_send_signal(handle.as_raw_fd(), sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    /// A process in the model table: its session and group as `/proc`
    /// shows them when read, and whether its handle shows it exited by
    /// the time it is checked.
    #[derive(Clone, Copy)]
    struct Proc {
        sid: i32,
        pgrp: i32,
        exits_before_check: bool,
    }

    #[derive(Default)]
    struct Model {
        procs: BTreeMap<i32, Proc>,
        signalled: Vec<(i32, i32)>,
        opened: BTreeSet<i32>,
    }

    impl SessionTable for Model {
        type Handle = i32;
        fn pids(&mut self) -> io::Result<Vec<i32>> {
            Ok(self.procs.keys().copied().collect())
        }
        fn open(&mut self, pid: i32) -> Option<i32> {
            self.procs.contains_key(&pid).then(|| {
                self.opened.insert(pid);
                pid
            })
        }
        fn ids(&mut self, pid: i32) -> Option<(i32, i32)> {
            self.procs.get(&pid).map(|p| (p.sid, p.pgrp))
        }
        fn alive(&mut self, h: &i32) -> bool {
            self.procs.get(h).is_some_and(|p| !p.exits_before_check)
        }
        fn send(&mut self, h: &i32, sig: i32) -> io::Result<()> {
            assert!(self.opened.contains(h), "signalled without a handle");
            self.signalled.push((*h, sig));
            Ok(())
        }
    }

    const MONITOR: i32 = 500;
    const SHELL: i32 = 501;
    const JOB: i32 = 510;

    fn table() -> Model {
        let p = |sid, pgrp| Proc {
            sid,
            pgrp,
            exits_before_check: false,
        };
        let mut m = Model::default();
        m.procs.insert(MONITOR, p(MONITOR, MONITOR));
        m.procs.insert(SHELL, p(MONITOR, SHELL));
        m.procs.insert(JOB, p(MONITOR, JOB));
        m.procs.insert(JOB + 1, p(MONITOR, JOB));
        m
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
            vec![(JOB, libc::SIGTERM), (JOB + 1, libc::SIGTERM)]
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
        m.procs.insert(
            outside,
            Proc {
                sid: 899,
                pgrp: JOB,
                exits_before_check: false,
            },
        );
        let left = 901;
        m.procs.insert(
            left,
            Proc {
                sid: left,
                pgrp: JOB,
                exits_before_check: false,
            },
        );
        deliver_in_session(&mut m, MONITOR, JOB, libc::SIGHUP).unwrap();
        let hit: BTreeSet<i32> = m.signalled.iter().map(|(p, _)| *p).collect();
        assert!(!hit.contains(&outside), "outside the session: {hit:?}");
        assert!(!hit.contains(&left), "left the session: {hit:?}");
        assert_eq!(hit, BTreeSet::from([JOB, JOB + 1]));
    }

    /// A process whose handle shows it exited between the `/proc` read and
    /// the liveness check is skipped: its pid may be another process's by
    /// then, and what was read may be that one's.
    #[test]
    fn a_process_that_exits_between_the_read_and_the_check_is_skipped() {
        let mut m = table();
        m.procs.get_mut(&JOB).unwrap().exits_before_check = true;
        let n = deliver_in_session(&mut m, MONITOR, JOB, libc::SIGTERM).unwrap();
        assert_eq!(n, 1);
        assert_eq!(m.signalled, vec![(JOB + 1, libc::SIGTERM)]);
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
}
