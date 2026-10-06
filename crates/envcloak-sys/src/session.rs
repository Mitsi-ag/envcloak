//! A child that leads a session of its own, with a terminal of its own:
//! how `envcloak agents status --probe` starts the agent host it probes and
//! the probe's own daemon (M2 plan task M2-28).
//!
//! [`new_session_on_spawn`] makes a [`std::process::Command`]'s child call
//! `setsid` before its program starts, so it leads a new session and a new
//! process group, both numbered by its pid, and, given a terminal (a PTY's
//! slave side, [`crate::pty::open_pty`]), take it as that session's
//! controlling terminal (`TIOCSCTTY`). Its standard streams stay as the
//! command sets them.
//!
//! Two things follow, and the probe rests on both:
//!
//! - nothing the child or its descendants do shares a session or a
//!   controlling terminal with the process that started it, so an approval
//!   given from that process's terminal is never one from the child's
//!   (SPEC §10b, T9-3: an approval from the session or the terminal of a
//!   request's chain is refused);
//! - when the last descriptor of the PTY's master side is closed (the
//!   starter exits, however it ends, `kill -9` included, and the master is
//!   close-on-exec, so no other program holds it) while the terminal is
//!   open in the session, the kernel hangs the terminal up and sends SIGHUP
//!   to the session's leader, the child: a lifeline that needs nothing from
//!   the child's program. The terminal must be open there: macOS sends
//!   nothing for a terminal no process has open (measured on macOS 26.4),
//!   so a child that is to have the lifeline gets the slave side as one of
//!   its standard streams.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::process::Command;

/// Makes `cmd`'s child lead a new session (`setsid`) before its program
/// starts and, with `terminal`, take that terminal as the session's
/// controlling terminal (`TIOCSCTTY`). `cmd` keeps its own copy of
/// `terminal`, made now with `F_DUPFD_CLOEXEC` and closed with `cmd`, so the
/// child takes this terminal whatever becomes of the number here before the
/// spawn (the rule of [`crate::inherit_on_spawn`]); the copy is
/// close-on-exec, so the child's program does not hold it open.
///
/// The child must not lead a process group already: `setsid` refuses a
/// group leader, so `cmd` must not also call `process_group`. A child that
/// cannot make the session or take the terminal is not started: the spawn
/// fails with that error.
///
/// # Errors
/// When the copy of `terminal` cannot be made.
pub fn new_session_on_spawn(cmd: &mut Command, terminal: Option<BorrowedFd<'_>>) -> io::Result<()> {
    use std::os::unix::process::CommandExt;
    let copy = match terminal {
        Some(t) => Some(crate::inherited_fd(t.as_raw_fd())?),
        None => None,
    };
    let lead = move || {
        // SAFETY: setsid has no preconditions; in a child of fork it makes
        // the child a new session's leader, or fails (EPERM for a group
        // leader) without effect. It is async-signal-safe.
        if unsafe { libc::setsid() } < 0 {
            return Err(io::Error::last_os_error());
        }
        if let Some(t) = &copy {
            // SAFETY: TIOCSCTTY with 0 on `t`, a descriptor the fork copied
            // into this child, which now leads a session without a
            // controlling terminal: the terminal becomes the session's, or
            // the call fails without effect (another session's terminal is
            // refused, the 0 never steals it). ioctl is async-signal-safe,
            // and nothing here allocates or takes a lock.
            if unsafe { libc::ioctl(t.as_raw_fd(), libc::TIOCSCTTY as _, 0) } < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    };
    // SAFETY: the closure runs in the child after the fork and before its
    // program starts, where a child forked from a threaded parent may call
    // only async-signal-safe functions: it calls `setsid` and `ioctl`, and
    // `last_os_error` only reads errno.
    unsafe { cmd.pre_exec(lead) };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    /// The session of process `pid` (`getsid`) and its terminal's name, as
    /// `ps` reports it (macOS's `ps` has no session column it fills).
    fn session_and_tty(pid: u32) -> (i32, String) {
        let id = libc::pid_t::try_from(pid).unwrap();
        // SAFETY: getsid only reads the kernel's record of a process.
        let sid = unsafe { libc::getsid(id) };
        assert!(sid > 0, "{}", io::Error::last_os_error());
        let out = Command::new("/bin/ps")
            .args(["-o", "tty=", "-p", &pid.to_string()])
            .output()
            .unwrap();
        let tty = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        (sid, tty)
    }

    /// `/bin/sh` waiting on a pipe nobody writes, in a session of its own,
    /// on `terminal` when given.
    fn waiting_shell(terminal: Option<BorrowedFd<'_>>) -> std::process::Child {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "read _ || :"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        new_session_on_spawn(&mut cmd, terminal).unwrap();
        cmd.spawn().unwrap()
    }

    /// Whether `ps` names no terminal: `?` on Linux, `??` on macOS.
    fn no_tty(tty: &str) -> bool {
        tty == "?" || tty == "??"
    }

    /// The child leads a session of its own, on the PTY given, apart from
    /// this process's session and terminal; without a terminal, the
    /// session has none. Mutation checked: the `setsid` call taken out
    /// (and with it the terminal, which only a session leader can take):
    /// the child is in this process's session and the session assertion
    /// fails.
    #[test]
    fn the_child_leads_a_session_on_its_own_terminal() {
        let pty = crate::pty::open_pty(None, None).unwrap();
        let mut child = waiting_shell(Some(pty.slave.as_fd()));
        let (sid, tty) = session_and_tty(child.id());
        let (own_sid, own_tty) = session_and_tty(std::process::id());
        drop(child.stdin.take());
        assert!(child.wait().unwrap().success());
        assert_eq!(
            u32::try_from(sid).unwrap(),
            child.id(),
            "the child leads its session"
        );
        assert_ne!(sid, own_sid);
        assert!(!no_tty(&tty) && !tty.is_empty(), "{tty}");
        assert_ne!(tty, own_tty);

        let mut child = waiting_shell(None);
        let (sid, tty) = session_and_tty(child.id());
        drop(child.stdin.take());
        assert!(child.wait().unwrap().success());
        assert_eq!(u32::try_from(sid).unwrap(), child.id());
        assert!(no_tty(&tty), "no terminal: {tty}");
    }

    /// Closing the PTY's master side, as the starter's exit does, hangs the
    /// session up: its leader, which has the slave side as its standard
    /// input, gets SIGHUP and ends. Mutation checked: the `TIOCSCTTY` call
    /// taken out: the session has no terminal to hang up, the shell gets
    /// only the end of its input, and it exits 0 without the signal.
    #[test]
    fn closing_the_master_hangs_the_session_up() {
        let crate::pty::Pty { master, slave } = crate::pty::open_pty(None, None).unwrap();
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "read _ || :"])
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        new_session_on_spawn(&mut cmd, Some(slave.as_fd())).unwrap();
        let mut child = cmd.spawn().unwrap();
        drop(cmd);
        drop(slave);
        drop(master);
        let end = Instant::now() + Duration::from_secs(20);
        let status = loop {
            if let Some(s) = child.try_wait().unwrap() {
                break Some(s);
            }
            if Instant::now() > end {
                break None;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let Some(status) = status else {
            // Still this test's own unreaped child.
            let _ = child.kill();
            let _ = child.wait();
            panic!("the session's leader outlived its terminal's master side");
        };
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(libc::SIGHUP), "{status:?}");
    }

    /// A child that already leads a process group cannot make a session:
    /// the spawn fails, rather than start it in the starter's session.
    #[test]
    fn a_group_leader_is_not_started() {
        use std::os::unix::process::CommandExt as _;
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "exit 0"]).process_group(0);
        new_session_on_spawn(&mut cmd, None).unwrap();
        let err = cmd.spawn().unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EPERM), "{err}");
    }
}
