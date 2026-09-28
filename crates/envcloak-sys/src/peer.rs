//! Who is on the other end of a Unix socket (SPEC §4.2, §4.3).
//!
//! - [`peer_identity`]: the daemon's view of a client at accept: its uid,
//!   pid and start time, read from handles the kernel ties to the process
//!   that connected.
//!   - macOS: the audit token (`LOCAL_PEERTOKEN`), which carries the uid,
//!     the pid and the pid version of the connecting process.
//!   - Linux 6.5 and later: `SO_PEERCRED` for the uid and pid, and
//!     `SO_PEERPIDFD`, a pidfd for the connecting process. The pidfd keeps
//!     the pid from being reused while the process lives, so a start time
//!     read while it still lives is that process's.
//!   - Linux before 6.5: `SO_PEERCRED` alone. A process whose start time is
//!     later than the accept cannot have connected, so it is refused. A
//!     narrow race remains: the peer exits and its pid is reused between
//!     its `connect` and the daemon's `accept`.
//!   - macOS reads the start time with `proc_pidinfo` and refuses a
//!     process that started after the accept, as the Linux fallback does.
//! - [`peer_uid`]: the client's view of the server, before it sends
//!   anything (SPEC §4.2): `getpeereid` on macOS, `SO_PEERCRED` on Linux.
//! - [`process_start_time`]: when a process started, as the kernel records
//!   it.
//!
//! The `testing` feature can force the `SO_PEERCRED` fallback on Linux
//! kernels that have `SO_PEERPIDFD`, so both paths are tested.

use std::io;
#[cfg(target_os = "macos")]
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;

/// When a process started, as the kernel records it. Two start times
/// compare meaningfully only on the same machine and boot.
///
/// macOS: microseconds since the Unix epoch (`pbi_start_tvsec` and
/// `pbi_start_tvusec`). Linux: clock ticks since boot (field 22 of
/// `/proc/<pid>/stat`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StartTime(u64);

impl StartTime {
    /// The kernel's value, in the units described on [`StartTime`].
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// A start time from a raw kernel value, for callers that read one
    /// themselves and for tests.
    pub const fn from_raw(v: u64) -> Self {
        StartTime(v)
    }
}

/// Which kernel interface identified a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerSource {
    /// macOS `LOCAL_PEERTOKEN`.
    AuditToken,
    /// Linux `SO_PEERCRED` plus `SO_PEERPIDFD`.
    PidFd,
    /// Linux `SO_PEERCRED` alone, checked against the time of the accept.
    PeerCred,
}

/// The process that connected to a socket, as the kernel saw it at
/// `connect`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerIdentity {
    /// Its effective uid.
    pub uid: u32,
    pub pid: i32,
    pub start_time: StartTime,
    /// macOS: the pid version from the audit token, which changes when a
    /// pid is reused. `None` on Linux.
    pub pidversion: Option<i32>,
    pub source: PeerSource,
}

/// The error for a peer that exited, or whose pid was reused, before its
/// identity could be read.
fn peer_gone() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        "the peer process exited before its identity could be read",
    )
}

/// Identifies the process that connected to the socket `fd`. Call it
/// right after `accept`: the Linux fallback and macOS refuse a process that
/// started after the call began.
///
/// # Errors
/// When the kernel does not report the peer, or the peer exited (or its
/// pid was reused) before its start time could be read, which is
/// [`io::ErrorKind::NotFound`].
pub fn peer_identity(fd: BorrowedFd<'_>) -> io::Result<PeerIdentity> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        linux::peer_identity(fd)
    }
    #[cfg(target_os = "macos")]
    {
        macos::peer_identity(fd)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    {
        let _ = fd;
        Err(io::ErrorKind::Unsupported.into())
    }
}

/// The effective uid of the process at the other end of the connected
/// socket `fd`, as it was when the socket was bound or connected.
///
/// # Errors
/// When the kernel does not report it.
pub fn peer_uid(fd: BorrowedFd<'_>) -> io::Result<u32> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        linux::peer_cred(fd).map(|c| c.uid)
    }
    #[cfg(target_os = "macos")]
    {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        // SAFETY: both out-pointers are valid, writable locals; the socket
        // stays open for the call.
        if unsafe { libc::getpeereid(fd.as_raw_fd(), &mut uid, &mut gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(uid)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    {
        let _ = fd;
        Err(io::ErrorKind::Unsupported.into())
    }
}

/// When process `pid` started.
///
/// # Errors
/// [`io::ErrorKind::NotFound`] when there is no such process.
pub fn process_start_time(pid: i32) -> io::Result<StartTime> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        linux::start_time(pid)
    }
    #[cfg(target_os = "macos")]
    {
        macos::start_time(pid)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    {
        let _ = pid;
        Err(io::ErrorKind::Unsupported.into())
    }
}

/// Parses the start time (field 22, in clock ticks since boot) from the
/// contents of a Linux `/proc/<pid>/stat` file. The command name in field
/// 2 is in parentheses and may itself hold spaces and parentheses, so the
/// fields are counted from the last `)`. Returns `None` when the field is
/// missing or malformed.
pub fn parse_stat_start_time(stat: &[u8]) -> Option<StartTime> {
    let close = stat.iter().rposition(|b| *b == b')')?;
    let rest = std::str::from_utf8(stat.get(close + 1..)?).ok()?;
    // Fields after the command: state (3), ppid (4), ... starttime (22).
    let field = rest.split_ascii_whitespace().nth(22 - 3)?;
    if field.is_empty() || !field.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    field.parse().ok().map(StartTime)
}

#[cfg(all(feature = "testing", any(target_os = "linux", target_os = "android")))]
fn fallback_forced() -> bool {
    crate::testing::peercred_fallback_forced()
}

#[cfg(all(
    not(feature = "testing"),
    any(target_os = "linux", target_os = "android")
))]
fn fallback_forced() -> bool {
    false
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux {
    use std::io;
    use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

    use super::{PeerIdentity, PeerSource, StartTime, parse_stat_start_time, peer_gone};

    /// Slack, in clock ticks, for rounding between the boot clock and the
    /// kernel's start time.
    const TICK_SLACK: u64 = 2;

    pub(super) fn peer_cred(fd: BorrowedFd<'_>) -> io::Result<libc::ucred> {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: `cred` is a writable ucred and `len` its size; the socket
        // stays open for the call.
        let rc = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&raw mut cred).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            let err = io::Error::last_os_error();
            return Err(if err.raw_os_error() == Some(libc::ENOTCONN) {
                peer_gone()
            } else {
                err
            });
        }
        if len as usize != size_of::<libc::ucred>() || cred.pid <= 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the kernel reported no peer credentials",
            ));
        }
        Ok(cred)
    }

    /// The peer's pidfd, or `None` on kernels without `SO_PEERPIDFD`.
    fn peer_pidfd(fd: BorrowedFd<'_>) -> io::Result<Option<OwnedFd>> {
        let mut pidfd: libc::c_int = -1;
        let mut len = size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `pidfd` is a writable int and `len` its size; the socket
        // stays open for the call.
        let rc = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERPIDFD,
                (&raw mut pidfd).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            let err = io::Error::last_os_error();
            return match err.raw_os_error() {
                Some(libc::ENOPROTOOPT) | Some(libc::EINVAL) => Ok(None),
                // The peer has already been reaped.
                Some(libc::ESRCH) | Some(libc::ENOTCONN) => Err(peer_gone()),
                _ => Err(err),
            };
        }
        if pidfd < 0 {
            return Ok(None);
        }
        // SAFETY: the kernel just created `pidfd` for this process, which
        // owns it and nothing else does.
        Ok(Some(unsafe { OwnedFd::from_raw_fd(pidfd) }))
    }

    /// Whether the process `pidfd` refers to is still running: its pidfd
    /// becomes readable when it exits.
    fn pidfd_alive(pidfd: &OwnedFd) -> io::Result<bool> {
        let mut p = libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            // SAFETY: one valid pollfd; a zero timeout never blocks.
            let n = unsafe { libc::poll(&mut p, 1, 0) };
            if n >= 0 {
                return Ok(n == 0);
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }

    /// The boot clock (`CLOCK_BOOTTIME`) in clock ticks, the unit of
    /// `/proc/<pid>/stat` start times.
    fn boot_ticks() -> io::Result<u64> {
        let now = crate::clock::read_clock(libc::CLOCK_BOOTTIME)?;
        // SAFETY: sysconf has no preconditions.
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        let hz = u64::try_from(hz)
            .ok()
            .filter(|h| *h > 0)
            .ok_or_else(|| io::Error::other("no clock tick rate"))?;
        let ticks = now
            .as_secs()
            .saturating_mul(hz)
            .saturating_add(u64::from(now.subsec_nanos()) * hz / 1_000_000_000);
        Ok(ticks)
    }

    pub(super) fn start_time(pid: i32) -> io::Result<StartTime> {
        let stat = match std::fs::read(format!("/proc/{pid}/stat")) {
            Ok(s) => s,
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => return Err(peer_gone()),
            Err(e) => return Err(e),
        };
        parse_stat_start_time(&stat).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "a malformed /proc stat file")
        })
    }

    pub(super) fn peer_identity(fd: BorrowedFd<'_>) -> io::Result<PeerIdentity> {
        let accepted = boot_ticks()?;
        let cred = peer_cred(fd)?;
        let pidfd = if super::fallback_forced() {
            None
        } else {
            peer_pidfd(fd)?
        };
        let start = match start_time(cred.pid) {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(peer_gone()),
            Err(e) => return Err(e),
        };
        // Either way, a process that started after the accept is not the
        // one that connected.
        if start.raw() > accepted.saturating_add(TICK_SLACK) {
            return Err(peer_gone());
        }
        let source = match pidfd {
            Some(pidfd) => {
                // The pidfd pins the connecting process: while it lives, its
                // pid is not reused, so the start time just read is its own.
                if !pidfd_alive(&pidfd)? {
                    return Err(peer_gone());
                }
                PeerSource::PidFd
            }
            None => PeerSource::PeerCred,
        };
        Ok(PeerIdentity {
            uid: cred.uid,
            pid: cred.pid,
            start_time: start,
            pidversion: None,
            source,
        })
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::io;
    use std::os::fd::{AsRawFd, BorrowedFd};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{PeerIdentity, PeerSource, StartTime, peer_gone};

    /// `audit_token_t` from `<bsm/audit.h>`: eight 32-bit words.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct AuditToken {
        val: [u32; 8],
    }

    #[link(name = "bsm")]
    unsafe extern "C" {
        // <bsm/libbsm.h>
        fn audit_token_to_euid(token: AuditToken) -> libc::uid_t;
        fn audit_token_to_pid(token: AuditToken) -> libc::pid_t;
        fn audit_token_to_pidversion(token: AuditToken) -> libc::c_int;
    }

    /// Slack for the wall clock the kernel records start times with.
    const SLACK_MICROS: u64 = 2_000_000;

    fn wall_micros() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    }

    pub(super) fn start_time(pid: i32) -> io::Result<StartTime> {
        // SAFETY: proc_bsdinfo is plain old data; all zeros is valid.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = size_of::<libc::proc_bsdinfo>() as libc::c_int;
        // SAFETY: `info` is writable for `size` bytes.
        let n = unsafe {
            libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size)
        };
        if n != size {
            let err = io::Error::last_os_error();
            return Err(match err.raw_os_error() {
                Some(libc::ESRCH) | Some(0) | None => peer_gone(),
                _ => err,
            });
        }
        if i64::from(info.pbi_pid) != i64::from(pid) {
            return Err(peer_gone());
        }
        let micros = info
            .pbi_start_tvsec
            .saturating_mul(1_000_000)
            .saturating_add(info.pbi_start_tvusec);
        Ok(StartTime(micros))
    }

    pub(super) fn peer_identity(fd: BorrowedFd<'_>) -> io::Result<PeerIdentity> {
        let accepted = wall_micros();
        let mut token = AuditToken { val: [0; 8] };
        let mut len = size_of::<AuditToken>() as libc::socklen_t;
        // SAFETY: `token` is writable for `len` bytes; the socket stays
        // open for the call.
        let rc = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_LOCAL,
                libc::LOCAL_PEERTOKEN,
                (&raw mut token).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            let err = io::Error::last_os_error();
            // The peer closed its end: it may already be gone.
            return Err(if err.raw_os_error() == Some(libc::ENOTCONN) {
                peer_gone()
            } else {
                err
            });
        }
        if len as usize != size_of::<AuditToken>() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the kernel reported no audit token",
            ));
        }
        // SAFETY: the token is a plain value the kernel filled in; these
        // functions only read its words.
        let (uid, pid, pidversion) = unsafe {
            (
                audit_token_to_euid(token),
                audit_token_to_pid(token),
                audit_token_to_pidversion(token),
            )
        };
        if pid <= 0 {
            return Err(peer_gone());
        }
        let start = start_time(pid)?;
        if start.raw() > accepted.saturating_add(SLACK_MICROS) {
            return Err(peer_gone());
        }
        Ok(PeerIdentity {
            uid,
            pid,
            start_time: start,
            pidversion: Some(pidversion),
            source: PeerSource::AuditToken,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{StartTime, parse_stat_start_time};

    fn stat_line(comm: &str, start: &str) -> Vec<u8> {
        // pid (comm) state ppid pgrp session tty tpgid flags minflt cminflt
        // majflt cmajflt utime stime cutime cstime priority nice threads
        // itrealvalue starttime vsize ...
        format!("4242 ({comm}) S 1 4242 4242 0 -1 4194304 100 0 0 0 1 2 0 0 20 0 1 0 {start} 1000 200 18446744073709551615\n")
            .into_bytes()
    }

    #[test]
    fn start_time_is_field_22() {
        assert_eq!(
            parse_stat_start_time(&stat_line("envcloak", "987654")),
            Some(StartTime::from_raw(987_654))
        );
    }

    #[test]
    fn command_names_with_spaces_and_parentheses_are_skipped() {
        for comm in ["a b", "x) S 1 2 3", "((", ")", "sh -c ) 7"] {
            assert_eq!(
                parse_stat_start_time(&stat_line(comm, "55")),
                Some(StartTime::from_raw(55)),
                "{comm:?}"
            );
        }
    }

    #[test]
    fn malformed_stat_files_are_none() {
        assert_eq!(parse_stat_start_time(b""), None);
        assert_eq!(parse_stat_start_time(b"4242 (x) S 1 2"), None);
        assert_eq!(parse_stat_start_time(&stat_line("x", "-5")), None);
        assert_eq!(parse_stat_start_time(&stat_line("x", "12a")), None);
        assert_eq!(
            parse_stat_start_time(&stat_line("x", "99999999999999999999999")),
            None
        );
        assert_eq!(parse_stat_start_time(b"no parenthesis at all 1 2 3"), None);
    }
}
