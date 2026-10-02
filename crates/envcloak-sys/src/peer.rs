//! Who is on the other end of a Unix socket (SPEC §4.2, §4.3).
//!
//! - [`peer_identity`]: the daemon's view of a client at accept: its uid,
//!   pid and start time, read from the kernel's record of the client's end
//!   of the socket.
//!   - macOS: the audit token (`LOCAL_PEERTOKEN`), which carries the uid,
//!     the pid and the pid version of the last process to use the client's
//!     socket (to connect, send or receive on it; the socket's
//!     `last_pid`), not of the one that connected. A process the
//!     descriptor passed to (across `fork`, or sent over another socket)
//!     becomes the peer by using it, and the peer can change after the
//!     accept: [`peer_unchanged`] reads it again. A descriptor held only
//!     by a process that never used it, after the one that connected
//!     exited, names no process: the token cannot be read and the peer is
//!     refused.
//!   - Linux 6.5 and later: `SO_PEERCRED` for the uid and pid, and
//!     `SO_PEERPIDFD`, a pidfd for the connecting process. The pidfd keeps
//!     the pid from being reused while the process lives, so a start time
//!     read while it still lives is that process's. Whether the kernel has
//!     `SO_PEERPIDFD` is found once, on a socket pair of this process's
//!     own; after that, every error for a real peer refuses it and none is
//!     taken for an older kernel. A peer that was reaped before the accept
//!     gets `EINVAL` from kernels 6.5 to about 6.15, and a pidfd that is
//!     already readable from later ones: both refuse it, without reading
//!     `/proc/<pid>/stat` for a pid another process may hold by then.
//!   - Linux before 6.5: `SO_PEERCRED` alone. A process whose start time is
//!     later than the accept cannot have connected, so it is refused. A
//!     narrow race remains: the peer exits and its pid is reused between
//!     its `connect` and the daemon's `accept`.
//!   - macOS reads the start time with `proc_pidinfo` and refuses a
//!     process that started after the accept, as the Linux fallback does.
//! - [`peer_unchanged`]: whether the kernel still names the process
//!   [`peer_identity`] reported. On macOS the daemon asks before each
//!   request and closes a connection another process is now using. Linux
//!   keeps the connecting process for the socket's life, whoever holds the
//!   descriptor; a process it was passed to acts as the one that
//!   connected, which can do the same itself.
//! - [`peer_uid`]: the client's view of the server, before it sends
//!   anything (SPEC §4.2): `getpeereid` on macOS, `SO_PEERCRED` on Linux.
//! - [`process_start_time`]: when a process started, as the kernel records
//!   it.
//!
//! The `testing` feature can force the `SO_PEERCRED` fallback on Linux
//! kernels that have `SO_PEERPIDFD`, so both paths are tested, and can make
//! a pid look reused by an older process, so the race above is tested.

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

/// The process at the client's end of a socket, as the kernel reported it
/// when the daemon asked (at accept): on Linux the one that connected, on
/// macOS the last one to use the socket (see the module documentation).
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

/// Whether the kernel still names `peer` at the other end of the socket
/// `fd`, as [`peer_identity`] reported it at accept: macOS reads the audit
/// token again (the last process to use the client's socket) and compares
/// its uid, pid and pid version; Linux compares `SO_PEERCRED`, which names
/// the connecting process for the socket's life.
///
/// # Errors
/// When the kernel does not report the peer: its end is closed, or the
/// last process to use it has exited.
pub fn peer_unchanged(fd: BorrowedFd<'_>, peer: &PeerIdentity) -> io::Result<bool> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        linux::peer_cred(fd).map(|c| c.pid == peer.pid && c.uid == peer.uid)
    }
    #[cfg(target_os = "macos")]
    {
        macos::audit_token(fd).map(|(uid, pid, pidversion)| {
            pid == peer.pid && uid == peer.uid && Some(pidversion) == peer.pidversion
        })
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    {
        let _ = (fd, peer);
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

/// The id of the running boot, so a process instance recorded in one boot
/// is never taken for a process of a later one. Linux: the UUID the kernel
/// makes at each boot (`/proc/sys/kernel/random/boot_id`), as 16 bytes; a
/// start time there counts clock ticks since boot, which a process of a
/// later boot can have again under the same pid. `None` elsewhere: on
/// macOS a start time is the wall clock's, in microseconds, and so tells
/// boots apart itself.
///
/// # Errors
/// Linux: when the file cannot be read or does not hold a UUID.
pub fn boot_id() -> io::Result<Option<[u8; 16]>> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let text = std::fs::read("/proc/sys/kernel/random/boot_id")?;
        parse_boot_id(&text)
            .map(Some)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "a malformed boot id"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        Ok(None)
    }
}

/// Parses a boot id as Linux writes it: 32 hex digits in the UUID's
/// groups (`8-4-4-4-12`), then a newline or nothing. `None` for anything
/// else.
pub fn parse_boot_id(text: &[u8]) -> Option<[u8; 16]> {
    let text = text.strip_suffix(b"\n").unwrap_or(text);
    if text.len() != 36 || [8, 13, 18, 23].iter().any(|&i| text[i] != b'-') {
        return None;
    }
    let digit = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    };
    let mut nibbles = text.iter().filter(|b| **b != b'-');
    let mut out = [0u8; 16];
    for byte in &mut out {
        let hi = digit(*nibbles.next()?)?;
        let lo = digit(*nibbles.next()?)?;
        *byte = hi << 4 | lo;
    }
    Some(out)
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

#[cfg(all(feature = "testing", any(target_os = "linux", target_os = "android")))]
fn pretended_start_time(pid: i32) -> Option<StartTime> {
    crate::testing::pretended_start_time(pid)
}

#[cfg(all(
    not(feature = "testing"),
    any(target_os = "linux", target_os = "android")
))]
fn pretended_start_time(_pid: i32) -> Option<StartTime> {
    None
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux {
    use std::io;
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
    use std::os::unix::net::UnixStream;
    use std::sync::OnceLock;

    use super::{
        PeerIdentity, PeerSource, StartTime, parse_stat_start_time, peer_gone, pretended_start_time,
    };

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

    /// `SO_PEERPIDFD` on the socket `fd`, with the kernel's error as is.
    fn getsockopt_pidfd(fd: BorrowedFd<'_>) -> io::Result<OwnedFd> {
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
            return Err(io::Error::last_os_error());
        }
        if pidfd < 0 || len as usize != size_of::<libc::c_int>() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the kernel reported no pidfd",
            ));
        }
        // SAFETY: the kernel just created `pidfd` for this process, which
        // owns it and nothing else does.
        Ok(unsafe { OwnedFd::from_raw_fd(pidfd) })
    }

    /// Whether this kernel has `SO_PEERPIDFD` (Linux 6.5), asked once of a
    /// socket pair whose peer is this live process, so only an unknown
    /// option (`ENOPROTOOPT`) can say no. Any other error is returned and
    /// asked again next time.
    fn pidfd_supported() -> io::Result<bool> {
        static SUPPORTED: OnceLock<bool> = OnceLock::new();
        if let Some(s) = SUPPORTED.get() {
            return Ok(*s);
        }
        let (ours, _theirs) = UnixStream::pair()?;
        let supported = match getsockopt_pidfd(ours.as_fd()) {
            Ok(_pidfd) => true,
            Err(e) if e.raw_os_error() == Some(libc::ENOPROTOOPT) => false,
            Err(e) => return Err(e),
        };
        Ok(*SUPPORTED.get_or_init(|| supported))
    }

    /// The peer's pidfd, on a kernel that has `SO_PEERPIDFD`. The errors a
    /// peer that is gone gives are [`peer_gone`]: `EINVAL` when it was
    /// reaped (kernels 6.5 to about 6.15), `ESRCH`, `ENODATA` when the
    /// socket has no peer process, and `ENOTCONN`. None of them means an
    /// older kernel.
    fn peer_pidfd(fd: BorrowedFd<'_>) -> io::Result<OwnedFd> {
        getsockopt_pidfd(fd).map_err(|e| match e.raw_os_error() {
            Some(libc::EINVAL | libc::ESRCH | libc::ENODATA | libc::ENOTCONN) => peer_gone(),
            _ => e,
        })
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
        if let Some(start) = pretended_start_time(pid) {
            return Ok(start);
        }
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
        let pidfd = if super::fallback_forced() || !pidfd_supported()? {
            None
        } else {
            Some(peer_pidfd(fd)?)
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

    /// The uid, pid and pid version in the socket's audit token: the last
    /// process to use the client's end (see the module documentation).
    pub(super) fn audit_token(fd: BorrowedFd<'_>) -> io::Result<(u32, i32, i32)> {
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
        Ok((uid, pid, pidversion))
    }

    pub(super) fn peer_identity(fd: BorrowedFd<'_>) -> io::Result<PeerIdentity> {
        let accepted = wall_micros();
        let (uid, pid, pidversion) = audit_token(fd)?;
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
    use super::{StartTime, boot_id, parse_boot_id, parse_stat_start_time};

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

    #[test]
    fn boot_ids_parse_only_as_linux_writes_them() {
        let want = [
            0x5c, 0x0f, 0x2a, 0x91, 0x7e, 0x34, 0x4b, 0x1d, 0x9a, 0x02, 0xc4, 0x8e, 0x61, 0x3f,
            0xd0, 0x7b,
        ];
        for text in [
            &b"5c0f2a91-7e34-4b1d-9a02-c48e613fd07b\n"[..],
            b"5c0f2a91-7e34-4b1d-9a02-c48e613fd07b",
            b"5C0F2A91-7E34-4B1D-9A02-C48E613FD07B\n",
        ] {
            assert_eq!(parse_boot_id(text), Some(want));
        }
        for text in [
            &b""[..],
            b"\n",
            b"5c0f2a917e344b1d9a02c48e613fd07b",
            b"5c0f2a91-7e34-4b1d-9a02-c48e613fd07",
            b"5c0f2a91-7e34-4b1d-9a02-c48e613fd07bb",
            b"5c0f2a91-7e34-4b1d-9a02-c48e613fd07g",
            b"5c0f2a91+7e34-4b1d-9a02-c48e613fd07b",
            b"5c0f2a91-7e34-4b1d-9a02-c48e613fd07b\n\n",
            b"\xff\xfe",
        ] {
            assert_eq!(parse_boot_id(text), None, "{text:?}");
        }
        // The running boot's id reads, and twice the same.
        let now = boot_id().unwrap();
        assert_eq!(now, boot_id().unwrap());
        assert_eq!(
            now.is_some(),
            cfg!(any(target_os = "linux", target_os = "android"))
        );
    }
}
