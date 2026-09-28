//! Processes and their ancestry, as the kernel reports them (SPEC §10a
//! "Caller identity", §10b "Root selection"). `envcloak-policy` turns the
//! chain into caller evidence.
//!
//! - [`proc_info`]: one process: its parent, start time, effective uid,
//!   session, whether it has a controlling terminal, its command name and
//!   its executable. [`proc_argv`] reads its arguments, which the evidence
//!   walk asks for only where it needs them (see below).
//!   - macOS: `sysctl(KERN_PROC_PID)` (`kinfo_proc`), which unlike
//!     `proc_pidinfo(PROC_PIDTBSDINFO)` also answers for processes of other
//!     users (`login`, `launchd`); `getsid`; `proc_pidpath`; and the code
//!     signature the kernel validated at exec (`csops`: signing identifier
//!     and Team ID). Arguments come from `KERN_PROCARGS2`.
//!   - Linux: `/proc/<pid>/stat` and `status`, and `/proc/<pid>/exe` for
//!     the executable's path and its device and inode. A process that made
//!     itself non-dumpable (the EnvCloak CLI does) or belongs to another
//!     user keeps its `exe` from us; its `stat` and `cmdline` stay
//!     readable. Arguments come from `/proc/<pid>/cmdline`.
//! - [`ancestry`]: the chain from a connected peer up to the top of the
//!   process tree, re-validated after the walk. Neither kernel offers a
//!   race-free parent chain (a parent can exit and its pid be reused while
//!   the chain is read), so:
//!   1. the first entry must be the peer the socket reported, with its
//!      start time;
//!   2. every parent must have started no later than its child: a pid
//!      reused after the real parent exited belongs to a newer process;
//!   3. after the walk, and after any arguments were read, every entry is
//!      read again and must still have its start time, parent, session and
//!      terminal. A process lives under one pid until it exits, so an
//!      entry that passes was the same process throughout, and each link
//!      held when it was checked.
//!
//!   A change is [`AncestryError::Changed`]; the caller walks again. A
//!   parent that cannot be read while its child still names it is
//!   [`AncestryError::Hidden`] (Linux `/proc` mounted with `hidepid`):
//!   walking again would not help.
//!
//! Arguments can hold other programs' secrets (`--token=...`), and on macOS
//! `KERN_PROCARGS2` returns the environment after them. So arguments are
//! read only for the processes the caller names, at most [`MAX_ARGV`] of
//! them and [`MAX_ARGV_BYTES`] in all; the rest of the buffer, the
//! environment included, is never parsed and is wiped. Where the arguments
//! start comes from the layout `exec` gives the buffer, not from its
//! contents: an empty argument is a lone NUL, as padding is (see
//! [`parse_procargs2`]). [`ProcInfo`]'s `Debug` prints how many arguments
//! were read, never what they are.

use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

use crate::peer::{PeerIdentity, StartTime};

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

/// How many processes the caller evidence reads at most, the peer
/// included. A deeper chain is cut, and [`reaches_top`] says so: what sits
/// above the cut, an agent included, is not seen, so the evidence built
/// from a cut chain must fail closed (`envcloak-policy` handles it as if an
/// agent may be there).
pub const MAX_ANCESTRY: usize = 64;
/// Arguments kept per process, `argv[0]` included.
pub const MAX_ARGV: usize = 64;
/// Bytes of arguments kept per process, NULs excluded. An argument that
/// would go past it is dropped, with every one after it.
pub const MAX_ARGV_BYTES: usize = 16 * 1024;

/// The code signature a macOS kernel validated when the process started
/// its current executable (`CS_VALID`). Evidence only: an ad hoc signature
/// can carry any identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CodeSignature {
    /// The signing identifier (`com.anthropic.claude-code`, say).
    pub identifier: String,
    /// The Team ID of a Developer ID signature; `None` for ad hoc and
    /// platform signatures.
    pub team_id: Option<String>,
}

/// A process's executable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExeIdentity {
    /// Its path as the kernel reports it: `proc_pidpath` on macOS, the
    /// `/proc/<pid>/exe` link on Linux (which ends in ` (deleted)` when the
    /// file was removed).
    pub path: PathBuf,
    /// Linux: the device and inode of the file the process runs, read
    /// through `/proc/<pid>/exe`. `None` on macOS.
    pub file: Option<(u64, u64)>,
    /// macOS: see [`CodeSignature`]. `None` on Linux and for unsigned or
    /// invalid signatures.
    pub signature: Option<CodeSignature>,
}

/// One process, as the kernel reported it at one moment.
#[derive(Clone, PartialEq, Eq)]
pub struct ProcInfo {
    pub pid: i32,
    /// 0 for the top of the tree.
    pub ppid: i32,
    pub start_time: StartTime,
    /// The effective uid.
    pub uid: u32,
    /// The session id: the pid of the session's leader. `None` when the
    /// kernel would not say.
    pub sid: Option<i32>,
    /// Whether the process's session has a controlling terminal.
    pub controlling_tty: bool,
    /// The command name the kernel keeps (Linux `comm`, macOS `p_comm`):
    /// the start of the executed file's name, at most 16 bytes.
    pub comm: OsString,
    /// `None` when the kernel keeps it from us (another user's process, or
    /// a non-dumpable one on Linux).
    pub exe: Option<ExeIdentity>,
    /// Filled in by [`ancestry`] for the processes its caller names; `None`
    /// otherwise, and when the kernel refused.
    pub argv: Option<Vec<OsString>>,
}

impl core::fmt::Debug for ProcInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProcInfo")
            .field("pid", &self.pid)
            .field("ppid", &self.ppid)
            .field("start_time", &self.start_time)
            .field("uid", &self.uid)
            .field("sid", &self.sid)
            .field("controlling_tty", &self.controlling_tty)
            .field("comm", &self.comm)
            .field("exe", &self.exe)
            .field("argc", &self.argv.as_ref().map(Vec::len))
            .finish()
    }
}

/// Why [`ancestry`] gave no chain. Every variant is value-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AncestryError {
    /// The peer exited, or its pid now belongs to another process.
    PeerGone,
    /// A process in the chain exited, was reparented, or changed its
    /// session or terminal while the chain was read. Walking again sees
    /// the new state.
    Changed,
    /// A parent in the chain exists but the kernel does not show it: its
    /// child still names it after it could not be read. On Linux, `/proc`
    /// mounted with `hidepid=1` or `hidepid=2` hides other users'
    /// processes (`login`, `sshd`, `init`) from the daemon. Walking again
    /// does not help.
    Hidden,
    /// The kernel refused a read that should succeed.
    Io(io::ErrorKind),
}

impl AncestryError {
    /// The fixed message.
    pub fn message(self) -> &'static str {
        match self {
            AncestryError::PeerGone => "the caller exited before its ancestry could be read",
            AncestryError::Changed => "the caller's ancestry changed while it was read",
            AncestryError::Hidden => {
                "a process in the caller's ancestry is hidden from the daemon (Linux: /proc \
                 mounted with hidepid)"
            }
            AncestryError::Io(_) => "the caller's ancestry could not be read",
        }
    }
}

impl core::fmt::Display for AncestryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.message())?;
        if let AncestryError::Io(k) = self {
            write!(f, " ({k})")?;
        }
        Ok(())
    }
}

impl std::error::Error for AncestryError {}

/// Where [`ancestry_in`] reads processes from: [`LiveProcesses`], or a
/// table a test controls.
pub trait ProcessTable {
    /// Process `pid`, without its arguments. [`io::ErrorKind::NotFound`]
    /// when there is none.
    fn info(&mut self, pid: i32) -> io::Result<ProcInfo>;
    /// The arguments of process `pid`, capped as [`proc_argv`] caps them.
    fn argv(&mut self, pid: i32) -> io::Result<Vec<OsString>>;
}

/// The kernel's process table: [`proc_info`] and [`proc_argv`].
#[derive(Debug, Clone, Copy, Default)]
pub struct LiveProcesses;

impl ProcessTable for LiveProcesses {
    fn info(&mut self, pid: i32) -> io::Result<ProcInfo> {
        proc_info(pid)
    }

    fn argv(&mut self, pid: i32) -> io::Result<Vec<OsString>> {
        proc_argv(pid)
    }
}

/// Process `pid` as the kernel reports it now, with `argv` left `None`.
///
/// # Errors
/// [`io::ErrorKind::NotFound`] when there is no such process; others when
/// the kernel refuses.
pub fn proc_info(pid: i32) -> io::Result<ProcInfo> {
    if pid <= 0 {
        return Err(io::ErrorKind::NotFound.into());
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        linux::proc_info(pid)
    }
    #[cfg(target_os = "macos")]
    {
        macos::proc_info(pid)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    {
        Err(io::ErrorKind::Unsupported.into())
    }
}

/// The arguments of process `pid`, `argv[0]` first: at most [`MAX_ARGV`]
/// of them and [`MAX_ARGV_BYTES`] in all. See the module documentation for
/// what is read and wiped.
///
/// # Errors
/// When the kernel refuses (another user's process on macOS, a process
/// that exited) or the arguments are malformed.
pub fn proc_argv(pid: i32) -> io::Result<Vec<OsString>> {
    if pid <= 0 {
        return Err(io::ErrorKind::NotFound.into());
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        linux::proc_argv(pid)
    }
    #[cfg(target_os = "macos")]
    {
        macos::proc_argv(pid)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    {
        Err(io::ErrorKind::Unsupported.into())
    }
}

/// The peer's ancestry from the live process table: [`ancestry_in`] with
/// [`LiveProcesses`].
///
/// # Errors
/// As [`ancestry_in`].
pub fn ancestry(
    peer: &PeerIdentity,
    max_depth: usize,
    want_argv: &dyn Fn(&ProcInfo) -> bool,
) -> Result<Vec<ProcInfo>, AncestryError> {
    ancestry_in(&mut LiveProcesses, peer, max_depth, want_argv)
}

/// The chain from `peer` up to the top of the process tree (a process
/// whose parent is 0), at most `max_depth` processes (at least 1), read
/// from `table` and re-validated as the module documentation describes.
/// `argv` is read for each process `want_argv` selects, before the
/// re-validation; a refused read leaves it `None`. A chain cut at
/// `max_depth` is returned as it is: [`reaches_top`] tells it from a
/// whole one.
///
/// # Errors
/// [`AncestryError::PeerGone`] when the peer is not the process the socket
/// reported, [`AncestryError::Changed`] when the chain changed under the
/// walk, [`AncestryError::Hidden`] when a parent is there but cannot be
/// read, [`AncestryError::Io`] when a read failed otherwise.
pub fn ancestry_in(
    table: &mut dyn ProcessTable,
    peer: &PeerIdentity,
    max_depth: usize,
    want_argv: &dyn Fn(&ProcInfo) -> bool,
) -> Result<Vec<ProcInfo>, AncestryError> {
    let io = |e: io::Error| AncestryError::Io(e.kind());
    let first = match table.info(peer.pid) {
        Ok(p) => p,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(AncestryError::PeerGone),
        Err(e) => return Err(io(e)),
    };
    if first.pid != peer.pid || first.start_time != peer.start_time {
        return Err(AncestryError::PeerGone);
    }
    let mut chain = vec![first];
    while let Some(child) = chain.last() {
        if child.ppid <= 0 || child.ppid == child.pid || chain.len() >= max_depth.max(1) {
            break;
        }
        let parent = match table.info(child.ppid) {
            Ok(p) => p,
            // Either the parent exited after the child was read, or the
            // kernel hides it. A process's children are reparented when it
            // exits, before its entry goes, so reading the child again
            // tells them apart: still naming the parent, the parent is
            // there but hidden.
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
                ) =>
            {
                let (pid, ppid, start) = (child.pid, child.ppid, child.start_time);
                return Err(match table.info(pid) {
                    Ok(again) if again.ppid == ppid && again.start_time == start => {
                        AncestryError::Hidden
                    }
                    Err(e) if e.kind() != io::ErrorKind::NotFound => io(e),
                    Ok(again) if pid == peer.pid && again.start_time != start => {
                        AncestryError::PeerGone
                    }
                    Err(_) if pid == peer.pid => AncestryError::PeerGone,
                    _ => AncestryError::Changed,
                });
            }
            Err(e) => return Err(io(e)),
        };
        if parent.pid != child.ppid || parent.start_time > child.start_time {
            return Err(AncestryError::Changed);
        }
        chain.push(parent);
    }
    for p in &mut chain {
        if want_argv(p) {
            p.argv = table.argv(p.pid).ok();
        }
    }
    for (k, p) in chain.iter().enumerate() {
        let again = match table.info(p.pid) {
            Ok(a) => a,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(if k == 0 {
                    AncestryError::PeerGone
                } else {
                    AncestryError::Changed
                });
            }
            Err(e) => return Err(io(e)),
        };
        if again.start_time != p.start_time
            || again.ppid != p.ppid
            || again.sid != p.sid
            || again.controlling_tty != p.controlling_tty
        {
            return Err(if k == 0 && again.start_time != p.start_time {
                AncestryError::PeerGone
            } else {
                AncestryError::Changed
            });
        }
    }
    Ok(chain)
}

/// Whether `chain`, as [`ancestry_in`] returned it, reaches the top of the
/// process tree: its last process's parent is 0 (`launchd`, `init`, or the
/// top of a pid namespace). A chain cut at its maximum depth does not, nor
/// does an empty one or one that stopped at a process named as its own
/// parent. What is above such a chain is unknown.
pub fn reaches_top(chain: &[ProcInfo]) -> bool {
    chain.last().is_some_and(|p| p.ppid <= 0)
}

/// The fields of a Linux `/proc/<pid>/stat` file the walk uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatFields {
    /// Field 1.
    pub pid: i32,
    /// Field 2, without its parentheses.
    pub comm: Vec<u8>,
    /// Field 4.
    pub ppid: i32,
    /// Field 6.
    pub session: i32,
    /// Field 7: the controlling terminal's device number, 0 for none.
    pub tty_nr: i64,
    /// Field 22, in clock ticks since boot.
    pub start_time: StartTime,
}

/// Parses the contents of a Linux `/proc/<pid>/stat` file. The command name
/// in field 2 is in parentheses and may itself hold spaces and
/// parentheses, so it runs from the first `(` to the last `)`, and the
/// other fields are counted from there. `None` when a field is missing or
/// malformed.
pub fn parse_proc_stat(stat: &[u8]) -> Option<StatFields> {
    let open = stat.iter().position(|b| *b == b'(')?;
    let close = stat.iter().rposition(|b| *b == b')')?;
    if close < open {
        return None;
    }
    let pid = parse_int(std::str::from_utf8(stat.get(..open)?).ok()?.trim_end())?;
    let comm = stat.get(open + 1..close)?.to_vec();
    let rest = std::str::from_utf8(stat.get(close + 1..)?).ok()?;
    let fields: Vec<&str> = rest.split_ascii_whitespace().take(20).collect();
    // `fields[0]` is field 3.
    let field = |n: usize| fields.get(n - 3).copied();
    let start = field(22)?;
    if start.is_empty() || !start.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(StatFields {
        pid: i32::try_from(pid).ok()?,
        comm,
        ppid: i32::try_from(parse_int(field(4)?)?).ok()?,
        session: i32::try_from(parse_int(field(6)?)?).ok()?,
        tty_nr: parse_int(field(7)?)?,
        start_time: StartTime::from_raw(start.parse().ok()?),
    })
}

/// A decimal integer with an optional leading `-`, and nothing else.
fn parse_int(s: &str) -> Option<i64> {
    let digits = s.strip_prefix('-').unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// The effective uid from the contents of a Linux `/proc/<pid>/status`
/// file: the second number on its `Uid:` line (real, effective, saved,
/// filesystem).
pub fn parse_status_euid(status: &[u8]) -> Option<u32> {
    let text = std::str::from_utf8(status).ok()?;
    let line = text.lines().find_map(|l| l.strip_prefix("Uid:"))?;
    let euid = line.split_ascii_whitespace().nth(1)?;
    if !euid.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    euid.parse().ok()
}

/// Splits the contents of a Linux `/proc/<pid>/cmdline` file into
/// arguments: NUL-separated, the last one usually NUL-terminated. A
/// process that rewrote its arguments (to set its title) may leave one
/// string without NULs, which counts as one argument. Capped at
/// [`MAX_ARGV`] arguments and [`MAX_ARGV_BYTES`] bytes; bytes past the
/// cap, or a last argument cut by it, are dropped.
pub fn parse_cmdline(bytes: &[u8]) -> Vec<OsString> {
    let mut args = Vec::new();
    let mut total = 0usize;
    let mut rest = bytes;
    while !rest.is_empty() && args.len() < MAX_ARGV {
        let (arg, next, terminated) = match rest.iter().position(|b| *b == 0) {
            Some(n) => (&rest[..n], &rest[n + 1..], true),
            None => (rest, &rest[rest.len()..], false),
        };
        total = total.saturating_add(arg.len());
        if total > MAX_ARGV_BYTES || (!terminated && bytes.len() > MAX_ARGV_BYTES) {
            break;
        }
        args.push(OsString::from_vec(arg.to_vec()));
        rest = next;
    }
    args
}

/// The alignment `exec` gives the executable's path in a macOS process's
/// string area: the new process's pointer size, 8 for every process
/// current macOS runs (XNU `exec_extract_strings`).
pub const PROCARGS_ALIGN: usize = 8;

/// Parses the buffer macOS `sysctl(KERN_PROCARGS2)` returns: `argc` as a
/// native-endian `int`, then the process's string area as `exec` laid it
/// out (XNU `exec_extract_strings`; `sysctl_procargsx` strips its
/// `executable_path=` key, 16 bytes, a multiple of the alignment): the
/// executable's path and its NUL, NULs up to the next multiple of
/// [`PROCARGS_ALIGN`] bytes from the path's start, then `argc`
/// NUL-terminated arguments, any of which may be empty, then the
/// environment.
///
/// The arguments start where that layout puts them, never at the first
/// byte that is not a NUL: an empty `argv[0]` is a lone NUL too, and
/// skipping it would shift the count into the environment (review finding F-33).
/// Only the arguments are read, at most [`MAX_ARGV`] of them and
/// [`MAX_ARGV_BYTES`] in all; parsing stops there, so no environment
/// string is parsed unless the process rewrote its own argument area.
/// `None` when the padding holds anything but NULs, or the buffer ends
/// before the arguments it announces.
pub fn parse_procargs2(buf: &[u8]) -> Option<Vec<OsString>> {
    let argc = i32::from_ne_bytes(buf.get(..4)?.try_into().ok()?);
    let argc = usize::try_from(argc).ok()?;
    let area = buf.get(4..)?;
    let path_len = area.iter().position(|b| *b == 0)?;
    let mut i = (path_len + 1).checked_next_multiple_of(PROCARGS_ALIGN)?;
    if area.get(path_len..i)?.iter().any(|b| *b != 0) {
        return None;
    }
    let want = argc.min(MAX_ARGV);
    let mut args = Vec::with_capacity(want);
    let mut total = 0usize;
    while args.len() < want {
        let rest = area.get(i..)?;
        let n = rest.iter().position(|b| *b == 0)?;
        total = total.saturating_add(n);
        if total > MAX_ARGV_BYTES {
            break;
        }
        args.push(OsString::from_vec(rest[..n].to_vec()));
        i += n + 1;
    }
    Some(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat_line(comm: &str, tty: &str, start: &str) -> Vec<u8> {
        format!(
            "4242 ({comm}) S 17 4242 4200 {tty} -1 4194304 100 0 0 0 1 2 0 0 20 0 1 0 {start} 1000 200 18446744073709551615\n"
        )
        .into_bytes()
    }

    #[test]
    fn stat_fields_are_counted_after_the_command_name() {
        for comm in ["bash", "a b", "x) S 1 2 3", "((", ")", "sh -c ) 7"] {
            let f = parse_proc_stat(&stat_line(comm, "34816", "987654")).unwrap();
            assert_eq!(f.pid, 4242);
            assert_eq!(f.comm, comm.as_bytes());
            assert_eq!(f.ppid, 17);
            assert_eq!(f.session, 4200);
            assert_eq!(f.tty_nr, 34816);
            assert_eq!(f.start_time, StartTime::from_raw(987_654));
        }
        assert_eq!(
            parse_proc_stat(&stat_line("x", "0", "5")).unwrap().tty_nr,
            0
        );
    }

    #[test]
    fn malformed_stat_files_are_none() {
        assert_eq!(parse_proc_stat(b""), None);
        assert_eq!(parse_proc_stat(b"4242 (x) S 1 2"), None);
        assert_eq!(parse_proc_stat(b"no parenthesis 1 2 3"), None);
        assert_eq!(parse_proc_stat(b"42 )x( S 1 2 3"), None);
        assert_eq!(parse_proc_stat(&stat_line("x", "0", "-5")), None);
        assert_eq!(parse_proc_stat(&stat_line("x", "0", "12a")), None);
        assert_eq!(parse_proc_stat(&stat_line("x", "1a", "12")), None);
        let mut bad_pid = stat_line("x", "0", "1");
        bad_pid[0] = b'z';
        assert_eq!(parse_proc_stat(&bad_pid), None);
    }

    #[test]
    fn the_effective_uid_is_the_second_number() {
        let status = b"Name:\tbash\nUmask:\t0022\nUid:\t1000\t1001\t1002\t1003\nGid:\t5\t5\t5\t5\n";
        assert_eq!(parse_status_euid(status), Some(1001));
        assert_eq!(parse_status_euid(b"Name:\tx\n"), None);
        assert_eq!(parse_status_euid(b"Uid:\t1000\n"), None);
        assert_eq!(parse_status_euid(b"Uid:\t1000\t-1\t0\t0\n"), None);
    }

    #[test]
    fn cmdline_splits_on_nul() {
        let args = parse_cmdline(b"node\0/usr/lib/cli.js\0--flag\0");
        assert_eq!(args, ["node", "/usr/lib/cli.js", "--flag"]);
        assert_eq!(parse_cmdline(b"retitled process"), ["retitled process"]);
        assert_eq!(parse_cmdline(b"a\0\0b\0"), ["a", "", "b"]);
        assert!(parse_cmdline(b"").is_empty());
    }

    #[test]
    fn cmdline_is_capped() {
        let many: Vec<u8> = (0..MAX_ARGV + 10).flat_map(|_| *b"x\0").collect();
        assert_eq!(parse_cmdline(&many).len(), MAX_ARGV);
        let mut long = vec![b'a'; MAX_ARGV_BYTES - 1];
        long.push(0);
        long.extend_from_slice(b"bb\0");
        assert_eq!(
            parse_cmdline(&long).len(),
            1,
            "the argument past the cap is dropped"
        );
        let unterminated = vec![b'a'; MAX_ARGV_BYTES + 5];
        assert!(parse_cmdline(&unterminated).is_empty());
    }

    /// A `KERN_PROCARGS2` buffer laid out as `exec` does: argc, the path,
    /// its NUL and NULs to the next multiple of 8, then the strings.
    fn procargs(argc: i32, path: &[u8], strings: &[&[u8]]) -> Vec<u8> {
        let mut b = argc.to_ne_bytes().to_vec();
        b.extend_from_slice(path);
        b.push(0);
        while (b.len() - 4) % PROCARGS_ALIGN != 0 {
            b.push(0);
        }
        for s in strings {
            b.extend_from_slice(s);
            b.push(0);
        }
        b
    }

    #[test]
    fn procargs2_reads_argc_arguments_and_no_environment() {
        let b = procargs(
            2,
            b"/usr/local/bin/node",
            &[b"node", b"/opt/cli.js", b"HOME=/Users/x", b"PATH=/bin"],
        );
        assert_eq!(parse_procargs2(&b).unwrap(), ["node", "/opt/cli.js"]);
        assert_eq!(
            parse_procargs2(&procargs(0, b"/bin/x", &[b"ENV=1"])).unwrap(),
            Vec::<OsString>::new()
        );
    }

    #[test]
    fn empty_arguments_are_arguments_not_padding() {
        // Review finding F-33: a path whose NUL ends on the alignment, then
        // an empty argv[0]. Skipping NULs read "30" as argv[0] and the
        // environment as argv[1].
        let b = procargs(2, b"/bin/sl", &[b"", b"30", b"ENVMARK=1"]);
        assert_eq!(b.len(), 4 + 8 + 1 + 3 + 10);
        assert_eq!(parse_procargs2(&b).unwrap(), ["", "30"]);
        // Padding before an empty argv[0], and several empty arguments.
        for path in [&b"/bin/x"[..], b"/usr/bin/xargs", b"/bin/sleep", b"/a", b""] {
            let b = procargs(4, path, &[b"", b"", b"", b"z", b"ENVMARK=1"]);
            assert_eq!(parse_procargs2(&b).unwrap(), ["", "", "", "z"]);
        }
    }

    #[test]
    fn padding_that_is_not_nul_is_refused() {
        let mut b = procargs(1, b"/bin/x", &[b"a", b"ENVMARK=1"]);
        // "/bin/x" and its NUL take 7 bytes: one byte of padding.
        assert_eq!(b[4 + 7], 0);
        b[4 + 7] = b'q';
        assert_eq!(parse_procargs2(&b), None);
        // A buffer that ends inside the padding.
        let b = procargs(1, b"/bin/x", &[]);
        assert_eq!(parse_procargs2(&b[..b.len() - 1]), None);
    }

    #[test]
    fn truncated_procargs2_is_none() {
        assert_eq!(parse_procargs2(b""), None);
        assert_eq!(parse_procargs2(&[1, 0, 0]), None);
        assert_eq!(
            parse_procargs2(&procargs(3, b"/bin/x", &[b"a", b"b"])),
            None
        );
        assert_eq!(parse_procargs2(&(-1i32).to_ne_bytes()), None);
        let mut no_path_end = 1i32.to_ne_bytes().to_vec();
        no_path_end.extend_from_slice(b"/bin/x");
        assert_eq!(parse_procargs2(&no_path_end), None);
    }
}
