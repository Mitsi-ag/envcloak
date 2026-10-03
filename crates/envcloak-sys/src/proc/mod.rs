//! Processes and their ancestry, as the kernel reports them (SPEC §10a
//! "Caller identity", §10b "Root selection"). `envcloak-policy` turns the
//! chain into caller evidence.
//!
//! - [`proc_info`]: one process: its parent, start time, effective uid,
//!   session, its controlling terminal's device (if its session has one),
//!   its command name and its executable. [`proc_argv`] reads its
//!   arguments, which the evidence walk asks for only where it needs them
//!   (see below).
//!   - macOS: `sysctl(KERN_PROC_PID)` (`kinfo_proc`), which unlike
//!     `proc_pidinfo(PROC_PIDTBSDINFO)` also answers for processes of other
//!     users (`login`, `launchd`); `getsid`; `proc_pidpath`; and the code
//!     signature the kernel validated at exec (`csops`: signing identifier,
//!     Team ID and cdhash). Arguments come from `KERN_PROCARGS2`.
//!   - Linux: `/proc/<pid>/stat` and `status`, and `/proc/<pid>/exe` for
//!     the executable's path and its device and inode; [`open_exe`] opens
//!     that file itself, for its SHA-256 (the daemon hashes it). A process
//!     that made itself non-dumpable (the EnvCloak CLI does) or belongs to
//!     another user keeps its `exe` from us; its `stat` and `cmdline` stay
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
//! Arguments can hold other programs' secrets (`--token=...`), so they are
//! read only for the processes the caller names, at most [`MAX_ARGV`] of
//! them and [`MAX_ARGV_BYTES`] in all, and they are held in an [`Argv`]:
//! storage wiped on drop, which lends them for comparison and is never
//! copied out as owned strings. [`ProcInfo`]'s and [`Argv`]'s `Debug` print
//! how many arguments were read, never what they are, and every error is
//! fixed text.
//!
//! Neither kernel keeps a boundary between a process's arguments and its
//! environment that the process cannot move, and each lays the environment
//! right after the arguments:
//!
//! - macOS `KERN_PROCARGS2` returns the executable's path, the arguments
//!   and the environment as they are now in the process's memory, with the
//!   argument count `exec` saved. The arguments start where `exec` put
//!   them, not at the first byte that is not a NUL (an empty argument is a
//!   lone NUL, as padding is; see [`parse_procargs2`]), and the count ends
//!   them. A process that rewrote its argument area and removed the NULs
//!   between its arguments (node's `process.title` does, over a short
//!   command line) makes that count run on into its environment: those
//!   strings are then read as arguments (review finding F-38). They stay
//!   in the wiped storage, and the rest of the buffer is wiped unparsed.
//! - Linux `/proc/<pid>/cmdline` runs on into the environment, up to its
//!   first NUL, when the process overwrote the NUL that ends its argument
//!   area (the kernel takes that for `setproctitle`). So no more than the
//!   area's length is read, from the kernel's own record of where it
//!   starts and ends (`stat` fields 48 and 49, which only a privileged
//!   `prctl(PR_SET_MM)` moves). The kernel shows that record only to a
//!   reader that may trace the process: for a non-dumpable one (the
//!   EnvCloak CLI) or another user's, the cap alone bounds the read.
//!
//! [`MAX_ARGV`] keeps only what the agent catalog looks at, so a rewritten
//! argument area hands over as few environment strings as it can.

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use zeroize::Zeroizing;

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
/// Arguments kept per process: `argv[0]` and the 16 after it, all that
/// the agent catalog looks at (docs/AGENTS.md: an interpreter's script is
/// among the first 16 arguments after `argv[0]`). Each one more could be an
/// environment string of a process that rewrote its argument area (see
/// the module documentation).
pub const MAX_ARGV: usize = 17;
/// Bytes of arguments kept per process, NULs excluded. An argument that
/// would go past it is dropped, with every one after it.
pub const MAX_ARGV_BYTES: usize = 16 * 1024;

/// Bytes in a macOS code directory hash (`CS_CDHASH_LEN`).
pub const CDHASH_LEN: usize = 20;

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
    /// The code directory hash (cdhash) of the running executable, which
    /// names its exact build (SPEC §6.1): the kernel's own record, so it
    /// is the file the process runs even when the file on disk changed.
    /// `None` when the kernel would not say.
    pub cdhash: Option<[u8; CDHASH_LEN]>,
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
    /// Linux: the SHA-256 of the file the process runs (SPEC §6.1 step 3),
    /// read through a descriptor of that file ([`open_exe`]), never its
    /// path. [`proc_info`] leaves it `None`: hashing is the daemon's, with
    /// a cache and a budget (M2 plan D-09; docs/AGENTS.md "The executable's
    /// SHA-256"), and `None` there means the identity is unknown. Always
    /// `None` on macOS, where the code signature's cdhash names the build.
    pub sha256: Option<[u8; 32]>,
    /// macOS: see [`CodeSignature`]. `None` on Linux and for unsigned or
    /// invalid signatures.
    pub signature: Option<CodeSignature>,
}

/// One state of a file, as `fstat` shows it: its device, inode, size and
/// change time (seconds, nanoseconds). The executable hash cache is keyed
/// by it (M2 plan D-09). No program can set a change time, and every
/// write, truncation, link or permission change moves it once the file
/// system's clock has moved past the file's last change
/// ([`crate::wait_for_clock_past`]); a rename over the path gives another
/// inode. The modification time is left out: a program can put it back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileKey {
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub ctime: (i64, i64),
}

impl FileKey {
    /// The key of the open file `f` now (`fstat`).
    ///
    /// # Errors
    /// When `fstat` fails.
    pub fn of(f: &std::fs::File) -> io::Result<FileKey> {
        use std::os::unix::fs::MetadataExt;
        let m = f.metadata()?;
        Ok(FileKey {
            dev: m.dev(),
            ino: m.ino(),
            size: m.size(),
            ctime: (m.ctime(), m.ctime_nsec()),
        })
    }
}

/// Opens, read-only and close-on-exec, the file process `pid` runs: on
/// Linux through `/proc/<pid>/exe`, which opens the file itself, even when
/// it was renamed or removed since the process started it. The kernel
/// allows it only to a reader that may trace the process, so not for
/// another user's process or a non-dumpable one (the EnvCloak CLI).
///
/// # Errors
/// [`io::ErrorKind::NotFound`] when there is no such process; others when
/// the kernel refuses; [`io::ErrorKind::Unsupported`] on macOS, where the
/// code signature's cdhash names the build.
pub fn open_exe(pid: i32) -> io::Result<std::fs::File> {
    if pid <= 0 {
        return Err(io::ErrorKind::NotFound.into());
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        linux::open_exe(pid)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        Err(io::ErrorKind::Unsupported.into())
    }
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
    /// The device of the process's controlling terminal (Linux `tty_nr`,
    /// macOS `e_tdev`), `None` when its session has none. Processes on one
    /// terminal have the same device: the daemon compares an approver's
    /// with the requester's (docs/GRANTS.md "Approval").
    pub controlling_tty: Option<u64>,
    /// The command name the kernel keeps (Linux `comm`, macOS `p_comm`):
    /// the start of the executed file's name, at most 16 bytes.
    pub comm: OsString,
    /// `None` when the kernel keeps it from us (another user's process, or
    /// a non-dumpable one on Linux).
    pub exe: Option<ExeIdentity>,
    /// Filled in by [`ancestry`] for the processes its caller names; `None`
    /// otherwise, and when the kernel refused.
    pub argv: Option<Argv>,
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
            .field("argc", &self.argv.as_ref().map(Argv::len))
            .finish()
    }
}

/// A process's arguments, `argv[0]` first, as [`proc_argv`] read them: at
/// most [`MAX_ARGV`] of them and [`MAX_ARGV_BYTES`] in all.
///
/// They can hold other programs' secrets, and a process that rewrote its
/// argument area can have its environment read among them (see the module
/// documentation). So their bytes live in one buffer allocated at its final
/// size and wiped when it is dropped; [`Argv::get`] and [`Argv::iter`] lend
/// them for comparison, nothing copies them out as owned strings, and
/// `Debug` prints only how many there are.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Argv {
    /// The arguments' bytes, one after another.
    bytes: Zeroizing<Vec<u8>>,
    /// Where each argument ends in `bytes`.
    ends: Vec<usize>,
}

impl Argv {
    /// Arguments copied from `args` (tests, and tables a test controls).
    pub fn new<I, S>(args: I) -> Argv
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let args: Vec<S> = args.into_iter().collect();
        let slices: Vec<&[u8]> = args.iter().map(|a| a.as_ref().as_bytes()).collect();
        Argv::from_slices(&slices)
    }

    /// Copies `args` into a buffer allocated once, at its final size:
    /// growing it would leave copies in freed memory.
    fn from_slices(args: &[&[u8]]) -> Argv {
        let total = args.iter().map(|a| a.len()).sum();
        let mut bytes = Zeroizing::new(Vec::with_capacity(total));
        let mut ends = Vec::with_capacity(args.len());
        for a in args {
            bytes.extend_from_slice(a);
            ends.push(bytes.len());
        }
        Argv { bytes, ends }
    }

    /// How many arguments there are.
    pub fn len(&self) -> usize {
        self.ends.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ends.is_empty()
    }

    /// Argument `i`.
    pub fn get(&self, i: usize) -> Option<&OsStr> {
        (i < self.len()).then(|| self.arg(i))
    }

    /// `argv[0]`.
    pub fn first(&self) -> Option<&OsStr> {
        self.get(0)
    }

    /// The arguments in order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &OsStr> + '_ {
        (0..self.len()).map(|i| self.arg(i))
    }

    /// Argument `i`, which must exist.
    fn arg(&self, i: usize) -> &OsStr {
        let start = i.checked_sub(1).map_or(0, |j| self.ends[j]);
        OsStr::from_bytes(&self.bytes[start..self.ends[i]])
    }
}

impl core::fmt::Debug for Argv {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Argv")
            .field("argc", &self.len())
            .finish_non_exhaustive()
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
    fn argv(&mut self, pid: i32) -> io::Result<Argv>;
}

/// The kernel's process table: [`proc_info`] and [`proc_argv`].
#[derive(Debug, Clone, Copy, Default)]
pub struct LiveProcesses;

impl ProcessTable for LiveProcesses {
    fn info(&mut self, pid: i32) -> io::Result<ProcInfo> {
        proc_info(pid)
    }

    fn argv(&mut self, pid: i32) -> io::Result<Argv> {
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

/// Whether process `pid` is the instance that started at `start` and has
/// not exited. A process that exited and is not yet reaped (a zombie)
/// keeps its pid and its start time until its parent waits for it, so a
/// pid and a start time alone still find it: its state says it ended
/// (Linux `Z` or `X` in `/proc/<pid>/stat`, macOS `SZOMB`). `false` when
/// there is no such process, it is another instance, it has exited, or it
/// cannot be read: a caller asks whether it may act for that process, and
/// the answer fails closed.
pub fn process_running(pid: i32, start: StartTime) -> bool {
    if pid <= 0 {
        return false;
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        linux::process_running(pid, start)
    }
    #[cfg(target_os = "macos")]
    {
        macos::process_running(pid, start)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    {
        let _ = start;
        false
    }
}

/// The state letter (field 3) of a Linux `/proc/<pid>/stat` file: the
/// first character after the `)` that ends the command name (the last one
/// in the file, since the name may hold parentheses), between single
/// spaces. `None` when it is not one ASCII letter so placed.
pub fn parse_stat_state(stat: &[u8]) -> Option<u8> {
    let close = stat.iter().rposition(|b| *b == b')')?;
    match stat.get(close + 1..close + 4)? {
        [b' ', s, b' '] if s.is_ascii_alphabetic() => Some(*s),
        _ => None,
    }
}

/// Whether a Linux process state letter ([`parse_stat_state`]) is one of a
/// process that has exited: `Z` (a zombie, not yet reaped), `X` or `x`
/// (dead, being reaped).
pub fn stat_state_exited(state: u8) -> bool {
    matches!(state, b'Z' | b'X' | b'x')
}

/// The arguments of process `pid`, `argv[0]` first: at most [`MAX_ARGV`]
/// of them and [`MAX_ARGV_BYTES`] in all, in wiped storage. See the module
/// documentation for what is read, and when environment strings can be
/// among them.
///
/// # Errors
/// When the kernel refuses (another user's process on macOS, a process
/// that exited) or the arguments are malformed. The errors are fixed text.
pub fn proc_argv(pid: i32) -> io::Result<Argv> {
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
    /// Fields 48 and 49: where the argument area starts and ends in the
    /// process's memory (`arg_start`, `arg_end`). `None` when the fields are
    /// missing or malformed, or the kernel shows zeros: it does unless the
    /// reader may trace the process (not another user's, nor a
    /// non-dumpable one).
    pub arg_area: Option<(u64, u64)>,
}

impl StatFields {
    /// The argument area's length in bytes, its NULs included, when
    /// [`StatFields::arg_area`] is known and not empty.
    pub fn arg_area_len(&self) -> Option<usize> {
        let (start, end) = self.arg_area?;
        usize::try_from(end.checked_sub(start)?)
            .ok()
            .filter(|n| *n > 0)
    }
}

/// Parses the contents of a Linux `/proc/<pid>/stat` file. The command name
/// in field 2 is in parentheses and may itself hold spaces and
/// parentheses, so it runs from the first `(` to the last `)`, and the
/// other fields are counted from there. `None` when a field up to 22 is
/// missing or malformed; fields 48 and 49 are optional
/// ([`StatFields::arg_area`]).
pub fn parse_proc_stat(stat: &[u8]) -> Option<StatFields> {
    let open = stat.iter().position(|b| *b == b'(')?;
    let close = stat.iter().rposition(|b| *b == b')')?;
    if close < open {
        return None;
    }
    let pid = parse_int(std::str::from_utf8(stat.get(..open)?).ok()?.trim_end())?;
    let comm = stat.get(open + 1..close)?.to_vec();
    let rest = std::str::from_utf8(stat.get(close + 1..)?).ok()?;
    let fields: Vec<&str> = rest.split_ascii_whitespace().take(47).collect();
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
        arg_area: match (field(48).and_then(parse_u64), field(49).and_then(parse_u64)) {
            (Some(start), Some(end)) if start != 0 && end != 0 => Some((start, end)),
            _ => None,
        },
    })
}

/// A decimal integer without a sign, and nothing else.
fn parse_u64(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
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
pub fn parse_cmdline(bytes: &[u8]) -> Argv {
    let mut args: Vec<&[u8]> = Vec::with_capacity(MAX_ARGV);
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
        args.push(arg);
        rest = next;
    }
    Argv::from_slices(&args)
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
/// Then `argc` NUL-terminated strings are read, at most [`MAX_ARGV`] of
/// them and [`MAX_ARGV_BYTES`] in all, and parsing stops.
///
/// `argc` is the count `exec` saved, and the strings are the process's
/// memory as it is now: nothing marks where the arguments end. A process
/// that removed the NULs between its arguments (node's `process.title`
/// does, over a short command line) is read as fewer, longer arguments,
/// followed by as many environment strings as it removed NULs (review
/// finding F-38). The [`Argv`] holding them is wiped on drop and never
/// shown.
///
/// `None` when the padding holds anything but NULs, or the buffer ends
/// before the arguments it announces.
pub fn parse_procargs2(buf: &[u8]) -> Option<Argv> {
    let argc = i32::from_ne_bytes(buf.get(..4)?.try_into().ok()?);
    let argc = usize::try_from(argc).ok()?;
    let area = buf.get(4..)?;
    let path_len = area.iter().position(|b| *b == 0)?;
    let mut i = (path_len + 1).checked_next_multiple_of(PROCARGS_ALIGN)?;
    if area.get(path_len..i)?.iter().any(|b| *b != 0) {
        return None;
    }
    let want = argc.min(MAX_ARGV);
    let mut args: Vec<&[u8]> = Vec::with_capacity(want);
    let mut total = 0usize;
    while args.len() < want {
        let rest = area.get(i..)?;
        let n = rest.iter().position(|b| *b == 0)?;
        total = total.saturating_add(n);
        if total > MAX_ARGV_BYTES {
            break;
        }
        args.push(&rest[..n]);
        i += n + 1;
    }
    Some(Argv::from_slices(&args))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strs(a: &Argv) -> Vec<&OsStr> {
        a.iter().collect()
    }

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

    /// A current kernel's 52 fields, with `arg_start` and `arg_end` (48
    /// and 49) as given.
    fn full_stat(arg_start: &str, arg_end: &str) -> Vec<u8> {
        let mut f: Vec<String> = (3..=52).map(|n: u32| n.to_string()).collect();
        f[0] = "S".into();
        f[22 - 3] = "987654".into();
        f[48 - 3] = arg_start.into();
        f[49 - 3] = arg_end.into();
        format!("4242 (node) {}\n", f.join(" ")).into_bytes()
    }

    #[test]
    fn the_argument_area_is_fields_48_and_49() {
        let f = parse_proc_stat(&full_stat("140736000000000", "140736000000040")).unwrap();
        assert_eq!((f.pid, f.ppid, f.session), (4242, 4, 6));
        assert_eq!(f.start_time, StartTime::from_raw(987_654));
        assert_eq!(f.arg_area, Some((140_736_000_000_000, 140_736_000_000_040)));
        assert_eq!(f.arg_area_len(), Some(40));
        // Zeros: the kernel keeps them from a reader that may not trace
        // the process.
        let hidden = parse_proc_stat(&full_stat("0", "0")).unwrap();
        assert_eq!((hidden.arg_area, hidden.arg_area_len()), (None, None));
        // Malformed, reversed or empty.
        for (start, end) in [("x", "12"), ("-4", "12"), ("12", "1e3")] {
            let f = parse_proc_stat(&full_stat(start, end)).unwrap();
            assert_eq!(f.arg_area_len(), None, "{start} {end}");
        }
        for (start, end) in [("50", "40"), ("40", "40")] {
            let f = parse_proc_stat(&full_stat(start, end)).unwrap();
            assert_eq!(f.arg_area_len(), None, "{start} {end}");
        }
        // A line that stops before field 48.
        assert_eq!(
            parse_proc_stat(&stat_line("x", "0", "5")).unwrap().arg_area,
            None
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
        assert_eq!(strs(&args), ["node", "/usr/lib/cli.js", "--flag"]);
        assert_eq!(
            strs(&parse_cmdline(b"retitled process")),
            ["retitled process"]
        );
        assert_eq!(strs(&parse_cmdline(b"a\0\0b\0")), ["a", "", "b"]);
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
        assert_eq!(strs(&parse_procargs2(&b).unwrap()), ["node", "/opt/cli.js"]);
        assert!(
            parse_procargs2(&procargs(0, b"/bin/x", &[b"ENV=1"]))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn empty_arguments_are_arguments_not_padding() {
        // Review finding F-33: a path whose NUL ends on the alignment, then
        // an empty argv[0]. Skipping NULs read "30" as argv[0] and the
        // environment as argv[1].
        let b = procargs(2, b"/bin/sl", &[b"", b"30", b"ENVMARK=1"]);
        assert_eq!(b.len(), 4 + 8 + 1 + 3 + 10);
        assert_eq!(strs(&parse_procargs2(&b).unwrap()), ["", "30"]);
        // Padding before an empty argv[0], and several empty arguments.
        for path in [&b"/bin/x"[..], b"/usr/bin/xargs", b"/bin/sleep", b"/a", b""] {
            let b = procargs(4, path, &[b"", b"", b"", b"z", b"ENVMARK=1"]);
            assert_eq!(strs(&parse_procargs2(&b).unwrap()), ["", "", "", "z"]);
        }
    }

    /// Review finding F-38: `argc` is the count `exec` saved, and nothing
    /// marks where the arguments end. A process that removed the NULs
    /// between its arguments is read with environment strings as
    /// arguments. They are held in an [`Argv`], which never shows them, and
    /// no more than [`MAX_ARGV`] are read.
    #[test]
    fn removed_separators_read_on_into_the_environment_and_are_never_shown() {
        let b = procargs(
            3,
            b"/usr/local/bin/node",
            &[b"node /tmp/t.js x", b"ENVMARK=hunter2", b"PATH=/bin"],
        );
        let args = parse_procargs2(&b).unwrap();
        assert_eq!(
            strs(&args),
            ["node /tmp/t.js x", "ENVMARK=hunter2", "PATH=/bin"]
        );
        assert_eq!(format!("{args:?}"), "Argv { argc: 3, .. }");
        let mut p = ProcInfo {
            pid: 7,
            ppid: 1,
            start_time: StartTime::from_raw(1),
            uid: 501,
            sid: Some(7),
            controlling_tty: None,
            comm: OsString::from("node"),
            exe: None,
            argv: None,
        };
        p.argv = Some(args);
        let shown = format!("{p:?}");
        assert!(!shown.contains("hunter2"), "{shown}");
        assert!(shown.contains("argc: Some(3)"), "{shown}");

        let env: Vec<Vec<u8>> = (0..40).map(|k| format!("V{k}=x").into_bytes()).collect();
        let mut strings: Vec<&[u8]> = vec![b"retitled"];
        strings.extend(env.iter().map(Vec::as_slice));
        let b = procargs(41, b"/bin/node", &strings);
        assert_eq!(parse_procargs2(&b).unwrap().len(), MAX_ARGV);
    }

    #[test]
    fn argv_lends_its_arguments_and_shows_only_their_count() {
        let a = Argv::new(["node", "", "--token=hunter2"]);
        assert_eq!(a.len(), 3);
        assert_eq!(a.first(), Some(OsStr::new("node")));
        assert_eq!(a.get(1), Some(OsStr::new("")));
        assert_eq!(a.get(2), Some(OsStr::new("--token=hunter2")));
        assert_eq!(a.get(3), None);
        assert_eq!(a.iter().len(), 3);
        assert_eq!(strs(&a), ["node", "", "--token=hunter2"]);
        let shown = format!("{a:?}");
        assert!(!shown.contains("hunter2"), "{shown}");
        // One buffer allocated at its final size: nothing grew and left a
        // copy behind in freed memory.
        assert_eq!(a.bytes.capacity(), a.bytes.len());
        let parsed = parse_cmdline(b"node\0\0--token=hunter2\0");
        assert_eq!(parsed, a);
        assert_eq!(parsed.bytes.capacity(), parsed.bytes.len());
        assert!(Argv::default().is_empty());
        assert_eq!(Argv::new(Vec::<&str>::new()).first(), None);
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
