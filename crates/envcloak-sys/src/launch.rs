//! Starting the processes a value goes into (M2 plan D-33, D-34, D-36;
//! task M2-27): EnvCloak's own runner, which the daemon starts, and the
//! registered server, which the runner starts. Every start returns the
//! child as an [`OwnedChild`], the only handle signals go through.
//!
//! **What runs is what was checked.** On Linux a launch bound to its image
//! never runs from its file: [`SealedImage::copy_from`] copies the checked
//! descriptor into a memory file (`memfd_create`), seals it against
//! writing, growing and shrinking and checks the seals, and the caller
//! hashes that sealed copy and compares it with the record; [`spawn`] then
//! executes the same copy with `execveat(fd, "", AT_EMPTY_PATH)`. A file
//! can be rewritten in place, or another put in its place, after any
//! check of it; the sealed copy cannot. The daemon's own runner is started
//! the same way, from the copy of the `envcloak` beside it that it made
//! when it started. A system whose policy refuses an executable memory
//! file (`vm.memfd_noexec=2`) refuses [`SealedImage::copy_from`]; nothing
//! here falls back to the file.
//!
//! macOS has no descriptor execution. There a child is started suspended
//! (`POSIX_SPAWN_START_SUSPENDED`: the task is created suspended, before
//! any instruction runs in user space, its dynamic loader's included), so
//! its parent can read the code directory hash the kernel validated it
//! against (`csops`, [`crate::proc_info`]) and resume it
//! ([`OwnedChild::resume`], `SIGCONT`, measured on macOS 26.4 for this
//! task) only when that hash is the expected one, or kill it through its
//! handle before it runs. A child started suspended reads as stopped to
//! `waitpid` with `WUNTRACED` until it is resumed.
//!
//! **What a child gets.** [`Spawn`] names the program, its argv and its
//! whole environment (nothing is inherited from this process), the
//! descriptors it gets and at which numbers ([`Spawn::fds`]; every other
//! descriptor is closed), the directory it starts in (a descriptor, so
//! the directory checked is the one it gets, `fchdir`), and whether it
//! leads a new session (EnvCloak's runner: it outlives a daemon restart
//! and launchd's cleanup of the daemon's job, which reaches only the
//! job's own process group, measured on macOS 26.4) or a new process
//! group (the server, whose group the runner stops). Signal dispositions
//! are reset and the signal mask cleared, so a daemon that blocks its
//! termination signals does not pass that on. No child gets
//! `PR_SET_PDEATHSIG`.
//!
//! On Linux the child is made with `fork` and calls only async-signal-safe
//! functions until it executes the program (the parent is
//! multi-threaded); a failure on the way is written to a close-on-exec
//! pipe, so the caller learns whether the program started. On macOS it is
//! `posix_spawn`, with `POSIX_SPAWN_CLOEXEC_DEFAULT` closing every
//! descriptor not handed over.

use std::ffi::c_char;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use zeroize::Zeroizing;

use crate::owned::OwnedChild;

/// The highest descriptor number a child may be given ([`Spawn::fds`]).
pub const MAX_TARGET_FD: i32 = 9;

/// What a child runs.
#[derive(Debug, Clone, Copy)]
pub enum Program<'a> {
    /// A path, as `execve` takes it.
    Path(&'a [u8]),
    /// Linux: an open executable file, run with `execveat(fd, "",
    /// AT_EMPTY_PATH)`: a [`SealedImage`], or, for a launch checked at
    /// rest only, the descriptor that was checked.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    Descriptor(BorrowedFd<'a>),
}

/// The session and process group a child gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Session {
    /// It leads a new session (and so a new process group).
    New,
    /// It leads a new process group in this process's session.
    Group,
}

/// What [`spawn`] starts.
pub struct Spawn<'a> {
    pub program: Program<'a>,
    /// The arguments, `argv[0]` first: no NUL byte in any.
    pub argv: &'a [&'a [u8]],
    /// The whole environment, each `NAME=value` with no NUL byte: nothing
    /// is inherited from this process. The copies made for the child are
    /// wiped when the start returns.
    pub env: &'a [&'a [u8]],
    /// Each descriptor to hand over and the number it gets in the child,
    /// at most [`MAX_TARGET_FD`], each number once. Every other descriptor
    /// is closed in the child.
    pub fds: &'a [(BorrowedFd<'a>, i32)],
    /// The directory the child starts in.
    pub cwd: Option<BorrowedFd<'a>>,
    pub session: Session,
    /// macOS: start the child suspended, to be resumed with
    /// [`OwnedChild::resume`] or killed through its handle. Refused on
    /// other systems.
    pub suspended: bool,
}

impl core::fmt::Debug for Spawn<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Spawn")
            .field("args", &self.argv.len())
            .field("env", &self.env.len())
            .field("fds", &self.fds.len())
            .field("cwd", &self.cwd.is_some())
            .field("session", &self.session)
            .field("suspended", &self.suspended)
            .finish()
    }
}

/// Why a child was not started. Nothing runs in either case.
#[derive(Debug)]
pub enum SpawnError {
    /// The program could not be run: the system's error for running it.
    Exec(io::Error),
    /// The child could not be set up, or the request was malformed (a
    /// target number out of range or twice, a NUL byte).
    Setup(io::Error),
}

impl SpawnError {
    /// The underlying error.
    pub fn io(&self) -> &io::Error {
        match self {
            SpawnError::Exec(e) | SpawnError::Setup(e) => e,
        }
    }
}

impl core::fmt::Display for SpawnError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SpawnError::Exec(e) => write!(f, "the program could not be run: {e}"),
            SpawnError::Setup(e) => write!(f, "the child could not be set up: {e}"),
        }
    }
}

impl std::error::Error for SpawnError {}

fn invalid() -> SpawnError {
    SpawnError::Setup(io::ErrorKind::InvalidInput.into())
}

/// NUL-terminated copies of `list`, wiped on drop, and the null-ended
/// pointer array a C call takes.
struct CStrings {
    owned: Vec<Zeroizing<Vec<u8>>>,
    pointers: Vec<*const c_char>,
}

impl CStrings {
    fn new(list: &[&[u8]]) -> Result<CStrings, SpawnError> {
        let mut owned: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(list.len());
        for s in list {
            if s.contains(&0) {
                return Err(invalid());
            }
            let mut c = Zeroizing::new(Vec::with_capacity(s.len() + 1));
            c.extend_from_slice(s);
            c.push(0);
            owned.push(c);
        }
        let pointers = owned
            .iter()
            .map(|c| c.as_ptr().cast::<c_char>())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        Ok(CStrings { owned, pointers })
    }

    fn as_ptr(&self) -> *const *const c_char {
        self.pointers.as_ptr()
    }
}

/// Checks the targets: in range, each once.
fn check_targets(fds: &[(BorrowedFd<'_>, i32)]) -> Result<(), SpawnError> {
    let mut seen = [false; (MAX_TARGET_FD + 1) as usize];
    for (_, t) in fds {
        let i = usize::try_from(*t).map_err(|_| invalid())?;
        if *t > MAX_TARGET_FD || seen[i] {
            return Err(invalid());
        }
        seen[i] = true;
    }
    Ok(())
}

/// Starts `s` (see the module documentation).
///
/// # Errors
/// [`SpawnError::Exec`] when the program could not be run (it does not
/// exist, is not executable, or is refused), [`SpawnError::Setup`] for a
/// malformed request or a child that could not be set up. Nothing runs
/// after either.
pub fn spawn(s: &Spawn<'_>) -> Result<OwnedChild, SpawnError> {
    check_targets(s.fds)?;
    if s.argv.is_empty() {
        return Err(invalid());
    }
    let argv = CStrings::new(s.argv)?;
    let env = CStrings::new(s.env)?;
    // The child must stay unreaped until its handle reaps it.
    crate::owned::keep_children_unreaped().map_err(SpawnError::Setup)?;
    imp::spawn(s, &argv, &env)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod imp {
    use super::*;
    use crate::pty_monitor::{LAST_SIGNAL, close_from, disposition, errno, set_mask};

    /// What the child needs, as plain numbers and pointers, prepared before
    /// the fork so it allocates nothing.
    struct Prepared {
        path: *const c_char,
        descriptor: libc::c_int,
        argv: *const *const c_char,
        envp: *const *const c_char,
        fds: [(libc::c_int, libc::c_int); (MAX_TARGET_FD + 1) as usize],
        nfds: usize,
        cwd: libc::c_int,
        new_session: bool,
        err: libc::c_int,
    }

    /// The stages a failure is reported from.
    const STAGE_SETUP: u8 = 1;
    const STAGE_EXEC: u8 = 2;

    pub(super) fn spawn(
        s: &Spawn<'_>,
        argv: &CStrings,
        env: &CStrings,
    ) -> Result<OwnedChild, SpawnError> {
        if s.suspended {
            return Err(SpawnError::Setup(io::ErrorKind::Unsupported.into()));
        }
        let path = match s.program {
            Program::Path(p) => Some(CStrings::new(&[p])?),
            Program::Descriptor(_) => None,
        };
        let (err_read, err_write) = crate::pipe_cloexec().map_err(SpawnError::Setup)?;
        let mut p = Prepared {
            path: path
                .as_ref()
                .map_or(std::ptr::null(), |c| c.owned[0].as_ptr().cast()),
            descriptor: match s.program {
                Program::Descriptor(fd) => fd.as_raw_fd(),
                Program::Path(_) => -1,
            },
            argv: argv.as_ptr(),
            envp: env.as_ptr(),
            fds: [(-1, -1); (MAX_TARGET_FD + 1) as usize],
            nfds: s.fds.len(),
            cwd: s.cwd.map_or(-1, |c| c.as_raw_fd()),
            new_session: s.session == Session::New,
            err: err_write.as_raw_fd(),
        };
        for (i, (fd, t)) in s.fds.iter().enumerate() {
            p.fds[i] = (fd.as_raw_fd(), *t);
        }
        // SAFETY: fork has no preconditions. The child runs only
        // `child_main`, which calls async-signal-safe functions, never
        // allocates and never returns.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(SpawnError::Setup(io::Error::last_os_error()));
        }
        if pid == 0 {
            // SAFETY: a new child of fork; `p`'s pointers point into this
            // process's copy of the parent's memory.
            unsafe { child_main(&p) };
        }
        let child = OwnedChild::from_fork(pid);
        drop(err_write);
        // Nothing to read means the program replaced the child: the pipe
        // closed when it started running.
        let mut report = [0u8; 5];
        let mut got = 0;
        let mut file = std::fs::File::from(err_read);
        while got < report.len() {
            match std::io::Read::read(&mut file, &mut report[got..]) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    let _ = child.kill_and_reap();
                    return Err(SpawnError::Setup(e));
                }
            }
        }
        if got == 0 {
            return Ok(child);
        }
        // The child failed and exits: reaped here, so nothing is left.
        let _ = child.reap();
        let e = if got == report.len() {
            io::Error::from_raw_os_error(i32::from_ne_bytes([
                report[1], report[2], report[3], report[4],
            ]))
        } else {
            io::ErrorKind::InvalidData.into()
        };
        Err(if report[0] == STAGE_EXEC {
            SpawnError::Exec(e)
        } else {
            SpawnError::Setup(e)
        })
    }

    /// Writes `stage` and `errno` to the report pipe and ends the child.
    fn fail(err: libc::c_int, stage: u8, e: libc::c_int) -> ! {
        let mut b = [0u8; 5];
        b[0] = stage;
        b[1..].copy_from_slice(&e.to_ne_bytes());
        // SAFETY: writes from a local; the process then ends.
        unsafe {
            libc::write(err, b.as_ptr().cast(), b.len());
            libc::_exit(127)
        }
    }

    /// The child, after `fork`. Never returns.
    ///
    /// # Safety
    /// Called only in a new child of `fork`, with `p`'s pointers valid.
    /// Calls only async-signal-safe functions and never allocates.
    unsafe fn child_main(p: &Prepared) -> ! {
        // 1. No signal arrives while the dispositions change; each is
        //    reset, so none of the parent's handlers or ignored signals
        //    carries over.
        set_mask(libc::SIG_SETMASK, true, &[]);
        for sig in 1..=LAST_SIGNAL {
            if sig != libc::SIGKILL && sig != libc::SIGSTOP {
                disposition(sig, libc::SIG_DFL);
            }
        }
        // 2. The session or group.
        // SAFETY: setsid and setpgid have no memory effects; a fresh child
        // of fork leads no group, so either succeeds.
        let ok = unsafe {
            if p.new_session {
                libc::setsid() >= 0
            } else {
                libc::setpgid(0, 0) == 0
            }
        };
        if !ok {
            fail(p.err, STAGE_SETUP, errno());
        }
        // 3. Every descriptor the child keeps is moved above the targets
        //    first, so a source numbered as some target is not lost when
        //    that target is filled.
        let max = p.fds[..p.nfds]
            .iter()
            .map(|(_, t)| *t)
            .max()
            .unwrap_or(2)
            .max(2);
        let report_at = max + 1;
        let program_at = max + 2;
        let high = max + 3;
        let up = |fd: libc::c_int| -> libc::c_int {
            if fd < 0 {
                return -1;
            }
            // SAFETY: F_DUPFD_CLOEXEC makes a new descriptor or fails.
            let n = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, high) };
            if n < 0 {
                fail(p.err, STAGE_SETUP, errno());
            }
            n
        };
        let err = up(p.err);
        let descriptor = up(p.descriptor);
        let cwd = up(p.cwd);
        let mut moved = [-1 as libc::c_int; (MAX_TARGET_FD + 1) as usize];
        for (i, m) in moved.iter_mut().enumerate().take(p.nfds) {
            *m = up(p.fds[i].0);
        }
        // 4. Into place: the targets (inherited), then the report pipe and
        //    the program, closed when the program runs.
        // SAFETY: dup2 and fcntl on descriptors this child owns.
        unsafe {
            for (i, m) in moved.iter().enumerate().take(p.nfds) {
                if libc::dup2(*m, p.fds[i].1) < 0 {
                    fail(err, STAGE_SETUP, errno());
                }
            }
            if libc::dup2(err, report_at) < 0
                || libc::fcntl(report_at, libc::F_SETFD, libc::FD_CLOEXEC) < 0
            {
                fail(err, STAGE_SETUP, errno());
            }
            if descriptor >= 0
                && (libc::dup2(descriptor, program_at) < 0
                    || libc::fcntl(program_at, libc::F_SETFD, libc::FD_CLOEXEC) < 0)
            {
                fail(report_at, STAGE_SETUP, errno());
            }
            // 5. The directory, through the descriptor that was checked.
            if cwd >= 0 && libc::fchdir(cwd) != 0 {
                fail(report_at, STAGE_SETUP, errno());
            }
        }
        // 6. Nothing else stays open.
        let keep_to = if descriptor >= 0 {
            program_at
        } else {
            report_at
        };
        if let Err(e) = close_from(keep_to + 1) {
            fail(report_at, STAGE_SETUP, e);
        }
        set_mask(libc::SIG_SETMASK, false, &[]);
        // 7. The program.
        // SAFETY: the pointers are NUL-terminated strings and null-ended
        // arrays prepared before the fork; on success this does not
        // return.
        unsafe {
            if descriptor >= 0 {
                libc::syscall(
                    libc::SYS_execveat,
                    program_at,
                    c"".as_ptr(),
                    p.argv,
                    p.envp,
                    libc::AT_EMPTY_PATH,
                );
            } else {
                libc::execve(p.path, p.argv, p.envp);
            }
        }
        fail(report_at, STAGE_EXEC, errno())
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;

    /// `POSIX_SPAWN_SETSID` (spawn.h; the libc crate does not have it).
    const POSIX_SPAWN_SETSID: libc::c_short = 0x0400;

    unsafe extern "C" {
        /// spawn.h, macOS 10.15 on (deprecated in favour of a name
        /// without `_np` only from macOS 26).
        fn posix_spawn_file_actions_addfchdir_np(
            actions: *mut libc::posix_spawn_file_actions_t,
            fd: libc::c_int,
        ) -> libc::c_int;
    }

    /// The attributes and file actions of one start, destroyed on drop.
    struct Actions {
        attr: libc::posix_spawnattr_t,
        actions: libc::posix_spawn_file_actions_t,
    }

    impl Drop for Actions {
        fn drop(&mut self) {
            // SAFETY: both were initialized in `spawn`.
            unsafe {
                libc::posix_spawnattr_destroy(&mut self.attr);
                libc::posix_spawn_file_actions_destroy(&mut self.actions);
            }
        }
    }

    fn check(rc: libc::c_int) -> Result<(), SpawnError> {
        if rc == 0 {
            Ok(())
        } else {
            Err(SpawnError::Setup(io::Error::from_raw_os_error(rc)))
        }
    }

    pub(super) fn spawn(
        s: &Spawn<'_>,
        argv: &CStrings,
        env: &CStrings,
    ) -> Result<OwnedChild, SpawnError> {
        let Program::Path(path) = s.program;
        let path = CStrings::new(&[path])?;
        // Each source moved above the targets first, so a file action that
        // fills a target never overwrites a source still to come.
        let mut moved: Vec<OwnedFd> = Vec::with_capacity(s.fds.len());
        for (fd, _) in s.fds {
            // SAFETY: F_DUPFD_CLOEXEC makes a new descriptor or fails.
            let n =
                unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, MAX_TARGET_FD + 1) };
            if n < 0 {
                return Err(SpawnError::Setup(io::Error::last_os_error()));
            }
            // SAFETY: just created; nothing else owns it.
            moved.push(unsafe { OwnedFd::from_raw_fd(n) });
        }
        // SAFETY: both are plain data, initialized by their init calls
        // before use and destroyed by `Actions`'s drop.
        let mut a: Actions = unsafe { std::mem::zeroed() };
        // SAFETY: `a`'s fields are writable.
        unsafe {
            check(libc::posix_spawnattr_init(&mut a.attr))?;
            check(libc::posix_spawn_file_actions_init(&mut a.actions))?;
        }
        let mut flags = libc::POSIX_SPAWN_SETSIGMASK
            | libc::POSIX_SPAWN_SETSIGDEF
            | libc::POSIX_SPAWN_CLOEXEC_DEFAULT;
        if s.suspended {
            flags |= libc::POSIX_SPAWN_START_SUSPENDED;
        }
        let mut flags = libc::c_short::try_from(flags).map_err(|_| invalid())?;
        match s.session {
            Session::New => flags |= POSIX_SPAWN_SETSID,
            Session::Group => {
                flags |=
                    libc::c_short::try_from(libc::POSIX_SPAWN_SETPGROUP).map_err(|_| invalid())?;
            }
        }
        // SAFETY: sigset_t is plain data, initialized by the calls below.
        let mut empty: libc::sigset_t = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        let mut all: libc::sigset_t = unsafe { std::mem::zeroed() };
        // SAFETY: every pointer is to an initialized local or field.
        unsafe {
            libc::sigemptyset(&mut empty);
            libc::sigfillset(&mut all);
            check(libc::posix_spawnattr_setflags(&mut a.attr, flags))?;
            check(libc::posix_spawnattr_setsigmask(&mut a.attr, &empty))?;
            check(libc::posix_spawnattr_setsigdefault(&mut a.attr, &all))?;
            if s.session == Session::Group {
                check(libc::posix_spawnattr_setpgroup(&mut a.attr, 0))?;
            }
            for (m, (_, t)) in moved.iter().zip(s.fds) {
                check(libc::posix_spawn_file_actions_adddup2(
                    &mut a.actions,
                    m.as_raw_fd(),
                    *t,
                ))?;
            }
            if let Some(cwd) = s.cwd {
                check(posix_spawn_file_actions_addfchdir_np(
                    &mut a.actions,
                    cwd.as_raw_fd(),
                ))?;
            }
        }
        let mut pid: libc::pid_t = 0;
        // SAFETY: `path`, `argv` and `env` are NUL-terminated strings and
        // null-ended arrays; `a` is initialized.
        let rc = unsafe {
            libc::posix_spawn(
                &mut pid,
                path.owned[0].as_ptr().cast(),
                &a.actions,
                &a.attr,
                argv.as_ptr().cast(),
                env.as_ptr().cast(),
            )
        };
        drop(moved);
        if rc != 0 {
            return Err(SpawnError::Exec(io::Error::from_raw_os_error(rc)));
        }
        Ok(OwnedChild::from_fork(pid))
    }
}

/// An executable's bytes in a sealed memory file (Linux): see the module
/// documentation.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[derive(Debug)]
pub struct SealedImage {
    fd: OwnedFd,
    len: u64,
}

/// The seals a [`SealedImage`] carries: no write, no growth, no
/// shrinking, and no further change of seals.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub const IMAGE_SEALS: libc::c_int =
    libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;

/// Why a sealed copy was not made. No copy is ever used after one.
#[derive(Debug)]
pub enum ImageError {
    /// The memory file could not be made: the kernel refuses executable
    /// memory files (`vm.memfd_noexec`), or has no `memfd_create`.
    Create(io::Error),
    /// Reading the source or writing the copy failed.
    Copy(io::Error),
    /// The source is not a regular file.
    NotRegular,
    /// The source is (or grew) larger than the limit.
    TooLarge,
    /// The seals could not be set, or are not all there.
    Seal(io::Error),
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl SealedImage {
    /// Copies the regular file `src` refers to, at most `max` bytes, into
    /// a new memory file, and seals it ([`IMAGE_SEALS`]): the bytes the
    /// copy holds when this returns are the bytes it holds for good. The
    /// source may change while it is copied; the copy is then what was
    /// read, and the caller's hash of the copy, never of the source, says
    /// whether it is the approved image.
    ///
    /// # Errors
    /// [`ImageError`]; nothing is left open.
    pub fn copy_from(src: BorrowedFd<'_>, max: u64) -> Result<SealedImage, ImageError> {
        let st = fstat(src).map_err(ImageError::Copy)?;
        if st.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err(ImageError::NotRegular);
        }
        if u64::try_from(st.st_size).unwrap_or(u64::MAX) > max {
            return Err(ImageError::TooLarge);
        }
        let fd = memfd().map_err(ImageError::Create)?;
        let mut buf = vec![0u8; 64 * 1024];
        let mut at: u64 = 0;
        loop {
            let n = pread(src, &mut buf, at).map_err(ImageError::Copy)?;
            if n == 0 {
                break;
            }
            let n64 = u64::try_from(n).map_err(|_| ImageError::TooLarge)?;
            if at.saturating_add(n64) > max {
                return Err(ImageError::TooLarge);
            }
            write_all_at(borrow(&fd), &buf[..n], at).map_err(ImageError::Copy)?;
            at += n64;
            // A test stops here, after the first piece, to change the
            // source while it is copied (M2-27's copying barrier).
            crate::pause_point("launch.copying");
        }
        let len = u64::try_from(fstat(borrow(&fd)).map_err(ImageError::Copy)?.st_size)
            .map_err(|_| ImageError::Copy(io::ErrorKind::InvalidData.into()))?;
        if len != at {
            return Err(ImageError::Copy(io::ErrorKind::InvalidData.into()));
        }
        // SAFETY: F_ADD_SEALS on a memory file this process made; it has
        // no shared writable mapping, which would make it fail (EBUSY).
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, IMAGE_SEALS) } != 0 {
            return Err(ImageError::Seal(io::Error::last_os_error()));
        }
        let image = SealedImage { fd, len };
        image.check_seals().map_err(ImageError::Seal)?;
        Ok(image)
    }

    /// The copy's descriptor, for [`Program::Descriptor`] or to hand over.
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        borrow(&self.fd)
    }

    /// Its length in bytes.
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Reads the copy from `at` into `buf`: how many bytes, 0 at its end.
    ///
    /// # Errors
    /// `pread`'s.
    pub fn read_at(&self, buf: &mut [u8], at: u64) -> io::Result<usize> {
        pread(self.as_fd(), buf, at)
    }

    /// Checks that every seal of [`IMAGE_SEALS`] is on the copy, and that
    /// its length is still the one it was made with: read again before a
    /// release, not taken from when it was made.
    ///
    /// # Errors
    /// [`io::ErrorKind::PermissionDenied`] when a seal is missing or the
    /// length moved; `fcntl`'s and `fstat`'s errors.
    pub fn check_seals(&self) -> io::Result<()> {
        // SAFETY: F_GET_SEALS only reads the file's seals.
        let seals = unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_GET_SEALS) };
        if seals < 0 {
            return Err(io::Error::last_os_error());
        }
        let len = u64::try_from(fstat(self.as_fd())?.st_size).unwrap_or(u64::MAX);
        if seals & IMAGE_SEALS != IMAGE_SEALS || len != self.len {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(())
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn borrow(fd: &OwnedFd) -> BorrowedFd<'_> {
    std::os::fd::AsFd::as_fd(fd)
}

/// A new memory file for an executable copy: close-on-exec, sealable, and
/// executable (`MFD_EXEC`, which a kernel before 6.3 does not know: there
/// every memory file is executable, and it is made without the flag).
#[cfg(any(target_os = "linux", target_os = "android"))]
fn memfd() -> io::Result<OwnedFd> {
    let name = c"envcloak-image";
    let base = libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING;
    // A test build can be made to fail here, as a kernel policy that
    // refuses executable memory files would (runner_unavailable).
    crate::fail_point("launch.memfd")?;
    // SAFETY: `name` is NUL-terminated; memfd_create makes a new
    // descriptor or fails without effect.
    let mut fd = unsafe { libc::memfd_create(name.as_ptr(), base | libc::MFD_EXEC) };
    if fd < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
        // SAFETY: as above.
        fd = unsafe { libc::memfd_create(name.as_ptr(), base) };
    }
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: just created; nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn fstat(fd: BorrowedFd<'_>) -> io::Result<libc::stat> {
    // SAFETY: stat is plain data; fstat fills it in.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `st` is writable; `fd` is open while borrowed.
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st)
}

fn pread(fd: BorrowedFd<'_>, buf: &mut [u8], at: u64) -> io::Result<usize> {
    let off =
        libc::off_t::try_from(at).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    loop {
        // SAFETY: `buf` is writable for its length.
        let n = unsafe { libc::pread(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), off) };
        if n >= 0 {
            return usize::try_from(n).map_err(|_| io::ErrorKind::InvalidData.into());
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn write_all_at(fd: BorrowedFd<'_>, mut buf: &[u8], mut at: u64) -> io::Result<()> {
    while !buf.is_empty() {
        let off =
            libc::off_t::try_from(at).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: `buf` is readable for its length.
        let n = unsafe { libc::pwrite(fd.as_raw_fd(), buf.as_ptr().cast(), buf.len(), off) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        let n = usize::try_from(n).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        buf = &buf[n..];
        at += n as u64;
    }
    Ok(())
}

/// The device and inode of the file `fd` refers to.
///
/// # Errors
/// `fstat`'s.
pub fn file_key(fd: BorrowedFd<'_>) -> io::Result<(u64, u64)> {
    let st = fstat(fd)?;
    #[allow(clippy::unnecessary_cast)]
    Ok((st.st_dev as u64, st.st_ino as u64))
}

/// Reads `fd` from `at` into `buf` (`pread`): how many bytes, 0 at the end
/// of the file.
///
/// # Errors
/// `pread`'s.
pub fn read_at(fd: BorrowedFd<'_>, buf: &mut [u8], at: u64) -> io::Result<usize> {
    pread(fd, buf, at)
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd;

    use super::*;

    fn wait_code(child: OwnedChild) -> Option<i32> {
        child.reap().ok().and_then(|s| s.code())
    }

    /// A child gets the descriptors it is handed at their numbers and
    /// nothing else from this process, and only the environment given.
    #[test]
    fn a_child_gets_its_descriptors_and_environment_only() {
        let (r, w) = crate::pipe_cloexec().unwrap();
        // Descriptor 7 open in the child, 8 and above closed.
        let script =
            b"test -e /dev/fd/7 && ! test -e /dev/fd/8 && echo \"$ONLY:${HOME-unset}\" >&7";
        let child = spawn(&Spawn {
            program: Program::Path(b"/bin/sh"),
            argv: &[b"sh", b"-c", script],
            env: &[b"ONLY=here"],
            fds: &[(w.as_fd(), 7)],
            cwd: None,
            session: Session::Group,
            suspended: false,
        })
        .unwrap();
        drop(w);
        let mut out = String::new();
        std::io::Read::read_to_string(&mut std::fs::File::from(r), &mut out).unwrap();
        assert_eq!(wait_code(child), Some(0));
        assert_eq!(out, "here:unset\n");
    }

    /// The working directory is the one the descriptor names, and a
    /// program that cannot be run is an `Exec` error with nothing left
    /// running.
    #[test]
    fn the_directory_is_the_descriptors_and_a_missing_program_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = std::fs::canonicalize(dir.path()).unwrap();
        let d = std::fs::File::open(&canonical).unwrap();
        let (r, w) = crate::pipe_cloexec().unwrap();
        let child = spawn(&Spawn {
            program: Program::Path(b"/bin/sh"),
            argv: &[b"sh", b"-c", b"pwd -P"],
            env: &[],
            fds: &[(w.as_fd(), 1)],
            cwd: Some(d.as_fd()),
            session: Session::New,
            suspended: false,
        })
        .unwrap();
        drop(w);
        let mut out = String::new();
        std::io::Read::read_to_string(&mut std::fs::File::from(r), &mut out).unwrap();
        assert_eq!(wait_code(child), Some(0));
        assert_eq!(out.trim_end(), canonical.to_str().unwrap());
        let e = spawn(&Spawn {
            program: Program::Path(b"/nonexistent/envcloak-test"),
            argv: &[b"x"],
            env: &[],
            fds: &[],
            cwd: None,
            session: Session::Group,
            suspended: false,
        })
        .unwrap_err();
        assert!(
            matches!(e, SpawnError::Exec(ref io) if io.kind() == io::ErrorKind::NotFound),
            "{e:?}"
        );
    }

    /// Malformed requests are refused before anything starts.
    #[test]
    fn malformed_requests_are_refused() {
        let (_r, w) = crate::pipe_cloexec().unwrap();
        for fds in [
            &[(w.as_fd(), 10)][..],
            &[(w.as_fd(), -1)],
            &[(w.as_fd(), 3), (w.as_fd(), 3)],
        ] {
            let e = spawn(&Spawn {
                program: Program::Path(b"/bin/sh"),
                argv: &[b"sh"],
                env: &[],
                fds,
                cwd: None,
                session: Session::Group,
                suspended: false,
            })
            .unwrap_err();
            assert!(matches!(e, SpawnError::Setup(_)), "{e:?}");
        }
        let e = spawn(&Spawn {
            program: Program::Path(b"/bin/sh"),
            argv: &[b"sh", b"a\0b"],
            env: &[],
            fds: &[],
            cwd: None,
            session: Session::Group,
            suspended: false,
        })
        .unwrap_err();
        assert!(matches!(e, SpawnError::Setup(_)));
    }

    /// Linux: the sealed copy refuses a write, growth and shrinking, keeps
    /// every seal, holds the source's bytes, and runs.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn a_sealed_copy_cannot_change_and_runs() {
        let src = std::fs::File::open("/bin/true").unwrap();
        let image = SealedImage::copy_from(src.as_fd(), 512 << 20).unwrap();
        image.check_seals().unwrap();
        let fd = image.as_fd().as_raw_fd();
        // SAFETY: a write, a growth and a shrinking of the test's own copy.
        unsafe {
            assert_eq!(libc::pwrite(fd, b"x".as_ptr().cast(), 1, 0), -1);
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
            let len = libc::off_t::try_from(image.len()).unwrap();
            assert_eq!(libc::ftruncate(fd, len + 1), -1);
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
            assert_eq!(libc::ftruncate(fd, len - 1), -1);
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
        }
        let original = std::fs::read("/bin/true").unwrap();
        let mut copied = vec![0u8; original.len()];
        let mut at = 0;
        while at < copied.len() {
            let n = image.read_at(&mut copied[at..], at as u64).unwrap();
            assert!(n > 0);
            at += n;
        }
        assert_eq!(copied, original);
        let child = spawn(&Spawn {
            program: Program::Descriptor(image.as_fd()),
            argv: &[b"true"],
            env: &[],
            fds: &[],
            cwd: None,
            session: Session::Group,
            suspended: false,
        })
        .unwrap();
        assert_eq!(wait_code(child), Some(0));
    }
}
