//! Spawning owned child processes with explicit descriptor mappings, session
//! leadership, `RLIMIT_CORE = 0`, and `PR_SET_PDEATHSIG` on Linux (M2 plan
//! D-34, F-73, task M2b-07).
//!
//! Used by `envcloak-browser::reaper` to launch the pinned headless Chrome for
//! Testing worker process in its own session (`setsid`) with only descriptors
//! 3 and 4 (`--remote-debugging-pipe`) inherited and every other descriptor
//! closed, returning an [`OwnedChild`] handle.

use std::ffi::{OsStr, OsString, c_char};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use zeroize::Zeroizing;

use crate::owned::OwnedChild;
use crate::pty_monitor::{LAST_SIGNAL, close_from, disposition, errno, set_mask};

/// Maximum target descriptor number accepted by [`spawn_with_fds`].
pub const MAX_SPAWN_FD: RawFd = 15;

/// Options for [`spawn_with_fds`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SpawnOpts {
    /// Start the child as a new session and process-group leader (`setsid`).
    /// When `false`, the child leads a new process group (`setpgid(0, 0)`) in
    /// the caller's session.
    pub new_session: bool,
    /// On Linux, set `PR_SET_PDEATHSIG` to this signal in the child immediately
    /// after `fork` (from the caller's thread) and verify that `getppid()` has
    /// not already changed. Ignored on non-Linux platforms.
    pub pdeathsig: Option<i32>,
}

/// Command specification for [`spawn_with_fds`].
#[derive(Debug, Clone)]
pub struct SpawnCommand {
    /// Executable path.
    pub program: PathBuf,
    /// Arguments after `argv[0]`.
    pub args: Vec<OsString>,
    /// Complete environment (`NAME`, `VALUE`) for the child; nothing is
    /// inherited from the calling process.
    pub env: Vec<(OsString, OsString)>,
    /// Working directory for the child, if any.
    pub cwd: Option<PathBuf>,
    /// Set `RLIMIT_CORE = (0, 0)` in the child before `execve`.
    pub rlimit_core_zero: bool,
}

impl SpawnCommand {
    /// Creates a new [`SpawnCommand`] for `program` with a cleared environment
    /// and `rlimit_core_zero = true`.
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
            rlimit_core_zero: true,
        }
    }

    /// Appends one argument.
    pub fn arg(&mut self, arg: impl AsRef<OsStr>) -> &mut Self {
        self.args.push(arg.as_ref().to_os_string());
        self
    }

    /// Appends multiple arguments.
    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        for a in args {
            self.args.push(a.as_ref().to_os_string());
        }
        self
    }

    /// Sets one environment variable in the child's cleared environment.
    pub fn env(&mut self, key: impl AsRef<OsStr>, val: impl AsRef<OsStr>) -> &mut Self {
        let k = key.as_ref();
        self.env.retain(|(ek, _)| ek != k);
        self.env
            .push((k.to_os_string(), val.as_ref().to_os_string()));
        self
    }

    /// Sets the child's working directory.
    pub fn current_dir(&mut self, dir: impl Into<PathBuf>) -> &mut Self {
        self.cwd = Some(dir.into());
        self
    }
}

struct CStringTable {
    owned: Vec<Zeroizing<Vec<u8>>>,
    ptrs: Vec<*const c_char>,
}

impl CStringTable {
    fn from_slices(slices: &[Vec<u8>]) -> io::Result<Self> {
        let mut owned = Vec::with_capacity(slices.len());
        for s in slices {
            if s.contains(&0) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "NUL byte in spawn string",
                ));
            }
            let mut buf = Zeroizing::new(Vec::with_capacity(s.len() + 1));
            buf.extend_from_slice(s);
            buf.push(0);
            owned.push(buf);
        }
        let ptrs = owned
            .iter()
            .map(|c| c.as_ptr().cast::<c_char>())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        Ok(Self { owned, ptrs })
    }

    fn as_ptr(&self) -> *const *const c_char {
        self.ptrs.as_ptr()
    }
}

/// Spawns `cmd` with explicit descriptor mappings `fd_map` (`(src_fd, dst_fd)`)
/// and [`SpawnOpts`], returning an [`OwnedChild`].
///
/// Any of standard input (`0`), standard output (`1`), and standard error (`2`)
/// not listed in `fd_map` are connected to `/dev/null`. Every other descriptor
/// not listed as a `dst_fd` in `fd_map` is closed before `execve`.
///
/// # Errors
/// Returns an error if `fd_map` contains a negative or duplicate target
/// descriptor or exceeds [`MAX_SPAWN_FD`], if `SIGCHLD` cannot be configured to
/// keep children unreaped, or if `fork`/child setup/`execve` fails.
pub fn spawn_with_fds(
    cmd: &SpawnCommand,
    fd_map: &[(RawFd, RawFd)],
    opts: SpawnOpts,
) -> io::Result<OwnedChild> {
    let mut seen = [false; (MAX_SPAWN_FD + 1) as usize];
    for &(src, dst) in fd_map {
        if src < 0 || !(0..=MAX_SPAWN_FD).contains(&dst) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "spawn descriptor out of range",
            ));
        }
        let idx = dst as usize;
        if seen[idx] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "duplicate target descriptor in spawn_with_fds",
            ));
        }
        seen[idx] = true;
    }

    let devnull = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")?;
    let devnull_fd = devnull.as_raw_fd();

    let mut full_map = [(0 as RawFd, 0 as RawFd); (MAX_SPAWN_FD + 1) as usize];
    let mut map_len = 0usize;
    for std_fd in 0..=2 {
        if !seen[std_fd as usize] {
            full_map[map_len] = (devnull_fd, std_fd);
            seen[std_fd as usize] = true;
            map_len += 1;
        }
    }
    for &pair in fd_map {
        full_map[map_len] = pair;
        map_len += 1;
    }

    let prog_bytes = cmd.program.as_os_str().as_bytes().to_vec();
    let prog_table = CStringTable::from_slices(std::slice::from_ref(&prog_bytes))?;

    let mut argv_vecs = Vec::with_capacity(1 + cmd.args.len());
    argv_vecs.push(prog_bytes);
    for a in &cmd.args {
        argv_vecs.push(a.as_bytes().to_vec());
    }
    let argv_table = CStringTable::from_slices(&argv_vecs)?;

    let mut env_vecs = Vec::with_capacity(cmd.env.len());
    for (k, v) in &cmd.env {
        let kb = k.as_bytes();
        let vb = v.as_bytes();
        if kb.is_empty() || kb.contains(&b'=') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid environment variable name",
            ));
        }
        let mut line = Vec::with_capacity(kb.len() + 1 + vb.len());
        line.extend_from_slice(kb);
        line.push(b'=');
        line.extend_from_slice(vb);
        env_vecs.push(line);
    }
    let env_table = CStringTable::from_slices(&env_vecs)?;

    let cwd_table = match &cmd.cwd {
        Some(dir) => Some(CStringTable::from_slices(&[dir
            .as_os_str()
            .as_bytes()
            .to_vec()])?),
        None => None,
    };

    crate::owned::keep_children_unreaped()?;
    let (err_read, err_write) = crate::pipe_cloexec()?;
    // SAFETY: getpid has no preconditions.
    let parent_pid = unsafe { libc::getpid() };

    let prepared = ChildPrepared {
        prog: prog_table.owned[0].as_ptr().cast::<c_char>(),
        argv: argv_table.as_ptr(),
        envp: env_table.as_ptr(),
        cwd: cwd_table
            .as_ref()
            .map_or(std::ptr::null(), |c| c.owned[0].as_ptr().cast::<c_char>()),
        fds: full_map,
        nfds: map_len,
        new_session: opts.new_session,
        pdeathsig: opts.pdeathsig.unwrap_or(0),
        parent_pid,
        rlimit_core_zero: cmd.rlimit_core_zero,
        err_fd: err_write.as_raw_fd(),
    };

    // SAFETY: fork has no preconditions; child runs only async-signal-safe
    // `child_exec` and never returns.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        // SAFETY: fresh single-threaded child process after fork; pointers in
        // `prepared` remain valid until `execve` or `_exit`.
        unsafe { child_exec(&prepared) };
    }

    let child = OwnedChild::from_fork(pid);
    drop(err_write);
    drop(devnull);

    let mut report = [0u8; 4];
    let mut got = 0usize;
    let mut err_file = std::fs::File::from(err_read);
    while got < report.len() {
        match std::io::Read::read(&mut err_file, &mut report[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                let _ = child.kill_and_reap();
                return Err(e);
            }
        }
    }
    if got == 0 {
        return Ok(child);
    }
    let _ = child.reap();
    let code = if got == 4 {
        i32::from_ne_bytes(report)
    } else {
        libc::EIO
    };
    Err(io::Error::from_raw_os_error(code))
}

struct ChildPrepared {
    prog: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
    cwd: *const c_char,
    fds: [(RawFd, RawFd); (MAX_SPAWN_FD + 1) as usize],
    nfds: usize,
    new_session: bool,
    pdeathsig: i32,
    #[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
    parent_pid: libc::pid_t,
    rlimit_core_zero: bool,
    err_fd: RawFd,
}

fn child_fail(err_fd: RawFd, code: i32) -> ! {
    let bytes = code.to_ne_bytes();
    // SAFETY: writes stack bytes to `err_fd` and exits immediately.
    unsafe {
        let _ = libc::write(err_fd, bytes.as_ptr().cast(), bytes.len());
        libc::_exit(127);
    }
}

/// Async-signal-safe child setup and `execve`. Never allocates and never returns.
///
/// # Safety
/// Must be called only in the child immediately after `fork`.
unsafe fn child_exec(p: &ChildPrepared) -> ! {
    set_mask(libc::SIG_SETMASK, true, &[]);
    for sig in 1..=LAST_SIGNAL {
        if sig != libc::SIGKILL && sig != libc::SIGSTOP {
            disposition(sig, libc::SIG_DFL);
        }
    }

    // SAFETY: setsid / setpgid on the new child process.
    let session_ok = unsafe {
        if p.new_session {
            libc::setsid() >= 0
        } else {
            libc::setpgid(0, 0) == 0
        }
    };
    if !session_ok {
        child_fail(p.err_fd, errno());
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    if p.pdeathsig > 0 {
        // SAFETY: prctl(PR_SET_PDEATHSIG) sets the parent-death signal for this child.
        let rc = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, p.pdeathsig, 0, 0, 0) };
        if rc != 0 {
            child_fail(p.err_fd, errno());
        }
        // SAFETY: getppid has no preconditions; if parent died before prctl, exit immediately.
        if unsafe { libc::getppid() } != p.parent_pid {
            // SAFETY: _exit is async-signal-safe and terminates the child immediately.
            unsafe { libc::_exit(127) };
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let _ = p.pdeathsig;

    if p.rlimit_core_zero {
        let zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: setrlimit with a valid rlimit struct on the stack.
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) } != 0 {
            child_fail(p.err_fd, errno());
        }
    }

    if !p.cwd.is_null() {
        // SAFETY: `p.cwd` points to a NUL-terminated path prepared before fork.
        if unsafe { libc::chdir(p.cwd) } != 0 {
            child_fail(p.err_fd, errno());
        }
    }

    let max_target = p.fds[..p.nfds]
        .iter()
        .map(|&(_, dst)| dst)
        .max()
        .unwrap_or(2)
        .max(2);
    let report_at = max_target + 1;
    let high_base = max_target + 2;

    let dup_high = |fd: RawFd| -> RawFd {
        // SAFETY: F_DUPFD_CLOEXEC duplicates `fd` to >= `high_base` with FD_CLOEXEC.
        let n = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, high_base) };
        if n < 0 {
            child_fail(p.err_fd, errno());
        }
        n
    };

    let err_high = dup_high(p.err_fd);
    let mut moved = [-1 as RawFd; (MAX_SPAWN_FD + 1) as usize];
    for (i, slot) in moved.iter_mut().enumerate().take(p.nfds) {
        *slot = dup_high(p.fds[i].0);
    }

    // SAFETY: dup2 and fcntl on descriptors owned by this child.
    unsafe {
        for (i, &src_high) in moved.iter().enumerate().take(p.nfds) {
            let dst = p.fds[i].1;
            if libc::dup2(src_high, dst) < 0 {
                child_fail(err_high, errno());
            }
            // Ensure FD_CLOEXEC is cleared on explicitly inherited target descriptors.
            let flags = libc::fcntl(dst, libc::F_GETFD);
            if flags < 0 || libc::fcntl(dst, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                child_fail(err_high, errno());
            }
        }
        if libc::dup2(err_high, report_at) < 0
            || libc::fcntl(report_at, libc::F_SETFD, libc::FD_CLOEXEC) < 0
        {
            child_fail(err_high, errno());
        }
    }

    let mut fd: RawFd = 0;
    while fd < report_at {
        if !p.fds[..p.nfds].iter().any(|&(_, dst)| dst == fd) {
            // SAFETY: closes non-target descriptors below `report_at`.
            unsafe { libc::close(fd) };
        }
        fd += 1;
    }
    if let Err(e) = close_from(report_at + 1) {
        child_fail(report_at, e);
    }

    set_mask(libc::SIG_SETMASK, false, &[]);

    // SAFETY: `prog`, `argv`, and `envp` are valid NUL-terminated strings and
    // null-terminated pointer arrays prepared before fork.
    unsafe {
        libc::execve(p.prog, p.argv, p.envp);
    }
    child_fail(report_at, errno())
}

/// Marks the calling process as a child subreaper on Linux
/// (`prctl(PR_SET_CHILD_SUBREAPER, 1)`), so any descendant of Chrome that
/// outlives its parent is reparented to the reaper rather than PID 1.
/// No-op on non-Linux systems.
///
/// # Errors
/// Returns the OS error if `prctl` fails on Linux.
pub fn set_child_subreaper() -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // SAFETY: PR_SET_CHILD_SUBREAPER takes integer arguments and has no memory safety preconditions.
        let rc = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Reaps any remaining reparented child processes (`waitpid(-1, ..., WNOHANG)`)
/// after the primary owned child has already been reaped by the reaper process.
/// Returns the number of reparented descendants reaped.
///
/// # Errors
/// Returns an OS error if `waitpid` fails with an error other than `ECHILD` or
/// `EINTR`.
pub fn reap_reparented_children(timeout: std::time::Duration) -> io::Result<usize> {
    let deadline = std::time::Instant::now() + timeout;
    let mut count = 0usize;
    loop {
        let mut status: libc::c_int = 0;
        // SAFETY: status is a valid stack int; waitpid(-1) reaps any exited child of this subreaper.
        let rc = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if rc > 0 {
            count += 1;
            continue;
        }
        if rc == 0 {
            if std::time::Instant::now() >= deadline {
                return Ok(count);
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
            continue;
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ECHILD) {
            return Ok(count);
        }
        if err.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(err);
    }
}

/// Recursively removes a directory named `name` beneath `parent_dir` without
/// following symlinks (`unlink_beneath`, `remove_dir_beneath`, `open_dir_beneath`),
/// and verifies that `name` is no longer present (`kind_beneath` returns `NotFound`).
///
/// # Errors
/// Returns an error if any entry cannot be listed, unlinked, or removed, or if
/// `name` still exists after removal.
pub fn remove_tree_beneath_and_verify(parent_dir: &File, name: &OsStr) -> io::Result<()> {
    crate::fail_point("signin.reaper.remove_profile")?;

    remove_entry_beneath(parent_dir, name, 0)?;

    match crate::kind_beneath(parent_dir, name) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::DirectoryNotEmpty,
            "profile directory still exists after removal",
        )),
        Err(e) => Err(e),
    }
}

const MAX_REMOVE_DEPTH: usize = 32;

fn remove_entry_beneath(parent_dir: &File, name: &OsStr, depth: usize) -> io::Result<()> {
    if depth > MAX_REMOVE_DEPTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "directory nesting exceeds maximum removal depth",
        ));
    }
    let kind = match crate::kind_beneath(parent_dir, name) {
        Ok(k) => k,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if kind == crate::DirEntryKind::Dir {
        let sub = crate::open_dir_beneath(parent_dir, name)?;
        let entries = crate::list_dir(&sub, crate::MAX_DIR_ENTRIES)?;
        for entry in entries {
            remove_entry_beneath(&sub, &entry.name, depth + 1)?;
        }
        drop(sub);
        crate::remove_dir_beneath(parent_dir, name)?;
    } else {
        // Symlinks, regular files, sockets, FIFOs: unlinked as a link/entry without following.
        crate::unlink_beneath(parent_dir, name)?;
    }
    Ok(())
}
