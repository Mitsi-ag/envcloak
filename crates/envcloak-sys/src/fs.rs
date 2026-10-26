//! Opening a file through a directory handle (SPEC §6.1 step 2: the daemon
//! opens the manifest itself; §6.4 "Filesystem safety": scans open from a
//! directory handle with `O_NOFOLLOW` and `O_NONBLOCK`).
//!
//! A path is looked up again on every use, so a directory checked by path
//! can be swapped before the file in it is opened. [`open_beneath`] opens
//! the file relative to a directory the caller already holds open, so what
//! it opens is in that directory, whatever has happened to the path since.

use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// Opens `path` read-only with `O_NOFOLLOW | O_NONBLOCK | O_NOCTTY | O_CLOEXEC`,
/// verifies via `fstat` ([`File::metadata`]) on the opened descriptor that it
/// is a regular file, clears `O_NONBLOCK`, and returns the [`File`].
///
/// Never follows a terminal symlink and never blocks on a FIFO or device node.
///
/// # Errors
/// Returns an [`io::Error`] if `path` contains a NUL byte, if `open` fails
/// (including `ELOOP` on a symlink), if the opened descriptor is not a regular
/// file, or if `fcntl` fails.
pub fn open_regular_nofollow(path: &Path) -> io::Result<File> {
    let b = path.as_os_str().as_bytes();
    if b.is_empty() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let c = CString::new(b).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let flags =
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC;
    // SAFETY: `c` is a NUL-terminated path that outlives `open`. `open` returns
    // a new file descriptor or -1 on error.
    let fd = unsafe { libc::open(c.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by `open`, is open, and nothing else owns it.
    let file = File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    // SAFETY: `F_GETFL` reads flags on `file`'s open descriptor.
    let fl = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if fl < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `F_SETFL` clears `O_NONBLOCK` on the newly opened regular file description.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, fl & !libc::O_NONBLOCK) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}

/// Opens `name` in the directory `dir`, read-only, with `openat(2)`:
/// - `O_NOFOLLOW`: a symlink in its place fails with `ELOOP` and is never
///   followed, dangling or not;
/// - `O_NONBLOCK`: a FIFO opens without waiting for a writer (a regular
///   file ignores the flag);
/// - `O_NOCTTY` and `O_CLOEXEC`.
///
/// `name` must be one path component: not empty, not `.` or `..`, and
/// without `/` or NUL, or the call fails with
/// [`io::ErrorKind::InvalidInput`]. The caller checks with `fstat` what it
/// opened ([`File::metadata`]): a directory, FIFO or device opens too.
pub fn open_beneath(dir: &File, name: &OsStr) -> io::Result<File> {
    let b = name.as_bytes();
    if b.is_empty() || b == b"." || b == b".." || b.contains(&b'/') {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let c = CString::new(b).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let flags =
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC;
    // SAFETY: `dir` keeps its descriptor open for the whole call, and `c` is
    // a NUL-terminated string that outlives it. openat reads both and
    // returns a new descriptor or -1.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by openat, is open, and nothing else
    // owns it.
    Ok(File::from(unsafe { OwnedFd::from_raw_fd(fd) }))
}
