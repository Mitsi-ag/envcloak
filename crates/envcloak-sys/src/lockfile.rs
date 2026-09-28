//! Advisory whole-file locks (SPEC §4.2: the daemon holds an exclusive
//! `flock` on `run/envcloakd.lock`, so a second instance refuses to start).
//!
//! `flock` locks belong to the open file description, so two separate
//! opens of the same file conflict even within one process, and the lock
//! goes away when the last descriptor for it closes, including when the
//! process dies.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;

/// Takes an exclusive `flock` on `file` without waiting. `Ok(true)` when
/// it was taken (or this open file description already held it),
/// `Ok(false)` when another open file description holds a lock on the
/// file.
///
/// # Errors
/// Any other failure of `flock`.
pub fn try_lock_exclusive(file: &File) -> io::Result<bool> {
    loop {
        // SAFETY: `file` keeps its descriptor open for the call.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(true);
        }
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EWOULDBLOCK) => return Ok(false),
            _ => return Err(err),
        }
    }
}
