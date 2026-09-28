//! Descriptors named by number (SPEC §5 "Unlockers": the Recovery Kit is
//! written only to the terminal or to a file descriptor the user named;
//! "Unlock flow": the passphrase comes from stdin or another descriptor
//! only with an explicit `--passphrase-fd`).

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

/// A new descriptor for the open file that the inherited descriptor `n`
/// refers to, made with `fcntl` and `F_DUPFD_CLOEXEC`, so it has the
/// close-on-exec flag. The original stays open and untouched; dropping the
/// copy closes only the copy.
///
/// # Errors
/// [`io::ErrorKind::InvalidInput`] for a negative number, and `EBADF`
/// when `n` is not an open descriptor.
pub fn inherited_fd(n: i32) -> io::Result<OwnedFd> {
    if n < 0 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    // The copy gets a number above the standard streams.
    // SAFETY: fcntl on any integer only reports EBADF for one that is not
    // open; F_DUPFD_CLOEXEC creates a new descriptor this process owns.
    let fd = unsafe { libc::fcntl(n, libc::F_DUPFD_CLOEXEC, 3) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just created and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Whether `fd` has the close-on-exec flag set.
///
/// # Errors
/// When `fcntl` fails.
pub fn cloexec_flag(fd: BorrowedFd<'_>) -> io::Result<bool> {
    // SAFETY: F_GETFD only reads the descriptor's flags.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(flags & libc::FD_CLOEXEC != 0)
}
