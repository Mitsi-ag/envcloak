//! Making a file durable (SPEC §6.1 step 5: the audit entry is on disk
//! before any value is released).
//!
//! On macOS `fsync(2)` moves data to the drive but not out of the drive's
//! own cache, so a power loss can still lose it. `fcntl(F_FULLFSYNC)` asks
//! the drive to flush that cache too, and [`sync_file`] uses it there. A
//! file system that does not support it (some network and FAT volumes)
//! refuses the request; `fsync` is then the best there is, and the answer
//! says which one ran. On Linux `fsync` flushes the device's cache as well.
//!
//! With the `testing` feature, each call is counted per thread
//! ([`crate::testing::sync_counts`]), so a test can show which call a
//! write path made and how often.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;

/// The call [`sync_file`] made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyncMethod {
    /// macOS `fcntl(F_FULLFSYNC)`: out of the drive's cache as well.
    FullFsync,
    /// `fsync(2)`: Linux, or macOS on a file system without
    /// `F_FULLFSYNC`.
    Fsync,
}

/// Flushes `f`'s data and metadata to stable storage: `F_FULLFSYNC` on
/// macOS, falling back to `fsync` only when the file system does not
/// support it, and `fsync` elsewhere. `f` may be a directory, which makes
/// its entries durable.
///
/// # Errors
/// Any failure other than an unsupported `F_FULLFSYNC`. A caller that
/// promised durability must treat a failure as data not written.
pub fn sync_file(f: &File) -> io::Result<SyncMethod> {
    #[cfg(target_os = "macos")]
    loop {
        // SAFETY: `f` keeps its descriptor open for the call; F_FULLFSYNC
        // takes no argument and only flushes.
        if unsafe { libc::fcntl(f.as_raw_fd(), libc::F_FULLFSYNC) } != -1 {
            note(SyncMethod::FullFsync);
            return Ok(SyncMethod::FullFsync);
        }
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::ENOTSUP | libc::ENOTTY | libc::EINVAL) => break,
            _ => return Err(err),
        }
    }
    loop {
        // SAFETY: `f` keeps its descriptor open for the call.
        if unsafe { libc::fsync(f.as_raw_fd()) } == 0 {
            note(SyncMethod::Fsync);
            return Ok(SyncMethod::Fsync);
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(err);
        }
    }
}

#[cfg(feature = "testing")]
fn note(m: SyncMethod) {
    crate::testing::note_sync(m);
}

#[cfg(not(feature = "testing"))]
fn note(_: SyncMethod) {}
