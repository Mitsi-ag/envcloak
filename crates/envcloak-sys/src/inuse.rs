//! Whether another process has a file open (SPEC §6.4: plaintext is not
//! deleted while it is open elsewhere). Best effort: the answer is
//! [`InUse::Unknown`] where the system cannot tell, and callers treat that
//! as unknown.
//!
//! The question is about the open file itself, never a path the caller
//! remembers: a path can name another file by the time it is asked about
//! (the directory above it renamed, another file put in its place).
//! - Linux: a write lease (`fcntl(F_SETLEASE, F_WRLCK)`) on the
//!   descriptor is granted only when no other open file description
//!   refers to the file, so a refusal with `EAGAIN` means someone else has
//!   it open. The lease is dropped at once. File systems without leases
//!   (NFS, some FUSE and overlay mounts) refuse with another error:
//!   unknown.
//! - macOS: the descriptor's current path (`fcntl(F_GETPATH)`), checked
//!   before and after to name this file (device and inode), is given to
//!   `proc_listpidspath(3)`, which lists the processes with it open among
//!   those this user may inspect (its own), leaving out this process and
//!   event-only opens (Finder's watchers). When the path does not name
//!   the file, the answer would be about another file:
//!   [`InUse::Unmatched`], and callers keep the file.
//!
//! Neither sees another user's processes, or a program that opens the
//! file just after the check.

use std::fs::File;

/// Whether another process has a file open ([`open_elsewhere`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InUse {
    /// No other process has it open, as far as the system can tell.
    No,
    /// Another process has it open.
    Yes,
    /// The system cannot tell (Linux: a file system without leases).
    Unknown,
    /// macOS: the file's current path, which the system is asked about,
    /// does not name the file (it was renamed or replaced meanwhile), or
    /// it has none. Callers keep the file.
    Unmatched,
}

/// Whether a process other than this one has `f` open. See the module
/// documentation. On Linux, this process's other descriptors for the file
/// count as opens too, so the caller holds only `f`.
pub fn open_elsewhere(f: &File) -> InUse {
    imp::open_elsewhere(f)
}

#[cfg(target_os = "linux")]
mod imp {
    use std::fs::File;
    use std::os::fd::AsRawFd;

    use super::InUse;

    pub fn open_elsewhere(f: &File) -> InUse {
        let fd = f.as_raw_fd();
        loop {
            // SAFETY: `f` keeps its descriptor open for the call;
            // F_SETLEASE takes an int argument.
            let r = unsafe { libc::fcntl(fd, libc::F_SETLEASE, libc::F_WRLCK) };
            if r == 0 {
                // SAFETY: as above; this drops the lease just taken.
                unsafe { libc::fcntl(fd, libc::F_SETLEASE, libc::F_UNLCK) };
                return InUse::No;
            }
            match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EAGAIN) => return InUse::Yes,
                _ => return InUse::Unknown,
            }
        }
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use std::ffi::{CStr, OsStr};
    use std::fs::File;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    use super::InUse;

    const PROC_ALL_PIDS: u32 = 1;
    const PROC_LISTPIDSPATH_EXCLUDE_EVTONLY: u32 = 2;
    /// Processes listed at most.
    const MAX_PIDS: usize = 4096;
    /// `MAXPATHLEN`: the buffer `F_GETPATH` fills.
    const MAX_PATH: usize = 1024;

    unsafe extern "C" {
        // libproc.h, in libSystem.
        fn proc_listpidspath(
            r#type: u32,
            typeinfo: u32,
            path: *const libc::c_char,
            pathflags: u32,
            buffer: *mut libc::c_void,
            buffersize: libc::c_int,
        ) -> libc::c_int;
    }

    /// The path the system has for the open file now, NUL-terminated.
    fn current_path(f: &File) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; MAX_PATH];
        // SAFETY: `f` keeps its descriptor open for the call; F_GETPATH
        // writes a NUL-terminated path of at most MAXPATHLEN bytes into
        // the buffer, which holds that many.
        let r = unsafe { libc::fcntl(f.as_raw_fd(), libc::F_GETPATH, buf.as_mut_ptr()) };
        if r == -1 {
            return None;
        }
        let end = buf.iter().position(|&b| b == 0)?;
        buf.truncate(end + 1);
        Some(buf)
    }

    /// Whether `path` names the file with this device and inode, without
    /// following a symlink.
    fn names(path: &CStr, id: (u64, u64)) -> bool {
        std::fs::symlink_metadata(Path::new(OsStr::from_bytes(path.to_bytes())))
            .is_ok_and(|m| (m.dev(), m.ino()) == id)
    }

    /// Whether a process other than this one has `path` open: `None` when
    /// the system cannot say.
    fn listed(path: &CStr) -> Option<bool> {
        let mut pids = vec![0 as libc::pid_t; MAX_PIDS];
        let size = libc::c_int::try_from(pids.len() * size_of::<libc::pid_t>()).ok()?;
        // SAFETY: `path` is NUL-terminated and outlives the call; `pids`
        // is a writable buffer of `size` bytes, which the call fills with
        // pids.
        let n = unsafe {
            proc_listpidspath(
                PROC_ALL_PIDS,
                0,
                path.as_ptr(),
                PROC_LISTPIDSPATH_EXCLUDE_EVTONLY,
                pids.as_mut_ptr().cast(),
                size,
            )
        };
        let bytes = usize::try_from(n).ok()?;
        let count = (bytes / size_of::<libc::pid_t>()).min(pids.len());
        let me = libc::pid_t::try_from(std::process::id()).ok()?;
        Some(pids[..count].iter().any(|&p| p > 0 && p != me))
    }

    pub fn open_elsewhere(f: &File) -> InUse {
        let Ok(m) = f.metadata() else {
            return InUse::Unmatched;
        };
        let id = (m.dev(), m.ino());
        let Some(buf) = current_path(f) else {
            return InUse::Unmatched;
        };
        let Ok(path) = CStr::from_bytes_with_nul(&buf) else {
            return InUse::Unmatched;
        };
        if !names(path, id) {
            return InUse::Unmatched;
        }
        let answer = listed(path);
        // Still this file at that path after the question: the answer is
        // about it.
        if !names(path, id) {
            return InUse::Unmatched;
        }
        match answer {
            Some(true) => InUse::Yes,
            Some(false) => InUse::No,
            None => InUse::Unknown,
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod imp {
    use std::fs::File;

    use super::InUse;

    pub fn open_elsewhere(_f: &File) -> InUse {
        InUse::Unknown
    }
}
