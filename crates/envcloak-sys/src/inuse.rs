//! Whether another process has a file open (SPEC §6.4: plaintext is not
//! deleted while it is open elsewhere). Best effort: the answer is `None`
//! where the system cannot tell, and callers treat that as unknown.
//!
//! - Linux: a write lease (`fcntl(F_SETLEASE, F_WRLCK)`) is granted only
//!   when no other open file description refers to the file, so a
//!   refusal with `EAGAIN` means someone else has it open. The lease is
//!   dropped at once. File systems without leases (NFS, some FUSE and
//!   overlay mounts) refuse with another error: unknown.
//! - macOS: `proc_listpidspath(3)` lists the processes with the file open
//!   among those this user may inspect (its own), leaving out this
//!   process and event-only opens (Finder's watchers).
//!
//! Neither sees another user's processes, or a program that opens the
//! file just after the check.

use std::fs::File;
use std::path::Path;

/// Whether a process other than this one has `f` (open at `path`) open:
/// `Some(true)` or `Some(false)` when the system can tell, `None` when it
/// cannot. On Linux, this process's other descriptors for the file count
/// as opens too, so the caller holds only `f`.
pub fn open_elsewhere(f: &File, path: &Path) -> Option<bool> {
    imp::open_elsewhere(f, path)
}

#[cfg(target_os = "linux")]
mod imp {
    use std::fs::File;
    use std::os::fd::AsRawFd;
    use std::path::Path;

    pub fn open_elsewhere(f: &File, _path: &Path) -> Option<bool> {
        let fd = f.as_raw_fd();
        loop {
            // SAFETY: `f` keeps its descriptor open for the call;
            // F_SETLEASE takes an int argument.
            let r = unsafe { libc::fcntl(fd, libc::F_SETLEASE, libc::F_WRLCK) };
            if r == 0 {
                // SAFETY: as above; this drops the lease just taken.
                unsafe { libc::fcntl(fd, libc::F_SETLEASE, libc::F_UNLCK) };
                return Some(false);
            }
            match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EAGAIN) => return Some(true),
                _ => return None,
            }
        }
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use std::ffi::CString;
    use std::fs::File;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    const PROC_ALL_PIDS: u32 = 1;
    const PROC_LISTPIDSPATH_EXCLUDE_EVTONLY: u32 = 2;
    /// Processes listed at most.
    const MAX_PIDS: usize = 4096;

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

    pub fn open_elsewhere(_f: &File, path: &Path) -> Option<bool> {
        let c = CString::new(path.as_os_str().as_bytes()).ok()?;
        let mut pids = vec![0 as libc::pid_t; MAX_PIDS];
        let size = libc::c_int::try_from(pids.len() * size_of::<libc::pid_t>()).ok()?;
        // SAFETY: `c` is NUL-terminated and outlives the call; `pids` is a
        // writable buffer of `size` bytes, which the call fills with pids.
        let n = unsafe {
            proc_listpidspath(
                PROC_ALL_PIDS,
                0,
                c.as_ptr(),
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
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod imp {
    use std::fs::File;
    use std::path::Path;

    pub fn open_elsewhere(_f: &File, _path: &Path) -> Option<bool> {
        None
    }
}
