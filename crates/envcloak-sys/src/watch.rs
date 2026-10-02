//! [`ProcessWatch`]: whether one process instance still runs, asked as
//! often as a caller needs, for a process the caller does not own (a
//! client of the daemon).
//!
//! - Linux: a pidfd (`pidfd_open`, Linux 5.3), taken for the pid and kept
//!   only once the process under that pid is shown to be the instance
//!   watched (its start time, read after the pidfd was taken). The pidfd
//!   becomes readable when that process exits, zombie or reaped, and never
//!   comes to name another process, so the answer needs no read of
//!   `/proc` by pid. Where `pidfd_open` fails (an older kernel, a seccomp
//!   filter, no descriptor left), the watch falls back to
//!   [`crate::process_running`].
//! - macOS, which has no pidfd: [`crate::process_running`] each time (the
//!   pid, the start time and the state from one `KERN_PROC_PID` read).
//!
//! Either way a process that exited and is not yet reaped no longer runs.
//! A watch holds no authority over the process: it is never signalled
//! through one.

use crate::peer::StartTime;

/// One process instance (a pid and the start time it had), watched for
/// its exit. See the module documentation.
pub struct ProcessWatch {
    pid: i32,
    start: StartTime,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pidfd: Option<std::os::fd::OwnedFd>,
}

impl core::fmt::Debug for ProcessWatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProcessWatch")
            .field("pid", &self.pid)
            .field("start", &self.start)
            .field("pidfd", &self.has_pidfd())
            .finish()
    }
}

impl ProcessWatch {
    /// Watches process `pid` as the instance that started at `start`. A
    /// pid that another process holds now, or none, makes a watch that
    /// never runs: the instance has exited.
    pub fn new(pid: i32, start: StartTime) -> ProcessWatch {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            // The pidfd names whatever process had the pid when it was
            // taken. Read after it, a start time of `start` with the pid
            // shows that process is the instance: the instance started
            // before this call, so it held the pid then, and a process
            // keeps its pid until it is reaped.
            let pidfd = linux::pidfd_open(pid)
                .ok()
                .filter(|_| crate::process_running(pid, start));
            ProcessWatch { pid, start, pidfd }
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            ProcessWatch { pid, start }
        }
    }

    /// The pid watched.
    pub fn pid(&self) -> i32 {
        self.pid
    }

    /// The start time watched.
    pub fn start_time(&self) -> StartTime {
        self.start
    }

    /// Whether the watch holds a pidfd (Linux), rather than reading the
    /// process table by pid each time.
    pub fn has_pidfd(&self) -> bool {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            self.pidfd.is_some()
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            false
        }
    }

    /// Whether the instance still runs: it has not exited, reaped or not.
    /// Fails closed: an answer that cannot be read is `false`.
    pub fn running(&self) -> bool {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(fd) = &self.pidfd {
            return linux::pidfd_alive(fd).unwrap_or(false);
        }
        crate::process_running(self.pid, self.start)
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) mod linux {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    /// `pidfd_open(pid, 0)`: a pidfd for the process that has `pid` now,
    /// close-on-exec.
    pub(crate) fn pidfd_open(pid: i32) -> io::Result<OwnedFd> {
        if pid <= 0 {
            return Err(io::ErrorKind::NotFound.into());
        }
        // SAFETY: `pidfd_open` takes a pid and a flags word and returns a
        // new descriptor or -1; no memory is passed.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = libc::c_int::try_from(fd)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "a pidfd out of range"))?;
        // SAFETY: the kernel just created `fd` for this process, which owns
        // it and nothing else does.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// Whether the process `pidfd` refers to is still running: its pidfd
    /// becomes readable when it exits.
    pub(crate) fn pidfd_alive(pidfd: &OwnedFd) -> io::Result<bool> {
        let mut p = libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            // SAFETY: one valid pollfd; a zero timeout never blocks.
            let n = unsafe { libc::poll(&mut p, 1, 0) };
            if n >= 0 {
                return Ok(n == 0);
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }
}
