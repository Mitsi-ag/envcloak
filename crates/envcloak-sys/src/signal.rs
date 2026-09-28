//! Waiting for the signals that ask a process to stop (SPEC §5 "Lock":
//! the daemon locks on stop).
//!
//! [`TerminationSignals::block`] blocks `SIGTERM`, `SIGINT` and `SIGHUP` in
//! the calling thread. Threads spawned afterwards inherit the mask, so
//! when it runs first in `main`, before any thread exists, no thread ever
//! takes these signals asynchronously: they stay pending until a thread
//! collects one with [`TerminationSignals::wait`] (`sigwait`). The code
//! that runs in response is ordinary code on an ordinary thread, free to
//! lock a mutex, wipe keys and remove files, which a signal handler could
//! not safely do.

use std::io;

/// The blocked set: `SIGTERM`, `SIGINT` and `SIGHUP`.
pub struct TerminationSignals {
    set: libc::sigset_t,
}

impl core::fmt::Debug for TerminationSignals {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TerminationSignals(SIGTERM, SIGINT, SIGHUP)")
    }
}

impl TerminationSignals {
    /// The signals in the set.
    pub const SIGNALS: [i32; 3] = [libc::SIGTERM, libc::SIGINT, libc::SIGHUP];

    /// Blocks the set in the calling thread. Call it before spawning any
    /// thread, which then inherits the mask.
    ///
    /// # Errors
    /// When the mask cannot be changed.
    pub fn block() -> io::Result<Self> {
        // SAFETY: sigset_t is plain data; sigemptyset initializes it.
        let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
        // SAFETY: `set` is a valid, writable sigset_t.
        if unsafe { libc::sigemptyset(&mut set) } != 0 {
            return Err(io::Error::last_os_error());
        }
        for sig in Self::SIGNALS {
            // SAFETY: `set` was initialized above; `sig` is a valid signal.
            if unsafe { libc::sigaddset(&mut set, sig) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        // SAFETY: `set` is initialized; the old mask is not wanted.
        let rc = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) };
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc));
        }
        Ok(TerminationSignals { set })
    }

    /// Waits until one of the signals is pending for this thread or the
    /// process, takes it, and returns its number. The signals must be
    /// blocked in every thread, or another thread may take it first.
    ///
    /// # Errors
    /// When `sigwait` fails.
    pub fn wait(&self) -> io::Result<i32> {
        loop {
            let mut sig: libc::c_int = 0;
            // SAFETY: `self.set` is an initialized sigset_t and `sig` a
            // writable int.
            let rc = unsafe { libc::sigwait(&self.set, &mut sig) };
            match rc {
                0 => return Ok(sig),
                libc::EINTR => continue,
                e => return Err(io::Error::from_raw_os_error(e)),
            }
        }
    }
}
