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
//!
//! [`TerminationWatch`] is for a process that must keep taking these
//! signals but has something to put back first: the CLI reading a
//! passphrase has the terminal in secret-input mode, and a `SIGTERM` that
//! ended the process there would leave the terminal without echo. The watch
//! installs handlers that only record the signal; without `SA_RESTART`, a
//! blocking read returns `EINTR`, the reader sees the record, restores the
//! terminal, and then [`exit_by_signal`] ends the process the way the
//! signal would have.

use std::io;
use std::sync::atomic::{AtomicI32, Ordering};

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

/// The signal a [`TerminationWatch`] recorded, or 0.
static RECORDED: AtomicI32 = AtomicI32::new(0);

extern "C" fn record(sig: libc::c_int) {
    // Only a store to an atomic: async-signal-safe.
    RECORDED.store(sig, Ordering::SeqCst);
}

/// Handlers for `SIGTERM`, `SIGINT` and `SIGHUP` that record the signal
/// instead of ending the process, installed for as long as the value
/// lives. The previous dispositions come back on drop.
pub struct TerminationWatch {
    saved: Vec<(i32, libc::sigaction)>,
}

impl core::fmt::Debug for TerminationWatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TerminationWatch(SIGTERM, SIGINT, SIGHUP)")
    }
}

impl TerminationWatch {
    /// Installs the recording handlers, with `SA_RESTART` off so a blocking
    /// read returns `EINTR` when one fires. Clears any earlier record.
    ///
    /// # Errors
    /// When a handler cannot be installed; nothing stays installed then.
    pub fn install() -> io::Result<Self> {
        RECORDED.store(0, Ordering::SeqCst);
        let mut watch = TerminationWatch {
            saved: Vec::with_capacity(3),
        };
        for sig in TerminationSignals::SIGNALS {
            // SAFETY: sigaction is plain data; every field is set below or
            // stays zero, which is a valid empty value.
            let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
            act.sa_sigaction = record as extern "C" fn(libc::c_int) as libc::sighandler_t;
            act.sa_flags = 0;
            // SAFETY: `act.sa_mask` is a writable sigset_t.
            if unsafe { libc::sigemptyset(&mut act.sa_mask) } != 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: sigaction is plain data, filled in by the call.
            let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
            // SAFETY: `sig` is a valid signal; `act` is initialized and `old`
            // is writable.
            if unsafe { libc::sigaction(sig, &act, &mut old) } != 0 {
                let err = io::Error::last_os_error();
                drop(watch);
                return Err(err);
            }
            watch.saved.push((sig, old));
        }
        Ok(watch)
    }

    /// The signal recorded since the watch was installed, if any.
    pub fn recorded(&self) -> Option<i32> {
        termination_recorded()
    }
}

/// The signal a live [`TerminationWatch`] recorded, if any. For a reader
/// that has only its `EINTR` to go on.
pub fn termination_recorded() -> Option<i32> {
    match RECORDED.load(Ordering::SeqCst) {
        0 => None,
        sig => Some(sig),
    }
}

impl Drop for TerminationWatch {
    fn drop(&mut self) {
        for (sig, old) in self.saved.drain(..).rev() {
            // SAFETY: `old` is the disposition sigaction returned for `sig`;
            // the previous one is not wanted.
            unsafe { libc::sigaction(sig, &old, std::ptr::null_mut()) };
        }
    }
}

/// Lets `SIGINT` end the process: gives it its default action and stops
/// the calling thread blocking it. An ignored disposition and a blocked
/// mask both survive `exec`, so a program can start this one with
/// `SIGINT` ignored (as a shell starts a background job) or blocked. A
/// wait that a person must be able to end, and that holds nothing a
/// signal could leave behind (`envcloak run --wait`), calls this first:
/// a `SIGINT` sent to the process then reaches the calling thread, if no
/// other, and ends the process as its default action does (a shell
/// reports 130).
///
/// # Errors
/// When the disposition or the mask cannot be changed; either may have
/// been changed then.
pub fn interrupt_ends_process() -> io::Result<()> {
    // SAFETY: sigaction is plain data; SIG_DFL with an empty mask is valid.
    let mut dfl: libc::sigaction = unsafe { std::mem::zeroed() };
    dfl.sa_sigaction = libc::SIG_DFL;
    // SAFETY: `dfl.sa_mask` is a writable sigset_t.
    if unsafe { libc::sigemptyset(&mut dfl.sa_mask) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: SIGINT is a valid signal; `dfl` is initialized and the old
    // action is not wanted.
    if unsafe { libc::sigaction(libc::SIGINT, &dfl, std::ptr::null_mut()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: sigset_t is plain data; sigemptyset initializes it.
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: `set` is a writable sigset_t and SIGINT a valid signal.
    if unsafe { libc::sigemptyset(&mut set) != 0 || libc::sigaddset(&mut set, libc::SIGINT) != 0 } {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `set` is initialized; the old mask is not wanted. The call
    // changes only the calling thread's mask.
    let rc = unsafe { libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut()) };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }
    Ok(())
}

/// Ends the process by `sig` with its default action, as if the signal had
/// never been caught: the parent sees a death by that signal. Falls back to
/// exit status 128 + `sig` if the signal does not end the process.
pub fn exit_by_signal(sig: i32) -> ! {
    // SAFETY: sigaction is plain data; SIG_DFL with an empty mask is valid.
    let mut dfl: libc::sigaction = unsafe { std::mem::zeroed() };
    dfl.sa_sigaction = libc::SIG_DFL;
    // SAFETY: `dfl.sa_mask` is a writable sigset_t.
    unsafe { libc::sigemptyset(&mut dfl.sa_mask) };
    // SAFETY: `sig` is a signal number; `dfl` is initialized.
    unsafe { libc::sigaction(sig, &dfl, std::ptr::null_mut()) };
    // SAFETY: sigset_t is plain data; sigemptyset initializes it.
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: `set` is writable; `sig` is a valid signal.
    unsafe {
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, sig);
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
        libc::raise(sig);
    }
    std::process::exit(128 + sig.clamp(1, 64));
}
