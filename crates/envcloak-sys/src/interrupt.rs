//! Breaking threads out of a blocking system call (SPEC §6.1 step 8: the
//! runner's output once the cutoff has passed).
//!
//! A write to a pipe, a socket or a terminal whose reader has stopped
//! reading blocks until the reader reads again, and nothing else ends it.
//! The runner's output threads must be able to give up on such a write
//! once the child has exited and the cutoff has passed, so they run inside
//! an [`Interrupter`]:
//!
//! - [`Interrupter::install`] catches `SIGURG` with a handler that does
//!   nothing, installed without `SA_RESTART`, for as long as the value
//!   lives. `SIGURG` is ignored by default, and the system sends it only
//!   to a process that asked for it (`F_SETOWN` on a socket), so taking it
//!   over disturbs nothing; `exec` resets the caught signal, so a child
//!   starts with the default.
//! - [`Interrupter::run`] runs a closure with the calling thread listed as
//!   one that may be interrupted, and takes it off the list before it
//!   returns or unwinds. A thread that blocks `SIGURG` (a signal mask
//!   survives `exec`, so a program can start the runner with it blocked)
//!   could never be interrupted: the thread unblocks it for the call and
//!   blocks it again after (review R-8).
//! - [`Interrupter::interrupt`] sends `SIGURG` (`pthread_kill`) to each
//!   listed thread. A `write`, `read` or `poll` it is blocked in returns
//!   `EINTR`, or a short count when part of the write was done. A signal
//!   that lands just before the call is lost, so a caller interrupts again
//!   until the thread has done what it was waiting for.
//!
//! A thread is signalled only under the lock it must take to leave the
//! list, so it is alive, and its `pthread_t` valid, whenever it is
//! signalled.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

/// An [`Interrupter`] is installed; there is at most one per process.
static ACTIVE: AtomicBool = AtomicBool::new(false);

extern "C" fn nothing(_sig: libc::c_int) {}

/// `SIGURG` caught without `SA_RESTART`, and the threads it may be sent
/// to. The previous disposition comes back on drop. At most one exists at
/// a time in a process.
pub struct Interrupter {
    saved: libc::sigaction,
    /// The threads inside [`Interrupter::run`], each with its own number.
    threads: Mutex<Vec<(u64, libc::pthread_t)>>,
    next: AtomicU64,
}

impl core::fmt::Debug for Interrupter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Interrupter")
            .field("threads", &self.list().len())
            .finish_non_exhaustive()
    }
}

impl Interrupter {
    /// The signal an interrupter sends.
    pub const SIGNAL: i32 = libc::SIGURG;

    /// Catches [`Interrupter::SIGNAL`] with a handler that does nothing and
    /// without `SA_RESTART`.
    ///
    /// # Errors
    /// [`io::ErrorKind::AlreadyExists`] while another interrupter is
    /// installed, and the errors of `sigaction`. Nothing stays installed
    /// after an error.
    pub fn install() -> io::Result<Interrupter> {
        if ACTIVE.swap(true, Ordering::SeqCst) {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        // SAFETY: sigaction is plain data; every field is set below or
        // stays zero, which is a valid empty value.
        let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
        act.sa_sigaction = nothing as extern "C" fn(libc::c_int) as libc::sighandler_t;
        act.sa_flags = 0;
        // SAFETY: sigaction is plain data, filled in by the call.
        let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: `act.sa_mask` is a writable sigset_t; the signal is valid,
        // `act` is initialized and `old` is writable.
        let rc = unsafe {
            if libc::sigemptyset(&mut act.sa_mask) != 0 {
                -1
            } else {
                libc::sigaction(Self::SIGNAL, &act, &mut old)
            }
        };
        if rc != 0 {
            let err = io::Error::last_os_error();
            ACTIVE.store(false, Ordering::SeqCst);
            return Err(err);
        }
        Ok(Interrupter {
            saved: old,
            threads: Mutex::new(Vec::new()),
            next: AtomicU64::new(0),
        })
    }

    fn list(&self) -> MutexGuard<'_, Vec<(u64, libc::pthread_t)>> {
        self.threads.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Runs `f` on the calling thread, which [`Interrupter::interrupt`]
    /// may signal until `f` returns or unwinds. The thread does not block
    /// [`Interrupter::SIGNAL`] meanwhile: one that did (a mask inherited
    /// through `exec`, or set by the caller) blocks it again when `f` has
    /// returned or unwound (review R-8).
    ///
    /// # Errors
    /// When the thread's signal mask cannot be changed; `f` is not run.
    pub fn run<R>(&self, f: impl FnOnce() -> R) -> io::Result<R> {
        /// Takes the thread off the list, then blocks the signal again if
        /// it did before, on return and on unwinding.
        struct Leave<'a> {
            interrupter: &'a Interrupter,
            id: u64,
            blocked: bool,
        }
        impl Drop for Leave<'_> {
            fn drop(&mut self) {
                self.interrupter.list().retain(|(id, _)| *id != self.id);
                if self.blocked {
                    // Cannot fail: the same set was just unblocked. Were
                    // it to, the thread would stay open to a signal that
                    // no one sends it any more (it is off the list), and
                    // whose handler does nothing.
                    let _ = mask_signal(libc::SIG_BLOCK);
                }
            }
        }
        // Unblocked before the thread is listed, and blocked again only
        // after it is off the list: a listed thread can always be
        // interrupted.
        let blocked = mask_signal(libc::SIG_UNBLOCK)?;
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        // SAFETY: pthread_self has no preconditions.
        let me = unsafe { libc::pthread_self() };
        self.list().push((id, me));
        let _leave = Leave {
            interrupter: self,
            id,
            blocked,
        };
        Ok(f())
    }

    /// Sends [`Interrupter::SIGNAL`] to every thread inside
    /// [`Interrupter::run`] now, and returns how many there were.
    pub fn interrupt(&self) -> usize {
        let threads = self.list();
        for (_, thread) in threads.iter() {
            // SAFETY: the thread is inside `run`, and cannot leave it (and
            // so cannot end) while this holds the lock its `Leave` needs:
            // its pthread_t names a live thread. The handler for the signal
            // does nothing.
            unsafe { libc::pthread_kill(*thread, Self::SIGNAL) };
        }
        threads.len()
    }
}

/// Blocks or unblocks (`how`: `SIG_BLOCK`, `SIG_UNBLOCK`)
/// [`Interrupter::SIGNAL`] for the calling thread, and returns whether the
/// thread blocked it before.
fn mask_signal(how: libc::c_int) -> io::Result<bool> {
    // SAFETY: sigset_t is plain data; sigemptyset initializes `set`, and
    // pthread_sigmask fills in `old`.
    let (mut set, mut old): (libc::sigset_t, libc::sigset_t) =
        unsafe { (std::mem::zeroed(), std::mem::zeroed()) };
    // SAFETY: `set` is a writable sigset_t and the signal is valid.
    if unsafe {
        libc::sigemptyset(&mut set) != 0 || libc::sigaddset(&mut set, Interrupter::SIGNAL) != 0
    } {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `set` is initialized and `old` writable; the call changes
    // only the calling thread's mask.
    let rc = unsafe { libc::pthread_sigmask(how, &set, &mut old) };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }
    // SAFETY: `old` holds the mask pthread_sigmask returned.
    Ok(unsafe { libc::sigismember(&old, Interrupter::SIGNAL) } == 1)
}

impl Drop for Interrupter {
    fn drop(&mut self) {
        // SAFETY: `saved` is the disposition sigaction returned for the
        // signal; the one being replaced is not wanted. A signal still
        // pending then gets the old disposition, by default ignored.
        unsafe { libc::sigaction(Self::SIGNAL, &self.saved, std::ptr::null_mut()) };
        ACTIVE.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use super::*;

    /// The handler is process-wide, so these tests take turns.
    static TURN: Mutex<()> = Mutex::new(());

    /// A write blocked on a socket nobody reads returns once interrupted,
    /// with what it managed: the thread learns it was interrupted and can
    /// give up. Interrupting again until it has is what makes it certain.
    #[test]
    fn a_blocked_write_returns_when_interrupted() {
        let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
        let interrupter = Interrupter::install().unwrap();
        assert_eq!(
            Interrupter::install().unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        let (done, finished) = mpsc::channel();
        std::thread::scope(|s| {
            s.spawn(|| {
                let block = vec![b'x'; 1 << 20];
                let result = interrupter.run(|| writer.write(&block)).unwrap();
                done.send(result.map_err(|e| e.kind())).unwrap();
            });
            // Nothing is read: the write blocks once the buffers are full.
            // It is interrupted until it returns.
            let end = Instant::now() + Duration::from_secs(30);
            let result = loop {
                interrupter.interrupt();
                if let Ok(r) = finished.recv_timeout(Duration::from_millis(20)) {
                    break r;
                }
                assert!(Instant::now() < end, "the write was never interrupted");
            };
            match result {
                Ok(n) => assert!(n < 1 << 20, "the whole write went through: {n}"),
                Err(kind) => assert_eq!(kind, io::ErrorKind::Interrupted),
            }
        });
        // The thread has left `run`: nothing is signalled any more.
        assert_eq!(interrupter.interrupt(), 0);
        reader.set_nonblocking(true).unwrap();
        let mut b = [0u8; 4096];
        assert!(reader.read(&mut b).unwrap() > 0);
    }

    /// Review R-8: a thread that blocks the signal, as a mask inherited
    /// through `exec` blocks it, is interrupted all the same inside `run`,
    /// and blocks it again after; a thread that did not block it still
    /// does not. A write that is never interrupted is let go by reading
    /// the socket, so a failure ends the test rather than hanging it.
    #[test]
    fn a_thread_that_blocks_the_signal_is_interrupted_inside_run() {
        let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
        let interrupter = Interrupter::install().unwrap();
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        let (done, finished) = mpsc::channel();
        std::thread::scope(|s| {
            s.spawn(|| {
                assert!(!mask_signal(libc::SIG_BLOCK).unwrap(), "blocked already");
                let block = vec![b'x'; 1 << 20];
                let result = interrupter.run(|| writer.write(&block)).unwrap();
                // Whether it was blocked before this call: after `run`.
                let blocked_after = mask_signal(libc::SIG_BLOCK).unwrap();
                done.send((result.map_err(|e| e.kind()), blocked_after))
                    .unwrap();
            });
            let end = Instant::now() + Duration::from_secs(10);
            let got = loop {
                interrupter.interrupt();
                if let Ok(r) = finished.recv_timeout(Duration::from_millis(20)) {
                    break Some(r);
                }
                if Instant::now() >= end {
                    break None;
                }
            };
            let Some((result, blocked_after)) = got else {
                reader.set_nonblocking(true).unwrap();
                let mut b = vec![0u8; 1 << 16];
                while finished.try_recv().is_err() {
                    let _ = reader.read(&mut b);
                }
                panic!("a thread that blocks the signal was never interrupted");
            };
            match result {
                Ok(n) => assert!(n < 1 << 20, "the whole write went through: {n}"),
                Err(kind) => assert_eq!(kind, io::ErrorKind::Interrupted),
            }
            assert!(blocked_after, "the signal was not blocked again after run");
        });
        std::thread::scope(|s| {
            s.spawn(|| {
                interrupter.run(|| ()).unwrap();
                assert!(!mask_signal(libc::SIG_UNBLOCK).unwrap());
            });
        });
    }

    /// The previous disposition comes back when the interrupter goes, and
    /// the list holds only threads still inside `run`, also after a panic.
    #[test]
    fn it_leaves_nothing_behind() {
        let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
        let before = disposition();
        let interrupter = Interrupter::install().unwrap();
        assert_ne!(disposition(), before);
        assert_eq!(interrupter.run(|| interrupter.list().len()).unwrap(), 1);
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            interrupter.run(|| panic!("inside run"))
        }));
        assert!(unwound.is_err());
        assert_eq!(interrupter.interrupt(), 0);
        drop(interrupter);
        assert_eq!(disposition(), before);
        drop(Interrupter::install().unwrap());
    }

    fn disposition() -> libc::sighandler_t {
        // SAFETY: sigaction is plain data, filled in by the call.
        let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: a null new action only reads the current one.
        let rc = unsafe { libc::sigaction(Interrupter::SIGNAL, std::ptr::null(), &mut old) };
        assert_eq!(rc, 0);
        old.sa_sigaction
    }
}
