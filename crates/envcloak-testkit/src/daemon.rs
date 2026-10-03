//! A running `envcloakd` in a [`TestHome`], for tests that talk to it.
//!
//! The daemon's standard error is a socket the test reads (F-80). A line
//! the daemon wrote is in that socket once its write returned, so before
//! the answer the line came with; [`Daemon::log`] reads whatever the
//! socket holds before it answers, so it holds every line written before
//! the call, whether or not the reading thread got to it. The thread only
//! keeps the socket from filling while no one asks. A line the daemon
//! writes after an answer (an event it reports later) is waited for with
//! a deadline ([`Daemon::wait_for_log`]).

use std::io::{self, Read};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::home::TestHome;

/// How long a daemon may take to start listening.
const START_TIMEOUT: Duration = Duration::from_secs(30);

/// How often the reading thread empties the socket while no one asks.
const COLLECT_EVERY: Duration = Duration::from_millis(5);

/// What the daemon wrote to standard error, as read so far, and the
/// socket the rest arrives on.
#[derive(Debug)]
struct Collected {
    /// The test's end, non-blocking: read only under the lock, so bytes
    /// are appended in the order they were written.
    stream: UnixStream,
    bytes: Vec<u8>,
    /// Every writer closed its end.
    closed: bool,
    /// How many times the socket was emptied: a test's barrier.
    drains: u64,
}

impl Collected {
    /// Appends what the socket holds now.
    fn drain(&mut self) {
        self.drains += 1;
        let mut buf = [0u8; 16 * 1024];
        while !self.closed {
            match self.stream.read(&mut buf) {
                Ok(0) => self.closed = true,
                Ok(n) => self.bytes.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                // Reset or failed: nothing more will come.
                Err(_) => self.closed = true,
            }
        }
    }
}

/// The daemon's standard error, collected ([`Collected`]).
#[derive(Debug, Clone)]
struct Collector(Arc<Mutex<Collected>>);

impl Collector {
    /// A collector reading `stream`, the end the test keeps. `every`
    /// starts the thread that empties it that often; `None` starts none,
    /// for a test of the barrier.
    fn start(stream: UnixStream, every: Option<Duration>) -> (Collector, Option<JoinHandle<()>>) {
        // Read only under the lock, never waiting: see `Collected`.
        let _ = stream.set_nonblocking(true);
        let c = Collector(Arc::new(Mutex::new(Collected {
            stream,
            bytes: Vec::new(),
            closed: false,
            drains: 0,
        })));
        let reader = every.map(|every| {
            let c = c.clone();
            std::thread::spawn(move || {
                loop {
                    let closed = {
                        let mut g = c.lock();
                        g.drain();
                        g.closed
                    };
                    if closed {
                        break;
                    }
                    // Not holding the lock, so a test's read gets it.
                    std::thread::sleep(every);
                }
            })
        });
        (c, reader)
    }

    fn lock(&self) -> MutexGuard<'_, Collected> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Everything written so far: the socket emptied first.
    fn bytes(&self) -> Vec<u8> {
        let mut g = self.lock();
        g.drain();
        g.bytes.clone()
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes()).into_owned()
    }

    #[cfg(test)]
    fn drains(&self) -> u64 {
        self.lock().drains
    }
}

/// The daemon's runtime directory in `home`: under the data directory on
/// macOS, under `XDG_RUNTIME_DIR` (the home's `run/`) elsewhere.
pub fn daemon_run_dir(home: &TestHome) -> PathBuf {
    if cfg!(target_os = "macos") {
        home.home().join("Library/Application Support/EnvCloak/run")
    } else {
        home.root().join("run/envcloak")
    }
}

/// The daemon's socket in `home`.
pub fn daemon_socket(home: &TestHome) -> PathBuf {
    daemon_run_dir(home).join("envcloakd.sock")
}

/// An `envcloakd --foreground` child in a test home, killed and reaped on
/// drop. Its standard error is collected as it runs.
#[derive(Debug)]
pub struct Daemon {
    child: Child,
    log: Collector,
    reader: Option<JoinHandle<()>>,
}

impl Daemon {
    /// Starts `exe --foreground <args>` in `home`'s cleared environment
    /// and waits until it listens.
    ///
    /// # Panics
    /// When it exits or is not listening within 30 seconds; the message
    /// holds its standard error, which is value-free by design.
    pub fn start(home: &TestHome, exe: &Path, args: &[&str]) -> Daemon {
        let mut cmd = Command::new(exe);
        home.apply(&mut cmd);
        Self::start_command(cmd, args)
    }

    /// Starts `cmd` (an `envcloakd` command whose environment the caller
    /// set) with `--foreground <args>` and waits until it listens.
    ///
    /// # Panics
    /// As [`Daemon::start`].
    pub fn start_command(cmd: Command, args: &[&str]) -> Daemon {
        let mut d = Self::spawn_command(cmd, args);
        if !d.wait_listening(START_TIMEOUT) {
            let status = d.wait_exit(Duration::from_secs(1));
            panic!(
                "envcloakd did not start ({status:?}); its log:\n{}",
                d.log()
            );
        }
        d
    }

    /// Starts `exe --foreground <args>` in `home`'s environment without
    /// waiting, for tests of a daemon that must refuse to start.
    ///
    /// # Panics
    /// When the process cannot be started.
    pub fn spawn(home: &TestHome, exe: &Path, args: &[&str]) -> Daemon {
        let mut cmd = Command::new(exe);
        home.apply(&mut cmd);
        Self::spawn_command(cmd, args)
    }

    /// Starts `cmd --foreground <args>` without waiting.
    ///
    /// # Panics
    /// When the process cannot be started.
    pub fn spawn_command(mut cmd: Command, args: &[&str]) -> Daemon {
        let (ours, theirs) = match UnixStream::pair() {
            Ok(p) => p,
            Err(e) => panic!("cannot make the daemon's standard error: {e}"),
        };
        cmd.arg("--foreground")
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(OwnedFd::from(theirs)));
        let child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => panic!("cannot start envcloakd: {e}"),
        };
        // The child's end goes with `cmd`, so the test's end sees the end
        // of the stream once the daemon (and whatever it handed it to)
        // closed it.
        drop(cmd);
        let (log, reader) = Collector::start(ours, Some(COLLECT_EVERY));
        Daemon { child, log, reader }
    }

    /// Everything the daemon wrote to standard error before this call:
    /// every line of an answer received is in it (see the module
    /// documentation).
    pub fn log(&self) -> String {
        self.log.text()
    }

    /// The raw bytes of the log, as [`Daemon::log`].
    pub fn log_bytes(&self) -> Vec<u8> {
        self.log.bytes()
    }

    pub fn pid(&self) -> i32 {
        i32::try_from(self.child.id()).unwrap_or(-1)
    }

    /// Whether the daemon is still running: this very process, not
    /// reaped and not exited.
    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Waits until the log holds a line containing `text`, or `limit`
    /// passes, or the daemon exits.
    pub fn wait_for_log(&mut self, text: &str, limit: Duration) -> bool {
        let end = Instant::now() + limit;
        loop {
            if self.log().contains(text) {
                return true;
            }
            if Instant::now() >= end || matches!(self.child.try_wait(), Ok(Some(_))) {
                // One last look: the log read now holds all it wrote.
                return self.log().contains(text);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Waits until `done` holds of the log, or `limit` passes, and returns
    /// the log it last looked at: for lines the daemon writes after an
    /// answer, such as a connection's closing, which it logs once its
    /// thread for the connection ends. A line that never comes leaves
    /// `done` false, and the caller's assertions fail on that log.
    pub fn log_when(&self, limit: Duration, done: impl Fn(&str) -> bool) -> String {
        let end = Instant::now() + limit;
        loop {
            let log = self.log();
            if done(&log) || Instant::now() >= end {
                return log;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Waits until the daemon says it listens.
    pub fn wait_listening(&mut self, limit: Duration) -> bool {
        self.wait_for_log("envcloakd: listening", limit)
    }

    /// Sends `sig` (such as `-TERM`) with `kill`.
    ///
    /// # Panics
    /// When `kill` fails.
    pub fn signal(&self, sig: &str) {
        let ok = Command::new("kill")
            .args([sig, &self.pid().to_string()])
            .status()
            .is_ok_and(|s| s.success());
        assert!(ok, "kill {sig} failed");
    }

    /// Waits up to `limit` for the daemon to exit, then collects the rest
    /// of its log. `None` when it is still running.
    pub fn wait_exit(&mut self, limit: Duration) -> Option<ExitStatus> {
        let end = Instant::now() + limit;
        loop {
            if let Ok(Some(status)) = self.child.try_wait() {
                if let Some(r) = self.reader.take() {
                    let _ = r.join();
                }
                return Some(status);
            }
            if Instant::now() >= end {
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(r) = self.reader.take() {
            let _ = r.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    /// F-80: a line written before an answer is in the log read after
    /// it, however far behind the reading thread is. With no thread at
    /// all (the slowest collector there is), the lines a writer wrote are
    /// there, in order, and a line never written is not.
    #[test]
    fn the_log_holds_every_line_written_before_it_is_read() {
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        let (log, reader) = Collector::start(ours, None);
        assert!(reader.is_none());
        theirs.write_all(b"one\ntwo\n").unwrap();
        assert_eq!(log.text(), "one\ntwo\n");
        theirs.write_all(b"three\n").unwrap();
        assert_eq!(log.text(), "one\ntwo\nthree\n");
        assert!(!log.text().contains("four"), "a line never written");
        // More than the socket holds at once: each read empties it.
        let big = vec![b'x'; 64 * 1024];
        let writer = std::thread::spawn(move || {
            theirs.write_all(&big).unwrap();
            theirs.write_all(b"\nlast\n").unwrap();
        });
        while !writer.is_finished() {
            let _ = log.bytes();
        }
        writer.join().unwrap();
        let text = log.text();
        assert!(text.ends_with("\nlast\n"));
        assert_eq!(
            text.len(),
            "one\ntwo\nthree\n".len() + 64 * 1024 + "\nlast\n".len()
        );
    }

    /// A waiter with a deadline sees a line written after it started
    /// (a barrier: written once the waiter has looked and not found it),
    /// and a line never written fails it at the deadline.
    #[test]
    fn a_wait_sees_a_late_line_and_fails_on_a_missing_one() {
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        let (log, reader) = Collector::start(ours, None);
        assert!(reader.is_none());
        let wait = |log: &Collector, text: &str, limit: Duration| {
            let end = Instant::now() + limit;
            loop {
                if log.text().contains(text) {
                    return true;
                }
                if Instant::now() >= end {
                    return log.text().contains(text);
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        };
        let seen = log.drains();
        let late = {
            let log = log.clone();
            std::thread::spawn(move || {
                // Once the waiter looked at least once and found nothing.
                while log.drains() <= seen + 1 {
                    std::thread::yield_now();
                }
                theirs.write_all(b"late line\n").unwrap();
                theirs
            })
        };
        assert!(wait(&log, "late line", Duration::from_secs(30)));
        let _theirs = late.join().unwrap();
        let start = Instant::now();
        assert!(!wait(&log, "never written", Duration::from_millis(200)));
        assert!(start.elapsed() >= Duration::from_millis(200));
    }

    /// The reading thread keeps the socket from filling, and ends once
    /// every writer closed its end.
    #[test]
    fn the_thread_reads_until_the_writers_close() {
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        let (log, reader) = Collector::start(ours, Some(COLLECT_EVERY));
        let big = vec![b'y'; 256 * 1024];
        theirs.write_all(&big).unwrap();
        drop(theirs);
        reader.unwrap().join().unwrap();
        assert_eq!(log.bytes().len(), 256 * 1024);
    }
}
