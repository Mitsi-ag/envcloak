//! Owner-lifetime witnesses for the processes a test has something else
//! start and stop (M2 plan task M2-06; the cycle279 review's scaffold):
//! whether a process ended is read from a socket it holds, never from a
//! process number, and nothing here signals anything.
//!
//! A [`Lifeline`] is a Unix socket a test listens on, in a private
//! directory under a short `/tmp` path. The fixture ([`FIXTURE`], started
//! with [`fixture`]) connects to it before it forks, so the leader and the
//! descendant it starts both hold the connection. Once both are set up
//! (the descendant has taken its `SIGTERM` disposition), the leader sends
//! one byte, `R`: [`Holders::ready`]. From then on, the end of the stream
//! ([`Holders::ended_within`]) means that every holder has exited: a
//! process number that was reused, or a leader reaped while its
//! descendant runs on, cannot fool it. A second lifeline that only the
//! leader holds says when the leader alone has exited.
//!
//! Each fixture has a finite lifetime: it ends when the stop request
//! exists ([`Lifeline::stop`], made when the lifeline is dropped, however
//! the test ends), or when its own deadline passes, whichever is first.
//! What a test cannot stop, such as a descendant that left the group the
//! code under test owns, ends so.

use std::io::{self, Read};
use std::os::fd::AsFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// The fixture, run by `python3 -I -B -c FIXTURE <kind> <group socket>
/// <stop request> <seconds> [<leader socket>] [<terms file>]`.
///
/// It connects to the group socket (and the leader socket, when given),
/// forks a descendant and waits until the descendant is set up. The
/// descendant ignores `SIGTERM`, keeps the group connection and the
/// standard streams it was started with (so it holds a reader's pipes),
/// closes the leader connection, and stays in the leader's process group,
/// except for `escape`, where it leads a group of its own. The leader then
/// takes `SIGTERM` as `kind` says, sends `R` on the group connection and:
///
/// - `dies-of-term`: waits, and dies of `SIGTERM` (its default action);
/// - `takes-term`: notes the time of each `SIGTERM` in the terms file (one
///   line, seconds on Python's monotonic clock) and waits;
/// - `escape`: as `dies-of-term`, with the descendant outside its group;
/// - `leader-exits`: exits 0 at once, leaving its descendant.
///
/// Waiting ends at the stop request or the deadline, `seconds` from the
/// start; the leader then exits 3, and the descendant 0.
pub const FIXTURE: &str = r#"import os, signal, socket, sys, time
kind, group_path, stop, seconds = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4])
leader_path = sys.argv[5] if len(sys.argv) > 5 else ""
terms = sys.argv[6] if len(sys.argv) > 6 else ""
deadline = time.monotonic() + seconds
def wait():
    while not os.path.exists(stop) and time.monotonic() < deadline:
        time.sleep(0.01)
def connect(path):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(path)
    return s
group = connect(group_path)
leader = connect(leader_path) if leader_path else None
r, w = os.pipe()
if os.fork() == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    if kind == "escape":
        os.setpgid(0, 0)
    if leader is not None:
        leader.close()
    os.close(r)
    os.write(w, b"x")
    os.close(w)
    wait()
    os._exit(0)
os.close(w)
os.read(r, 1)
os.close(r)
if kind == "takes-term":
    def noted(*_):
        with open(terms, "a") as f:
            f.write("%f\n" % time.monotonic())
    signal.signal(signal.SIGTERM, noted)
group.sendall(b"R")
if kind == "leader-exits":
    os._exit(0)
wait()
sys.exit(3)
"#;

/// How long a fixture lives at most: longer than any test waits for it,
/// so its deadline never decides a test.
pub const FIXTURE_SECONDS: u64 = 120;

/// The `python3` on `PATH`.
///
/// # Panics
/// When there is none.
pub fn python3() -> PathBuf {
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .map(|d| d.join("python3"))
        .find(|p| p.is_file())
        .expect("python3 is needed on PATH")
}

/// A socket a test listens on, and the fixture's stop request beside it.
#[derive(Debug)]
pub struct Lifeline {
    listener: UnixListener,
    dir: tempfile::TempDir,
}

impl Lifeline {
    /// A new lifeline, in a private directory under `/tmp`.
    ///
    /// # Panics
    /// When the directory or the socket cannot be made.
    pub fn new() -> Lifeline {
        let dir = tempfile::Builder::new()
            .prefix("ec-life")
            .tempdir_in("/tmp")
            .expect("a directory for the lifeline");
        let listener = UnixListener::bind(dir.path().join("l.sock")).expect("the lifeline socket");
        Lifeline { listener, dir }
    }

    /// The socket's path, which the fixture connects to.
    pub fn socket(&self) -> PathBuf {
        self.dir.path().join("l.sock")
    }

    /// `name` in the lifeline's directory.
    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// The fixture's stop request.
    pub fn stop_path(&self) -> PathBuf {
        self.path("stop")
    }

    /// Asks the fixtures that wait on this lifeline's stop request to end.
    pub fn stop(&self) {
        let _ = std::fs::write(self.stop_path(), b"");
    }

    /// The next process to connect, waited for up to `limit`: the holders
    /// of that connection.
    pub fn accept(&self, limit: Duration) -> Option<Holders> {
        let end = Instant::now() + limit;
        loop {
            let left = end.saturating_duration_since(Instant::now());
            match envcloak_sys::wait_readable(self.listener.as_fd(), left) {
                Ok(true) => break,
                Ok(false) => return None,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return None,
            }
        }
        let (stream, _) = self.listener.accept().ok()?;
        stream.set_nonblocking(false).ok()?;
        Some(Holders(stream))
    }
}

impl Default for Lifeline {
    fn default() -> Self {
        Lifeline::new()
    }
}

impl Drop for Lifeline {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The processes that hold one connection to a [`Lifeline`].
#[derive(Debug)]
pub struct Holders(UnixStream);

impl Holders {
    /// The next byte within `limit`: `Some(None)` at the end of the stream,
    /// `None` when nothing came in time. Waits with `poll`, not a read
    /// timeout: macOS refuses to set one on a socket whose peer has closed.
    fn next_byte(&mut self, limit: Duration) -> Option<Option<u8>> {
        let end = Instant::now() + limit;
        loop {
            let left = end.saturating_duration_since(Instant::now());
            match envcloak_sys::wait_readable(self.0.as_fd(), left) {
                Ok(true) => break,
                Ok(false) => return None,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return None,
            }
        }
        let mut b = [0u8; 1];
        loop {
            match self.0.read(&mut b) {
                Ok(0) => return Some(None),
                Ok(_) => return Some(Some(b[0])),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return None,
            }
        }
    }

    /// Whether the fixture said it is ready (`R`) within `limit`.
    pub fn ready(&mut self, limit: Duration) -> bool {
        self.next_byte(limit) == Some(Some(b'R'))
    }

    /// Whether every holder has closed the connection within `limit`: the
    /// end of the stream. A byte, or nothing yet, is not.
    pub fn ended_within(&mut self, limit: Duration) -> bool {
        self.next_byte(limit) == Some(None)
    }
}

/// The fixture as a command: `kind` (see [`FIXTURE`]), holding `group`
/// (and `leader`, when given) and stopped by `group`'s stop request, with a
/// cleared environment and its working directory in `group`'s directory.
/// `terms` is the file `takes-term` notes its `SIGTERM`s in.
pub fn fixture(
    kind: &str,
    group: &Lifeline,
    leader: Option<&Lifeline>,
    terms: Option<&Path>,
) -> Command {
    let mut cmd = Command::new(python3());
    cmd.args(["-I", "-B", "-c", FIXTURE, kind])
        .arg(group.socket())
        .arg(group.stop_path())
        .arg(FIXTURE_SECONDS.to_string())
        .arg(leader.map(Lifeline::socket).unwrap_or_default())
        .arg(terms.map(Path::to_path_buf).unwrap_or_default())
        .current_dir(group.dir.path())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", group.dir.path())
        .env("LC_ALL", "C");
    cmd
}

/// The times a `takes-term` fixture noted, in seconds on its clock.
pub fn terms_noted(file: &Path) -> Vec<f64> {
    std::fs::read_to_string(file)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.trim().parse().ok())
        .collect()
}
