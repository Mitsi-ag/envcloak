//! The processes a tool starts (`envcloak run` for `run_with_secrets`,
//! `envcloak check` for `project_status`), as owned children.
//!
//! - Each child is EnvCloak's own executable, started with standard input
//!   from `/dev/null` and its output on pipes this server reads: nothing
//!   it writes reaches the protocol stream, and a command that reads its
//!   input gets end of file at once.
//! - Each leads a process group of its own. The group is signalled only
//!   while its leader is this server's unreaped child ([`Group`]): the
//!   leader is marked reaped, under the same lock as every signal, before
//!   it is reaped, so a signal can never reach a reused process number (M2
//!   plan §6, rule 3; D-34). No signal goes to a number read from anywhere
//!   else.
//! - A host's cancellation ([`Call::cancel`]) sends the group `SIGTERM`,
//!   which `envcloak run` passes on to its command's group, and then
//!   `SIGKILL` if the leader has not exited within [`KILL_GRACE`]. Without
//!   a controlling terminal the command leads a group of its own, which
//!   only `envcloak run` owns: a command that ignores `SIGTERM` keeps
//!   running after `envcloak run` is killed, without its output pipes
//!   (docs/MCP.md "Limits").
//! - Output is kept as its first and last [`OUTPUT_HEAD`] and
//!   [`OUTPUT_TAIL`] bytes, with a count of what was left out between them
//!   ([`HeadTail`]); it is read until end of stream, or for [`DRAIN`] after
//!   the child exits, whichever is first.

use std::io::Read;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// How much of the start of each output stream is kept.
pub const OUTPUT_HEAD: usize = 64 * 1024;
/// How much of the end of each output stream is kept.
pub const OUTPUT_TAIL: usize = 64 * 1024;
/// How long a cancelled child's group has between `SIGTERM` and `SIGKILL`.
pub const KILL_GRACE: Duration = Duration::from_secs(2);
/// How long output is still read after the child exits.
pub const DRAIN: Duration = Duration::from_secs(2);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A child's process group, which the child leads. Signalled only while
/// the leader is unreaped (see the module documentation).
#[derive(Debug)]
pub(crate) struct Group {
    leader: Mutex<Option<i32>>,
    reaped: Condvar,
}

impl Group {
    fn new(pid: i32) -> Arc<Group> {
        Arc::new(Group {
            leader: Mutex::new(Some(pid)),
            reaped: Condvar::new(),
        })
    }

    /// Sends `sig` to the group while its leader is unreaped. Whether it
    /// was sent.
    pub(crate) fn signal(&self, sig: i32) -> bool {
        let leader = lock(&self.leader);
        leader.is_some_and(|pid| envcloak_sys::signal_group(pid, sig).is_ok())
    }

    /// The leader has exited and is about to be reaped: from here on
    /// nothing is signalled.
    fn reaping(&self) {
        *lock(&self.leader) = None;
        self.reaped.notify_all();
    }

    /// Waits up to `limit` for the leader to be reaped. Whether it was.
    fn wait_reaped(&self, limit: Duration) -> bool {
        let guard = lock(&self.leader);
        let (guard, _) = self
            .reaped
            .wait_timeout_while(guard, limit, |l| l.is_some())
            .unwrap_or_else(PoisonError::into_inner);
        guard.is_none()
    }
}

/// Stops `group`: `SIGTERM`, then `SIGKILL` once [`KILL_GRACE`] has passed
/// with the leader not reaped.
fn stop(group: Arc<Group>) {
    if group.signal(libc::SIGTERM) {
        std::thread::spawn(move || {
            if !group.wait_reaped(KILL_GRACE) {
                group.signal(libc::SIGKILL);
            }
        });
    }
}

/// One tool call: whether it was cancelled, and the child it runs.
#[derive(Debug, Default)]
pub struct Call {
    cancelled: AtomicBool,
    group: Mutex<Option<Arc<Group>>>,
}

impl Call {
    pub fn new() -> Call {
        Call::default()
    }

    /// Whether the call was cancelled.
    pub fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Cancels the call: a child it runs is stopped (`SIGTERM` to its
    /// group, then `SIGKILL`), and one it would start is not started.
    pub fn cancel(&self) {
        if self.cancelled.swap(true, Ordering::SeqCst) {
            return;
        }
        let group = lock(&self.group).clone();
        if let Some(g) = group {
            stop(g);
        }
    }

    /// Records the call's child. False when the call was cancelled first:
    /// the caller then stops the child itself.
    fn attach(&self, group: Arc<Group>) -> bool {
        *lock(&self.group) = Some(group);
        !self.cancelled()
    }

    fn detach(&self) {
        *lock(&self.group) = None;
    }
}

/// The first [`OUTPUT_HEAD`] and last [`OUTPUT_TAIL`] bytes of a stream,
/// and how many bytes between them were left out.
#[derive(Clone, Default)]
pub struct HeadTail {
    head: Vec<u8>,
    /// A ring once full: the oldest byte is at `tail_at`.
    tail: Vec<u8>,
    tail_at: usize,
    left_out: u64,
}

impl std::fmt::Debug for HeadTail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeadTail")
            .field("head", &self.head.len())
            .field("tail", &self.tail.len())
            .field("left_out", &self.left_out)
            .finish()
    }
}

impl HeadTail {
    /// Adds `b` to the stream.
    pub fn push(&mut self, b: &[u8]) {
        let room = OUTPUT_HEAD - self.head.len();
        let (to_head, mut rest) = b.split_at(room.min(b.len()));
        self.head.extend_from_slice(to_head);
        if rest.is_empty() {
            return;
        }
        if rest.len() >= OUTPUT_TAIL {
            self.left_out += (self.tail.len() + rest.len() - OUTPUT_TAIL) as u64;
            self.tail.clear();
            self.tail
                .extend_from_slice(&rest[rest.len() - OUTPUT_TAIL..]);
            self.tail_at = 0;
            return;
        }
        if self.tail.len() < OUTPUT_TAIL {
            let n = (OUTPUT_TAIL - self.tail.len()).min(rest.len());
            self.tail.extend_from_slice(&rest[..n]);
            rest = &rest[n..];
        }
        while !rest.is_empty() {
            let n = (OUTPUT_TAIL - self.tail_at).min(rest.len());
            self.tail[self.tail_at..self.tail_at + n].copy_from_slice(&rest[..n]);
            self.left_out += n as u64;
            self.tail_at = (self.tail_at + n) % OUTPUT_TAIL;
            rest = &rest[n..];
        }
    }

    /// The bytes kept from the start.
    pub fn head(&self) -> &[u8] {
        &self.head
    }

    /// The bytes kept from the end, in order.
    pub fn tail(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.tail.len());
        out.extend_from_slice(&self.tail[self.tail_at..]);
        out.extend_from_slice(&self.tail[..self.tail_at]);
        out
    }

    /// How many bytes between the head and the tail were left out.
    pub fn left_out(&self) -> u64 {
        self.left_out
    }
}

/// What a child did.
#[derive(Debug)]
pub struct Captured {
    /// Its exit code, when it exited.
    pub code: Option<i32>,
    /// The signal that ended it, when one did.
    pub signal: Option<i32>,
    pub stdout: HeadTail,
    pub stderr: HeadTail,
    /// It outlived its limit and was killed.
    pub timed_out: bool,
    /// Its output was still open [`DRAIN`] after it exited, and what came
    /// after that was not read.
    pub cut: bool,
}

/// Why a child was not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotRun {
    /// The call was cancelled before it started.
    Cancelled,
    /// It could not be started.
    Spawn,
}

/// Reads `pipe` into a shared [`HeadTail`] until end of stream; the
/// receiver hears when it ends.
fn pump<R: Read + Send + 'static>(pipe: Option<R>) -> (Arc<Mutex<HeadTail>>, mpsc::Receiver<()>) {
    let buf = Arc::new(Mutex::new(HeadTail::default()));
    let (tx, rx) = mpsc::channel();
    let shared = Arc::clone(&buf);
    std::thread::spawn(move || {
        if let Some(mut pipe) = pipe {
            let mut chunk = [0u8; 16 * 1024];
            loop {
                match pipe.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => lock(&shared).push(&chunk[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
            chunk.fill(0);
        }
        let _ = tx.send(());
    });
    (buf, rx)
}

/// Runs `cmd` as the child of `call` (see the module documentation), and
/// waits for it: killed at `limit` when one is given, and stopped when
/// the call is cancelled.
pub fn run(mut cmd: Command, call: &Call, limit: Option<Duration>) -> Result<Captured, NotRun> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    if call.cancelled() {
        return Err(NotRun::Cancelled);
    }
    let mut child = cmd.spawn().map_err(|_| NotRun::Spawn)?;
    let Ok(pid) = i32::try_from(child.id()) else {
        // A pid that does not fit an i32 cannot be signalled as a group;
        // it is reaped and refused.
        let _ = child.kill();
        let _ = child.wait();
        return Err(NotRun::Spawn);
    };
    let group = Group::new(pid);
    let (out, out_done) = pump(child.stdout.take());
    let (err, err_done) = pump(child.stderr.take());
    if !call.attach(Arc::clone(&group)) {
        stop(Arc::clone(&group));
    }
    let (tx, exited) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(envcloak_sys::wait_for_exit(pid));
    });
    let mut timed_out = false;
    if let Some(limit) = limit {
        if exited.recv_timeout(limit).is_err() {
            timed_out = true;
            group.signal(libc::SIGKILL);
            let _ = exited.recv();
        }
    } else {
        let _ = exited.recv();
    }
    group.reaping();
    let status = child.wait();
    call.detach();
    let deadline = Instant::now() + DRAIN;
    let mut cut = false;
    for done in [&out_done, &err_done] {
        let left = deadline.saturating_duration_since(Instant::now());
        cut |= done.recv_timeout(left).is_err();
    }
    let (code, signal) = match status {
        Ok(s) => (s.code(), s.signal()),
        Err(_) => (None, None),
    };
    let stdout = lock(&out).clone();
    let stderr = lock(&err).clone();
    Ok(Captured {
        code,
        signal,
        stdout,
        stderr,
        timed_out,
        cut,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn head_and_tail_keep_the_ends_and_count_the_rest() {
        let mut h = HeadTail::default();
        h.push(b"abc");
        assert_eq!(h.head(), b"abc");
        assert_eq!(h.left_out(), 0);
        // Byte i of a long stream is i mod 251, so any slice is checkable.
        let total = OUTPUT_HEAD + OUTPUT_TAIL + 100_003;
        let stream: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        for step in [
            1usize,
            7,
            4096,
            OUTPUT_TAIL - 1,
            OUTPUT_TAIL,
            3 * OUTPUT_TAIL,
        ] {
            let mut h = HeadTail::default();
            for piece in stream.chunks(step) {
                h.push(piece);
            }
            assert_eq!(h.head(), &stream[..OUTPUT_HEAD], "step {step}");
            assert_eq!(h.tail(), &stream[total - OUTPUT_TAIL..], "step {step}");
            assert_eq!(h.left_out(), 100_003, "step {step}");
        }
        // Short of the cap, nothing is left out and the tail is in order.
        let mut h = HeadTail::default();
        h.push(&stream[..OUTPUT_HEAD + 10]);
        h.push(&stream[OUTPUT_HEAD + 10..OUTPUT_HEAD + 20]);
        assert_eq!(h.tail(), &stream[OUTPUT_HEAD..OUTPUT_HEAD + 20]);
        assert_eq!(h.left_out(), 0);
        assert!(!format!("{h:?}").contains('['));
    }

    #[test]
    fn a_child_runs_with_no_input_and_its_output_captured() {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "cat; echo out; echo err >&2; exit 3"]);
        let c = run(cmd, &Call::new(), Some(Duration::from_secs(60))).unwrap();
        assert_eq!(c.code, Some(3));
        assert_eq!(c.stdout.head(), b"out\n");
        assert_eq!(c.stderr.head(), b"err\n");
        assert!(!c.timed_out && !c.cut);
    }

    #[test]
    fn a_child_past_its_limit_is_killed_with_its_group() {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "sleep 600 & sleep 600"]);
        let start = Instant::now();
        let c = run(cmd, &Call::new(), Some(Duration::from_millis(300))).unwrap();
        assert!(c.timed_out);
        assert_eq!(c.signal, Some(libc::SIGKILL));
        // The background sleep held the pipes; it went with the group, so
        // the output ended at once rather than after the drain.
        assert!(!c.cut);
        assert!(start.elapsed() < Duration::from_secs(30));
    }

    #[test]
    fn a_cancelled_call_starts_nothing() {
        let call = Call::new();
        call.cancel();
        let cmd = Command::new("/bin/sh");
        assert_eq!(run(cmd, &call, None).unwrap_err(), NotRun::Cancelled);
    }
}
