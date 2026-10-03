//! The processes a tool starts (`envcloak run` for `run_with_secrets`,
//! `envcloak check` for `project_status`), as owned children.
//!
//! - Each child is EnvCloak's own executable, started with standard input
//!   from `/dev/null` and its output on pipes this server reads: nothing
//!   it writes reaches the protocol stream, and a command that reads its
//!   input gets end of file at once. It starts with `SIGTERM`, `SIGINT`
//!   and `SIGHUP` unblocked, though every thread here blocks them (they
//!   are taken on one thread, `envcloak mcp`): a child that kept that mask
//!   would not stop when asked to, and an `envcloak run` waiting for an
//!   approval would start its command once the approval came, after its
//!   call was cancelled (Codex review of M2-06, high).
//! - Each leads a process group of its own. The group is signalled only
//!   while its leader is this server's unreaped child ([`Group`]): the
//!   leader is marked reaped, under the same lock as every signal, before
//!   it is reaped, so a signal can never reach a reused process number (M2
//!   plan §6, rule 3; D-34). No signal goes to a number read from anywhere
//!   else. The leader is reaped only once its output has been read, so its
//!   group stays its own until then.
//! - A host's cancellation ([`Call::cancel`]) sends the group `SIGTERM`,
//!   which `envcloak run` passes on to its command; if the leader has not
//!   exited within [`TERM_GRACE`], a second `SIGTERM`, on which `envcloak
//!   run` kills its command (`SIGKILL`, through the handle it owns: the
//!   command is its unreaped child); and `SIGKILL` if the leader has still
//!   not exited [`KILL_GRACE`] later. Once the leader of a stopped call has
//!   exited, the whole group gets `SIGKILL`: what is left there (on a
//!   controlling terminal `envcloak run` keeps its command, and what the
//!   command starts, in this group) ends with the call, however soon
//!   `envcloak run` exited. A call cancelled after its leader exited, while
//!   its output is still read, has its group killed at once: there is no
//!   leader left to pass a `SIGTERM` on (Codex review of M2-06, high).
//!   Without a controlling terminal the command leads a group of its own,
//!   which only `envcloak run` owns, and `envcloak run` ends what is left of
//!   it in turn before it reaps the command (docs/RUN.md); never by a
//!   signal from here to a group this server did not start.
//! - Children are started one at a time ([`SPAWNING`]). On macOS a pipe
//!   gets its close-on-exec flag only after it is made, so a child started
//!   by another worker in between would inherit the pipes of another
//!   call's child: it could hold that call's output open, or write into
//!   it what its own `envcloak run` never redacted. The lock covers the
//!   pipes made here, not every descriptor this server makes (a worker's
//!   connection to the daemon is made meanwhile, and on macOS a socket too
//!   gets its flag only after it is made): `envcloak run --status-fd`
//!   sets the close-on-exec flag on every descriptor it inherited above
//!   the standard streams before it starts its command, so whatever a
//!   child of this server inherits by mistake never reaches the command.
//! - [`run_reporting`] also hands the child the write end of a pipe of its
//!   own, its status descriptor (`envcloak run --status-fd N`): the flag
//!   is cleared on it in that child only, after the fork, and this
//!   server's copy is closed once the child is started, so the end of
//!   that pipe is the child's exit. What comes through it is the child's
//!   record of how the run ended ([`Report`]), which the command, never
//!   holding the descriptor, cannot write.
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
/// How long a cancelled child's group has between its first `SIGTERM` and
/// the second, on which `envcloak run` kills its command.
pub const TERM_GRACE: Duration = Duration::from_secs(2);
/// How long it has after the second `SIGTERM`, before `SIGKILL`.
pub const KILL_GRACE: Duration = Duration::from_secs(2);
/// How long output is still read after the child exits.
pub const DRAIN: Duration = Duration::from_secs(2);

/// Held while a child is started, pipes made, forked and its program
/// started: see the module documentation.
static SPAWNING: Mutex<()> = Mutex::new(());

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A child's process group, which the child leads. Signalled only while
/// the leader is unreaped (see the module documentation).
#[derive(Debug)]
pub(crate) struct Group {
    leader: Mutex<Leader>,
    reaped: Condvar,
}

/// The leader of a [`Group`], as far as the signals sent to it go.
#[derive(Debug)]
struct Leader {
    /// Its process number, while it is unreaped.
    pid: Option<i32>,
    /// Its exit was seen; it is not reaped yet.
    exited: bool,
}

/// What [`Group::first_stop`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirstStop {
    /// `SIGTERM`, to a leader still running: the rest of the stop follows.
    Asked,
    /// `SIGKILL`, to a group whose leader has exited, or nothing, to one
    /// reaped already: there is nothing more to do.
    Done,
}

impl Group {
    fn new(pid: i32) -> Arc<Group> {
        Arc::new(Group {
            leader: Mutex::new(Leader {
                pid: Some(pid),
                exited: false,
            }),
            reaped: Condvar::new(),
        })
    }

    /// Sends `sig` to the group while its leader is unreaped. Whether it
    /// was sent.
    pub(crate) fn signal(&self, sig: i32) -> bool {
        let leader = lock(&self.leader);
        leader
            .pid
            .is_some_and(|pid| envcloak_sys::signal_group(pid, sig).is_ok())
    }

    /// The first step of a stop: `SIGTERM` while the leader runs; `SIGKILL`
    /// once it has exited and before it is reaped, when its output is still
    /// read and nothing is left to pass a `SIGTERM` on; nothing once it is
    /// reaped.
    fn first_stop(&self) -> FirstStop {
        let leader = lock(&self.leader);
        match (leader.pid, leader.exited) {
            (Some(pid), false) if envcloak_sys::signal_group(pid, libc::SIGTERM).is_ok() => {
                FirstStop::Asked
            }
            (Some(pid), true) => {
                let _ = envcloak_sys::signal_group(pid, libc::SIGKILL);
                FirstStop::Done
            }
            _ => FirstStop::Done,
        }
    }

    /// The leader has exited, and stays unreaped while its output is read.
    /// When `stopped` says, under the same lock, that its call was stopped,
    /// what is left of its group is killed now.
    fn exited(&self, stopped: impl FnOnce() -> bool) {
        let mut leader = lock(&self.leader);
        leader.exited = true;
        if let Some(pid) = leader.pid {
            if stopped() {
                let _ = envcloak_sys::signal_group(pid, libc::SIGKILL);
            }
        }
    }

    /// The leader is about to be reaped: from here on nothing is
    /// signalled. When `stopped` says, under the same lock, that its call
    /// was stopped, what is left of its group is killed first, while the
    /// group is still the exited leader's.
    fn reaping(&self, stopped: impl FnOnce() -> bool) {
        let mut leader = lock(&self.leader);
        if let Some(pid) = leader.pid {
            if stopped() {
                let _ = envcloak_sys::signal_group(pid, libc::SIGKILL);
            }
        }
        leader.pid = None;
        self.reaped.notify_all();
    }

    /// Waits up to `limit` for the leader to be reaped. Whether it was.
    fn wait_reaped(&self, limit: Duration) -> bool {
        let guard = lock(&self.leader);
        let (guard, _) = self
            .reaped
            .wait_timeout_while(guard, limit, |l| l.pid.is_some())
            .unwrap_or_else(PoisonError::into_inner);
        guard.pid.is_none()
    }
}

/// Stops `group`: `SIGTERM`; again once [`TERM_GRACE`] has passed with the
/// leader not reaped (`envcloak run` then kills its command); then
/// `SIGKILL` once [`KILL_GRACE`] more has passed. A group whose leader has
/// exited already gets `SIGKILL` at once ([`Group::first_stop`]).
fn stop(group: Arc<Group>) {
    if group.first_stop() == FirstStop::Asked {
        std::thread::spawn(move || {
            if !group.wait_reaped(TERM_GRACE)
                && group.signal(libc::SIGTERM)
                && !group.wait_reaped(KILL_GRACE)
            {
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
    /// group, a second `SIGTERM`, then `SIGKILL`), and one it would start
    /// is not started.
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

/// What came through a child's status descriptor ([`run_reporting`]).
#[derive(Debug, Clone)]
pub struct Report {
    /// The bytes read, at most [`OUTPUT_HEAD`]; `None` when more came.
    pub bytes: Option<Vec<u8>>,
    /// The pipe ended (every copy of its write end closed) within
    /// [`DRAIN`] of the child's exit.
    pub ended: bool,
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
pub fn run(cmd: Command, call: &Call, limit: Option<Duration>) -> Result<Captured, NotRun> {
    follow(|_| cmd, false, call, limit).map(|(captured, _)| captured)
}

/// [`run`], for a child that reports how it ended on a status descriptor:
/// `make` builds the command given that descriptor's number, which it
/// passes on (`envcloak run --status-fd N`). Returns what came through
/// it with what the child did (see the module documentation).
pub fn run_reporting(
    make: impl FnOnce(i32) -> Command,
    call: &Call,
    limit: Option<Duration>,
) -> Result<(Captured, Report), NotRun> {
    let (captured, report) = follow(|fd| make(fd.unwrap_or(-1)), true, call, limit)?;
    let report = report.ok_or(NotRun::Spawn)?;
    Ok((captured, report))
}

/// Starts the child `make` builds, with a status pipe when `reporting`,
/// and follows it (see [`run`] and [`run_reporting`]).
fn follow(
    make: impl FnOnce(Option<i32>) -> Command,
    reporting: bool,
    call: &Call,
    limit: Option<Duration>,
) -> Result<(Captured, Option<Report>), NotRun> {
    use std::os::fd::{AsFd, AsRawFd};
    if call.cancelled() {
        return Err(NotRun::Cancelled);
    }
    // The pipes are made, and the child started, one child at a time: the
    // status pipe's write end, like the output pipes, gets its
    // close-on-exec flag only after it is made on macOS.
    let (mut child, status) = {
        let _one_at_a_time = lock(&SPAWNING);
        let pipe = if reporting {
            Some(envcloak_sys::pipe_cloexec().map_err(|_| NotRun::Spawn)?)
        } else {
            None
        };
        let mut cmd = make(pipe.as_ref().map(|(_, w)| w.as_fd().as_raw_fd()));
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        envcloak_sys::unblock_termination_on_spawn(&mut cmd).map_err(|_| NotRun::Spawn)?;
        if let Some((_, w)) = &pipe {
            envcloak_sys::inherit_on_spawn(&mut cmd, w.as_fd()).map_err(|_| NotRun::Spawn)?;
        }
        let child = cmd.spawn().map_err(|_| NotRun::Spawn)?;
        // This server's write end closes here: the child's copy is the
        // only one left.
        (child, pipe.map(|(r, _)| std::fs::File::from(r)))
    };
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
    let status = status.map(|r| pump(Some(r)));
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
    // A cancellation that signalled the group did so before this takes
    // the lock, after it marked the call cancelled: the call is seen
    // stopped here, and what is left of its group goes with it. One that
    // comes while the output is read kills the group itself.
    group.exited(|| timed_out || call.cancelled());
    let deadline = Instant::now() + DRAIN;
    let mut cut = false;
    for done in [&out_done, &err_done] {
        let left = deadline.saturating_duration_since(Instant::now());
        cut |= done.recv_timeout(left).is_err();
    }
    let report = status.map(|(buf, done)| {
        let left = deadline.saturating_duration_since(Instant::now());
        let ended = done.recv_timeout(left).is_ok();
        let read = lock(&buf);
        let whole = read.left_out() == 0 && read.tail().is_empty();
        Report {
            bytes: whole.then(|| read.head().to_vec()),
            ended,
        }
    });
    group.reaping(|| timed_out || call.cancelled());
    let status = child.wait();
    call.detach();
    let (code, signal) = match status {
        Ok(s) => (s.code(), s.signal()),
        Err(_) => (None, None),
    };
    let stdout = lock(&out).clone();
    let stderr = lock(&err).clone();
    let captured = Captured {
        code,
        signal,
        stdout,
        stderr,
        timed_out,
        cut,
    };
    Ok((captured, report))
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

    /// Cancelling a call whose child ignores `SIGTERM`: the group gets
    /// `SIGTERM`, a second `SIGTERM` [`TERM_GRACE`] later (on which
    /// `envcloak run` kills its command's group), then `SIGKILL`.
    ///
    /// Mutation checked: no second `SIGTERM` (straight to `SIGKILL`): the
    /// child records one `SIGTERM` and this fails.
    #[test]
    fn a_cancelled_child_gets_a_second_sigterm_before_sigkill() {
        let dir = tempfile::tempdir().unwrap();
        let rec = dir.path().join("rec");
        let ready = dir.path().join("ready");
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg("trap 'echo term >>\"$1\"' TERM; : >\"$2\"; while :; do sleep 0.05; done")
            .arg("sh")
            .arg(&rec)
            .arg(&ready);
        let call = Arc::new(Call::new());
        let running = Arc::clone(&call);
        let t = std::thread::spawn(move || run(cmd, &running, Some(Duration::from_secs(120))));
        let end = Instant::now() + Duration::from_secs(30);
        while !ready.exists() {
            assert!(Instant::now() < end, "the child did not start");
            std::thread::sleep(Duration::from_millis(10));
        }
        call.cancel();
        let done = t.join().unwrap().unwrap();
        assert_eq!(done.signal, Some(libc::SIGKILL));
        assert!(!done.timed_out);
        assert_eq!(std::fs::read_to_string(&rec).unwrap(), "term\nterm\n");
    }

    /// Cancelling a call whose leader dies of the `SIGTERM` but leaves a
    /// process in its group that ignores it (on a controlling terminal,
    /// `envcloak run` and its command are such a group): the group gets
    /// `SIGKILL` once the leader has exited, before it is reaped, so that
    /// process ends with the call. It held the output pipes, which close at
    /// once rather than at the drain's end.
    ///
    /// Mutation checked: the group not killed at the reap (`reaping`
    /// ignoring `stopped`): the process runs on holding the pipes, the
    /// output is cut at the drain's end and this fails.
    #[test]
    fn what_a_cancelled_leader_leaves_in_its_group_ends_with_it() {
        let dir = tempfile::tempdir().unwrap();
        let ready = dir.path().join("ready");
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg("(trap '' TERM; : >\"$1\"; exec sleep 30) & wait")
            .arg("sh")
            .arg(&ready);
        let call = Arc::new(Call::new());
        let running = Arc::clone(&call);
        let t = std::thread::spawn(move || run(cmd, &running, Some(Duration::from_secs(120))));
        let end = Instant::now() + Duration::from_secs(30);
        while !ready.exists() {
            assert!(Instant::now() < end, "the child did not start");
            std::thread::sleep(Duration::from_millis(10));
        }
        let start = Instant::now();
        call.cancel();
        let done = t.join().unwrap().unwrap();
        assert_eq!(done.signal, Some(libc::SIGTERM));
        assert!(!done.timed_out);
        assert!(
            !done.cut,
            "a process left in the cancelled call's group held its output"
        );
        assert!(start.elapsed() < DRAIN, "{:?}", start.elapsed());
    }

    /// A child starts with `SIGTERM`, `SIGINT` and `SIGHUP` unblocked,
    /// though the thread that starts it blocks them, as every thread of
    /// `envcloak mcp` does: a shell that sends itself each one ends by it
    /// (Codex review of M2-06, high: a waiting `envcloak run` that kept the
    /// mask went on waiting after its call was cancelled, and started its
    /// command when the approval came).
    ///
    /// Mutation checked: `run` not calling `unblock_termination_on_spawn`:
    /// the shell goes on past its own signal and this fails.
    #[test]
    fn a_child_starts_with_the_termination_signals_unblocked() {
        // On a thread of its own, whose mask ends with it.
        std::thread::spawn(|| {
            let _blocked = envcloak_sys::TerminationSignals::block().unwrap();
            for (sig, name) in [
                (libc::SIGTERM, "TERM"),
                (libc::SIGINT, "INT"),
                (libc::SIGHUP, "HUP"),
            ] {
                let mut cmd = Command::new("/bin/sh");
                cmd.arg("-c")
                    .arg(format!("kill -{name} $$; echo went-on"))
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin");
                let c = run(cmd, &Call::new(), Some(Duration::from_secs(60))).unwrap();
                assert_eq!(c.signal, Some(sig), "{name}: {c:?}");
                assert!(c.stdout.head().is_empty(), "{name}: the shell went on");
            }
        })
        .join()
        .unwrap();
    }

    /// A call cancelled after its child exited, while what the child left
    /// in its group still holds the output: that process is killed at
    /// once, with the group, which is still the unreaped child's (Codex
    /// review of M2-06, high). The fixture's leader exits as soon as its
    /// descendant, which ignores `SIGTERM` and keeps the output pipes, is
    /// set up; a lifeline only the leader holds says when it has exited,
    /// and one both hold, when both have. The call returns well before the
    /// drain's end, its output read to its end.
    ///
    /// Mutation checked: the child reaped before its output is read, as it
    /// was (`reaping` before the drain): the cancellation finds the group
    /// no longer signalled, the descendant runs on holding the output, the
    /// group's lifeline does not end and this fails.
    #[test]
    fn a_call_cancelled_while_its_output_is_read_ends_its_group_at_once() {
        use envcloak_testkit::lifeline::{self, Lifeline};
        let group = Lifeline::new();
        let leader = Lifeline::new();
        let cmd = lifeline::fixture("leader-exits", &group, Some(&leader), None);
        let call = Arc::new(Call::new());
        let running = Arc::clone(&call);
        let t = std::thread::spawn(move || run(cmd, &running, Some(Duration::from_secs(120))));
        let mut both = group
            .accept(Duration::from_secs(30))
            .expect("the fixture connected");
        let mut alone = leader
            .accept(Duration::from_secs(30))
            .expect("the leader connected");
        assert!(
            both.ready(Duration::from_secs(30)),
            "the fixture is not ready"
        );
        assert!(
            alone.ended_within(Duration::from_secs(30)),
            "the leader did not exit"
        );
        // The run has seen the exit too (and, before this fix, reaped the
        // leader): the cancellation comes after that, never before.
        let end = Instant::now() + Duration::from_secs(30);
        while !exit_seen(&call) {
            assert!(Instant::now() < end, "the run did not see the exit");
            std::thread::yield_now();
        }
        let start = Instant::now();
        call.cancel();
        assert!(
            both.ended_within(DRAIN),
            "what the child left in its group outlived the cancellation"
        );
        let done = t.join().unwrap().unwrap();
        assert_eq!(done.code, Some(0));
        assert!(
            !done.cut,
            "the output was cut: a holder outlived the cancellation"
        );
        assert!(start.elapsed() < DRAIN, "{:?}", start.elapsed());
    }

    /// Whether the run of `call` has seen its child's exit: the leader is
    /// marked exited, or reaped already.
    fn exit_seen(call: &Call) -> bool {
        lock(&call.group).as_ref().is_some_and(|g| {
            let leader = lock(&g.leader);
            leader.exited || leader.pid.is_none()
        })
    }

    #[test]
    fn a_cancelled_call_starts_nothing() {
        let call = Call::new();
        call.cancel();
        let cmd = Command::new("/bin/sh");
        assert_eq!(run(cmd, &call, None).unwrap_err(), NotRun::Cancelled);
    }
}
