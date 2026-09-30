//! One output stream of the child, through the redactor (SPEC §6.1 step
//! 7).
//!
//! A pump reads the child's end of one pipe and writes what the redactor
//! releases to one output descriptor:
//! - every read is `push`ed; the read buffer, which holds the child's raw
//!   bytes, is wiped after each read and when the pump ends;
//! - when nothing arrives for the idle interval, `flush_idle` releases the
//!   held-back bytes that cannot be the start of a value, so a prompt
//!   without a newline shows up;
//! - at end of stream, `finish` releases the rest, redacted;
//! - once the child has exited, the [`Cutoff`] gives a pipe that a
//!   descendant still holds open until its deadline: after that the pump
//!   closes the pipe, and what the descendant writes later is lost;
//! - when the output cannot be written (the reader went away), the pump
//!   stops and closes the pipe, so the child's next write to it fails as
//!   it would on a closed pipe of its own.
//!
//! The pump never buffers more than one read: a writer that blocks holds
//! the child up. How long a write to an output nobody reads may wait
//! depends on the pipe (review F-49):
//! - while a writer holds the pipe open, until the cutoff's deadline: a
//!   write still waiting then is given up, the pipe closed, and what the
//!   redactor held back written only as far as the output takes it at
//!   once. So a descendant that holds the pipe, with a reader that has
//!   stopped, holds the run up for no longer than the cutoff;
//! - once no writer holds it (the child and every descendant closed it:
//!   [`envcloak_sys::hung_up`]), what is left in it is read to the end and
//!   delivered as fast as the reader takes it, as it would be from any
//!   program writing there.
//!
//! A write to a non-blocking output waits for room with `poll`, until the
//! deadline. A blocking write that must be given up is broken off by
//! [`Cutoff::wait_for_pumps`], which interrupts the pumps' threads
//! ([`envcloak_sys::Interrupter`]) until they have ended.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use envcloak_redact::Redactor;
use envcloak_sys::Interrupter;
use zeroize::{Zeroize, Zeroizing};

/// Bytes read from the child at a time.
const CHUNK: usize = 64 * 1024;

/// How often [`Cutoff::wait_for_pumps`] interrupts the pumps while one
/// must give up: an interruption that lands just before a pump enters its
/// write is lost, and the next one ends the write.
const NUDGE: Duration = Duration::from_millis(20);

/// When the pumps must stop: set once the child has exited. Also counts
/// the pumps still running, and those whose pipe no writer holds any
/// more, so the thread that waits for them knows when to break off their
/// writes.
#[derive(Debug, Default)]
pub(crate) struct Cutoff {
    state: Mutex<CutState>,
    changed: Condvar,
}

#[derive(Debug, Default)]
struct CutState {
    deadline: Option<Instant>,
    /// Pumps started and not yet ended ([`PumpToken`]).
    pumps: usize,
    /// Of those, the ones whose pipe no writer holds ([`PumpToken::settle`]).
    settled: usize,
}

impl CutState {
    fn passed(&self) -> bool {
        self.deadline.is_some_and(|d| d <= Instant::now())
    }
}

/// One pump, counted by [`Cutoff::wait_for_pumps`] from before its thread
/// starts until the token is dropped: when the pump returns, or with its
/// thread's closure when the thread could not be started.
#[derive(Debug)]
pub(crate) struct PumpToken<'a> {
    cutoff: &'a Cutoff,
    settled: bool,
}

/// Where a pump is, for how long its writes may wait.
#[derive(Clone, Copy)]
enum Phase<'f> {
    /// Reading its pipe, `fd`.
    Reading(BorrowedFd<'f>),
    /// Its pipe reached its end: what is left waits for the reader.
    Ended,
    /// It closed its pipe at the cutoff: only what the output takes at
    /// once.
    Cut,
}

impl PumpToken<'_> {
    /// No writer holds the pump's pipe any more: what it still writes
    /// waits for the reader, deadline or not.
    fn settle(&mut self) {
        if !self.settled {
            self.settled = true;
            self.cutoff.lock().settled += 1;
            self.cutoff.changed.notify_all();
        }
    }

    /// Whether a writer still holds the pipe `fd` open. Once none does,
    /// the pump settles. A pipe that cannot be asked counts as held.
    fn held(&mut self, fd: BorrowedFd<'_>) -> bool {
        if self.settled {
            return false;
        }
        if envcloak_sys::hung_up(fd).unwrap_or(false) {
            self.settle();
            return false;
        }
        true
    }

    /// Whether the pump, in `phase`, must stop reading or give up a write
    /// that has not finished: after a cut always, and while reading, once
    /// the deadline has passed with a writer still holding the pipe.
    fn must_give_up(&mut self, phase: Phase<'_>) -> bool {
        let passed = self.cutoff.lock().passed();
        match phase {
            Phase::Cut => true,
            Phase::Ended => false,
            Phase::Reading(fd) => passed && self.held(fd),
        }
    }

    /// How long a write in `phase` waits for room on a non-blocking output
    /// before it looks again: until the deadline while the pipe is held
    /// (for ever while the child runs), not at all after a cut, and
    /// otherwise until an interruption.
    fn room_wait(&self, phase: Phase<'_>) -> Duration {
        match phase {
            Phase::Cut => Duration::ZERO,
            Phase::Reading(_) if !self.settled => self.cutoff.remaining().unwrap_or(Duration::MAX),
            Phase::Reading(_) | Phase::Ended => Duration::MAX,
        }
    }
}

impl Drop for PumpToken<'_> {
    fn drop(&mut self) {
        let mut st = self.cutoff.lock();
        st.pumps = st.pumps.saturating_sub(1);
        if self.settled {
            st.settled = st.settled.saturating_sub(1);
        }
        self.cutoff.changed.notify_all();
    }
}

impl Cutoff {
    fn lock(&self) -> MutexGuard<'_, CutState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Starts the clock: the pumps stop `limit` from now. A deadline set
    /// already stays.
    pub(crate) fn start(&self, limit: Duration) {
        let mut st = self.lock();
        if st.deadline.is_none() {
            st.deadline = Some(Instant::now() + limit);
            self.changed.notify_all();
        }
    }

    /// The time left, or `None` while the child runs.
    fn remaining(&self) -> Option<Duration> {
        self.lock()
            .deadline
            .map(|d| d.saturating_duration_since(Instant::now()))
    }

    /// Counts one more pump until the token is dropped. Taken before the
    /// pump's thread is started.
    pub(crate) fn pump_token(&self) -> PumpToken<'_> {
        self.lock().pumps += 1;
        PumpToken {
            cutoff: self,
            settled: false,
        }
    }

    /// Waits until every counted pump has ended. While one may have to give
    /// up its write (the deadline has passed and a pump has not seen its
    /// pipe released by every writer), the pumps'
    /// threads are interrupted every [`NUDGE`]: a write blocked on an
    /// output nobody reads returns then, and the pump that must give it up
    /// does. Otherwise nothing is interrupted, so ordinary backpressure
    /// holds.
    pub(crate) fn wait_for_pumps(&self, threads: &Interrupter) {
        let mut st = self.lock();
        while st.pumps > 0 {
            let nudge = st.passed() && st.pumps > st.settled;
            if nudge {
                drop(st);
                threads.interrupt();
                st = self.lock();
                if st.pumps > 0 {
                    st = self
                        .changed
                        .wait_timeout(st, NUDGE)
                        .unwrap_or_else(|e| e.into_inner())
                        .0;
                }
                continue;
            }
            let now = Instant::now();
            st = match st.deadline {
                Some(d) if d > now => {
                    self.changed
                        .wait_timeout(st, d - now)
                        .unwrap_or_else(|e| e.into_inner())
                        .0
                }
                _ => self.changed.wait(st).unwrap_or_else(|e| e.into_inner()),
            };
        }
    }
}

/// How a pump ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PumpEnd {
    /// The pipe reached end of stream, or could not be read.
    Eof,
    /// The cutoff passed with a writer still holding the pipe.
    Cut,
    /// The output could not be written.
    OutputClosed,
}

/// Why released bytes were not all written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Undelivered {
    /// The pump had to give up before the output took them.
    Cut,
    /// The output failed: its reader is gone, or it is not writable.
    Closed,
}

/// An output descriptor.
struct Sink {
    file: File,
}

impl Sink {
    /// Writes `out`, and removes what was written from it. A write is
    /// always tried; one that does not finish (interrupted, short, or
    /// waiting for room) is tried again unless the pump, in `phase`, must
    /// give up ([`PumpToken::must_give_up`]).
    fn deliver(
        &mut self,
        out: &mut Vec<u8>,
        token: &mut PumpToken<'_>,
        phase: Phase<'_>,
    ) -> Result<(), Undelivered> {
        let mut done = 0;
        let result = loop {
            let Some(rest) = out.get(done..).filter(|r| !r.is_empty()) else {
                break Ok(());
            };
            match self.file.write(rest) {
                Ok(0) => break Err(Undelivered::Closed),
                Ok(n) => done += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    let wait = token.room_wait(phase);
                    let _ = envcloak_sys::wait_writable(self.file.as_fd(), wait);
                }
                Err(_) => break Err(Undelivered::Closed),
            }
            if done < out.len() && token.must_give_up(phase) {
                break Err(Undelivered::Cut);
            }
        };
        out.drain(..done.min(out.len()));
        result
    }
}

/// Reads `source` to its end (or the cutoff) through a stream of
/// `redactor`, writing what it releases to `sink`. `source` is closed when
/// the pump returns, and `token`, which counts the pump in its [`Cutoff`],
/// is dropped.
pub(crate) fn pump<R: Read + AsFd>(
    mut source: R,
    sink: OwnedFd,
    redactor: &Redactor,
    idle: Duration,
    mut token: PumpToken<'_>,
) -> PumpEnd {
    let cutoff = token.cutoff;
    let mut sink = Sink {
        file: File::from(sink),
    };
    let mut stream = redactor.stream();
    let mut buf = Zeroizing::new(vec![0u8; CHUNK]);
    // Released bytes only.
    let mut out: Vec<u8> = Vec::with_capacity(CHUNK);
    let end = loop {
        let left = cutoff.remaining();
        if left == Some(Duration::ZERO) && token.must_give_up(Phase::Reading(source.as_fd())) {
            break PumpEnd::Cut;
        }
        let wait = left.map_or(idle, |l| l.min(idle));
        match envcloak_sys::wait_readable(source.as_fd(), wait) {
            Ok(true) => match source.read(&mut buf[..]) {
                Ok(0) => break PumpEnd::Eof,
                Ok(n) => {
                    stream.push(buf.get(..n).unwrap_or_default(), &mut out);
                    if let Some(read) = buf.get_mut(..n) {
                        read.zeroize();
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) => {}
                Err(_) => break PumpEnd::Eof,
            },
            Ok(false) => stream.flush_idle(&mut out),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break PumpEnd::Eof,
        }
        match sink.deliver(&mut out, &mut token, Phase::Reading(source.as_fd())) {
            Ok(()) => {}
            Err(Undelivered::Cut) => break PumpEnd::Cut,
            Err(Undelivered::Closed) => break PumpEnd::OutputClosed,
        }
    };
    // The child's end of the pipe is closed first: after a cutoff or a
    // lost reader nothing more is read from it.
    drop(source);
    let phase = match end {
        PumpEnd::Eof => {
            token.settle();
            Phase::Ended
        }
        PumpEnd::Cut | PumpEnd::OutputClosed => Phase::Cut,
    };
    if end != PumpEnd::OutputClosed {
        // What the output did not take, then the rest the redactor held
        // back.
        stream.finish(&mut out);
        let _ = sink.deliver(&mut out, &mut token, phase);
    }
    end
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, mpsc};

    use envcloak_redact::RedactorBuilder;

    use super::*;

    /// A value made at run time from letters and digits.
    fn value() -> Vec<u8> {
        let mut x = u64::from(std::process::id()) ^ 0x2545_f491_4f6c_dd1d;
        (0..40)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                b"abcdefghijklmnopqrstuvwxyz0123456789"[usize::try_from(x % 36).unwrap()]
            })
            .collect()
    }

    /// A pump from a socket pair to another, on its own thread. Returns
    /// the writing end, the reading end of the output, and the pump.
    fn start(
        redactor: Arc<Redactor>,
        idle: Duration,
        cutoff: Arc<Cutoff>,
    ) -> (UnixStream, UnixStream, std::thread::JoinHandle<PumpEnd>) {
        let (child_side, source) = UnixStream::pair().unwrap();
        let (sink, reader) = UnixStream::pair().unwrap();
        let pump = std::thread::spawn(move || {
            let token = cutoff.pump_token();
            pump(source, OwnedFd::from(sink), &redactor, idle, token)
        });
        (child_side, reader, pump)
    }

    /// Reads from `r` until `want` has arrived; returns how long it took.
    fn read_until(r: &mut UnixStream, want: &[u8], got: &mut Vec<u8>) -> Duration {
        let start = Instant::now();
        r.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut b = [0u8; 4096];
        while !got.windows(want.len()).any(|w| w == want) {
            let n = r.read(&mut b).unwrap();
            assert!(n > 0, "the output ended early");
            got.extend_from_slice(&b[..n]);
        }
        start.elapsed()
    }

    /// A prompt without a newline is written out within 100 ms; the start
    /// of a value is held until the rest shows it is not one, or until the
    /// value is complete and redacted.
    #[test]
    fn a_prompt_shows_at_once_and_the_start_of_a_value_waits() {
        let v = value();
        let (r, _) = RedactorBuilder::new().secret("t/x", &v).build();
        let (mut child, mut out, pump) =
            start(Arc::new(r), Duration::from_millis(40), Arc::default());
        let mut got = Vec::new();

        child.write_all(b"Continue? [y/N] ").unwrap();
        let took = read_until(&mut out, b"Continue? [y/N] ", &mut got);
        assert!(
            took < Duration::from_millis(100),
            "the prompt took {took:?}"
        );

        // The first half of the value: held, however long the pipe is quiet.
        child.write_all(&v[..20]).unwrap();
        out.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let mut b = [0u8; 64];
        assert!(
            out.read(&mut b).is_err(),
            "the start of a value was released"
        );
        // The rest: the whole value, redacted.
        child.write_all(&v[20..]).unwrap();
        child.write_all(b"\n").unwrap();
        read_until(&mut out, b"[envcloak:t/x]\n", &mut got);
        // A half that turns out not to be the value is released as it was.
        child.write_all(&v[..20]).unwrap();
        child.write_all(b"!\n").unwrap();
        let mut tail = v[..20].to_vec();
        tail.extend_from_slice(b"!\n");
        read_until(&mut out, &tail, &mut got);
        drop(child);
        assert_eq!(pump.join().unwrap(), PumpEnd::Eof);
        assert!(!got.windows(v.len()).any(|w| w == v.as_slice()));
    }

    /// Once the cutoff passes, the pump finishes with the pipe still open:
    /// what was held is released, redacted, and nothing after it.
    #[test]
    fn the_cutoff_ends_a_pipe_a_descendant_holds() {
        let v = value();
        let (r, _) = RedactorBuilder::new().secret("t/x", &v).build();
        let cutoff = Arc::new(Cutoff::default());
        let (mut child, mut out, pump) =
            start(Arc::new(r), Duration::from_millis(40), Arc::clone(&cutoff));
        child.write_all(b"before ").unwrap();
        child.write_all(&v).unwrap();
        let mut got = Vec::new();
        read_until(&mut out, b"before [envcloak:t/x]", &mut got);
        let started = Instant::now();
        cutoff.start(Duration::from_millis(200));
        assert_eq!(pump.join().unwrap(), PumpEnd::Cut);
        assert!(started.elapsed() >= Duration::from_millis(190));
        // The pipe is closed: the writer's next write fails.
        assert!(child.write_all(&[b'x'; 1 << 16]).is_err());
        let mut rest = Vec::new();
        out.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty());
    }

    /// When the output's reader is gone, the pump stops and closes the
    /// child's pipe.
    #[test]
    fn a_closed_output_closes_the_pipe() {
        let (r, _) = RedactorBuilder::new().secret("t/x", value()).build();
        let (mut child, out, pump) = start(Arc::new(r), Duration::from_millis(40), Arc::default());
        drop(out);
        let result = (0..1000).try_for_each(|_| child.write_all(&[b'y'; 4096]));
        assert!(result.is_err(), "the pipe stayed open");
        assert_eq!(pump.join().unwrap(), PumpEnd::OutputClosed);
    }

    /// The interrupter is process-wide: the tests that use it take turns.
    static TURN: Mutex<()> = Mutex::new(());

    /// A pump whose output nobody reads: its socket is filled before the
    /// pump starts, so the pump's first write finds no room (blocking, or
    /// `nonblocking`). The pump runs inside `interrupter`, and `cutoff`
    /// counts it by the time this returns. Returns the child's side of the
    /// pipe, the output's reader (kept open, never read unless a test
    /// drains it), the pump, and how many bytes filled the output.
    fn start_stalled(
        cutoff: &Arc<Cutoff>,
        interrupter: &Arc<Interrupter>,
        nonblocking: bool,
    ) -> (
        UnixStream,
        UnixStream,
        std::thread::JoinHandle<PumpEnd>,
        usize,
    ) {
        let (r, _) = RedactorBuilder::new().secret("t/x", value()).build();
        let (child_side, source) = UnixStream::pair().unwrap();
        let (sink, reader) = UnixStream::pair().unwrap();
        // The socket's file is shared with the clone: non-blocking to fill
        // it, then back to what the test wants.
        let mut filler = sink.try_clone().unwrap();
        filler.set_nonblocking(true).unwrap();
        let mut filled = 0;
        for size in [4096, 1] {
            loop {
                match filler.write(&vec![b'.'; size]) {
                    Ok(n) => filled += n,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => panic!("filling the output: {e}"),
                }
            }
        }
        filler.set_nonblocking(nonblocking).unwrap();
        drop(filler);
        let (counted, ready) = mpsc::channel();
        let (cutoff, interrupter) = (Arc::clone(cutoff), Arc::clone(interrupter));
        let pump = std::thread::spawn(move || {
            let token = cutoff.pump_token();
            counted.send(()).unwrap();
            interrupter.run(|| {
                pump(
                    source,
                    OwnedFd::from(sink),
                    &r,
                    Duration::from_millis(40),
                    token,
                )
            })
        });
        ready.recv().unwrap();
        (child_side, reader, pump, filled)
    }

    /// `wait_for_pumps` on a thread of its own: its end arrives on the
    /// channel, so a test can bound the wait (a pump that never gives up
    /// would hold the test for ever).
    fn waiting(cutoff: &Arc<Cutoff>, interrupter: &Arc<Interrupter>) -> mpsc::Receiver<()> {
        let (done, ended) = mpsc::channel();
        let (cutoff, interrupter) = (Arc::clone(cutoff), Arc::clone(interrupter));
        std::thread::spawn(move || {
            cutoff.wait_for_pumps(&interrupter);
            let _ = done.send(());
        });
        ended
    }

    /// Review F-49: a pipe a descendant holds open, and an output nobody
    /// reads. The pump is stuck writing what it released, blocking or
    /// waiting for room, when the cutoff passes; it gives the write up,
    /// closes the pipe (the writer's next write fails) and ends, and the
    /// wait for it ends within the cutoff plus a margin. Before the cutoff,
    /// the stuck write is ordinary backpressure and nothing is given up.
    #[test]
    fn a_stalled_output_is_given_up_at_the_cutoff_while_the_pipe_is_open() {
        let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
        let interrupter = Arc::new(Interrupter::install().unwrap());
        for nonblocking in [false, true] {
            let cutoff = Arc::new(Cutoff::default());
            let (mut child, _reader, pump, _) = start_stalled(&cutoff, &interrupter, nonblocking);
            // Released after the idle flush, then stuck: no room.
            child.write_all(b"hello\n").unwrap();
            let ended = waiting(&cutoff, &interrupter);
            assert!(
                ended.recv_timeout(Duration::from_millis(300)).is_err(),
                "gave up before any cutoff ({nonblocking})"
            );
            let started = Instant::now();
            cutoff.start(Duration::from_millis(300));
            ended
                .recv_timeout(Duration::from_secs(10))
                .unwrap_or_else(|_| panic!("the stuck write was never given up ({nonblocking})"));
            let took = started.elapsed();
            assert!(took >= Duration::from_millis(290), "{took:?}");
            assert!(took < Duration::from_secs(3), "{took:?}");
            assert_eq!(pump.join().unwrap(), PumpEnd::Cut);
            assert!(
                (0..64)
                    .try_for_each(|_| child.write_all(&[b'x'; 4096]))
                    .is_err(),
                "the pipe stayed open ({nonblocking})"
            );
        }
    }

    /// The control: a pipe the child has closed, with more in it than one
    /// read, and a reader that is only slow. Well past the deadline it
    /// reads everything, and the pump ends at the end of the pipe.
    #[test]
    fn a_slow_reader_gets_all_of_an_ended_pipe_past_the_deadline() {
        let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
        let interrupter = Arc::new(Interrupter::install().unwrap());
        let cutoff = Arc::new(Cutoff::default());
        let (mut child, mut reader, pump, filled) = start_stalled(&cutoff, &interrupter, false);
        // Small enough for the pipe to take it all while the output is
        // stalled, so the writer can close it before the deadline.
        let body: Vec<u8> = (0..6000u32)
            .map(|i| b"abcdefgh\n"[(i % 9) as usize])
            .collect();
        child.write_all(&body).unwrap();
        drop(child);
        cutoff.start(Duration::from_millis(50));
        let ended = waiting(&cutoff, &interrupter);
        assert!(
            ended.recv_timeout(Duration::from_millis(400)).is_err(),
            "a pipe no writer holds was cut at the deadline"
        );
        let mut got = Vec::new();
        reader.read_to_end(&mut got).unwrap();
        ended.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(pump.join().unwrap(), PumpEnd::Eof);
        assert_eq!(got.len(), filled + body.len());
        assert!(got[filled..] == body[..], "the output changed");
    }
}
