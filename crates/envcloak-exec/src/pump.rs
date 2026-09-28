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
//! - once the child has exited, the [`Cutoff`] gives the pipe until its
//!   deadline: after that the pump finishes and closes the pipe, and what
//!   a descendant writes later is lost;
//! - when the output cannot be written (the reader went away), the pump
//!   stops and closes the pipe, so the child's next write to it fails as
//!   it would on a closed pipe of its own.
//!
//! The pump never buffers more than one read: a writer that blocks holds
//! the child up.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use envcloak_redact::Redactor;
use zeroize::{Zeroize, Zeroizing};

/// Bytes read from the child at a time.
const CHUNK: usize = 64 * 1024;

/// How long a write to a non-blocking output waits for room before it
/// tries again.
const WRITE_WAIT: Duration = Duration::from_millis(100);

/// When the pumps must stop reading: set once the child has exited.
#[derive(Debug, Default)]
pub(crate) struct Cutoff {
    deadline: Mutex<Option<Instant>>,
}

impl Cutoff {
    /// Starts the clock: the pumps stop `limit` from now.
    pub(crate) fn start(&self, limit: Duration) {
        let mut d = self.deadline.lock().unwrap_or_else(|e| e.into_inner());
        if d.is_none() {
            *d = Some(Instant::now() + limit);
        }
    }

    /// The time left, or `None` while the child runs.
    fn remaining(&self) -> Option<Duration> {
        self.deadline
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map(|d| d.saturating_duration_since(Instant::now()))
    }
}

/// How a pump ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PumpEnd {
    /// The pipe reached end of stream, or could not be read.
    Eof,
    /// The cutoff passed with the pipe still open.
    Cut,
    /// The output could not be written.
    OutputClosed,
}

/// An output descriptor written in full, waiting for room when it was left
/// non-blocking.
struct Sink {
    file: File,
}

impl Sink {
    fn write_all(&mut self, mut data: &[u8]) -> io::Result<()> {
        while !data.is_empty() {
            match self.file.write(data) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => data = data.get(n..).unwrap_or_default(),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    let _ = envcloak_sys::wait_writable(self.file.as_fd(), WRITE_WAIT);
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// Reads `source` to its end (or the cutoff) through a stream of
/// `redactor`, writing what it releases to `sink`. `source` is closed when
/// the pump returns.
pub(crate) fn pump<R: Read + AsFd>(
    mut source: R,
    sink: OwnedFd,
    redactor: &Redactor,
    idle: Duration,
    cutoff: &Cutoff,
) -> PumpEnd {
    let mut sink = Sink {
        file: File::from(sink),
    };
    let mut stream = redactor.stream();
    let mut buf = Zeroizing::new(vec![0u8; CHUNK]);
    // Released bytes only.
    let mut out: Vec<u8> = Vec::with_capacity(CHUNK);
    let end = loop {
        let left = cutoff.remaining();
        if left == Some(Duration::ZERO) {
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
        if !out.is_empty() {
            if sink.write_all(&out).is_err() {
                break PumpEnd::OutputClosed;
            }
            out.clear();
        }
    };
    // The child's end of the pipe is closed first: after a cutoff or a
    // lost reader nothing more is read from it.
    drop(source);
    if end != PumpEnd::OutputClosed {
        stream.finish(&mut out);
        let _ = sink.write_all(&out);
    }
    end
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;

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
        let pump =
            std::thread::spawn(move || pump(source, OwnedFd::from(sink), &redactor, idle, &cutoff));
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
}
