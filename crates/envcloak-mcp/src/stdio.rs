//! MCP's stdio transport: one JSON-RPC message per line on standard input,
//! and on standard output, written by one thread.
//!
//! [`LineReader`] holds at most [`MAX_LINE`] bytes of a line. A longer line
//! is reported as [`Line::Oversized`] as soon as it passes the cap, and the
//! rest of it, up to its newline, is read and discarded without being kept,
//! so a line of any length costs no more memory than the cap. A message
//! cannot hold a newline (MCP's stdio transport forbids it), so a message
//! sent with one arrives as two lines, each refused on its own. One `\r`
//! before the newline is dropped; an empty line is skipped.
//!
//! [`Outbox`] hands finished messages to the writer thread, which alone
//! writes standard output, each message whole and then flushed: no thread
//! and no child process ever writes there itself, so the stream holds
//! messages and nothing else.

use std::io::{self, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread::JoinHandle;

/// The longest message taken: 1 MiB, not counting its newline.
pub const MAX_LINE: usize = 1024 * 1024;

/// How much is read from standard input at a time.
const CHUNK: usize = 64 * 1024;

/// What [`LineReader::next_line`] read.
#[derive(Debug, PartialEq, Eq)]
pub enum Line {
    /// One line, without its newline (and without one `\r` before it).
    Message(Vec<u8>),
    /// A line longer than [`MAX_LINE`]: reported once, as soon as it
    /// passes the cap; the rest of it is discarded.
    Oversized,
    /// The end of input.
    End,
}

/// Lines from `R`, bounded (see the module documentation).
pub struct LineReader<R> {
    inner: R,
    buf: Vec<u8>,
    start: usize,
    end: usize,
    line: Vec<u8>,
    /// Inside a line already reported as oversized.
    discarding: bool,
}

impl<R> std::fmt::Debug for LineReader<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LineReader")
            .field("held", &self.line.len())
            .field("discarding", &self.discarding)
            .finish_non_exhaustive()
    }
}

impl<R: Read> LineReader<R> {
    pub fn new(inner: R) -> Self {
        LineReader {
            inner,
            buf: vec![0; CHUNK],
            start: 0,
            end: 0,
            line: Vec::new(),
            discarding: false,
        }
    }

    /// The next line.
    ///
    /// # Errors
    /// When reading fails other than by an interrupted call.
    pub fn next_line(&mut self) -> io::Result<Line> {
        loop {
            if self.start == self.end {
                let n = loop {
                    match self.inner.read(&mut self.buf) {
                        Ok(n) => break n,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(e) => return Err(e),
                    }
                };
                if n == 0 {
                    // A last line without its newline is still a line.
                    if self.discarding || self.line.is_empty() {
                        self.discarding = false;
                        return Ok(Line::End);
                    }
                    return Ok(self.finish());
                }
                self.start = 0;
                self.end = n;
            }
            let chunk = &self.buf[self.start..self.end];
            match chunk.iter().position(|b| *b == b'\n') {
                Some(i) => {
                    self.start += i + 1;
                    if self.discarding {
                        self.discarding = false;
                        continue;
                    }
                    if self.line.len() + i > MAX_LINE {
                        self.line.clear();
                        return Ok(Line::Oversized);
                    }
                    let piece = &self.buf[self.start - i - 1..self.start - 1];
                    self.line.extend_from_slice(piece);
                    match self.finish() {
                        Line::Message(m) if m.is_empty() => {}
                        other => return Ok(other),
                    }
                }
                None => {
                    let len = chunk.len();
                    self.start = self.end;
                    if self.discarding {
                        continue;
                    }
                    if self.line.len() + len > MAX_LINE {
                        self.line.clear();
                        self.discarding = true;
                        return Ok(Line::Oversized);
                    }
                    self.line
                        .extend_from_slice(&self.buf[self.end - len..self.end]);
                }
            }
        }
    }

    /// The line held, without one trailing `\r`.
    fn finish(&mut self) -> Line {
        let mut line = std::mem::take(&mut self.line);
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        Line::Message(line)
    }
}

/// Where finished messages go: the writer thread ([`spawn_writer`]).
#[derive(Debug, Clone)]
pub struct Outbox {
    tx: mpsc::Sender<Vec<u8>>,
    closed: Arc<AtomicBool>,
}

impl Outbox {
    /// Queues `message` (one line, newline included) for standard output.
    /// Returns false once the output has closed.
    pub fn send(&self, message: Vec<u8>) -> bool {
        !self.closed() && self.tx.send(message).is_ok()
    }

    /// Whether writing has failed: the host stopped reading.
    pub fn closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}

/// Starts the thread that writes `out`. It ends when every [`Outbox`] is
/// dropped and what they queued is written, or when a write fails.
pub fn spawn_writer<W: Write + Send + 'static>(mut out: W) -> (Outbox, JoinHandle<()>) {
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let closed = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&closed);
    let handle = std::thread::spawn(move || {
        for message in rx {
            if out.write_all(&message).and_then(|()| out.flush()).is_err() {
                flag.store(true, Ordering::SeqCst);
                break;
            }
        }
    });
    (Outbox { tx, closed }, handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reads at most `step` bytes a call, to cut lines everywhere.
    struct Trickle<'a> {
        data: &'a [u8],
        step: usize,
    }

    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.step.min(buf.len()).min(self.data.len());
            buf[..n].copy_from_slice(&self.data[..n]);
            self.data = &self.data[n..];
            Ok(n)
        }
    }

    fn all(data: &[u8], step: usize) -> Vec<Line> {
        let mut r = LineReader::new(Trickle { data, step });
        let mut out = Vec::new();
        loop {
            match r.next_line().unwrap() {
                Line::End => return out,
                l => out.push(l),
            }
        }
    }

    #[test]
    fn lines_are_cut_at_newlines_whatever_the_reads() {
        let data = b"one\r\n\ntwo\nthree";
        for step in [1, 2, 3, 7, CHUNK] {
            assert_eq!(
                all(data, step),
                vec![
                    Line::Message(b"one".to_vec()),
                    Line::Message(b"two".to_vec()),
                    Line::Message(b"three".to_vec()),
                ],
                "step {step}"
            );
        }
        assert_eq!(all(b"", 1), Vec::<Line>::new());
    }

    /// A line of exactly the cap is taken; one byte more is refused, once,
    /// and the next line is read as usual.
    #[test]
    fn a_line_over_the_cap_is_refused_and_skipped() {
        for step in [1000, CHUNK, 3 * CHUNK] {
            let mut data = vec![b'a'; MAX_LINE];
            data.push(b'\n');
            data.extend(vec![b'b'; MAX_LINE + 1]);
            data.extend_from_slice(b"\nnext\n");
            data.extend(vec![b'c'; 3 * MAX_LINE]);
            let got = all(&data, step);
            assert_eq!(got.len(), 4, "step {step}");
            assert_eq!(got[0], Line::Message(vec![b'a'; MAX_LINE]));
            assert_eq!(got[1], Line::Oversized);
            assert_eq!(got[2], Line::Message(b"next".to_vec()));
            assert_eq!(got[3], Line::Oversized);
        }
    }

    /// The reader keeps at most the cap: a line of many times the cap is
    /// refused before its end, and the reader then holds nothing of it.
    #[test]
    fn an_oversized_line_is_refused_before_its_end() {
        let data = vec![b'x'; MAX_LINE + CHUNK];
        let mut r = LineReader::new(Trickle {
            data: &data,
            step: CHUNK,
        });
        assert_eq!(r.next_line().unwrap(), Line::Oversized);
        assert!(r.line.capacity() <= MAX_LINE + CHUNK);
        assert!(r.line.is_empty());
        assert_eq!(r.next_line().unwrap(), Line::End);
    }

    #[test]
    fn the_writer_writes_whole_messages_until_closed() {
        let (outbox, handle) = spawn_writer(Vec::<u8>::new());
        assert!(outbox.send(b"a\n".to_vec()));
        drop(outbox);
        handle.join().unwrap();

        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let (outbox, handle) = spawn_writer(Broken);
        assert!(outbox.send(b"a\n".to_vec()));
        handle.join().unwrap();
        assert!(outbox.closed());
        assert!(!outbox.send(b"b\n".to_vec()));
    }
}
