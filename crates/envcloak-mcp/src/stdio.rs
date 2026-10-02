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
//!
//! What waits for the writer is bounded too: at most [`MAX_QUEUED`]
//! messages and [`MAX_QUEUED_BYTES`] bytes (one message of any size is
//! taken when nothing waits). A host that goes on sending requests but
//! stops reading the answers fills it; the next answer is then refused,
//! and the session is over ([`Outbox::stalled`]): the server stops reading
//! and stops the calls in hand, rather than keep answers it cannot
//! deliver.
//!
//! The output closes when a write fails (the host closed its end) or when
//! the queue fills. Either way the writer's owner is told at once (the
//! `on_close` of [`spawn_writer`]), so a server waiting for input that may
//! never come stops waiting.
//!
//! A message may carry a [`Ticket`] ([`Outbox::send_withdrawable`]): the
//! writer asks it, just before the write, whether the message is still to
//! be sent, and tells it when it is done with the message. A call's answer
//! waits so, and the host's cancellation of the call withdraws it while it
//! waits behind a write the host does not read (Codex review of M2-06,
//! medium).

use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;

/// The longest message taken: 1 MiB, not counting its newline.
pub const MAX_LINE: usize = 1024 * 1024;

/// The most answers waiting for the writer.
pub const MAX_QUEUED: usize = 1024;
/// The most bytes of answers waiting for the writer.
pub const MAX_QUEUED_BYTES: usize = 8 * 1024 * 1024;

/// How much is read from standard input at a time.
const CHUNK: usize = 64 * 1024;

/// What [`LineReader::next_line`] read. Its `Debug` shows a line's length,
/// never its bytes, which could hold a pasted key (L-12).
#[derive(PartialEq, Eq)]
pub enum Line {
    /// One line, without its newline (and without one `\r` before it).
    Message(Vec<u8>),
    /// A line longer than [`MAX_LINE`]: reported once, as soon as it
    /// passes the cap; the rest of it is discarded.
    Oversized,
    /// The end of input.
    End,
}

impl std::fmt::Debug for Line {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Line::Message(m) => write!(f, "Message(<{} bytes>)", m.len()),
            Line::Oversized => f.write_str("Oversized"),
            Line::End => f.write_str("End"),
        }
    }
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

/// What the writer has in hand: messages queued or being written.
#[derive(Debug, Default)]
struct Queued {
    messages: usize,
    bytes: usize,
}

/// What the writer asks of a message before it writes it.
pub trait Ticket: Send + Sync {
    /// Whether the message is still to be written. Asked once, by the
    /// writer, just before it writes it; from a true answer on the message
    /// is being sent, and it can no longer be withdrawn.
    fn take(&self) -> bool;

    /// The writer is done with the message: it was written, withdrawn, or
    /// will never be written (the output closed, or the queue refused it).
    /// Called once, from the thread that drops it.
    fn done(&self);
}

/// A message on its way to the writer. Dropped, it tells its ticket it is
/// done with, wherever that happens.
struct Outgoing {
    bytes: Vec<u8>,
    ticket: Option<Arc<dyn Ticket>>,
}

impl Drop for Outgoing {
    fn drop(&mut self) {
        if let Some(t) = self.ticket.take() {
            t.done();
        }
    }
}

/// The state an [`Outbox`] and its writer share.
struct Shared {
    /// No more is sent: a write failed, or the queue was full.
    closed: AtomicBool,
    /// The queue was full: the host stopped reading.
    stalled: AtomicBool,
    queued: Mutex<Queued>,
    /// Called once, when the output closes.
    on_close: Box<dyn Fn() + Send + Sync>,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("closed", &self.closed)
            .field("stalled", &self.stalled)
            .field("queued", &self.queued)
            .finish_non_exhaustive()
    }
}

impl Shared {
    fn queued(&self) -> std::sync::MutexGuard<'_, Queued> {
        self.queued.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Closes the output, and says so the first time.
    fn close(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            (self.on_close)();
        }
    }
}

/// Where finished messages go: the writer thread ([`spawn_writer`]).
#[derive(Clone)]
pub struct Outbox {
    tx: mpsc::Sender<Outgoing>,
    shared: Arc<Shared>,
}

impl std::fmt::Debug for Outbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Outbox")
            .field("shared", &self.shared)
            .finish_non_exhaustive()
    }
}

impl Outbox {
    /// Queues `message` (one line, newline included) for standard output.
    /// Returns false once the output has closed. A message that would
    /// pass [`MAX_QUEUED`] or [`MAX_QUEUED_BYTES`] closes it: it is not
    /// sent, nor is anything after it ([`Outbox::stalled`]).
    pub fn send(&self, message: Vec<u8>) -> bool {
        self.queue(Outgoing {
            bytes: message,
            ticket: None,
        })
    }

    /// [`Outbox::send`], for a message that `ticket` may withdraw until
    /// the writer takes it ([`Ticket::take`]). The ticket is told when the
    /// message is done with ([`Ticket::done`]), also when it is refused
    /// here.
    pub fn send_withdrawable(&self, message: Vec<u8>, ticket: Arc<dyn Ticket>) -> bool {
        self.queue(Outgoing {
            bytes: message,
            ticket: Some(ticket),
        })
    }

    fn queue(&self, message: Outgoing) -> bool {
        if self.closed() {
            return false;
        }
        {
            let mut q = self.shared.queued();
            let len = message.bytes.len();
            let over = q.messages + 1 > MAX_QUEUED || q.bytes + len > MAX_QUEUED_BYTES;
            if q.messages > 0 && over {
                drop(q);
                self.shared.stalled.store(true, Ordering::SeqCst);
                self.shared.close();
                return false;
            }
            q.messages += 1;
            q.bytes += len;
        }
        self.tx.send(message).is_ok()
    }

    /// Whether no more is sent: writing failed (the host closed its end),
    /// or the host stopped reading ([`Outbox::stalled`]).
    pub fn closed(&self) -> bool {
        self.shared.closed.load(Ordering::SeqCst)
    }

    /// Whether the queue filled: the host went on sending but stopped
    /// reading the answers.
    pub fn stalled(&self) -> bool {
        self.shared.stalled.load(Ordering::SeqCst)
    }
}

/// Starts the thread that writes `out`. It ends when every [`Outbox`] is
/// dropped and what they queued is written, or when a write fails. A
/// write the host never reads stays blocked: the server does not wait
/// for this thread for ever ([`crate::Server::run`]). `on_close` is called
/// once, from whichever thread closes the output: the writer's, on a
/// failed write, or a sender's, on a full queue.
pub fn spawn_writer<W, F>(mut out: W, on_close: F) -> (Outbox, JoinHandle<()>)
where
    W: Write + Send + 'static,
    F: Fn() + Send + Sync + 'static,
{
    let (tx, rx) = mpsc::channel::<Outgoing>();
    let shared = Arc::new(Shared {
        closed: AtomicBool::new(false),
        stalled: AtomicBool::new(false),
        queued: Mutex::new(Queued::default()),
        on_close: Box::new(on_close),
    });
    let state = Arc::clone(&shared);
    let handle = std::thread::spawn(move || {
        for message in rx {
            // A message withdrawn while it waited is dropped unwritten.
            let wanted = message.ticket.as_ref().is_none_or(|t| t.take());
            let failed = wanted
                && out
                    .write_all(&message.bytes)
                    .and_then(|()| out.flush())
                    .is_err();
            let len = message.bytes.len();
            drop(message);
            if failed {
                state.close();
                break;
            }
            let mut q = state.queued();
            q.messages -= 1;
            q.bytes -= len;
        }
    });
    (Outbox { tx, shared }, handle)
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

    /// A line's `Debug` is its length (L-12).
    ///
    /// Mutation checked: `Line` deriving `Debug`: the line's bytes show and
    /// this fails.
    #[test]
    fn a_lines_debug_is_its_length() {
        let cs = envcloak_testkit::canaries(envcloak_testkit::fresh_seed());
        for c in &cs {
            let shown = format!("{:?}", Line::Message(c.as_str().as_bytes().to_vec()));
            envcloak_testkit::assert_no_canary(shown.as_bytes(), &cs);
            assert_eq!(shown, format!("Message(<{} bytes>)", c.as_str().len()));
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

    /// An `on_close` that counts its calls in `told`.
    fn closing(told: &Arc<std::sync::atomic::AtomicUsize>) -> impl Fn() + Send + Sync + 'static {
        let told = Arc::clone(told);
        move || {
            told.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A failed write closes the output and says so, once; nothing is sent
    /// after it.
    ///
    /// Mutation checked: the writer's failure not calling `on_close`: the
    /// count stays 0 and this fails (and `tests/server.rs`'s
    /// `closed_output_ends_the_session_while_input_stays_open` hangs).
    #[test]
    fn the_writer_writes_whole_messages_until_closed() {
        let told = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (outbox, handle) = spawn_writer(Vec::<u8>::new(), || {});
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
        let (outbox, handle) = spawn_writer(Broken, closing(&told));
        assert!(outbox.send(b"a\n".to_vec()));
        handle.join().unwrap();
        assert!(outbox.closed());
        assert!(!outbox.stalled());
        assert!(!outbox.send(b"b\n".to_vec()));
        assert_eq!(
            told.load(Ordering::SeqCst),
            1,
            "the closing was not told once"
        );
    }

    /// A writer that takes nothing until told to: the host not reading.
    struct Held(mpsc::Receiver<()>, Vec<u8>);

    impl Write for Held {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            let _ = self.0.recv();
            self.1.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// While the host reads nothing, the answers waiting are bounded in
    /// count and in bytes: the one past either bound is refused, and so is
    /// everything after it. One message larger than the byte bound is
    /// taken when nothing waits. Each writer is released and joined at the
    /// end (the held write returns once its sender is dropped), so none is
    /// left blocked behind the test.
    ///
    /// Mutation checked: no bound (every message queued): the refusals do
    /// not come and this fails.
    #[test]
    fn answers_waiting_for_a_host_that_does_not_read_are_bounded() {
        let told = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (go, held) = mpsc::channel();
        let (outbox, writer) = spawn_writer(Held(held, Vec::new()), closing(&told));
        let mut sent = 0;
        while outbox.send(b"{}\n".to_vec()) {
            sent += 1;
            assert!(sent <= MAX_QUEUED, "more than {MAX_QUEUED} queued");
        }
        assert_eq!(sent, MAX_QUEUED);
        assert!(outbox.stalled() && outbox.closed());
        assert!(!outbox.send(b"{}\n".to_vec()));
        assert_eq!(
            told.load(Ordering::SeqCst),
            1,
            "the stall was not told once"
        );
        let release = |go: mpsc::Sender<()>, outbox: Outbox, writer: JoinHandle<()>| {
            drop(go);
            drop(outbox);
            writer.join().unwrap();
        };
        release(go, outbox, writer);

        let (go, held) = mpsc::channel();
        let (outbox, writer) = spawn_writer(Held(held, Vec::new()), || {});
        assert!(outbox.send(vec![b'x'; MAX_QUEUED_BYTES + 1]));
        assert!(!outbox.send(b"{}\n".to_vec()));
        assert!(outbox.stalled());
        release(go, outbox, writer);

        let (go, held) = mpsc::channel();
        let (outbox, writer) = spawn_writer(Held(held, Vec::new()), || {});
        let piece = MAX_QUEUED_BYTES / 4;
        let mut sent = 0;
        while outbox.send(vec![b'x'; piece]) {
            sent += 1;
            assert!(sent <= 4, "more than {MAX_QUEUED_BYTES} bytes queued");
        }
        assert_eq!(sent, 4);
        assert!(outbox.stalled());
        release(go, outbox, writer);
    }

    /// Answers written leave the queue: a host that reads takes any number.
    #[test]
    fn a_host_that_reads_takes_any_number_of_answers() {
        let (outbox, handle) = spawn_writer(io::sink(), || {});
        for _ in 0..4 * MAX_QUEUED {
            assert!(
                outbox.send(vec![b'x'; 64 * 1024]),
                "refused with a host that reads"
            );
            while outbox.shared.queued().messages > 0 {
                std::thread::yield_now();
            }
        }
        assert!(!outbox.stalled());
        drop(outbox);
        handle.join().unwrap();
    }
}
