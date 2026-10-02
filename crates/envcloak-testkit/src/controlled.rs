//! A server's standard input and output under a test's control (M2 plan
//! task M2-06; the cycle278 and cycle279 reviews' scaffold), each with a
//! witness of its owner dropping it, and none able to block for ever.
//!
//! - [`controlled_input`]: a reader fed line by line by the test. The end
//!   of input is the test dropping its sender ([`InputControl::end`]);
//!   whether the reader was dropped is a separate witness
//!   ([`InputControl::reader_dropped`]): a server may drop its reader, with
//!   lines still queued, while the test's sender stays open.
//! - [`controlled_output`]: a writer that keeps what it is given, and can
//!   be told to hold the next write until released
//!   ([`OutputControl::hold_next`], [`OutputControl::entered`],
//!   [`OutputControl::release`]: a host that stops reading) or to fail
//!   every write ([`OutputControl::break_writes`]: a host that closed its
//!   end). A held write gives up after [`HOLD_FALLBACK`], and the control's
//!   drop releases it, so a failing test never leaves a writer blocked.

use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

/// How long a held write waits for its release before it fails.
pub const HOLD_FALLBACK: Duration = Duration::from_secs(30);

/// How far the reader of [`controlled_input`] has got.
#[derive(Debug, Default)]
struct Progress {
    /// Chunks sent by the test.
    sent: usize,
    /// Chunks the reader has taken.
    taken: usize,
    /// The reader has given out every byte it took, and waits for more.
    waiting: bool,
}

/// The reader end of [`controlled_input`].
#[derive(Debug)]
pub struct ControlledInput {
    rx: Receiver<Vec<u8>>,
    held: Vec<u8>,
    progress: Arc<Mutex<Progress>>,
    dropped: Arc<AtomicBool>,
}

impl Read for ControlledInput {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.held.is_empty() {
            lock(&self.progress).waiting = true;
            let next = self.rx.recv();
            let mut p = lock(&self.progress);
            p.waiting = false;
            match next {
                Ok(v) => {
                    p.taken += 1;
                    self.held = v;
                }
                Err(_) => return Ok(0),
            }
        }
        let n = buf.len().min(self.held.len());
        buf[..n].copy_from_slice(&self.held[..n]);
        self.held.drain(..n);
        Ok(n)
    }
}

impl Drop for ControlledInput {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

/// The test's end of [`controlled_input`].
#[derive(Debug)]
pub struct InputControl {
    tx: Option<Sender<Vec<u8>>>,
    progress: Arc<Mutex<Progress>>,
    dropped: Arc<AtomicBool>,
}

impl InputControl {
    /// Sends `bytes` as they are, as one chunk. Whether the reader may
    /// still read them.
    pub fn send_raw(&self, bytes: &[u8]) -> bool {
        let mut p = lock(&self.progress);
        let sent = self
            .tx
            .as_ref()
            .is_some_and(|tx| tx.send(bytes.to_vec()).is_ok());
        p.sent += usize::from(sent);
        sent
    }

    /// Waits up to `limit` until the reader has taken every chunk sent,
    /// given out all of it, and asks for more. A server that reads one
    /// line ahead of what it handles has then handled every line but the
    /// last two: a barrier for a line sent two lines before the end, never
    /// a sleep. Whether that came in time.
    pub fn all_read(&self, limit: Duration) -> bool {
        let end = std::time::Instant::now() + limit;
        loop {
            {
                let p = lock(&self.progress);
                if p.taken == p.sent && p.waiting {
                    return true;
                }
            }
            if std::time::Instant::now() >= end {
                return false;
            }
            std::thread::yield_now();
        }
    }

    /// Sends `v` as one line.
    pub fn send(&self, v: &serde_json::Value) -> bool {
        let mut line = serde_json::to_vec(v).unwrap_or_default();
        line.push(b'\n');
        self.send_raw(&line)
    }

    /// Ends the input: the reader reads the end once it has read what was
    /// sent.
    pub fn end(&mut self) {
        self.tx = None;
    }

    /// Whether the test still holds its sender: the input has not ended.
    pub fn open(&self) -> bool {
        self.tx.is_some()
    }

    /// Whether the reader was dropped.
    pub fn reader_dropped(&self) -> bool {
        self.dropped.load(Ordering::SeqCst)
    }
}

/// A reader the test feeds, and the test's end of it.
pub fn controlled_input() -> (ControlledInput, InputControl) {
    let (tx, rx) = mpsc::channel();
    let dropped = Arc::new(AtomicBool::new(false));
    let progress = Arc::new(Mutex::new(Progress::default()));
    (
        ControlledInput {
            rx,
            held: Vec::new(),
            progress: Arc::clone(&progress),
            dropped: Arc::clone(&dropped),
        },
        InputControl {
            tx: Some(tx),
            progress,
            dropped,
        },
    )
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

const NORMAL: u8 = 0;
const HOLD_NEXT: u8 = 1;
const BROKEN: u8 = 2;

/// The writer end of [`controlled_output`].
#[derive(Debug)]
pub struct ControlledOutput {
    bytes: Arc<Mutex<Vec<u8>>>,
    mode: Arc<AtomicU8>,
    entered: Sender<()>,
    release: Receiver<()>,
    dropped: Arc<AtomicBool>,
}

impl Write for ControlledOutput {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.mode.load(Ordering::SeqCst) {
            BROKEN => return Err(io::ErrorKind::BrokenPipe.into()),
            HOLD_NEXT => {
                self.mode.store(NORMAL, Ordering::SeqCst);
                let _ = self.entered.send(());
                if self.release.recv_timeout(HOLD_FALLBACK).is_err() {
                    return Err(io::ErrorKind::TimedOut.into());
                }
            }
            _ => {}
        }
        lock(&self.bytes).extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for ControlledOutput {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

/// The test's end of [`controlled_output`]. Dropped, it releases a held
/// write.
#[derive(Debug)]
pub struct OutputControl {
    bytes: Arc<Mutex<Vec<u8>>>,
    mode: Arc<AtomicU8>,
    entered: Receiver<()>,
    release: Option<Sender<()>>,
    dropped: Arc<AtomicBool>,
}

impl OutputControl {
    /// The next write waits until [`OutputControl::release`] (at most
    /// [`HOLD_FALLBACK`]), as a host that stops reading holds it.
    pub fn hold_next(&self) {
        self.mode.store(HOLD_NEXT, Ordering::SeqCst);
    }

    /// Every write from now on fails, as one to a host that closed its end.
    pub fn break_writes(&self) {
        self.mode.store(BROKEN, Ordering::SeqCst);
    }

    /// Whether a held write began within `limit`.
    pub fn entered(&self, limit: Duration) -> bool {
        self.entered.recv_timeout(limit).is_ok()
    }

    /// Lets a held write go on. Releases only once; later holds then wait
    /// for their fallback.
    pub fn release(&mut self) {
        if let Some(tx) = self.release.take() {
            let _ = tx.send(());
        }
    }

    /// Everything written so far.
    pub fn bytes(&self) -> Vec<u8> {
        lock(&self.bytes).clone()
    }

    /// The messages written so far, one per line; a line that is not JSON
    /// is `Err` with its length.
    pub fn messages(&self) -> Vec<Result<serde_json::Value, usize>> {
        self.bytes()
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_slice(l).map_err(|_| l.len()))
            .collect()
    }

    /// Whether the writer was dropped.
    pub fn writer_dropped(&self) -> bool {
        self.dropped.load(Ordering::SeqCst)
    }
}

impl Drop for OutputControl {
    fn drop(&mut self) {
        self.release();
    }
}

/// A writer the test controls, and the test's end of it.
pub fn controlled_output() -> (ControlledOutput, OutputControl) {
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let mode = Arc::new(AtomicU8::new(NORMAL));
    let dropped = Arc::new(AtomicBool::new(false));
    let (entered_tx, entered) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    (
        ControlledOutput {
            bytes: Arc::clone(&bytes),
            mode: Arc::clone(&mode),
            entered: entered_tx,
            release: release_rx,
            dropped: Arc::clone(&dropped),
        },
        OutputControl {
            bytes,
            mode,
            entered,
            release: Some(release),
            dropped,
        },
    )
}
