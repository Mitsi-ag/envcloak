//! Frames (SPEC §4 "envcloak-ipc", §10a "Bounds"): a 4-byte big-endian
//! length, then that many bytes of JSON, one JSON-RPC 2.0 message.
//!
//! - A frame is at most [`MAX_FRAME`] bytes (1 MiB). A header announcing
//!   more, or an empty frame, is refused before anything else is read or
//!   allocated.
//! - A frame may carry values (a passphrase, and later the values a run
//!   receives), so its body lives in a [`SecretBuf`], wiped on drop. An
//!   incoming body starts in a small buffer that grows only as bytes
//!   arrive; growing copies into a new buffer and wipes the old one.
//! - [`Frame::encode`] serializes straight into the body, and
//!   [`Frame::decode`] parses from it without copying strings out: a
//!   [`crate::WireSecret`] is decoded from the frame into its own
//!   [`SecretBuf`].
//! - Errors carry a kind only. A decode error never carries serde's text,
//!   which can quote the offending input.

use std::io::{self, Read, Write};

use envcloak_core::SecretBuf;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

/// The largest frame body, in bytes.
pub const MAX_FRAME: usize = 1 << 20;

/// The first allocation for an incoming body. It doubles as bytes arrive,
/// up to the announced length.
const INITIAL_CAPACITY: usize = 16 * 1024;

/// One frame's body: a JSON-RPC message.
pub struct Frame {
    body: SecretBuf,
}

impl core::fmt::Debug for Frame {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Frame")
            .field("len", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// Why a frame could not be read or written. Carries its kind only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrameError {
    /// The peer closed the connection between frames.
    Closed,
    /// The connection closed or failed (a reset, an abort), or its
    /// deadline passed, inside a frame.
    Truncated,
    /// The header announced more than [`MAX_FRAME`] bytes, or a message
    /// does not fit in one frame.
    TooLarge,
    /// The header announced an empty frame.
    Empty,
    /// Reading or writing failed.
    Io(io::ErrorKind),
}

impl FrameError {
    /// The fixed message for this error.
    pub fn message(self) -> &'static str {
        match self {
            FrameError::Closed => "the connection closed",
            FrameError::Truncated => {
                "the connection closed or timed out in the middle of a message"
            }
            FrameError::TooLarge => "a message exceeds the 1 MiB frame limit",
            FrameError::Empty => "an empty message",
            FrameError::Io(_) => "reading or writing the daemon socket failed",
        }
    }
}

impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for FrameError {}

/// Why a frame's JSON did not decode. Carries its kind only, never
/// serde's message, which can quote the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecodeError {
    /// Not valid JSON.
    Syntax,
    /// Valid JSON of the wrong shape: a missing or unknown field, a value
    /// of the wrong type, or a secret that is not plain base64.
    Data,
    /// The JSON ended early.
    Eof,
}

impl DecodeError {
    /// The fixed message for this error.
    pub fn message(self) -> &'static str {
        match self {
            DecodeError::Syntax => "a message is not valid JSON",
            DecodeError::Data => "a message does not have the expected fields and types",
            DecodeError::Eof => "a message ends early",
        }
    }
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for DecodeError {}

impl From<serde_json::Error> for DecodeError {
    fn from(e: serde_json::Error) -> Self {
        use serde_json::error::Category;
        match e.classify() {
            Category::Syntax => DecodeError::Syntax,
            Category::Eof => DecodeError::Eof,
            Category::Data | Category::Io => DecodeError::Data,
        }
    }
}

/// Serializes into a body, growing it by copying into a larger buffer and
/// wiping the old one, and refusing to grow past [`MAX_FRAME`].
struct BodyWriter<'a> {
    body: &'a mut SecretBuf,
    too_large: bool,
}

impl Write for BodyWriter<'_> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let need = self.body.len().saturating_add(b.len());
        if need > MAX_FRAME {
            self.too_large = true;
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if need > self.body.capacity() {
            let doubled = self.body.capacity().saturating_mul(2);
            self.body.grow(doubled.max(need).min(MAX_FRAME));
        }
        self.body
            .extend(b)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        Ok(b.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Frame {
    /// Serializes `v` as the body of a new frame.
    ///
    /// # Errors
    /// [`FrameError::TooLarge`] when it does not fit in [`MAX_FRAME`]
    /// bytes, [`FrameError::Empty`] when it serializes to nothing.
    pub fn encode<T: Serialize + ?Sized>(v: &T) -> Result<Frame, FrameError> {
        let mut body = SecretBuf::with_capacity(512);
        let mut w = BodyWriter {
            body: &mut body,
            too_large: false,
        };
        match serde_json::to_writer(&mut w, v) {
            Ok(()) => {}
            Err(_) if w.too_large => return Err(FrameError::TooLarge),
            Err(_) => return Err(FrameError::Io(io::ErrorKind::InvalidData)),
        }
        if body.is_empty() {
            return Err(FrameError::Empty);
        }
        Ok(Frame { body })
    }

    /// Parses the body as `T`, borrowing strings from it where `T` does.
    ///
    /// # Errors
    /// A [`DecodeError`] kind, never serde's message.
    #[allow(clippy::disallowed_methods)] // Parses the body in place.
    pub fn decode<'a, T: Deserialize<'a>>(&'a self) -> Result<T, DecodeError> {
        serde_json::from_slice(self.body.expose_secret()).map_err(DecodeError::from)
    }

    /// The body's length in bytes. Not secret.
    pub fn len(&self) -> usize {
        self.body.len()
    }

    pub fn is_empty(&self) -> bool {
        self.body.is_empty()
    }

    /// Reads one frame. A header announcing an empty frame or more than
    /// [`MAX_FRAME`] bytes is refused before any of the body is read.
    ///
    /// # Errors
    /// [`FrameError::Closed`] when the stream ends before a header starts,
    /// and [`FrameError::Io`] when reading fails or times out before one
    /// starts; [`FrameError::Truncated`] when the stream ends, fails (a
    /// reset, an abort) or times out once part of a frame was read;
    /// [`FrameError::Empty`] and [`FrameError::TooLarge`] for a refused
    /// header.
    pub fn read_from(r: &mut impl Read) -> Result<Frame, FrameError> {
        let mut header = [0u8; 4];
        let mut got = 0;
        while got < header.len() {
            match r.read(&mut header[got..]) {
                Ok(0) if got == 0 => return Err(FrameError::Closed),
                Ok(0) => return Err(FrameError::Truncated),
                Ok(n) => got += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                // Inside a frame, however the stream failed: a caller
                // must never take it for a frame that was not sent.
                Err(_) if got > 0 => return Err(FrameError::Truncated),
                Err(e) => return Err(FrameError::Io(e.kind())),
            }
        }
        let len = usize::try_from(u32::from_be_bytes(header)).unwrap_or(usize::MAX);
        if len == 0 {
            return Err(FrameError::Empty);
        }
        if len > MAX_FRAME {
            return Err(FrameError::TooLarge);
        }
        let mut body = SecretBuf::with_capacity(len.min(INITIAL_CAPACITY));
        while body.len() < len {
            if body.len() == body.capacity() {
                body.grow(body.capacity().saturating_mul(2).min(len));
            }
            let n = (len - body.len()).min(body.capacity() - body.len());
            // The header was read: any failure now is inside the frame.
            if body.read_exact_from(r, n).is_err() {
                return Err(FrameError::Truncated);
            }
        }
        Ok(Frame { body })
    }

    /// Writes the header and the body.
    ///
    /// # Errors
    /// [`FrameError::Io`] when writing fails.
    #[allow(clippy::disallowed_methods)] // Sends the body to a verified peer.
    pub fn write_to(&self, w: &mut impl Write) -> Result<(), FrameError> {
        let len = u32::try_from(self.body.len()).map_err(|_| FrameError::TooLarge)?;
        let io = |e: io::Error| FrameError::Io(e.kind());
        w.write_all(&len.to_be_bytes()).map_err(io)?;
        w.write_all(self.body.expose_secret()).map_err(io)?;
        w.flush().map_err(io)
    }
}
