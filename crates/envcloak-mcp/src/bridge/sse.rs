//! Server-Sent Events (SSE) parser for MCP Streamable HTTP responses
//! (`text/event-stream`, M2 plan task M2-18).
//!
//! Reads a byte stream line by line (`\n`, `\r\n` or `\r`), ignores comment
//! lines (`:`), collects `event`, `data`, `id` and `retry` fields until an
//! empty line dispatches the event, and enforces [`MAX_SSE_EVENT_BYTES`] on
//! each event so an oversized event from a server cannot grow memory
//! without bound.

use std::io::{self, Read};

/// The largest SSE event accepted: 1 MiB across its `data`, `event` and `id`
/// fields.
pub const MAX_SSE_EVENT_BYTES: usize = 1024 * 1024;

/// Size of the internal read buffer.
const CHUNK: usize = 16 * 1024;

/// One dispatched Server-Sent Event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    /// The event type (`"message"` when none was given).
    pub event: String,
    /// The joined `data` lines.
    pub data: String,
    /// The last `id` field seen on the stream, if any.
    pub id: Option<String>,
    /// The `retry` reconnection time in milliseconds, if valid digits.
    pub retry_ms: Option<u64>,
}

/// Why reading an SSE stream failed.
#[derive(Debug)]
pub enum SseError {
    /// An event exceeded the size cap (`MAX_SSE_EVENT_BYTES`).
    EventTooLarge,
    /// An event contained invalid UTF-8.
    InvalidUtf8,
    /// Underlying I/O error.
    Io(io::Error),
}

impl std::fmt::Display for SseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SseError::EventTooLarge => f.write_str("SSE event exceeds size cap"),
            SseError::InvalidUtf8 => f.write_str("SSE event is not valid UTF-8"),
            SseError::Io(e) => write!(f, "SSE read error: {e}"),
        }
    }
}

impl std::error::Error for SseError {}

impl From<io::Error> for SseError {
    fn from(e: io::Error) -> Self {
        SseError::Io(e)
    }
}

/// Streaming SSE parser over `R`, bounded per event by `max_event_bytes`.
pub struct SseParser<R> {
    inner: R,
    max_event_bytes: usize,
    buf: Vec<u8>,
    start: usize,
    end: usize,
    pending_cr: bool,
    line: Vec<u8>,
    last_id: Option<String>,
}

impl<R> std::fmt::Debug for SseParser<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SseParser")
            .field("max_event_bytes", &self.max_event_bytes)
            .field("held", &self.line.len())
            .finish_non_exhaustive()
    }
}

impl<R: Read> SseParser<R> {
    /// Creates an SSE parser with [`MAX_SSE_EVENT_BYTES`].
    pub fn new(inner: R) -> Self {
        Self::with_max_event_bytes(inner, MAX_SSE_EVENT_BYTES)
    }

    /// Creates an SSE parser with a custom per-event byte cap.
    pub fn with_max_event_bytes(inner: R, max_event_bytes: usize) -> Self {
        SseParser {
            inner,
            max_event_bytes,
            buf: vec![0; CHUNK],
            start: 0,
            end: 0,
            pending_cr: false,
            line: Vec::new(),
            last_id: None,
        }
    }

    /// Reads the next raw line (without its line ending), bounded by
    /// `max_event_bytes`.
    fn next_line(&mut self) -> Result<Option<Vec<u8>>, SseError> {
        loop {
            if self.start < self.end {
                if self.pending_cr {
                    self.pending_cr = false;
                    if self.buf[self.start] == b'\n' {
                        self.start += 1;
                        continue;
                    }
                }
                let slice = &self.buf[self.start..self.end];
                if let Some(pos) = slice.iter().position(|&b| b == b'\n' || b == b'\r') {
                    let delim = slice[pos];
                    let piece = &slice[..pos];
                    if self.line.len().saturating_add(piece.len()) > self.max_event_bytes {
                        self.line.clear();
                        return Err(SseError::EventTooLarge);
                    }
                    self.line.extend_from_slice(piece);
                    self.start += pos + 1;
                    if delim == b'\r' {
                        if self.start < self.end {
                            if self.buf[self.start] == b'\n' {
                                self.start += 1;
                            }
                        } else {
                            self.pending_cr = true;
                        }
                    }
                    return Ok(Some(std::mem::take(&mut self.line)));
                }
                if self.line.len().saturating_add(slice.len()) > self.max_event_bytes {
                    self.line.clear();
                    return Err(SseError::EventTooLarge);
                }
                self.line.extend_from_slice(slice);
                self.start = self.end;
            }
            let n = loop {
                match self.inner.read(&mut self.buf) {
                    Ok(n) => break n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(SseError::Io(e)),
                }
            };
            if n == 0 {
                self.pending_cr = false;
                if self.line.is_empty() {
                    return Ok(None);
                }
                return Ok(Some(std::mem::take(&mut self.line)));
            }
            self.start = 0;
            self.end = n;
        }
    }

    /// Reads and returns the next dispatched [`SseEvent`], or `Ok(None)` at
    /// end of stream.
    ///
    /// # Errors
    /// [`SseError::EventTooLarge`] when an event's accumulated fields or a
    /// line exceeds the cap, [`SseError::InvalidUtf8`] for invalid UTF-8, or
    /// [`SseError::Io`].
    pub fn next_event(&mut self) -> Result<Option<SseEvent>, SseError> {
        let mut event_type = String::new();
        let mut data = String::new();
        let mut has_data = false;
        let mut retry_ms = None;
        let mut event_bytes = 0usize;

        while let Some(raw) = self.next_line()? {
            if raw.is_empty() {
                if !has_data {
                    event_type.clear();
                    retry_ms = None;
                    event_bytes = 0;
                    continue;
                }
                let kind = if event_type.is_empty() {
                    "message".to_owned()
                } else {
                    std::mem::take(&mut event_type)
                };
                return Ok(Some(SseEvent {
                    event: kind,
                    data,
                    id: self.last_id.clone(),
                    retry_ms,
                }));
            }
            if raw[0] == b':' {
                continue;
            }
            let line = std::str::from_utf8(&raw).map_err(|_| SseError::InvalidUtf8)?;
            let (field, value) = match line.split_once(':') {
                Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
                None => (line, ""),
            };
            event_bytes = event_bytes.saturating_add(value.len());
            if event_bytes > self.max_event_bytes {
                return Err(SseError::EventTooLarge);
            }
            match field {
                "event" => {
                    event_type.clear();
                    event_type.push_str(value);
                }
                "data" => {
                    if has_data {
                        if event_bytes.saturating_add(1) > self.max_event_bytes {
                            return Err(SseError::EventTooLarge);
                        }
                        event_bytes += 1;
                        data.push('\n');
                    }
                    has_data = true;
                    data.push_str(value);
                }
                "id" if !value.contains('\0') => {
                    self.last_id = Some(value.to_owned());
                }
                "retry" if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) => {
                    retry_ms = value.parse::<u64>().ok();
                }
                _ => {}
            }
        }
        if has_data {
            let kind = if event_type.is_empty() {
                "message".to_owned()
            } else {
                event_type
            };
            return Ok(Some(SseEvent {
                event: kind,
                data,
                id: self.last_id.clone(),
                retry_ms,
            }));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_multiline_events_comments_id_and_retry() {
        let stream = b": keepalive\r\nevent: message\r\nid: evt-1\r\nretry: 1500\r\ndata: {\"jsonrpc\":\"2.0\",\r\ndata: \"id\":1,\"result\":{}}\r\n\r\ndata: second\n\n";
        let mut parser = SseParser::new(&stream[..]);
        let first = parser.next_event().unwrap().unwrap();
        assert_eq!(first.event, "message");
        assert_eq!(first.id.as_deref(), Some("evt-1"));
        assert_eq!(first.retry_ms, Some(1500));
        assert_eq!(first.data, "{\"jsonrpc\":\"2.0\",\n\"id\":1,\"result\":{}}");

        let second = parser.next_event().unwrap().unwrap();
        assert_eq!(second.event, "message");
        assert_eq!(second.id.as_deref(), Some("evt-1"));
        assert_eq!(second.retry_ms, None);
        assert_eq!(second.data, "second");
        assert!(parser.next_event().unwrap().is_none());
    }

    #[test]
    fn refuses_oversized_sse_event() {
        let body = format!("data: {}\n\n", "x".repeat(256));
        let mut parser = SseParser::with_max_event_bytes(body.as_bytes(), 128);
        assert!(matches!(parser.next_event(), Err(SseError::EventTooLarge)));
    }
}
