//! Chrome DevTools Protocol (CDP) client over the `--remote-debugging-pipe`
//! descriptors (SPEC §6.8, M2 plan D-25, task M2b-07).
//!
//! - Framing: null-delimited (`\0`) UTF-8 JSON messages, capped at
//!   [`MAX_CDP_MESSAGE_BYTES`] (8 MiB).
//! - Queueing: bounded event queue ([`MAX_CDP_QUEUE_LEN`]).
//! - Errors: value-free ([`CdpError`] never holds raw payloads, page text, URLs
//!   with queries, or secret strings).
//! - Session mode: flat session mode (`sessionId` on the top-level JSON object).
//! - Domain allowlist: only [`ALLOWED_CDP_DOMAINS`] (`Target`, `Page`, `Fetch`,
//!   `Network`, `DOM`, `Input`, `Runtime`, `DOMStorage`) may be enabled or
//!   invoked.

use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Read, Write};

use serde_json::{Value, json};
use zeroize::Zeroizing;

/// Maximum size of a single null-delimited CDP message (8 MiB, SPEC §6.8).
pub const MAX_CDP_MESSAGE_BYTES: usize = 8 * 1024 * 1024;

/// Maximum number of queued asynchronous CDP events before the client refuses
/// with [`CdpErrorKind::QueueFull`].
pub const MAX_CDP_QUEUE_LEN: usize = 4096;

/// The only CDP domains the sign-in worker is permitted to enable or call.
pub const ALLOWED_CDP_DOMAINS: &[&str] = &[
    "Browser",
    "Target",
    "Page",
    "Fetch",
    "Network",
    "DOM",
    "Input",
    "Runtime",
    "DOMStorage",
];

/// Value-free CDP error classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CdpErrorKind {
    /// Underlying pipe I/O failed or reached EOF unexpectedly.
    Io,
    /// Incoming or outgoing message exceeded [`MAX_CDP_MESSAGE_BYTES`].
    MessageTooLarge,
    /// Incoming frame was not valid UTF-8 or valid JSON object.
    MalformedFrame,
    /// Asynchronous event queue exceeded [`MAX_CDP_QUEUE_LEN`].
    QueueFull,
    /// Caller attempted to enable or call a CDP domain outside [`ALLOWED_CDP_DOMAINS`].
    ForbiddenDomain,
    /// Browser returned a protocol error response for a command.
    ProtocolError,
    /// Response did not arrive within the step's read budget.
    Timeout,
}

/// Value-free CDP error (never contains page content, URLs, or credential bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdpError {
    pub kind: CdpErrorKind,
    pub code: Option<i64>,
}

impl CdpError {
    /// Creates a new value-free [`CdpError`].
    pub const fn new(kind: CdpErrorKind) -> Self {
        Self { kind, code: None }
    }

    /// Creates a [`CdpErrorKind::ProtocolError`] carrying only the numeric CDP
    /// error code.
    pub const fn protocol(code: Option<i64>) -> Self {
        Self {
            kind: CdpErrorKind::ProtocolError,
            code,
        }
    }
}

impl core::fmt::Display for CdpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match (self.kind, self.code) {
            (CdpErrorKind::ProtocolError, Some(c)) => write!(f, "cdp_protocol_error({c})"),
            (CdpErrorKind::ProtocolError, None) => f.write_str("cdp_protocol_error"),
            (CdpErrorKind::Io, _) => f.write_str("cdp_io_error"),
            (CdpErrorKind::MessageTooLarge, _) => f.write_str("cdp_message_too_large"),
            (CdpErrorKind::MalformedFrame, _) => f.write_str("cdp_malformed_frame"),
            (CdpErrorKind::QueueFull, _) => f.write_str("cdp_queue_full"),
            (CdpErrorKind::ForbiddenDomain, _) => f.write_str("cdp_forbidden_domain"),
            (CdpErrorKind::Timeout, _) => f.write_str("cdp_timeout"),
        }
    }
}

impl std::error::Error for CdpError {}

/// One asynchronous CDP event received in flat session mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdpEvent {
    pub session_id: Option<String>,
    pub method: String,
    pub params: Value,
}

/// Parsed incoming CDP frame (either a command reply or an asynchronous event).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CdpFrame {
    /// Reply to a command with `id`.
    Response {
        id: u64,
        session_id: Option<String>,
        result: Result<Value, CdpError>,
    },
    /// Asynchronous event notification.
    Event(CdpEvent),
}

/// Validates that `method` belongs to an allowed CDP domain (`<Domain>.<command>`).
///
/// # Errors
/// Returns [`CdpErrorKind::ForbiddenDomain`] if `method` has no `<Domain>.<name>`
/// separator or its domain is not in [`ALLOWED_CDP_DOMAINS`].
pub fn check_allowed_method(method: &str) -> Result<(&str, &str), CdpError> {
    let Some((domain, cmd)) = method.split_once('.') else {
        return Err(CdpError::new(CdpErrorKind::ForbiddenDomain));
    };
    if cmd.is_empty() || !ALLOWED_CDP_DOMAINS.contains(&domain) {
        return Err(CdpError::new(CdpErrorKind::ForbiddenDomain));
    }
    Ok((domain, cmd))
}

/// Parses one null-stripped raw frame slice (without the trailing `\0`) into a
/// [`CdpFrame`]. Exposed for unit tests and fuzzing.
///
/// # Errors
/// Returns [`CdpErrorKind::MessageTooLarge`] if `raw.len() > MAX_CDP_MESSAGE_BYTES`
/// and [`CdpErrorKind::MalformedFrame`] on invalid UTF-8 or JSON structure.
pub fn parse_cdp_frame(raw: &[u8]) -> Result<CdpFrame, CdpError> {
    if raw.len() > MAX_CDP_MESSAGE_BYTES {
        return Err(CdpError::new(CdpErrorKind::MessageTooLarge));
    }
    let text = std::str::from_utf8(raw).map_err(|_| CdpError::new(CdpErrorKind::MalformedFrame))?;
    let val: Value =
        serde_json::from_str(text).map_err(|_| CdpError::new(CdpErrorKind::MalformedFrame))?;
    let Some(obj) = val.as_object() else {
        return Err(CdpError::new(CdpErrorKind::MalformedFrame));
    };
    let session_id = obj
        .get("sessionId")
        .and_then(Value::as_str)
        .map(str::to_owned);

    if let Some(id_val) = obj.get("id") {
        let Some(id) = id_val.as_u64() else {
            return Err(CdpError::new(CdpErrorKind::MalformedFrame));
        };
        if let Some(err_obj) = obj.get("error") {
            let code = err_obj.get("code").and_then(Value::as_i64);
            return Ok(CdpFrame::Response {
                id,
                session_id,
                result: Err(CdpError::protocol(code)),
            });
        }
        let result = obj.get("result").cloned().unwrap_or_else(|| json!({}));
        return Ok(CdpFrame::Response {
            id,
            session_id,
            result: Ok(result),
        });
    }

    let Some(method) = obj.get("method").and_then(Value::as_str) else {
        return Err(CdpError::new(CdpErrorKind::MalformedFrame));
    };
    let params = obj.get("params").cloned().unwrap_or_else(|| json!({}));
    Ok(CdpFrame::Event(CdpEvent {
        session_id,
        method: method.to_owned(),
        params,
    }))
}

/// CDP pipe client speaking null-delimited JSON in flat session mode.
#[derive(Debug)]
pub struct CdpClient<R, W> {
    reader: R,
    writer: W,
    read_buf: Zeroizing<Vec<u8>>,
    events: VecDeque<CdpEvent>,
    pending_responses: BTreeMap<u64, Result<Value, CdpError>>,
    next_id: u64,
}

impl<R: Read, W: Write> CdpClient<R, W> {
    /// Wraps `reader` (pipe fd 4 from Chrome) and `writer` (pipe fd 3 to Chrome).
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader,
            writer,
            read_buf: Zeroizing::new(Vec::with_capacity(16 * 1024)),
            events: VecDeque::new(),
            pending_responses: BTreeMap::new(),
            next_id: 1,
        }
    }

    /// Number of queued asynchronous events waiting to be processed.
    pub fn queued_event_count(&self) -> usize {
        self.events.len()
    }

    /// Pops the next queued asynchronous [`CdpEvent`], if any.
    pub fn pop_event(&mut self) -> Option<CdpEvent> {
        self.events.pop_front()
    }

    /// Removes and returns a response for `id` if it has already been received
    /// and queued in `pending_responses`.
    pub fn take_pending_response(&mut self, id: u64) -> Option<Result<Value, CdpError>> {
        self.pending_responses.remove(&id)
    }

    /// Enables a CDP domain (`<Domain>.enable`) on `session_id` (`None` for the
    /// root browser connection). Refuses any domain outside [`ALLOWED_CDP_DOMAINS`].
    ///
    /// # Errors
    /// Returns [`CdpError`] if `domain` is not allowed or the command fails.
    pub fn enable_domain(
        &mut self,
        session_id: Option<&str>,
        domain: &str,
        params: Value,
    ) -> Result<Value, CdpError> {
        if !ALLOWED_CDP_DOMAINS.contains(&domain) || domain == "Browser" || domain == "Input" {
            return Err(CdpError::new(CdpErrorKind::ForbiddenDomain));
        }
        let method = format!("{domain}.enable");
        self.call(session_id, &method, params)
    }

    /// Sends a CDP command (`method`, `params`) in flat session mode (`session_id`)
    /// and returns its assigned request `id` without waiting for the response.
    ///
    /// # Errors
    /// Returns [`CdpError`] if `method` is outside [`ALLOWED_CDP_DOMAINS`], the
    /// serialized message exceeds [`MAX_CDP_MESSAGE_BYTES`], or writing fails.
    pub fn send_command(
        &mut self,
        session_id: Option<&str>,
        method: &str,
        params: Value,
    ) -> Result<u64, CdpError> {
        check_allowed_method(method)?;
        let id = self.next_id;
        self.next_id += 1;

        let mut payload = json!({
            "id": id,
            "method": method,
            "params": params,
        });
        if let Some(sid) = session_id
            && let Some(obj) = payload.as_object_mut()
        {
            obj.insert("sessionId".to_owned(), Value::String(sid.to_owned()));
        }

        let mut encoded = Zeroizing::new(
            serde_json::to_vec(&payload)
                .map_err(|_| CdpError::new(CdpErrorKind::MalformedFrame))?,
        );
        if encoded.len() > MAX_CDP_MESSAGE_BYTES {
            return Err(CdpError::new(CdpErrorKind::MessageTooLarge));
        }
        encoded.push(0);
        self.writer
            .write_all(&encoded)
            .map_err(|_| CdpError::new(CdpErrorKind::Io))?;
        self.writer
            .flush()
            .map_err(|_| CdpError::new(CdpErrorKind::Io))?;
        Ok(id)
    }

    /// Reads at most one frame from the pipe toward completing request `id`,
    /// returning `Ok(Some(result))` if `id`'s response has arrived, or `Ok(None)`
    /// if an asynchronous event or another request's response was queued instead.
    ///
    /// # Errors
    /// Returns [`CdpError`] on pipe EOF/error, malformed frame, or event queue overflow.
    pub fn step_until_response(
        &mut self,
        id: u64,
    ) -> Result<Option<Result<Value, CdpError>>, CdpError> {
        if let Some(res) = self.pending_responses.remove(&id) {
            return Ok(Some(res));
        }
        let frame = self.read_next_frame()?;
        match frame {
            CdpFrame::Response {
                id: got_id, result, ..
            } if got_id == id => Ok(Some(result)),
            CdpFrame::Response {
                id: got_id, result, ..
            } => {
                if self.pending_responses.len() >= MAX_CDP_QUEUE_LEN {
                    return Err(CdpError::new(CdpErrorKind::QueueFull));
                }
                self.pending_responses.insert(got_id, result);
                Ok(None)
            }
            CdpFrame::Event(ev) => {
                if self.events.len() >= MAX_CDP_QUEUE_LEN {
                    return Err(CdpError::new(CdpErrorKind::QueueFull));
                }
                self.events.push_back(ev);
                Ok(None)
            }
        }
    }

    /// Sends a synchronous CDP command (`method`, `params`) in flat session mode
    /// (`session_id`) and waits for its matching response `id`, queueing any
    /// interleaved events in `self.events` up to [`MAX_CDP_QUEUE_LEN`].
    ///
    /// # Errors
    /// Returns [`CdpError`] if `method` is outside [`ALLOWED_CDP_DOMAINS`], a
    /// message exceeds [`MAX_CDP_MESSAGE_BYTES`], the event queue overflows, or
    /// the pipe closes/errors.
    pub fn call(
        &mut self,
        session_id: Option<&str>,
        method: &str,
        params: Value,
    ) -> Result<Value, CdpError> {
        let id = self.send_command(session_id, method, params)?;
        loop {
            if let Some(res) = self.step_until_response(id)? {
                return res;
            }
        }
    }

    /// Inserts `text` into the currently focused DOM element on `session_id` via
    /// `Input.insertText` without putting `text` into any JS script evaluation.
    /// The serialized frame buffer is wiped on drop.
    ///
    /// # Errors
    /// Returns [`CdpError`] if sending or executing `Input.insertText` fails.
    pub fn insert_text_wiping(
        &mut self,
        session_id: Option<&str>,
        text_utf8: &[u8],
    ) -> Result<(), CdpError> {
        let s = Zeroizing::new(
            std::str::from_utf8(text_utf8)
                .map_err(|_| CdpError::new(CdpErrorKind::MalformedFrame))?
                .to_owned(),
        );
        let _ = self.call(session_id, "Input.insertText", json!({ "text": &*s }))?;
        Ok(())
    }

    /// Reads one null-delimited frame from `self.reader`.
    ///
    /// # Errors
    /// Returns [`CdpError`] on EOF, I/O error, oversize frame, or malformed JSON.
    pub fn read_next_frame(&mut self) -> Result<CdpFrame, CdpError> {
        loop {
            if let Some(pos) = self.read_buf.iter().position(|&b| b == 0) {
                if pos > MAX_CDP_MESSAGE_BYTES {
                    self.read_buf.clear();
                    return Err(CdpError::new(CdpErrorKind::MessageTooLarge));
                }
                let raw = Zeroizing::new(self.read_buf[..pos].to_vec());
                self.read_buf.drain(..=pos);
                if raw.is_empty() {
                    continue;
                }
                return parse_cdp_frame(&raw);
            }

            if self.read_buf.len() > MAX_CDP_MESSAGE_BYTES {
                self.read_buf.clear();
                return Err(CdpError::new(CdpErrorKind::MessageTooLarge));
            }

            let mut chunk = Zeroizing::new(vec![0u8; 8192]);
            let n = match self.reader.read(&mut chunk) {
                Ok(0) => return Err(CdpError::new(CdpErrorKind::Io)),
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    return Err(CdpError::new(CdpErrorKind::Timeout));
                }
                Err(_) => return Err(CdpError::new(CdpErrorKind::Io)),
            };
            if self.read_buf.len().saturating_add(n) > MAX_CDP_MESSAGE_BYTES + 1 {
                self.read_buf.clear();
                return Err(CdpError::new(CdpErrorKind::MessageTooLarge));
            }
            self.read_buf.extend_from_slice(&chunk[..n]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn allowed_domains_enforced_and_forbidden_domains_refused() {
        assert!(check_allowed_method("Target.setAutoAttach").is_ok());
        assert!(check_allowed_method("Fetch.enable").is_ok());
        assert!(check_allowed_method("Input.insertText").is_ok());
        assert!(check_allowed_method("DOMStorage.getDOMStorageItems").is_ok());

        for forbidden in [
            "Tracing.start",
            "Profiler.enable",
            "HeapProfiler.takeHeapSnapshot",
            "HeadlessExperimental.beginFrame",
            "Storage.getCookies",
            "InvalidNoDot",
            "Target.",
        ] {
            assert_eq!(
                check_allowed_method(forbidden).unwrap_err().kind,
                CdpErrorKind::ForbiddenDomain,
                "must refuse {forbidden}"
            );
        }
    }

    #[test]
    fn oversize_and_malformed_frames_produce_value_free_errors() {
        let big = vec![b'a'; MAX_CDP_MESSAGE_BYTES + 1];
        let err = parse_cdp_frame(&big).unwrap_err();
        assert_eq!(err.kind, CdpErrorKind::MessageTooLarge);
        assert_eq!(err.to_string(), "cdp_message_too_large");

        let bad_json = b"{\"secret\":\"super-secret-value-123\"";
        let err2 = parse_cdp_frame(bad_json).unwrap_err();
        assert_eq!(err2.kind, CdpErrorKind::MalformedFrame);
        assert!(!err2.to_string().contains("super-secret-value-123"));
    }

    proptest! {
        #[test]
        fn fuzz_parse_cdp_frame_never_panics_or_leaks_input(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let res = parse_cdp_frame(&bytes);
            if let Err(e) = res {
                let msg = e.to_string();
                prop_assert!(msg.starts_with("cdp_"));
            }
        }
    }
}
