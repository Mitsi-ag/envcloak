//! `envcloak mcp-bridge --relay`: the daemon-started HTTP/SSE relay for a
//! bridged remote MCP server (SPEC §6.4, §6.6; M2 plan D-18, D-36; task
//! M2-18).
//!
//! Only `envcloakd` starts this mode, from its retained anchor image, with
//! the client's pipe ends on descriptors 0 and 1, `/dev/null` on descriptor
//! 2, the control socket on [`envcloak_ipc::control::CONTROL_FD`], and the
//! lifeline pipe on [`envcloak_ipc::control::LIFELINE_FD`]. Any direct
//! invocation exits 125 with `not_started_by_daemon` before reading from
//! descriptor 3.
//!
//! After reading the daemon's [`Release`] (`Recipient::Relay { origin,
//! headers }`), the relay:
//! 1. validates the origin (`https://`, or `http://` on loopback only);
//! 2. checks every released header value against the provider registry's
//!    `allowed_hosts` for the origin's host (refusing with `policy_denied`
//!    before any network request when a known provider's key is not allowed
//!    on that host, while allowing keys of unknown providers, M2R-5);
//! 3. builds an [`envcloak_redact::Redactor`] from all released header
//!    values (refusing values under 8 bytes, or 8 to 15 bytes without
//!    `allow_short`, with `value_too_short`);
//! 4. verifies that the client's requested `--url` has the exact registered
//!    `origin` (D-18);
//! 5. forwards each MCP JSON-RPC line as an HTTP `POST` to that URL using
//!    `ureq` + `rustls` with platform certificate verification and redirect
//!    following disabled (`max_redirects(0)`), attaching the secret headers
//!    only to requests to that origin, and redacting every JSON response,
//!    SSE event and error body before writing it to standard output.

use std::io::{self, Read, Write};
use std::sync::Arc;
use std::time::Duration;

use envcloak_client::fail::{Failure, refuse_if_traced};
use envcloak_client::managed::host_allowed_for_header;
use envcloak_core::SecretBytes;
use envcloak_core::vault::Slug;
use envcloak_ipc::control::{self, LIFELINE_FD, Recipient, RelayHeader, Release, ToRunner};
use envcloak_ipc::proto::ReleasedValue;
use envcloak_policy::escape_for_display;
use envcloak_policy::managed::bridge_binding_name;
use envcloak_redact::{Redactor, RedactorBuilder};
use secrecy::ExposeSecret;
use serde_json::{Value, json};

use super::handoff::started_by_daemon;
use super::http::BridgeUrl;
use super::sse::{MAX_SSE_EVENT_BYTES, SseError, SseParser};
use crate::rpc::{self, Id, Incoming, PARSE_ERROR, PARSE_MESSAGE};
use crate::stdio::{Line, LineReader};

/// Maximum non-SSE HTTP response body read by the relay (4 MiB).
pub const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// Maximum error response body read on upstream 4xx/5xx responses (64 KiB).
const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;

/// JSON-RPC server error code for transport/relay refusals.
const RELAY_RPC_ERROR: i64 = -32000;

/// One header resolved from the daemon's [`Release`].
struct BoundHeader {
    name: String,
    value: SecretBytes,
}

/// Prepared relay session holding the validated origin, bound headers, and
/// response redactor.
pub struct PreparedRelay {
    origin_url: BridgeUrl,
    headers: Vec<BoundHeader>,
    redactor: Redactor,
    max_sse_event_bytes: usize,
}

impl std::fmt::Debug for PreparedRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedRelay")
            .field("origin", &self.origin_url.origin)
            .field("headers", &self.headers.len())
            .finish_non_exhaustive()
    }
}

/// Entry point for `envcloak mcp-bridge --relay`.
///
/// # Errors
/// Returns `not_started_by_daemon` when not spawned by `envcloakd`, or a
/// [`Failure`] on startup/runtime refusal.
pub fn run_relay() -> Result<(), Failure> {
    let Ok(_signals) = envcloak_sys::TerminationSignals::block() else {
        return Err(Failure::new(
            "run_failed",
            "the relay's signals could not be set up",
        ));
    };
    refuse_if_traced()?;
    let Some(control) = started_by_daemon() else {
        return Err(not_started_by_daemon());
    };
    let _ = control.set_read_timeout(Some(Duration::from_secs(30)));
    let release = match control::receive::<ToRunner>(&control) {
        Ok(ToRunner::Release(r)) => *r,
        _ => return Err(not_started_by_daemon()),
    };
    drop(control);

    let Some(lifeline) = envcloak_sys::claim_inherited_fd(LIFELINE_FD).ok() else {
        return Err(Failure::new(
            "run_failed",
            "the relay's lifeline descriptor is not open; nothing was started",
        ));
    };
    // When the client exits or drops its lifeline write end, terminate this
    // relay process immediately so no stalled upstream request lingers.
    std::thread::spawn(move || {
        let mut life = std::fs::File::from(lifeline);
        let mut buf = [0u8; 1];
        loop {
            match life.read(&mut buf) {
                Ok(0) | Err(_) => std::process::exit(0),
                Ok(_) => {}
            }
        }
    });

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = LineReader::new(stdin.lock());
    let mut output = stdout.lock();

    let first = match input.next_line() {
        Ok(Line::Message(m)) => Some(m),
        Ok(Line::Oversized) => {
            let _ = output.write_all(&rpc::error(None, PARSE_ERROR, PARSE_MESSAGE));
            let _ = output.flush();
            None
        }
        Ok(Line::End) | Err(_) => return Ok(()),
    };

    let (handshake_url, pending_first) = match first {
        Some(ref line) => match parse_handshake_url(line) {
            Some(u) => (Some(u), None),
            None => (None, first),
        },
        None => (None, None),
    };

    let prepared = match prepare_release(release, MAX_SSE_EVENT_BYTES) {
        Ok(p) => p,
        Err(f) => {
            if handshake_url.is_some() {
                write_handshake_err(&mut output, &f);
            }
            return Err(f);
        }
    };

    let target_url = match handshake_url {
        Some(raw_url) => match validate_target_url(&prepared.origin_url, &raw_url) {
            Ok(u) => {
                write_handshake_ok(&mut output);
                u
            }
            Err(f) => {
                write_handshake_err(&mut output, &f);
                return Err(f);
            }
        },
        None => prepared.origin_url.url.clone(),
    };

    let agent = build_http_agent()?;
    serve_with_agent(
        &prepared,
        &agent,
        &target_url,
        pending_first,
        &mut input,
        &mut output,
    )
}

/// Prepares a [`PreparedRelay`] from the daemon's [`Release`].
///
/// Validates the origin, checks provider `allowed_hosts` for every released
/// header value, and constructs the response [`Redactor`].
///
/// # Errors
/// Returns `policy_denied`, `value_too_short`, `managed_command_mismatch`,
/// or `run_failed`.
pub fn prepare_release(
    release: Release,
    max_sse_event_bytes: usize,
) -> Result<PreparedRelay, Failure> {
    let Release { bindings, to } = release;
    let Recipient::Relay { origin, headers } = to else {
        return Err(not_started_by_daemon());
    };
    let origin_url = BridgeUrl::parse(&origin).map_err(|_| {
        Failure::new(
            "managed_command_mismatch",
            "the relay's registered origin is not a valid https:// or loopback http:// origin",
        )
    })?;
    if origin_url.origin != origin || origin_url.path_and_query != "/" {
        return Err(Failure::new(
            "managed_command_mismatch",
            "the relay's registered origin must not contain a path or query",
        ));
    }

    build_prepared_relay(origin_url, &headers, bindings, max_sse_event_bytes)
}

fn build_prepared_relay(
    origin_url: BridgeUrl,
    headers: &[RelayHeader],
    bindings: Vec<ReleasedValue>,
    max_sse_event_bytes: usize,
) -> Result<PreparedRelay, Failure> {
    if headers.is_empty() || bindings.len() != headers.len() {
        return Err(Failure::new(
            "managed_command_mismatch",
            "the daemon's release does not match the bridged server's headers",
        ));
    }

    let mut builder = RedactorBuilder::new();
    let mut refused_short: Vec<String> = Vec::new();
    let mut resolved: Vec<(String, SecretBytes)> = Vec::with_capacity(bindings.len());

    for v in bindings {
        let slug = Slug::new(&v.slug).map_err(|_| {
            Failure::new(
                "run_failed",
                "the daemon's release carried an invalid item slug",
            )
        })?;
        let secret = v.value.into_inner();
        #[allow(clippy::disallowed_methods)]
        let raw: &[u8] = secret.expose_secret();
        if raw.contains(&0) || raw.contains(&b'\r') || raw.contains(&b'\n') {
            return Err(Failure::new(
                "run_failed",
                "a bridged header value contains a newline or NUL byte",
            ));
        }
        let min_len = if v.allow_short { 8 } else { 16 };
        if raw.len() < min_len {
            if !refused_short.iter().any(|s| s == slug.as_str()) {
                refused_short.push(slug.as_str().to_owned());
            }
            continue;
        }
        builder = builder.secret(slug.as_str(), raw);
        // Also register whitespace-separated tokens (such as the token after
        // `Bearer `) so an upstream response that echoes the bare token
        // without its scheme prefix is redacted too.
        for tok in raw.split(u8::is_ascii_whitespace) {
            if tok.len() >= min_len && tok.len() < raw.len() {
                builder = builder.secret(slug.as_str(), tok);
            }
        }
        resolved.push((v.env_name, secret));
    }

    if !refused_short.is_empty() {
        return Err(Failure::new(
            "value_too_short",
            format!(
                "{}: a value under 8 bytes is never sent, and one of 8 to 15 bytes only when \
                 its item allows short values; nothing was started",
                refused_short.join(", ")
            ),
        ));
    }

    let host = origin_url.bare_host();
    let mut bound_headers = Vec::with_capacity(headers.len());
    for h in headers {
        let Some(expected_binding) = bridge_binding_name(&h.name, &origin_url.origin) else {
            return Err(Failure::new(
                "managed_command_mismatch",
                "a bridged header name is invalid",
            ));
        };
        if expected_binding != h.binding {
            return Err(Failure::new(
                "managed_command_mismatch",
                "a bridged header's binding does not carry the registered origin's digest",
            ));
        }
        let Some((_, value)) = resolved.iter().find(|(env_name, _)| *env_name == h.binding) else {
            return Err(Failure::new(
                "managed_command_mismatch",
                "a bridged header's binding was not in the release",
            ));
        };
        if !header_allowed_for_host(value, &h.name, host) {
            return Err(Failure::new(
                "policy_denied",
                "the provider's allowed_hosts policy does not permit sending this key to the \
                 target host; nothing was sent",
            ));
        }
        #[allow(clippy::disallowed_methods)]
        let cloned = SecretBytes::copy_from(value.expose_secret());
        bound_headers.push(BoundHeader {
            name: h.name.clone(),
            value: cloned,
        });
    }

    let (redactor, _report) = builder.build();
    Ok(PreparedRelay {
        origin_url,
        headers: bound_headers,
        redactor,
        max_sse_event_bytes,
    })
}

fn header_allowed_for_host(value: &SecretBytes, header_name: &str, host: &str) -> bool {
    if !host_allowed_for_header(value, header_name, host) {
        return false;
    }
    #[allow(clippy::disallowed_methods)]
    let raw: &[u8] = value.expose_secret();
    for tok in raw.split(u8::is_ascii_whitespace) {
        if tok.len() >= 8 && tok.len() < raw.len() {
            let word = SecretBytes::copy_from(tok);
            if !host_allowed_for_header(&word, header_name, host) {
                return false;
            }
        }
    }
    true
}

/// Validates that `requested_url` parses as a [`BridgeUrl`] whose `origin`
/// equals `registered_origin.origin` (D-18).
///
/// # Errors
/// Returns `managed_command_mismatch` if the URL is invalid or its origin
/// differs from the registered origin.
pub fn validate_target_url(
    registered_origin: &BridgeUrl,
    requested_url: &str,
) -> Result<String, Failure> {
    let parsed = BridgeUrl::parse(requested_url).map_err(|_| {
        Failure::new(
            "managed_command_mismatch",
            "the requested --url is not a valid https:// (or loopback http://) URL",
        )
    })?;
    if parsed.origin != registered_origin.origin {
        return Err(Failure::new(
            "managed_command_mismatch",
            "the requested --url origin does not match the server's registered origin",
        ));
    }
    Ok(parsed.url)
}

/// Builds the `ureq::Agent` configured with `rustls` platform certificate
/// verification and zero redirect following (`max_redirects(0)`).
///
/// # Errors
/// Returns `run_failed` if the TLS provider cannot be initialized.
pub fn build_http_agent() -> Result<ureq::Agent, Failure> {
    let crypto = Arc::new(rustls::crypto::ring::default_provider());
    let tls = ureq::tls::TlsConfig::builder()
        .provider(ureq::tls::TlsProvider::Rustls)
        .root_certs(ureq::tls::RootCerts::PlatformVerifier)
        .disable_verification(false)
        .unversioned_rustls_crypto_provider(crypto)
        .build();
    let config = ureq::Agent::config_builder()
        .tls_config(tls)
        .max_redirects(0)
        .http_status_as_error(false)
        .timeout_connect(Some(Duration::from_secs(10)))
        .timeout_recv_response(Some(Duration::from_secs(30)))
        .build();
    Ok(config.new_agent())
}

/// Serves an active relay session over `input` and `output` using `agent`.
///
/// # Errors
/// Returns a [`Failure`] if a fatal relay refusal occurs.
pub fn serve_with_agent<R: Read, W: Write>(
    prepared: &PreparedRelay,
    agent: &ureq::Agent,
    target_url: &str,
    first_line: Option<Vec<u8>>,
    input: &mut LineReader<R>,
    output: &mut W,
) -> Result<(), Failure> {
    if validate_target_url(&prepared.origin_url, target_url).is_err() {
        return Err(Failure::new(
            "managed_command_mismatch",
            "the target URL origin does not match the registered origin",
        ));
    }
    let mut session_id: Option<String> = None;
    let mut protocol_version: Option<String> = None;

    if let Some(line) = first_line {
        if let Err(f) = handle_client_line(
            prepared,
            agent,
            target_url,
            &mut session_id,
            &mut protocol_version,
            &line,
            output,
        ) {
            write_relay_error(output, &f);
            return Err(f);
        }
    }

    loop {
        match input.next_line() {
            Ok(Line::Message(line)) => {
                if let Err(f) = handle_client_line(
                    prepared,
                    agent,
                    target_url,
                    &mut session_id,
                    &mut protocol_version,
                    &line,
                    output,
                ) {
                    write_relay_error(output, &f);
                    return Err(f);
                }
            }
            Ok(Line::Oversized) => {
                if output
                    .write_all(&rpc::error(None, PARSE_ERROR, PARSE_MESSAGE))
                    .is_err()
                    || output.flush().is_err()
                {
                    break;
                }
            }
            Ok(Line::End) | Err(_) => break,
        }
    }

    Ok(())
}

fn handle_client_line<W: Write>(
    prepared: &PreparedRelay,
    agent: &ureq::Agent,
    target_url: &str,
    session_id: &mut Option<String>,
    protocol_version: &mut Option<String>,
    line: &[u8],
    output: &mut W,
) -> Result<(), Failure> {
    let mut init_req_version: Option<String> = None;
    let req_id = match rpc::parse(line) {
        Incoming::Invalid { id, code, message } => {
            let _ = output.write_all(&rpc::error(id.as_ref(), code, message));
            let _ = output.flush();
            return Ok(());
        }
        Incoming::Request { id, method, params } => {
            if method == "initialize" {
                init_req_version = params
                    .as_ref()
                    .and_then(|p| p.get("protocolVersion"))
                    .and_then(Value::as_str)
                    .filter(|s| is_valid_protocol_version(s))
                    .map(ToOwned::to_owned);
            }
            Some(id)
        }
        Incoming::Notification { .. } | Incoming::Response => None,
    };

    let mut req = agent
        .post(target_url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream");
    if let Some(sid) = session_id.as_deref() {
        req = req.header("Mcp-Session-Id", sid);
    }
    if let Some(ver) = protocol_version.as_deref() {
        req = req.header("MCP-Protocol-Version", ver);
    }
    for h in &prepared.headers {
        #[allow(clippy::disallowed_methods)]
        let val = std::str::from_utf8(h.value.expose_secret()).map_err(|_| {
            Failure::new(
                "run_failed",
                "a bridged header value is not valid UTF-8; nothing was sent",
            )
        })?;
        req = req.header(&h.name, val);
    }

    let response = match req.send(line) {
        Ok(resp) => resp,
        Err(_) => {
            write_rpc_error(
                output,
                req_id.as_ref(),
                "upstream HTTP/TLS connection failed",
            );
            return Err(Failure::new(
                "run_failed",
                "the upstream MCP server connection or TLS verification failed",
            ));
        }
    };

    let status = response.status().as_u16();
    // Never follow HTTP redirects (301/302/303/307/308 or any 3xx).
    if (300..400).contains(&status) || response.headers().contains_key("location") && status >= 300
    {
        write_rpc_error(
            output,
            req_id.as_ref(),
            "HTTP redirect refused: mcp-bridge never follows redirects",
        );
        return Err(Failure::new(
            "run_failed",
            "the upstream MCP server returned an HTTP redirect, which mcp-bridge refuses to follow",
        ));
    }

    if let Some(sid) = response
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| {
            !s.is_empty() && s.len() <= 256 && s.bytes().all(|b| (0x21..=0x7E).contains(&b))
        })
    {
        *session_id = Some(sid.to_owned());
    }

    if status == 202 || status == 204 {
        return Ok(());
    }

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();

    if (200..300).contains(&status) && content_type.starts_with("text/event-stream") {
        let reader = response.into_body().into_reader();
        let mut parser = SseParser::with_max_event_bytes(reader, prepared.max_sse_event_bytes);
        loop {
            match parser.next_event() {
                Ok(Some(ev)) => {
                    if ev.data.trim().is_empty() {
                        continue;
                    }
                    let redacted = redact_json_line(&prepared.redactor, ev.data.as_bytes());
                    if protocol_version.is_none() {
                        if let Some(v) =
                            extract_protocol_version(&redacted).or_else(|| init_req_version.clone())
                        {
                            *protocol_version = Some(v);
                        }
                    }
                    let _ = output.write_all(&redacted);
                    let _ = output.flush();
                }
                Ok(None) => break,
                Err(SseError::EventTooLarge) => {
                    write_rpc_error(output, req_id.as_ref(), "SSE event exceeds size cap");
                    return Err(Failure::new(
                        "run_failed",
                        "an SSE event from the upstream MCP server exceeded the size cap",
                    ));
                }
                Err(_) => {
                    write_rpc_error(output, req_id.as_ref(), "SSE stream read error");
                    return Err(Failure::new(
                        "run_failed",
                        "reading the SSE stream from the upstream MCP server failed",
                    ));
                }
            }
        }
        return Ok(());
    }

    if (200..300).contains(&status) {
        let body =
            read_bounded(response.into_body().into_reader(), MAX_RESPONSE_BYTES).map_err(|_| {
                write_rpc_error(
                    output,
                    req_id.as_ref(),
                    "upstream response exceeded size cap or failed to read",
                );
                Failure::new(
                    "run_failed",
                    "the upstream MCP server response could not be read",
                )
            })?;
        if !body.iter().all(u8::is_ascii_whitespace) {
            let redacted = redact_json_line(&prepared.redactor, &body);
            if protocol_version.is_none() {
                if let Some(v) =
                    extract_protocol_version(&redacted).or_else(|| init_req_version.clone())
                {
                    *protocol_version = Some(v);
                }
            }
            let _ = output.write_all(&redacted);
            let _ = output.flush();
        }
        return Ok(());
    }

    // Upstream 4xx/5xx error response: read bounded body and redact it before
    // returning a JSON-RPC error or forwarding a JSON-RPC error object.
    let err_body =
        read_bounded(response.into_body().into_reader(), MAX_ERROR_BODY_BYTES).unwrap_or_default();
    let redacted_text = redact_text(&prepared.redactor, &err_body);
    if let Ok(mut v) = serde_json::from_str::<Value>(redacted_text.trim()) {
        if let Some(obj) = v.as_object_mut() {
            obj.remove("envcloak_relay_error");
        }
        if v.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
            && (v.get("error").is_some() || v.get("result").is_some())
        {
            sanitize_response_id(&mut v, req_id.as_ref());
            let mut out = serde_json::to_vec(&v).unwrap_or_default();
            let final_text = redact_text(&prepared.redactor, &out);
            out = final_text.into_bytes();
            out.push(b'\n');
            let _ = output.write_all(&out);
            let _ = output.flush();
            return Ok(());
        }
    }
    let clean = escape_for_display(redacted_text.trim());
    let detail = if clean.is_empty() {
        format!("upstream HTTP {status}")
    } else {
        format!("upstream HTTP {status}: {clean}")
    };
    let id_val = req_id.as_ref().map_or(Value::Null, Id::to_value);
    let mut line_bytes = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": id_val,
        "error": {
            "code": RELAY_RPC_ERROR,
            "message": detail,
        }
    }))
    .unwrap_or_default();
    line_bytes.push(b'\n');
    let _ = output.write_all(&line_bytes);
    let _ = output.flush();
    Ok(())
}

fn is_valid_protocol_version(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| (0x21..=0x7E).contains(&b))
}

fn extract_protocol_version(line: &[u8]) -> Option<String> {
    let v: Value = serde_json::from_slice(line).ok()?;
    let ver = v
        .get("result")
        .and_then(|r| r.get("protocolVersion"))
        .and_then(Value::as_str)?;
    is_valid_protocol_version(ver).then(|| ver.to_owned())
}

/// Redacts `raw` through both the bound-secret [`Redactor`] and the provider
/// registry's [`envcloak_providers::Registry::mask_keys`], returning a single
/// newline-terminated JSON line.
#[must_use]
pub fn redact_json_line(redactor: &Redactor, raw: &[u8]) -> Vec<u8> {
    let first_pass = redact_text(redactor, raw);
    let single_line = match serde_json::from_str::<Value>(first_pass.trim()) {
        Ok(mut v) => {
            if let Some(obj) = v.as_object_mut() {
                obj.remove("envcloak_relay_error");
            }
            if let Some(id_val) = v.get("id") {
                if !id_val.is_null() && Id::from_value(id_val).is_none() {
                    if let Some(obj) = v.as_object_mut() {
                        obj.insert("id".to_owned(), Value::Null);
                    }
                }
            }
            let compact = serde_json::to_vec(&v).unwrap_or_else(|_| first_pass.into_bytes());
            redact_text(redactor, &compact)
        }
        Err(_) => first_pass
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>()
            .join(" "),
    };
    let mut out = single_line.into_bytes();
    out.push(b'\n');
    out
}

/// Redacts arbitrary bytes through `redactor` and the provider registry's
/// `mask_keys`.
#[must_use]
pub fn redact_text(redactor: &Redactor, raw: &[u8]) -> String {
    let bytes = redactor.redact(raw);
    let lossy = String::from_utf8_lossy(&bytes);
    match envcloak_client::render::registry() {
        Some(reg) => reg.mask_keys(&lossy),
        None => lossy.into_owned(),
    }
}

fn sanitize_response_id(v: &mut Value, fallback: Option<&Id>) {
    let Some(obj) = v.as_object_mut() else {
        return;
    };
    match obj.get("id") {
        Some(id_val) if id_val.is_null() || Id::from_value(id_val).is_some() => {}
        _ => {
            obj.insert("id".to_owned(), fallback.map_or(Value::Null, Id::to_value));
        }
    }
}

fn read_bounded<R: Read>(mut reader: R, max_bytes: usize) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => return Ok(out),
            Ok(n) => {
                if out.len().saturating_add(n) > max_bytes {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "response exceeds maximum size",
                    ));
                }
                out.extend_from_slice(&chunk[..n]);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

fn parse_handshake_url(line: &[u8]) -> Option<String> {
    let v: Value = serde_json::from_slice(line).ok()?;
    v.get("envcloak_relay_url")?.as_str().map(ToOwned::to_owned)
}

fn write_handshake_ok<W: Write>(output: &mut W) {
    let _ = output.write_all(b"{\"ok\":true}\n");
    let _ = output.flush();
}

fn write_handshake_err<W: Write>(output: &mut W, f: &Failure) {
    let mut bytes = serde_json::to_vec(&json!({
        "ok": false,
        "token": f.token(),
        "message": f.message(),
    }))
    .unwrap_or_default();
    bytes.push(b'\n');
    let _ = output.write_all(&bytes);
    let _ = output.flush();
}

fn write_relay_error<W: Write>(output: &mut W, f: &Failure) {
    let mut bytes = serde_json::to_vec(&json!({
        "envcloak_relay_error": {
            "token": f.token(),
            "message": f.message(),
        }
    }))
    .unwrap_or_default();
    bytes.push(b'\n');
    let _ = output.write_all(&bytes);
    let _ = output.flush();
}

fn write_rpc_error<W: Write>(output: &mut W, id: Option<&Id>, message: &'static str) {
    let _ = output.write_all(&rpc::error(id, RELAY_RPC_ERROR, message));
    let _ = output.flush();
}

fn not_started_by_daemon() -> Failure {
    Failure::new(
        "not_started_by_daemon",
        "envcloak mcp-bridge --relay is started only by envcloakd, for a bridged server; nothing \
         was received and nothing was started",
    )
}
