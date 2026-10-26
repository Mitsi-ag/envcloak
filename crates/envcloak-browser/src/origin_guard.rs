//! Origin guard for the sign-in worker (`SPEC.md` §6.8, M2 plan D-26, gate `b1`,
//! task `M2b-07`).
//!
//! Enforces strict origin boundaries across the browser root, out-of-process
//! iframes, dedicated/shared/service workers, `Fetch.requestPaused` interception,
//! `Network.webSocketWillSendHandshakeRequest` interception, form `action`
//! verification before and during submission, and an optional driver-side
//! loopback proxy (`LoopbackOriginProxy`) so that neither `sendBeacon`,
//! `WebSocket`, `ServiceWorker`, nor `Worker` can reach an unregistered origin
//! before CDP pauses it.

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use envcloak_signin::origin::parse_registered;
use envcloak_signin::{AttemptFailure, Host, Origin, SortedSet};

use crate::cdp::{CdpClient, CdpError, CdpEvent};

/// Registered origin sets enforced by [`OriginGuard`] during a sign-in attempt (`D-26`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetScope {
    pub app: SortedSet<Origin>,
    pub credential_entry: SortedSet<Origin>,
    pub identity_provider: SortedSet<Origin>,
    pub callback: SortedSet<Origin>,
}

fn set_contains(set: &SortedSet<Origin>, target: &Origin) -> bool {
    set.iter().any(|o| o == target)
}

/// Specific violation caught by [`OriginGuard`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardViolation {
    /// URL contained a userinfo component (`user@...`).
    Userinfo,
    /// URL could not be parsed as a valid `http(s)` origin or was not in the
    /// target's registered sets.
    UnregisteredOrigin,
    /// Hostname was an IDN/punycode lookalike or suffix mismatch not in the
    /// registered set.
    HostMismatch,
    /// Port differed from the registered origin's port.
    PortMismatch,
    /// Credential-bearing submission targeted an origin outside `credential_entry`
    /// and `identity_provider`.
    CredentialToNonEntryOrigin,
    /// Form `action` resolved to an origin outside `credential_entry` / `identity_provider`.
    OffOriginFormAction,
    /// Cross-origin iframe (`securityOrigin` or `Document` request) outside registered sets.
    CrossOriginFrame,
    /// WebSocket handshake targeted an origin outside registered sets.
    OffOriginWebSocket,
    /// TLS certificate error or self-signed certificate on an `https:` origin.
    CertificateInvalid,
    /// A new CDP target could not be attached and guarded with `Fetch.enable`.
    AttachFailed,
}

impl GuardViolation {
    /// Maps any origin-guard violation to [`AttemptFailure::OffOrigin`].
    pub const fn to_attempt_failure(&self) -> AttemptFailure {
        AttemptFailure::OffOrigin
    }
}

/// Phase of the sign-in flow when checking an origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardPhase {
    /// Navigating or loading resources during login.
    NavigationOrSubresource,
    /// Submitting credentials (username, password, or TOTP code).
    CredentialSubmission,
    /// Checking identity on the application after sign-in.
    IdentityCheck,
}

/// Enforces `D-26` origin sets for a [`TargetScope`].
#[derive(Debug, Clone)]
pub struct OriginGuard {
    scope: TargetScope,
    attached_sessions: BTreeSet<String>,
    pending_guard_commands: BTreeSet<u64>,
    violations: Vec<GuardViolation>,
}

impl OriginGuard {
    /// Creates an [`OriginGuard`] bound to `scope`.
    pub fn new(scope: TargetScope) -> Self {
        Self {
            scope,
            attached_sessions: BTreeSet::new(),
            pending_guard_commands: BTreeSet::new(),
            violations: Vec::new(),
        }
    }

    /// Returns the underlying [`TargetScope`].
    pub fn scope(&self) -> &TargetScope {
        &self.scope
    }

    /// Recorded violations, if any.
    pub fn violations(&self) -> &[GuardViolation] {
        &self.violations
    }

    /// Records a violation and returns [`AttemptFailure::OffOrigin`].
    pub fn record_violation(&mut self, v: GuardViolation) -> AttemptFailure {
        self.violations.push(v);
        AttemptFailure::OffOrigin
    }

    /// Checks whether `origin` belongs to any registered origin set in `self.scope`.
    pub fn is_any_registered_origin(&self, origin: &Origin) -> bool {
        set_contains(&self.scope.app, origin)
            || set_contains(&self.scope.credential_entry, origin)
            || set_contains(&self.scope.identity_provider, origin)
            || set_contains(&self.scope.callback, origin)
    }

    /// Checks whether `origin` is a registered credential-entry or identity-provider
    /// origin (the only origins permitted to receive credentials).
    pub fn is_credential_origin(&self, origin: &Origin) -> bool {
        set_contains(&self.scope.credential_entry, origin)
            || set_contains(&self.scope.identity_provider, origin)
    }

    /// Checks whether `origin` is a registered application origin.
    pub fn is_app_origin(&self, origin: &Origin) -> bool {
        set_contains(&self.scope.app, origin)
    }

    /// Parses and validates the origin of `url_str` (which may include a path,
    /// query, or fragment) against `self.scope` for `phase`.
    ///
    /// - Rejects any URL with userinfo (`@` in authority).
    /// - Converts `ws://` -> `http://` and `wss://` -> `https://` when `allow_ws` is true.
    /// - Compares scheme, host, and port strictly against the scope's sets
    ///   (never matching hosts by suffix).
    ///
    /// # Errors
    /// Returns [`GuardViolation`] if `url_str` violates any D-26 rule.
    pub fn check_url(
        &self,
        url_str: &str,
        phase: GuardPhase,
        allow_ws: bool,
    ) -> Result<Origin, GuardViolation> {
        let trimmed = url_str.trim();
        let normalized = if allow_ws {
            if let Some(rest) = trimmed.strip_prefix("ws://") {
                format!("http://{rest}")
            } else if let Some(rest) = trimmed.strip_prefix("wss://") {
                format!("https://{rest}")
            } else {
                trimmed.to_owned()
            }
        } else {
            trimmed.to_owned()
        };

        let origin_str = extract_origin_prefix(&normalized)?;
        let origin =
            parse_registered(&origin_str).map_err(|_| GuardViolation::UnregisteredOrigin)?;

        match phase {
            GuardPhase::CredentialSubmission => {
                if !self.is_credential_origin(&origin) {
                    return Err(classify_mismatch(&self.scope, &origin, true));
                }
            }
            GuardPhase::IdentityCheck => {
                if !self.is_app_origin(&origin) {
                    return Err(classify_mismatch(&self.scope, &origin, false));
                }
            }
            GuardPhase::NavigationOrSubresource => {
                if !self.is_any_registered_origin(&origin) {
                    return Err(classify_mismatch(&self.scope, &origin, false));
                }
            }
        }
        Ok(origin)
    }

    /// Resolves a form's `action` attribute relative to `document_url` and
    /// verifies that the resolved destination is a registered credential-entry
    /// or identity-provider origin.
    ///
    /// # Errors
    /// Returns [`GuardViolation`] if the document URL or resolved action URL is
    /// outside the credential-entry / identity-provider sets or contains userinfo.
    pub fn verify_form_action(
        &self,
        document_url: &str,
        action_attr: Option<&str>,
    ) -> Result<Origin, GuardViolation> {
        let doc_origin = self.check_url(document_url, GuardPhase::CredentialSubmission, false)?;
        let Some(raw_action) = action_attr.map(str::trim).filter(|s| !s.is_empty()) else {
            return Ok(doc_origin);
        };
        if raw_action.contains("://") || raw_action.starts_with("//") {
            let resolved = if let Some(schemeless) = raw_action.strip_prefix("//") {
                format!("{}://{schemeless}", doc_origin.scheme().as_str())
            } else {
                raw_action.to_owned()
            };
            self.check_url(&resolved, GuardPhase::CredentialSubmission, false)
                .map_err(|v| match v {
                    GuardViolation::Userinfo => GuardViolation::Userinfo,
                    _ => GuardViolation::OffOriginFormAction,
                })
        } else if raw_action.starts_with('/')
            || raw_action.starts_with('?')
            || !raw_action.contains(':')
        {
            // Same-origin relative path
            Ok(doc_origin)
        } else {
            // Non-http(s) scheme like javascript: or data:
            Err(GuardViolation::OffOriginFormAction)
        }
    }

    /// Configures root-level `Target.setAutoAttach` on `cdp`.
    ///
    /// # Errors
    /// Returns [`AttemptFailure::OffOrigin`] if `Target.setAutoAttach` fails.
    pub fn install_on_root<R: Read, W: Write>(
        &mut self,
        cdp: &mut CdpClient<R, W>,
    ) -> Result<(), AttemptFailure> {
        cdp.call(
            None,
            "Target.setAutoAttach",
            json!({
                "autoAttach": true,
                "waitForDebuggerOnStart": true,
                "flatten": true
            }),
        )
        .map_err(|_| self.record_violation(GuardViolation::AttachFailed))?;

        Ok(())
    }

    /// Attaches the origin guard (`Target.setAutoAttach`, `Fetch.enable`,
    /// `Network.enable`, `Page.enable`, `DOM.enable`, `DOMStorage.enable`) to a
    /// newly created or auto-attached target `session_id` before releasing it
    /// with `Runtime.runIfWaitingForDebugger`.
    ///
    /// # Errors
    /// Returns [`AttemptFailure::OffOrigin`] if any guard setup call fails.
    pub fn guard_and_release_session<R: Read, W: Write>(
        &mut self,
        cdp: &mut CdpClient<R, W>,
        session_id: &str,
        is_page_or_iframe: bool,
    ) -> Result<(), AttemptFailure> {
        self.guard_and_release_target(
            cdp,
            session_id,
            if is_page_or_iframe { "page" } else { "worker" },
        )
    }

    fn guard_and_release_target<R: Read, W: Write>(
        &mut self,
        cdp: &mut CdpClient<R, W>,
        session_id: &str,
        target_type: &str,
    ) -> Result<(), AttemptFailure> {
        if self.attached_sessions.contains(session_id) {
            let _ = cdp.send_command(
                Some(session_id),
                "Runtime.runIfWaitingForDebugger",
                json!({}),
            );
            return Ok(());
        }

        if matches!(
            target_type,
            "page" | "iframe" | "worker" | "shared_worker" | "service_worker"
        ) {
            let auto_id = cdp
                .send_command(
                    Some(session_id),
                    "Target.setAutoAttach",
                    json!({
                        "autoAttach": true,
                        "waitForDebuggerOnStart": true,
                        "flatten": true
                    }),
                )
                .map_err(|_| self.record_violation(GuardViolation::AttachFailed))?;
            self.pending_guard_commands.insert(auto_id);

            let fetch_id = cdp
                .send_command(
                    Some(session_id),
                    "Fetch.enable",
                    json!({
                        "patterns": [{ "urlPattern": "*", "requestStage": "Request" }]
                    }),
                )
                .map_err(|_| self.record_violation(GuardViolation::AttachFailed))?;
            self.pending_guard_commands.insert(fetch_id);

            let _ = cdp.send_command(Some(session_id), "Network.enable", json!({}));
            if matches!(target_type, "page" | "iframe") {
                let _ = cdp.send_command(Some(session_id), "Page.enable", json!({}));
                let _ = cdp.send_command(Some(session_id), "DOM.enable", json!({}));
                let _ = cdp.send_command(Some(session_id), "DOMStorage.enable", json!({}));
            }
        }

        // Release the target from `waitForDebuggerOnStart` without blocking on
        // paused worker threads.
        let _ = cdp.send_command(
            Some(session_id),
            "Runtime.runIfWaitingForDebugger",
            json!({}),
        );
        self.attached_sessions.insert(session_id.to_owned());
        Ok(())
    }

    /// Sends a CDP command while continuously draining and enforcing [`OriginGuard`]
    /// on any interleaved `Fetch.requestPaused`, `Target.attachedToTarget`,
    /// `Network.webSocketWillSendHandshakeRequest`, or `Page.frameNavigated` events.
    ///
    /// # Errors
    /// Returns [`AttemptFailure`] if an origin violation occurs or the command fails.
    pub fn call<R: Read, W: Write>(
        &mut self,
        cdp: &mut CdpClient<R, W>,
        session_id: Option<&str>,
        method: &str,
        params: Value,
    ) -> Result<Value, AttemptFailure> {
        self.drain_events(cdp)?;
        let id = cdp
            .send_command(session_id, method, params)
            .map_err(|_| AttemptFailure::OffOrigin)?;
        loop {
            self.drain_events(cdp)?;
            match cdp.step_until_response(id) {
                Ok(Some(Ok(val))) => {
                    self.drain_events(cdp)?;
                    return Ok(val);
                }
                Ok(Some(Err(_))) | Err(_) => return Err(AttemptFailure::OffOrigin),
                Ok(None) => {}
            }
        }
    }

    /// Inspects and handles one queued [`CdpEvent`]:
    /// - On `Target.attachedToTarget`: recursively attaches `Fetch` + `Network`
    ///   before `Runtime.runIfWaitingForDebugger` and checks the target URL's origin.
    /// - On `Fetch.requestPaused`: verifies the request URL against `self.scope`
    ///   (requiring credential-entry/IdP origins for POST submissions), fails
    ///   any violating request with `Fetch.failRequest`, and fulfills/continues
    ///   allowed requests with `Fetch.continueRequest`.
    /// - On `Network.webSocketWillSendHandshakeRequest`: verifies the WebSocket
    ///   URL against `self.scope`.
    /// - On `Page.frameNavigated`: verifies the frame's `securityOrigin`.
    ///
    /// # Errors
    /// Returns [`AttemptFailure::TargetMismatch`] immediately on any origin
    /// violation.
    pub fn process_cdp_event<R: Read, W: Write>(
        &mut self,
        cdp: &mut CdpClient<R, W>,
        event: &CdpEvent,
    ) -> Result<(), AttemptFailure> {
        match event.method.as_str() {
            "Target.attachedToTarget" => {
                let Some(sid) = event.params.get("sessionId").and_then(Value::as_str) else {
                    return Err(self.record_violation(GuardViolation::AttachFailed));
                };
                let target_info = event
                    .params
                    .get("targetInfo")
                    .cloned()
                    .unwrap_or(Value::Null);
                let target_type = target_info
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let target_url = target_info.get("url").and_then(Value::as_str).unwrap_or("");
                let is_wrapper = matches!(target_type, "tab" | "browser")
                    || target_url.starts_with("chrome-extension://")
                    || target_url.starts_with("chrome://")
                    || target_url.starts_with("devtools://");
                if !is_wrapper && !target_url.is_empty() && target_url != "about:blank" {
                    if let Err(v) =
                        self.check_url(target_url, GuardPhase::NavigationOrSubresource, false)
                    {
                        return Err(self.record_violation(v));
                    }
                }
                self.guard_and_release_target(
                    cdp,
                    sid,
                    if is_wrapper { "tab" } else { target_type },
                )?;
            }
            "Fetch.requestPaused" => {
                let req_id = event
                    .params
                    .get("requestId")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let req_obj = event.params.get("request").cloned().unwrap_or(Value::Null);
                let url = req_obj.get("url").and_then(Value::as_str).unwrap_or("");
                let method = req_obj
                    .get("method")
                    .and_then(Value::as_str)
                    .unwrap_or("GET");
                let res_type = event
                    .params
                    .get("resourceType")
                    .and_then(Value::as_str)
                    .unwrap_or("");

                if url == "about:blank"
                    || url.starts_with("favicon.")
                    || url.ends_with("/favicon.ico")
                    || url.starts_with("chrome-extension://")
                    || url.starts_with("chrome://")
                {
                    if !req_id.is_empty() {
                        let _ = cdp.call(
                            event.session_id.as_deref(),
                            "Fetch.continueRequest",
                            json!({ "requestId": req_id }),
                        );
                    }
                    return Ok(());
                }

                let phase = if method.eq_ignore_ascii_case("POST") {
                    GuardPhase::CredentialSubmission
                } else {
                    GuardPhase::NavigationOrSubresource
                };

                match self.check_url(url, phase, false) {
                    Ok(_) => {
                        if !req_id.is_empty() {
                            let _ = cdp.call(
                                event.session_id.as_deref(),
                                "Fetch.continueRequest",
                                json!({ "requestId": req_id }),
                            );
                        }
                    }
                    Err(v) => {
                        if !req_id.is_empty() {
                            let _ = cdp.call(
                                event.session_id.as_deref(),
                                "Fetch.failRequest",
                                json!({
                                    "requestId": req_id,
                                    "errorReason": "BlockedByClient"
                                }),
                            );
                        }
                        let recorded = if res_type.eq_ignore_ascii_case("SubFrame") {
                            GuardViolation::CrossOriginFrame
                        } else {
                            v
                        };
                        return Err(self.record_violation(recorded));
                    }
                }
            }
            "Network.webSocketWillSendHandshakeRequest" => {
                let ws_url = event
                    .params
                    .get("request")
                    .and_then(|r| r.get("url"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if self
                    .check_url(ws_url, GuardPhase::NavigationOrSubresource, true)
                    .is_err()
                {
                    return Err(self.record_violation(GuardViolation::OffOriginWebSocket));
                }
            }
            "Page.frameNavigated" => {
                if let Some(frame) = event.params.get("frame") {
                    let sec_origin = frame
                        .get("securityOrigin")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let frame_url = frame.get("url").and_then(Value::as_str).unwrap_or("");
                    if !sec_origin.is_empty()
                        && sec_origin != "://"
                        && sec_origin != "null"
                        && frame_url != "about:blank"
                    {
                        if let Err(v) =
                            self.check_url(sec_origin, GuardPhase::NavigationOrSubresource, false)
                        {
                            return Err(self.record_violation(v));
                        }
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Drains and processes all currently queued CDP events through
    /// [`OriginGuard::process_cdp_event`], and verifies that all pipelined
    /// `Target.setAutoAttach` and `Fetch.enable` commands succeeded.
    pub fn drain_events<R: Read, W: Write>(
        &mut self,
        cdp: &mut CdpClient<R, W>,
    ) -> Result<(), AttemptFailure> {
        let mut attach_failed = false;
        self.pending_guard_commands
            .retain(|&cmd_id| match cdp.take_pending_response(cmd_id) {
                Some(Ok(_)) => false,
                Some(Err(_)) => {
                    attach_failed = true;
                    false
                }
                None => true,
            });
        if attach_failed {
            return Err(self.record_violation(GuardViolation::AttachFailed));
        }
        while let Some(ev) = cdp.pop_event() {
            self.process_cdp_event(cdp, &ev)?;
        }
        Ok(())
    }
}

/// Extracts `"scheme://authority"` from `url` and rejects userinfo (`@`).
fn extract_origin_prefix(url: &str) -> Result<String, GuardViolation> {
    let Some((scheme, rest)) = url.split_once("://") else {
        return Err(GuardViolation::UnregisteredOrigin);
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.is_empty() {
        return Err(GuardViolation::UnregisteredOrigin);
    }
    if authority.contains('@') {
        return Err(GuardViolation::Userinfo);
    }
    Ok(format!("{scheme}://{authority}"))
}

fn classify_mismatch(
    scope: &TargetScope,
    candidate: &Origin,
    credential_only: bool,
) -> GuardViolation {
    let mut same_host_diff_port = false;
    let empty_origins = SortedSet::new(vec![]).expect("empty set");
    let iter = scope
        .credential_entry
        .iter()
        .chain(scope.identity_provider.iter())
        .chain(if credential_only {
            empty_origins.iter()
        } else {
            scope.app.iter()
        });
    for allowed in iter {
        if allowed.host() == candidate.host()
            && allowed.scheme() == candidate.scheme()
            && allowed.port() != candidate.port()
        {
            same_host_diff_port = true;
        }
    }
    if same_host_diff_port {
        return GuardViolation::PortMismatch;
    }
    if let Host::Name(hn) = candidate.host()
        && hn.as_str().contains("xn--")
    {
        return GuardViolation::HostMismatch;
    }
    if credential_only
        && (set_contains(&scope.app, candidate) || set_contains(&scope.callback, candidate))
    {
        return GuardViolation::CredentialToNonEntryOrigin;
    }
    GuardViolation::UnregisteredOrigin
}

/// Driver-side loopback proxy (`M2b-07`, `D-26`): sits in front of the worker
/// Chrome process (`--proxy-server=127.0.0.1:<port>` + `--proxy-bypass-list=<-loopback>`)
/// and refuses any HTTP request, WebSocket upgrade, `sendBeacon`, Worker fetch,
/// or HTTPS `CONNECT` tunnel to an origin outside [`OriginGuard`]'s registered
/// sets before a single TCP connection reaches the destination server.
#[derive(Debug)]
pub struct LoopbackOriginProxy {
    addr: String,
    stop: Arc<AtomicBool>,
    blocked_count: Arc<AtomicU64>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl LoopbackOriginProxy {
    /// Starts a [`LoopbackOriginProxy`] enforcing `scope`.
    ///
    /// # Errors
    /// Returns an I/O error if binding `127.0.0.1:0` fails.
    pub fn start(scope: TargetScope) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let addr = format!("127.0.0.1:{port}");
        let stop = Arc::new(AtomicBool::new(false));
        let blocked_count = Arc::new(AtomicU64::new(0));

        let stop_clone = Arc::clone(&stop);
        let blocked_clone = Arc::clone(&blocked_count);
        let guard = Arc::new(OriginGuard::new(scope));

        let thread = std::thread::Builder::new()
            .name("signin-origin-proxy".into())
            .spawn(move || {
                while !stop_clone.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((client, _)) => {
                            let g = Arc::clone(&guard);
                            let b = Arc::clone(&blocked_clone);
                            let _ = std::thread::spawn(move || {
                                handle_proxy_client(client, &g, &b);
                            });
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            })?;

        Ok(Self {
            addr,
            stop,
            blocked_count,
            thread: Some(thread),
        })
    }

    /// Proxy `host:port` string for `--proxy-server`.
    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// Number of off-origin connections or requests blocked by the proxy.
    pub fn blocked_count(&self) -> u64 {
        self.blocked_count.load(Ordering::SeqCst)
    }

    /// Clones the atomic counter handle for [`Driver::run`].
    pub fn blocked_handle(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.blocked_count)
    }
}

impl Drop for LoopbackOriginProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.thread.take() {
            let _ = h.join();
        }
    }
}

fn handle_proxy_client(mut client: TcpStream, guard: &OriginGuard, blocked: &AtomicU64) {
    let _ = client.set_nonblocking(false);
    let _ = client.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = client.set_write_timeout(Some(Duration::from_secs(5)));

    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 2048];
    let header_end = loop {
        match client.read(&mut tmp) {
            Ok(0) => return,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if let Some(pos) = find_double_crlf(&buf) {
                    break pos;
                }
                if buf.len() > 65536 {
                    return;
                }
            }
            Err(_) => return,
        }
    };

    let head_str = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let mut lines = head_str.lines();
    let Some(req_line) = lines.next() else {
        return;
    };
    let mut parts = req_line.split_whitespace();
    let Some(method) = parts.next() else {
        return;
    };
    let Some(target) = parts.next() else {
        return;
    };
    let version = parts.next().unwrap_or("HTTP/1.1");

    if method.eq_ignore_ascii_case("CONNECT") {
        // CONNECT host:port HTTP/1.1
        let candidate_url = format!("https://{target}");
        let Ok(origin) =
            guard.check_url(&candidate_url, GuardPhase::NavigationOrSubresource, false)
        else {
            if !is_chrome_background_noise_url(&candidate_url) {
                blocked.fetch_add(1, Ordering::SeqCst);
            }
            let _ = client.write_all(
                b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
            return;
        };
        let port = origin.port();
        let upstream_addr = match origin.host() {
            Host::V6(_) => std::net::SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port)),
            _ => std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port)),
        };
        let Ok(mut upstream) = TcpStream::connect(upstream_addr) else {
            let _ = client.write_all(
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
            return;
        };
        let _ = client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
        let _ = upstream.write_all(&buf[header_end + 4..]);
        relay_bidirectional(client, upstream);
        return;
    }

    // Standard HTTP or WebSocket upgrade request through proxy
    let mut host_header = None;
    let mut is_ws_upgrade = false;
    let mut content_length = 0usize;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("host") {
                host_header = Some(v.trim().to_owned());
            } else if k.trim().eq_ignore_ascii_case("upgrade")
                && v.trim().eq_ignore_ascii_case("websocket")
            {
                is_ws_upgrade = true;
            } else if k.trim().eq_ignore_ascii_case("content-length")
                && let Ok(cl) = v.trim().parse::<usize>()
            {
                content_length = cl.min(1024 * 1024);
            }
        }
    }

    let full_url = if target.starts_with("http://") || target.starts_with("https://") {
        target.to_owned()
    } else if let Some(h) = &host_header {
        format!("http://{h}{target}")
    } else {
        blocked.fetch_add(1, Ordering::SeqCst);
        return;
    };

    let phase = if method.eq_ignore_ascii_case("POST") {
        GuardPhase::CredentialSubmission
    } else {
        GuardPhase::NavigationOrSubresource
    };

    let Ok(origin) = guard.check_url(&full_url, phase, is_ws_upgrade) else {
        if !is_chrome_background_noise_url(&full_url) {
            blocked.fetch_add(1, Ordering::SeqCst);
        }
        let _ = client
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        return;
    };

    while !is_ws_upgrade && buf.len() < header_end + 4 + content_length {
        match client.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => break,
        }
    }

    let port = origin.port();
    let upstream_addr = match origin.host() {
        Host::V6(_) => std::net::SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port)),
        _ => std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port)),
    };

    let path_and_query = extract_path_and_query(&full_url);
    let Ok(mut upstream) = TcpStream::connect(upstream_addr) else {
        let _ = client.write_all(
            b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        return;
    };
    let _ = upstream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = upstream.set_write_timeout(Some(Duration::from_secs(10)));

    let mut rebuilt = format!("{method} {path_and_query} {version}\r\n");
    for line in head_str.lines().skip(1) {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("proxy-connection:")
            || (!is_ws_upgrade && lower.starts_with("connection:"))
        {
            continue;
        }
        rebuilt.push_str(line);
        rebuilt.push_str("\r\n");
    }
    if !is_ws_upgrade {
        rebuilt.push_str("Connection: close\r\n");
    }
    rebuilt.push_str("\r\n");
    if upstream.write_all(rebuilt.as_bytes()).is_err() {
        return;
    }
    if upstream.write_all(&buf[header_end + 4..]).is_err() {
        return;
    }
    let _ = upstream.flush();
    if is_ws_upgrade {
        relay_bidirectional(client, upstream);
    } else {
        let _ = std::io::copy(&mut upstream, &mut client);
        let _ = client.flush();
        let _ = client.shutdown(std::net::Shutdown::Both);
        let _ = upstream.shutdown(std::net::Shutdown::Both);
    }
}

fn is_chrome_background_noise_url(url: &str) -> bool {
    let Ok(origin_str) = extract_origin_prefix(url) else {
        return false;
    };
    let Some((_, rest)) = origin_str.split_once("://") else {
        return false;
    };
    let host = rest.split(':').next().unwrap_or("").to_ascii_lowercase();
    host == "google.com"
        || host.ends_with(".google.com")
        || host == "googleapis.com"
        || host.ends_with(".googleapis.com")
        || host == "gstatic.com"
        || host.ends_with(".gstatic.com")
        || host == "gvt1.com"
        || host.ends_with(".gvt1.com")
        || host == "chromium.org"
        || host.ends_with(".chromium.org")
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn extract_path_and_query(url: &str) -> &str {
    if let Some((_, rest)) = url.split_once("://") {
        if let Some(idx) = rest.find('/') {
            return &rest[idx..];
        }
        return "/";
    }
    if url.starts_with('/') { url } else { "/" }
}

fn relay_bidirectional(mut a: TcpStream, mut b: TcpStream) {
    let Ok(mut a_read) = a.try_clone() else {
        return;
    };
    let Ok(mut b_write) = b.try_clone() else {
        return;
    };
    let t = std::thread::spawn(move || {
        let _ = std::io::copy(&mut a_read, &mut b_write);
        let _ = b_write.shutdown(std::net::Shutdown::Both);
    });
    let _ = std::io::copy(&mut b, &mut a);
    let _ = a.shutdown(std::net::Shutdown::Both);
    let _ = t.join();
}

#[allow(dead_code)]
fn _use_cdp_error(_e: CdpError) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_scope() -> TargetScope {
        let app = parse_registered("http://acme.localhost:4100").unwrap();
        let entry = parse_registered("http://acme.localhost:4100").unwrap();
        let idp = parse_registered("http://idp-acme.localhost:4101").unwrap();
        TargetScope {
            app: SortedSet::new(vec![app.clone()]).unwrap(),
            credential_entry: SortedSet::new(vec![entry]).unwrap(),
            identity_provider: SortedSet::new(vec![idp]).unwrap(),
            callback: SortedSet::new(vec![app]).unwrap(),
        }
    }

    #[test]
    fn guard_rejects_unregistered_lookalike_userinfo_port_and_off_origin_action() {
        let guard = OriginGuard::new(sample_scope());

        // Allowed entry origin
        assert!(
            guard
                .check_url(
                    "http://acme.localhost:4100/login",
                    GuardPhase::CredentialSubmission,
                    false
                )
                .is_ok()
        );

        // Unregistered origin
        assert_eq!(
            guard.check_url(
                "http://evil.localhost:4105/login",
                GuardPhase::CredentialSubmission,
                false
            ),
            Err(GuardViolation::UnregisteredOrigin)
        );

        // Suffix lookalike (not suffix matched!)
        assert_eq!(
            guard.check_url(
                "http://sub.acme.localhost:4100/login",
                GuardPhase::NavigationOrSubresource,
                false
            ),
            Err(GuardViolation::UnregisteredOrigin)
        );

        // IDN punycode lookalike
        assert_eq!(
            guard.check_url(
                "http://xn--cme-pla.localhost:4105/login",
                GuardPhase::CredentialSubmission,
                false
            ),
            Err(GuardViolation::HostMismatch)
        );

        // Userinfo URL
        assert_eq!(
            guard.check_url(
                "http://acme.localhost@evil.localhost:4105/login",
                GuardPhase::NavigationOrSubresource,
                false
            ),
            Err(GuardViolation::Userinfo)
        );

        // Changed port
        assert_eq!(
            guard.check_url(
                "http://acme.localhost:4199/login",
                GuardPhase::CredentialSubmission,
                false
            ),
            Err(GuardViolation::PortMismatch)
        );

        // Form action check
        assert!(
            guard
                .verify_form_action("http://acme.localhost:4100/login", Some("/login"))
                .is_ok()
        );
        assert_eq!(
            guard.verify_form_action(
                "http://acme.localhost:4100/login",
                Some("http://evil.localhost:4105/login")
            ),
            Err(GuardViolation::OffOriginFormAction)
        );
    }
}
