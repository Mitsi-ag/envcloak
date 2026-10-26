//! Sign-in worker driver (`SPEC.md` §6.8, M2 plan D-25, D-26, D-27, D-34, F-73,
//! gates `b1`, `b2`, `b5`, `b6`, `b13`, `b16`, task `M2b-07`).
//!
//! - Communicates with the daemon over a dedicated pipe (`DriverPipe`) using
//!   [`DriverMessage`] (`NeedUsername`, `NeedPassword`, `NeedCode { step }`,
//!   `Captured(DeclaredState)`, `Stopped(WorkerStopReason)`).
//! - Never spawns Chrome, never learns Chrome's PID or process group, and sends
//!   no `WorkerStarted` message (`F-73`).
//! - Drives either a browser login over CDP (`AttemptFlow::BrowserLogin`) or a
//!   D-28 loopback test-session mint (`AttemptFlow::TestSession`).
//! - Closes its CDP pipe descriptors immediately on exit.

use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use envcloak_signin::{IdentityCheck, TransferScope};

use crate::adapter::execute_test_session_adapter;
use crate::cdp::CdpClient;
use crate::extract::{DeclaredState, WorkerSessionFormat, extract_from_cdp};
use crate::identity::{ExpectedIdentity, WorkerStopReason, verify_worker_identity};
use crate::origin_guard::{GuardPhase, OriginGuard, TargetScope};
use crate::state_machine::{
    InspectedInput, LoginFieldHints, LoginStateMachine, LoginStepDecision, PageLoginSurface,
};

/// Maximum byte length of a single message on the driver pipe (1 MiB).
pub const MAX_DRIVER_MESSAGE_BYTES: usize = 1024 * 1024;

/// Messages sent from the driver to the daemon (`M2b-07`).
///
/// Note (`F-73`): `WorkerStarted` is intentionally absent; the driver never
/// spawns Chrome or learns its PID.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DriverMessage {
    /// Driver reached the username field and requests the account username.
    NeedUsername,
    /// Driver reached the password field (or test-session adapter step) and
    /// requests the password / adapter key.
    NeedPassword,
    /// Driver reached a one-time code field (`step` is `1` or `2`).
    NeedCode { step: u8 },
    /// Driver verified identity and captured the declared session state.
    Captured(DeclaredState),
    /// Driver stopped with a value-free reason.
    Stopped(WorkerStopReason),
}

/// Messages sent from the daemon to the driver in response to [`DriverMessage`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DaemonToDriver {
    /// Account username for [`DriverMessage::NeedUsername`].
    Username(#[serde(with = "crate::extract::serde_zeroizing_string")] Zeroizing<String>),
    /// Password or adapter key for [`DriverMessage::NeedPassword`].
    Password(#[serde(with = "crate::extract::serde_zeroizing_string")] Zeroizing<String>),
    /// TOTP code for [`DriverMessage::NeedCode`].
    Code(#[serde(with = "crate::extract::serde_zeroizing_string")] Zeroizing<String>),
    /// Immediate abort requested by the daemon (cancel, lock, timeout, etc.).
    Stop,
}

impl fmt::Debug for DaemonToDriver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DaemonToDriver::Username(_) => f.write_str("DaemonToDriver::Username([REDACTED])"),
            DaemonToDriver::Password(_) => f.write_str("DaemonToDriver::Password([REDACTED])"),
            DaemonToDriver::Code(_) => f.write_str("DaemonToDriver::Code([REDACTED])"),
            DaemonToDriver::Stop => f.write_str("DaemonToDriver::Stop"),
        }
    }
}

/// Framed bidirectional pipe between the driver and the daemon (or test harness).
#[derive(Debug)]
pub struct DriverPipe<R, W> {
    reader: R,
    writer: W,
}

impl<R: Read, W: Write> DriverPipe<R, W> {
    /// Wraps `reader` and `writer` in a [`DriverPipe`].
    pub fn new(reader: R, writer: W) -> Self {
        Self { reader, writer }
    }

    /// Sends a [`DriverMessage`] to the daemon.
    ///
    /// # Errors
    /// Returns [`WorkerStopReason::WorkerLost`] on I/O or serialization failure.
    pub fn send(&mut self, msg: &DriverMessage) -> Result<(), WorkerStopReason> {
        let payload =
            Zeroizing::new(serde_json::to_vec(msg).map_err(|_| WorkerStopReason::WorkerLost)?);
        if payload.len() > MAX_DRIVER_MESSAGE_BYTES {
            return Err(WorkerStopReason::WorkerLost);
        }
        let len = u32::try_from(payload.len()).map_err(|_| WorkerStopReason::WorkerLost)?;
        self.writer
            .write_all(&len.to_be_bytes())
            .map_err(|_| WorkerStopReason::WorkerLost)?;
        self.writer
            .write_all(&payload)
            .map_err(|_| WorkerStopReason::WorkerLost)?;
        self.writer
            .flush()
            .map_err(|_| WorkerStopReason::WorkerLost)?;
        Ok(())
    }

    /// Receives a [`DaemonToDriver`] reply from the daemon.
    ///
    /// # Errors
    /// Returns [`WorkerStopReason::WorkerLost`] on EOF, oversized frame, or
    /// [`DaemonToDriver::Stop`].
    pub fn recv(&mut self) -> Result<DaemonToDriver, WorkerStopReason> {
        let mut len_buf = [0u8; 4];
        self.reader
            .read_exact(&mut len_buf)
            .map_err(|_| WorkerStopReason::WorkerLost)?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 || len > MAX_DRIVER_MESSAGE_BYTES {
            return Err(WorkerStopReason::WorkerLost);
        }
        let mut buf = Zeroizing::new(vec![0u8; len]);
        self.reader
            .read_exact(&mut buf)
            .map_err(|_| WorkerStopReason::WorkerLost)?;
        let msg: DaemonToDriver =
            serde_json::from_slice(&buf).map_err(|_| WorkerStopReason::WorkerLost)?;
        if matches!(msg, DaemonToDriver::Stop) {
            return Err(WorkerStopReason::WorkerLost);
        }
        Ok(msg)
    }
}

/// Sends a [`DaemonToDriver`] message from the daemon/harness side of a driver pipe.
///
/// # Errors
/// Returns an I/O error if writing fails.
pub fn send_to_driver<W: Write>(writer: &mut W, msg: &DaemonToDriver) -> std::io::Result<()> {
    let payload = Zeroizing::new(
        serde_json::to_vec(msg)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
    );
    let len = u32::try_from(payload.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "frame too large"))?;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()
}

/// Receives a [`DriverMessage`] on the daemon/harness side of a driver pipe.
///
/// # Errors
/// Returns an I/O error on EOF or invalid frame.
pub fn recv_from_driver<R: Read>(reader: &mut R) -> std::io::Result<DriverMessage> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_DRIVER_MESSAGE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid driver frame length",
        ));
    }
    let mut buf = Zeroizing::new(vec![0u8; len]);
    reader.read_exact(&mut buf)?;
    serde_json::from_slice(&buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Which flow the sign-in attempt runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptFlow {
    /// Browser form login driven over the CDP pipe to the worker Chrome instance.
    BrowserLogin {
        login_url: String,
        hints: LoginFieldHints,
    },
    /// D-28 loopback test-session adapter mint (`POST /__envcloak/test-session`).
    TestSession {
        endpoint_origin: String,
        ttl_secs: u64,
    },
}

/// Complete specification of a single sign-in attempt passed to [`Driver::run`].
#[derive(Debug, Clone)]
pub struct AttemptSpec {
    pub scope: TargetScope,
    pub identity_check: IdentityCheck,
    pub expected_identity: ExpectedIdentity,
    pub transfer: TransferScope,
    pub session_format: WorkerSessionFormat,
    pub flow: AttemptFlow,
}

/// Final outcome of [`Driver::run`].
#[derive(Debug, Clone, PartialEq)]
pub enum AttemptOutcome {
    /// Worker verified identity and captured only the declared state.
    Captured(DeclaredState),
    /// Worker stopped with a reason and captured nothing.
    Stopped(WorkerStopReason),
}

/// Sign-in worker driver (`envcloakd --signin-driver`).
#[derive(Debug, Default)]
pub struct Driver;

impl Driver {
    /// Runs a sign-in attempt to completion, communicating credential requests
    /// and the final outcome over `pipe`.
    ///
    /// When `cdp_pipes` is `Some((cdp_read_fd, cdp_write_fd))`, both descriptors
    /// are consumed and closed before `Driver::run` returns.
    pub fn run<R: Read, W: Write>(
        pipe: &mut DriverPipe<R, W>,
        spec: AttemptSpec,
        cdp_pipes: Option<(OwnedFd, OwnedFd)>,
        proxy_blocked: Option<Arc<AtomicU64>>,
    ) -> AttemptOutcome {
        let res = match &spec.flow {
            AttemptFlow::TestSession {
                endpoint_origin,
                ttl_secs,
            } => {
                // Drop CDP pipes immediately if any were passed.
                drop(cdp_pipes);
                Self::run_test_session(pipe, &spec, endpoint_origin, *ttl_secs)
            }
            AttemptFlow::BrowserLogin { login_url, hints } => {
                let Some((cdp_r_fd, cdp_w_fd)) = cdp_pipes else {
                    let _ = pipe.send(&DriverMessage::Stopped(WorkerStopReason::WorkerLost));
                    return AttemptOutcome::Stopped(WorkerStopReason::WorkerLost);
                };
                let cdp_reader = File::from(cdp_r_fd);
                let cdp_writer = File::from(cdp_w_fd);
                let mut cdp = CdpClient::new(cdp_reader, cdp_writer);
                let out = Self::run_browser_login(
                    pipe,
                    &mut cdp,
                    &spec,
                    login_url,
                    hints.clone(),
                    proxy_blocked.as_ref(),
                );
                // Explicitly drop `cdp` so the driver's pipe ends close immediately.
                drop(cdp);
                out
            }
        };

        match res {
            Ok(state) => {
                let _ = pipe.send(&DriverMessage::Captured(state.clone()));
                AttemptOutcome::Captured(state)
            }
            Err(reason) => {
                let _ = pipe.send(&DriverMessage::Stopped(reason));
                AttemptOutcome::Stopped(reason)
            }
        }
    }

    fn run_test_session<R: Read, W: Write>(
        pipe: &mut DriverPipe<R, W>,
        spec: &AttemptSpec,
        endpoint_origin: &str,
        ttl_secs: u64,
    ) -> Result<DeclaredState, WorkerStopReason> {
        let mut guard = OriginGuard::new(spec.scope.clone());
        guard
            .check_url(endpoint_origin, GuardPhase::CredentialSubmission, false)
            .map_err(|v| WorkerStopReason::from(guard.record_violation(v)))?;

        pipe.send(&DriverMessage::NeedPassword)?;
        let adapter_key = match pipe.recv()? {
            DaemonToDriver::Password(pw) => pw,
            _ => return Err(WorkerStopReason::WorkerLost),
        };

        execute_test_session_adapter(
            endpoint_origin,
            adapter_key.as_bytes(),
            ttl_secs,
            &mut guard,
            &spec.expected_identity,
            &spec.transfer,
            spec.session_format,
        )
    }

    fn run_browser_login<R: Read, W: Write, CR: Read, CW: Write>(
        pipe: &mut DriverPipe<R, W>,
        cdp: &mut CdpClient<CR, CW>,
        spec: &AttemptSpec,
        login_url: &str,
        hints: LoginFieldHints,
        proxy_blocked: Option<&Arc<AtomicU64>>,
    ) -> Result<DeclaredState, WorkerStopReason> {
        if spec.session_format == WorkerSessionFormat::Unsupported {
            return Err(WorkerStopReason::UnsupportedSessionScope);
        }

        let mut guard = OriginGuard::new(spec.scope.clone());

        // Pre-flight check of the initial login URL before touching the browser!
        guard
            .check_url(login_url, GuardPhase::CredentialSubmission, false)
            .map_err(|v| WorkerStopReason::from(guard.record_violation(v)))?;

        guard.install_on_root(cdp).map_err(WorkerStopReason::from)?;

        let create_res = cdp
            .call(None, "Target.createTarget", json!({ "url": "about:blank" }))
            .map_err(|_| WorkerStopReason::WorkerLost)?;
        let target_id = create_res
            .get("targetId")
            .and_then(Value::as_str)
            .ok_or(WorkerStopReason::WorkerLost)?
            .to_owned();

        let attach_res = cdp
            .call(
                None,
                "Target.attachToTarget",
                json!({ "targetId": target_id, "flatten": true }),
            )
            .map_err(|_| WorkerStopReason::WorkerLost)?;
        let session_id = attach_res
            .get("sessionId")
            .and_then(Value::as_str)
            .ok_or(WorkerStopReason::WorkerLost)?
            .to_owned();

        guard
            .guard_and_release_session(cdp, &session_id, true)
            .map_err(WorkerStopReason::from)?;
        guard.drain_events(cdp).map_err(WorkerStopReason::from)?;

        let nav_res = guard
            .call(
                cdp,
                Some(&session_id),
                "Page.navigate",
                json!({ "url": login_url }),
            )
            .map_err(WorkerStopReason::from)?;

        if let Some(err_text) = nav_res.get("errorText").and_then(Value::as_str)
            && !err_text.is_empty()
        {
            return Err(WorkerStopReason::OffOrigin);
        }

        wait_for_page_settle(cdp, &session_id, &mut guard, proxy_blocked, false)?;

        let mut state_machine = LoginStateMachine::new(hints);

        for _step_idx in 0..6 {
            guard.drain_events(cdp).map_err(WorkerStopReason::from)?;
            check_proxy_blocked(proxy_blocked)?;

            let surface = inspect_page_login_surface(cdp, &session_id, &mut guard)?;
            check_proxy_blocked(proxy_blocked)?;

            match state_machine.decide(&surface) {
                LoginStepDecision::Stop(failure) => {
                    return Err(WorkerStopReason::from(failure));
                }
                LoginStepDecision::Completed => {
                    break;
                }
                LoginStepDecision::SubmitCredentials {
                    username_selector,
                    password_selector,
                    code_selector,
                    submit_selector,
                } => {
                    guard
                        .verify_form_action(&surface.document_url, surface.form_action.as_deref())
                        .map_err(|v| WorkerStopReason::from(guard.record_violation(v)))?;

                    state_machine
                        .record_password_submission()
                        .map_err(WorkerStopReason::from)?;

                    if let Some(u_sel) = username_selector {
                        pipe.send(&DriverMessage::NeedUsername)?;
                        let username = match pipe.recv()? {
                            DaemonToDriver::Username(u) => u,
                            _ => return Err(WorkerStopReason::WorkerLost),
                        };
                        focus_and_insert_text(cdp, &session_id, &u_sel, username)?;
                        pump_guard_after_fill(cdp, &session_id, &mut guard, proxy_blocked)?;
                    }

                    pipe.send(&DriverMessage::NeedPassword)?;
                    let password = match pipe.recv()? {
                        DaemonToDriver::Password(p) => p,
                        _ => return Err(WorkerStopReason::WorkerLost),
                    };
                    focus_and_insert_text(cdp, &session_id, &password_selector, password)?;
                    pump_guard_after_fill(cdp, &session_id, &mut guard, proxy_blocked)?;

                    if let Some(c_sel) = code_selector {
                        let step = state_machine
                            .record_code_submission()
                            .map_err(WorkerStopReason::from)?;
                        pipe.send(&DriverMessage::NeedCode { step })?;
                        let code = match pipe.recv()? {
                            DaemonToDriver::Code(c) => c,
                            _ => return Err(WorkerStopReason::WorkerLost),
                        };
                        focus_and_insert_text(cdp, &session_id, &c_sel, code)?;
                        pump_guard_after_fill(cdp, &session_id, &mut guard, proxy_blocked)?;
                    }

                    // Re-verify form action immediately prior to submission (`D-26`).
                    let pre_submit = inspect_page_login_surface(cdp, &session_id, &mut guard)?;
                    guard
                        .verify_form_action(
                            &pre_submit.document_url,
                            pre_submit.form_action.as_deref(),
                        )
                        .map_err(|v| WorkerStopReason::from(guard.record_violation(v)))?;

                    submit_form_element(cdp, &session_id, &mut guard, &submit_selector)?;
                    wait_for_page_settle(cdp, &session_id, &mut guard, proxy_blocked, true)?;
                }
                LoginStepDecision::SubmitCode {
                    step: _,
                    code_selector,
                    submit_selector,
                } => {
                    guard
                        .verify_form_action(&surface.document_url, surface.form_action.as_deref())
                        .map_err(|v| WorkerStopReason::from(guard.record_violation(v)))?;

                    let step = state_machine
                        .record_code_submission()
                        .map_err(WorkerStopReason::from)?;
                    pipe.send(&DriverMessage::NeedCode { step })?;
                    let code = match pipe.recv()? {
                        DaemonToDriver::Code(c) => c,
                        _ => return Err(WorkerStopReason::WorkerLost),
                    };
                    focus_and_insert_text(cdp, &session_id, &code_selector, code)?;
                    pump_guard_after_fill(cdp, &session_id, &mut guard, proxy_blocked)?;

                    let pre_submit = inspect_page_login_surface(cdp, &session_id, &mut guard)?;
                    guard
                        .verify_form_action(
                            &pre_submit.document_url,
                            pre_submit.form_action.as_deref(),
                        )
                        .map_err(|v| WorkerStopReason::from(guard.record_violation(v)))?;

                    submit_form_element(cdp, &session_id, &mut guard, &submit_selector)?;
                    wait_for_page_settle(cdp, &session_id, &mut guard, proxy_blocked, true)?;
                }
            }
        }

        let final_surface = inspect_page_login_surface(cdp, &session_id, &mut guard)?;
        verify_worker_identity(
            cdp,
            &session_id,
            &mut guard,
            &final_surface.document_url,
            &spec.identity_check,
            &spec.expected_identity,
        )?;

        extract_from_cdp(cdp, &session_id, &spec.transfer, spec.session_format)
    }
}

fn check_proxy_blocked(proxy_blocked: Option<&Arc<AtomicU64>>) -> Result<(), WorkerStopReason> {
    if let Some(counter) = proxy_blocked
        && counter.load(Ordering::SeqCst) > 0
    {
        return Err(WorkerStopReason::OffOrigin);
    }
    Ok(())
}

fn wait_for_page_settle<R: Read, W: Write>(
    cdp: &mut CdpClient<R, W>,
    session_id: &str,
    guard: &mut OriginGuard,
    proxy_blocked: Option<&Arc<AtomicU64>>,
    after_submit: bool,
) -> Result<(), WorkerStopReason> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut ready_streak = 0u8;
    let mut last_href = String::new();
    while Instant::now() < deadline {
        guard.drain_events(cdp).map_err(WorkerStopReason::from)?;
        check_proxy_blocked(proxy_blocked)?;

        let eval = guard.call(
            cdp,
            Some(session_id),
            "Runtime.evaluate",
            json!({
                "expression": "(() => ({ href: location.href, ready: document.readyState, beforeSubmit: Boolean(window.__ec_before_submit), hasMarker: Boolean(document.querySelector('[data-auth-error], #auth-error, [data-code-error], #code-error, [data-handoff], #captcha-challenge, .g-recaptcha, [data-captcha]')) }))()",
                "returnByValue": true
            }),
        );
        check_proxy_blocked(proxy_blocked)?;
        let res = match eval {
            Ok(v) => v,
            Err(_) => {
                // If an origin violation was recorded while evaluating, stop immediately.
                if !guard.violations().is_empty() {
                    return Err(WorkerStopReason::OffOrigin);
                }
                std::thread::sleep(Duration::from_millis(25));
                continue;
            }
        };

        let val = res.get("result").and_then(|r| r.get("value"));
        let href = val
            .and_then(|v| v.get("href"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let ready = val
            .and_then(|v| v.get("ready"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let before_submit = val
            .and_then(|v| v.get("beforeSubmit"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let has_marker = val
            .and_then(|v| v.get("hasMarker"))
            .and_then(Value::as_bool)
            .unwrap_or(false);

        if href.starts_with("chrome-error://") {
            return Err(WorkerStopReason::OffOrigin);
        }
        if href.is_empty() || href == "about:blank" {
            std::thread::sleep(Duration::from_millis(25));
            continue;
        }
        last_href = href.to_owned();

        guard
            .check_url(href, GuardPhase::NavigationOrSubresource, false)
            .map_err(|v| WorkerStopReason::from(guard.record_violation(v)))?;

        if after_submit && before_submit && !has_marker {
            std::thread::sleep(Duration::from_millis(25));
            continue;
        }

        if ready == "complete" {
            ready_streak += 1;
            if ready_streak >= 2 {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    if last_href.is_empty() || last_href == "about:blank" {
        return Err(WorkerStopReason::OffOrigin);
    }
    Ok(())
}

fn inspect_page_login_surface<R: Read, W: Write>(
    cdp: &mut CdpClient<R, W>,
    session_id: &str,
    guard: &mut OriginGuard,
) -> Result<PageLoginSurface, WorkerStopReason> {
    guard.drain_events(cdp).map_err(WorkerStopReason::from)?;

    let script = r##"(() => {
        const href = location.href;
        const bodyText = document.body ? (document.body.innerText || "") : "";
        const form = document.querySelector("form");
        const formAction = form ? form.getAttribute("action") : null;
        const hasHandoff = Boolean(
            document.querySelector("[data-handoff], #captcha-challenge, .g-recaptcha, [data-captcha]")
        );
        const hasCodeRej = Boolean(
            document.querySelector("[data-code-error], #code-error") ||
            bodyText.includes("\"code_rejected\"") ||
            bodyText.includes("code_rejected")
        );
        const hasCredRej = Boolean(
            document.querySelector("[data-auth-error], #auth-error") ||
            bodyText.includes("\"credentials_rejected\"") ||
            bodyText.includes("credentials_rejected")
        );
        const iframes = Array.from(document.querySelectorAll("iframe[src]")).map(f => f.getAttribute("src") || "");
        const inputs = Array.from(document.querySelectorAll("input:not([type='hidden']):not([type='submit']):not([type='button'])")).map((el, idx) => {
            const id = el.getAttribute("id") || "";
            const name = el.getAttribute("name") || "";
            const type = (el.getAttribute("type") || "text").toLowerCase();
            const autocomplete = el.getAttribute("autocomplete") || "";
            let selector = "";
            if (id) {
                selector = "#" + CSS.escape(id);
            } else if (name) {
                selector = "input[name=" + JSON.stringify(name) + "]";
            } else {
                selector = "input:nth-of-type(" + (idx + 1) + ")";
            }
            return { selector, id, name, input_type: type, autocomplete };
        });
        const submitEl = document.querySelector("button[type='submit'], input[type='submit'], #submit, button");
        let submitSelector = null;
        if (submitEl) {
            const sid = submitEl.getAttribute("id");
            submitSelector = sid ? ("#" + CSS.escape(sid)) : "button[type='submit'], input[type='submit'], button";
        }
        return {
            document_url: href,
            form_action: formAction,
            has_handoff_marker: hasHandoff,
            has_rejection_marker: hasCredRej,
            has_code_rejection_marker: hasCodeRej,
            iframes,
            inputs,
            submit_selector: submitSelector
        };
    })()"##;

    let res = guard
        .call(
            cdp,
            Some(session_id),
            "Runtime.evaluate",
            json!({
                "expression": script,
                "returnByValue": true
            }),
        )
        .map_err(WorkerStopReason::from)?;

    let val = res
        .get("result")
        .and_then(|r| r.get("value"))
        .ok_or(WorkerStopReason::OffOrigin)?;

    let document_url = val
        .get("document_url")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    if document_url.is_empty() || document_url.starts_with("chrome-error://") {
        return Err(WorkerStopReason::OffOrigin);
    }

    guard
        .check_url(&document_url, GuardPhase::NavigationOrSubresource, false)
        .map_err(|v| WorkerStopReason::from(guard.record_violation(v)))?;

    let mut has_cross_origin_iframe = false;
    let mut cross_origin_iframe_src = None;
    if let Some(iframes) = val.get("iframes").and_then(Value::as_array) {
        for item in iframes {
            if let Some(src) = item.as_str()
                && !src.is_empty()
                && src != "about:blank"
                && guard
                    .check_url(src, GuardPhase::NavigationOrSubresource, false)
                    .is_err()
            {
                has_cross_origin_iframe = true;
                cross_origin_iframe_src = Some(src.to_owned());
                break;
            }
        }
    }

    let form_action = val
        .get("form_action")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if form_action.is_some() {
        guard
            .verify_form_action(&document_url, form_action.as_deref())
            .map_err(|v| WorkerStopReason::from(guard.record_violation(v)))?;
    }

    let mut inputs = Vec::new();
    if let Some(arr) = val.get("inputs").and_then(Value::as_array) {
        for item in arr {
            if let Ok(inp) = serde_json::from_value::<InspectedInput>(item.clone()) {
                inputs.push(inp);
            }
        }
    }

    Ok(PageLoginSurface {
        document_url,
        form_action,
        has_handoff_marker: val
            .get("has_handoff_marker")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        has_rejection_marker: val
            .get("has_rejection_marker")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        has_code_rejection_marker: val
            .get("has_code_rejection_marker")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        has_cross_origin_iframe,
        cross_origin_iframe_src,
        inputs,
        submit_selector: val
            .get("submit_selector")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

fn focus_and_insert_text<R: Read, W: Write>(
    cdp: &mut CdpClient<R, W>,
    session_id: &str,
    selector: &str,
    text: Zeroizing<String>,
) -> Result<(), WorkerStopReason> {
    let doc = cdp
        .call(Some(session_id), "DOM.getDocument", json!({ "depth": 1 }))
        .map_err(|_| WorkerStopReason::WorkerLost)?;
    let root_node_id = doc
        .get("root")
        .and_then(|r| r.get("nodeId"))
        .and_then(Value::as_i64)
        .ok_or(WorkerStopReason::WorkerLost)?;

    let q = cdp
        .call(
            Some(session_id),
            "DOM.querySelector",
            json!({
                "nodeId": root_node_id,
                "selector": selector
            }),
        )
        .map_err(|_| WorkerStopReason::WorkerLost)?;
    let node_id = q
        .get("nodeId")
        .and_then(Value::as_i64)
        .filter(|id| *id > 0)
        .ok_or(WorkerStopReason::WorkerLost)?;

    cdp.call(Some(session_id), "DOM.focus", json!({ "nodeId": node_id }))
        .map_err(|_| WorkerStopReason::WorkerLost)?;

    // Clear any existing text in the focused input without putting any secret in JS,
    // then insert via `Input.insertText` with wiping buffer.
    let sel_json = serde_json::to_string(selector).map_err(|_| WorkerStopReason::WorkerLost)?;
    let _ = cdp.call(
        Some(session_id),
        "Runtime.evaluate",
        json!({
            "expression": format!("(() => {{ const el = document.querySelector({sel_json}); if (el) el.value = ''; }})()")
        }),
    );

    cdp.insert_text_wiping(Some(session_id), text.as_bytes())
        .map_err(|_| WorkerStopReason::WorkerLost)?;
    Ok(())
}

fn pump_guard_after_fill<R: Read, W: Write>(
    cdp: &mut CdpClient<R, W>,
    session_id: &str,
    guard: &mut OriginGuard,
    proxy_blocked: Option<&Arc<AtomicU64>>,
) -> Result<(), WorkerStopReason> {
    // If the page registered an on-fill exfiltration hook (`window.__triggerExfil`),
    // fire it asynchronously without embedding any secret in the expression, then
    // pump CDP events and proxy counters so `OriginGuard` / `LoopbackOriginProxy`
    // intercepts and aborts any off-origin `fetch`, `Worker`, `ServiceWorker`,
    // `WebSocket`, or `sendBeacon` before form submission.
    let has_exfil_hook = guard
        .call(
            cdp,
            Some(session_id),
            "Runtime.evaluate",
            json!({
                "expression": "(() => { if (typeof window.__triggerExfil === 'function') { const el = document.querySelector('input[type=\"password\"]'); setTimeout(() => { try { window.__triggerExfil(el ? el.value : ''); } catch (_) {} }, 0); return true; } return false; })()",
                "returnByValue": true
            }),
        )
        .ok()
        .and_then(|v| v.get("result")?.get("value")?.as_bool())
        .unwrap_or(false);

    let rounds = if has_exfil_hook { 20 } else { 2 };
    for _ in 0..rounds {
        guard.drain_events(cdp).map_err(WorkerStopReason::from)?;
        check_proxy_blocked(proxy_blocked)?;
        if has_exfil_hook {
            std::thread::sleep(Duration::from_millis(25));
            // Perform a lightweight no-op round trip so `CdpClient` reads any queued
            // `Target.attachedToTarget`, `Fetch.requestPaused`, or WebSocket events.
            let _ = guard
                .call(
                    cdp,
                    Some(session_id),
                    "Runtime.evaluate",
                    json!({ "expression": "0", "returnByValue": true }),
                )
                .map_err(WorkerStopReason::from)?;
            check_proxy_blocked(proxy_blocked)?;
        }
    }
    Ok(())
}

fn submit_form_element<R: Read, W: Write>(
    cdp: &mut CdpClient<R, W>,
    session_id: &str,
    guard: &mut OriginGuard,
    submit_selector: &str,
) -> Result<(), WorkerStopReason> {
    let sel_json =
        serde_json::to_string(submit_selector).map_err(|_| WorkerStopReason::WorkerLost)?;
    let expr = format!(
        r#"(() => {{
            window.__ec_before_submit = true;
            const btn = document.querySelector({sel_json});
            if (btn && typeof btn.click === "function") {{
                btn.click();
                return true;
            }}
            const form = document.querySelector("form");
            if (form) {{
                if (typeof form.requestSubmit === "function") form.requestSubmit();
                else form.submit();
                return true;
            }}
            return false;
        }})()"#
    );
    let _ = guard
        .call(
            cdp,
            Some(session_id),
            "Runtime.evaluate",
            json!({ "expression": expr, "returnByValue": true }),
        )
        .map_err(WorkerStopReason::from)?;
    Ok(())
}
