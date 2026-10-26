//! Sign-in tools (`SPEC.md` §6.8, §7, D-28, D-31, R-M2b-07, R-M2b-09, M2b-06,
//! M2b-10): `request_sign_in`, `sign_in_status`, `cancel_sign_in`, and
//! `end_sign_in_session`.
//!
//! Registered through [`SignInTools::register`]. In `Server::new()` and
//! `Server::with_browser_relay()` they are registered with `listed = true`, so
//! `tools/list` exposes all four tools and `tools/call` routes them.
//!
//! Every string argument is validated against a closed grammar before any
//! daemon connection is opened. Arguments shaped like a secret (`value_on_argv`)
//! or carrying a URL, script, callback, or DevTools address (`invalid_params`)
//! are refused without echoing any caller input. The caller's `operation_key`
//! is never echoed in any response or error, and every returned status view is
//! filtered through [`allowlist_status_view`] so no upstream error text or
//! credential fragment can cross into tool output.

use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use envcloak_client::fail::Failure;
use envcloak_ipc::proto::{FdRole, SigninRequestParams};
use envcloak_ipc::view::SigninStatusView;
use serde_json::{Map, Value, json};

use super::{
    Ctx, check_keys, invalid, manifest_of, object, opt_str, project_dir, refuse_value_like, req_str,
};
use crate::child::Call;
use crate::router::{Annotations, RegisterError, Router, Tool, ToolResult, ToolSchema};

/// Sign-in MCP tool registration (`request_sign_in`, `sign_in_status`,
/// `cancel_sign_in`, `end_sign_in_session`).
#[derive(Debug)]
pub struct SignInTools;

impl SignInTools {
    /// Registers the four sign-in tools on `router`. When `listed` is `true`,
    /// the tools appear in `tools/list` and are callable via `tools/call`.
    /// When `listed` is `false`, they are recorded in the router's unlisted
    /// table so duplicate names are still caught at construction while
    /// `tools/list` omits them and `tools/call` refuses them as unknown tools.
    pub fn register(router: &mut Router, listed: bool) -> Result<(), RegisterError> {
        let tools: [Box<dyn Tool>; 4] = [
            Box::new(request_sign_in::RequestSignIn),
            Box::new(sign_in_status::SignInStatus),
            Box::new(cancel_sign_in::CancelSignIn),
            Box::new(end_sign_in_session::EndSignInSession),
        ];
        for tool in tools {
            if listed {
                router.register(tool)?;
            } else {
                router.register_unlisted(tool)?;
            }
        }
        Ok(())
    }
}

/// Returns `true` if `s` contains any URL scheme, script fragment, callback
/// parameter, or Chrome DevTools address/flag (`R-M2b-07`, `L-06`).
pub fn is_forbidden_signin_arg(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    if s.bytes().any(|b| b.is_ascii_control()) {
        return true;
    }
    let lower = s.to_ascii_lowercase();
    for needle in [
        "://",
        "http:",
        "https:",
        "ws:",
        "wss:",
        "file:",
        "data:",
        "javascript:",
        "vbscript:",
        "about:",
        "chrome:",
        "chrome-extension:",
        "devtools:",
        "blob:",
        "mailto:",
        "<script",
        "</script",
        "onload=",
        "onerror=",
        "eval(",
        "function(",
        "settimeout(",
        "setinterval(",
        "document.cookie",
        "--remote-debugging",
        "/devtools/",
        "/json/version",
        "/json/list",
        "127.0.0.1:",
        "localhost:",
        "[::1]:",
        "0.0.0.0:",
        "callback=",
        "redirect_uri=",
        "return_to=",
    ] {
        if lower.contains(needle) {
            return true;
        }
    }
    s.chars().any(|c| {
        matches!(
            c,
            '<' | '>' | '"' | '\'' | '`' | ';' | '(' | ')' | '{' | '}' | '?' | '#' | '&' | '='
        )
    })
}

/// Validates a sign-in `target` name (`1..=128` ASCII bytes of `[a-z0-9._-/]`,
/// starting and ending with `[a-z0-9]`, without `//` or `..`) and rejects any
/// URL, script, callback, or CDP address.
pub fn validate_target(s: &str) -> Result<(), Failure> {
    if s.is_empty()
        || s.len() > 128
        || is_forbidden_signin_arg(s)
        || s.contains("//")
        || s.contains("..")
    {
        return Err(invalid());
    }
    let bytes = s.as_bytes();
    let is_lower_alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !is_lower_alnum(bytes[0]) || !is_lower_alnum(bytes[bytes.len() - 1]) {
        return Err(invalid());
    }
    if !bytes
        .iter()
        .all(|&b| is_lower_alnum(b) || matches!(b, b'.' | b'_' | b'-' | b'/'))
    {
        return Err(invalid());
    }
    Ok(())
}

/// Validates an optional sign-in `role` (`1..=64` bytes of `[A-Za-z0-9._-]`
/// starting with an ASCII alphanumeric character) and rejects any URL, script,
/// callback, or CDP address.
pub fn validate_role(s: &str) -> Result<(), Failure> {
    if s.is_empty() || s.len() > 64 || is_forbidden_signin_arg(s) {
        return Err(invalid());
    }
    let bytes = s.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() {
        return Err(invalid());
    }
    if !bytes
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(invalid());
    }
    Ok(())
}

/// Validates a caller-chosen `operation_key` (`1..=128` bytes of
/// `[A-Za-z0-9._-]`) and rejects any URL, script, callback, or CDP address.
/// Never echoes the input.
pub fn validate_operation_key(s: &str) -> Result<(), Failure> {
    if s.is_empty() || s.len() > 128 || is_forbidden_signin_arg(s) {
        return Err(invalid());
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(invalid());
    }
    Ok(())
}

/// Validates a 32-character lowercase hexadecimal `RequestId`.
pub fn validate_request_id(s: &str) -> Result<(), Failure> {
    if s.len() != 32 || is_forbidden_signin_arg(s) {
        return Err(invalid());
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid());
    }
    Ok(())
}

/// Validates a `session` argument for `end_sign_in_session`: either a
/// 32-character lowercase hexadecimal `RequestId` or a `ctx-<digits>` browser
/// context handle.
pub fn validate_session_id(s: &str) -> Result<(), Failure> {
    if is_forbidden_signin_arg(s) {
        return Err(invalid());
    }
    if let Some(rest) = s.strip_prefix("ctx-") {
        if rest.is_empty()
            || rest.len() > 20
            || !rest.bytes().all(|b| b.is_ascii_digit())
            || rest.parse::<u64>().map_or(true, |n| n == 0)
        {
            return Err(invalid());
        }
        return Ok(());
    }
    validate_request_id(s)
}

fn status_output_schema() -> Value {
    object(
        json!({
            "request": {"type": "string"},
            "revision": {"type": "integer"},
            "state": {"type": "string"},
            "retry_until_secs": {"type": "integer"},
            "delivered_context": {"type": ["string", "null"]},
            "cleanup": {"type": "string"},
            "revocation": {"type": "string"},
            "reason": {"type": ["string", "null"]},
            "shared_loopback_cookie_jar": {"type": "boolean"},
            "authorization": {"type": ["string", "null"]},
        }),
        &[
            "request",
            "revision",
            "state",
            "retry_until_secs",
            "delivered_context",
            "cleanup",
            "revocation",
            "reason",
            "shared_loopback_cookie_jar",
            "authorization",
        ],
    )
}

/// Closed allowlist of sign-in operation state tokens (`M2b-10`, R-M2b-40).
pub const ALLOWED_SIGNIN_STATES: &[&str] = &[
    "requested",
    "pending_approval",
    "awaiting_approval",
    "waiting_for_approval",
    "approved",
    "attempt_running",
    "captured",
    "publish_decided",
    "published",
    "ready",
    "ended",
    "cancelled",
    "failed",
];

/// Closed allowlist of local cleanup tokens (`M2b-10`, R-M2b-40).
pub const ALLOWED_SIGNIN_CLEANUP: &[&str] = &[
    "not_needed",
    "pending",
    "done",
    "confirmed",
    "cleaned",
    "cleanup_failed",
    "cleanup_unconfirmed",
];

/// Closed allowlist of server revocation tokens (`M2b-10`, R-M2b-40).
pub const ALLOWED_SIGNIN_REVOCATION: &[&str] = &[
    "unknown",
    "not_configured",
    "pending",
    "confirmed",
    "verified",
    "failed",
    "server session expiry unknown",
];

/// Closed allowlist of stop/failure reason tokens (`M2b-10`, R-M2b-40).
pub const ALLOWED_SIGNIN_REASONS: &[&str] = &[
    "waiting_for_approval",
    "cancelled",
    "cancelled_by_requester",
    "ended_by_owner",
    "ended_by_requester",
    "locked",
    "root_exited",
    "epoch_changed",
    "project_changed",
    "revision_changed",
    "limits_changed",
    "recipient_replaced",
    "subject_ineligible",
    "revoked",
    "statement_expired",
    "authorization_ended",
    "attempt_timed_out",
    "session_expired",
    "identity_unverified",
    "credentials_rejected",
    "code_rejected",
    "handoff_required",
    "off_origin",
    "unsupported_session_scope",
    "audit_failed",
    "worker_lost",
    "cleanup_failed",
    "cleanup_unconfirmed",
    "ended_by_reboot",
];

/// Sanitizes a [`SigninStatusView`] against closed token allowlists so no
/// upstream error text, password, TOTP seed/code, or `operation_key` can ever
/// appear in a tool result (`R-M2b-40`, gate `b3`).
#[must_use]
pub fn allowlist_status_view(v: &SigninStatusView) -> SigninStatusView {
    let request = if validate_request_id(&v.request).is_ok() {
        v.request.clone()
    } else {
        "00000000000000000000000000000000".to_owned()
    };
    let state = if ALLOWED_SIGNIN_STATES.contains(&v.state.as_str()) {
        v.state.clone()
    } else {
        "failed".to_owned()
    };
    let cleanup = if ALLOWED_SIGNIN_CLEANUP.contains(&v.cleanup.as_str()) {
        v.cleanup.clone()
    } else {
        "cleanup_unconfirmed".to_owned()
    };
    let revocation = if ALLOWED_SIGNIN_REVOCATION.contains(&v.revocation.as_str()) {
        v.revocation.clone()
    } else {
        "unknown".to_owned()
    };
    let reason = v.reason.as_ref().map(|r| {
        if ALLOWED_SIGNIN_REASONS.contains(&r.as_str()) {
            r.clone()
        } else {
            "worker_lost".to_owned()
        }
    });
    let delivered_context = v
        .delivered_context
        .as_ref()
        .filter(|c| c.starts_with("ctx-") && validate_session_id(c).is_ok())
        .cloned();
    let authorization = v
        .authorization
        .as_ref()
        .filter(|a| {
            validate_operation_key(a).is_ok() && !envcloak_client::render::looks_like_value(a)
        })
        .cloned();
    SigninStatusView {
        request,
        revision: v.revision,
        state,
        retry_until_secs: v.retry_until_secs,
        delivered_context,
        cleanup,
        revocation,
        reason,
        shared_loopback_cookie_jar: v.shared_loopback_cookie_jar,
        authorization,
    }
}

pub fn status_to_value(v: &SigninStatusView) -> Value {
    let clean = allowlist_status_view(v);
    json!({
        "request": clean.request,
        "revision": clean.revision,
        "state": clean.state,
        "retry_until_secs": clean.retry_until_secs,
        "delivered_context": clean.delivered_context,
        "cleanup": clean.cleanup,
        "revocation": clean.revocation,
        "reason": clean.reason,
        "shared_loopback_cookie_jar": clean.shared_loopback_cookie_jar,
        "authorization": clean.authorization,
    })
}

pub mod request_sign_in {
    use super::*;

    /// The tool's name.
    pub const TOOL: &str = "request_sign_in";

    #[derive(Debug)]
    pub struct RequestSignIn;

    impl Tool for RequestSignIn {
        fn schema(&self) -> ToolSchema {
            ToolSchema {
                name: TOOL,
                title: "Sign in to a development target",
                description: "Signs in to a registered development target with stored credentials \
                     after the person approves in EnvCloak, and delivers the resulting session to \
                     EnvCloak's hosted browser context. The resulting session acts as that \
                     account on the target's origins for the session's lifetime. Cancelling a \
                     tool call only stops waiting for an answer; call cancel_sign_in to end the \
                     operation itself. Takes the target name, optional role, and an idempotency \
                     operation_key (never echoed or logged), never a credential value, URL, \
                     script, callback, or DevTools address, and never returns a password, TOTP \
                     code, cookie, or storage token.",
                input: object(
                    json!({
                        "target": {
                            "type": "string",
                            "description": "Name of the registered sign-in target \
                                 (`1..=128` characters of `[a-z0-9._-/]` starting and ending \
                                 with `[a-z0-9]`, e.g. `acme/local`). Never a URL, script, \
                                 callback, or DevTools address.",
                        },
                        "role": {
                            "type": "string",
                            "description": "Optional role name on the target (`1..=64` characters \
                                 of `[A-Za-z0-9._-]`). Never a URL, script, callback, or DevTools \
                                 address.",
                        },
                        "operation_key": {
                            "type": "string",
                            "description": "Caller-chosen idempotency key (`1..=128` characters \
                                 of `[A-Za-z0-9._-]`). Never echoed or logged.",
                        },
                        "project_dir": {
                            "type": "string",
                            "description": "Optional absolute path of the project directory whose \
                                 envcloak.toml scopes the sign-in request.",
                        },
                    }),
                    &["target", "operation_key"],
                ),
                output: status_output_schema(),
                annotations: Annotations {
                    destructive: Some(true),
                    idempotent: Some(true),
                    open_world: Some(true),
                    ..Annotations::default()
                },
            }
        }

        fn call(&self, args: &Map<String, Value>, ctx: &Ctx, call: &Call) -> ToolResult {
            match execute(args, ctx, call) {
                Ok(v) => ToolResult::Ok(v),
                Err(f) => ToolResult::Err(f),
            }
        }
    }

    fn execute(args: &Map<String, Value>, ctx: &Ctx, call: &Call) -> Result<Value, Failure> {
        check_keys(
            args,
            &["target", "role", "operation_key", "project_dir"],
            &["target", "operation_key"],
        )?;
        let target = req_str(args, "target")?;
        let role = opt_str(args, "role")?;
        let operation_key = req_str(args, "operation_key")?;
        let given_dir = opt_str(args, "project_dir")?;

        if is_forbidden_signin_arg(target)
            || is_forbidden_signin_arg(operation_key)
            || role.is_some_and(is_forbidden_signin_arg)
            || given_dir.is_some_and(is_forbidden_signin_arg)
        {
            return Err(invalid());
        }

        let mut value_checks = vec![target, operation_key];
        if let Some(r) = role {
            value_checks.push(r);
        }
        if let Some(d) = given_dir {
            value_checks.push(d);
        }
        refuse_value_like(&value_checks)?;

        validate_target(target)?;
        if let Some(r) = role {
            validate_role(r)?;
        }
        validate_operation_key(operation_key)?;

        let dir = match given_dir {
            Some(d) => project_dir(d)?,
            None => std::env::current_dir().map_err(|_| {
                Failure::new(
                    "invalid_path",
                    "the working directory could not be read; pass project_dir",
                )
            })?,
        };
        let manifest = manifest_of(&dir)?.ok_or_else(|| {
            Failure::new(
                "no_manifest",
                "no envcloak.toml in that directory or any parent; run `envcloak init` there first",
            )
        })?;

        let wait = ctx.effective_wait();
        let deadline = call.deadline(wait);
        let poll_deadline = if wait > Duration::from_millis(250) {
            deadline
                .checked_sub(Duration::from_millis(120))
                .unwrap_or(deadline)
        } else {
            deadline
        };
        let mut client = ctx.connect_for_fds()?;
        let (in_client, in_daemon) = UnixStream::pair()
            .map_err(|_| Failure::new("internal", "an internal error occurred"))?;
        let (out_client, out_daemon) = UnixStream::pair()
            .map_err(|_| Failure::new("internal", "an internal error occurred"))?;
        let params = SigninRequestParams {
            manifest: manifest.to_string_lossy().into_owned(),
            target: target.to_owned(),
            role: role.map(str::to_owned),
            operation_key: operation_key.to_owned(),
            claims: envcloak_client::claims(),
            fds: vec![FdRole::Stdin, FdRole::Stdout],
        };
        let mut view = client
            .signin_request_with_fds(&params, &[in_daemon.as_fd(), out_daemon.as_fd()])
            .map_err(Failure::from)?;
        drop(client);
        drop(in_daemon);
        drop(out_daemon);
        if let Some(relay) = ctx.browser_relay() {
            relay.register_request_pipes(
                &view.request,
                OwnedFd::from(in_client),
                OwnedFd::from(out_client),
            );
        } else {
            drop(in_client);
            drop(out_client);
        }

        while matches!(
            view.state.as_str(),
            "requested"
                | "pending_approval"
                | "approved"
                | "attempt_running"
                | "captured"
                | "publish_decided"
        ) {
            if call.cancelled() {
                break;
            }
            let now = Instant::now();
            if now >= poll_deadline {
                break;
            }
            let sleep_dur =
                Duration::from_millis(25).min(poll_deadline.saturating_duration_since(now));
            std::thread::sleep(sleep_dur);
            if call.cancelled() || Instant::now() >= poll_deadline {
                break;
            }
            let Ok(mut poll_client) = ctx.connect_by(deadline) else {
                continue;
            };
            let Ok(next) = poll_client.signin_status(&view.request) else {
                continue;
            };
            view = next;
        }

        if !call.cancelled() && matches!(view.state.as_str(), "requested" | "pending_approval") {
            view.state = "waiting_for_approval".to_owned();
        }
        if matches!(view.state.as_str(), "published" | "ready")
            && let Some(relay) = ctx.browser_relay()
        {
            relay.activate_from_request(&view.request);
        }
        Ok(status_to_value(&view))
    }
}

pub mod sign_in_status {
    use super::*;

    /// The tool's name.
    pub const TOOL: &str = "sign_in_status";

    #[derive(Debug)]
    pub struct SignInStatus;

    impl Tool for SignInStatus {
        fn schema(&self) -> ToolSchema {
            ToolSchema {
                name: TOOL,
                title: "Check a sign-in operation's status",
                description: "Checks the status of a sign-in operation started with \
                     request_sign_in (which signs in with stored credentials after the person \
                     approves in EnvCloak, so the resulting session acts as that account). \
                     Cancelling a tool call only stops waiting for an answer; call cancel_sign_in \
                     to end the operation itself, or end_sign_in_session to close an active \
                     session. Never returns a credential value, cookie, or storage token.",
                input: object(
                    json!({
                        "request": {
                            "type": "string",
                            "description": "The 32-character lowercase hex request identifier \
                                 returned by request_sign_in.",
                        },
                    }),
                    &["request"],
                ),
                output: status_output_schema(),
                annotations: Annotations {
                    read_only: Some(true),
                    open_world: Some(false),
                    ..Annotations::default()
                },
            }
        }

        fn call(&self, args: &Map<String, Value>, ctx: &Ctx, call: &Call) -> ToolResult {
            match execute(args, ctx, call) {
                Ok(v) => ToolResult::Ok(v),
                Err(f) => ToolResult::Err(f),
            }
        }
    }

    fn execute(args: &Map<String, Value>, ctx: &Ctx, call: &Call) -> Result<Value, Failure> {
        check_keys(args, &["request"], &["request"])?;
        let request = req_str(args, "request")?;
        if is_forbidden_signin_arg(request) {
            return Err(invalid());
        }
        if validate_request_id(request).is_err() {
            refuse_value_like(&[request])?;
            return Err(invalid());
        }

        let deadline = call.deadline(ctx.wait);
        let mut client = ctx.connect_by(deadline)?;
        let view = client.signin_status(request).map_err(Failure::from)?;
        if matches!(view.state.as_str(), "published" | "ready")
            && let Some(relay) = ctx.browser_relay()
        {
            relay.activate_from_request(&view.request);
        }
        Ok(status_to_value(&view))
    }
}

pub mod cancel_sign_in {
    use super::*;

    /// The tool's name.
    pub const TOOL: &str = "cancel_sign_in";

    #[derive(Debug)]
    pub struct CancelSignIn;

    impl Tool for CancelSignIn {
        fn schema(&self) -> ToolSchema {
            ToolSchema {
                name: TOOL,
                title: "Cancel a sign-in operation",
                description: "Ends a sign-in operation started with request_sign_in (which signs \
                     in with stored credentials after the person approves in EnvCloak, producing \
                     a session that acts as that account). Cancelling a request_sign_in or \
                     sign_in_status tool call only stops waiting for an answer; cancel_sign_in \
                     ends the operation itself, stops any in-flight sign-in worker, and tears \
                     down any browser context it opened.",
                input: object(
                    json!({
                        "request": {
                            "type": "string",
                            "description": "The 32-character lowercase hex request identifier \
                                 returned by request_sign_in.",
                        },
                    }),
                    &["request"],
                ),
                output: status_output_schema(),
                annotations: Annotations {
                    read_only: Some(false),
                    destructive: Some(false),
                    idempotent: Some(true),
                    open_world: Some(false),
                },
            }
        }

        fn call(&self, args: &Map<String, Value>, ctx: &Ctx, call: &Call) -> ToolResult {
            match execute(args, ctx, call) {
                Ok(v) => ToolResult::Ok(v),
                Err(f) => ToolResult::Err(f),
            }
        }
    }

    fn execute(args: &Map<String, Value>, ctx: &Ctx, call: &Call) -> Result<Value, Failure> {
        check_keys(args, &["request"], &["request"])?;
        let request = req_str(args, "request")?;
        if is_forbidden_signin_arg(request) {
            return Err(invalid());
        }
        if validate_request_id(request).is_err() {
            refuse_value_like(&[request])?;
            return Err(invalid());
        }

        let deadline = call.deadline(ctx.effective_wait());
        let mut client = ctx.connect_by(deadline)?;
        let view = client.signin_cancel(request).map_err(Failure::from)?;
        if let Some(relay) = ctx.browser_relay() {
            let fallback_gen = view
                .delivered_context
                .clone()
                .unwrap_or_else(|| view.request.clone());
            relay.revoke_active(&fallback_gen);
        }
        Ok(status_to_value(&view))
    }
}

pub mod end_sign_in_session {
    use super::*;

    /// The tool's name.
    pub const TOOL: &str = "end_sign_in_session";

    #[derive(Debug)]
    pub struct EndSignInSession;

    impl Tool for EndSignInSession {
        fn schema(&self) -> ToolSchema {
            ToolSchema {
                name: TOOL,
                title: "End a delivered sign-in session",
                description: "Ends an active browser session delivered by request_sign_in (which \
                     signed in with stored credentials after the person approved in EnvCloak, so \
                     the session acts as that account). Cancelling a tool call only stops waiting \
                     while cancel_sign_in ends a pending or running operation; \
                     end_sign_in_session closes the delivered browser context, runs configured \
                     server-side revocation, and confirms local cleanup.",
                input: object(
                    json!({
                        "session": {
                            "type": "string",
                            "description": "The delivered session handle (`ctx-...`) or \
                                 32-character lowercase hex request identifier to end.",
                        },
                    }),
                    &["session"],
                ),
                output: status_output_schema(),
                annotations: Annotations {
                    read_only: Some(false),
                    destructive: Some(false),
                    idempotent: Some(true),
                    open_world: Some(false),
                },
            }
        }

        fn call(&self, args: &Map<String, Value>, ctx: &Ctx, call: &Call) -> ToolResult {
            match execute(args, ctx, call) {
                Ok(v) => ToolResult::Ok(v),
                Err(f) => ToolResult::Err(f),
            }
        }
    }

    fn execute(args: &Map<String, Value>, ctx: &Ctx, call: &Call) -> Result<Value, Failure> {
        check_keys(args, &["session"], &["session"])?;
        let session = req_str(args, "session")?;
        if is_forbidden_signin_arg(session) {
            return Err(invalid());
        }
        if validate_session_id(session).is_err() {
            refuse_value_like(&[session])?;
            return Err(invalid());
        }

        let deadline = call.deadline(ctx.effective_wait());
        let mut client = ctx.connect_by(deadline)?;
        let view = client.signin_end(session).map_err(Failure::from)?;
        if let Some(relay) = ctx.browser_relay() {
            let fallback_gen = view
                .delivered_context
                .clone()
                .unwrap_or_else(|| session.to_owned());
            relay.revoke_active(&fallback_gen);
        }
        Ok(status_to_value(&view))
    }
}
