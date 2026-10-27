//! Host-facing browser tool relay for `envcloak mcp` (`M2b-08`, D-03, D-30).
//!
//! The host-facing `envcloak mcp` server never holds a secret value in its own
//! heap (`SecretAllocator` count remains `0`). Hosted browser tool calls
//! (`browser_*`) are checked against [`ToolAllowlist::admit`] and the active
//! session lease before being forwarded to the supervised browser helper.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Write};
use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex};

use envcloak_client::fail::Failure;
use serde_json::{Map, Value, json};

use crate::child::Call;
use crate::router::{Annotations, Backend, ToolResult, ToolSchema};
use crate::tools::Ctx;

use super::allowlist::{ALLOWED_BROWSER_TOOLS, TOOL_NOT_ALLOWED, ToolAllowlist};
use super::supervisor::{BrowserSupervisor, CONTEXT_NOT_PUBLISHED, GRANT_REVOKED};

struct RemoteSupervisorPipe {
    to_sup: Option<std::fs::File>,
    from_sup: BufReader<std::fs::File>,
    lease_active: bool,
}

/// Shared, thread-safe handle to an optional [`BrowserSupervisor`] backing the
/// 20 hosted browser tools in `envcloak mcp`.
#[derive(Clone, Default)]
pub struct BrowserRelay {
    inner: Arc<Mutex<Option<BrowserSupervisor>>>,
    remote: Arc<Mutex<Option<RemoteSupervisorPipe>>>,
    pending_pipes: Arc<Mutex<BTreeMap<String, (OwnedFd, OwnedFd)>>>,
    activated_requests: Arc<Mutex<BTreeSet<String>>>,
    active_request: Arc<Mutex<Option<String>>>,
}

impl std::fmt::Debug for BrowserRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrowserRelay").finish_non_exhaustive()
    }
}

impl BrowserRelay {
    /// Creates an empty relay with no attached supervisor (all `browser_*`
    /// tool calls return `sign_in_context_not_published` after passing the
    /// D-30 allowlist check).
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(None)),
            remote: Arc::new(Mutex::new(None)),
            pending_pipes: Arc::new(Mutex::new(BTreeMap::new())),
            activated_requests: Arc::new(Mutex::new(BTreeSet::new())),
            active_request: Arc::new(Mutex::new(None)),
        }
    }

    /// Creates a relay backed by an active [`BrowserSupervisor`].
    #[must_use]
    pub fn with_supervisor(supervisor: BrowserSupervisor) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Some(supervisor))),
            remote: Arc::new(Mutex::new(None)),
            pending_pipes: Arc::new(Mutex::new(BTreeMap::new())),
            activated_requests: Arc::new(Mutex::new(BTreeSet::new())),
            active_request: Arc::new(Mutex::new(None)),
        }
    }

    /// Registers the client pipe ends passed to `signin.request` for `request`,
    /// so [`Self::activate_from_request`] can read the `"published:..."` readiness
    /// line and forward allowed tool calls to the daemon-spawned
    /// `envcloak mcp --browser-supervisor` child without `envcloak mcp` ever
    /// receiving session state (`D-03`, `D-30`).
    pub fn register_request_pipes(&self, request: &str, pipe_in: OwnedFd, pipe_out: OwnedFd) {
        if self
            .activated_requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(request)
        {
            return;
        }
        self.pending_pipes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(request.to_owned())
            .or_insert((pipe_in, pipe_out));
    }

    /// Activates the recipient supervisor pipe for `request` when the sign-in
    /// operation reaches `published` or `ready`.
    pub fn activate_from_request(&self, request: &str) {
        if self
            .activated_requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(request)
        {
            if let Some(rem) = self
                .remote
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_mut()
            {
                rem.lease_active = true;
            }
            self.with_supervisor_mut(|sup| sup.set_lease_active(true));
            return;
        }
        let pipes_opt = self
            .pending_pipes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(request);
        if let Some((pipe_in, pipe_out)) = pipes_opt {
            let mut from_sup = BufReader::new(std::fs::File::from(pipe_out));
            let mut line = String::new();
            if from_sup.read_line(&mut line).is_ok() && line.trim_start().starts_with("published:")
            {
                *self
                    .remote
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    Some(RemoteSupervisorPipe {
                        to_sup: Some(std::fs::File::from(pipe_in)),
                        from_sup,
                        lease_active: true,
                    });
                *self
                    .active_request
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(request.to_owned());
                self.activated_requests
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(request.to_owned());
                return;
            }
        }
        self.with_supervisor_mut(|sup| sup.set_lease_active(true));
    }

    /// Revokes the active session lease and closes any attached remote pipe or
    /// local supervisor context.
    pub fn revoke_active(&self, fallback_gen: &str) {
        if let Some(rem) = self
            .remote
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
        {
            rem.lease_active = false;
            rem.to_sup = None;
        }
        self.with_supervisor_mut(|sup| {
            let gen_id = sup
                .bound_generation()
                .map(str::to_owned)
                .unwrap_or_else(|| fallback_gen.to_owned());
            let _ = crate::browser::end_session(sup, &gen_id, true, false);
        });
    }

    /// Replaces or attaches a [`BrowserSupervisor`] to this relay.
    pub fn attach(&self, supervisor: BrowserSupervisor) {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = Some(supervisor);
    }

    /// Runs a closure with exclusive access to the attached [`BrowserSupervisor`],
    /// if any.
    pub fn with_supervisor_mut<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&mut BrowserSupervisor) -> R,
    {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.as_mut().map(f)
    }

    fn call_remote(rem: &mut RemoteSupervisorPipe, name: &str, args: &Value) -> Value {
        if !rem.lease_active {
            return json!({
                "isError": true,
                "refusedBySupervisor": true,
                "reason": GRANT_REVOKED,
                "content": [{ "type": "text", "text": GRANT_REVOKED }]
            });
        }
        let Some(to_sup) = rem.to_sup.as_mut() else {
            rem.lease_active = false;
            return json!({
                "isError": true,
                "refusedBySupervisor": true,
                "reason": GRANT_REVOKED,
                "content": [{ "type": "text", "text": GRANT_REVOKED }]
            });
        };
        let req_line = match serde_json::to_string(&json!({
            "name": name,
            "arguments": args,
        })) {
            Ok(s) => s,
            Err(e) => {
                return json!({
                    "isError": true,
                    "reason": "browser_tool_failed",
                    "content": [{ "type": "text", "text": e.to_string() }]
                });
            }
        };
        if writeln!(to_sup, "{req_line}").is_err() || to_sup.flush().is_err() {
            rem.lease_active = false;
            rem.to_sup = None;
            return json!({
                "isError": true,
                "refusedBySupervisor": true,
                "reason": GRANT_REVOKED,
                "content": [{ "type": "text", "text": GRANT_REVOKED }]
            });
        }
        let mut reply_line = String::new();
        match rem.from_sup.read_line(&mut reply_line) {
            Ok(n) if n > 0 => {
                serde_json::from_str::<Value>(reply_line.trim()).unwrap_or_else(|e| {
                    json!({
                        "isError": true,
                        "reason": "browser_tool_failed",
                        "content": [{ "type": "text", "text": e.to_string() }]
                    })
                })
            }
            _ => {
                rem.lease_active = false;
                rem.to_sup = None;
                json!({
                    "isError": true,
                    "refusedBySupervisor": true,
                    "reason": GRANT_REVOKED,
                    "content": [{ "type": "text", "text": GRANT_REVOKED }]
                })
            }
        }
    }

    /// Invokes a browser tool by name and arguments, returning the raw JSON
    /// result payload (`isError`, `content`, `reason`, `refusedBySupervisor`).
    pub fn call_json(&self, name: &str, args: Value) -> Value {
        if let Err(code) = ToolAllowlist::admit(name, &args) {
            return json!({
                "isError": true,
                "refusedBySupervisor": true,
                "reason": code,
                "content": [{ "type": "text", "text": code }]
            });
        }
        if let Some(rem) = self
            .remote
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
        {
            return Self::call_remote(rem, name, &args);
        }
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(sup) = guard.as_mut() else {
            return json!({
                "isError": true,
                "refusedBySupervisor": true,
                "reason": CONTEXT_NOT_PUBLISHED,
                "content": [{ "type": "text", "text": CONTEXT_NOT_PUBLISHED }]
            });
        };
        match sup.tools_call(name, args) {
            Ok(val) => val,
            Err(err) => json!({
                "isError": true,
                "reason": err.as_str(),
                "content": [{ "type": "text", "text": err.to_string() }]
            }),
        }
    }
}

fn value_to_tool_result(res: Value) -> ToolResult {
    let is_err = res.get("isError").and_then(Value::as_bool).unwrap_or(false);
    let text = res
        .get("content")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|item| item.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();
    if is_err {
        let reason: &'static str = match res.get("reason").and_then(Value::as_str) {
            Some(GRANT_REVOKED) => GRANT_REVOKED,
            Some(TOOL_NOT_ALLOWED) => TOOL_NOT_ALLOWED,
            Some(CONTEXT_NOT_PUBLISHED) => CONTEXT_NOT_PUBLISHED,
            _ if text.contains(CONTEXT_NOT_PUBLISHED) => CONTEXT_NOT_PUBLISHED,
            _ => "browser_tool_failed",
        };
        ToolResult::Err(Failure::new("run_failed", format!("{reason}: {text}")))
    } else {
        ToolResult::Ok(res)
    }
}

impl Backend for BrowserRelay {
    fn tools(&self) -> Vec<ToolSchema> {
        let static_schemas = ToolAllowlist::static_schemas();
        ALLOWED_BROWSER_TOOLS
            .iter()
            .map(|&name| {
                let input = static_schemas
                    .iter()
                    .find(|s| s.get("name").and_then(Value::as_str) == Some(name))
                    .and_then(|s| s.get("inputSchema"))
                    .cloned()
                    .unwrap_or_else(|| {
                        json!({
                            "type": "object",
                            "properties": {},
                        })
                    });
                let read_only = matches!(
                    name,
                    "browser_console_messages"
                        | "browser_network_requests"
                        | "browser_snapshot"
                        | "browser_take_screenshot"
                );
                ToolSchema {
                    name,
                    title: name,
                    description: "Hosted Playwright browser tool",
                    input,
                    output: json!({ "type": "object" }),
                    annotations: Annotations {
                        read_only: Some(read_only),
                        destructive: Some(false),
                        idempotent: Some(read_only),
                        open_world: Some(true),
                    },
                }
            })
            .collect()
    }

    fn call(&self, name: &str, args: &Map<String, Value>, ctx: &Ctx, call: &Call) -> ToolResult {
        let args_val = Value::Object(args.clone());
        if let Err(why) = ToolAllowlist::admit(name, &args_val) {
            return ToolResult::Err(Failure::new(
                "invalid_params",
                format!("{TOOL_NOT_ALLOWED}: {why}"),
            ));
        }
        let active_req = self
            .active_request
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let daemon_revoked = if let Some(req_id) = active_req.as_deref() {
            match ctx
                .connect(call)
                .and_then(|mut c| Ok(c.signin_status(req_id)?))
            {
                Ok(view) => !matches!(view.state.as_str(), "published" | "ready"),
                Err(_) => true,
            }
        } else {
            false
        };
        if let Some(rem) = self
            .remote
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
        {
            if daemon_revoked {
                rem.lease_active = false;
                rem.to_sup = None;
            }
            if !rem.lease_active {
                return ToolResult::Err(Failure::new(
                    "policy_denied",
                    format!("{GRANT_REVOKED}: the sign-in session grant was revoked"),
                ));
            }
            let res = Self::call_remote(rem, name, &args_val);
            return value_to_tool_result(res);
        }
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(sup) = guard.as_mut() else {
            return ToolResult::Err(Failure::new(
                "policy_denied",
                format!("{CONTEXT_NOT_PUBLISHED}: no signed-in browser context is published"),
            ));
        };
        if daemon_revoked {
            sup.set_lease_active(false);
            if let Some(gen_id) = sup.bound_generation().map(str::to_owned) {
                let _ = sup.close(&gen_id);
            }
        }
        if !sup.is_lease_active() {
            return ToolResult::Err(Failure::new(
                "policy_denied",
                format!("{GRANT_REVOKED}: the sign-in session grant was revoked"),
            ));
        }
        match sup.tools_call(name, args_val) {
            Ok(res) => value_to_tool_result(res),
            Err(err) => ToolResult::Err(Failure::new(
                "run_failed",
                format!("{}: {err}", err.as_str()),
            )),
        }
    }
}
