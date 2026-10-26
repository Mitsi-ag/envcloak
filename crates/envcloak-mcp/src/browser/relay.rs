//! Host-facing browser tool relay for `envcloak mcp` (`M2b-08`, D-03, D-30).
//!
//! The host-facing `envcloak mcp` server never holds a secret value in its own
//! heap (`SecretAllocator` count remains `0`). Hosted browser tool calls
//! (`browser_*`) are checked against [`ToolAllowlist::admit`] and the active
//! session lease before being forwarded to the supervised browser helper.

use std::sync::{Arc, Mutex};

use envcloak_client::fail::Failure;
use serde_json::{Map, Value, json};

use crate::child::Call;
use crate::router::{Annotations, Backend, ToolResult, ToolSchema};
use crate::tools::Ctx;

use super::allowlist::{ALLOWED_BROWSER_TOOLS, TOOL_NOT_ALLOWED, ToolAllowlist};
use super::supervisor::{BrowserSupervisor, CONTEXT_NOT_PUBLISHED, GRANT_REVOKED};

/// Shared, thread-safe handle to an optional [`BrowserSupervisor`] backing the
/// 19 hosted browser tools in `envcloak mcp`.
#[derive(Clone, Default)]
pub struct BrowserRelay {
    inner: Arc<Mutex<Option<BrowserSupervisor>>>,
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
        }
    }

    /// Creates a relay backed by an active [`BrowserSupervisor`].
    #[must_use]
    pub fn with_supervisor(supervisor: BrowserSupervisor) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Some(supervisor))),
        }
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

    fn call(&self, name: &str, args: &Map<String, Value>, _ctx: &Ctx, _call: &Call) -> ToolResult {
        let args_val = Value::Object(args.clone());
        if let Err(why) = ToolAllowlist::admit(name, &args_val) {
            return ToolResult::Err(Failure::new(
                "invalid_params",
                format!("{TOOL_NOT_ALLOWED}: {why}"),
            ));
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
        if !sup.is_lease_active() {
            return ToolResult::Err(Failure::new(
                "policy_denied",
                format!("{GRANT_REVOKED}: the sign-in session grant was revoked"),
            ));
        }
        match sup.tools_call(name, args_val) {
            Ok(res) => {
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
            Err(err) => ToolResult::Err(Failure::new(
                "run_failed",
                format!("{}: {err}", err.as_str()),
            )),
        }
    }
}
