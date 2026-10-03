//! Codex's hook contract (https://learn.chatgpt.com/docs/hooks), as the
//! pinned version sends it (crates/envcloak-e2e/tests/fixtures/
//! hook-payloads/codex-0.159.2/) and as measured (Codex's cycle177 and
//! cycle178 notes: the event-specific denial, the legacy block and exit 2
//! stop the action; `continue: false` and `ask` do not).
//!
//! - Every event carries `session_id`, `cwd`, `hook_event_name` and
//!   `model`; the turn events (`UserPromptSubmit`, `PreToolUse`) add
//!   `turn_id`, `UserPromptSubmit` `prompt`, and `PreToolUse` `tool_name`
//!   and `tool_input`. Its shell tool reaches hooks as `Bash`, with
//!   `tool_input.command`.
//! - A prompt is blocked with `decision: "block"` and a `reason`; a tool
//!   call is denied with `hookSpecificOutput.permissionDecision: "deny"`.
//! - `SessionStart` adds `hookSpecificOutput.additionalContext`.

use serde_json::{Map, Value, json};

use super::Event;

/// Whether `p` is Codex's payload for `event`.
pub fn fits(event: Event, p: &Map<String, Value>) -> bool {
    let s = |k: &str| p.get(k).is_some_and(Value::is_string);
    if p.get("hook_event_name").and_then(Value::as_str) != Some(event.name())
        || !s("session_id")
        || !s("cwd")
        || !s("model")
    {
        return false;
    }
    match event {
        Event::UserPromptSubmit => s("turn_id") && s("prompt"),
        Event::PreToolUse => {
            s("turn_id") && s("tool_name") && p.get("tool_input").is_some_and(Value::is_object)
        }
        Event::SessionStart => true,
    }
}

/// The denial of `event`, with `message`.
pub fn deny(event: Event, message: &str) -> Value {
    match event {
        Event::UserPromptSubmit => json!({
            "decision": "block",
            "reason": message,
        }),
        Event::PreToolUse | Event::SessionStart => json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": message,
            },
        }),
    }
}

/// `SessionStart`'s added context.
pub fn context(text: &str) -> Value {
    json!({
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": text,
        },
    })
}
