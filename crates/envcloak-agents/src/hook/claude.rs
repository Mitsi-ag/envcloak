//! Claude Code's hook contract (https://code.claude.com/docs/en/hooks), as
//! the pinned version sends it (crates/envcloak-e2e/tests/fixtures/
//! hook-payloads/claude-code-2.1.280/): the payload a hook gets and the
//! JSON it answers with.
//!
//! - Every event carries `session_id`, `cwd` and `hook_event_name`, and
//!   never Codex's `turn_id`; `UserPromptSubmit` adds `prompt`,
//!   `PreToolUse` adds `tool_name` and `tool_input` (an object).
//! - A prompt is blocked with a top-level `decision: "block"` and a
//!   `reason`, and `hookSpecificOutput.suppressOriginalPrompt` keeps the
//!   prompt's text out of the block message (it can still reach the
//!   transcript and history: SPEC §7.1).
//! - A tool call is denied with `hookSpecificOutput.permissionDecision:
//!   "deny"` and its `permissionDecisionReason`, which Claude reads; with
//!   `"ask"`, Claude Code puts it to the person, the reason shown.
//! - `SessionStart` adds `hookSpecificOutput.additionalContext`.

use serde_json::{Map, Value, json};

use super::Event;

/// Whether `p` is Claude Code's payload for `event`.
pub fn fits(event: Event, p: &Map<String, Value>) -> bool {
    let s = |k: &str| p.get(k).is_some_and(Value::is_string);
    if p.get("hook_event_name").and_then(Value::as_str) != Some(event.name())
        || !s("session_id")
        || !s("cwd")
        || p.contains_key("turn_id")
    {
        return false;
    }
    match event {
        Event::UserPromptSubmit => s("prompt"),
        Event::PreToolUse => s("tool_name") && p.get("tool_input").is_some_and(Value::is_object),
        Event::SessionStart => true,
    }
}

/// The denial of `event`, with `message`.
pub fn deny(event: Event, message: &str) -> Value {
    match event {
        Event::UserPromptSubmit => json!({
            "decision": "block",
            "reason": message,
            "hookSpecificOutput": {
                "hookEventName": "UserPromptSubmit",
                "suppressOriginalPrompt": true,
            },
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

/// A tool call put to the person, with `message`: Claude Code shows its
/// permission prompt, the reason on it, and runs the call only once they
/// allow it.
pub fn ask(message: &str) -> Value {
    json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": message,
        },
    })
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
