//! Cursor's hook contract (`~/.cursor/hooks.json`), as specified in Map C
//! §2.3 and M2 plan task M2-24:
//!
//! - Events: `beforeSubmitPrompt`, `beforeShellExecution`, `beforeReadFile`,
//!   `beforeMCPExecution`, `preToolUse` and `sessionStart`.
//! - `beforeSubmitPrompt` blocks a prompt containing a key with
//!   `{"continue": false, "user_message": message}` and exit 2.
//! - `beforeReadFile`, `beforeShellExecution`, `beforeMCPExecution` and
//!   `preToolUse` deny with flat `{"permission": "deny", "user_message":
//!   message, "agent_message": message}` and exit 2.
//! - `beforeReadFile` decides on `file_path` (or `path`) only and never
//!   parses, logs or echoes `content` (`payload.rs` wipes all strings in the
//!   parsed JSON object on drop).
//! - `sessionStart` returns `{"additional_context": text}`.

use serde_json::{Map, Value, json};

use super::payload::{Wiped, parse_wiped_object};
use super::shell::Class;
use super::{Decision, Event, Reason, decide_argv, prompt, shell, strings_class};

/// Whether `p` is Cursor's payload for `event`.
pub fn fits(event: Event, p: &Map<String, Value>) -> bool {
    let s = |k: &str| p.get(k).is_some_and(Value::is_string);
    if let Some(ev) = p.get("hook_event_name").and_then(Value::as_str)
        && ev != event.name()
    {
        return false;
    }
    match event {
        Event::BeforeSubmitPrompt => s("prompt"),
        Event::BeforeShellExecution => s("command"),
        Event::BeforeReadFile => s("file_path") || s("path"),
        Event::BeforeMcpExecution => {
            s("tool_name")
                && p.get("tool_input")
                    .is_some_and(|v| v.is_object() || v.is_string())
        }
        Event::PreToolUseLower => {
            s("tool_name")
                && p.get("tool_input")
                    .is_some_and(|v| v.is_object() || v.is_string())
        }
        Event::SessionStartLower => {
            s("session_id")
                || s("conversation_id")
                || s("cursor_version")
                || s("cwd")
                || p.contains_key("workspace_roots")
        }
        _ => false,
    }
}

/// Evaluates a Cursor hook payload that [`fits`] accepted.
pub fn decide(event: Event, p: &Map<String, Value>) -> Decision {
    match event {
        Event::SessionStartLower => Decision::Allow,
        Event::BeforeSubmitPrompt => match p.get("prompt").and_then(Value::as_str) {
            Some(text) if prompt::holds_key(text) => Decision::Deny(Reason::KeyInPrompt),
            Some(_) => Decision::Allow,
            None => Decision::NoDecision,
        },
        Event::BeforeShellExecution => match p.get("command").and_then(Value::as_str) {
            Some(cmd) => {
                shell::check_script(cmd).map_or(Decision::Allow, |c| Decision::Deny(Reason::of(c)))
            }
            None => Decision::NoDecision,
        },
        Event::BeforeReadFile => {
            // Decide on `file_path` (or `path`) only; never read, parse, log,
            // or echo `content` (M2-24).
            let Some(file_path) = p
                .get("file_path")
                .or_else(|| p.get("path"))
                .and_then(Value::as_str)
            else {
                return Decision::NoDecision;
            };
            shell::path_class(file_path).map_or(Decision::Allow, |c| Decision::Deny(Reason::of(c)))
        }
        Event::BeforeMcpExecution => {
            let Some(tool_name) = p.get("tool_name").and_then(Value::as_str) else {
                return Decision::NoDecision;
            };
            with_input(p.get("tool_input"), |input| {
                check_mcp_or_tool(tool_name, input, true)
            })
        }
        Event::PreToolUseLower => {
            let Some(tool_name) = p.get("tool_name").and_then(Value::as_str) else {
                return Decision::NoDecision;
            };
            with_input(p.get("tool_input"), |input| {
                check_mcp_or_tool(tool_name, input, false)
            })
        }
        _ => Decision::NoDecision,
    }
}

fn with_input(raw: Option<&Value>, f: impl FnOnce(&Map<String, Value>) -> Decision) -> Decision {
    match raw {
        Some(Value::Object(map)) => f(map),
        Some(Value::String(s)) => {
            let Some(wiped): Option<Wiped> = parse_wiped_object(s) else {
                return Decision::NoDecision;
            };
            f(&wiped)
        }
        _ => Decision::NoDecision,
    }
}

fn check_mcp_or_tool(tool: &str, input: &Map<String, Value>, force_mcp: bool) -> Decision {
    let deny_if = |c: Option<Class>| c.map_or(Decision::Allow, |c| Decision::Deny(Reason::of(c)));
    if tool == "run_with_secrets"
        || tool == "mcp__envcloak__run_with_secrets"
        || tool == "MCP:run_with_secrets"
        || tool == "envcloak:run_with_secrets"
    {
        return match input.get("argv") {
            Some(Value::Array(argv)) => {
                let words: Option<Vec<&str>> = argv.iter().map(Value::as_str).collect();
                words.map_or(Decision::Allow, |w| decide_argv(&w))
            }
            _ => Decision::Allow,
        };
    }
    if force_mcp {
        return deny_if(strings_class(input.values(), 0));
    }
    match tool {
        "Shell" | "Bash" => match input.get("command").and_then(Value::as_str) {
            Some(cmd) => deny_if(shell::check_script(cmd)),
            None => Decision::NoDecision,
        },
        "Read" | "Write" | "Edit" | "MultiEdit" | "Delete" => {
            match input
                .get("file_path")
                .or_else(|| input.get("path"))
                .or_else(|| input.get("target_file"))
                .and_then(Value::as_str)
            {
                Some(path) => deny_if(shell::path_class(path)),
                None => Decision::NoDecision,
            }
        }
        "Grep" | "Glob" => {
            let path = input
                .get("path")
                .or_else(|| input.get("file_path"))
                .and_then(Value::as_str);
            let glob = input
                .get("glob")
                .or_else(|| input.get("pattern"))
                .and_then(Value::as_str);
            let kind = input.get("type").and_then(Value::as_str);
            if path.is_none() && glob.is_none() && kind.is_none() {
                return Decision::NoDecision;
            }
            if let Some(c) = path.and_then(shell::path_class) {
                return Decision::Deny(Reason::of(c));
            }
            if let Some(c) = glob.and_then(shell::path_class) {
                return Decision::Deny(Reason::of(c));
            }
            if glob.is_some_and(shell::grep_tool_glob_may_name_env_file)
                || kind
                    .is_some_and(|t| shell::RG_ENV_TYPES.contains(&t.to_ascii_lowercase().as_str()))
            {
                return Decision::Deny(Reason::EnvFile);
            }
            Decision::Allow
        }
        _ => deny_if(strings_class(input.values(), 0)),
    }
}

/// The denial of `event`, with `message`.
pub fn deny(event: Event, message: &str) -> Value {
    match event {
        Event::BeforeSubmitPrompt => json!({
            "continue": false,
            "user_message": message,
        }),
        _ => json!({
            "permission": "deny",
            "user_message": message,
            "agent_message": message,
        }),
    }
}

/// `sessionStart`'s added context.
pub fn context(text: &str) -> Value {
    json!({
        "additional_context": text,
    })
}
