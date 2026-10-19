//! OpenCode's hook contract (`~/.config/opencode/plugins/envcloak.js` ->
//! `envcloak hook --host opencode --event PreToolUse`), as specified in Map C
//! §2.7 and M2 plan task M2-24:
//!
//! - Accepts the payload constructed by EnvCloak's OpenCode plugin
//!   (`tool_name`, `tool_input`) as well as OpenCode's native
//!   (`tool`, `args`) shape.
//! - Matches `bash`, `read`, `write`, `edit`, `patch`, `multiedit`, `glob`,
//!   `grep`, `list` and MCP tools.
//! - Exits 2 with the denial reason on stderr and structured JSON on stdout,
//!   which the plugin throws to abort tool execution in OpenCode v1 and v2.

use serde_json::{Map, Value, json};

use super::shell::Class;
use super::{Decision, Event, Reason, decide_argv, shell, strings_class};

/// Whether `p` is OpenCode's payload for `event`.
pub fn fits(event: Event, p: &Map<String, Value>) -> bool {
    let s = |k: &str| p.get(k).is_some_and(Value::is_string);
    if let Some(ev) = p.get("hook_event_name").and_then(Value::as_str)
        && ev != "PreToolUse"
        && ev != "preToolUse"
        && ev != "SessionStart"
        && ev != "sessionStart"
    {
        return false;
    }
    match event {
        Event::PreToolUse | Event::PreToolUseLower => {
            (s("tool_name") && p.get("tool_input").is_some_and(Value::is_object))
                || (s("tool") && p.get("args").is_some_and(Value::is_object))
        }
        Event::SessionStart | Event::SessionStartLower => {
            s("session_id") || s("sessionID") || s("cwd") || s("hook_event_name")
        }
        _ => false,
    }
}

/// Evaluates an OpenCode hook payload that [`fits`] accepted.
pub fn decide(event: Event, p: &Map<String, Value>) -> Decision {
    match event {
        Event::SessionStart | Event::SessionStartLower => Decision::Allow,
        Event::PreToolUse | Event::PreToolUseLower => {
            let Some(tool) = p
                .get("tool_name")
                .or_else(|| p.get("tool"))
                .and_then(Value::as_str)
            else {
                return Decision::NoDecision;
            };
            let Some(Value::Object(input)) = p.get("tool_input").or_else(|| p.get("args")) else {
                return Decision::NoDecision;
            };
            check_tool(tool, input)
        }
        _ => Decision::NoDecision,
    }
}

fn check_tool(tool: &str, input: &Map<String, Value>) -> Decision {
    let deny_if = |c: Option<Class>| c.map_or(Decision::Allow, |c| Decision::Deny(Reason::of(c)));
    match tool {
        "bash" | "Bash" | "shell" | "Shell" => match input.get("command").and_then(Value::as_str) {
            Some(cmd) => deny_if(shell::check_script(cmd)),
            None => Decision::NoDecision,
        },
        "read" | "write" | "edit" | "patch" | "multiedit" | "Read" | "Write" | "Edit"
        | "MultiEdit" => {
            match input
                .get("filePath")
                .or_else(|| input.get("file_path"))
                .or_else(|| input.get("path"))
                .and_then(Value::as_str)
            {
                Some(path) => deny_if(shell::path_class(path)),
                None => Decision::NoDecision,
            }
        }
        "glob" | "grep" | "list" | "Glob" | "Grep" => {
            let path = input
                .get("path")
                .or_else(|| input.get("filePath"))
                .or_else(|| input.get("file_path"))
                .and_then(Value::as_str);
            let pattern = input
                .get("pattern")
                .or_else(|| input.get("include"))
                .or_else(|| input.get("glob"))
                .and_then(Value::as_str);
            let kind = input.get("type").and_then(Value::as_str);
            if path.is_none() && pattern.is_none() && kind.is_none() {
                return Decision::NoDecision;
            }
            if let Some(c) = path.and_then(shell::path_class) {
                return Decision::Deny(Reason::of(c));
            }
            if let Some(c) = pattern.and_then(shell::path_class) {
                return Decision::Deny(Reason::of(c));
            }
            if pattern.is_some_and(shell::grep_tool_glob_may_name_env_file)
                || kind
                    .is_some_and(|t| shell::RG_ENV_TYPES.contains(&t.to_ascii_lowercase().as_str()))
            {
                return Decision::Deny(Reason::EnvFile);
            }
            Decision::Allow
        }
        "envcloak_run_with_secrets" | "mcp__envcloak__run_with_secrets" | "run_with_secrets" => {
            match input.get("argv") {
                Some(Value::Array(argv)) => {
                    let words: Option<Vec<&str>> = argv.iter().map(Value::as_str).collect();
                    words.map_or(Decision::Allow, |w| decide_argv(&w))
                }
                _ => Decision::Allow,
            }
        }
        _ => deny_if(strings_class(input.values(), 0)),
    }
}

/// The denial JSON for OpenCode.
pub fn deny(message: &str) -> Value {
    json!({
        "decision": "deny",
        "reason": message,
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
