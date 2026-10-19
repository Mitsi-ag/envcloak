//! GitHub Copilot CLI's hook contract (`~/.copilot/hooks/envcloak.json`),
//! as specified in Map C §2.5 and M2 plan task M2-24:
//!
//! - Accepts both native camelCase (`toolName`, `toolArgs` as a JSON string
//!   or object) and Claude-compatible snake_case (`tool_name`, `tool_input`)
//!   for `preToolUse` / `PreToolUse`.
//! - Matches `bash`, `write_bash`, `powershell`, `write_powershell`, `view`,
//!   `edit`, `create`, `glob`, `grep` and MCP tools.
//! - Denies with top-level `{"permissionDecision": "deny",
//!   "permissionDecisionReason": message}` and exit 2.

use serde_json::{Map, Value, json};

use super::payload::{Wiped, parse_wiped_object};
use super::shell::Class;
use super::{Decision, Event, Reason, decide_argv, shell, strings_class};

/// Whether `p` is Copilot CLI's payload for `event`.
pub fn fits(event: Event, p: &Map<String, Value>) -> bool {
    let s = |k: &str| p.get(k).is_some_and(Value::is_string);
    if let Some(ev) = p.get("hook_event_name").and_then(Value::as_str)
        && ev != "preToolUse"
        && ev != "PreToolUse"
        && ev != "sessionStart"
        && ev != "SessionStart"
    {
        return false;
    }
    match event {
        Event::PreToolUseLower | Event::PreToolUse => {
            let camel = s("toolName")
                && p.get("toolArgs")
                    .is_some_and(|v| v.is_string() || v.is_object());
            let snake = s("tool_name")
                && p.get("tool_input")
                    .or_else(|| p.get("tool_args"))
                    .is_some_and(|v| v.is_object() || v.is_string());
            camel || snake
        }
        Event::SessionStartLower | Event::SessionStart => {
            s("cwd") || s("sessionId") || s("session_id") || p.contains_key("timestamp")
        }
        _ => false,
    }
}

/// Evaluates a Copilot CLI hook payload that [`fits`] accepted.
pub fn decide(event: Event, p: &Map<String, Value>) -> Decision {
    match event {
        Event::SessionStartLower | Event::SessionStart => Decision::Allow,
        Event::PreToolUseLower | Event::PreToolUse => {
            let Some(tool) = p
                .get("toolName")
                .or_else(|| p.get("tool_name"))
                .and_then(Value::as_str)
            else {
                return Decision::NoDecision;
            };
            let raw_args = p
                .get("toolArgs")
                .or_else(|| p.get("tool_input"))
                .or_else(|| p.get("tool_args"));
            match raw_args {
                Some(Value::Object(map)) => check_tool(tool, map),
                Some(Value::String(s)) => {
                    let Some(wiped): Option<Wiped> = parse_wiped_object(s) else {
                        return Decision::NoDecision;
                    };
                    check_tool(tool, &wiped)
                }
                _ => Decision::NoDecision,
            }
        }
        _ => Decision::NoDecision,
    }
}

fn check_tool(tool: &str, input: &Map<String, Value>) -> Decision {
    let deny_if = |c: Option<Class>| c.map_or(Decision::Allow, |c| Decision::Deny(Reason::of(c)));
    match tool {
        "bash" | "write_bash" | "powershell" | "write_powershell" | "Bash" | "shell" => {
            let cmd = input
                .get("command")
                .or_else(|| input.get("input"))
                .or_else(|| input.get("cmd"))
                .or_else(|| input.get("script"))
                .or_else(|| input.get("text"))
                .and_then(Value::as_str);
            match cmd {
                Some(c) => deny_if(shell::check_script(c).or_else(|| {
                    matches!(tool, "powershell" | "write_powershell")
                        .then(|| powershell_env_dump(c))
                        .flatten()
                })),
                None => Decision::NoDecision,
            }
        }
        "view" | "edit" | "create" | "Read" | "Write" | "Edit" => {
            let path = input
                .get("path")
                .or_else(|| input.get("file_path"))
                .or_else(|| input.get("file"))
                .and_then(Value::as_str);
            match path {
                Some(p) => deny_if(shell::path_class(p)),
                None => Decision::NoDecision,
            }
        }
        "glob" | "grep" | "Glob" | "Grep" => {
            let path = input
                .get("path")
                .or_else(|| input.get("file_path"))
                .or_else(|| input.get("file"))
                .and_then(Value::as_str);
            let pattern = input
                .get("pattern")
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
        "run_with_secrets"
        | "mcp__envcloak__run_with_secrets"
        | "envcloak-run_with_secrets"
        | "envcloak/run_with_secrets" => match input.get("argv") {
            Some(Value::Array(argv)) => {
                let words: Option<Vec<&str>> = argv.iter().map(Value::as_str).collect();
                words.map_or(Decision::Allow, |w| decide_argv(&w))
            }
            _ => Decision::Allow,
        },
        _ => deny_if(strings_class(input.values(), 0)),
    }
}

/// Top-level denial JSON for Copilot CLI.
pub fn deny(message: &str) -> Value {
    json!({
        "permissionDecision": "deny",
        "permissionDecisionReason": message,
    })
}

/// `sessionStart`'s added context.
pub fn context(text: &str) -> Value {
    json!({
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": text,
        },
    })
}

fn powershell_env_dump(script: &str) -> Option<Class> {
    let lower = script.to_ascii_lowercase();
    if lower
        .split(|c: char| c.is_whitespace() || matches!(c, ';' | '|' | '(' | ')' | '{' | '}'))
        .any(|tok| {
            let t = tok.trim_matches(|c: char| matches!(c, '\'' | '"'));
            t == "env:"
                || t.starts_with("env:/")
                || t.starts_with("env:\\")
                || t.starts_with("$env:")
        })
    {
        return Some(Class::EnvDump);
    }
    None
}
