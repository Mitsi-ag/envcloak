//! Gemini CLI's hook contract (`~/.gemini/settings.json`), as specified in
//! Map C §2.4 and M2 plan task M2-24:
//!
//! - Events: `BeforeAgent`, `BeforeTool` and `SessionStart`.
//! - Both `BeforeAgent` and `BeforeTool` deny with `{"decision": "deny",
//!   "reason": message}` and exit 2.
//! - `SessionStart` adds `hookSpecificOutput.additionalContext`.

use serde_json::{Map, Value, json};

use super::shell::Class;
use super::{Decision, Event, Reason, decide_argv, prompt, shell, strings_class};

/// Whether `p` is Gemini CLI's payload for `event`.
pub fn fits(event: Event, p: &Map<String, Value>) -> bool {
    let s = |k: &str| p.get(k).is_some_and(Value::is_string);
    if let Some(ev) = p.get("hook_event_name").and_then(Value::as_str)
        && ev != event.name()
    {
        return false;
    }
    match event {
        Event::BeforeAgent | Event::UserPromptSubmit => s("prompt"),
        Event::BeforeTool | Event::PreToolUse => {
            s("tool_name") && p.get("tool_input").is_some_and(Value::is_object)
        }
        Event::SessionStart => s("session_id") || s("cwd") || s("hook_event_name"),
        _ => false,
    }
}

/// Evaluates a Gemini CLI hook payload that [`fits`] accepted.
pub fn decide(event: Event, p: &Map<String, Value>) -> Decision {
    match event {
        Event::SessionStart => Decision::Allow,
        Event::BeforeAgent | Event::UserPromptSubmit => {
            match p.get("prompt").and_then(Value::as_str) {
                Some(text) if prompt::holds_key(text) => Decision::Deny(Reason::KeyInPrompt),
                Some(_) => Decision::Allow,
                None => Decision::NoDecision,
            }
        }
        Event::BeforeTool | Event::PreToolUse => {
            let (Some(tool), Some(Value::Object(input))) = (
                p.get("tool_name").and_then(Value::as_str),
                p.get("tool_input"),
            ) else {
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
        "run_shell_command" | "Bash" | "shell" => {
            match input.get("command").and_then(Value::as_str) {
                Some(cmd) => deny_if(shell::check_script(cmd)),
                None => Decision::NoDecision,
            }
        }
        "read_file" | "write_file" | "replace" | "edit" | "Read" | "Write" | "Edit" => {
            match input
                .get("file_path")
                .or_else(|| input.get("path"))
                .and_then(Value::as_str)
            {
                Some(path) => deny_if(shell::path_class(path)),
                None => Decision::NoDecision,
            }
        }
        "read_many_files" => {
            let mut checked_any = false;
            for key in ["paths", "include"] {
                if let Some(Value::Array(arr)) = input.get(key) {
                    checked_any = true;
                    for item in arr {
                        if let Some(s) = item.as_str() {
                            if let Some(c) = shell::path_class(s) {
                                return Decision::Deny(Reason::of(c));
                            }
                            if shell::grep_tool_glob_may_name_env_file(s) {
                                return Decision::Deny(Reason::EnvFile);
                            }
                        }
                    }
                }
            }
            for key in ["file_path", "path"] {
                if let Some(s) = input.get(key).and_then(Value::as_str) {
                    checked_any = true;
                    if let Some(c) = shell::path_class(s) {
                        return Decision::Deny(Reason::of(c));
                    }
                }
            }
            if checked_any {
                Decision::Allow
            } else {
                Decision::NoDecision
            }
        }
        "grep_search" | "glob" | "Grep" | "Glob" => {
            let path = input
                .get("path")
                .or_else(|| input.get("dir_path"))
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
        "mcp_envcloak_run_with_secrets"
        | "mcp__envcloak__run_with_secrets"
        | "run_with_secrets" => match input.get("argv") {
            Some(Value::Array(argv)) => {
                let words: Option<Vec<&str>> = argv.iter().map(Value::as_str).collect();
                words.map_or(Decision::Allow, |w| decide_argv(&w))
            }
            _ => Decision::Allow,
        },
        _ => deny_if(strings_class(input.values(), 0)),
    }
}

/// The denial JSON for Gemini CLI.
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
