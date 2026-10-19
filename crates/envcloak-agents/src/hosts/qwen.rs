//! What the installer writes for Qwen Code (SPEC §7; Map C §2.8; M2 plan
//! task M2-24, D-14, D-16, D-22):
//!
//! - reads `context.fileName` from `~/.qwen/settings.json` before writing
//!   instructions: writes `~/.qwen/AGENTS.md` if configured, else
//!   `~/.qwen/QWEN.md`;
//! - in `~/.qwen/settings.json`: `UserPromptSubmit`, `PreToolUse` and
//!   `SessionStart` hooks, plus `mcpServers.envcloak` with `"timeout":
//!   60000` and never `"trust": true` (D-22).

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use super::hook_command;
use crate::hook::{Event, Host};

/// The MCP server's name.
pub const SERVER: &str = "envcloak";
/// Timeout (seconds) for Qwen Code hooks.
pub const QWEN_HOOK_TIMEOUT_SECS: u64 = 5;
/// Timeout (milliseconds) for Qwen Code's MCP server entry.
pub const QWEN_MCP_TIMEOUT_MS: u64 = 60_000;
/// Tool matcher for Qwen Code's `PreToolUse` hook.
pub const PRE_TOOL_MATCHER: &str = "run_shell_command|read_file|write_file|edit|replace|read_many_files|glob|grep_search|Bash|Read|Write|Edit|Glob|Grep|mcp__.*|mcp_.*";

fn is_safe_filename(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && !s.contains('/')
        && !s.contains('\\')
        && !s.contains('\0')
}

/// Extracts a configured `context.fileName` from a parsed `settings.json`,
/// if present and valid.
pub fn configured_context_filename(settings: &Value) -> Option<String> {
    let raw = settings.get("context")?.get("fileName")?;
    match raw {
        Value::String(s) if is_safe_filename(s) => Some(s.clone()),
        Value::Array(arr) => {
            let valid: Vec<&str> = arr
                .iter()
                .filter_map(Value::as_str)
                .filter(|s| is_safe_filename(s))
                .collect();
            if valid.contains(&"AGENTS.md") && !valid.contains(&"QWEN.md") {
                Some("AGENTS.md".to_owned())
            } else {
                valid.first().map(|s| (*s).to_owned())
            }
        }
        _ => None,
    }
}

fn read_settings(path: &Path) -> Option<Value> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Resolves the global instruction file path under `qwen_dir` (`~/.qwen`)
/// by reading `context.fileName` from `settings_path` (`~/.qwen/settings.json`).
pub fn resolve_global_instruction_path(qwen_dir: &Path, settings_path: &Path) -> PathBuf {
    if let Some(settings) = read_settings(settings_path)
        && let Some(name) = configured_context_filename(&settings)
    {
        return qwen_dir.join(name);
    }
    let agents_md = qwen_dir.join("AGENTS.md");
    let qwen_md = qwen_dir.join("QWEN.md");
    if agents_md.exists() && !qwen_md.exists() {
        agents_md
    } else {
        qwen_md
    }
}

fn handler(envcloak: &Path, event: Event) -> Value {
    json!({
        "type": "command",
        "command": hook_command(envcloak, Host::Qwen, event),
        "timeout": QWEN_HOOK_TIMEOUT_SECS,
    })
}

/// The array elements the installer adds to `~/.qwen/settings.json`.
pub fn hooks_additions(envcloak: &Path) -> Vec<(Vec<&'static str>, Value)> {
    vec![
        (
            vec!["hooks", "UserPromptSubmit"],
            json!({"hooks": [handler(envcloak, Event::UserPromptSubmit)]}),
        ),
        (
            vec!["hooks", "PreToolUse"],
            json!({
                "matcher": PRE_TOOL_MATCHER,
                "hooks": [handler(envcloak, Event::PreToolUse)],
            }),
        ),
        (
            vec!["hooks", "SessionStart"],
            json!({"hooks": [handler(envcloak, Event::SessionStart)]}),
        ),
    ]
}

/// The MCP server entry in `~/.qwen/settings.json` (never sets `"trust":
/// true`, D-22).
pub fn mcp_entry(envcloak: &Path) -> Value {
    json!({
        "command": envcloak.to_string_lossy(),
        "args": ["mcp", "--host", "qwen"],
        "timeout": QWEN_MCP_TIMEOUT_MS,
    })
}

/// Whether `~/.qwen/settings.json` holds EnvCloak's hooks.
pub fn envcloak_hooks(settings: &Value) -> bool {
    settings
        .get("hooks")
        .and_then(Value::as_object)
        .is_some_and(|events| {
            events
                .values()
                .filter_map(Value::as_array)
                .flatten()
                .any(|group| {
                    group
                        .get("hooks")
                        .and_then(Value::as_array)
                        .is_some_and(|hs| {
                            hs.iter()
                                .filter_map(|h| h.get("command").and_then(Value::as_str))
                                .any(|cmd| cmd.contains(" hook --host qwen --event "))
                        })
                })
        })
}
