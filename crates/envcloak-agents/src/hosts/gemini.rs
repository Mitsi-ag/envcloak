//! What the installer writes for Gemini CLI (SPEC §7; Map C §2.4; M2 plan
//! task M2-24, D-14, D-16, D-22):
//!
//! - reads the effective `context.fileName` from `~/.gemini/settings.json`
//!   (and `<project>/.gemini/settings.json` in project scope) before
//!   writing instructions: when `context.fileName` names `AGENTS.md` (or
//!   another custom file), writes the managed block there and never creates
//!   `GEMINI.md` alongside it; rechecked at write time (D-16);
//! - in `~/.gemini/settings.json`: `BeforeAgent`, `BeforeTool` and
//!   `SessionStart` hooks, plus `mcpServers.envcloak` with `"timeout":
//!   60000` and never `"trust": true` (D-22).

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use super::hook_command;
use crate::hook::{Event, Host};

/// The MCP server's name.
pub const SERVER: &str = "envcloak";
/// Timeout (milliseconds) for Gemini CLI hooks.
pub const GEMINI_HOOK_TIMEOUT_MS: u64 = 5_000;
/// Timeout (milliseconds) for Gemini CLI's MCP server entry.
pub const GEMINI_MCP_TIMEOUT_MS: u64 = 60_000;
/// Tool matcher for Gemini CLI's `BeforeTool` hook.
pub const BEFORE_TOOL_MATCHER: &str =
    "run_shell_command|read_file|read_many_files|write_file|replace|grep_search|glob|mcp_.*";

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
            if valid.contains(&"AGENTS.md") && !valid.contains(&"GEMINI.md") {
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

/// Resolves the global instruction file path under `gemini_dir` (`~/.gemini`)
/// by reading `context.fileName` from `settings_path` (`~/.gemini/settings.json`).
pub fn resolve_global_instruction_path(gemini_dir: &Path, settings_path: &Path) -> PathBuf {
    if let Some(settings) = read_settings(settings_path)
        && let Some(name) = configured_context_filename(&settings)
    {
        return gemini_dir.join(name);
    }
    let agents_md = gemini_dir.join("AGENTS.md");
    let gemini_md = gemini_dir.join("GEMINI.md");
    if agents_md.exists() && !gemini_md.exists() {
        agents_md
    } else {
        gemini_md
    }
}

/// Resolves the project instruction file path under `project_dir` by reading
/// `<project_dir>/.gemini/settings.json` and `global_settings_path`.
pub fn resolve_project_instruction_path(
    project_dir: &Path,
    global_settings_path: &Path,
) -> PathBuf {
    let project_settings = project_dir.join(".gemini").join("settings.json");
    if let Some(settings) = read_settings(&project_settings)
        && let Some(name) = configured_context_filename(&settings)
    {
        return project_dir.join(name);
    }
    if let Some(settings) = read_settings(global_settings_path)
        && let Some(name) = configured_context_filename(&settings)
    {
        return project_dir.join(name);
    }
    let gemini_md = project_dir.join("GEMINI.md");
    let agents_md = project_dir.join("AGENTS.md");
    if gemini_md.exists() && !agents_md.exists() {
        gemini_md
    } else {
        agents_md
    }
}

fn handler(envcloak: &Path, event: Event) -> Value {
    json!({
        "name": format!("envcloak-{}", event.name()),
        "type": "command",
        "command": hook_command(envcloak, Host::Gemini, event),
        "timeout": GEMINI_HOOK_TIMEOUT_MS,
    })
}

/// The array elements the installer adds to `~/.gemini/settings.json`.
pub fn hooks_additions(envcloak: &Path) -> Vec<(Vec<&'static str>, Value)> {
    vec![
        (
            vec!["hooks", "BeforeAgent"],
            json!({"hooks": [handler(envcloak, Event::BeforeAgent)]}),
        ),
        (
            vec!["hooks", "BeforeTool"],
            json!({
                "matcher": BEFORE_TOOL_MATCHER,
                "hooks": [handler(envcloak, Event::BeforeTool)],
            }),
        ),
        (
            vec!["hooks", "SessionStart"],
            json!({"hooks": [handler(envcloak, Event::SessionStart)]}),
        ),
    ]
}

/// The MCP server entry in `~/.gemini/settings.json` (never sets
/// `"trust": true`, D-22).
pub fn mcp_entry(envcloak: &Path) -> Value {
    json!({
        "command": envcloak.to_string_lossy(),
        "args": ["mcp", "--host", "gemini"],
        "timeout": GEMINI_MCP_TIMEOUT_MS,
    })
}

/// Whether `~/.gemini/settings.json` holds EnvCloak's hooks.
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
                                .any(|cmd| cmd.contains(" hook --host gemini --event "))
                        })
                })
        })
}
