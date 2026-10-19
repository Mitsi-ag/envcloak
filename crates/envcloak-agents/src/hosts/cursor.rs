//! What the installer writes for Cursor (SPEC §7 "Cursor"; Map C §2.3; M2
//! plan task M2-24, D-14, D-16, D-22):
//!
//! - in `~/.cursor/hooks.json`: `"version": 1` and hooks for
//!   `beforeSubmitPrompt`, `beforeShellExecution` (`failClosed: true`),
//!   `beforeReadFile` (`matcher: "Read"`, `failClosed: true`),
//!   `beforeMCPExecution` (`failClosed: true`), `preToolUse`
//!   (`matcher: "Read|Grep|Shell|MCP:.*"`) and `sessionStart`;
//! - in `~/.cursor/mcp.json`: `mcpServers.envcloak` with EnvCloak's
//!   absolute path and `args = ["mcp", "--host", "cursor"]`;
//! - in project scope (`--project` when `.cursor/` exists or `--agent
//!   cursor` is given): `.cursor/rules/envcloak.mdc` with `alwaysApply:
//!   true` frontmatter and the managed instruction block, alongside the
//!   shared `AGENTS.md` block.

use std::path::Path;

use serde_json::{Value, json};

use super::hook_command;
use crate::blocks;
use crate::hook::{Event, Host};

/// The MCP server's name.
pub const SERVER: &str = "envcloak";
/// Timeout (seconds) for Cursor hooks.
pub const CURSOR_HOOK_TIMEOUT_SECS: u64 = 5;
/// Matcher for `beforeReadFile`.
pub const READ_FILE_MATCHER: &str = "Read";
/// Matcher for `preToolUse`.
pub const PRE_TOOL_MATCHER: &str = "Read|Grep|Shell|MCP:.*";

/// YAML frontmatter for `.cursor/rules/envcloak.mdc`.
pub const MDC_FRONTMATTER: &str =
    "---\ndescription: EnvCloak secret protection rules\nalwaysApply: true\n---\n\n";

/// Complete `.cursor/rules/envcloak.mdc` content.
pub fn mdc_content() -> String {
    format!("{MDC_FRONTMATTER}{}", blocks::block())
}

/// The MCP server entry in `~/.cursor/mcp.json`.
pub fn mcp_entry(envcloak: &Path) -> Value {
    json!({
        "command": envcloak.to_string_lossy(),
        "args": ["mcp", "--host", "cursor"],
    })
}

/// The array elements the installer adds to `~/.cursor/hooks.json`.
pub fn hooks_additions(envcloak: &Path) -> Vec<(Vec<&'static str>, Value)> {
    vec![
        (
            vec!["hooks", "beforeSubmitPrompt"],
            json!({
                "command": hook_command(envcloak, Host::Cursor, Event::BeforeSubmitPrompt),
                "timeout": CURSOR_HOOK_TIMEOUT_SECS,
            }),
        ),
        (
            vec!["hooks", "beforeShellExecution"],
            json!({
                "command": hook_command(envcloak, Host::Cursor, Event::BeforeShellExecution),
                "timeout": CURSOR_HOOK_TIMEOUT_SECS,
                "failClosed": true,
            }),
        ),
        (
            vec!["hooks", "beforeReadFile"],
            json!({
                "command": hook_command(envcloak, Host::Cursor, Event::BeforeReadFile),
                "matcher": READ_FILE_MATCHER,
                "timeout": CURSOR_HOOK_TIMEOUT_SECS,
                "failClosed": true,
            }),
        ),
        (
            vec!["hooks", "beforeMCPExecution"],
            json!({
                "command": hook_command(envcloak, Host::Cursor, Event::BeforeMcpExecution),
                "timeout": CURSOR_HOOK_TIMEOUT_SECS,
                "failClosed": true,
            }),
        ),
        (
            vec!["hooks", "preToolUse"],
            json!({
                "command": hook_command(envcloak, Host::Cursor, Event::PreToolUseLower),
                "matcher": PRE_TOOL_MATCHER,
                "timeout": CURSOR_HOOK_TIMEOUT_SECS,
            }),
        ),
        (
            vec!["hooks", "sessionStart"],
            json!({
                "command": hook_command(envcloak, Host::Cursor, Event::SessionStartLower),
                "timeout": CURSOR_HOOK_TIMEOUT_SECS,
            }),
        ),
    ]
}

/// Whether `~/.cursor/hooks.json` holds EnvCloak's hooks.
pub fn envcloak_hooks(hooks_json: &Value) -> bool {
    hooks_json
        .get("hooks")
        .and_then(Value::as_object)
        .is_some_and(|events| {
            events
                .values()
                .filter_map(Value::as_array)
                .flatten()
                .filter_map(|h| h.get("command").and_then(Value::as_str))
                .any(|cmd| cmd.contains(" hook --host cursor --event "))
        })
}
