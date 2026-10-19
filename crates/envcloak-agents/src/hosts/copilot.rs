//! What the installer writes for GitHub Copilot CLI (SPEC §7; Map C §2.5;
//! M2 plan task M2-24, D-14, D-16, D-22):
//!
//! - `~/.copilot/instructions/envcloak.instructions.md` (`$COPILOT_HOME`)
//!   with `applyTo: "**"` frontmatter and the managed instruction block;
//! - `~/.copilot/hooks/envcloak.json` with `preToolUse` and `sessionStart`
//!   hooks invoking `envcloak hook --host copilot`;
//! - `~/.copilot/mcp-config.json` with `mcpServers.envcloak` (`type =
//!   "local"`, `tools = ["*"]`).

use std::path::Path;

use serde_json::{Value, json};

use super::hook_command;
use crate::blocks;
use crate::hook::{Event, Host};

/// The MCP server's name.
pub const SERVER: &str = "envcloak";
/// Timeout (seconds) for Copilot CLI hooks.
pub const COPILOT_HOOK_TIMEOUT_SECS: u64 = 5;

/// YAML frontmatter for `~/.copilot/instructions/envcloak.instructions.md`.
pub const INSTRUCTIONS_FRONTMATTER: &str = "---\napplyTo: \"**\"\n---\n\n";

/// Complete `envcloak.instructions.md` content.
pub fn instructions_content() -> String {
    format!("{INSTRUCTIONS_FRONTMATTER}{}", blocks::block())
}

/// Complete `envcloak.json` hook file content for Copilot CLI.
pub fn hooks_file_json(envcloak: &Path) -> Value {
    json!({
        "version": 1,
        "hooks": {
            "preToolUse": [
                {
                    "type": "command",
                    "bash": hook_command(envcloak, Host::Copilot, Event::PreToolUseLower),
                    "timeoutSec": COPILOT_HOOK_TIMEOUT_SECS,
                }
            ],
            "sessionStart": [
                {
                    "type": "command",
                    "bash": hook_command(envcloak, Host::Copilot, Event::SessionStartLower),
                    "timeoutSec": COPILOT_HOOK_TIMEOUT_SECS,
                }
            ]
        }
    })
}

/// Formatted JSON string for `~/.copilot/hooks/envcloak.json`.
pub fn hooks_file_content(envcloak: &Path) -> String {
    let mut s = serde_json::to_string_pretty(&hooks_file_json(envcloak)).unwrap_or_default();
    s.push('\n');
    s
}

/// The MCP server entry in `~/.copilot/mcp-config.json`.
pub fn mcp_entry(envcloak: &Path) -> Value {
    json!({
        "type": "local",
        "command": envcloak.to_string_lossy(),
        "args": ["mcp", "--host", "copilot"],
        "tools": ["*"],
    })
}

/// Whether a Copilot hook JSON document holds EnvCloak's hooks.
pub fn envcloak_hooks(v: &Value) -> bool {
    v.get("hooks")
        .and_then(Value::as_object)
        .is_some_and(|events| {
            events
                .values()
                .filter_map(Value::as_array)
                .flatten()
                .filter_map(|h| {
                    h.get("bash")
                        .or_else(|| h.get("command"))
                        .and_then(Value::as_str)
                })
                .any(|cmd| cmd.contains(" hook --host copilot --event "))
        })
}
