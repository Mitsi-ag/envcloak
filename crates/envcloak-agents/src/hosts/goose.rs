//! What the installer writes for Goose (SPEC §7; Map C §2.9; M2 plan task
//! M2-24, D-16):
//!
//! - the instruction block in `~/.config/goose/.goosehints`
//!   (`$XDG_CONFIG_HOME/goose/.goosehints`);
//! - Open Plugins hook at `~/.agents/plugins/envcloak/hooks/hooks.json`
//!   for `PreToolUse`;
//! - a manual YAML note for `~/.config/goose/config.yaml` (YAML files are
//!   never auto-rewritten in M2, D-16).

use std::path::Path;

use serde_json::{Value, json};

use super::hook_command;
use crate::hook::{Event, Host};

/// Timeout (seconds) for Goose Open Plugins hooks.
pub const GOOSE_HOOK_TIMEOUT_SECS: u64 = 5;

/// Complete `~/.agents/plugins/envcloak/hooks/hooks.json` JSON object.
pub fn plugin_hooks_json(envcloak: &Path) -> Value {
    json!({
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": ".*",
                    "hooks": [
                        {
                            "type": "command",
                            "command": hook_command(envcloak, Host::Goose, Event::PreToolUse),
                            "timeout": GOOSE_HOOK_TIMEOUT_SECS,
                        }
                    ]
                }
            ]
        }
    })
}

/// Formatted JSON string for `~/.agents/plugins/envcloak/hooks/hooks.json`.
pub fn plugin_hooks_content(envcloak: &Path) -> String {
    let mut s = serde_json::to_string_pretty(&plugin_hooks_json(envcloak)).unwrap_or_default();
    s.push('\n');
    s
}

/// Manual YAML snippet note for `~/.config/goose/config.yaml`.
pub fn manual_yaml_note(envcloak: &Path) -> String {
    format!(
        "Goose stores MCP extensions in ~/.config/goose/config.yaml (YAML, which EnvCloak does \
         not rewrite automatically). Add under `extensions:`:\n  envcloak:\n    # EnvCloak MCP \
         server\n    name: envcloak\n    type: stdio\n    enabled: true\n    cmd: {}\n    args: \
         [\"mcp\", \"--host\", \"goose\"]\n    timeout: 60",
        envcloak.display()
    )
}
