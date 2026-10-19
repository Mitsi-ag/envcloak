//! What the installer writes for OpenCode (SPEC §7; Map C §2.7; M2 plan
//! task M2-24, D-14, D-16, D-22):
//!
//! - detects OpenCode v1 vs v2 from the version and writes a small plugin
//!   at `~/.config/opencode/plugins/envcloak.js` that serves both v1
//!   (exported async function) and v2 (`{ id, server }` object) and invokes
//!   `envcloak hook --host opencode --event PreToolUse`;
//! - respects OpenCode's Claude fallback: when `~/.claude/CLAUDE.md` exists,
//!   `~/.config/opencode/AGENTS.md` does not exist, and neither
//!   `OPENCODE_DISABLE_CLAUDE_CODE` nor
//!   `OPENCODE_DISABLE_CLAUDE_CODE_PROMPT` is set, does not create
//!   `~/.config/opencode/AGENTS.md` (which would shadow `~/.claude/CLAUDE.md`)
//!   and emits an explanatory note;
//! - in `~/.config/opencode/opencode.json`: `mcp.envcloak` (`type =
//!   "local"`, `command = [envcloak, "mcp", "--host", "opencode"]`,
//!   `enabled = true`, `timeout = 60000`).

use std::ffi::OsString;
use std::path::Path;

use serde_json::{Value, json};

/// The MCP server's name.
pub const SERVER: &str = "envcloak";
/// Timeout (milliseconds) for OpenCode's MCP server entry.
pub const OPENCODE_MCP_TIMEOUT_MS: u64 = 60_000;
/// Header marker identifying an EnvCloak-managed OpenCode plugin file.
pub const PLUGIN_MARKER: &str = "// envcloak-managed: opencode-plugin-v1";

/// Detects whether `version` uses the v1 or v2 OpenCode plugin API.
pub fn plugin_api_generation(version: &str) -> &'static str {
    let major = version
        .trim()
        .strip_prefix('v')
        .unwrap_or(version.trim())
        .split('.')
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(1);
    if major >= 2 { "v2" } else { "v1" }
}

fn env_truthy(val: Option<OsString>) -> bool {
    val.and_then(|v| v.into_string().ok()).is_some_and(|s| {
        matches!(
            s.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

/// Whether OpenCode's fallback to Claude Code instructions is disabled by
/// environment variables (`OPENCODE_DISABLE_CLAUDE_CODE` or
/// `OPENCODE_DISABLE_CLAUDE_CODE_PROMPT`).
pub fn claude_fallback_disabled(env: &dyn Fn(&str) -> Option<OsString>) -> bool {
    env_truthy(env("OPENCODE_DISABLE_CLAUDE_CODE"))
        || env_truthy(env("OPENCODE_DISABLE_CLAUDE_CODE_PROMPT"))
}

/// Whether creating `~/.config/opencode/AGENTS.md` should be skipped so it
/// does not shadow an existing `~/.claude/CLAUDE.md`.
pub fn should_skip_global_agents_md(
    opencode_agents_md: &Path,
    claude_md: &Path,
    env: &dyn Fn(&str) -> Option<OsString>,
) -> bool {
    !opencode_agents_md.exists() && claude_md.exists() && !claude_fallback_disabled(env)
}

/// Generates `~/.config/opencode/plugins/envcloak.js`, serving both v1 and
/// v2 OpenCode plugin loaders and invoking `envcloak hook --host opencode
/// --event PreToolUse`.
pub fn plugin_content(envcloak: &Path, version: &str) -> String {
    let api_gen = plugin_api_generation(version);
    let bin_json = serde_json::to_string(&envcloak.to_string_lossy().as_ref())
        .unwrap_or_else(|_| "\"envcloak\"".to_owned());
    format!(
        r#"{PLUGIN_MARKER}
// Written by `envcloak agents install` (detected OpenCode plugin API: {api_gen}).
// Serves both OpenCode v1 (exported async function) and v2 (`{{ id, server }}`).
import {{ spawnSync }} from "node:child_process";

const ENVCLOAK_BIN = {bin_json};

const createHooks = async ({{ directory }} = {{}}) => ({{
  "tool.execute.before": async (input, output) => {{
    const payload = JSON.stringify({{
      hook_event_name: "PreToolUse",
      session_id: String((input && input.sessionID) || ""),
      cwd: String(directory || process.cwd()),
      tool_name: String((input && input.tool) || ""),
      tool_input: (output && output.args) || {{}},
    }});
    const proc = spawnSync(
      ENVCLOAK_BIN,
      ["hook", "--host", "opencode", "--event", "PreToolUse"],
      {{
        input: payload,
        encoding: "utf8",
        timeout: 5000,
      }},
    );
    if (proc.status === 2) {{
      let reason = (proc.stderr || "").trim();
      if (!reason && proc.stdout) {{
        try {{
          const parsed = JSON.parse(proc.stdout);
          reason = parsed.reason || "";
        }} catch {{
          reason = proc.stdout.trim();
        }}
      }}
      throw new Error(reason || "[envcloak] Blocked by EnvCloak policy");
    }}
  }},
}});

const EnvCloakPlugin = async (ctx) => createHooks(ctx);
EnvCloakPlugin.id = "envcloak";
EnvCloakPlugin.server = createHooks;

export {{ EnvCloakPlugin }};
export default EnvCloakPlugin;
"#
    )
}

/// The MCP server entry in `~/.config/opencode/opencode.json`.
pub fn mcp_entry(envcloak: &Path) -> Value {
    json!({
        "type": "local",
        "command": [envcloak.to_string_lossy(), "mcp", "--host", "opencode"],
        "enabled": true,
        "timeout": OPENCODE_MCP_TIMEOUT_MS,
    })
}

/// Whether a plugin file's text is EnvCloak's OpenCode plugin.
pub fn is_envcloak_plugin(text: &str) -> bool {
    text.contains("hook\", \"--host\", \"opencode\"") || text.contains("hook --host opencode")
}
