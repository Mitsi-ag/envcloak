//! How a probe drives Claude Code (the pinned 2.1.280, as M2-04 measured
//! it, docs/AGENTS.md "Host behaviour"): `claude -p <prompt>` with
//! `ANTHROPIC_BASE_URL` at the scripted model and its token as
//! `ANTHROPIC_API_KEY`, the permission mode pinned to `default` (an
//! unpinned `-p` session can start in `auto`, D-13; never
//! `bypassPermissions`) and the tools a probe needs allowed by name, so a
//! denial can only be EnvCloak's. A fixture MCP server is added for one
//! run with `--mcp-config` and a sandbox for one run with `--settings`:
//! the person's files are never edited.

use std::ffi::OsString;
use std::path::Path;

use serde_json::{Value, json};

/// The fixture MCP server's name in a probe.
pub const MCP_SERVER: &str = "ecprobe";

/// The model's settings in the host's environment; the updater is kept off
/// (a probe never changes the host it measures).
pub fn model_env(base_url: &str, token: &str) -> Vec<(OsString, OsString)> {
    vec![
        ("ANTHROPIC_BASE_URL".into(), base_url.into()),
        ("ANTHROPIC_API_KEY".into(), token.into()),
        ("DISABLE_AUTOUPDATER".into(), "1".into()),
    ]
}

/// `--permission-mode default`, with `allowed` (when there are any) as
/// `--allowedTools`.
pub fn permissions(allowed: &[&str]) -> Vec<String> {
    let mut out = vec!["--permission-mode".to_owned(), "default".to_owned()];
    if !allowed.is_empty() {
        out.push("--allowedTools".to_owned());
        out.push(allowed.join(","));
    }
    out
}

/// The arguments of a run of `prompt`: `-p <prompt>`, the probe's own
/// flags, then the probe home's.
pub fn args(prompt: &str, probe: &[String], home: &[String]) -> Vec<OsString> {
    let mut out: Vec<OsString> = vec!["-p".into(), prompt.into()];
    out.extend(probe.iter().map(OsString::from));
    out.extend(home.iter().map(OsString::from));
    out
}

/// A step that reads `path` with Claude Code's own file tool.
pub fn read_step(path: &Path) -> Value {
    json!({"tool": "Read", "input": {"file_path": path.to_string_lossy()}})
}

/// A step that calls `tool` of MCP server `server`.
pub fn mcp_step(server: &str, tool: &str, input: Value) -> Value {
    json!({"tool": format!("mcp__{server}__{tool}"), "input": input})
}

/// The name `--allowedTools` takes for `tool` of `server`.
pub fn mcp_tool(server: &str, tool: &str) -> String {
    format!("mcp__{server}__{tool}")
}

/// The file `--mcp-config` reads: the fixture as a stdio server.
pub fn mcp_config(fixture: &Path) -> Value {
    json!({"mcpServers": {MCP_SERVER: {"command": fixture.to_string_lossy(), "args": []}}})
}

/// `--settings` for the sentinel probe: the Bash sandbox on, with no
/// escape for a command it refuses (M2 plan §4, the sandboxed variant).
pub fn sandbox_settings() -> String {
    json!({"sandbox": {"enabled": true, "allowUnsandboxedCommands": false}}).to_string()
}
