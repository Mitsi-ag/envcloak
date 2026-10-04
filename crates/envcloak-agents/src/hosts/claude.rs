//! What the installer writes for Claude Code (SPEC §7 "Claude Code"; M2
//! plan M2-08, D-16, D-22):
//!
//! - the instruction block in `~/.claude/CLAUDE.md`;
//! - in `~/.claude/settings.json` (which Claude Code may rewrite itself,
//!   so D-16's rule applies): the hooks (`UserPromptSubmit`; `PreToolUse`
//!   for the tools in [`TOOL_MATCHER`] and every MCP tool, `mcp__.*`;
//!   `SessionStart`),
//!   unless EnvCloak's plugin, which carries them, is enabled; the deny
//!   rule `Read(**/.env*)`, which
//!   Claude Code also applies, best effort, to `@` file mentions that no
//!   hook sees, `sandbox.credentials` deny entries for the vault and the
//!   backups, and on macOS the socket's resolved path in
//!   `sandbox.network.allowUnixSockets` (M2-04 measured that the sandbox
//!   compares the resolved path). On Linux no socket allowance is written,
//!   with or without consent: K-01's measurement found no setting that
//!   lets the pinned sandbox reach and verify the daemon, so the sandboxed
//!   shell is `unsupported` there. `excludedCommands` is never written;
//! - EnvCloak's MCP server, registered with Claude Code's own command,
//!   `claude mcp add-json --scope user envcloak '{...}'` with its per-server
//!   `timeout`, and checked with `claude mcp get` (D-16: `~/.claude.json`,
//!   which Claude Code rewrites on every start, is never edited);
//! - no approval setting for any EnvCloak tool (D-22).

use std::ffi::OsString;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use serde_json::{Value, json};

use super::{HOOK_TIMEOUT_SECS, hook_command};
use crate::hook::{Event, Host};
use crate::tool_timeouts;
use crate::writer::Refusal;

/// The MCP server's name.
pub const SERVER: &str = "envcloak";
/// The deny rule for env files.
pub const READ_DENY: &str = "Read(**/.env*)";
/// The `PreToolUse` matcher for Claude Code's own tools: an exact list,
/// every tool of the pinned version (2.1.280's `sdk-tools.d.ts`, and
/// `ClaudeDesign`, whose `arguments` its server checks) that runs a
/// command (`Bash`; `Monitor`, whose `command` is a shell script), reads a
/// file or a resource (`Read`, `Edit`, `NotebookEdit`, `Grep`, `Glob`,
/// `ReadMcpResourceTool`, `ReadMcpResourceDirTool`), or reads a local file
/// to send it on (`Artifact`'s `file_path` and `file_paths`, `Projects`'
/// `local_path`, `Workflow`'s `scriptPath`). `Write` reads nothing;
/// `WebFetch` fetches a URL. The m2_story test reads the pinned
/// `sdk-tools.d.ts` and fails on a tool with a path, a URI or a command
/// that is in neither list.
pub const TOOL_MATCHER: &str = "Bash|Monitor|Read|Edit|NotebookEdit|Grep|Glob|ReadMcpResourceTool|ReadMcpResourceDirTool|Artifact|Projects|Workflow|ClaudeDesign";
/// The `PreToolUse` matcher for every MCP tool: a regular expression.
pub const MCP_MATCHER: &str = "mcp__.*";
/// How long a `claude mcp` command may take.
const CLI_LIMIT: Duration = Duration::from_secs(60);

/// The MCP server entry: EnvCloak's absolute path, `mcp --host
/// claude-code`, and the per-server `timeout` (milliseconds) the tools'
/// waits are sized for.
pub fn mcp_entry(envcloak: &Path) -> Value {
    let timeout = tool_timeouts::host(Host::ClaudeCode.id())
        .map_or(tool_timeouts::UNKNOWN_CUTOFF, |h| h.tool_timeout);
    json!({
        "command": envcloak.to_string_lossy(),
        "args": ["mcp", "--host", "claude-code"],
        "timeout": u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
    })
}

fn handler(envcloak: &Path, event: Event) -> Value {
    json!({
        "type": "command",
        "command": hook_command(envcloak, Host::ClaudeCode, event),
        "timeout": HOOK_TIMEOUT_SECS,
    })
}

/// The hooks the installer adds to `settings.json`, each with its path:
/// what EnvCloak's plugin carries too.
pub fn hooks_additions(envcloak: &Path) -> Vec<(Vec<&'static str>, Value)> {
    vec![
        (
            vec!["hooks", "UserPromptSubmit"],
            json!({"hooks": [handler(envcloak, Event::UserPromptSubmit)]}),
        ),
        (
            vec!["hooks", "PreToolUse"],
            json!({"matcher": TOOL_MATCHER, "hooks": [handler(envcloak, Event::PreToolUse)]}),
        ),
        (
            vec!["hooks", "PreToolUse"],
            json!({"matcher": MCP_MATCHER, "hooks": [handler(envcloak, Event::PreToolUse)]}),
        ),
        (
            vec!["hooks", "SessionStart"],
            json!({"hooks": [handler(envcloak, Event::SessionStart)]}),
        ),
    ]
}

/// The settings no plugin carries, which the installer adds to
/// `settings.json` with or without one, each with its path: the deny rule,
/// the sandbox's deny entries for the vault and the backups, and with
/// `socket` (the daemon's socket, resolved; macOS only) its allowance.
pub fn protections(socket: Option<&Path>, data_dir: &Path) -> Vec<(Vec<&'static str>, Value)> {
    let mut out = vec![(vec!["permissions", "deny"], json!(READ_DENY))];
    if let Some(s) = socket {
        out.push((
            vec!["sandbox", "network", "allowUnixSockets"],
            json!(s.to_string_lossy()),
        ));
    }
    for d in ["vault", "backups"] {
        out.push((
            vec!["sandbox", "credentials", "files"],
            json!({"path": data_dir.join(d).to_string_lossy(), "mode": "deny"}),
        ));
    }
    out
}

/// Every element the installer adds to `settings.json` when no plugin
/// carries the hooks.
pub fn settings_additions(
    envcloak: &Path,
    socket: Option<&Path>,
    data_dir: &Path,
) -> Vec<(Vec<&'static str>, Value)> {
    let mut out = protections(socket, data_dir);
    out.extend(hooks_additions(envcloak));
    out
}

/// Whether the person enabled an EnvCloak plugin (`integrations/
/// claude-code/`) in these settings: its hooks are then already there,
/// and installing them again would run each twice.
pub fn plugin_enabled(settings: &Value) -> bool {
    settings
        .get("enabledPlugins")
        .and_then(Value::as_object)
        .is_some_and(|m| {
            m.iter()
                .any(|(k, v)| k.split('@').next() == Some("envcloak") && v.as_bool() == Some(true))
        })
}

/// Whether these settings hold EnvCloak's own hooks, as `agents install`
/// writes them (`<envcloak> hook --host claude-code --event <name>`, the
/// program named `envcloak`, quoted or not): the plugin's are in its own
/// `hooks/hooks.json`, never in a settings file.
pub fn envcloak_hooks(settings: &Value) -> bool {
    let own = |cmd: &str| {
        Event::ALL.iter().any(|e| {
            let tail = format!(
                " hook --host {} --event {}",
                Host::ClaudeCode.id(),
                e.name()
            );
            cmd.strip_suffix(tail.as_str()).is_some_and(|exe| {
                let exe = exe
                    .strip_prefix('\'')
                    .and_then(|x| x.strip_suffix('\''))
                    .unwrap_or(exe);
                Path::new(exe).file_name() == Some(std::ffi::OsStr::new("envcloak"))
            })
        })
    };
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
                                .any(own)
                        })
                })
        })
}

/// The user-scope MCP server entry named `envcloak` in `~/.claude.json`, as
/// read (never written: D-16).
///
/// # Errors
/// When the file is not JSON or its servers not an object.
pub fn registered(claude_json: &[u8]) -> Result<Option<Value>, Refusal> {
    let v: Value = serde_json::from_slice(claude_json).map_err(|_| {
        Refusal::new(
            "not_json",
            "Claude Code's ~/.claude.json is not JSON, so its MCP servers could not be read",
        )
    })?;
    match v.get("mcpServers") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(m)) => Ok(m.get(SERVER).cloned()),
        Some(_) => Err(Refusal::new(
            "unexpected_shape",
            "Claude Code's MCP servers in ~/.claude.json are not an object",
        )),
    }
}

/// Runs `claude` with `args`, with only the environment Claude Code needs
/// to find its files from `env`, within 60 seconds, its output read within
/// them too ([`crate::detect::run_bounded`]).
///
/// # Errors
/// When it cannot start or does not finish in time.
pub fn run(
    exe: &Path,
    args: &[&str],
    env: &dyn Fn(&str) -> Option<OsString>,
) -> Result<Output, Refusal> {
    let mut cmd = Command::new(exe);
    cmd.args(args)
        .env_clear()
        .env("DISABLE_AUTOUPDATER", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for k in [
        "HOME",
        "PATH",
        "USER",
        "LOGNAME",
        "LANG",
        "LC_ALL",
        "TMPDIR",
        "CLAUDE_CONFIG_DIR",
        "CLAUDE_CODE_TMPDIR",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "XDG_CACHE_HOME",
        "XDG_RUNTIME_DIR",
    ] {
        if let Some(v) = env(k) {
            cmd.env(k, v);
        }
    }
    match crate::detect::run_bounded(&mut cmd, CLI_LIMIT, 1 << 20) {
        Ok(out) => Ok(out),
        Err(crate::detect::Bounded::Failed) => Err(Refusal::new(
            "host_cli_failed",
            "Claude Code's `claude` command could not be started",
        )),
        Err(crate::detect::Bounded::Timeout) => Err(Refusal::new(
            "host_cli_failed",
            "Claude Code's `claude mcp` command did not finish within 60 seconds",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_entry_and_the_additions_are_as_documented() {
        let e = mcp_entry(Path::new("/b/envcloak"));
        assert_eq!(e["args"], json!(["mcp", "--host", "claude-code"]));
        assert_eq!(e["timeout"], json!(60_000));
        let adds = settings_additions(Path::new("/b/envcloak"), None, Path::new("/d"));
        assert!(
            adds.iter()
                .all(|(p, _)| p[0] != "sandbox" || p[1] != "network")
        );
        let text = serde_json::to_string(&adds.iter().map(|(_, v)| v).collect::<Vec<_>>())
            .unwrap_or_default();
        assert!(!text.contains("excludedCommands"));
        assert!(
            !text.contains("allow"),
            "no approval and no allow rule: {text}"
        );
        assert!(text.contains("/b/envcloak hook --host claude-code --event PreToolUse"));
        let with = settings_additions(
            Path::new("/b/envcloak"),
            Some(Path::new("/s")),
            Path::new("/d"),
        );
        assert_eq!(with.len(), adds.len() + 1);
    }

    #[test]
    fn envcloaks_own_hooks_are_told_from_others() {
        let mut v = json!({});
        for (path, value) in hooks_additions(Path::new("/opt/homebrew/bin/envcloak")) {
            let event = path[1];
            v["hooks"][event] = json!([value]);
        }
        assert!(envcloak_hooks(&v));
        let quoted = hook_command(
            Path::new("/Users/a b/envcloak"),
            Host::ClaudeCode,
            Event::SessionStart,
        );
        assert!(envcloak_hooks(
            &json!({"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": quoted}]}]}})
        ));
        for other in [
            "/usr/bin/true",
            "/b/envcloakx hook --host claude-code --event PreToolUse",
            "/b/envcloak hook --host codex --event PreToolUse",
        ] {
            assert!(!envcloak_hooks(
                &json!({"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": other}]}]}})
            ));
        }
        assert!(!envcloak_hooks(&json!({})));
    }

    #[test]
    fn a_plugin_named_envcloak_counts_only_when_enabled() {
        assert!(plugin_enabled(
            &json!({"enabledPlugins": {"envcloak@market": true}})
        ));
        assert!(!plugin_enabled(
            &json!({"enabledPlugins": {"envcloak@market": false}})
        ));
        assert!(!plugin_enabled(
            &json!({"enabledPlugins": {"envcloakish@m": true}})
        ));
        assert!(!plugin_enabled(&json!({})));
    }
}
