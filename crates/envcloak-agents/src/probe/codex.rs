//! How a probe drives Codex (the pinned 0.159.2, as M2-04 measured it,
//! docs/AGENTS.md "Host behaviour"): `codex exec` with the scripted model
//! as its only provider and the sandbox and approval policy pinned per
//! probe, all as `-c` settings for that run (`--strict-config`, so a
//! setting the version does not know fails the run rather than being
//! dropped): the person's `config.toml` is never edited. Approval policy is
//! always `never`: a call Codex would ask about is refused, never
//! approved by default.
//!
//! Codex reads files through its shell, so its file-read probe is a shell
//! command. Its `forbidden` rules (`envcloak.rules`) refuse `printenv` and
//! `cat .env`, without EnvCloak's marker, where EnvCloak's hook does not
//! answer first (measured on 0.159.2: a running hook answers both with its
//! marker; untrusted or taken out, the rules refuse them with their
//! justification): the hook's cases are `env` and `cat -- .env`, which the
//! rules' prefixes do not match and the hook denies, so what they measure
//! is the hook whatever the rules do; `printenv` and `cat .env` are the
//! rule's cases, which must be refused, by the rule or the hook. Claude
//! Code's probes follow the same rule (`run`'s `file_read`).

use std::ffi::OsString;

use serde_json::{Value, json};

/// The fixture MCP server's name in a probe.
pub const MCP_SERVER: &str = "ecprobe";

/// The model's token, which the provider entry names as its `env_key`.
pub fn model_env(token: &str) -> Vec<(OsString, OsString)> {
    vec![("EC_MODEL_TOKEN".into(), token.into())]
}

/// `s` as a TOML basic string.
pub fn toml_str(s: &str) -> String {
    toml_edit::Value::from(s).to_string().trim().to_owned()
}

/// The settings every run pins: no git check, strict settings, approval
/// policy `never`, and the scripted model at `base_url` as the only
/// provider.
fn pinned(base_url: &str) -> Vec<OsString> {
    let provider = format!(
        "model_providers.ec={{name={}, base_url={}, env_key=\"EC_MODEL_TOKEN\", \
         wire_api=\"responses\"}}",
        toml_str("EnvCloak scripted model"),
        toml_str(&format!("{base_url}/v1"))
    );
    let mut out: Vec<OsString> = [
        "--skip-git-repo-check",
        "--strict-config",
        "-c",
        "approval_policy=\"never\"",
        "-c",
        "model=\"ec-scripted\"",
        "-c",
        "model_provider=\"ec\"",
        "-c",
        "check_for_update_on_startup=false",
        "-c",
    ]
    .iter()
    .map(OsString::from)
    .collect();
    out.push(provider.into());
    out
}

/// The arguments of a run of `prompt` against the model at `base_url`, in
/// `sandbox`, with the probe's own `-c` settings and flags, then the probe
/// home's.
pub fn args(
    base_url: &str,
    prompt: &str,
    sandbox: &str,
    probe: &[String],
    home: &[String],
) -> Vec<OsString> {
    let mut out: Vec<OsString> = vec!["exec".into()];
    out.extend(pinned(base_url));
    out.extend(["--sandbox".into(), sandbox.into()]);
    out.extend(probe.iter().map(OsString::from));
    out.extend(home.iter().map(OsString::from));
    out.push(prompt.into());
    out
}

/// The arguments of a run of `prompt` in the session `session`, resumed
/// (`exec resume`), against the model at `base_url`: as [`args`], with the
/// sandbox as its setting, which `exec resume` takes in place of
/// `--sandbox` (measured on the pinned 0.159.2), and the session's id
/// before the prompt.
pub fn resume_args(
    base_url: &str,
    session: &str,
    prompt: &str,
    sandbox: &str,
    probe: &[String],
    home: &[String],
) -> Vec<OsString> {
    let mut out: Vec<OsString> = vec!["exec".into(), "resume".into()];
    out.extend(pinned(base_url));
    out.extend([
        "-c".into(),
        format!("sandbox_mode={}", toml_str(sandbox)).into(),
    ]);
    out.extend(probe.iter().map(OsString::from));
    out.extend(home.iter().map(OsString::from));
    out.push(session.into());
    out.push(prompt.into());
    out
}

/// The `-c` settings among `args` (`-c key=value`, `--config key=value`,
/// `--config=key=value`), each as its key and its value's text.
pub fn settings(args: &[String]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let setting = match a.as_str() {
            "-c" | "--config" => it.next().map(String::as_str),
            other => other.strip_prefix("--config="),
        };
        if let Some((k, v)) = setting.and_then(|s| s.split_once('=')) {
            out.push((k.trim().to_owned(), v.trim().to_owned()));
        }
    }
    out
}

/// The folder a `-c` setting's value names (Codex reads it as TOML, and as
/// a plain string when it is not): an absolute path, or `~/` from `home`;
/// `None` for anything else (a relative path, read from where Codex was
/// started, is not taken as known).
pub fn setting_path(value: &str, home: &std::path::Path) -> Option<std::path::PathBuf> {
    let text = match value.parse::<toml_edit::Value>() {
        Ok(toml_edit::Value::String(s)) => s.value().clone(),
        Ok(_) => return None,
        Err(_) => value.to_owned(),
    };
    match text.strip_prefix("~/") {
        Some(rest) => Some(home.join(rest)),
        None => {
            let p = std::path::PathBuf::from(&text);
            p.is_absolute().then_some(p)
        }
    }
}

/// A step that calls `tool` of MCP server `server` (Codex offers a
/// server's tools as the Responses namespace `mcp__<server>`).
pub fn mcp_step(server: &str, tool: &str, input: Value) -> Value {
    json!({"tool": tool, "namespace": format!("mcp__{server}"), "input": input})
}

/// The `-c` settings that add the fixture MCP server for one run, its
/// tools approved there (the probe's own server; EnvCloak's are never
/// approved by the installer, D-22).
pub fn mcp_server(fixture: &str) -> Vec<String> {
    vec![
        "-c".to_owned(),
        format!(
            "mcp_servers.{MCP_SERVER}={{command={}, args=[], default_tools_approval_mode=\"approve\"}}",
            toml_str(fixture)
        ),
    ]
}

/// The `-c` settings of the sentinel probe: `workspace-write` with `/tmp`
/// and `TMPDIR` excluded from the writable roots (the probe home is under
/// a temporary directory), and the person's approval of EnvCloak's
/// `run_with_secrets` for this run only, as a person sets it by tool
/// (`[mcp_servers.envcloak.tools.run_with_secrets] approval_mode`).
pub fn sentinel_settings() -> Vec<String> {
    [
        "sandbox_workspace_write.exclude_slash_tmp=true",
        "sandbox_workspace_write.exclude_tmpdir_env_var=true",
        "mcp_servers.envcloak.tools.run_with_secrets.approval_mode=\"approve\"",
    ]
    .iter()
    .flat_map(|s| ["-c".to_owned(), (*s).to_owned()])
    .collect()
}
