use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Map, Value};

use crate::detect::find_on_path;
use crate::jsonedit::Doc;
use crate::locations::Locations;

use super::MigrateError;

pub fn rewrite_mcp_json(
    source: &str,
    rewrites: &[(String, Value)],
) -> Result<String, MigrateError> {
    let mut doc = Doc::parse(source.as_bytes()).map_err(|e| MigrateError::InvalidConfig {
        path: PathBuf::from(".mcp.json"),
        reason: e.message().to_string(),
    })?;
    for (server, value) in rewrites {
        let replaced = doc
            .replace_member(&["mcpServers"], server, value)
            .map_err(|e| MigrateError::InvalidConfig {
                path: PathBuf::from(".mcp.json"),
                reason: e.message().to_string(),
            })?;
        if !replaced {
            return Err(MigrateError::ServerNotFound {
                agent: "claude-code".to_string(),
                server: server.clone(),
            });
        }
    }
    Ok(doc.text().to_string())
}

pub fn resolve_claude_cli(path_env: &OsStr) -> Result<PathBuf, MigrateError> {
    if !path_env.is_empty()
        && let Some(found) = find_on_path("claude", path_env)
    {
        return Ok(found);
    }
    if let Some(sys_path) = std::env::var_os("PATH")
        && let Some(found) = find_on_path("claude", &sys_path)
    {
        return Ok(found);
    }
    Err(MigrateError::MissingTool {
        tool: "claude".to_string(),
        detail: "claude CLI is required to update ~/.claude.json via `claude mcp`".to_string(),
    })
}

pub fn apply_claude_user_scope(
    loc: &Locations,
    path_env: &OsStr,
    claude_bin: &Path,
    rewrites: &[(String, Value)],
) -> Result<Vec<u8>, MigrateError> {
    let effective = effective_path(path_env);
    let claude_json = loc.claude_json().to_path_buf();
    let custom_dir = (claude_json.parent() == Some(loc.claude_dir())).then(|| loc.claude_dir());

    for (server, value) in rewrites {
        let json_payload = serde_json::to_string(value).map_err(|e| MigrateError::Io {
            path: claude_json.clone(),
            message: e.to_string(),
        })?;

        let mut rm_cmd = Command::new(claude_bin);
        rm_cmd
            .args(["mcp", "remove", "--scope", "user", server])
            .env("HOME", loc.home())
            .env("PATH", &effective);
        if let Some(d) = custom_dir {
            rm_cmd.env("CLAUDE_CONFIG_DIR", d);
        } else {
            rm_cmd.env_remove("CLAUDE_CONFIG_DIR");
        }
        let remove_out = rm_cmd.output().map_err(|e| MigrateError::Io {
            path: claude_bin.to_path_buf(),
            message: format!("failed to run `claude mcp remove`: {e}"),
        })?;
        if !remove_out.status.success() {
            let stderr = String::from_utf8_lossy(&remove_out.stderr);
            return Err(MigrateError::ExternalToolFailed {
                tool: "claude mcp remove".to_string(),
                detail: stderr.trim().to_string(),
            });
        }

        let mut add_cmd = Command::new(claude_bin);
        add_cmd
            .args(["mcp", "add-json", "--scope", "user", server, &json_payload])
            .env("HOME", loc.home())
            .env("PATH", &effective);
        if let Some(d) = custom_dir {
            add_cmd.env("CLAUDE_CONFIG_DIR", d);
        } else {
            add_cmd.env_remove("CLAUDE_CONFIG_DIR");
        }
        let add_out = add_cmd.output().map_err(|e| MigrateError::Io {
            path: claude_bin.to_path_buf(),
            message: format!("failed to run `claude mcp add-json`: {e}"),
        })?;
        if !add_out.status.success() {
            let stderr = String::from_utf8_lossy(&add_out.stderr);
            return Err(MigrateError::ExternalToolFailed {
                tool: "claude mcp add-json".to_string(),
                detail: stderr.trim().to_string(),
            });
        }
    }

    fs::read(&claude_json).map_err(|e| MigrateError::Io {
        path: claude_json,
        message: e.to_string(),
    })
}

pub fn build_entry_value(command: &str, args: &[String]) -> Value {
    let mut map = Map::new();
    map.insert("command".to_string(), Value::String(command.to_string()));
    map.insert(
        "args".to_string(),
        Value::Array(args.iter().cloned().map(Value::String).collect()),
    );
    Value::Object(map)
}

fn effective_path(path_env: &OsStr) -> OsString {
    if !path_env.is_empty() {
        return path_env.to_os_string();
    }
    std::env::var_os("PATH").unwrap_or_default()
}
