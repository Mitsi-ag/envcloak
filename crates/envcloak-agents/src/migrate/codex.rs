use std::path::Path;

use toml_edit::{Array, DocumentMut, Item, Table, Value as TomlValue};

use super::MigrateError;

pub const CODEX_STARTUP_TIMEOUT_SEC: i64 = 60;

#[derive(Debug, Clone)]
pub struct CodexServerRewrite {
    pub server: String,
    pub command: String,
    pub args: Vec<String>,
    pub set_startup_timeout: bool,
}

pub fn needs_startup_timeout(source: &str, server: &str) -> bool {
    let Ok(doc) = source.parse::<DocumentMut>() else {
        return true;
    };
    let Some(mcp_servers) = doc.get("mcp_servers").and_then(Item::as_table_like) else {
        return true;
    };
    let Some(tbl) = mcp_servers.get(server).and_then(Item::as_table_like) else {
        return true;
    };
    match tbl.get("startup_timeout_sec").and_then(Item::as_integer) {
        Some(v) => v < CODEX_STARTUP_TIMEOUT_SEC,
        None => true,
    }
}

pub fn rewrite_codex_toml(
    path: &Path,
    source: &str,
    rewrites: &[CodexServerRewrite],
) -> Result<String, MigrateError> {
    let mut doc = source
        .parse::<DocumentMut>()
        .map_err(|e| MigrateError::InvalidConfig {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })?;

    let mcp_item = doc
        .get_mut("mcp_servers")
        .ok_or_else(|| MigrateError::InvalidConfig {
            path: path.to_path_buf(),
            reason: "missing [mcp_servers] table".to_string(),
        })?;
    let mcp_table = mcp_item
        .as_table_like_mut()
        .ok_or_else(|| MigrateError::InvalidConfig {
            path: path.to_path_buf(),
            reason: "mcp_servers is not a table".to_string(),
        })?;

    for rw in rewrites {
        let srv_item =
            mcp_table
                .get_mut(&rw.server)
                .ok_or_else(|| MigrateError::ServerNotFound {
                    agent: "codex".to_string(),
                    server: rw.server.clone(),
                })?;
        let srv_table =
            srv_item
                .as_table_like_mut()
                .ok_or_else(|| MigrateError::InvalidConfig {
                    path: path.to_path_buf(),
                    reason: format!("mcp_servers.{} is not a table", rw.server),
                })?;

        for key in [
            "command",
            "args",
            "env",
            "env_vars",
            "cwd",
            "envFile",
            "url",
            "httpUrl",
            "headers",
            "http_headers",
            "env_http_headers",
            "bearer_token_env_var",
            "http_headers_helper",
            "auth",
            "type",
        ] {
            srv_table.remove(key);
        }

        srv_table.insert("command", toml_edit::value(rw.command.as_str()));
        let mut arr = Array::new();
        for arg in &rw.args {
            arr.push(arg.as_str());
        }
        srv_table.insert("args", Item::Value(TomlValue::Array(arr)));

        if rw.set_startup_timeout {
            let existing = srv_table
                .get("startup_timeout_sec")
                .and_then(Item::as_integer)
                .unwrap_or(0);
            if existing < CODEX_STARTUP_TIMEOUT_SEC {
                srv_table.insert(
                    "startup_timeout_sec",
                    toml_edit::value(CODEX_STARTUP_TIMEOUT_SEC),
                );
            }
        }

        if let Some(tbl) = srv_item.as_table_mut() {
            clean_empty_subtables(tbl);
        }
    }

    Ok(doc.to_string())
}

fn clean_empty_subtables(tbl: &mut Table) {
    tbl.set_implicit(false);
}
