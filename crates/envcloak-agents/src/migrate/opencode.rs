use std::path::Path;

use serde_json::{Value, json};

use crate::jsonedit::Doc;

use super::MigrateError;

pub fn build_entry_value(command: &str, args: &[String]) -> Value {
    let mut cmd = Vec::with_capacity(1 + args.len());
    cmd.push(Value::String(command.to_string()));
    cmd.extend(args.iter().cloned().map(Value::String));
    json!({
        "type": "local",
        "command": cmd,
    })
}

pub fn rewrite_opencode_json(
    path: &Path,
    source: &str,
    rewrites: &[(String, Value)],
) -> Result<String, MigrateError> {
    let mut doc = Doc::parse(source.as_bytes()).map_err(|e| MigrateError::InvalidConfig {
        path: path.to_path_buf(),
        reason: e.message().to_string(),
    })?;
    for (server, value) in rewrites {
        let replaced = doc.replace_member(&["mcp"], server, value).map_err(|e| {
            MigrateError::InvalidConfig {
                path: path.to_path_buf(),
                reason: e.message().to_string(),
            }
        })?;
        if !replaced {
            return Err(MigrateError::ServerNotFound {
                agent: "opencode".to_string(),
                server: server.clone(),
            });
        }
    }
    Ok(doc.text().to_string())
}
