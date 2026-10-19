use std::path::Path;

use serde_json::Value;

use crate::jsonedit::Doc;

use super::MigrateError;

pub fn rewrite_cursor_json(
    path: &Path,
    source: &str,
    rewrites: &[(String, Value)],
) -> Result<String, MigrateError> {
    let mut doc = Doc::parse(source.as_bytes()).map_err(|e| MigrateError::InvalidConfig {
        path: path.to_path_buf(),
        reason: e.message().to_string(),
    })?;
    for (server, value) in rewrites {
        let mut replaced = false;
        for top in ["mcpServers", "servers", "mcp_servers", "mcp"] {
            if let Ok(true) = doc.replace_member(&[top], server, value) {
                replaced = true;
                break;
            }
        }
        if !replaced {
            return Err(MigrateError::ServerNotFound {
                agent: "cursor".to_string(),
                server: server.clone(),
            });
        }
    }
    Ok(doc.text().to_string())
}
