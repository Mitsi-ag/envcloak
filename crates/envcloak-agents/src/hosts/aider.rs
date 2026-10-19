//! What the installer writes for Aider (SPEC §7; Map C §2.10; M2 plan task
//! M2-24):
//!
//! - the instruction block in `<data_dir>/AGENTS.md`;
//! - in `~/.aider.conf.yml`: a `read:` entry pointing at
//!   `<data_dir>/AGENTS.md`, removed cleanly on uninstall;
//! - a note that Aider has no hook or MCP support (all hook and MCP
//!   surfaces are `unsupported`, and output is `unverified
//!   (not_drivable)`).

use std::path::Path;

use serde_json::json;

use crate::writer::{Change, Edit, Edited, Refusal, Undo};

const BEGIN_MARKER: &str = "# envcloak:begin";
const END_MARKER: &str = "# envcloak:end";

fn yaml_quote(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| format!("\"{s}\""))
}

/// Applies the `read:` entry for `agents_md` to `~/.aider.conf.yml`.
///
/// # Errors
/// Returns a [`Refusal`] if `existing` is not valid UTF-8.
pub fn apply_aider_conf(existing: Option<&[u8]>, agents_md: &Path) -> Result<Edited, Refusal> {
    let text = match existing {
        Some(b) => std::str::from_utf8(b).map_err(|_| {
            Refusal::new(
                "not_utf8",
                "Aider's ~/.aider.conf.yml is not UTF-8, so it was not changed",
            )
        })?,
        None => "",
    };
    let path_str = agents_md.to_string_lossy().into_owned();
    let quoted = yaml_quote(&path_str);
    if text.contains(&path_str) || text.contains(&quoted) {
        return Ok(None);
    }
    let block = format!("{BEGIN_MARKER}\nread:\n  - {quoted}\n{END_MARKER}\n");
    let mut out = text.to_owned();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&block);
    let edit = Edit::TomlValue {
        path: vec!["read".to_owned()],
        value: json!(path_str),
        previous: None,
        created: usize::from(existing.is_none()),
    };
    Ok(Some(Change::new(out.into_bytes(), vec![edit])))
}

/// Removes EnvCloak's `read:` entry from `~/.aider.conf.yml`.
///
/// # Errors
/// Returns a [`Refusal`] if `existing` is not valid UTF-8.
pub fn remove_aider_conf(existing: &[u8], created_file: bool) -> Result<Undo, Refusal> {
    let text = std::str::from_utf8(existing).map_err(|_| {
        Refusal::new(
            "not_utf8",
            "Aider's ~/.aider.conf.yml is not UTF-8, so it was not changed",
        )
    })?;
    let Some(start) = text.find(BEGIN_MARKER) else {
        return Ok(Undo::Nothing);
    };
    let Some(rel_end) = text[start..].find(END_MARKER) else {
        return Ok(Undo::Nothing);
    };
    let mut end = start + rel_end + END_MARKER.len();
    if text[end..].starts_with("\r\n") {
        end += 2;
    } else if text[end..].starts_with('\n') {
        end += 1;
    }
    let mut out = String::with_capacity(text.len());
    out.push_str(&text[..start]);
    out.push_str(&text[end..]);
    if created_file && out.trim().is_empty() {
        return Ok(Undo::Remove);
    }
    Ok(Undo::Rewrite(out.into_bytes()))
}

/// Note explaining Aider's surface support.
pub const AIDER_NOTE: &str = "Aider has no hook or MCP support (all hook and MCP surfaces are \
    unsupported); run commands that need secrets through `envcloak run -- <cmd>`";
