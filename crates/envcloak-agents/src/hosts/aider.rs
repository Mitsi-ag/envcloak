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

fn damaged() -> Refusal {
    let e = crate::blocks::BlockError::Damaged;
    Refusal::new(e.name(), e.message())
}

fn modified() -> Refusal {
    let e = crate::blocks::BlockError::Modified;
    Refusal::new(e.name(), e.message())
}

fn find_block(text: &str) -> Result<Option<(usize, usize)>, Refusal> {
    let mut begins = Vec::new();
    let mut ends = Vec::new();
    let mut at = 0;
    for line in text.split_inclusive('\n') {
        let bare = line.trim_end_matches('\n').trim_end_matches('\r');
        if bare == BEGIN_MARKER {
            begins.push(at);
        } else if bare == END_MARKER {
            ends.push(at + line.len());
        } else if bare.contains("envcloak:begin") || bare.contains("envcloak:end") {
            return Err(damaged());
        }
        at += line.len();
    }
    match (begins.as_slice(), ends.as_slice()) {
        ([], []) => Ok(None),
        ([b], [e]) if b < e => Ok(Some((*b, *e))),
        _ => Err(damaged()),
    }
}

fn is_ours(slice: &str) -> bool {
    let lines: Vec<&str> = slice.lines().map(|l| l.trim_end_matches('\r')).collect();
    matches!(
        lines.as_slice(),
        [BEGIN_MARKER, "read:", item, END_MARKER] if item.starts_with("  - ")
    )
}

/// Applies the `read:` entry for `agents_md` to `~/.aider.conf.yml`.
///
/// # Errors
/// Returns a [`Refusal`] if `existing` is not valid UTF-8 or has damaged/modified markers.
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
    let existing_range = find_block(text)?;
    let path_str = agents_md.to_string_lossy().into_owned();
    let quoted = yaml_quote(&path_str);
    let block = format!("{BEGIN_MARKER}\nread:\n  - {quoted}\n{END_MARKER}\n");
    let out = if let Some((start, end)) = existing_range {
        if !is_ours(&text[start..end]) {
            return Err(modified());
        }
        let norm = text[start..end].replace("\r\n", "\n");
        if norm.trim_end_matches('\n') == block.trim_end_matches('\n') {
            return Ok(None);
        }
        let mut s = String::with_capacity(text.len() + block.len());
        s.push_str(&text[..start]);
        s.push_str(&block);
        s.push_str(&text[end..]);
        s
    } else {
        if text.contains(&path_str) || text.contains(&quoted) {
            return Ok(None);
        }
        let mut s = text.to_owned();
        if !s.is_empty() && !s.ends_with('\n') {
            s.push('\n');
        }
        s.push_str(&block);
        s
    };
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
/// Returns a [`Refusal`] if `existing` is not valid UTF-8 or has damaged/modified markers.
pub fn remove_aider_conf(existing: &[u8], created_file: bool) -> Result<Undo, Refusal> {
    let text = std::str::from_utf8(existing).map_err(|_| {
        Refusal::new(
            "not_utf8",
            "Aider's ~/.aider.conf.yml is not UTF-8, so it was not changed",
        )
    })?;
    let Some((start, end)) = find_block(text)? else {
        return Ok(Undo::Nothing);
    };
    if !is_ours(&text[start..end]) {
        return Err(modified());
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
