//! What the installer writes for Kimi Code and Kimi CLI (SPEC §7; Map C
//! §2.6; M2 plan task M2-24, D-14, D-16, D-20, D-22):
//!
//! - detects whether the installed `kimi` binary is Kimi Code
//!   (`@moonshot-ai/kimi-code`, data root `~/.kimi-code` / `$KIMI_CODE_HOME`)
//!   or Kimi CLI (`kimi-cli` Python package, data root `~/.kimi` /
//!   `$KIMI_SHARE_DIR`) by executable name, canonical path / shebang,
//!   version string and data root, so ONLY the detected product's files
//!   are written, never both (D-20);
//! - for Kimi Code: `~/.kimi-code/AGENTS.md` block, `[[hooks]]` in
//!   `~/.kimi-code/config.toml` and `mcpServers.envcloak` in
//!   `~/.kimi-code/mcp.json`;
//! - for Kimi CLI: `[[hooks]]` in `~/.kimi/config.toml` and
//!   `mcpServers.envcloak` in `~/.kimi/mcp.json`.

use std::ffi::OsString;
use std::path::Path;

use serde_json::{Value, json};
use toml_edit::{ArrayOfTables, DocumentMut, Item, Table};

use super::hook_command;
use crate::hook::{Event, Host};
use crate::locations::Locations;
use crate::writer::{Change, Edit, Edited, Refusal, Undo};

/// The MCP server's name.
pub const SERVER: &str = "envcloak";
/// Timeout (seconds) for Kimi hooks.
pub const KIMI_HOOK_TIMEOUT_SECS: i64 = 5;
/// Tool matcher for Kimi's `PreToolUse` hook.
pub const PRE_TOOL_MATCHER: &str =
    "Bash|Shell|Read|ReadFile|Write|WriteFile|Edit|StrReplaceFile|Glob|Grep|mcp:.*|mcp__.*";

/// Which Kimi product is installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KimiProduct {
    /// `@moonshot-ai/kimi-code` (`~/.kimi-code` / `$KIMI_CODE_HOME`).
    Code,
    /// `kimi-cli` Python package (`~/.kimi` / `$KIMI_SHARE_DIR`).
    Cli,
}

impl KimiProduct {
    pub fn id(self) -> &'static str {
        match self {
            KimiProduct::Code => "kimi-code",
            KimiProduct::Cli => "kimi-cli",
        }
    }

    pub fn display_name(self) -> &'static str {
        match self {
            KimiProduct::Code => "Kimi Code",
            KimiProduct::Cli => "Kimi CLI",
        }
    }
}

/// Detects whether the installed Kimi binary is Kimi Code or Kimi CLI (D-20).
pub fn detect_product(
    exe: Option<&Path>,
    version: Option<&str>,
    locations: &Locations,
    env: &dyn Fn(&str) -> Option<OsString>,
) -> KimiProduct {
    if let Some(p) = exe {
        if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
            if name == "kimi-cli" {
                return KimiProduct::Cli;
            }
            if name == "kimi-code" {
                return KimiProduct::Code;
            }
        }
        let canon = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        let canon_str = canon.to_string_lossy().to_ascii_lowercase();
        if canon_str.contains("kimi-cli")
            || canon_str.contains("kimi_cli")
            || canon_str.contains("/uv/tools/")
            || canon_str.contains("/pipx/venvs/")
        {
            return KimiProduct::Cli;
        }
        if canon_str.contains("@moonshot-ai/kimi-code") || canon_str.contains("kimi-code") {
            return KimiProduct::Code;
        }
        {
            use std::io::Read as _;
            use std::os::unix::fs::OpenOptionsExt as _;
            if let Ok(f) = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&canon)
                && f.metadata().is_ok_and(|m| m.is_file())
            {
                let mut bytes = Vec::with_capacity(512);
                if f.take(512).read_to_end(&mut bytes).is_ok() {
                    let head = String::from_utf8_lossy(&bytes).to_ascii_lowercase();
                    if head.contains("kimi_cli")
                        || head.contains("kimi-cli")
                        || head.contains("python")
                    {
                        return KimiProduct::Cli;
                    }
                    if head.contains("@moonshot-ai/kimi-code")
                        || head.contains("kimi-code")
                        || head.starts_with("#!/usr/bin/env node")
                    {
                        return KimiProduct::Code;
                    }
                }
            }
        }
    }
    if let Some(v) = version {
        let low = v.to_ascii_lowercase();
        if low.contains("kimi-cli") || low.contains("kimi cli") {
            return KimiProduct::Cli;
        }
        if low.contains("kimi-code") || low.contains("kimi code") {
            return KimiProduct::Code;
        }
        let ver_part = low
            .split(|c: char| !c.is_ascii_digit() && c != '.')
            .find(|s| s.contains('.') && s.chars().next().is_some_and(|c| c.is_ascii_digit()));
        if let Some(ver) = ver_part
            && let Some(major) = ver.split('.').next().and_then(|m| m.parse::<u32>().ok())
        {
            if major >= 2 {
                return KimiProduct::Code;
            }
            if major == 1 {
                return KimiProduct::Cli;
            }
        }
    }
    let has_code_env = env("KIMI_CODE_HOME").is_some_and(|v| !v.is_empty());
    let has_cli_env = env("KIMI_SHARE_DIR").is_some_and(|v| !v.is_empty());
    if has_cli_env && !has_code_env {
        return KimiProduct::Cli;
    }
    if has_code_env && !has_cli_env {
        return KimiProduct::Code;
    }
    let code_dir = locations.kimi_code_dir();
    let cli_dir = locations.kimi_cli_dir();
    if cli_dir.exists() && !code_dir.exists() {
        return KimiProduct::Cli;
    }
    KimiProduct::Code
}

/// The MCP server entry in `mcp.json` (`~/.kimi-code/mcp.json` or
/// `~/.kimi/mcp.json`).
pub fn mcp_entry(envcloak: &Path) -> Value {
    json!({
        "command": envcloak.to_string_lossy(),
        "args": ["mcp", "--host", "kimi"],
    })
}

const KIMI_EVENTS: [Event; 3] = [
    Event::UserPromptSubmit,
    Event::PreToolUse,
    Event::SessionStart,
];

fn hook_spec(envcloak: &Path, event: Event) -> (String, Option<&'static str>, String) {
    let matcher = match event {
        Event::PreToolUse => Some(PRE_TOOL_MATCHER),
        _ => None,
    };
    (
        event.name().to_owned(),
        matcher,
        hook_command(envcloak, Host::Kimi, event),
    )
}

fn table_matches_envcloak(t: &Table, event: &str) -> bool {
    t.get("event").and_then(Item::as_str) == Some(event)
        && t.get("command")
            .and_then(Item::as_str)
            .is_some_and(|c| c.contains(" hook --host kimi --event "))
}

/// Applies EnvCloak's `[[hooks]]` tables to Kimi's `config.toml`.
///
/// # Errors
/// Returns a [`Refusal`] if `existing` is not valid UTF-8 or TOML, or if
/// `hooks` in the document is not an array of tables.
pub fn apply_config_toml(existing: Option<&[u8]>, envcloak: &Path) -> Result<Edited, Refusal> {
    let text = match existing {
        Some(b) => std::str::from_utf8(b).map_err(|_| {
            Refusal::new(
                "not_utf8",
                "Kimi's config.toml is not UTF-8, so it was not changed",
            )
        })?,
        None => "",
    };
    let mut doc: DocumentMut = text.parse().map_err(|_| {
        Refusal::new(
            "not_toml",
            "Kimi's config.toml is not valid TOML, so it was not changed",
        )
    })?;
    let created_hooks_array = !doc.contains_key("hooks");
    if created_hooks_array {
        doc.insert("hooks", Item::ArrayOfTables(ArrayOfTables::new()));
    }
    let Some(arr) = doc.get_mut("hooks").and_then(Item::as_array_of_tables_mut) else {
        return Err(Refusal::new(
            "unexpected_shape",
            "hooks in Kimi's config.toml is not an array of tables ([[hooks]])",
        ));
    };
    let mut added = Vec::new();
    let mut changed = false;
    for (idx, ev) in KIMI_EVENTS.iter().enumerate() {
        let (event_name, matcher, cmd) = hook_spec(envcloak, *ev);
        let already = arr.iter().any(|t| {
            t.get("event").and_then(Item::as_str) == Some(event_name.as_str())
                && t.get("command").and_then(Item::as_str) == Some(cmd.as_str())
                && t.get("matcher").and_then(Item::as_str) == matcher
        });
        let val = json!({
            "event": event_name,
            "matcher": matcher,
            "command": cmd,
            "timeout": KIMI_HOOK_TIMEOUT_SECS,
        });
        let edit = Edit::TomlValue {
            path: vec!["hooks".to_owned(), event_name.clone()],
            value: val,
            previous: None,
            created: usize::from(created_hooks_array && idx == 0),
        };
        if !already {
            // Remove any stale EnvCloak entry for this event before adding.
            arr.retain(|t| !table_matches_envcloak(t, &event_name));
            let mut t = Table::new();
            t.insert("event", toml_edit::value(event_name));
            if let Some(m) = matcher {
                t.insert("matcher", toml_edit::value(m));
            }
            t.insert("command", toml_edit::value(cmd));
            t.insert("timeout", toml_edit::value(KIMI_HOOK_TIMEOUT_SECS));
            arr.push(t);
            changed = true;
        }
        added.push(edit);
    }
    if !changed {
        return Ok(None);
    }
    let mut out = doc.to_string();
    if !out.ends_with('\n') {
        out.push('\n');
    }
    Ok(Some(Change::new(out.into_bytes(), added)))
}

/// Removes EnvCloak's `[[hooks]]` tables from Kimi's `config.toml`.
///
/// # Errors
/// Returns a [`Refusal`] if `existing` is not valid UTF-8 or TOML.
pub fn remove_config_toml(
    existing: &[u8],
    edits: &[Edit],
    created_file: bool,
) -> Result<Undo, Refusal> {
    let text = std::str::from_utf8(existing).map_err(|_| {
        Refusal::new(
            "not_utf8",
            "Kimi's config.toml is not UTF-8, so it was not changed",
        )
    })?;
    let mut doc: DocumentMut = text.parse().map_err(|_| {
        Refusal::new(
            "not_toml",
            "Kimi's config.toml is not valid TOML, so it was not changed",
        )
    })?;
    let mut changed = false;
    if let Some(arr) = doc.get_mut("hooks").and_then(Item::as_array_of_tables_mut) {
        let before = arr.len();
        arr.retain(|t| {
            !edits.iter().any(|e| match e {
                Edit::TomlValue { path, .. } if path.len() == 2 && path[0] == "hooks" => {
                    table_matches_envcloak(t, &path[1])
                }
                _ => false,
            })
        });
        if arr.len() != before {
            changed = true;
        }
        if arr.is_empty() {
            doc.remove("hooks");
            changed = true;
        }
    }
    if !changed {
        return Ok(Undo::Nothing);
    }
    let out = doc.to_string();
    if created_file && out.trim().is_empty() {
        return Ok(Undo::Remove);
    }
    Ok(Undo::Rewrite(out.into_bytes()))
}

/// Whether Kimi's `config.toml` text holds EnvCloak's hooks.
pub fn envcloak_hooks(toml_text: &str) -> bool {
    let Ok(doc) = toml_text.parse::<DocumentMut>() else {
        return false;
    };
    doc.get("hooks")
        .and_then(Item::as_array_of_tables)
        .is_some_and(|arr| {
            arr.iter().any(|t| {
                t.get("command")
                    .and_then(Item::as_str)
                    .is_some_and(|c| c.contains(" hook --host kimi --event "))
            })
        })
}
