//! What the installer writes for Codex (SPEC §7 "Codex"; M2 plan M2-08,
//! D-16, D-22; K-01 as M2-04 measured it):
//!
//! - the instruction block in `~/.codex/AGENTS.md`, unless
//!   `~/.codex/AGENTS.override.md` exists, which Codex reads instead: then
//!   nothing is written there, the instruction surface reads `degraded
//!   (override_file)`, and the report asks the person to add the block to
//!   the override or remove it;
//! - the hooks in `~/.codex/hooks.json` (`UserPromptSubmit`; `PreToolUse`
//!   for `Bash`, the shell tool's hook name, and every MCP tool;
//!   `SessionStart`), which Codex runs only once the person trusts them in
//!   `/hooks` (until then: `degraded (hooks_untrusted)`);
//! - `~/.codex/rules/envcloak.rules`, `forbidden` prefix rules for the
//!   commands that print secrets ([`RULES`]): they match a command's first
//!   words only, so a compound script, which reaches Codex as one shell
//!   call, passes them;
//! - in `config.toml` (which Codex rewrites itself, so D-16's rule
//!   applies), edited key by key with `toml_edit`: `[mcp_servers.envcloak]`
//!   with EnvCloak's absolute path, `args = ["mcp", "--host", "codex"]`,
//!   `tool_timeout_sec`, and on Linux `env_vars` naming the XDG variables
//!   that place EnvCloak's socket and data; no approval setting for any
//!   EnvCloak tool (D-22); and on macOS, only with the person's consent,
//!   the bounded socket allowance M2-04 qualified:
//!   `sandbox_workspace_write.network_access = true` and
//!   `[features.network_proxy]` enabled with no domain rule and one
//!   `unix_sockets` rule allowing EnvCloak's socket. On Linux no socket
//!   allowance or broader network setting is written, with or without
//!   consent: Codex's proxy honours `unix_sockets` on macOS only, so the
//!   sandboxed shell is `unsupported (sandbox_blocks_socket)` there (K-01).

use std::path::Path;

use serde_json::{Map, Value, json};
use toml_edit::{Array, DocumentMut, Item, Table};

use super::{HOOK_TIMEOUT_SECS, hook_command};
use crate::hook::{Event, Host};
use crate::tool_timeouts;
use crate::writer::{Change, Edit, Edited, Refusal, Undo};

/// The MCP server's name.
pub const SERVER: &str = "envcloak";

/// How many bytes of the instruction files it joins Codex reads by
/// default (`project_doc_max_bytes`, Map C section 2.2).
pub const DOC_BUDGET: usize = 32 * 1024;

/// EnvCloak's rules file: `forbidden` prefix rules for the commands that
/// print secrets, each with examples Codex checks when it loads them.
pub const RULES: &str = r#"# EnvCloak: commands that print secrets, refused before they run.
# Written by `envcloak agents install`; `envcloak agents uninstall` removes
# this file. A prefix rule matches a command's first words only: a compound
# script (a pipe, `&&`, a redirection, a substitution) reaches Codex as one
# shell call and is not matched here. EnvCloak's PreToolUse hook reads
# those. Neither is a security boundary: they prevent accidents.
prefix_rule(
    pattern = ["printenv"],
    decision = "forbidden",
    justification = "It prints environment variables, which can hold keys. Run a command that needs a key as `envcloak run -- <command>`, and use `envcloak ls` to see which keys exist.",
    match = ["printenv", "printenv HOME"],
    not_match = ["envcloak run -- npm test"],
)
prefix_rule(
    pattern = ["export", "-p"],
    decision = "forbidden",
    justification = "It prints environment variables, which can hold keys. Use `envcloak ls` to see which keys exist.",
    match = ["export -p"],
    not_match = ["export PATH=/usr/bin"],
)
prefix_rule(
    pattern = ["envcloak", ["reveal", "approve"]],
    decision = "forbidden",
    justification = "Only the person runs `envcloak reveal` and `envcloak approve`, in a terminal of their own. Ask them to run `envcloak pending` and approve the request there.",
    match = ["envcloak reveal openai/project", "envcloak approve REQUEST"],
    not_match = ["envcloak pending", "envcloak run -- npm test"],
)
prefix_rule(
    pattern = [["cat", "head", "tail", "less", "more", "bat", "source", "."], [".env", ".env.local", ".env.development", ".env.development.local", ".env.production", ".env.production.local", ".env.test", ".env.test.local"]],
    decision = "forbidden",
    justification = "It reads a .env file, whose values would reach the model. Run the command that needs them as `envcloak run -- <command>`.",
    match = ["cat .env", "head .env.local", "source .env.local"],
    not_match = ["cat README.md", "cat .env.example"],
)
"#;

fn handler(envcloak: &Path, event: Event) -> Value {
    json!({
        "type": "command",
        "command": hook_command(envcloak, Host::Codex, event),
        "timeout": HOOK_TIMEOUT_SECS,
    })
}

/// The array elements the installer adds to `hooks.json`.
pub fn hooks_additions(envcloak: &Path) -> Vec<(Vec<&'static str>, Value)> {
    vec![
        (
            vec!["hooks", "UserPromptSubmit"],
            json!({"hooks": [handler(envcloak, Event::UserPromptSubmit)]}),
        ),
        (
            vec!["hooks", "PreToolUse"],
            json!({"matcher": "Bash", "hooks": [handler(envcloak, Event::PreToolUse)]}),
        ),
        (
            vec!["hooks", "PreToolUse"],
            json!({"matcher": "mcp__.*", "hooks": [handler(envcloak, Event::PreToolUse)]}),
        ),
        (
            vec!["hooks", "SessionStart"],
            json!({"hooks": [handler(envcloak, Event::SessionStart)]}),
        ),
    ]
}

/// One TOML setting: the keys to it and its value, as JSON.
pub type Setting = (Vec<String>, Value);

/// The settings the installer writes into `config.toml`: the MCP server,
/// and with `socket` (macOS, with consent) the bounded socket allowance.
pub fn config_settings(envcloak: &Path, linux: bool, socket: Option<&Path>) -> Vec<Setting> {
    let timeout = tool_timeouts::host(Host::Codex.id())
        .map_or(tool_timeouts::UNKNOWN_CUTOFF, |h| h.tool_timeout);
    let mut server = Map::new();
    server.insert("command".to_owned(), json!(envcloak.to_string_lossy()));
    server.insert("args".to_owned(), json!(["mcp", "--host", "codex"]));
    if linux {
        server.insert(
            "env_vars".to_owned(),
            json!(["XDG_RUNTIME_DIR", "XDG_DATA_HOME", "XDG_STATE_HOME"]),
        );
    }
    server.insert("tool_timeout_sec".to_owned(), json!(timeout.as_secs()));
    let k = |p: &[&str]| p.iter().map(|s| (*s).to_owned()).collect::<Vec<String>>();
    let mut out = vec![(k(&["mcp_servers", SERVER]), Value::Object(server))];
    if let Some(s) = socket {
        out.push((
            k(&["sandbox_workspace_write", "network_access"]),
            json!(true),
        ));
        out.push((k(&["features", "network_proxy", "enabled"]), json!(true)));
        out.push((
            vec![
                "features".to_owned(),
                "network_proxy".to_owned(),
                "unix_sockets".to_owned(),
                s.to_string_lossy().into_owned(),
            ],
            json!("allow"),
        ));
    }
    out
}

fn not_toml() -> Refusal {
    Refusal::new(
        "not_toml",
        "the file is not valid TOML (or gives a key twice)",
    )
}

fn shape() -> Refusal {
    Refusal::new(
        "unexpected_shape",
        "a setting EnvCloak adds to is not a table of the type it expects (an inline table or \
         a value), which it does not rewrite",
    )
}

/// A TOML item as JSON, for comparing.
fn item_json(item: &Item) -> Value {
    match item {
        Item::None => Value::Null,
        Item::Value(v) => value_json(v),
        Item::Table(t) => Value::Object(
            t.iter()
                .map(|(k, v)| (k.to_owned(), item_json(v)))
                .collect(),
        ),
        Item::ArrayOfTables(a) => Value::Array(
            a.iter()
                .map(|t| item_json(&Item::Table(t.clone())))
                .collect(),
        ),
    }
}

fn value_json(v: &toml_edit::Value) -> Value {
    use toml_edit::Value as V;
    match v {
        V::String(s) => json!(s.value()),
        V::Integer(i) => json!(i.value()),
        V::Float(f) => json!(f.value()),
        V::Boolean(b) => json!(b.value()),
        V::Datetime(d) => json!(d.value().to_string()),
        V::Array(a) => Value::Array(a.iter().map(value_json).collect()),
        V::InlineTable(t) => Value::Object(
            t.iter()
                .map(|(k, v)| (k.to_owned(), value_json(v)))
                .collect(),
        ),
    }
}

/// JSON as a TOML item: an object as a table, the rest as values.
fn json_item(v: &Value) -> Result<Item, Refusal> {
    Ok(match v {
        Value::Object(m) => {
            let mut t = Table::new();
            for (k, x) in m {
                t.insert(k, json_item(x)?);
            }
            Item::Table(t)
        }
        other => toml_edit::value(json_value(other)?),
    })
}

fn json_value(v: &Value) -> Result<toml_edit::Value, Refusal> {
    Ok(match v {
        Value::String(s) => toml_edit::Value::from(s.as_str()),
        Value::Bool(b) => toml_edit::Value::from(*b),
        Value::Number(n) => toml_edit::Value::from(n.as_i64().ok_or_else(shape)?),
        Value::Array(a) => {
            let mut arr = Array::new();
            for x in a {
                arr.push(json_value(x)?);
            }
            toml_edit::Value::Array(arr)
        }
        Value::Null | Value::Object(_) => return Err(shape()),
    })
}

/// EnvCloak's server table, changed since EnvCloak wrote it.
fn server_modified() -> Refusal {
    Refusal::new(
        "server_modified",
        format!(
            "[mcp_servers.{SERVER}] in config.toml changed since EnvCloak wrote it (a setting in it \
             is not EnvCloak's), so it was left as it is: take your change out, or remove the \
             table, and run this again"
        ),
    )
}

/// Sets `leaf` in `t` to `value`, keeping what the file has around it
/// (the Codex review: a reinstall dropped the person's comments): the
/// key and its comments stay, a value written over keeps its own
/// decoration (a trailing comment), and a table is changed key by key,
/// the keys of it `value` lacks taken out (it holds only EnvCloak's: the
/// caller checked it is what EnvCloak wrote).
fn set_kept(t: &mut Table, leaf: &str, value: &Value) -> Result<(), Refusal> {
    match (t.get_mut(leaf), value) {
        (Some(Item::Table(old)), Value::Object(m)) => {
            let stale: Vec<String> = old
                .iter()
                .map(|(k, _)| k.to_owned())
                .filter(|k| !m.contains_key(k))
                .collect();
            for k in stale {
                old.remove(&k);
            }
            for (k, x) in m {
                if old.get(k).map(item_json).as_ref() != Some(x) {
                    set_kept(old, k, x)?;
                }
            }
        }
        (Some(Item::Value(old)), v) if !v.is_object() => {
            let mut new = json_value(v)?;
            *new.decor_mut() = old.decor().clone();
            *old = new;
        }
        (Some(item), v) => *item = json_item(v)?,
        (None, v) => {
            t.insert(leaf, json_item(v)?);
        }
    }
    Ok(())
}

/// The values EnvCloak writes over, and so keeps as what was there
/// before: a boolean, or a rule's `"allow"` or `"deny"`. Anything else at
/// one of its keys is not written over (and so never copied into
/// EnvCloak's state, lesson L-12).
fn plain_previous(v: &Value) -> bool {
    matches!(v, Value::Bool(_)) || matches!(v.as_str(), Some("allow" | "deny"))
}

fn broader() -> Refusal {
    Refusal::new(
        "network_settings_present",
        "config.toml already has network settings of its own (a proxy domain rule, another \
         allowed socket, another proxy option, network access without the proxy, or a profile or \
         permission profile with network settings), which EnvCloak's socket allowance would turn \
         on or change: the allowance was not written. Add the unix_sockets rule for EnvCloak's \
         socket to your own proxy settings yourself, or remove them and run this again",
    )
}

/// The setting EnvCloak wrote at `path` (lesson L-09: its own earlier
/// write is not the person's setting).
fn written_by_envcloak(owned: &[Edit], path: &[&str], value: &Value) -> bool {
    owned.iter().any(|e| {
        matches!(e, Edit::TomlValue { path: p, value: v, .. }
            if p.iter().map(String::as_str).eq(path.iter().copied()) && v == value)
    })
}

/// With the socket allowance among `settings`: refuses a file whose own
/// settings would make it broader than command networking limited to
/// EnvCloak's socket once `network_access` and the proxy are on (Codex
/// review: existing domain and socket rules would be switched on with
/// it), or whose network access the proxy would change.
fn allowance_fits(doc: &DocumentMut, settings: &[Setting], owned: &[Edit]) -> Result<(), Refusal> {
    let Some(socket) = settings.iter().find_map(|(p, _)| match p.as_slice() {
        [f, n, u, s] if f == "features" && n == "network_proxy" && u == "unix_sockets" => {
            Some(s.as_str())
        }
        _ => None,
    }) else {
        return Ok(());
    };
    let root = doc.as_table();
    // Named permission profiles and config profiles have network settings
    // of their own, which this allowance would combine with.
    if root.contains_key("default_permissions") || root.contains_key("permissions") {
        return Err(broader());
    }
    if let Some(profiles) = root.get("profiles") {
        let Some(profiles) = profiles.as_table_like() else {
            return Err(broader());
        };
        for (_, p) in profiles.iter() {
            let Some(p) = p.as_table_like() else {
                continue;
            };
            if p.contains_key("sandbox_workspace_write")
                || p.get("features")
                    .and_then(Item::as_table_like)
                    .is_some_and(|f| f.contains_key("network_proxy"))
            {
                return Err(broader());
            }
        }
    }
    let proxy = root
        .get("features")
        .and_then(Item::as_table_like)
        .and_then(|f| f.get("network_proxy"));
    let mut proxy_on = false;
    if let Some(proxy) = proxy {
        let Some(t) = proxy.as_table_like() else {
            return Err(broader());
        };
        for (k, v) in t.iter() {
            match k {
                "enabled" => match item_json(v) {
                    Value::Bool(on) => {
                        proxy_on = on
                            && !written_by_envcloak(
                                owned,
                                &["features", "network_proxy", "enabled"],
                                &Value::Bool(true),
                            )
                    }
                    _ => return Err(broader()),
                },
                "unix_sockets" => {
                    let Some(rules) = v.as_table_like() else {
                        return Err(broader());
                    };
                    for (path, rule) in rules.iter() {
                        let rule = item_json(rule);
                        if path != socket && rule.as_str() != Some("deny") {
                            return Err(broader());
                        }
                    }
                }
                _ => return Err(broader()),
            }
        }
    }
    let access = root
        .get("sandbox_workspace_write")
        .and_then(Item::as_table_like)
        .and_then(|t| t.get("network_access"))
        .map(item_json);
    let access_mine = written_by_envcloak(
        owned,
        &["sandbox_workspace_write", "network_access"],
        &Value::Bool(true),
    );
    if access == Some(Value::Bool(true)) && !access_mine && !proxy_on {
        // Networking without the proxy: the proxy would limit it to the
        // socket, changing the person's own setting.
        return Err(broader());
    }
    Ok(())
}

/// Whether `path` is one of the socket allowance's settings
/// (`sandbox_workspace_write.network_access` and what is under
/// `[features.network_proxy]`).
pub fn is_allowance_path(path: &[String]) -> bool {
    let p: Vec<&str> = path.iter().map(String::as_str).collect();
    matches!(
        p.as_slice(),
        ["sandbox_workspace_write", "network_access"] | ["features", "network_proxy", ..]
    )
}

/// `before` (`None` for no file) with `settings` set. `owned` names the
/// settings EnvCloak wrote before, which it may change; another value
/// already at the MCP server's place is a conflict, refused. The settings
/// EnvCloak wrote before that are not among `settings` (the socket
/// allowance, once consent is not given or the Codex version was not
/// measured) are taken out first, by structure, as uninstall takes them
/// out: set back to what they held before, or removed, while they still
/// hold what EnvCloak wrote (the verifier's finding: an allowance written
/// for a measured Codex stayed in place after an upgrade, while the report
/// said it was not written).
///
/// # Errors
/// When the file is not TOML, a table on the way is not one, another
/// MCP server named `envcloak` is there, a value EnvCloak would write over
/// is not a plain one ([`plain_previous`]), or the socket allowance would
/// be broader than EnvCloak's socket ([`allowance_fits`]).
pub fn apply(
    before: Option<&[u8]>,
    settings: &[Setting],
    owned: &[Edit],
) -> Result<Edited, Refusal> {
    let text = match before {
        Some(b) => std::str::from_utf8(b).map_err(|_| not_toml())?,
        None => "",
    };
    let mut doc: DocumentMut = text.parse().map_err(|_| not_toml())?;
    let stale: Vec<Edit> = owned
        .iter()
        .filter(|e| {
            matches!(e, Edit::TomlValue { path, .. }
                if !settings.iter().any(|(p, _)| p == path))
        })
        .cloned()
        .collect();
    undo_in(&mut doc, &stale)?;
    allowance_fits(&doc, settings, owned)?;
    let mut edits = Vec::new();
    for (path, value) in settings {
        let Some((leaf, tables)) = path.split_last() else {
            continue;
        };
        let mut created = 0;
        let mut t: &mut Table = doc.as_table_mut();
        for (k, name) in tables.iter().enumerate() {
            if !t.contains_key(name) {
                let mut nt = Table::new();
                // Intermediate tables are not written as headers of their
                // own (`[mcp_servers.envcloak]`, not `[mcp_servers]` too).
                nt.set_implicit(k + 1 < tables.len() || !value.is_object());
                t.insert(name, Item::Table(nt));
                created += 1;
            }
            t = t
                .get_mut(name)
                .and_then(Item::as_table_mut)
                .ok_or_else(shape)?;
        }
        let current = t.get(leaf).map(item_json);
        if current.as_ref() == Some(value) {
            continue;
        }
        // What EnvCloak last wrote here, and what was there before it.
        let last = owned.iter().rev().find_map(|e| match e {
            Edit::TomlValue {
                path: p,
                value: v,
                previous,
                ..
            } if p == path => Some((v, previous)),
            _ => None,
        });
        let previous = match (&current, last) {
            // Not there (any more): written afresh.
            (None, _) => None,
            // Still what EnvCloak wrote: EnvCloak's to change, and what
            // was there before it stays the value to give back.
            (Some(c), Some((v, before))) if c == v => before.clone(),
            // EnvCloak's server table, changed since (a setting of the
            // person's in it): theirs now, never written over (the Codex
            // review: a reinstall replaced it whole).
            (Some(_), Some(_)) if value.is_object() => return Err(server_modified()),
            (Some(_), None) if value.is_object() => {
                return Err(Refusal::new(
                    "conflict",
                    format!(
                        "an MCP server named `{SERVER}` is already in config.toml, and EnvCloak \
                         did not write it; remove or rename it first"
                    ),
                ));
            }
            // A value of the person's, or one they set since EnvCloak
            // wrote it: what there was before.
            (Some(c), _) => Some(c.clone()),
        };
        if previous.as_ref().is_some_and(|p| !plain_previous(p)) {
            return Err(shape());
        }
        if let Some(existing) = t.get(leaf) {
            if value.is_object() != existing.is_table() {
                return Err(shape());
            }
        }
        set_kept(t, leaf, value)?;
        edits.push(Edit::TomlValue {
            path: path.clone(),
            value: value.clone(),
            previous,
            created,
        });
    }
    if edits.is_empty() && stale.is_empty() {
        return Ok(None);
    }
    Ok(Some(Change {
        bytes: doc.to_string().into_bytes(),
        added: edits,
        dropped: stale,
    }))
}

/// `current` with EnvCloak's settings taken out by structure: each set
/// back to what was there before, or removed, while it still holds what
/// EnvCloak wrote; then the tables EnvCloak made, while empty.
///
/// # Errors
/// When the file is not TOML.
pub fn undo(current: &[u8], edits: &[Edit], created_file: bool) -> Result<Undo, Refusal> {
    let text = std::str::from_utf8(current).map_err(|_| not_toml())?;
    let mut doc: DocumentMut = text.parse().map_err(|_| not_toml())?;
    undo_in(&mut doc, edits)?;
    let out = doc.to_string();
    if created_file && out.trim().is_empty() {
        return Ok(Undo::Remove);
    }
    if out.as_bytes() == current {
        return Ok(Undo::Nothing);
    }
    Ok(Undo::Rewrite(out.into_bytes()))
}

/// `doc` with the TOML `edits` taken out by structure, in reverse: each
/// set back to what was there before, or removed, while it still holds
/// what EnvCloak wrote; then the tables made for it, while empty.
fn undo_in(doc: &mut DocumentMut, edits: &[Edit]) -> Result<(), Refusal> {
    for e in edits.iter().rev() {
        let Edit::TomlValue {
            path,
            value,
            previous,
            created,
        } = e
        else {
            continue;
        };
        let Some((leaf, tables)) = path.split_last() else {
            continue;
        };
        {
            let mut t: Option<&mut Table> = Some(doc.as_table_mut());
            for name in tables {
                t = t.and_then(|t| t.get_mut(name)).and_then(Item::as_table_mut);
            }
            let Some(t) = t else { continue };
            if t.get(leaf).map(item_json).as_ref() != Some(value) {
                continue;
            }
            match previous {
                Some(p) => set_kept(t, leaf, p)?,
                None => {
                    t.remove(leaf);
                }
            }
        }
        // The tables made for it, innermost first, while empty.
        for depth in (tables.len().saturating_sub(*created)..tables.len()).rev() {
            let mut parent: Option<&mut Table> = Some(doc.as_table_mut());
            for name in &tables[..depth] {
                parent = parent
                    .and_then(|t| t.get_mut(name))
                    .and_then(Item::as_table_mut);
            }
            let Some(parent) = parent else { break };
            let empty = parent
                .get(&tables[depth])
                .and_then(Item::as_table)
                .is_some_and(Table::is_empty);
            if !empty {
                break;
            }
            parent.remove(&tables[depth]);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hunks::{hunks, unapply};

    fn run(before: &str, settings: &[Setting]) -> (String, Vec<Edit>) {
        match apply(Some(before.as_bytes()), settings, &[]) {
            Ok(Some(c)) => (String::from_utf8(c.bytes).unwrap_or_default(), c.added),
            Ok(None) => (before.to_owned(), Vec::new()),
            Err(r) => panic!("{r:?}"),
        }
    }

    #[test]
    fn settings_go_in_and_come_out_leaving_the_rest() {
        let s = config_settings(
            Path::new("/b/envcloak"),
            false,
            Some(Path::new("/r/s.sock")),
        );
        for before in [
            "",
            "[mcp_servers.fixture]\ncommand = \"/bin/echo\"\nargs = [\"a\"]\n",
            "model = \"m\" # mine\n\n[features]\nhooks = true\n",
            "[sandbox_workspace_write]\nnetwork_access = false\n",
        ] {
            let (after, edits) = run(before, &s);
            let doc: DocumentMut = after.parse().unwrap_or_else(|e| panic!("{e}\n{after}"));
            assert_eq!(
                doc["mcp_servers"]["envcloak"]["args"][1].as_str(),
                Some("--host")
            );
            assert_eq!(
                doc["features"]["network_proxy"]["unix_sockets"]["/r/s.sock"].as_str(),
                Some("allow")
            );
            assert!(!after.contains("domains"), "{after}");
            assert!(!after.contains("approval"), "{after}");
            // Again: no change.
            assert_eq!(apply(Some(after.as_bytes()), &s, &edits), Ok(None));
            // Where nothing but an insertion was made, its hunks give the
            // file back exactly; a value set over another has none.
            match hunks(before.as_bytes(), after.as_bytes()) {
                Some(h) => assert_eq!(
                    unapply(after.as_bytes(), &h).as_deref(),
                    Some(before.as_bytes())
                ),
                None => assert!(before.contains("network_access = false"), "{before}"),
            }
            // So does the structural undo, as TOML.
            let back = match undo(after.as_bytes(), &edits, before.is_empty()) {
                Ok(Undo::Rewrite(b)) => String::from_utf8(b).unwrap_or_default(),
                Ok(Undo::Remove) => String::new(),
                other => panic!("{other:?}"),
            };
            let want: DocumentMut = before.parse().unwrap_or_default();
            let got: DocumentMut = back.parse().unwrap_or_default();
            assert_eq!(
                item_json(got.as_item()),
                item_json(want.as_item()),
                "{before}\n{back}"
            );
        }
    }

    #[test]
    fn another_envcloak_server_is_a_conflict_and_bad_toml_is_refused() {
        let s = config_settings(Path::new("/b/envcloak"), false, None);
        let mine = "[mcp_servers.envcloak]\ncommand = \"/other\"\n";
        assert!(matches!(apply(Some(mine.as_bytes()), &s, &[]), Err(r) if r.name == "conflict"));
        assert!(matches!(apply(Some(b"a = 1\na = 2\n"), &s, &[]), Err(r) if r.name == "not_toml"));
        assert!(matches!(apply(Some(b"\xff"), &s, &[]), Err(r) if r.name == "not_toml"));
        assert!(matches!(
            apply(Some(b"mcp_servers = 3\n"), &s, &[]),
            Err(r) if r.name == "unexpected_shape"
        ));
    }

    /// The Codex review's finding: with consent, settings already in
    /// config.toml that `network_access` and the proxy would switch on (a
    /// domain rule, another allowed socket, another proxy option), or a
    /// network access the proxy would limit, refuse the allowance; a
    /// denied socket, an enabled proxy of the person's with nothing else,
    /// and EnvCloak's own earlier allowance do not.
    ///
    /// Mutation checked: `allowance_fits` answering `Ok(())` at once (the
    /// previous code): each refused case is written and this fails.
    #[test]
    fn the_socket_allowance_is_refused_where_it_would_be_broader() {
        let s = config_settings(
            Path::new("/b/envcloak"),
            false,
            Some(Path::new("/r/s.sock")),
        );
        for before in [
            "[features.network_proxy]\nenabled = false\n\n[features.network_proxy.domains]\n\"example.com\" = \"allow\"\n",
            "[features.network_proxy.unix_sockets]\n\"/other.sock\" = \"allow\"\n",
            "[features.network_proxy]\ndangerously_allow_all_unix_sockets = true\n",
            "[features.network_proxy]\nallow_local_binding = true\n",
            "[features]\nnetwork_proxy = true\n",
            "[sandbox_workspace_write]\nnetwork_access = true\n",
            "default_permissions = \"mine\"\n",
            "[permissions.mine.network]\nenabled = true\n",
            "[profiles.fast.features.network_proxy.domains]\n\"x.dev\" = \"allow\"\n",
            "[profiles.fast.sandbox_workspace_write]\nnetwork_access = false\n",
        ] {
            assert!(
                matches!(apply(Some(before.as_bytes()), &s, &[]), Err(r) if r.name == "network_settings_present"),
                "{before}"
            );
        }
        for before in [
            "[features.network_proxy.unix_sockets]\n\"/other.sock\" = \"deny\"\n",
            "[features.network_proxy]\nenabled = true\n",
            "[sandbox_workspace_write]\nnetwork_access = true\n\n[features.network_proxy]\nenabled = true\n",
            "[sandbox_workspace_write]\nnetwork_access = false\n",
            "[profiles.fast]\nmodel = \"m\"\n",
        ] {
            assert!(
                matches!(apply(Some(before.as_bytes()), &s, &[]), Ok(Some(_))),
                "{before}"
            );
        }
        // EnvCloak's own allowance, written before, is no obstacle.
        let (after, edits) = run("", &s);
        assert_eq!(apply(Some(after.as_bytes()), &s, &edits), Ok(None));
        // Without consent nothing is looked at.
        let plain = config_settings(Path::new("/b/envcloak"), false, None);
        assert!(matches!(
            apply(
                Some(b"[sandbox_workspace_write]\nnetwork_access = true\n"),
                &plain,
                &[]
            ),
            Ok(Some(_))
        ));
    }

    /// Lesson L-12: a value EnvCloak would write over is kept in its state
    /// as what was there before, so only a plain one (a boolean, `allow`,
    /// `deny`) is written over; anything else is refused, never copied.
    #[test]
    fn only_a_plain_value_is_written_over() {
        let s = config_settings(
            Path::new("/b/envcloak"),
            false,
            Some(Path::new("/r/s.sock")),
        );
        let odd = "[features.network_proxy.unix_sockets]\n\"/r/s.sock\" = \"anything else\"\n";
        assert!(apply(Some(odd.as_bytes()), &s, &[]).is_err());
        let (_, edits) = run("[sandbox_workspace_write]\nnetwork_access = false\n", &s);
        assert!(edits.iter().all(|e| match e {
            Edit::TomlValue { previous, .. } => previous.as_ref().is_none_or(plain_previous),
            _ => true,
        }));
    }

    /// The Codex review: a reinstall wrote EnvCloak's whole server table
    /// over the person's changes to it. A table still as EnvCloak wrote
    /// it is changed key by key (a comment of the person's in it stays);
    /// one with a setting of the person's is left, and refused; a value
    /// the person set since EnvCloak wrote it is what uninstall gives
    /// back.
    ///
    /// Mutation checked: the table replaced whole whenever EnvCloak wrote
    /// it before (the previous `t.insert` of the whole item with the
    /// recorded previous value): the person's `enabled_tools` and comment
    /// are gone and this fails.
    #[test]
    fn a_reinstall_changes_only_what_is_still_envcloaks() {
        let old = config_settings(Path::new("/old/envcloak"), false, None);
        let new = config_settings(Path::new("/new/envcloak"), false, None);
        let (after, edits) = run("model = \"m\"\n", &old);
        // The person adds a comment in EnvCloak's table: an upgrade's
        // reinstall changes the command and keeps the comment.
        let commented = after.replace(
            "[mcp_servers.envcloak]\n",
            "[mcp_servers.envcloak]\n# my note\n",
        );
        let Ok(Some(Change {
            bytes: again,
            added: more,
            ..
        })) = apply(Some(commented.as_bytes()), &new, &edits)
        else {
            panic!("not changed");
        };
        let again = String::from_utf8(again).unwrap_or_default();
        assert!(again.contains("# my note"), "{again}");
        assert!(
            again.contains("/new/envcloak") && !again.contains("/old/envcloak"),
            "{again}"
        );
        // A setting of the person's in it: left, and refused.
        let theirs = after.replace(
            "[mcp_servers.envcloak]\n",
            "[mcp_servers.envcloak]\nenabled_tools = [\"run_with_secrets\"]\n",
        );
        assert!(matches!(
            apply(Some(theirs.as_bytes()), &new, &edits),
            Err(r) if r.name == "server_modified"
        ));
        // Uninstall of the upgraded table takes it out whole.
        let mut all = edits.clone();
        all.extend(more);
        let back = match undo(again.as_bytes(), &all, false) {
            Ok(Undo::Rewrite(b)) => String::from_utf8(b).unwrap_or_default(),
            other => panic!("{other:?}"),
        };
        assert!(!back.contains("envcloak"), "{back}");
        // A value set since EnvCloak wrote it is the person's: install
        // keeps it as what was there before, with its comment.
        let s = config_settings(
            Path::new("/b/envcloak"),
            false,
            Some(Path::new("/r/s.sock")),
        );
        let (after, edits) = run("[features.network_proxy]\nenabled = true\n", &s);
        assert!(after.contains("network_access = true"), "{after}");
        let theirs = after.replace("network_access = true", "network_access = false # mine");
        let Ok(Some(Change {
            bytes: again,
            added: more,
            ..
        })) = apply(Some(theirs.as_bytes()), &s, &edits)
        else {
            panic!("not changed");
        };
        let again = String::from_utf8(again).unwrap_or_default();
        assert!(again.contains("network_access = true # mine"), "{again}");
        let mut all = edits;
        all.extend(more);
        let back = match undo(again.as_bytes(), &all, false) {
            Ok(Undo::Rewrite(b)) => String::from_utf8(b).unwrap_or_default(),
            other => panic!("{other:?}"),
        };
        assert!(back.contains("network_access = false # mine"), "{back}");
    }

    /// The verifier's finding: the version gate stopped new writes of the
    /// socket allowance, but one written earlier (for a measured Codex,
    /// with consent) stayed in config.toml after an upgrade, while the
    /// report said it was not written. A run that does not write it (no
    /// consent, an unmeasured version) takes EnvCloak's own allowance out
    /// by structure, as uninstall does, and says which edits it dropped;
    /// the server stays; a value the person had before comes back; a
    /// value the person set since is theirs and stays.
    ///
    /// Mutation checked: the stale settings left in place (`undo_in` not
    /// called for them in `apply`): `network_access` and the proxy stay,
    /// and this fails.
    #[test]
    fn an_allowance_written_before_goes_when_this_run_does_not_write_it() {
        let with = config_settings(
            Path::new("/b/envcloak"),
            false,
            Some(Path::new("/r/s.sock")),
        );
        let without = config_settings(Path::new("/b/envcloak"), false, None);
        for before in [
            "model = \"m\"\n",
            "[sandbox_workspace_write]\nnetwork_access = false\n",
        ] {
            let (after, edits) = run(before, &with);
            assert!(after.contains("unix_sockets"), "{after}");
            let Ok(Some(c)) = apply(Some(after.as_bytes()), &without, &edits) else {
                panic!("nothing taken out of {after}");
            };
            let out = String::from_utf8(c.bytes).unwrap_or_default();
            for word in ["network_proxy", "unix_sockets", "network_access = true"] {
                assert!(!out.contains(word), "{word}: {out}");
            }
            assert!(out.contains("[mcp_servers.envcloak]"), "{out}");
            assert_eq!(
                out.contains("network_access = false"),
                before.contains("network_access = false"),
                "{out}"
            );
            assert_eq!(c.dropped.len(), 3, "{:?}", c.dropped);
            assert!(c.dropped.iter().all(|e| matches!(e,
                Edit::TomlValue { path, .. } if is_allowance_path(path))));
            // Taken out already: nothing more to do, the record updated.
            match apply(Some(out.as_bytes()), &without, &edits) {
                Ok(Some(again)) => {
                    assert_eq!(again.bytes, out.as_bytes());
                    assert_eq!(again.dropped.len(), 3);
                }
                other => panic!("{other:?}"),
            }
        }
        // A value the person set since EnvCloak wrote it is theirs.
        let (after, edits) = run("model = \"m\"\n", &with);
        let theirs = after.replace("network_access = true", "network_access = false # mine");
        let Ok(Some(c)) = apply(Some(theirs.as_bytes()), &without, &edits) else {
            panic!("nothing taken out");
        };
        let out = String::from_utf8(c.bytes).unwrap_or_default();
        assert!(out.contains("network_access = false # mine"), "{out}");
        assert!(!out.contains("unix_sockets"), "{out}");
    }

    #[test]
    fn linux_gets_env_vars_and_no_socket_setting() {
        let s = config_settings(Path::new("/b/envcloak"), true, None);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].1["env_vars"][0], "XDG_RUNTIME_DIR");
    }
}
