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
use crate::writer::{Edit, Edited, Refusal, Undo};

/// The MCP server's name.
pub const SERVER: &str = "envcloak";

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

/// `before` (`None` for no file) with `settings` set. `owned` names the
/// settings EnvCloak wrote before, which it may change; another value
/// already at the MCP server's place is a conflict, refused.
///
/// # Errors
/// When the file is not TOML, a table on the way is not one, or another
/// MCP server named `envcloak` is there.
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
        let previous = t.get(leaf).map(item_json);
        if previous.as_ref() == Some(value) {
            continue;
        }
        let ours = owned.iter().find_map(|e| match e {
            Edit::TomlValue {
                path: p, previous, ..
            } if p == path => Some(previous.clone()),
            _ => None,
        });
        let previous = match ours {
            // Written by EnvCloak before: what was there before it.
            Some(p) => p,
            None if value.is_object() && previous.is_some() => {
                return Err(Refusal::new(
                    "conflict",
                    format!(
                        "an MCP server named `{SERVER}` is already in config.toml, and EnvCloak \
                         did not write it; remove or rename it first"
                    ),
                ));
            }
            None => previous,
        };
        if let Some(existing) = t.get(leaf) {
            if value.is_object() != existing.is_table() {
                return Err(shape());
            }
        }
        t.insert(leaf, json_item(value)?);
        edits.push(Edit::TomlValue {
            path: path.clone(),
            value: value.clone(),
            previous,
            created,
        });
    }
    if edits.is_empty() {
        return Ok(None);
    }
    Ok(Some((doc.to_string().into_bytes(), edits)))
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
                Some(p) => {
                    t.insert(leaf, json_item(p)?);
                }
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
    let out = doc.to_string();
    if created_file && out.trim().is_empty() {
        return Ok(Undo::Remove);
    }
    if out.as_bytes() == current {
        return Ok(Undo::Nothing);
    }
    Ok(Undo::Rewrite(out.into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jsonedit::splice;

    fn run(before: &str, settings: &[Setting]) -> (String, Vec<Edit>) {
        match apply(Some(before.as_bytes()), settings, &[]) {
            Ok(Some((b, e))) => (String::from_utf8(b).unwrap_or_default(), e),
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
            // The exact splice gives the file back.
            assert_eq!(splice(before, &after).undo(&after).as_deref(), Some(before));
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

    #[test]
    fn linux_gets_env_vars_and_no_socket_setting() {
        let s = config_settings(Path::new("/b/envcloak"), true, None);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].1["env_vars"][0], "XDG_RUNTIME_DIR");
    }
}
