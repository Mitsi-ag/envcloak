//! `list_secrets { project_dir? }`: the vault's items, metadata only (SPEC
//! §7): slug, class, provider, classification and field names, and, for a
//! project, which variables its `envcloak.toml` binds to which items and
//! whether each resolves. Never a value, and nothing of an item that is
//! not a secret beyond its slug and class.

use envcloak_client::fail::Failure;
use envcloak_ipc::view::{ItemClassView, ItemView};
use serde_json::{Map, Value, json};

use super::{
    Ctx, check_keys, manifest_of, object, opt_str, path_text, project_dir, refuse_value_like, shown,
};
use crate::child::Call;
use crate::router::{Annotations, Tool, ToolResult, ToolSchema};

/// The tool's name.
pub const TOOL: &str = "list_secrets";

#[derive(Debug)]
pub struct ListSecrets;

impl Tool for ListSecrets {
    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: TOOL,
            title: "List the keys EnvCloak holds",
            description: "Lists the keys in the person's EnvCloak vault by name (slug), with each \
                 one's provider and whether it is a test or live key. Never returns a value. With \
                 project_dir, also shows which variables that project's envcloak.toml binds to \
                 which keys, and whether each binding resolves. Use run_with_secrets to run a \
                 command with them; use add_reference to bind one to a variable.",
            input: object(
                json!({
                    "project_dir": {
                        "type": "string",
                        "description": "Absolute path of a project directory: its envcloak.toml \
                             (there or above) is read for its bindings.",
                    },
                }),
                &[],
            ),
            output: object(
                json!({
                    "items": {
                        "type": "array",
                        "items": object(json!({
                            "slug": {"type": "string"},
                            "class": {"type": "string"},
                            "provider": {"type": ["string", "null"]},
                            "classification": {"type": "string"},
                            "fields": {"type": "array", "items": {"type": "string"}},
                            "exposed": {"type": ["boolean", "null"]},
                        }), &["slug", "class", "provider", "classification", "fields", "exposed"]),
                    },
                    "project": {"type": ["object", "null"]},
                    "note": {"type": "string"},
                }),
                &["items", "project", "note"],
            ),
            annotations: Annotations {
                read_only: Some(true),
                open_world: Some(false),
                ..Annotations::default()
            },
        }
    }

    fn call(&self, args: &Map<String, Value>, ctx: &Ctx, _: &Call) -> ToolResult {
        match list(args, ctx) {
            Ok(v) => ToolResult::Ok(v),
            Err(f) => ToolResult::Err(f),
        }
    }
}

/// One item, as the tool shows it.
fn item(v: &ItemView) -> Value {
    let class = serde_json::to_value(v.class).unwrap_or(Value::Null);
    if v.class != ItemClassView::Secret {
        // Metadata only, and only what names it: an item that is not a
        // secret (a card, a login) is never bound or shown further.
        return json!({
            "slug": shown(&v.slug),
            "class": class,
            "provider": Value::Null,
            "classification": "unknown",
            "fields": [],
            "exposed": Value::Null,
        });
    }
    json!({
        "slug": shown(&v.slug),
        "class": class,
        "provider": v.provider.as_deref().map(shown),
        "classification": serde_json::to_value(v.classification).unwrap_or(Value::Null),
        "fields": v.fields.iter().map(|f| shown(&f.name)).collect::<Vec<_>>(),
        // Exposure ("exposed: rotate") is not tracked in this build.
        "exposed": Value::Null,
    })
}

fn list(args: &Map<String, Value>, ctx: &Ctx) -> Result<Value, Failure> {
    check_keys(args, &["project_dir"], &[])?;
    let dir = opt_str(args, "project_dir")?;
    if let Some(d) = dir {
        refuse_value_like(&[d])?;
    }
    let dir = dir.map(project_dir).transpose()?;
    let mut client = ctx.connect()?;
    let items = client.items_list(false)?;
    let project = match dir {
        None => Value::Null,
        Some(dir) => match manifest_of(&dir)? {
            None => json!({"manifest": Value::Null, "bindings": []}),
            Some(manifest) => {
                let text = path_text(&manifest)?;
                let check = client.items_check(Some(&text), &[])?;
                json!({
                    "manifest": super::shown_path(&text),
                    "name": check.project_name.as_deref().map(shown),
                    "bindings": check.bindings.iter().map(|b| json!({
                        "profile": b.profile.as_deref().map(shown),
                        "env_name": b.env_name.as_deref().map(shown),
                        "reference": b.reference.as_deref().map(shown),
                        "status": serde_json::to_value(b.status).unwrap_or(Value::Null),
                    })).collect::<Vec<_>>(),
                })
            }
        },
    };
    Ok(json!({
        "items": items.items.iter().map(item).collect::<Vec<_>>(),
        "project": project,
        "note": "Names and metadata only: EnvCloak never returns a key's value. `exposed` is null: \
             exposure is not tracked in this build.",
    }))
}
