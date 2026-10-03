//! `add_reference { project_dir, env_name, slug, profile? }`: binds a
//! variable to a vault item in the project's `envcloak.toml`, as `envcloak
//! ref` does (the client's manifest editor, which keeps everything else in
//! the file and replaces it atomically). Only an item of the `secret`
//! class can be bound: the daemon is asked what the slug names first, and
//! anything else, or a slug no item has, is refused before the file is
//! touched. A name shaped like a key is refused unechoed. A binding written
//! is a request for approval later, not an approval: the next run asks.

use envcloak_client::fail::Failure;
use envcloak_client::manifest_edit::edit_manifest_ref;
use envcloak_ipc::proto::ErrorKind;
use envcloak_ipc::view::ItemClassView;
use envcloak_ipc::{ClientError, RpcError};
use envcloak_policy::{Binding, ProfileName};
use serde_json::{Map, Value, json};

use super::{
    Ctx, check_keys, invalid, manifest_of, object, opt_str, path_text, project_dir,
    refuse_value_like, req_str, shown, shown_path,
};
use crate::child::Call;
use crate::router::{Annotations, Tool, ToolResult, ToolSchema};

/// The tool's name.
pub const TOOL: &str = "add_reference";

#[derive(Debug)]
pub struct AddReference;

impl Tool for AddReference {
    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: TOOL,
            title: "Bind a variable to a key in envcloak.toml",
            description: "Adds a binding to the project's envcloak.toml: the variable env_name \
                 will get the key the slug names when a command runs through EnvCloak. Takes \
                 names only, never a value; only keys of the secret class can be bound (find them \
                 with list_secrets). The binding is a request, not an approval: the next run that \
                 uses it asks the person.",
            input: object(
                json!({
                    "project_dir": {
                        "type": "string",
                        "description": "Absolute path of the project directory; its envcloak.toml \
                             (there or above) is edited.",
                    },
                    "env_name": {
                        "type": "string",
                        "description": "The environment variable, such as OPENAI_API_KEY.",
                    },
                    "slug": {
                        "type": "string",
                        "description": "The key's slug as list_secrets shows it, optionally with \
                             #<field>.",
                    },
                    "profile": {
                        "type": "string",
                        "description": "A profile ([env.<profile>]) instead of [env].",
                    },
                }),
                &["project_dir", "env_name", "slug"],
            ),
            output: object(
                json!({
                    "manifest": {"type": "string"},
                    "profile": {"type": ["string", "null"]},
                    "env_name": {"type": "string"},
                    "reference": {"type": "string"},
                    "change": {"type": "string"},
                    "previous": {"type": ["string", "null"]},
                    "resolves": {"type": ["string", "null"]},
                    "note": {"type": "string"},
                }),
                &["manifest", "env_name", "reference", "change", "note"],
            ),
            annotations: Annotations {
                read_only: Some(false),
                destructive: Some(false),
                idempotent: Some(true),
                open_world: Some(false),
            },
        }
    }

    fn call(&self, args: &Map<String, Value>, ctx: &Ctx, call: &Call) -> ToolResult {
        match add(args, ctx, call) {
            Ok(v) => ToolResult::Ok(v),
            Err(f) => ToolResult::Err(f),
        }
    }
}

fn add(args: &Map<String, Value>, ctx: &Ctx, call: &Call) -> Result<Value, Failure> {
    check_keys(
        args,
        &["project_dir", "env_name", "slug", "profile"],
        &["project_dir", "env_name", "slug"],
    )?;
    let dir = req_str(args, "project_dir")?;
    let env_name = req_str(args, "env_name")?;
    let reference = req_str(args, "slug")?;
    let profile = opt_str(args, "profile")?;
    // A value pasted in place of a name is refused as one, before its
    // grammar is looked at, and never echoed.
    let mut names = vec![dir, env_name];
    names.extend(reference.split('#'));
    names.extend(profile);
    refuse_value_like(&names)?;
    if env_name.contains('=') {
        return Err(invalid());
    }
    let binding = Binding::parse_arg(&format!("{env_name}={reference}")).map_err(|_| {
        Failure::new(
            "invalid_reference",
            "env_name must be a variable name and slug a slug, optionally with #<field>; nothing \
             was written",
        )
    })?;
    let profile = profile
        .map(ProfileName::new)
        .transpose()
        .map_err(|_| Failure::new("invalid_profile_name", "the profile name is invalid"))?;
    let dir = project_dir(dir)?;

    // What the slug names, from the daemon: only a secret can be bound.
    let mut client = ctx.connect(call)?;
    let item = match client.items_show(binding.reference.slug.as_str()) {
        Ok(item) => item,
        Err(ClientError::Rpc(RpcError {
            kind: ErrorKind::NoSuchItem,
            ..
        })) => {
            return Err(Failure::new(
                "no_such_item",
                "no item has that slug (list_secrets shows the slugs); nothing was written",
            ));
        }
        Err(e) => return Err(e.into()),
    };
    if item.class != ItemClassView::Secret {
        return Err(Failure::new(
            "not_secret",
            "that slug names an item that is not a secret, which is never bound to a variable; \
             nothing was written",
        ));
    }
    let manifest = manifest_of(&dir)?.ok_or_else(|| {
        Failure::new(
            "manifest_invalid",
            "no envcloak.toml in project_dir or above it: the person runs `envcloak init` there \
             first; nothing was written",
        )
    })?;
    let edit = edit_manifest_ref(&manifest, &binding, profile.as_ref())?;
    let text = format!("{}={}", binding.env_name, binding.reference);
    let resolves = client
        .items_check(None, &[text])
        .ok()
        .and_then(|v| v.refs.first().copied());
    Ok(json!({
        "manifest": shown_path(&path_text(&manifest)?),
        "profile": profile.as_ref().map(|p| shown(p.as_str())),
        "env_name": shown(binding.env_name.as_str()),
        "reference": shown(&binding.reference.to_string()),
        "change": serde_json::to_value(edit.change).unwrap_or(Value::Null),
        "previous": edit.previous.map(|r| shown(&r.to_string())),
        "resolves": resolves.and_then(|r| serde_json::to_value(r).ok()),
        "note": "A binding is a request, not an approval: the next run that uses it asks the \
             person in EnvCloak.",
    }))
}
