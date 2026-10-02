//! `request_new_secret { provider }`: what to ask the person when a key
//! does not exist yet (SPEC §7, D-20). In M2 it takes no value and returns
//! the terminal instruction: the person runs `envcloak add <provider>` in
//! a terminal of their own and types or pastes the key at its hidden
//! prompt. From M3 the app's paste sheet takes its place. A provider the
//! registry does not know is not echoed: the instruction is then plain
//! `envcloak add`, which tells the provider from the key's shape.

use envcloak_client::fail::Failure;
use serde_json::{Map, Value, json};

use super::{Ctx, check_keys, object, refuse_value_like, req_str};
use crate::child::Call;
use crate::router::{Annotations, Tool, ToolResult, ToolSchema};

/// The tool's name.
pub const TOOL: &str = "request_new_secret";

#[derive(Debug)]
pub struct RequestNewSecret;

impl Tool for RequestNewSecret {
    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: TOOL,
            title: "Ask the person to add a key",
            description: "Use when a key the project needs is not in EnvCloak (list_secrets does \
                 not show it). Takes the provider's name only, never a key, and returns what to \
                 ask the person: to run `envcloak add <provider>` in a terminal of their own and \
                 enter the key at its hidden prompt. Never ask the person to paste a key into \
                 this conversation. In this version EnvCloak has no app to paste into.",
            input: object(
                json!({
                    "provider": {
                        "type": "string",
                        "description": "The provider's name in EnvCloak's registry, such as \
                             openai, stripe or github.",
                    },
                }),
                &["provider"],
            ),
            output: object(
                json!({
                    "provider": {"type": ["string", "null"]},
                    "command": {"type": "string"},
                    "instruction": {"type": "string"},
                }),
                &["provider", "command", "instruction"],
            ),
            annotations: Annotations {
                read_only: Some(true),
                open_world: Some(false),
                ..Annotations::default()
            },
        }
    }

    fn call(&self, args: &Map<String, Value>, _: &Ctx, _: &Call) -> ToolResult {
        match request(args) {
            Ok(v) => ToolResult::Ok(v),
            Err(f) => ToolResult::Err(f),
        }
    }
}

fn request(args: &Map<String, Value>) -> Result<Value, Failure> {
    check_keys(args, &["provider"], &["provider"])?;
    let provider = req_str(args, "provider")?;
    refuse_value_like(&[provider])?;
    let known = envcloak_client::render::registry()
        .and_then(|r| r.get(provider))
        .map(|p| p.id.as_str().to_owned());
    let command = match &known {
        Some(id) => format!("envcloak add {id}"),
        None => "envcloak add".to_owned(),
    };
    let mut instruction = format!(
        "Ask the person to run `{command}` in a terminal of their own, not through you, and to \
         enter the key at its hidden prompt. Never ask them to paste a key into this \
         conversation. Once it is added, bind it with add_reference and run the command with \
         run_with_secrets."
    );
    if known.is_none() {
        instruction.push_str(
            " EnvCloak's registry has no provider of that name: `envcloak add` tells the provider \
             from the key's shape, or adds the key without one.",
        );
    }
    Ok(json!({
        "provider": known,
        "command": command,
        "instruction": instruction,
    }))
}
