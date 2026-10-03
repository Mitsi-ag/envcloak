//! The files in `integrations/` (M2 plan M2-08) are what the installer
//! writes, with `envcloak` found on `PATH` instead of an absolute path: the
//! Claude Code plugin's skill, hooks and MCP server, and Codex's hooks and
//! rules. A change to one without the other fails here.
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use envcloak_agents::blocks::INSTRUCTIONS;
use envcloak_agents::hosts::{claude, codex};
use serde_json::{Map, Value, json};

fn integrations() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../integrations")
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(integrations().join(rel)).unwrap()
}

fn json_file(rel: &str) -> Value {
    serde_json::from_str(&read(rel)).unwrap()
}

/// The `{"hooks": {...}}` file the installer's additions make.
fn hooks_file(additions: Vec<(Vec<&'static str>, Value)>) -> Value {
    let mut events = Map::new();
    for (path, value) in additions {
        if path[0] != "hooks" {
            continue;
        }
        events
            .entry(path[1])
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .unwrap()
            .push(value);
    }
    json!({ "hooks": events })
}

#[test]
fn the_claude_code_plugin_is_the_installers_integration() {
    let skill = read("claude-code/skills/envcloak/SKILL.md");
    let (front, body) = skill
        .strip_prefix("---\n")
        .unwrap()
        .split_once("\n---\n\n")
        .unwrap();
    assert!(front.starts_with("name: envcloak\ndescription: "), "{front}");
    assert_eq!(body, format!("{INSTRUCTIONS}\n"));
    let envcloak = Path::new("envcloak");
    assert_eq!(
        json_file("claude-code/hooks/hooks.json"),
        hooks_file(claude::settings_additions(envcloak, None, Path::new("/d")))
    );
    assert_eq!(
        json_file("claude-code/.mcp.json"),
        json!({ "mcpServers": { "envcloak": claude::mcp_entry(envcloak) } })
    );
    let manifest = json_file("claude-code/.claude-plugin/plugin.json");
    assert_eq!(manifest["name"], "envcloak");
    // The plugin is how claude::plugin_enabled recognizes it.
    assert!(claude::plugin_enabled(
        &json!({"enabledPlugins": {"envcloak@marketplace": true}})
    ));
}

#[test]
fn the_codex_files_are_the_installers() {
    assert_eq!(
        json_file("codex/hooks.json"),
        hooks_file(codex::hooks_additions(Path::new("envcloak")))
    );
    assert_eq!(read("codex/envcloak.rules"), codex::RULES);
}
