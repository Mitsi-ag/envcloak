//! What `tools/list` shows, byte for byte against a snapshot
//! (tests/snapshots/tools-list.json; `ENVCLOAK_SNAPSHOT_UPDATE=1` writes it
//! instead), and the rules the snapshot must keep (SPEC §7, D-22): the five
//! M2 tools and no other, so no reveal, doctor or `usage_summary` tool;
//! `readOnlyHint` on `list_secrets`, `project_status` and
//! `request_new_secret`; `destructiveHint` and `openWorldHint` on
//! `run_with_secrets`, which never carries `readOnlyHint`; no tool with
//! both a read-only and a destructive hint; and every input schema closed
//! (`additionalProperties: false`). Annotations are hints a host may
//! ignore: whether each host asks is tested against the real hosts.
#![allow(clippy::unwrap_used)]

use std::path::Path;

use envcloak_mcp::{Server, ToolSchema};
use serde_json::Value;

fn listed() -> Value {
    let tools: Vec<Value> = Server::new()
        .tools()
        .iter()
        .map(ToolSchema::to_json)
        .collect();
    serde_json::json!({ "tools": tools })
}

#[test]
fn tools_list_matches_its_snapshot() {
    let got = serde_json::to_string_pretty(&listed()).unwrap() + "\n";
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/snapshots/tools-list.json");
    if std::env::var_os("ENVCLOAK_SNAPSHOT_UPDATE").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &got).unwrap();
    }
    let want = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("no snapshot: run with ENVCLOAK_SNAPSHOT_UPDATE=1"));
    assert_eq!(
        got, want,
        "tools/list changed; review it and update the snapshot"
    );
}

#[test]
fn the_annotations_and_schemas_keep_their_rules() {
    let v = listed();
    let tools = v["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        [
            "list_secrets",
            "project_status",
            "add_reference",
            "run_with_secrets",
            "request_new_secret"
        ]
    );
    for t in tools {
        let name = t["name"].as_str().unwrap();
        for word in ["reveal", "doctor", "usage"] {
            assert!(!name.contains(word), "{name}");
        }
        let a = &t["annotations"];
        assert!(
            !(a["readOnlyHint"] == true && a["destructiveHint"] == true),
            "{name} carries both a read-only and a destructive hint"
        );
        assert_eq!(t["inputSchema"]["type"], "object", "{name}");
        assert_eq!(t["inputSchema"]["additionalProperties"], false, "{name}");
        assert_eq!(t["outputSchema"]["type"], "object", "{name}");
        match name {
            "list_secrets" | "project_status" | "request_new_secret" => {
                assert_eq!(a["readOnlyHint"], true, "{name}");
                assert!(a.get("destructiveHint").is_none(), "{name}");
            }
            "run_with_secrets" => {
                assert!(a.get("readOnlyHint").is_none(), "{name}");
                assert_eq!(a["destructiveHint"], true);
                assert_eq!(a["openWorldHint"], true);
            }
            "add_reference" => {
                assert_eq!(a["readOnlyHint"], false);
                assert_eq!(a["destructiveHint"], false);
            }
            _ => panic!("{name}"),
        }
    }
    // The descriptions state the inject-mode limit (R-M2-02) and the
    // terminal approval (T-15), and never name a feature that has not
    // shipped as available (R-M2-01).
    let run = tools
        .iter()
        .find(|t| t["name"] == "run_with_secrets")
        .unwrap();
    let d = run["description"].as_str().unwrap();
    assert!(d.contains("outside this host's sandbox"), "{d}");
    assert!(d.contains("holds the injected keys"), "{d}");
    assert!(d.contains("terminal of their own"), "{d}");
    for t in tools {
        let d = t["description"].as_str().unwrap();
        assert!(!d.contains("--ask"), "{d}");
        assert!(!d.contains("paste sheet"), "{d}");
    }
}

/// `run_with_secrets` claims what SPEC §1.1 and §6.1 establish and no more
/// (R-M2-02, R-M2-03, L-15): each key and its common encodings are masked
/// in the command's output, output the command transforms is not, and the
/// command holds the keys while it runs, outside the host's sandbox.
///
/// Mutation checked: the round-2 description ("Values never come back:
/// each key and its common encodings are masked in the output"): this
/// fails.
#[test]
fn run_with_secrets_claims_no_more_than_masking_does() {
    let v = listed();
    let tools = v["tools"].as_array().unwrap();
    let run = tools
        .iter()
        .find(|t| t["name"] == "run_with_secrets")
        .unwrap();
    let d = run["description"].as_str().unwrap();
    for part in [
        "each key, and its common encodings, are masked",
        "output the command transforms",
        "is not",
        "outside this host's sandbox",
        "holds the injected keys",
    ] {
        assert!(d.contains(part), "{part}: {d}");
    }
    assert!(!d.contains("never come back"), "{d}");
}
