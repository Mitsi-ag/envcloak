//! The combined-graph compile gate (M2 plan F-75, D-02): the host catalog
//! in `envcloak-agents` emits the scanner's own descriptors
//! (`envcloak_scan::source::ConfigSource`), and the scanner never depends
//! on the catalog. A tiny fixture home is cataloged here and its sources
//! compile against, and are read as, the scanner's types (M2-12 extends
//! this test to assert a finding, M2-20 a migration plan). Cargo's own view
//! of the graph is the second half: `envcloak-scan` declares no dependency
//! on the agents crate or anything built on it, while `envcloak-agents`
//! depends on the scanner (its hook reuses `dotenv_kind`).
#![allow(clippy::unwrap_used)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use envcloak_agents::locations::Locations;
use envcloak_scan::source::{ConfigFormat, ConfigSource, SourceKind};

fn fixture_home() -> tempfile::TempDir {
    let home = tempfile::Builder::new()
        .prefix("ec-cg")
        .tempdir_in("/tmp")
        .unwrap();
    let h = home.path();
    std::fs::create_dir_all(h.join(".claude/projects/p")).unwrap();
    std::fs::create_dir_all(h.join(".codex/sessions")).unwrap();
    std::fs::write(h.join(".claude.json"), b"{\"mcpServers\": {}}\n").unwrap();
    std::fs::write(h.join(".claude/settings.json"), b"{}\n").unwrap();
    std::fs::write(h.join(".claude/projects/p/s.jsonl"), b"{}\n").unwrap();
    std::fs::write(h.join(".codex/config.toml"), b"model = \"m\"\n").unwrap();
    home
}

fn catalog(home: &Path) -> Locations {
    let home = home.to_path_buf();
    Locations::new(&move |k| (k == "HOME").then(|| OsString::from(&home))).unwrap()
}

/// What the scanner gets: its own type, by name, from the catalog.
fn present(sources: Vec<ConfigSource>) -> Vec<(PathBuf, ConfigFormat, SourceKind, String)> {
    sources
        .into_iter()
        .filter(|s| s.path.exists())
        .map(|s| (s.path, s.format, s.source_kind, s.label))
        .collect()
}

#[test]
fn a_fixture_catalog_emits_the_scanners_descriptors() {
    let home = fixture_home();
    let h = home.path();
    let l = catalog(h);
    let config = present(l.config_sources());
    assert_eq!(
        config,
        vec![
            (
                h.join(".claude.json"),
                ConfigFormat::Json,
                SourceKind::McpConfig,
                "Claude Code user config".to_owned()
            ),
            (
                h.join(".claude/settings.json"),
                ConfigFormat::Json,
                SourceKind::McpConfig,
                "Claude Code user settings".to_owned()
            ),
            (
                h.join(".codex/config.toml"),
                ConfigFormat::Toml,
                SourceKind::McpConfig,
                "Codex config".to_owned()
            ),
        ]
    );
    let stores = present(l.transcript_sources());
    assert!(stores.contains(&(
        h.join(".claude/projects"),
        ConfigFormat::Jsonl,
        SourceKind::Transcript,
        "Claude Code transcripts".to_owned()
    )));
    assert!(stores.contains(&(
        h.join(".codex/sessions"),
        ConfigFormat::Jsonl,
        SourceKind::Transcript,
        "Codex sessions".to_owned()
    )));
    // Every path is in the fixture home: the catalog names nothing else.
    for s in l.config_sources().iter().chain(&l.transcript_sources()) {
        assert!(s.path.starts_with(h), "{}", s.path.display());
    }
}

/// The workspace dependencies each package declares, normal and build
/// (dev-dependencies are a test's own business), by package name.
fn declared(package: &str) -> Vec<String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out = Command::new(env!("CARGO"))
        .current_dir(&root)
        .args(["metadata", "--format-version", "1", "--no-deps", "--offline"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let meta: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let pkg = meta["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == package)
        .unwrap();
    pkg["dependencies"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|d| d["kind"] != "dev")
        .map(|d| d["name"].as_str().unwrap().to_owned())
        .filter(|n| n.starts_with("envcloak"))
        .collect()
}

#[test]
fn the_graph_is_agents_to_scan_and_never_back() {
    let scan = declared("envcloak-scan");
    for never in ["envcloak-agents", "envcloak-mcp", "envcloak-client", "envcloak"] {
        assert!(!scan.iter().any(|d| d == never), "scan -> {never}: {scan:?}");
    }
    // Control: the edge the check would see is there the other way.
    let agents = declared("envcloak-agents");
    assert!(agents.iter().any(|d| d == "envcloak-scan"), "{agents:?}");
}
