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

/// The catalog of `home`, the hosts' temporary directories in it too.
fn catalog(home: &Path) -> Locations {
    let home = home.to_path_buf();
    Locations::new(&move |k| match k {
        "HOME" => Some(OsString::from(&home)),
        "CLAUDE_CODE_TMPDIR" => Some(home.join("claude-tmp").into_os_string()),
        "TMPDIR" => Some(home.join("tmp").into_os_string()),
        _ => None,
    })
    .unwrap()
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
        ConfigFormat::Mixed,
        SourceKind::Transcript,
        "Claude Code transcripts and tool results".to_owned()
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
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--offline",
        ])
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
    for never in [
        "envcloak-agents",
        "envcloak-mcp",
        "envcloak-client",
        "envcloak",
    ] {
        assert!(
            !scan.iter().any(|d| d == never),
            "scan -> {never}: {scan:?}"
        );
    }
    // Control: the edge the check would see is there the other way.
    let agents = declared("envcloak-agents");
    assert!(agents.iter().any(|d| d == "envcloak-scan"), "{agents:?}");
}

/// Codex review: the catalog left out documented stores (Claude Code's
/// `debug/`, `plans/` and temporary directory, Codex's `hook_outputs/`),
/// and its tests checked chosen fixtures only. The catalog's stores are
/// checked against two lists it does not make: every store the test kit
/// sweeps, which M2-04 saw the pinned hosts write
/// (`envcloak_testkit::transcripts::transcript_roots`), and Map C section
/// 4's documented ones. Each needs a source that reads it: the same path
/// or a directory above it read whole, or, for files kept among others,
/// the directory with the same name filter.
///
/// Mutation checked: Claude Code's `debug/` source taken out of
/// `transcript_sources`: the test kit's `claude/debug` is uncovered and
/// this fails.
#[test]
fn every_store_the_hosts_write_has_a_source() {
    use envcloak_testkit::agents::Host;
    use envcloak_testkit::transcripts::{HostDirs, Shape, transcript_roots};
    let home = fixture_home();
    let h = home.path();
    let l = catalog(h);
    let mut sources = l.config_sources();
    sources.extend(l.transcript_sources());
    let covers = |path: &Path, names: Option<&str>| {
        sources.iter().any(|s| match (names, &s.names) {
            (None, None) => path.starts_with(&s.path),
            (Some(n), Some(m)) => s.path == path && m == n,
            _ => false,
        })
    };
    let dirs = HostDirs {
        home: h.to_path_buf(),
        codex_home: h.join(".codex"),
        claude_tmp: h.join("claude-tmp"),
    };
    let mut checked = 0;
    for host in [Host::ClaudeCode, Host::Codex] {
        for store in transcript_roots(host, &dirs) {
            let ok = match store.shape {
                Shape::Dir | Shape::File => covers(&store.path, None),
                Shape::Named(part) => covers(&store.path, Some(part)),
            };
            assert!(ok, "{}: {} has no source", store.name, store.path.display());
            checked += 1;
        }
    }
    assert!(checked >= 20, "{checked}");
    // Documented stores the test kit does not sweep (the documentation's
    // own list is read whole below).
    for p in [
        h.join(".claude/plans"),
        h.join(".claude/projects/p/s/tool-results/t.txt"),
        l.claude_tmp_dir().join("p/s/scratchpad"),
        l.claude_tmp_dir().join("p/s/images"),
        h.join("tmp/hook_outputs/s/u.txt"),
    ] {
        assert!(covers(&p, None), "{} has no source", p.display());
    }
    // Control: a path no store holds is not covered.
    assert!(!covers(&h.join("project/.env"), None));
}

/// One row of docs/INSTALLERS.md's catalog table: the host, the store's
/// path at its default place, what it is.
struct Row {
    host: String,
    store: String,
    kind: String,
}

/// The rows between `<!-- catalog -->` and `<!-- /catalog -->`.
fn documented() -> Vec<Row> {
    let doc = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/INSTALLERS.md"),
    )
    .unwrap();
    let (_, rest) = doc.split_once("<!-- catalog -->").unwrap();
    let (table, _) = rest.split_once("<!-- /catalog -->").unwrap();
    table
        .lines()
        .filter(|l| l.starts_with("| ") && !l.starts_with("| Host"))
        .map(|l| {
            let cells: Vec<&str> = l.trim_matches('|').split(" | ").map(str::trim).collect();
            assert_eq!(cells.len(), 3, "{l}");
            Row {
                host: cells[0].to_owned(),
                store: cells[1].trim_matches('`').to_owned(),
                kind: cells[2].to_owned(),
            }
        })
        .collect()
}

/// A documented store's path in the fixture home: `~` the home,
/// `$CLAUDE_CODE_TMPDIR` and `$TMPDIR` the fixture's, `<project>` a
/// project, any other `<...>` a sample name, and a directory (`/` at the
/// end) a file in it.
fn expand(store: &str, h: &Path, l: &Locations, project: &Path) -> PathBuf {
    let tmp = l.claude_tmp_dir();
    let mut s = store
        .replacen(
            "$CLAUDE_CODE_TMPDIR/claude-<uid>",
            &tmp.to_string_lossy(),
            1,
        )
        .replacen(
            "$CLAUDE_CODE_TMPDIR",
            &h.join("claude-tmp").to_string_lossy(),
            1,
        )
        .replacen("$TMPDIR", &h.join("tmp").to_string_lossy(), 1)
        .replacen("<project>", &project.to_string_lossy(), 1);
    if let Some(rest) = s.strip_prefix("~/") {
        s = h.join(rest).to_string_lossy().into_owned();
    }
    while let (Some(a), Some(b)) = (s.find('<'), s.find('>')) {
        assert!(a < b, "{store}");
        s.replace_range(a..=b, "x1");
    }
    if s.ends_with('/') {
        s.push('f');
    }
    assert!(Path::new(&s).is_absolute(), "{store}");
    PathBuf::from(s)
}

/// Whether `source` reads the file at `path`.
fn reads(source: &ConfigSource, path: &Path) -> bool {
    match &source.names {
        None => path.starts_with(&source.path),
        Some(n) => {
            path.parent() == Some(source.path.as_path())
                && path
                    .file_name()
                    .is_some_and(|f| f.to_string_lossy().contains(n.as_str()))
        }
    }
}

/// Codex review, round 7 (medium): the catalog left out documented stores
/// (Copilot CLI's `mcp-secrets/`, OpenCode's `auth.json`, Claude Code's
/// `tasks/`), and its test checked a list of its own making. The list is
/// now the documentation's: docs/INSTALLERS.md's catalog table, every
/// store Map C and SPEC §6.6 name, each at its default place, read here
/// against the catalog both ways: every row has a source that reads it
/// (an agent's credential store as `SourceKind::Credentials`), and every
/// source reads a row. The three stores Codex named are asserted by name
/// too. Control: a file no store holds has no source.
///
/// Mutations checked: Copilot CLI's `mcp-secrets/` source taken out of
/// `config_sources`: its row has no source and this fails; a row taken
/// out of the table (Claude Code's `telemetry/`): its source reads no row
/// and this fails; OpenCode's `auth.json` given `SourceKind::McpConfig`:
/// the credential row's kind fails.
#[test]
fn every_documented_store_has_a_source_and_every_source_a_row() {
    let home = fixture_home();
    let h = home.path();
    let l = catalog(h);
    let project = h.join("proj");
    let mut sources = l.config_sources();
    sources.extend(l.transcript_sources());
    sources.extend(Locations::project_config_sources(&project));
    let rows = documented();
    assert!(rows.len() >= 40, "{}", rows.len());
    let mut misses = Vec::new();
    let mut read = vec![false; sources.len()];
    for r in &rows {
        let path = expand(&r.store, h, &l, &project);
        let by: Vec<usize> = (0..sources.len())
            .filter(|&i| reads(&sources[i], &path))
            .collect();
        if by.is_empty() {
            misses.push(format!("{} {}: no source reads it", r.host, r.store));
        }
        if r.kind.contains("reported, not migrated")
            && !by
                .iter()
                .any(|&i| sources[i].source_kind == SourceKind::Credentials)
        {
            misses.push(format!("{} {}: not a credential store", r.host, r.store));
        }
        for i in by {
            read[i] = true;
        }
    }
    for (s, r) in sources.iter().zip(&read) {
        if !r {
            misses.push(format!("{} ({}): in no row", s.label, s.path.display()));
        }
    }
    for named in [
        "~/.copilot/mcp-secrets/",
        "~/.local/share/opencode/auth.json",
        "~/.claude/tasks/",
    ] {
        if !rows.iter().any(|r| r.store == named) {
            misses.push(format!("{named}: not documented"));
        }
    }
    assert!(misses.is_empty(), "{misses:#?}");
    // Control: a file no store holds.
    let stray = h.join("proj/.env");
    assert!(!sources.iter().any(|s| reads(s, &stray)));
}

/// Codex's `config.toml` moves its SQLite state (`sqlite_home`) and its
/// logs (`log_dir`; Map C section 2.2), read as Codex reads a path there:
/// a relative one from Codex's directory, `~/` from the home. The moved
/// places are named beside the default ones; a value naming Codex's own
/// directory adds nothing.
///
/// Mutation checked: `codex_moved` not read (both `None`): the moved
/// places are not named and this fails.
#[test]
fn codex_settings_that_move_its_stores_are_read() {
    let home = fixture_home();
    let h = home.path();
    std::fs::write(
        h.join(".codex/config.toml"),
        "model = \"m\"\nsqlite_home = \"db\"\nlog_dir = \"~/codex-logs\"\n",
    )
    .unwrap();
    let stores = catalog(h).transcript_sources();
    assert!(stores.iter().any(|s| s.path == h.join(".codex/db")
        && s.names.as_deref() == Some(".sqlite")
        && s.source_kind == SourceKind::Database));
    assert!(
        stores
            .iter()
            .any(|s| s.path == h.join("codex-logs") && s.source_kind == SourceKind::Log)
    );
    // The defaults stay.
    assert!(stores.iter().any(|s| s.path == h.join(".codex/log")));
    // Codex's own directory: nothing added.
    std::fs::write(
        h.join(".codex/config.toml"),
        format!("sqlite_home = \"{}\"\n", h.join(".codex").display()),
    )
    .unwrap();
    let n = catalog(h)
        .transcript_sources()
        .iter()
        .filter(|s| s.names.as_deref() == Some(".sqlite"))
        .count();
    assert_eq!(n, 1);
}

/// F-75's compile-only fixture now crosses the actual scanner boundary.
#[test]
fn fixture_catalog_sources_produce_a_finding() {
    let home = fixture_home();
    std::fs::write(
        home.path().join(".claude.json"),
        br#"{"mcpServers":{"fixture":{"env":{"TOKEN":"fixture-catalog-value"}}}}"#,
    )
    .unwrap();
    let report =
        envcloak_scan::scan_config_sources(&catalog(home.path()).config_sources()).unwrap();
    assert_eq!(report.findings.len(), 1);
    assert!(
        report.findings[0]
            .value
            .as_ref()
            .unwrap()
            .ct_eq(b"fixture-catalog-value")
    );
}

/// The documented provider config is an inspection source, not an MCP server.
#[test]
fn provider_config_paths_stay_in_the_catalog() {
    let home = fixture_home();
    let path = home.path().join(".config/codexbar/config.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        &path,
        br#"{"version":1,"providers":[{"id":"fixture","apiKey":"fixture-provider-value"}]}"#,
    )
    .unwrap();
    let sources = catalog(home.path()).config_sources();
    assert!(
        sources
            .iter()
            .any(|s| s.path == path && s.source_kind == SourceKind::ProviderConfig)
    );
    let report = envcloak_scan::scan_config_sources(&sources).unwrap();
    assert!(report.findings.iter().any(|f| {
        f.value
            .as_ref()
            .is_some_and(|v| v.ct_eq(b"fixture-provider-value"))
    }));
}
