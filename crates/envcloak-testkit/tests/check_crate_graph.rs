//! `scripts/check-crate-graph.py` (M2 plan D-02, F-75) on the workspace and
//! on fixture workspaces that Cargo itself reads: the workspace passes; the
//! cycle Codex's cycle173 fixture reproduced (`agents -> scan` and `scan ->
//! agents`, which Cargo refuses too) and a single forbidden edge Cargo
//! accepts (`scan -> client`) are refused by name; an edge outside the
//! table is refused in every form a manifest can give it; the planned
//! one-way graph passes; and a table that allowed a forbidden edge would
//! fail the check itself.
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use envcloak_testkit::TestHome;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn script() -> PathBuf {
    repo_root().join("scripts/check-crate-graph.py")
}

/// Runs `script` on the workspace at `ws`, with this build's cargo.
fn check_with(script: &Path, ws: &Path) -> Output {
    Command::new("python3")
        .arg(script)
        .arg(ws)
        .env("CARGO", env!("CARGO"))
        .env_remove("RUSTFLAGS")
        .output()
        .unwrap()
}

fn check(ws: &Path) -> Output {
    check_with(&script(), ws)
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn write(root: &Path, rel: &str, body: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
}

/// A dependency on the fixture crate `name`, as `envcloak-<name>`.
fn dep(name: &str) -> String {
    format!("envcloak-{name} = {{ path = \"../envcloak-{name}\" }}\n")
}

/// A workspace at `<home>/ws` with one library crate per entry: its
/// package name and the rest of its manifest after `[package]`.
fn fixture(crates: &[(&str, &str)]) -> (TestHome, PathBuf) {
    let t = TestHome::new();
    let ws = t.home().join("ws");
    write(
        &ws,
        "Cargo.toml",
        "[workspace]\nresolver = \"3\"\nmembers = [\"crates/*\"]\n",
    );
    for (name, rest) in crates {
        write(
            &ws,
            &format!("crates/{name}/Cargo.toml"),
            &format!(
                "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n{rest}"
            ),
        );
        write(&ws, &format!("crates/{name}/src/lib.rs"), "");
    }
    (t, ws)
}

/// What Cargo's own resolver says of the fixture: `cargo metadata` with
/// dependencies resolved, offline (the fixtures have no registry
/// dependency).
fn cargo_resolves(ws: &Path) -> Output {
    Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1", "--offline"])
        .current_dir(ws)
        .env("CARGO_TARGET_DIR", ws.join("target"))
        .env_remove("RUSTFLAGS")
        .output()
        .unwrap()
}

fn assert_passes(ws: &Path) {
    let out = check(ws);
    assert!(
        out.status.success(),
        "expected a pass: {}",
        text(&out.stderr)
    );
    assert!(
        text(&out.stdout).starts_with("check-crate-graph: ok ("),
        "{}",
        text(&out.stdout)
    );
}

/// Fails, and its report holds every one of `expected`.
fn assert_refused(ws: &Path, expected: &[&str]) -> String {
    let out = check(ws);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "expected a failure: {stderr}");
    assert_eq!(text(&out.stdout), "", "{stderr}");
    for e in expected {
        assert!(stderr.contains(e), "missing {e:?} in: {stderr}");
    }
    stderr
}

#[test]
fn the_workspace_graph_passes() {
    assert_passes(&repo_root());
}

/// Codex's cycle173 pair: Cargo refuses it as a cycle (the independent
/// oracle that the fixture is the cycle), and the check names both the
/// forbidden edge and the cycle without resolving anything.
#[test]
fn the_agents_scan_cycle_is_refused_as_cargo_refuses_it() {
    let deps = |d: &str| format!("[dependencies]\n{}", dep(d));
    let (_t, ws) = fixture(&[
        ("envcloak-agents", &deps("scan")),
        ("envcloak-scan", &deps("agents")),
    ]);
    let cargo = cargo_resolves(&ws);
    assert!(!cargo.status.success());
    assert!(
        text(&cargo.stderr).contains("cyclic package dependency"),
        "{}",
        text(&cargo.stderr)
    );
    assert_refused(
        &ws,
        &[
            "scan -> agents (normal) is forbidden: the scanner never depends on",
            "dependency cycle: agents -> scan -> agents",
        ],
    );
}

/// One forbidden edge with no cycle: Cargo builds the graph, the check
/// refuses it.
#[test]
fn a_single_forbidden_edge_cargo_accepts_is_refused() {
    let (_t, ws) = fixture(&[
        ("envcloak-client", ""),
        (
            "envcloak-scan",
            &format!("[dependencies]\n{}", dep("client")),
        ),
    ]);
    let cargo = cargo_resolves(&ws);
    assert!(cargo.status.success(), "{}", text(&cargo.stderr));
    let report = assert_refused(&ws, &["scan -> client (normal) is forbidden"]);
    assert!(!report.contains("cycle"), "{report}");
    // The client may not reach back to the scanner either.
    let (_t, ws) = fixture(&[
        (
            "envcloak-client",
            &format!("[dependencies]\n{}", dep("scan")),
        ),
        ("envcloak-scan", ""),
    ]);
    assert_refused(
        &ws,
        &["client -> scan (normal) is forbidden: the client is the base"],
    );
}

/// The plan's one-way graph, with scan-owned input types (Codex's
/// passing control): every edge is in the table.
#[test]
fn the_planned_one_way_graph_passes() {
    let deps = |ds: &[&str]| {
        let mut s = "[dependencies]\n".to_owned();
        for d in ds {
            s.push_str(&dep(d));
        }
        s
    };
    let (_t, ws) = fixture(&[
        ("envcloak-sys", ""),
        ("envcloak-core", &deps(&["sys"])),
        ("envcloak-policy", &deps(&["core", "sys"])),
        ("envcloak-redact", ""),
        ("envcloak-providers", &deps(&["core"])),
        ("envcloak-ipc", &deps(&["core", "policy", "sys"])),
        ("envcloak-scan", &deps(&["core", "policy", "redact", "sys"])),
        (
            "envcloak-client",
            &deps(&["core", "ipc", "policy", "providers", "sys"]),
        ),
        (
            "envcloak-agents",
            &deps(&["client", "scan", "ipc", "core", "policy", "sys"]),
        ),
        (
            "envcloak-mcp",
            &deps(&["client", "agents", "ipc", "core", "policy", "redact", "sys"]),
        ),
        ("envcloak-signin", &deps(&["core", "policy"])),
        ("envcloak-browser", &deps(&["signin", "sys"])),
        (
            "envcloakd",
            "[dependencies]\nenvcloak-signin = { path = \"../envcloak-signin\" }\n\
             envcloak-browser = { path = \"../envcloak-browser\" }\n",
        ),
        (
            "envcloak",
            &deps(&["mcp", "agents", "client", "scan", "ipc", "providers"]),
        ),
    ]);
    assert!(cargo_resolves(&ws).status.success());
    assert_passes(&ws);
}

/// A forbidden edge counts however the manifest gives it: for one target
/// only, optional, renamed or as a build dependency. A dev-dependency is
/// not an edge of the shipped code, and passes.
#[test]
fn every_form_of_a_normal_dependency_counts() {
    let agents = "path = \"../envcloak-agents\"";
    for (form, rest) in [
        (
            "normal for cfg(unix)",
            format!("[target.'cfg(unix)'.dependencies]\nenvcloak-agents = {{ {agents} }}\n"),
        ),
        (
            "normal, optional",
            format!("[dependencies]\nenvcloak-agents = {{ {agents}, optional = true }}\n"),
        ),
        (
            "normal, as catalog",
            format!("[dependencies]\ncatalog = {{ package = \"envcloak-agents\", {agents} }}\n"),
        ),
        (
            "build",
            format!("[build-dependencies]\nenvcloak-agents = {{ {agents} }}\n"),
        ),
    ] {
        let (_t, ws) = fixture(&[("envcloak-agents", ""), ("envcloak-scan", &rest)]);
        assert_refused(&ws, &[&format!("scan -> agents ({form}) is forbidden")]);
    }
    let (_t, ws) = fixture(&[
        ("envcloak-agents", ""),
        (
            "envcloak-scan",
            &format!("[dev-dependencies]\nenvcloak-agents = {{ {agents} }}\n"),
        ),
    ]);
    assert_passes(&ws);
}

/// An edge the table does not list is refused, forbidden by name or not:
/// a new edge is a plan change. The CLI may use any crate but the daemon
/// and the test-only ones, and a crate with no row may use none.
#[test]
fn an_edge_outside_the_table_is_refused() {
    let one = |from: &str, to: &str| {
        fixture(&[
            (to, ""),
            (
                from,
                &format!("[dependencies]\n{to} = {{ path = \"../{to}\" }}\n"),
            ),
        ])
    };
    for (from, to, shown) in [
        ("envcloak-core", "envcloak-ipc", "core -> ipc"),
        ("envcloak-agents", "envcloak-mcp", "agents -> mcp"),
        ("envcloak-newthing", "envcloak-core", "newthing -> core"),
        ("envcloak", "envcloakd", "cli -> daemon"),
        ("envcloak", "envcloak-testkit", "cli -> testkit"),
    ] {
        let (_t, ws) = one(from, to);
        assert_refused(
            &ws,
            &[&format!(
                "{shown} (normal) is not in the allowed-edge table: a new edge is a plan change"
            )],
        );
    }
    let (_t, ws) = one("envcloak", "envcloak-newthing");
    assert_passes(&ws);
}

/// The table guards itself: an edit that allows a forbidden edge, or
/// makes the table cyclic, fails the check on the unchanged workspace.
#[test]
fn a_table_that_allows_a_forbidden_edge_fails() {
    let t = TestHome::new();
    let original = std::fs::read_to_string(script()).unwrap();
    for (from, to, expected) in [
        (
            "    \"scan\": {\"core\", \"policy\", \"redact\", \"sys\"},",
            "    \"scan\": {\"core\", \"policy\", \"redact\", \"sys\", \"agents\"},",
            "the table allows the forbidden edge scan -> agents",
        ),
        (
            "    \"core\": {\"sys\"},",
            "    \"core\": {\"sys\", \"policy\"},",
            "the allowed-edge table has a cycle: core -> policy -> core",
        ),
    ] {
        assert_eq!(original.matches(from).count(), 1, "{from}");
        let edited = t.home().join("check-crate-graph.py");
        std::fs::write(&edited, original.replace(from, to)).unwrap();
        let out = check_with(&edited, &repo_root());
        assert_eq!(out.status.code(), Some(1));
        assert!(
            text(&out.stderr).contains(expected),
            "{}",
            text(&out.stderr)
        );
    }
}
