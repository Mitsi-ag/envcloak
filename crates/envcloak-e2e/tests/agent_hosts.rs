//! The pinned agent hosts against the scripted model (M2 plan task M2-04,
//! D-13, R-M2-66, R-M2-78, R-M2-88): the stub answers scripted turns to
//! Claude Code and Codex; a canary a scripted turn prints with plain
//! `echo` is found in that host's transcript (the positive control) and
//! in what it sent its model; a run with no canary leaves none anywhere
//! (the negative control).
//!
//! Each host runs in an isolated home with a cleared environment, its
//! flags pinned per run (D-13), and `HTTPS_PROXY` pointed at the model,
//! which refuses and records every tunnel. A host that is not installed
//! (scripts/install-agent-hosts.py) skips its test with a line on
//! standard error, unless ENVCLOAK_TEST_REQUIRE_AGENT_HOSTS is set, as in
//! CI's agent jobs.
//!
//! Lines starting `measurement:` are what docs/AGENTS.md's host behaviour
//! table and docs/ACCEPTANCE.md record; CI prints them on both systems.
#![allow(clippy::unwrap_used)]

use std::path::Path;

use envcloak_agents::probe::model::{QUALIFIED, SERVER};
use envcloak_e2e::{bin_dir, versions_toml};
use envcloak_testkit::agents::{AgentHome, Host, HostFlags, HostRun, Installed, pins, require};
use envcloak_testkit::transcripts::{OTHER, Sweep};
use envcloak_testkit::{Canary, by_label, canaries, fresh_seed, labels};
use serde_json::json;

fn host(h: Host, variant: &str, test: &str) -> Option<AgentHome> {
    let found = Installed::find(&versions_toml(), h.id(), variant);
    require(found, test).map(|i| AgentHome::start(h, i))
}

/// The flags every run here pins (D-13): Claude Code `-p` in the default
/// permission mode with Bash allowed; Codex `exec` in its workspace-write
/// sandbox with approval policy `never`. Never a bypass mode.
fn flags(h: Host) -> HostFlags {
    match h {
        Host::ClaudeCode => HostFlags::claude("default", &["Bash"]),
        Host::Codex => HostFlags::codex("workspace-write", "never"),
    }
}

/// The store a host keeps its transcripts in.
fn transcript_store(h: Host) -> &'static str {
    match h {
        Host::ClaudeCode => "claude/projects",
        Host::Codex => "codex/sessions",
    }
}

fn os() -> &'static str {
    std::env::consts::OS
}

fn measure(a: &AgentHome, what: &str, value: impl std::fmt::Display) {
    println!(
        "measurement: {what} host={} version={} os={}: {value}",
        a.installed.pin.id,
        a.installed.pin.version,
        os()
    );
}

/// The body of the request the script answered with `pick`.
fn body_of(run: &HostRun, pick: &str) -> String {
    let r = run
        .model
        .requests
        .iter()
        .find(|r| r.pick.as_deref() == Some(pick))
        .unwrap_or_else(|| panic!("no request for {pick}: {:?}", run.model.requests));
    String::from_utf8_lossy(&r.body).into_owned()
}

#[test]
fn the_qualified_table_is_the_pinned_tier_1_hosts() {
    let mut pinned: Vec<(String, String)> = pins(&versions_toml())
        .into_iter()
        .filter(|p| p.tier == 1)
        .map(|p| (p.id, p.version))
        .collect();
    pinned.sort();
    pinned.dedup();
    let mut qualified: Vec<(String, String)> = QUALIFIED
        .iter()
        .map(|q| (q.host.to_owned(), q.version.to_owned()))
        .collect();
    qualified.sort();
    assert_eq!(pinned, qualified);
}

#[test]
fn the_scripted_model_is_never_linked_into_envcloak_or_envcloakd() {
    let contains = |p: &Path| {
        let bytes = std::fs::read(p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
        bytes.windows(SERVER.len()).any(|w| w == SERVER.as_bytes())
    };
    let bins = bin_dir();
    for name in ["envcloak", "envcloakd"] {
        assert!(
            !contains(&bins.join(name)),
            "{name} holds the scripted model"
        );
    }
    // The positive control: the model's own program holds it.
    let model = envcloak_testkit::agents::probe_model_exe();
    assert!(contains(&model), "the sentinel is not where it must be");
}

fn scripted_turns(h: Host, variant: &str) {
    let Some(a) = host(h, variant, "scripted_turns") else {
        return;
    };
    let marker = format!("ecturn-{:016x}", fresh_seed());
    let script = json!({"steps": [
        {"say": "running the step", "shell": format!("echo {marker}")},
        {"say": "done"},
    ]});
    let run = a.run(&script, "Run the scripted step.", &flags(h), &a.home_dir());
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    assert!(
        String::from_utf8_lossy(&run.output.stdout).contains("done"),
        "{}",
        run.text()
    );
    assert!(run.model.clean(), "{:?}", run.model.outcome);
    let picks: Vec<&str> = run
        .model
        .model_calls()
        .iter()
        .filter_map(|r| r.pick.as_deref())
        .collect();
    assert_eq!(picks, ["step 0", "step 1"], "{:?}", run.model.requests);
    // The host ran the command and sent its output back.
    assert!(body_of(&run, "step 1").contains(&marker), "{}", run.text());
    let mut endpoints = run.model.endpoints();
    endpoints.retain(|e| !e.starts_with("CONNECT "));
    endpoints.dedup();
    measure(&a, "model endpoints", endpoints.join(", "));
    let mut tunnels: Vec<&str> = run.model.connects();
    tunnels.sort_unstable();
    tunnels.dedup();
    measure(&a, "tunnels refused", tunnels.join(", "));
    measure(&a, "seconds", run.elapsed.as_secs_f32());
}

#[test]
fn claude_code_is_served_scripted_turns() {
    scripted_turns(Host::ClaudeCode, "native");
}

#[test]
fn claude_code_from_npm_is_served_scripted_turns() {
    scripted_turns(Host::ClaudeCode, "npm");
}

#[test]
fn codex_is_served_scripted_turns() {
    scripted_turns(Host::Codex, "native");
}

/// A canary printed by a scripted turn with plain `echo` must be found in
/// the host's transcript store and in the model's request bodies: the
/// sweep's positive control (L-01, SI-18). Raw counts per store are
/// printed for docs/ACCEPTANCE.md.
fn positive_control(h: Host) {
    let Some(a) = host(h, "native", "positive_control") else {
        return;
    };
    let control = Canary::new(
        "POSITIVE_CONTROL",
        format!("ecctl-{:016x}{:016x}", fresh_seed(), fresh_seed()),
    );
    // A key-shaped one too, printed the same way: whether a host keeps a
    // key it saw printed, raw.
    let cs = canaries(fresh_seed());
    let key = by_label(&cs, labels::OPENAI_API_KEY).clone();
    let script = json!({"steps": [
        {"shell": format!("echo {}; echo {}", control.as_str(), key.as_str())},
        {"say": "done"},
    ]});
    let run = a.run(&script, "Print the two lines.", &flags(h), &a.home_dir());
    assert_eq!(run.output.status.code(), Some(0), "exit code");
    assert!(run.model.clean(), "{:?}", run.model.outcome);
    let all = [control.clone(), key.clone()];
    let hits = Sweep::host_stores(&a, &all, &[&run.model]);
    print!(
        "measurement: store hits host={} os={}:\n{hits}",
        a.installed.pin.id,
        os()
    );
    let store = transcript_store(h);
    assert!(
        hits.in_store_as(store, "POSITIVE_CONTROL", "raw") >= 1,
        "the positive control is not in {store}:\n{hits}"
    );
    assert!(
        hits.in_model("POSITIVE_CONTROL") >= 1,
        "the positive control is not in the model's request bodies:\n{hits}"
    );
    measure(
        &a,
        "printed key kept raw in the transcript",
        hits.in_store_as(store, &key.label, "raw"),
    );
    // Every hit outside the listed stores is reported, never dropped: a
    // new store shows up here first.
    measure(
        &a,
        "control hits outside the listed stores",
        hits.in_store(OTHER, "POSITIVE_CONTROL"),
    );
}

#[test]
fn claude_code_keeps_what_a_scripted_turn_prints() {
    positive_control(Host::ClaudeCode);
}

#[test]
fn codex_keeps_what_a_scripted_turn_prints() {
    positive_control(Host::Codex);
}

/// A run that never sees a canary leaves none anywhere: not in the host's
/// stores, not in the rest of the home, not in what it sent its model.
fn negative_control(h: Host) {
    let Some(a) = host(h, "native", "negative_control") else {
        return;
    };
    let cs = canaries(fresh_seed());
    let script = json!({"steps": [
        {"shell": "echo nothing secret here"},
        {"say": "done"},
    ]});
    let run = a.run(&script, "Print a line.", &flags(h), &a.home_dir());
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    let hits = Sweep::host_stores(&a, &cs, &[&run.model]);
    assert_eq!(hits.total(), 0, "{hits}");
    let home = a.test_home().unwrap();
    assert!(home.sweep(&cs).is_empty(), "the home holds a canary");
}

#[test]
fn claude_code_negative_control_is_clean() {
    negative_control(Host::ClaudeCode);
}

#[test]
fn codex_negative_control_is_clean() {
    negative_control(Host::Codex);
}

/// Every file a host wrote in its home, by path relative to `HOME`
/// (names only), for the store list in docs/ACCEPTANCE.md.
fn files_written(a: &AgentHome) -> Vec<String> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                walk(&p, base, out);
            } else {
                out.push(p.strip_prefix(base).unwrap_or(&p).display().to_string());
            }
        }
    }
    let mut out = Vec::new();
    let home = a.home_dir();
    walk(&home, &home, &mut out);
    out.sort();
    out
}

fn stores_written(h: Host) {
    let Some(a) = host(h, "native", "stores_written") else {
        return;
    };
    let script = json!({"steps": [{"shell": "echo stores"}, {"say": "done"}]});
    let run = a.run(&script, "Print a line.", &flags(h), &a.home_dir());
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    // Collapse ids so the list reads as shapes.
    let shapes: Vec<String> = files_written(&a)
        .into_iter()
        .map(|f| {
            f.split('/')
                .map(|part| {
                    if part.chars().filter(char::is_ascii_hexdigit).count() >= 8 {
                        "<id>".to_owned()
                    } else {
                        part.to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join("/")
        })
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    measure(&a, "files written", shapes.join(", "));
}

#[test]
fn claude_code_stores() {
    stores_written(Host::ClaudeCode);
}

#[test]
fn codex_stores() {
    stores_written(Host::Codex);
}
