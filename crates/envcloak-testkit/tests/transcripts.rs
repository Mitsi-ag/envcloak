//! The host-store sweep (M2 plan task M2-04, D-15, SI-18): a canary planted
//! in every store, in every encoding, is found and filed under its store;
//! nothing found is ever dropped; a home without canaries is clean; the
//! scripted model's request bodies are swept too.
//!
//! The stores each host must have are listed here again, by hand, from
//! D-15 and what M2-04 saw the pinned hosts write: an independent list,
//! so a store dropped from `transcript_roots` fails its control below.
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use envcloak_testkit::agents::{Host, ModelReport, ModelRequest};
use envcloak_testkit::transcripts::{
    Hits, OTHER, host_root, sweep_model, sweep_stores, transcript_roots,
};
use envcloak_testkit::{Canary, TestHome, by_label, canaries, fresh_seed, labels};
use zeroize::Zeroizing;

/// `(store name, file to plant, relative to HOME)`: one file per store.
const CLAUDE: &[(&str, &str)] = &[
    ("claude/projects", ".claude/projects/-tmp-acme/4f0c.jsonl"),
    (
        "claude/projects",
        ".claude/projects/-tmp-acme/4f0c/tool-results/a.txt",
    ),
    (
        "claude/projects",
        ".claude/projects/-tmp-acme/4f0c/subagents/agent-1.jsonl",
    ),
    ("claude/history.jsonl", ".claude/history.jsonl"),
    ("claude/paste-cache", ".claude/paste-cache/9a.txt"),
    ("claude/file-history", ".claude/file-history/4f0c/env@v1"),
    ("claude/backups", ".claude/backups/.claude.json.backup.1"),
    ("claude/sessions", ".claude/sessions/77.json"),
    ("claude/session-env", ".claude/session-env/4f0c/hook-1.sh"),
    (
        "claude/shell-snapshots",
        ".claude/shell-snapshots/snapshot-zsh-1.sh",
    ),
    (
        "claude/telemetry",
        ".claude/telemetry/1p_failed_events.4f0c.json",
    ),
    ("claude/todos", ".claude/todos/4f0c-agent.json"),
    ("claude/debug", ".claude/debug/4f0c.txt"),
    ("claude.json", ".claude.json"),
    ("claude.json backups", ".claude.json.backup.1790853962065"),
];

/// The same for Codex, relative to `$CODEX_HOME` (`~/.codex`).
const CODEX: &[(&str, &str)] = &[
    (
        "codex/sessions",
        "sessions/2026/10/01/rollout-2026-10-01T21-26-47-01a0.jsonl",
    ),
    (
        "codex/archived_sessions",
        "archived_sessions/rollout-1.jsonl",
    ),
    ("codex/history.jsonl", "history.jsonl"),
    ("codex/log", "log/codex-tui.log"),
    ("codex/sqlite", "thread_history_1.sqlite-wal"),
    ("codex/sqlite", "state_5.sqlite"),
    ("codex/shell_snapshots", "shell_snapshots/1.sh"),
    ("codex/memories", "memories/1.md"),
];

/// The encodings planted, by the names `encodings` gives them. The
/// planted bytes are made here, independently of the sweep's encoders:
/// the `base64` crate, `serde_json`, and hex and RFC 3986 percent-encoding
/// written out below (L-02).
const PLANTED: [&str; 5] = [
    "raw",
    "base64",
    "hex-lower",
    "percent-rfc3986-upper",
    "json/quote-esc/slash-raw/non-ascii-raw/html-raw/extra-raw",
];

fn planted(c: &Canary) -> Vec<Vec<u8>> {
    let v = c.value();
    let hex: String = v.iter().map(|b| format!("{b:02x}")).collect();
    let percent: String = v
        .iter()
        .map(|&b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    let json = serde_json::to_string(c.as_str()).unwrap();
    vec![
        v.to_vec(),
        STANDARD.encode(v).into_bytes(),
        hex.into_bytes(),
        percent.into_bytes(),
        json.as_bytes()[1..json.len() - 1].to_vec(),
    ]
}

fn plant(path: &Path, c: &Canary) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut body = b"{\"type\":\"user\",\"text\":\"".to_vec();
    for bytes in planted(c) {
        body.extend_from_slice(b" <");
        body.extend_from_slice(&bytes);
        body.extend_from_slice(b"> ");
    }
    body.extend_from_slice(b"\"}\n");
    std::fs::write(path, body).unwrap();
}

fn sweep(host: Host, home: &TestHome, cs: &[Canary]) -> Hits {
    let h = home.home();
    let codex = h.join(".codex");
    let (root, files) = host_root(host, &h, &codex);
    Hits {
        stores: sweep_stores(&root, &files, &transcript_roots(host, &h, &codex), cs),
        model: Vec::new(),
    }
}

/// The URL canary: it has `/`, `"`, `+`, a space and a non-ASCII
/// character, so its encodings differ from its raw bytes.
fn url_canary(cs: &[Canary]) -> Canary {
    by_label(cs, labels::DATABASE_URL).clone()
}

fn every_store(host: Host, list: &[(&str, &str)], base: impl Fn(&TestHome) -> PathBuf) {
    let cs = canaries(fresh_seed());
    let c = url_canary(&cs);
    let home = TestHome::new();
    for (_, rel) in list {
        plant(&base(&home).join(rel), &c);
    }
    let hits = sweep(host, &home, std::slice::from_ref(&c));
    for (store, rel) in list {
        let planted_here = list.iter().filter(|(s, _)| s == store).count();
        for name in PLANTED {
            assert!(
                hits.in_store_as(store, &c.label, name) >= planted_here,
                "{store} ({rel}): {name} not found\n{hits}"
            );
        }
    }
    assert_eq!(hits.in_store(OTHER, &c.label), 0, "{hits}");
}

#[test]
fn a_canary_planted_in_every_claude_store_is_found_there_in_every_encoding() {
    every_store(Host::ClaudeCode, CLAUDE, TestHome::home);
}

#[test]
fn a_canary_planted_in_every_codex_store_is_found_there_in_every_encoding() {
    every_store(Host::Codex, CODEX, |h| h.home().join(".codex"));
}

#[test]
fn a_hit_outside_every_listed_store_is_kept_under_other() {
    let cs = canaries(fresh_seed());
    let c = url_canary(&cs);
    let home = TestHome::new();
    plant(&home.home().join(".claude/plans/new-store.md"), &c);
    plant(&home.home().join(".codex/new-store/x.json"), &c);
    // Not the host's: a project beside it in HOME, which the tests sweep
    // with the whole home instead.
    plant(&home.home().join("acme-web/.env.local"), &c);
    let claude = sweep(Host::ClaudeCode, &home, std::slice::from_ref(&c));
    assert!(
        claude.in_store(OTHER, &c.label) >= PLANTED.len(),
        "{claude}"
    );
    let codex = sweep(Host::Codex, &home, std::slice::from_ref(&c));
    assert!(codex.in_store(OTHER, &c.label) >= PLANTED.len(), "{codex}");
    assert!(home.sweep(&cs).len() >= 3 * PLANTED.len());
}

#[test]
fn the_negative_control_is_clean() {
    let cs = canaries(fresh_seed());
    let home = TestHome::new();
    // The same stores holding everything but a canary: other values of
    // the same shapes, from another seed.
    let others = canaries(fresh_seed());
    for (_, rel) in CLAUDE {
        plant(&home.home().join(rel), &url_canary(&others));
    }
    for (_, rel) in CODEX {
        plant(&home.home().join(".codex").join(rel), &url_canary(&others));
    }
    for host in [Host::ClaudeCode, Host::Codex] {
        let hits = sweep(host, &home, &cs);
        assert_eq!(hits.total(), 0, "{hits}");
        assert_eq!(hits.to_string(), "no hits");
    }
}

#[test]
fn the_harness_s_own_canaries_are_counted_like_any_other() {
    let cs = canaries(fresh_seed());
    let control = Canary::new("POSITIVE_CONTROL", format!("ecctl-{:016x}", fresh_seed()));
    let home = TestHome::new();
    let file = home.home().join(".claude/projects/-tmp/1.jsonl");
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, format!("{{\"stdout\":\"{}\"}}\n", control.as_str())).unwrap();
    let mut all = cs.clone();
    all.push(control.clone());
    let hits = sweep(Host::ClaudeCode, &home, &all);
    assert_eq!(
        hits.in_store_as("claude/projects", "POSITIVE_CONTROL", "raw"),
        1,
        "{hits}"
    );
}

#[test]
fn the_model_s_request_bodies_are_swept() {
    let cs = canaries(fresh_seed());
    let c = url_canary(&cs);
    let body = serde_json::json!({"messages": [{"role": "user", "content": [
        {"type": "tool_result", "content": c.as_str()}]}]})
    .to_string();
    let report = ModelReport {
        requests: vec![ModelRequest {
            seq: 3,
            at_ms: 0,
            method: "POST".to_owned(),
            path: "/v1/messages".to_owned(),
            status: 200,
            api: Some("messages".to_owned()),
            pick: Some("step 1".to_owned()),
            body: Zeroizing::new(body.into_bytes()),
        }],
        outcome: serde_json::json!({}),
    };
    let hits = sweep_model(&report, &cs);
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert_eq!(hits[0].seq, 3);
    assert!(hits[0].found.encoding.starts_with("json/"), "{hits:?}");
}
