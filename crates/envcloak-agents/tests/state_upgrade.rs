//! An installer state an earlier build of this change wrote (format 1, with
//! Claude Code's MCP registrations kept apart from the file records) is
//! read, and the installation it records is still managed (Codex F-125:
//! all four of the predecessor's journals were refused as
//! `state_unreadable`, so uninstall could no longer take its registration
//! out).
//!
//! An independent check through the public API (`StateFile::open`, and
//! `install::uninstall` with the real writer and `install::structural`),
//! built from Codex's cycle 345 gate: the predecessor's four journal shapes
//! (both maps empty, a completed registration, a pending one, both), with
//! synthetic entries and no key; each opens, its bytes untouched by the
//! open; a fresh state saves and reopens in the current format; an unknown
//! field and an unknown version are still refused, their bytes kept. Then
//! what the migrated record does:
//!
//! - a completed or a pending registration is taken out of its
//!   `.claude.json` by uninstall while the entry holds what EnvCloak
//!   registered, the person's other servers and keys kept;
//! - an entry the person changed since is theirs, and stays;
//! - a `.claude.json` the registration created is removed while it is
//!   still exactly what the command left, and otherwise keeps everything
//!   but EnvCloak's entry.
//!
//! Mutation checked: `decode_state` without its format-1 arm (a version 1
//! state refused as of another version): every legacy case fails to open
//! and this fails. A pending registration not migrated (`mcp_intent`
//! dropped): the pending case's entry stays after uninstall and this
//! fails. A created file migrated without its whole-file run (`whole`
//! answering `None`): the unchanged created file is rewritten, not
//! removed, and this fails.
//!
//! The second test is Codex's cycle 355 gate (the F-125 follow-up): a
//! completed registration A and a different pending one B of the same
//! `.claude.json` (a run stopped during a reinstall with a changed entry),
//! with the file holding A, B or the person's own entry, beside the
//! person's other server and keys. Uninstall takes EnvCloak's entry out
//! whichever of A and B it holds, keeps the person's, and keeps every
//! other byte's meaning. Mutation checked: `LegacyState::migrate` keeping
//! the completed registration over a different pending one (the earlier
//! `registrations.entry(k).or_insert(r)`): the case holding B keeps B
//! after an uninstall that says complete, and this fails.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::{Duration, SystemTime};

use envcloak_agents::hook::Host;
use envcloak_agents::install::{self, Options};
use envcloak_agents::writer::{
    Backups, Edit, Journal, Refusal, STATE_VERSION, State, StateFile, Writer,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[derive(Default)]
struct Counter {
    saves: usize,
    backups: usize,
}

impl Journal for Counter {
    fn save(&mut self, _: &State) -> Result<(), Refusal> {
        self.saves += 1;
        Ok(())
    }
}

impl Backups for Counter {
    fn back_up(&mut self, _: &Path, _: &[u8], _: u32) -> Result<String, Refusal> {
        self.backups += 1;
        Ok("upgrade-backup".to_owned())
    }
    fn record(&mut self, _: &str, _: &[u8]) -> Result<(), Refusal> {
        Ok(())
    }
}

fn entry() -> Value {
    json!({"type": "stdio", "command": "/synthetic/envcloak", "args": ["mcp", "--host", "claude-code"]})
}

fn registration(created: Option<Value>) -> Value {
    json!({"host": "claude-code", "entry": entry(), "config_dir": null, "created": created})
}

/// A format-1 journal as the predecessor (7ff5d2d) serialized it.
fn legacy(mcp: &[(&str, Value)], intent: &[(&str, Value)]) -> Value {
    let map = |rs: &[(&str, Value)]| {
        Value::Object(
            rs.iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect(),
        )
    };
    json!({
        "version": 1,
        "files": {},
        "mcp": map(mcp),
        "mcp_intent": map(intent),
        "written": {},
        "leftovers": {},
        "dirs": {},
    })
}

fn store(data: &Path, v: &Value) -> std::path::PathBuf {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(data.join("agents"))
        .unwrap();
    let p = data.join("agents").join("state.json");
    std::fs::write(&p, serde_json::to_vec(v).unwrap()).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    p
}

fn uninstall(state: &mut State) -> install::Report {
    let opts = Options {
        hosts: vec![Host::ClaudeCode],
        global: true,
        ..Options::default()
    };
    install::uninstall(
        &opts,
        &mut Writer {
            state,
            journal: &mut Counter::default(),
            backups: &mut Counter::default(),
            now: SystemTime::now() + Duration::from_secs(360),
        },
    )
}

#[test]
fn the_predecessors_journals_open_and_their_registrations_are_managed() {
    let dir = tempfile::Builder::new()
        .prefix("ecsu")
        .tempdir_in("/tmp")
        .unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();

    // The predecessor's four shapes (Codex's fixtures), each opened.
    let synthetic = "synthetic-old-registration";
    let shapes = [
        legacy(&[], &[]),
        legacy(&[(synthetic, registration(None))], &[]),
        legacy(&[], &[(synthetic, registration(None))]),
        legacy(
            &[(synthetic, registration(None))],
            &[(synthetic, registration(None))],
        ),
    ];
    for (id, v) in shapes.iter().enumerate() {
        let data = root.join(format!("old-{id}"));
        let p = store(&data, v);
        let before = std::fs::read(&p).unwrap();
        let (_lock, state) = StateFile::open(&data).unwrap_or_else(|r| panic!("{id}: {r:?}"));
        assert_eq!(state.version, STATE_VERSION, "{id}");
        // The open changes nothing on disk.
        assert_eq!(std::fs::read(&p).unwrap(), before, "{id}");
        let edits: Vec<&Edit> = state.files.values().flat_map(|r| &r.edits).collect();
        if id == 0 {
            assert!(state.files.is_empty(), "{id}");
        } else {
            // One record, one edit: a completed and a pending one of the
            // same file are one registration.
            assert_eq!(state.files.len(), 1, "{id}");
            assert!(
                matches!(edits.as_slice(), [Edit::JsonMember { key, value, .. }]
                    if key == "envcloak" && *value == entry()),
                "{id}: {edits:?}"
            );
        }
    }

    // Controls: a fresh state saves in the current format and reopens; an
    // unknown field and an unknown version are refused, their bytes kept.
    let fresh = root.join("fresh");
    {
        let (mut journal, state) = StateFile::open(&fresh).unwrap();
        journal.save(&state).unwrap();
    }
    let saved: Value =
        serde_json::from_slice(&std::fs::read(fresh.join("agents/state.json")).unwrap()).unwrap();
    assert_eq!(saved["version"], json!(STATE_VERSION));
    assert!(saved.get("mcp").is_none() && saved.get("mcp_intent").is_none());
    assert!(StateFile::open(&fresh).is_ok());
    let mut unknown = legacy(&[], &[]);
    unknown["unexpected_schema_field"] = json!(true);
    let mut current_unknown = saved.clone();
    current_unknown["mcp"] = json!({});
    let mut wrong = legacy(&[], &[]);
    wrong["version"] = json!(99);
    for (name, v) in [
        ("unknown", unknown),
        ("current-unknown", current_unknown),
        ("wrong", wrong),
    ] {
        let data = root.join(name);
        let p = store(&data, &v);
        let before = std::fs::read(&p).unwrap();
        let r = StateFile::open(&data);
        assert!(
            matches!(&r, Err(e) if e.name == "state_unreadable"),
            "{name}"
        );
        drop(r);
        assert_eq!(std::fs::read(&p).unwrap(), before, "{name}");
    }

    // What the migrated records do, each in a home of its own.
    let theirs = json!({"command": "/usr/bin/true"});
    for (id, kind) in ["completed", "pending", "changed-by-person"]
        .iter()
        .enumerate()
    {
        let home = root.join(format!("home-{id}"));
        std::fs::create_dir(&home).unwrap();
        let claude_json = home.join(".claude.json");
        let key = claude_json.to_str().unwrap();
        let value = if *kind == "changed-by-person" {
            json!({"command": "/person/own"})
        } else {
            entry()
        };
        let original =
            json!({"numStartups": 3, "mcpServers": {"other": theirs.clone(), "envcloak": value}});
        std::fs::write(&claude_json, serde_json::to_vec_pretty(&original).unwrap()).unwrap();
        let v = if *kind == "pending" {
            legacy(&[], &[(key, registration(None))])
        } else {
            legacy(&[(key, registration(None))], &[])
        };
        let data = root.join(format!("data-{id}"));
        store(&data, &v);
        let (_lock, mut state) = StateFile::open(&data).unwrap();
        let report = uninstall(&mut state);
        let after: Value = serde_json::from_slice(&std::fs::read(&claude_json).unwrap()).unwrap();
        assert_eq!(after["mcpServers"]["other"], theirs, "{kind}");
        assert_eq!(after["numStartups"], json!(3), "{kind}");
        if *kind == "changed-by-person" {
            assert_eq!(after, original, "{kind}: {report:?}");
        } else {
            assert!(
                after["mcpServers"].get("envcloak").is_none(),
                "{kind}: {report:?}"
            );
        }
        assert!(report.complete(), "{kind}: {report:?}");
        assert!(state.files.is_empty(), "{kind}");
    }

    // A `.claude.json` the registration created: removed while it is
    // exactly what the command left; changed since, everything but
    // EnvCloak's entry kept.
    for changed in [false, true] {
        let home = root.join(format!("created-{changed}"));
        std::fs::create_dir(&home).unwrap();
        let claude_json = home.join(".claude.json");
        let made = serde_json::to_vec_pretty(
            &json!({"firstStartTime": "synthetic", "mcpServers": {"envcloak": entry()}}),
        )
        .unwrap();
        std::fs::write(&claude_json, &made).unwrap();
        let m = std::fs::metadata(&claude_json).unwrap();
        let stamp = json!({
            "dev": m.dev(), "ino": m.ino(), "size": m.size(),
            "mtime": m.mtime(), "mtime_nsec": m.mtime_nsec(),
            "ctime": m.ctime(), "ctime_nsec": m.ctime_nsec(),
            "mode": m.mode(), "nlink": m.nlink(), "uid": m.uid(),
        });
        let sha = hex(&Sha256::digest(&made));
        let created = json!({"sha256": sha, "stamp": stamp});
        let data = root.join(format!("data-created-{changed}"));
        store(
            &data,
            &legacy(
                &[(claude_json.to_str().unwrap(), registration(Some(created)))],
                &[],
            ),
        );
        if changed {
            let mut v: Value = serde_json::from_slice(&made).unwrap();
            v["projects"] = json!({"/w": {}});
            std::fs::write(&claude_json, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
        }
        let (_lock, mut state) = StateFile::open(&data).unwrap();
        let report = uninstall(&mut state);
        assert!(report.complete(), "changed {changed}: {report:?}");
        if changed {
            let after: Value =
                serde_json::from_slice(&std::fs::read(&claude_json).unwrap()).unwrap();
            assert_eq!(
                after,
                json!({"firstStartTime": "synthetic", "projects": {"/w": {}}}),
                "the entry and the object made for it go, the rest stays"
            );
        } else {
            assert!(
                !claude_json.exists(),
                "a created file still as the command left it is removed"
            );
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Codex's cycle 355 gate, adopted: six homes, each with a format-1
/// journal of the registrations named and a `.claude.json` holding the
/// entry named, the person's other server and a key of theirs.
#[test]
fn a_completed_and_a_different_pending_registration_are_both_managed() {
    let dir = tempfile::Builder::new()
        .prefix("ecsp")
        .tempdir_in("/tmp")
        .unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let a = entry();
    let mut b = a.clone();
    b["args"]
        .as_array_mut()
        .unwrap()
        .push(json!("synthetic-alternate"));
    let person = json!({"command": "synthetic-person-owned"});
    let other = json!({"command": "synthetic-other"});
    // (completed, pending, what the file holds, EnvCloak's to take out)
    let cases: [(Option<&Value>, Option<&Value>, &Value, bool); 6] = [
        (Some(&a), None, &a, true),
        (None, Some(&b), &b, true),
        (Some(&a), Some(&a), &a, true),
        (Some(&a), Some(&b), &a, true),
        (Some(&a), Some(&b), &b, true),
        (Some(&a), Some(&b), &person, false),
    ];
    let mut misses = Vec::new();
    let mut shapes = Vec::new();
    for (id, (completed, pending, current, ours)) in cases.iter().enumerate() {
        let home = root.join(format!("case-{id}"));
        std::fs::create_dir(&home).unwrap();
        let claude_json = home.join(".claude.json");
        let key = claude_json.to_str().unwrap();
        let input = json!({"custom": 7, "mcpServers": {"envcloak": current, "other": other}});
        std::fs::write(&claude_json, serde_json::to_vec_pretty(&input).unwrap()).unwrap();
        std::fs::set_permissions(&claude_json, std::fs::Permissions::from_mode(0o600)).unwrap();
        let reg = |e: &Value| json!({"host": "claude-code", "entry": e, "config_dir": null, "created": null});
        let mcp: Vec<(&str, Value)> = completed.iter().map(|e| (key, reg(e))).collect();
        let intent: Vec<(&str, Value)> = pending.iter().map(|e| (key, reg(e))).collect();
        let data = root.join(format!("data-{id}"));
        let p = store(&data, &legacy(&mcp, &intent));
        let before = std::fs::read(&p).unwrap();
        let (_lock, mut state) = StateFile::open(&data).unwrap();
        assert_eq!(
            std::fs::read(&p).unwrap(),
            before,
            "{id}: the open writes nothing"
        );
        // Each distinct registration is one edit of the one record.
        let distinct = usize::from(completed.is_some())
            + usize::from(pending.is_some() && pending != completed);
        let edits = state.files.values().flat_map(|r| &r.edits).count();
        if edits != distinct {
            shapes.push(format!("case {id}: {edits} edits, not {distinct}"));
        }
        let report = uninstall(&mut state);
        let after: Value = serde_json::from_slice(&std::fs::read(&claude_json).unwrap()).unwrap();
        // Controls: the person's other server and key stay, and their own
        // entry leaves the file as it was.
        assert_eq!(after["custom"], json!(7), "{id}");
        assert_eq!(after["mcpServers"]["other"], other, "{id}");
        if !ours {
            assert_eq!(after, input, "{id}: the person's entry is theirs");
        }
        let removed = after["mcpServers"].get("envcloak").is_none();
        if removed != *ours {
            misses.push(format!(
                "case {id}: EnvCloak's entry {} after an uninstall that said complete={}",
                if removed { "removed" } else { "left" },
                report.complete()
            ));
        }
        assert!(report.complete(), "{id}: {report:?}");
        assert!(
            state.files.is_empty(),
            "{id}: the record is dropped once undone"
        );
    }
    assert!(misses.is_empty(), "{misses:#?}");
    assert!(shapes.is_empty(), "{shapes:#?}");
}
