//! An undo that would make a file larger than the writer reads is refused
//! before anything is backed up, saved or written, keeps EnvCloak's
//! record, and is made by a later uninstall once the person has made room
//! (F124: a structural undo of Codex's `config.toml` that the person had
//! grown to the limit wrote a file past it and forgot the record, so the
//! next run could neither read it nor take the setting out).
//!
//! An independent oracle through the public API only (the real writer and
//! `codex::apply` for the install, `install::uninstall` for the undo, a
//! journal and backups that count), typed TOML read with `toml_edit`, four
//! cases, each with its positive controls:
//!
//! 0. below the limit, the person's comment added: the structural undo
//!    takes the setting out and keeps the comment; a repeat changes
//!    nothing;
//! 1. the file at the limit, the undo growing it by a byte: refused
//!    `too_large`, the file and the record kept, no backup; once the
//!    person makes room, the retry makes the undo, once;
//! 2. the person grew the file past the limit: refused as it is read, the
//!    same retry after room is made;
//! 3. the file at the limit, as EnvCloak left it: undone exactly.
//!
//! Mutation checked: the outgoing check in `Writer::try_undo` taken out
//! (`Undo::Rewrite(after) if after.len() > t.limit` never true): case 1
//! writes the file past the limit and drops the record, and this fails.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use envcloak_agents::hook::Host;
use envcloak_agents::hosts::codex;
use envcloak_agents::install::{self, Context, Options};
use envcloak_agents::locations::Locations;
use envcloak_agents::writer::{
    Backups, Journal, MAX_FILE, Outcome, Refusal, State, Target, Writer,
};
use serde_json::json;

#[derive(Default)]
struct Counter {
    saves: usize,
    backups: usize,
    records: usize,
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
        Ok("owned-rewrite".to_owned())
    }
    fn record(&mut self, _: &str, _: &[u8]) -> Result<(), Refusal> {
        self.records += 1;
        Ok(())
    }
}

/// `sandbox_workspace_write.network_access` as a TOML boolean.
fn network_access(bytes: &[u8]) -> Option<bool> {
    let doc = toml_edit::DocumentMut::from_str(std::str::from_utf8(bytes).ok()?).ok()?;
    doc.as_table()
        .get("sandbox_workspace_write")
        .and_then(toml_edit::Item::as_table_like)
        .and_then(|t| t.get("network_access"))
        .and_then(toml_edit::Item::as_bool)
}

fn changed(r: &install::Report) -> bool {
    r.hosts
        .iter()
        .flat_map(|h| &h.results)
        .any(|r| matches!(r.outcome, Outcome::Changed { created: false, .. }))
}

fn refused_too_large(r: &install::Report) -> bool {
    r.hosts
        .iter()
        .flat_map(|h| &h.results)
        .any(|r| matches!(&r.outcome, Outcome::Refused(x) if x.name == "too_large"))
}

fn run_case(parent: &Path, id: usize) {
    let root = parent.join(format!("structural-size-{id}"));
    std::fs::create_dir(&root).unwrap();
    let dir = root.join(".codex");
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("config.toml");
    let prefix = b"model = \"preserved\"\n[sandbox_workspace_write]\nnetwork_access = false\n#";
    let initial_len = if id == 0 { MAX_FILE - 8 } else { MAX_FILE };
    let mut original = prefix.to_vec();
    original.resize(initial_len, b'p');
    std::fs::write(&path, &original).unwrap();
    let home = root.clone().into_os_string();
    let env = move |k: &str| (k == "HOME").then(|| home.clone());
    let ctx = Context {
        locations: Locations::new(&env).unwrap(),
        envcloak: root.join("envcloak"),
        data_dir: root.join("data"),
        socket: root.join("socket"),
        path: std::ffi::OsString::new(),
        env: &env,
    };
    let _ = &ctx;
    let target = Target {
        path: path.clone(),
        host: "codex",
        scope: "global".to_owned(),
        host_owned: true,
        host_name: "Codex",
        limit: MAX_FILE,
    };
    let settings = vec![(
        vec![
            "sandbox_workspace_write".to_owned(),
            "network_access".to_owned(),
        ],
        json!(true),
    )];
    let (mut state, mut journal, mut backups) =
        (State::default(), Counter::default(), Counter::default());
    let now = SystemTime::now() + Duration::from_secs(360);
    let first = Writer {
        state: &mut state,
        journal: &mut journal,
        backups: &mut backups,
        now,
    }
    .change(&target, &mut |b, record| {
        codex::apply(b, &settings, record.map_or(&[], |r| r.edits.as_slice()))
    });
    let mut current = std::fs::read(&path).unwrap();
    // Positive control: the install made its one change.
    assert!(
        matches!(first, Outcome::Changed { created: false, .. }),
        "{id}: {first:?}"
    );
    assert_eq!(current.len() + 1, original.len(), "{id}");
    assert_eq!(
        (state.files.len(), backups.backups, backups.records),
        (1, 1, 1)
    );
    // The person's own edit since (none in case 3).
    if id != 3 {
        current.resize(current.len() + if id == 2 { 8 } else { 1 }, b'#');
        std::fs::write(&path, &current).unwrap();
    }
    match id {
        1 => assert_eq!(current.len(), MAX_FILE, "{id}"),
        2 => assert!(current.len() > MAX_FILE, "{id}"),
        _ => assert!(current.len() <= MAX_FILE, "{id}"),
    }
    assert_eq!(network_access(&current), Some(true), "{id}");

    let opts = Options {
        hosts: vec![Host::Codex],
        global: true,
        ..Options::default()
    };
    let report = install::uninstall(
        &opts,
        &mut Writer {
            state: &mut state,
            journal: &mut journal,
            backups: &mut backups,
            now,
        },
    );
    let after = std::fs::read(&path).unwrap();
    // The file stays readable whatever happened.
    assert!(
        after.len() <= MAX_FILE || id == 2,
        "{id}: {} bytes",
        after.len()
    );
    let mut next_called = false;
    let next = Writer {
        state: &mut state.clone(),
        journal: &mut Counter::default(),
        backups: &mut Counter::default(),
        now,
    }
    .change(&target, &mut |_, _| {
        next_called = true;
        Ok(None)
    });
    let needs_retry = id == 1 || id == 2;
    if needs_retry {
        // Refused, before any backup, save or write; the record kept.
        assert!(refused_too_large(&report), "{id}: {report:?}");
        assert!(!report.complete(), "{id}");
        assert_eq!(after, current, "{id}");
        assert_eq!(state.files.len(), 1, "{id}");
        assert_eq!((backups.backups, backups.records), (1, 1), "{id}");
        if id == 2 {
            assert!(
                matches!(&next, Outcome::Refused(r) if r.name == "too_large") && !next_called,
                "{id}: {next:?}"
            );
        } else {
            assert!(matches!(next, Outcome::Unchanged) && next_called, "{id}");
        }
    } else {
        let mut expected = original.clone();
        if id != 3 {
            expected.push(b'#');
        }
        assert_eq!(after, expected, "{id}");
        assert!(changed(&report) && report.complete(), "{id}: {report:?}");
        assert!(state.files.is_empty(), "{id}");
        assert_eq!((backups.backups, backups.records), (2, 2), "{id}");
        assert!(matches!(next, Outcome::Unchanged) && next_called, "{id}");
    }

    // The person makes room; the retry makes the undo kept for it.
    let before_retry = backups.backups;
    let mut room = after.clone();
    if needs_retry {
        room.truncate(MAX_FILE - 2);
        std::fs::write(&path, &room).unwrap();
    }
    let room_true = network_access(&room) == Some(true);
    let mut expected_retry = room.clone();
    if room_true {
        let needle = b"network_access = true";
        let pos = expected_retry
            .windows(needle.len())
            .position(|s| s == needle)
            .unwrap();
        expected_retry.splice(
            pos..pos + needle.len(),
            b"network_access = false".iter().copied(),
        );
    }
    let retry = install::uninstall(
        &opts,
        &mut Writer {
            state: &mut state,
            journal: &mut journal,
            backups: &mut backups,
            now,
        },
    );
    let final_bytes = std::fs::read(&path).unwrap();
    assert!(
        retry.complete() && state.files.is_empty(),
        "{id}: {retry:?}"
    );
    assert_eq!(final_bytes, expected_retry, "{id}");
    assert!(final_bytes.len() <= MAX_FILE, "{id}");
    if needs_retry {
        assert!(room_true && changed(&retry), "{id}");
        assert_eq!((backups.backups, backups.records), (2, 2), "{id}");
    } else {
        assert!(!changed(&retry), "{id}");
        assert_eq!(backups.backups, before_retry, "{id}");
    }
    // A repeat changes nothing.
    let (b, r) = (backups.backups, backups.records);
    let repeat = install::uninstall(
        &opts,
        &mut Writer {
            state: &mut state,
            journal: &mut journal,
            backups: &mut backups,
            now,
        },
    );
    assert!(repeat.complete(), "{id}");
    assert_eq!(std::fs::read(&path).unwrap(), final_bytes, "{id}");
    assert_eq!((backups.backups, backups.records), (b, r), "{id}");
    assert_eq!(network_access(&final_bytes), Some(false), "{id}");
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_refused_structural_undo_is_made_once_there_is_room() {
    let dir = tempfile::tempdir().unwrap();
    let parent = std::fs::canonicalize(dir.path()).unwrap();
    for id in 0..4 {
        run_case(&parent, id);
    }
}
