//! M3-04 project index metadata, verification, cursor and frame gates.
#![allow(clippy::unwrap_used)]

mod common;

use common::{client, data_dir, passphrase, project, seed_vault, start};
use envcloak_core::vault::{LockedVault, ProjectBinding, ProjectKey, ProjectRecord, VaultPaths};
use envcloak_ipc::ClientError;
use envcloak_ipc::proto::{ErrorKind, RunRequestParams};
use envcloak_ipc::view::DecisionView;
use envcloak_policy::{ApprovalOptions, statement_digest};
use envcloak_testkit::{TestHome, assert_no_canary, canaries, fresh_seed};
use sha2::{Digest, Sha256};
use std::time::Duration;

fn kind(e: ClientError) -> ErrorKind {
    match e {
        ClientError::Rpc(e) => e.kind,
        _ => panic!("expected RPC refusal"),
    }
}

#[test]
fn projects_adopted_by_run_are_listed_with_current_bindings_and_hashes() {
    common::terminal_session();
    let home = TestHome::new();
    let mut cs = canaries(fresh_seed());
    cs.push(seed_vault(&home, &cs));
    let daemon = start(&home);
    let mut c = client(&home);
    assert_eq!(
        kind(c.projects_list(None).unwrap_err()),
        ErrorKind::VaultLocked
    );
    c.unlock(passphrase(&cs), &[]).unwrap();
    assert!(c.projects_list(None).unwrap().projects.is_empty());
    for (name, text) in [
        ("first", "[env]\nA='openai/acme-web'\n"),
        ("second", "[env]\nB='stripe/acme-web'\n"),
    ] {
        let path = project(&home, name, text);
        let params = RunRequestParams {
            manifest: path.to_str().unwrap().into(),
            profile: None,
            refs: vec![],
            env_file: None,
            argv: vec!["/usr/bin/true".into()],
            claims: vec![],
        };
        let DecisionView::Pending { request } = c.run_request(&params).unwrap().decision else {
            panic!("pending")
        };
        let statement = c.pending_get(&request, &[]).unwrap();
        let options = ApprovalOptions::session(Duration::from_secs(60));
        c.approve(
            &request,
            options.clone(),
            &statement_digest(&statement, &options),
            passphrase(&cs),
            &[],
        )
        .unwrap();
        assert!(matches!(
            c.run_request(&params).unwrap().decision,
            DecisionView::Covered { .. }
        ));
    }
    let page = c.projects_list(None).unwrap();
    assert_eq!(page.projects.len(), 2);
    assert!(page.next.is_none());
    for row in &page.projects {
        let text = std::fs::read(std::path::Path::new(&row.dir).join("envcloak.toml")).unwrap();
        assert_eq!(
            row.manifest_sha256,
            Sha256::digest(&text)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        assert_eq!(row.bindings.len(), 1);
        assert!(row.last_seen_secs > 0);
        let expected = if row.dir.ends_with("first") {
            ("A", "openai/acme-web")
        } else {
            ("B", "stripe/acme-web")
        };
        assert_eq!(
            (
                row.bindings[0].env_name.as_str(),
                row.bindings[0].reference.as_str()
            ),
            expected
        );
    }
    assert_no_canary(&serde_json::to_vec(&page).unwrap(), &cs);
    // A covered run updates the adopted hash instead of keeping a stale
    // copy from the first use. No new approval for a comment-only edit.
    let path = project(&home, "first", "# edited\n[env]\nA='openai/acme-web'\n");
    let params = RunRequestParams {
        manifest: path.to_str().unwrap().into(),
        profile: None,
        refs: vec![],
        env_file: None,
        argv: vec!["/usr/bin/true".into()],
        claims: vec![],
    };
    assert!(matches!(
        c.run_request(&params).unwrap().decision,
        DecisionView::Covered { .. }
    ));
    let refreshed = c.projects_list(None).unwrap();
    assert_eq!(refreshed.projects.len(), 2);
    let old = page
        .projects
        .iter()
        .find(|p| p.dir.ends_with("/first"))
        .unwrap();
    let new = refreshed
        .projects
        .iter()
        .find(|p| p.dir.ends_with("/first"))
        .unwrap();
    assert_ne!(old.manifest_sha256, new.manifest_sha256);
    assert_eq!(new.bindings, old.bindings);
    c.lock().unwrap();
    assert_eq!(
        kind(c.projects_list(None).unwrap_err()),
        ErrorKind::VaultLocked
    );
    assert_no_canary(&daemon.log_bytes(), &cs);
    home.assert_clean(&cs);
}

#[test]
fn projects_hostile_cursors_are_refused_without_echo() {
    let home = TestHome::new();
    let cs = canaries(fresh_seed());
    let _daemon = start(&home);
    for params in [
        serde_json::json!({"extra": true}),
        serde_json::json!({"after": {"last_seen": -1, "id": ""}}),
        serde_json::json!({"after": {"last_seen": 1, "id": "é\n"}}),
        serde_json::json!({"after": {"last_seen": 1, "id": "x".repeat(10000)}}),
        serde_json::json!({"after": {"last_seen": 1, "id": "Z".repeat(26)}}),
        serde_json::json!({"after": {"last_seen": 1, "id": std::str::from_utf8(cs[0].value()).unwrap()}}),
    ] {
        let mut stream = common::raw(&home);
        common::send_json(
            &mut stream,
            &serde_json::json!({"jsonrpc":"2.0","id":1,"method":"projects.list","params":params}),
        );
        let answer = common::read_json(&mut stream).unwrap();
        assert_eq!(common::error_kind(&answer), "invalid_params");
        assert_no_canary(&serde_json::to_vec(&answer).unwrap(), &cs);
    }
}

#[test]
fn projects_tampered_vault_never_reports_an_empty_success() {
    common::terminal_session();
    let home = TestHome::new();
    let cs = canaries(fresh_seed());
    seed_vault(&home, &cs);
    let db = rusqlite::Connection::open(VaultPaths::under(data_dir(&home)).db).unwrap();
    db.execute_batch("DELETE FROM fields WHERE rowid=(SELECT min(rowid) FROM fields)")
        .unwrap();
    drop(db);
    let _daemon = start(&home);
    let mut c = client(&home);
    c.unlock(passphrase(&cs), &[]).unwrap();
    assert_eq!(
        kind(c.projects_list(None).unwrap_err()),
        ErrorKind::VaultTampered
    );
}

#[test]
fn projects_worst_case_pages_fit_and_cursor_survives_a_new_adoption() {
    common::terminal_session();
    let home = TestHome::new();
    let cs = canaries(fresh_seed());
    seed_vault(&home, &cs);
    let paths = VaultPaths::under(data_dir(&home));
    let mut vault = LockedVault::open(&paths)
        .unwrap()
        .unlock_with_passphrase(&passphrase(&cs))
        .map_err(|(_, e)| e)
        .unwrap();
    let mut expected = Vec::new();
    vault
        .transact(|t| {
            for n in 0..32_u64 {
                let record = ProjectRecord {
                    key: ProjectKey::new(&n.to_be_bytes())?,
                    display_path: format!("/{n}/{}", "\u{1}\"\\é".repeat(6000)),
                    manifest_sha256: [u8::try_from(n).unwrap(); 32],
                    bindings: (0..150)
                        .map(|i| ProjectBinding {
                            env_name: format!("NAME_{i}"),
                            reference: "ordinary/item#value".into(),
                        })
                        .collect(),
                    last_seen: n / 4,
                };
                let id = t.upsert_project(record.clone())?;
                expected.push((record.last_seen, id, record.display_path));
            }
            Ok(())
        })
        .unwrap();
    drop(vault);
    expected.sort_by_key(|a| std::cmp::Reverse((a.0, a.1)));
    let daemon = start(&home);
    let mut c = client(&home);
    c.unlock(passphrase(&cs), &[]).unwrap();
    let first = c.projects_list(None).unwrap();
    assert!(first.next.is_some());
    let mut oracle = std::process::Command::new("python3");
    home.apply(&mut oracle)
        .arg(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/oracles/project_pages.py"),
        )
        .arg(common::run_paths(&home).socket)
        .arg("32");
    let result = oracle.output().unwrap();
    assert!(
        result.status.success(),
        "independent frame oracle: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let mut seen = Vec::new();
    let mut after = None;
    let mut pages = 0;
    loop {
        let page = c.projects_list(after).unwrap();
        let encoded = serde_json::to_vec(&page).unwrap();
        assert!(encoded.len() <= 768 * 1024, "page budget");
        let frame = envcloak_ipc::proto::result_frame(u64::MAX, &page).unwrap();
        assert!(frame.len() <= envcloak_ipc::MAX_FRAME);
        assert!(!page.projects.is_empty());
        seen.extend(page.projects.into_iter().map(|p| p.dir));
        pages += 1;
        assert!(pages <= 32, "cursor must advance");
        let Some(next) = page.next else { break };
        after = Some(next);
    }
    assert!(
        seen == expected.into_iter().map(|e| e.2).collect::<Vec<_>>(),
        "cursor order and completeness"
    );
    // A new project adopted above the cursor is visible on refresh only.
    let path = project(&home, "new", "[env]\nA='openai/acme-web'\n");
    let params = RunRequestParams {
        manifest: path.to_str().unwrap().into(),
        profile: None,
        refs: vec![],
        env_file: None,
        argv: vec!["/usr/bin/true".into()],
        claims: vec![],
    };
    let DecisionView::Pending { request } = c.run_request(&params).unwrap().decision else {
        panic!("pending")
    };
    let statement = c.pending_get(&request, &[]).unwrap();
    let options = ApprovalOptions::session(Duration::from_secs(60));
    c.approve(
        &request,
        options.clone(),
        &statement_digest(&statement, &options),
        passphrase(&cs),
        &[],
    )
    .unwrap();
    c.run_request(&params).unwrap();
    let continued = c.projects_list(first.next).unwrap();
    assert!(continued.projects.iter().all(|p| !p.dir.ends_with("/new")));
    assert!(
        c.projects_list(None).unwrap().projects[0]
            .dir
            .ends_with("/new")
    );
    assert_no_canary(&daemon.log_bytes(), &cs);
}
