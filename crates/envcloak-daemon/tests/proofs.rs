//! Proofs from a caller that is not a terminal session (SPEC §10b "Approval
//! proofs"; gate 23): this test process first leaves its session for a new
//! one without a controlling terminal, as a job a service manager starts
//! does (`launchctl submit`, `systemd-run --user`), or a command that
//! forked out of an agent's tree and called `setsid`. Such a caller is no
//! orphan and shows no agent, yet no person can type a proof there, so
//! `unlock`, `approve` and `pending.get` are refused before the passphrase
//! is looked at, and audited; so are `items.target`, `items.rotate` and
//! `items.remove` (T11). That a request from such a caller is still
//! decided, and that its own `envcloak approve` gets no grant, is in
//! `crates/envcloak-cli/tests/approve.rs`.
//!
//! The session change is process-wide, so this is a test binary of its
//! own, with one test. Under a developer's agent the refusals give the
//! agent as the reason instead.
#![allow(clippy::unwrap_used)]

mod common;

use std::time::Duration;

use common::{client, passphrase, seed_vault, start};
use envcloak_core::SecretBytes;
use envcloak_ipc::ClientError;
use envcloak_ipc::proto::ErrorKind;
use envcloak_ipc::view::{ClassificationView, ItemClassView, ItemView, TargetView, VaultState};
use envcloak_policy::ApprovalOptions;
use envcloak_testkit::{TestHome, assert_no_canary, canaries, fresh_seed};

fn rpc_kind(e: ClientError) -> ErrorKind {
    match e {
        ClientError::Rpc(r) => r.kind,
        other => panic!("expected an error response, got {other:?}"),
    }
}

/// Whether the daemon's log refuses a proof for `method` with a reason
/// this caller can have: no terminal, or an agent above the tests.
fn refused_in_log(log: &str, method: &str) -> bool {
    ["no_terminal", "agent"]
        .iter()
        .any(|r| log.contains(&format!("proof refused method={method} reason={r} ")))
}

#[test]
fn a_caller_without_a_terminal_gives_no_proof() {
    envcloak_sys::testing::setsid().expect("this test process could not start a session");
    let cs = canaries(fresh_seed());
    let home = TestHome::new();
    let kit = seed_vault(&home, &cs);
    let mut cs = cs;
    cs.push(kit);
    let mut d = start(&home);
    let mut c = client(&home);

    // Unlocking is a proof: refused, the vault stays locked, and no
    // attempt is counted, so the passphrase was never looked at.
    let e = c.unlock(passphrase(&cs), &[]).unwrap_err();
    assert_eq!(rpc_kind(e), ErrorKind::ProofRefused);
    let st = c.status().unwrap();
    assert_eq!(st.vault.state, VaultState::Locked);
    assert_eq!(st.vault.failed_unlocks, 0);
    assert_eq!(st.approvals.proof_failures, 0);
    assert!(
        d.wait_for_log("proof refused method=unlock", Duration::from_secs(5)),
        "{}",
        d.log()
    );
    assert!(refused_in_log(&d.log(), "unlock"), "{}", d.log());

    // `pending.get` and `approve` are refused before the request is looked
    // up: an unknown id gets the same answer as a real one would.
    let e = c.pending_get("ABCDEFGH", &[]).unwrap_err();
    assert_eq!(rpc_kind(e), ErrorKind::ProofRefused);
    let e = c
        .approve(
            "ABCDEFGH",
            ApprovalOptions::session(Duration::from_secs(60)),
            &[0u8; 32],
            passphrase(&cs),
            &[],
        )
        .unwrap_err();
    assert_eq!(rpc_kind(e), ErrorKind::ProofRefused);
    // A malformed id is still a malformed id.
    let e = c.pending_get("not an id", &[]).unwrap_err();
    assert_eq!(rpc_kind(e), ErrorKind::InvalidParams);
    let e = c
        .unlock(
            SecretBytes::copy_from(b"not the passphrase, not at all"),
            &[],
        )
        .unwrap_err();
    assert_eq!(rpc_kind(e), ErrorKind::ProofRefused);
    assert_eq!(c.status().unwrap().approvals.proof_failures, 0);
    let log = d.log();
    assert!(refused_in_log(&log, "pending.get"), "{log}");
    assert!(refused_in_log(&log, "approve"), "{log}");

    // Rotating and removing an item are proofs too, and the target a
    // statement would show is not served here either.
    let e = c.items_target("openai/acme-web", None, &[]).unwrap_err();
    assert_eq!(rpc_kind(e), ErrorKind::ProofRefused);
    let target = TargetView {
        item: ItemView {
            id: "01K00000000000000000000000".into(),
            slug: "openai/acme-web".into(),
            class: ItemClassView::Secret,
            title: String::new(),
            provider: None,
            classification: ClassificationView::Unknown,
            env_hint: None,
            allow_short: false,
            fields: Vec::new(),
            created_secs: 0,
            updated_secs: 0,
            rotated_secs: None,
            expires_secs: None,
            account: None,
            detail: None,
        },
        field: Some("value".into()),
        grants: 0,
    };
    let rotated = c.items_rotate(
        &target,
        SecretBytes::copy_from(b"a new value, long enough"),
        passphrase(&cs),
        &[],
    );
    assert_eq!(rpc_kind(rotated.unwrap_err()), ErrorKind::ProofRefused);
    let removed = c.items_remove(&target, passphrase(&cs), &[]);
    assert_eq!(rpc_kind(removed.unwrap_err()), ErrorKind::ProofRefused);
    assert_eq!(c.status().unwrap().approvals.proof_failures, 0);
    assert!(
        d.wait_for_log("proof refused method=items.remove", Duration::from_secs(5)),
        "{}",
        d.log()
    );
    let log = d.log();
    for method in ["items.target", "items.rotate", "items.remove"] {
        assert!(refused_in_log(&log, method), "{method}: {log}");
    }
    assert_no_canary(&d.log_bytes(), &cs);
    home.assert_clean(&cs);
}
