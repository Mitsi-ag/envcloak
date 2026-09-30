//! The release path of `run.request` (SPEC §6.1 step 5, §15.2 gate 33's
//! release order): a covered request's answer carries the bindings'
//! values, and only once its audit entry is on disk; a pending or denied
//! one carries none; a delivery whose entry cannot be written, or whose
//! vault turns out changed on disk while open, releases nothing.
//!
//! The caller is this test process, made a terminal session so the daemon
//! takes its proofs (see crates/envcloak-daemon/tests/grants.rs).
#![allow(clippy::unwrap_used)]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use common::{
    MANIFEST, client, data_dir, flip_sealed_values, passphrase, project, sealed_values, seed_vault,
    start,
};
use envcloak_core::SecretBytes;
use envcloak_core::audit::AuditKind;
use envcloak_core::vault::{LockedVault, VaultPaths};
use envcloak_ipc::ClientError;
use envcloak_ipc::WireSecret;
use envcloak_ipc::proto::{AddParams, ErrorKind, RunAnswer, RunRequestParams};
use envcloak_ipc::view::{DecisionView, Integrity};
use envcloak_policy::{ApprovalOptions, statement_digest};
use envcloak_testkit::{
    Canary, Daemon, TestHome, assert_no_canary, by_label, canaries, fresh_seed, labels,
};

struct Fixture {
    cs: Vec<Canary>,
    home: TestHome,
    d: Daemon,
    manifest: String,
    /// Every sealed field value in the seeded file, in the order the items
    /// were seeded (`common::SLUGS`), read before the daemon opened it (it
    /// then holds the file exclusively).
    sealed: Vec<Vec<u8>>,
}

impl Fixture {
    fn new() -> Self {
        common::terminal_session();
        let cs = canaries(fresh_seed());
        let home = TestHome::new();
        let kit = seed_vault(&home, &cs);
        let mut cs = cs;
        cs.push(kit);
        let sealed = sealed_values(&home);
        let d = start(&home);
        client(&home).unlock(passphrase(&cs), &[]).unwrap();
        let manifest = project(&home, "acme-web", MANIFEST);
        Fixture {
            cs,
            home,
            d,
            manifest: manifest.to_str().unwrap().to_owned(),
            sealed,
        }
    }

    fn ask(&self, refs: &[&str]) -> Result<RunAnswer, ClientError> {
        client(&self.home).run_request(&RunRequestParams {
            manifest: self.manifest.clone(),
            profile: None,
            refs: refs.iter().map(|r| (*r).to_owned()).collect(),
            env_file: None,
            argv: vec!["./emit".to_owned()],
            claims: Vec::new(),
        })
    }

    fn approve(&self, answer: &RunAnswer) -> String {
        let DecisionView::Pending { request } = &answer.decision else {
            panic!("expected a pending request, got {:?}", answer.decision);
        };
        assert!(
            answer.values.is_empty(),
            "a pending request released values"
        );
        let mut c = client(&self.home);
        let opts = ApprovalOptions::session(Duration::from_secs(3600));
        let d = c.pending_get(request, &[]).unwrap();
        let digest = statement_digest(&d, &opts);
        let pass = by_label(&self.cs, labels::VAULT_PASSPHRASE).value();
        c.approve(request, opts, &digest, SecretBytes::copy_from(pass), &[])
            .unwrap()
            .grant
    }

    fn value(&self, label: &str) -> &[u8] {
        by_label(&self.cs, label).value()
    }

    fn sweep(&self) {
        assert_no_canary(&self.d.log_bytes(), &self.cs);
        self.home.assert_clean(&self.cs);
    }
}

fn rpc_kind(e: ClientError) -> ErrorKind {
    match e {
        ClientError::Rpc(r) => r.kind,
        other => panic!("expected an error response, got {other:?}"),
    }
}

/// `(env_name, slug, allow_short)` of each released value.
fn released(a: &RunAnswer) -> Vec<(&str, &str, bool)> {
    a.values
        .iter()
        .map(|v| (v.env_name.as_str(), v.slug.as_str(), v.allow_short))
        .collect()
}

fn equals(v: &WireSecret, want: &[u8]) -> bool {
    v.as_secret().ct_eq(want)
}

/// A covered request carries each binding's value, under its variable and
/// slug, with the item's `allow_short`; the entry for it is on disk before
/// the answer: the daemon is killed as soon as the answer arrives, with
/// nothing written after, and the log read back ends with the delivery.
#[test]
fn a_covered_request_carries_the_values_after_its_entry() {
    let f = Fixture::new();
    let grant = f.approve(&f.ask(&[]).unwrap());
    let a = f.ask(&[]).unwrap();
    assert!(
        matches!(&a.decision, DecisionView::Covered { grant: g, .. } if *g == grant),
        "{:?}",
        a.decision
    );
    assert_eq!(
        released(&a),
        vec![
            ("OPENAI_API_KEY", "openai/acme-web", false),
            ("STRIPE_SECRET_KEY", "stripe/acme-web", false),
        ]
    );
    assert!(equals(&a.values[0].value, f.value(labels::OPENAI_API_KEY)));
    assert!(equals(
        &a.values[1].value,
        f.value(labels::STRIPE_SECRET_KEY)
    ));
    drop(a);

    // An item that takes short values, asked for by `--ref`: the
    // difference prompts, and once approved it goes out with its flag.
    let short = f.value(labels::SHORT_TOKEN).to_vec();
    client(&f.home)
        .items_add(&AddParams {
            slug: Some("short/allowed".to_owned()),
            provider: None,
            field: None,
            account: None,
            env_hint: None,
            allow_short: true,
            value: WireSecret::new(SecretBytes::copy_from(&short)),
            claims: Vec::new(),
        })
        .unwrap();
    let refs = ["SHORT_TOKEN=short/allowed"];
    f.approve(&f.ask(&refs).unwrap());
    let a = f.ask(&refs).unwrap();
    assert_eq!(
        released(&a),
        vec![
            ("OPENAI_API_KEY", "openai/acme-web", false),
            ("SHORT_TOKEN", "short/allowed", true),
            ("STRIPE_SECRET_KEY", "stripe/acme-web", false),
        ]
    );
    assert!(equals(&a.values[1].value, &short));
    let DecisionView::Covered { grant: last, .. } = &a.decision else {
        panic!("{:?}", a.decision);
    };
    let last = last.clone();
    drop(a);

    // Killed at once: the delivery's entry was written before the answer.
    let mut f = f;
    f.d.signal("-KILL");
    assert!(f.d.wait_exit(Duration::from_secs(30)).is_some());
    let v = LockedVault::open(&VaultPaths::under(data_dir(&f.home)))
        .unwrap()
        .unlock_with_passphrase(&passphrase(&f.cs))
        .map_err(|(_, e)| e)
        .unwrap();
    let (entries, _) = v.read_audit().unwrap();
    let e = entries.last().unwrap();
    assert_eq!(e.record.kind, AuditKind::Run);
    assert_eq!(e.record.decision.outcome, "covered");
    assert_eq!(e.record.grant_id.as_deref(), Some(last.as_str()));
    for e in &entries {
        assert_no_canary(format!("{:?}", e.record).as_bytes(), &f.cs);
    }
    drop(v);
    f.sweep();
}

/// A covered request whose entry cannot be written is denied with no
/// value; once the log can be written again, the same grant releases. A
/// vault changed on disk while open releases nothing: the read that meets
/// the change turns it tampered, and every request after is refused, even
/// for items whose rows are intact.
#[test]
fn an_audit_failure_or_a_changed_vault_releases_nothing() {
    let f = Fixture::new();
    f.approve(&f.ask(&[]).unwrap());
    assert_eq!(f.ask(&[]).unwrap().values.len(), 2);

    // Another program running as the user removes the log's directory and
    // puts a file in its place: no entry can be written.
    let audit = data_dir(&f.home).join("audit");
    std::fs::remove_dir_all(&audit).unwrap();
    std::fs::write(&audit, b"in the way").unwrap();
    let a = f.ask(&[]).unwrap();
    assert_eq!(
        a.decision,
        DecisionView::Denied {
            reason: "audit_failed".to_owned()
        }
    );
    assert!(a.values.is_empty());
    std::fs::remove_file(&audit).unwrap();
    std::fs::create_dir(&audit).unwrap();
    std::fs::set_permissions(&audit, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(f.ask(&[]).unwrap().values.len(), 2);

    // The GitHub item's sealed value, one bit flipped in the file while the
    // daemon has it open; a write transaction (adding an item) drops the
    // pages SQLite cached, so the next read of it meets the change. The
    // bound items' rows are intact.
    let db = VaultPaths::under(data_dir(&f.home)).db;
    assert_eq!(flip_sealed_values(&db, &f.sealed[2..3]), 1);
    client(&f.home)
        .items_add(&AddParams {
            slug: Some("other/item".to_owned()),
            provider: None,
            field: None,
            account: None,
            env_hint: None,
            allow_short: false,
            value: WireSecret::new(SecretBytes::copy_from(
                f.value(labels::OPENAI_API_KEY_ROTATED),
            )),
            claims: Vec::new(),
        })
        .unwrap();
    assert_eq!(f.ask(&[]).unwrap().values.len(), 2);
    // A request that reads the changed row turns the vault tampered ...
    match f.ask(&["GITHUB_TOKEN=github/acme-web"]) {
        Ok(a) => assert!(a.values.is_empty(), "{:?}", a.decision),
        Err(e) => assert_eq!(rpc_kind(e), ErrorKind::VaultTampered),
    }
    // ... and nothing more is released from it, the intact rows included.
    for _ in 0..2 {
        assert_eq!(rpc_kind(f.ask(&[]).unwrap_err()), ErrorKind::VaultTampered);
    }
    let st = client(&f.home).status().unwrap();
    assert_eq!(st.vault.integrity, Some(Integrity::Tampered));
    f.sweep();
}
