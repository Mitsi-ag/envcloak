//! Grants and approvals over the daemon's socket (SPEC §6.1 steps 2 to 4,
//! §10a "Bounds", §10b): the daemon parts of gates 23, 28, 29, 30 and 32,
//! with the test process as the caller. Real agents and terminals are in
//! `crates/envcloak-cli/tests/approve.rs`; the store's rules on synthetic
//! chains in `crates/envcloak-policy/tests/grants.rs`.
//!
//! The caller here is this test process, so `unlock` and `approve` need
//! it to have no agent in its ancestry: CI runs it that way. Under a
//! developer's Claude Code the proofs are refused, as they must be; run
//! the tests outside the agent's tree then (on macOS, `launchctl submit`).
//! Every test sweeps the daemon's log for the passphrase, the kit and the
//! values.
#![allow(clippy::unwrap_used)]

mod common;

use std::os::unix::fs::symlink;
use std::time::{Duration, Instant};

use common::{MANIFEST, SLUGS, client, data_dir, passphrase, project, seed_vault, start};
use envcloak_core::SecretBytes;
use envcloak_core::vault::VaultPaths;
use envcloak_ipc::proto::{ErrorKind, RunRequestParams};
use envcloak_ipc::view::{DecisionView, VaultState};
use envcloak_ipc::{Client, ClientError};
use envcloak_policy::{
    ApprovalOptions, DenyReason, FREE_ATTEMPTS, GrantId, MAX_PENDING_PER_ROOT, PendingId,
    SubjectKind, Uses, statement_digest,
};
use envcloak_testkit::{
    Canary, Daemon, TestHome, assert_no_canary, by_label, canaries, fresh_seed, labels,
};

fn rpc_kind(e: ClientError) -> (ErrorKind, Option<&'static str>) {
    match e {
        ClientError::Rpc(r) => (r.kind, r.reason),
        other => panic!("expected an error response, got {other:?}"),
    }
}

/// A seeded vault, a running daemon with it unlocked, and the project.
struct Fixture {
    cs: Vec<Canary>,
    home: TestHome,
    d: Daemon,
    manifest: String,
}

impl Fixture {
    fn new() -> Self {
        let cs = canaries(fresh_seed());
        let home = TestHome::new();
        let kit = seed_vault(&home, &cs);
        let mut cs = cs;
        cs.push(kit);
        let d = start(&home);
        let mut c = client(&home);
        c.unlock(passphrase(&cs), &[]).unwrap();
        assert_eq!(c.status().unwrap().vault.state, VaultState::Unlocked);
        let manifest = project(&home, "acme-web", MANIFEST);
        Fixture {
            cs,
            home,
            d,
            manifest: manifest.to_str().unwrap().to_owned(),
        }
    }

    fn params(&self, argv: &[&str]) -> RunRequestParams {
        RunRequestParams {
            manifest: self.manifest.clone(),
            profile: None,
            refs: Vec::new(),
            argv: argv.iter().map(|a| (*a).to_owned()).collect(),
            claims: Vec::new(),
        }
    }

    fn request(&self, argv: &[&str]) -> DecisionView {
        client(&self.home).run_request(&self.params(argv)).unwrap()
    }

    /// Approves `id` with `opts`, computing the digest from what the
    /// daemon shows, with `pass`.
    fn approve(&self, id: &str, opts: ApprovalOptions, pass: &[u8]) -> Result<String, ClientError> {
        let mut c = client(&self.home);
        let d = c.pending_get(id)?;
        let digest = statement_digest(&d, &opts);
        c.approve(id, opts, &digest, SecretBytes::copy_from(pass), &[])
            .map(|a| a.grant)
    }

    /// The passphrase's bytes, from the canary.
    fn pass(&self) -> &[u8] {
        by_label(&self.cs, labels::VAULT_PASSPHRASE).value()
    }

    fn approve_ok(&self, id: &str, opts: ApprovalOptions) -> String {
        self.approve(id, opts, self.pass()).unwrap()
    }

    fn sweep(&self) {
        assert_no_canary(&self.d.log_bytes(), &self.cs);
        self.home.assert_clean(&self.cs);
    }
}

fn pending(d: &DecisionView) -> String {
    match d {
        DecisionView::Pending { request } => {
            PendingId::parse(request).unwrap();
            request.clone()
        }
        other => panic!("expected pending, got {other:?}"),
    }
}

fn covered(d: &DecisionView) -> String {
    match d {
        DecisionView::Covered { grant, .. } => {
            GrantId::parse(grant).unwrap();
            grant.clone()
        }
        other => panic!("expected covered, got {other:?}"),
    }
}

fn session(secs: u64) -> ApprovalOptions {
    ApprovalOptions::session(Duration::from_secs(secs))
}

/// The story's S4 to S6 decisions, gate 23's passphrase and statement
/// checks, gate 28's binding changes and gate 29's revocation, on one
/// daemon.
#[test]
fn a_request_is_pending_until_approved_then_covered() {
    let mut f = Fixture::new();
    let mut c = client(&f.home);

    // S4: no grant covers the first request.
    let id = pending(&f.request(&["./emit", "--flag"]));
    let st = c.status().unwrap();
    assert_eq!((st.approvals.grants, st.approvals.pending), (0, 1));
    let d = c.pending_get(&id).unwrap();
    assert_eq!(d.request, id);
    assert!(d.project.new_project);
    assert!(d.project.dir.ends_with("acme-web"), "{}", d.project.dir);
    assert_eq!(d.argv, vec!["./emit", "--flag"]);
    assert_eq!(d.bindings.len(), 2);
    assert_eq!(d.bindings[0].env_name, "OPENAI_API_KEY");
    assert_eq!(d.bindings[0].slug, SLUGS[0]);
    assert!(d.bindings.iter().all(|b| b.first_use));
    assert_eq!(
        d.subject.caller_pid,
        i32::try_from(std::process::id()).unwrap()
    );
    // The same request again is the same pending request.
    assert_eq!(pending(&f.request(&["./emit", "--flag"])), id);

    // S5: a wrong passphrase is refused and counted; a wrong statement
    // is refused; the right one creates the grant.
    let e = f
        .approve(&id, session(3600), b"not the passphrase, not at all")
        .unwrap_err();
    assert_eq!(rpc_kind(e).0, ErrorKind::WrongPassphrase);
    assert_eq!(c.status().unwrap().approvals.proof_failures, 1);
    let mut wrong = statement_digest(&d, &session(3600));
    wrong[5] ^= 0x40;
    let e = c
        .approve(&id, session(3600), &wrong, passphrase(&f.cs), &[])
        .unwrap_err();
    assert_eq!(rpc_kind(e).0, ErrorKind::StatementMismatch);
    // Options other than the ones the digest covers: refused too.
    let digest = statement_digest(&d, &session(3600));
    let e = c
        .approve(&id, session(3599), &digest, passphrase(&f.cs), &[])
        .unwrap_err();
    assert_eq!(rpc_kind(e).0, ErrorKind::StatementMismatch);
    // Out-of-bounds options are refused before the passphrase is looked
    // at: the failure count does not move.
    let e = f.approve(&id, session(25 * 3600), b"whatever").unwrap_err();
    assert_eq!(
        rpc_kind(e),
        (ErrorKind::InvalidOptions, Some("ttl_too_long"))
    );
    assert_eq!(c.status().unwrap().approvals.proof_failures, 1);
    let e = c.pending_get("ZZZZZZZZ").unwrap_err();
    assert_eq!(rpc_kind(e).0, ErrorKind::NoSuchRequest);
    let e = c.pending_get("not an id").unwrap_err();
    assert_eq!(rpc_kind(e).0, ErrorKind::InvalidParams);

    let grant = f.approve_ok(&id, session(3600));
    assert_eq!(c.status().unwrap().approvals.proof_failures, 0);
    let e = c.pending_get(&id).unwrap_err();
    assert_eq!(rpc_kind(e).0, ErrorKind::NoSuchRequest);
    let list = c.grants_list().unwrap();
    assert_eq!(list.grants.len(), 1);
    let g = &list.grants[0];
    assert_eq!(g.id, grant);
    assert_eq!(g.uses, Uses::Session);
    assert!(
        g.remaining_secs > 3500 && g.remaining_secs <= 3600,
        "{}",
        g.remaining_secs
    );
    assert_eq!(g.bindings.len(), 2);
    assert!(g.project_dir.ends_with("acme-web"));
    assert_ne!(g.kind, SubjectKind::Agent);

    // S6: covered now, with any command line, and by a subset.
    let d = f.request(&["./emit", "--flag"]);
    assert_eq!(covered(&d), grant);
    match d {
        DecisionView::Covered {
            redact,
            manifest_changed,
            ..
        } => {
            assert!(redact);
            assert!(!manifest_changed);
        }
        _ => unreachable!(),
    }
    assert_eq!(covered(&f.request(&["npm", "test"])), grant);
    let mut fewer = f.params(&["true"]);
    fewer.refs = vec!["OPENAI_API_KEY=openai/acme-web".to_owned()];
    assert_eq!(
        covered(&client(&f.home).run_request(&fewer).unwrap()),
        grant
    );

    // Gate 28: a comment-only manifest change is covered and audited; an
    // added reference, a retargeted or renamed variable and a profile
    // switch each prompt.
    std::fs::write(&f.manifest, format!("# a comment\n{MANIFEST}")).unwrap();
    match f.request(&["./emit"]) {
        DecisionView::Covered {
            manifest_changed, ..
        } => assert!(manifest_changed),
        other => panic!("{other:?}"),
    }
    assert!(
        f.d.wait_for_log(
            &format!("manifest changed grant={grant}"),
            Duration::from_secs(5)
        ),
        "{}",
        f.d.log()
    );
    let mut added = f.params(&["./emit"]);
    added.refs = vec!["GITHUB_TOKEN=github/acme-web".to_owned()];
    let mut retargeted = f.params(&["./emit"]);
    retargeted.refs = vec!["OPENAI_API_KEY=github/acme-web".to_owned()];
    let mut renamed = f.params(&["./emit"]);
    renamed.refs = vec!["OPENAI_KEY=openai/acme-web".to_owned()];
    let mut profile = f.params(&["./emit"]);
    profile.profile = Some("short".to_owned());
    let mut ids = Vec::new();
    let mut denied = 0;
    for p in [added, retargeted, renamed, profile] {
        match client(&f.home).run_request(&p).unwrap() {
            DecisionView::Pending { request } => ids.push(request),
            DecisionView::Denied { reason } => {
                assert_eq!(reason, DenyReason::PendingPerRoot.token());
                denied += 1;
            }
            other => panic!("{other:?}"),
        }
    }
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), MAX_PENDING_PER_ROOT);
    assert_eq!(denied, 1, "the fourth is denied by the per-root cap");

    // Gate 29: revocation needs no proof and ends the grant.
    assert_eq!(c.grants_revoke(Some(&grant)).unwrap().revoked, 1);
    assert_eq!(c.grants_revoke(Some(&grant)).unwrap().revoked, 0);
    assert!(c.grants_list().unwrap().grants.is_empty());
    assert_eq!(
        rpc_kind(c.grants_revoke(Some("nope")).unwrap_err()).0,
        ErrorKind::InvalidParams
    );
    f.sweep();
}

/// Gate 29: lock ends every grant and pending request; the same after a
/// daemon restart, which starts empty.
#[test]
fn lock_and_restart_end_grants_and_pending_requests() {
    let mut f = Fixture::new();
    let mut c = client(&f.home);
    let id = pending(&f.request(&["./emit"]));
    f.approve_ok(&id, session(60));
    // Another binding set, so the grant does not cover it.
    let mut short = f.params(&["./emit"]);
    short.profile = Some("short".to_owned());
    let other = pending(&client(&f.home).run_request(&short).unwrap());
    let st = c.status().unwrap();
    assert_eq!((st.approvals.grants, st.approvals.pending), (1, 1));

    assert!(c.lock().unwrap().was_unlocked);
    let st = c.status().unwrap();
    assert_eq!((st.approvals.grants, st.approvals.pending), (0, 0));
    assert!(c.grants_list().unwrap().grants.is_empty());
    assert_eq!(
        rpc_kind(c.pending_get(&other).unwrap_err()).0,
        ErrorKind::NoSuchRequest
    );
    // While locked, a request is refused, not queued.
    let e = c.run_request(&f.params(&["./emit"])).unwrap_err();
    assert_eq!(rpc_kind(e).0, ErrorKind::VaultLocked);
    c.unlock(passphrase(&f.cs), &[]).unwrap();
    assert!(matches!(
        f.request(&["./emit"]),
        DecisionView::Pending { .. }
    ));
    let id = pending(&f.request(&["./emit"]));
    f.approve_ok(&id, session(60));
    assert_eq!(c.grants_list().unwrap().grants.len(), 1);

    // A restart: grants live only in daemon memory.
    f.d.signal("-TERM");
    assert!(f.d.wait_exit(Duration::from_secs(10)).is_some());
    drop(c);
    f.d = start(&f.home);
    let mut c = client(&f.home);
    assert_eq!(c.status().unwrap().vault.state, VaultState::Locked);
    c.unlock(passphrase(&f.cs), &[]).unwrap();
    assert!(c.grants_list().unwrap().grants.is_empty());
    assert!(matches!(
        f.request(&["./emit"]),
        DecisionView::Pending { .. }
    ));
    f.sweep();
}

/// Gate 32: the pending caps hold, an identical request after a denial
/// is denied without a prompt, three denials auto-deny the root, and the
/// attempt limiter, shared with `unlock`, holds.
#[test]
fn flood_control_and_the_attempt_limiter_hold() {
    let mut f = Fixture::new();
    let mut c = client(&f.home);

    // The per-root cap: this process's root holds at most 3.
    let mut ids = Vec::new();
    for n in 0..MAX_PENDING_PER_ROOT {
        ids.push(pending(&f.request(&[&n.to_string()])));
    }
    match f.request(&["one more"]) {
        DecisionView::Denied { reason } => assert_eq!(reason, DenyReason::PendingPerRoot.token()),
        other => panic!("{other:?}"),
    }
    // Denying frees a place; an identical request is then denied at once.
    let denied = c.deny(&ids[0]).unwrap();
    assert!(!denied.root_auto_denied);
    assert_eq!(
        rpc_kind(c.deny(&ids[0]).unwrap_err()).0,
        ErrorKind::NoSuchRequest
    );
    match f.request(&["0"]) {
        DecisionView::Denied { reason } => assert_eq!(reason, DenyReason::Repeated.token()),
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        f.request(&["one more"]),
        DecisionView::Pending { .. }
    ));
    // Two more denials: the root is denied for 30 minutes.
    assert!(!c.deny(&ids[1]).unwrap().root_auto_denied);
    assert!(c.deny(&ids[2]).unwrap().root_auto_denied);
    match f.request(&["anything"]) {
        DecisionView::Denied { reason } => assert_eq!(reason, DenyReason::RootDenied.token()),
        other => panic!("{other:?}"),
    }
    assert!(f.d.wait_for_log("denied three times", Duration::from_secs(5)));
    f.sweep();

    // The limiter, on a daemon of its own: five failures cost nothing,
    // the sixth attempt is refused, and so is `unlock` (the limiter is
    // shared).
    let f = Fixture::new();
    let mut c = client(&f.home);
    let id = pending(&f.request(&["./emit"]));
    for n in 1..=FREE_ATTEMPTS {
        let e = f
            .approve(&id, session(60), b"wrong passphrase attempt")
            .unwrap_err();
        assert_eq!(rpc_kind(e).0, ErrorKind::WrongPassphrase, "attempt {n}");
    }
    let st = c.status().unwrap();
    assert_eq!(st.approvals.proof_failures, FREE_ATTEMPTS);
    assert!(st.approvals.proof_wait_secs > 20 && st.approvals.proof_wait_secs <= 30);
    let e = f.approve(&id, session(60), f.pass()).unwrap_err();
    assert_eq!(rpc_kind(e).0, ErrorKind::TooManyAttempts);
    assert!(c.lock().unwrap().was_unlocked);
    let e = c.unlock(passphrase(&f.cs), &[]).unwrap_err();
    assert_eq!(rpc_kind(e).0, ErrorKind::TooManyAttempts);
    assert_eq!(c.status().unwrap().vault.state, VaultState::Locked);
    f.sweep();
}

/// Gate 30: of concurrent requests on a `once` grant, exactly one is
/// covered; the others are pending.
#[test]
fn concurrent_requests_on_a_once_grant_cover_exactly_one() {
    let f = Fixture::new();
    let id = pending(&f.request(&["./emit"]));
    let grant = f.approve_ok(&id, ApprovalOptions::once(Duration::from_secs(600)));
    let params = f.params(&["./emit"]);
    let paths = common::run_paths(&f.home);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let (params, paths, barrier) = (params.clone(), paths.clone(), barrier.clone());
            std::thread::spawn(move || {
                let mut c = Client::connect(&paths).unwrap();
                barrier.wait();
                c.run_request(&params).unwrap()
            })
        })
        .collect();
    let decisions: Vec<DecisionView> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let covered: Vec<&DecisionView> = decisions
        .iter()
        .filter(|d| matches!(d, DecisionView::Covered { .. }))
        .collect();
    assert_eq!(covered.len(), 1, "{decisions:?}");
    assert_eq!(
        match covered[0] {
            DecisionView::Covered { grant: g, .. } => g.clone(),
            _ => unreachable!(),
        },
        grant
    );
    let mut pendings: Vec<String> = decisions
        .iter()
        .filter_map(|d| match d {
            DecisionView::Pending { request } => Some(request.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(pendings.len(), 7);
    pendings.dedup();
    assert_eq!(
        pendings.len(),
        1,
        "one pending request for the identical requests"
    );
    assert!(client(&f.home).grants_list().unwrap().grants.is_empty());
    f.sweep();
}

/// Gate 28: a symlinked path to the project keeps its identity; a copy of
/// the project is another one. Errors for a missing or loosening manifest
/// and an unknown item name their reason.
#[test]
fn project_identity_and_manifest_errors() {
    let f = Fixture::new();
    let id = pending(&f.request(&["./emit"]));
    let grant = f.approve_ok(&id, session(600));

    let link = f.home.root().join("link-to-acme");
    symlink(f.home.root().join("acme-web"), &link).unwrap();
    let mut via_link = f.params(&["./emit"]);
    via_link.manifest = link.join("envcloak.toml").to_str().unwrap().to_owned();
    assert_eq!(
        covered(&client(&f.home).run_request(&via_link).unwrap()),
        grant
    );

    let copy = project(&f.home, "acme-copy", MANIFEST);
    let mut via_copy = f.params(&["./emit"]);
    via_copy.manifest = copy.to_str().unwrap().to_owned();
    assert!(matches!(
        client(&f.home).run_request(&via_copy).unwrap(),
        DecisionView::Pending { .. }
    ));

    let mut missing = f.params(&["./emit"]);
    missing.manifest = f
        .home
        .root()
        .join("nowhere/envcloak.toml")
        .to_str()
        .unwrap()
        .to_owned();
    let e = client(&f.home).run_request(&missing).unwrap_err();
    assert_eq!(rpc_kind(e), (ErrorKind::ManifestInvalid, Some("not_found")));
    let mut relative = f.params(&["./emit"]);
    relative.manifest = "acme-web/envcloak.toml".to_owned();
    let e = client(&f.home).run_request(&relative).unwrap_err();
    assert_eq!(
        rpc_kind(e),
        (ErrorKind::ManifestInvalid, Some("invalid_path"))
    );

    let loose = project(
        &f.home,
        "loose",
        "[env]\nA = \"openai/acme-web\"\n[policy]\nagents = \"allow\"\n",
    );
    let mut p = f.params(&["./emit"]);
    p.manifest = loose.to_str().unwrap().to_owned();
    let e = client(&f.home).run_request(&p).unwrap_err();
    assert_eq!(
        rpc_kind(e),
        (ErrorKind::ManifestInvalid, Some("loose_policy"))
    );

    let mut unknown = f.params(&["./emit"]);
    unknown.refs = vec!["X=nobody/has-this".to_owned()];
    let e = client(&f.home).run_request(&unknown).unwrap_err();
    assert_eq!(
        rpc_kind(e),
        (ErrorKind::BindingUnresolved, Some("unknown_item"))
    );
    let mut bad_profile = f.params(&["./emit"]);
    bad_profile.profile = Some("nope".to_owned());
    let e = client(&f.home).run_request(&bad_profile).unwrap_err();
    assert_eq!(
        rpc_kind(e),
        (ErrorKind::BindingUnresolved, Some("unknown_profile"))
    );
    // Proxy mode is not in this build: refused rather than injected.
    let proxy = project(
        &f.home,
        "proxy",
        "[env]\nA = \"openai/acme-web\"\n[policy]\nmode = \"proxy\"\n",
    );
    let mut p = f.params(&["./emit"]);
    p.manifest = proxy.to_str().unwrap().to_owned();
    let e = client(&f.home).run_request(&p).unwrap_err();
    assert_eq!(rpc_kind(e).0, ErrorKind::ModeUnsupported);
    f.sweep();
}

/// No grant is evaluated, and no proof taken, from a vault whose
/// integrity check failed (T3's rule for `projects()` and `header()`,
/// carried to the grant path).
#[test]
fn a_tampered_vault_gives_no_decision_and_takes_no_proof() {
    let cs = canaries(fresh_seed());
    let home = TestHome::new();
    let kit = seed_vault(&home, &cs);
    let mut cs = cs;
    cs.push(kit);
    // Gate 6's deletion: a field row gone from the file.
    let db = VaultPaths::under(data_dir(&home)).db;
    let raw = rusqlite::Connection::open(&db).unwrap();
    raw.execute_batch("DELETE FROM fields WHERE rowid = (SELECT min(rowid) FROM fields);")
        .unwrap();
    drop(raw);
    let d = start(&home);
    let mut c = client(&home);
    let u = c.unlock(passphrase(&cs), &[]).unwrap();
    assert_eq!(u.integrity, envcloak_ipc::view::Integrity::Tampered);
    assert!(u.read_only);
    let manifest = project(&home, "acme-web", MANIFEST);
    let e = c
        .run_request(&RunRequestParams {
            manifest: manifest.to_str().unwrap().to_owned(),
            profile: None,
            refs: Vec::new(),
            argv: vec!["./emit".to_owned()],
            claims: Vec::new(),
        })
        .unwrap_err();
    assert_eq!(rpc_kind(e).0, ErrorKind::VaultTampered);
    let e = c
        .approve("ABCDEFGH", session(60), &[0u8; 32], passphrase(&cs), &[])
        .unwrap_err();
    assert_eq!(rpc_kind(e).0, ErrorKind::VaultTampered);
    assert_no_canary(&d.log_bytes(), &cs);
}

/// A grant lasts until its root exits: the daemon's tick drops it. The
/// root here is this test process's own root, so the check is that a
/// live root is kept across ticks; the exit half runs with a real agent
/// in the CLI tests.
#[test]
fn grants_survive_ticks_while_their_root_lives() {
    let f = Fixture::new();
    let id = pending(&f.request(&["./emit"]));
    let grant = f.approve_ok(&id, session(600));
    let end = Instant::now() + Duration::from_secs(3);
    while Instant::now() < end {
        std::thread::sleep(Duration::from_millis(500));
        let list = client(&f.home).grants_list().unwrap();
        assert_eq!(list.grants.len(), 1);
        assert_eq!(list.grants[0].id, grant);
    }
    f.sweep();
}
