//! Grants and approvals over the daemon's socket (SPEC §6.1 steps 2 to 4,
//! §10a "Bounds", §10b): the daemon parts of gates 23, 28, 29, 30 and 32,
//! with the test process as the caller. Real agents and terminals are in
//! `crates/envcloak-cli/tests/approve.rs`; the store's rules on synthetic
//! chains in `crates/envcloak-policy/tests/grants.rs`.
//!
//! The caller here is this test process, so `unlock` and `approve` need
//! it to be a terminal subject with no agent in its ancestry: each test
//! makes it a terminal session first (`common::terminal_session`), and CI
//! has no agent above it. Under a developer's Claude Code the proofs are
//! refused, as they must be; run the tests outside the agent's tree then
//! (on macOS, `launchctl submit`).
//! Every test sweeps the daemon's log for the passphrase, the kit and the
//! values.
#![allow(clippy::unwrap_used)]

mod common;

use std::os::unix::fs::symlink;
use std::sync::{Arc, Condvar, Mutex, PoisonError, mpsc};
use std::time::{Duration, Instant};

use common::{MANIFEST, SLUGS, client, data_dir, passphrase, project, seed_vault, start};
use envcloak_core::SecretBytes;
use envcloak_core::vault::VaultPaths;
use envcloak_ipc::proto::{EnvFileLine, EnvFileParams, ErrorKind, RunRequestParams};
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
        common::terminal_session();
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
            env_file: None,
            argv: argv.iter().map(|a| (*a).to_owned()).collect(),
            claims: Vec::new(),
        }
    }

    fn request(&self, argv: &[&str]) -> DecisionView {
        client(&self.home)
            .run_request(&self.params(argv))
            .unwrap()
            .decision
    }

    /// Approves `id` with `opts`, computing the digest from what the
    /// daemon shows, with `pass`.
    fn approve(&self, id: &str, opts: ApprovalOptions, pass: &[u8]) -> Result<String, ClientError> {
        let mut c = client(&self.home);
        let d = c.pending_get(id, &[])?;
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

/// Lower-case hex of the SHA-256 of `bytes`.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Polls `cond` until it holds or `limit` passes.
fn wait_until(limit: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + limit;
    loop {
        if cond() {
            return true;
        }
        if Instant::now() >= end {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
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
    let d = c.pending_get(&id, &[]).unwrap();
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
    let e = c.pending_get("ZZZZZZZZ", &[]).unwrap_err();
    assert_eq!(rpc_kind(e).0, ErrorKind::NoSuchRequest);
    let e = c.pending_get("not an id", &[]).unwrap_err();
    assert_eq!(rpc_kind(e).0, ErrorKind::InvalidParams);

    let grant = f.approve_ok(&id, session(3600));
    assert_eq!(c.status().unwrap().approvals.proof_failures, 0);
    let e = c.pending_get(&id, &[]).unwrap_err();
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
        covered(&client(&f.home).run_request(&fewer).unwrap().decision),
        grant
    );

    // Gate 28: a comment-only manifest change is covered, and audited with
    // the hash at approval and the new one, each the SHA-256 of the file's
    // bytes; an added reference, a retargeted or renamed variable and a
    // profile switch each prompt.
    let rewritten = format!("# a comment\n{MANIFEST}");
    std::fs::write(&f.manifest, &rewritten).unwrap();
    match f.request(&["./emit"]) {
        DecisionView::Covered {
            manifest_changed, ..
        } => assert!(manifest_changed),
        other => panic!("{other:?}"),
    }
    let audited = format!(
        "manifest changed grant={grant} approved_sha256={} sha256={} pid=",
        sha256_hex(MANIFEST.as_bytes()),
        sha256_hex(rewritten.as_bytes())
    );
    assert!(
        f.d.wait_for_log(&audited, Duration::from_secs(5)),
        "{audited}\n{}",
        f.d.log()
    );
    // Once per covered request: the same change is audited again.
    let _ = f.request(&["./emit"]);
    assert!(
        wait_until(Duration::from_secs(5), || f
            .d
            .log()
            .matches(&audited)
            .count()
            == 2),
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
    // Each prompts for the difference: the statement asks for the
    // bindings the grant does not hold and marks the ones it does.
    for (p, new) in [
        (added, "GITHUB_TOKEN"),
        (retargeted, "OPENAI_API_KEY"),
        (renamed, "OPENAI_KEY"),
        (profile, "SHORT_TOKEN"),
    ] {
        match client(&f.home).run_request(&p).unwrap().decision {
            DecisionView::Pending { request } => {
                let d = c.pending_get(&request, &[]).unwrap();
                let asked: Vec<&str> = d
                    .bindings
                    .iter()
                    .filter(|b| !b.granted)
                    .map(|b| b.env_name.as_str())
                    .collect();
                assert_eq!(asked, vec![new], "{d:?}");
                assert!(d.bindings.iter().any(|b| b.granted), "{d:?}");
                ids.push(request);
            }
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

/// Gate 28 through `--env-file`: an env file's references join the
/// resolution, so one naming an ungranted item, or retargeting a granted
/// variable, prompts for exactly that binding, and the statement lists
/// the granted ones apart. References and ordinary variables that leave
/// the bindings a subset are covered. What `envcloak run` sends of the
/// file is its references and names (`EnvFileParams`); the CLI's own
/// reading of a file is in `crates/envcloak-cli/tests/approve.rs`.
#[test]
fn an_env_file_prompts_for_its_ungranted_references() {
    let f = Fixture::new();
    let mut c = client(&f.home);
    let id = pending(&f.request(&["./emit"]));
    let grant = f.approve_ok(&id, session(3600));
    let with = |refs: &[&str], plain: &[&str]| {
        let line = |(n, text): (usize, &&str)| EnvFileLine {
            line: u32::try_from(n + 1).unwrap(),
            text: (*text).to_owned(),
        };
        let mut p = f.params(&["./emit"]);
        p.env_file = Some(EnvFileParams {
            refs: refs.iter().enumerate().map(line).collect(),
            plain: plain.iter().enumerate().map(line).collect(),
        });
        p
    };
    let ask = |p: &RunRequestParams| client(&f.home).run_request(p).map(|a| a.decision);

    // Granted references only, an ordinary variable in place of a bound
    // one, or an empty file: a subset, covered.
    for p in [
        with(&["OPENAI_API_KEY=openai/acme-web"], &[]),
        with(&[], &["STRIPE_SECRET_KEY", "PLAIN"]),
        with(&[], &[]),
    ] {
        assert_eq!(covered(&ask(&p).unwrap()), grant, "{p:?}");
    }

    // An ungranted item, and a granted variable retargeted: each asks for
    // exactly that binding and lists the rest as already covered.
    let added = with(&["GITHUB_TOKEN=github/acme-web"], &["PLAIN"]);
    let retargeted = with(&["OPENAI_API_KEY=github/acme-web"], &[]);
    let mut ids = Vec::new();
    for (p, asked_for, held) in [
        (
            &added,
            vec!["GITHUB_TOKEN"],
            vec!["OPENAI_API_KEY", "STRIPE_SECRET_KEY"],
        ),
        (
            &retargeted,
            vec!["OPENAI_API_KEY"],
            vec!["STRIPE_SECRET_KEY"],
        ),
    ] {
        let id = pending(&ask(p).unwrap());
        let d = c.pending_get(&id, &[]).unwrap();
        let names = |granted: bool| -> Vec<&str> {
            d.bindings
                .iter()
                .filter(|b| b.granted == granted)
                .map(|b| b.env_name.as_str())
                .collect()
        };
        assert_eq!(names(false), asked_for, "{d:?}");
        assert_eq!(names(true), held, "{d:?}");
        ids.push(id);
    }
    // Approved, the new grant holds the whole request and covers it.
    let g2 = f.approve_ok(&ids[0], session(600));
    assert_ne!(g2, grant);
    assert_eq!(covered(&ask(&added).unwrap()), g2);

    // An item the vault lacks, a variable named by both `--ref` and the
    // file, and an entry that is not a reference are unresolved, and
    // nothing is pending for them.
    let mut both = with(&["GITHUB_TOKEN=github/acme-web"], &[]);
    both.refs = vec!["GITHUB_TOKEN=openai/acme-web".to_owned()];
    for (p, reason) in [
        (with(&["NOPE=nope/acme-web"], &[]), None),
        (both, Some("duplicate_env_name")),
        (with(&["GITHUB_TOKEN"], &[]), Some("invalid_reference")),
        (with(&[], &["NOT A NAME"]), Some("invalid_reference")),
    ] {
        let (kind, why) = rpc_kind(ask(&p).unwrap_err());
        assert_eq!(kind, ErrorKind::BindingUnresolved, "{p:?}");
        if reason.is_some() {
            assert_eq!(why, reason, "{p:?}");
        }
    }
    assert_eq!(c.status().unwrap().approvals.pending, 1);
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
    let other = pending(&client(&f.home).run_request(&short).unwrap().decision);
    let st = c.status().unwrap();
    assert_eq!((st.approvals.grants, st.approvals.pending), (1, 1));

    assert!(c.lock().unwrap().was_unlocked);
    let st = c.status().unwrap();
    assert_eq!((st.approvals.grants, st.approvals.pending), (0, 0));
    assert!(c.grants_list().unwrap().grants.is_empty());
    assert_eq!(
        rpc_kind(c.pending_get(&other, &[]).unwrap_err()).0,
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

/// Gate 23: a terminal session whose caller claims an agent's markers
/// gives no proof. `pending.get`, `approve` and `unlock` are refused and
/// audited before the passphrase is looked at: the failure count does not
/// move. (A caller without a terminal is refused the same way: see
/// `tests/proofs.rs`.)
#[test]
fn claimed_markers_refuse_every_proof() {
    let f = Fixture::new();
    let mut c = client(&f.home);
    let id = pending(&f.request(&["./emit"]));
    let claims = vec!["CLAUDECODE".to_owned()];
    let e = c.pending_get(&id, &claims).unwrap_err();
    assert_eq!(rpc_kind(e).0, ErrorKind::ProofRefused);
    let d = c.pending_get(&id, &[]).unwrap();
    let digest = statement_digest(&d, &session(60));
    let e = c
        .approve(&id, session(60), &digest, passphrase(&f.cs), &claims)
        .unwrap_err();
    assert_eq!(rpc_kind(e).0, ErrorKind::ProofRefused);
    let e = c
        .approve(
            &id,
            session(60),
            &digest,
            passphrase(&f.cs),
            &["X_UNKNOWN_MARKER".to_owned()],
        )
        .unwrap_err();
    assert_eq!(
        rpc_kind(e).0,
        ErrorKind::ProofRefused,
        "any marker claims an agent"
    );
    assert!(c.grants_list().unwrap().grants.is_empty());
    assert!(c.lock().unwrap().was_unlocked);
    let e = c.unlock(passphrase(&f.cs), &claims).unwrap_err();
    assert_eq!(rpc_kind(e).0, ErrorKind::ProofRefused);
    let st = c.status().unwrap();
    assert_eq!(st.vault.state, VaultState::Locked);
    assert_eq!(st.approvals.proof_failures, 0);
    let log = f.d.log();
    for method in ["pending.get", "approve", "unlock"] {
        assert!(
            log.contains(&format!("proof refused method={method} reason=agent ")),
            "{log}"
        );
    }
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

/// How long a race may take, start to finish, before the test fails
/// instead of hanging the job.
const RACE_LIMIT: Duration = Duration::from_secs(60);

/// A start line for racing threads that cannot deadlock (review T12-5). A
/// `Barrier` waits for ever for a thread that panicked before reaching it;
/// here every racer holds a [`Ticket`], and one dropped without starting
/// (as a panic drops it while unwinding) counts as having arrived, failed,
/// so the others are released at once and told the race is off.
struct StartGate {
    racers: usize,
    /// Racers arrived, and how many of them failed before they did.
    state: Mutex<(usize, usize)>,
    changed: Condvar,
}

/// One racer's place at a [`StartGate`].
struct Ticket {
    gate: Arc<StartGate>,
    arrived: bool,
}

impl StartGate {
    fn new(racers: usize) -> Arc<StartGate> {
        Arc::new(StartGate {
            racers,
            state: Mutex::new((0, 0)),
            changed: Condvar::new(),
        })
    }

    fn ticket(self: &Arc<Self>) -> Ticket {
        Ticket {
            gate: Arc::clone(self),
            arrived: false,
        }
    }

    fn arrive(&self, failed: bool) -> std::sync::MutexGuard<'_, (usize, usize)> {
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        s.0 += 1;
        s.1 += usize::from(failed);
        self.changed.notify_all();
        s
    }
}

impl Ticket {
    /// Arrives and waits until every racer has, or `limit` passes. True
    /// when all arrived in time and none failed first.
    fn start(mut self, limit: Duration) -> bool {
        self.arrived = true;
        let end = Instant::now() + limit;
        let gate = Arc::clone(&self.gate);
        let mut s = gate.arrive(false);
        while s.0 < gate.racers && s.1 == 0 {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            s = gate
                .changed
                .wait_timeout(s, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        s.1 == 0
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        if !self.arrived {
            drop(self.gate.arrive(true));
        }
    }
}

/// Collects one result from each of `racers` threads within `limit` (the
/// watchdog): a racer that reports an error, panics without reporting, or
/// is still running at the limit fails the test.
fn finish_race<T>(
    rx: &mpsc::Receiver<(usize, Result<T, String>)>,
    racers: usize,
    limit: Duration,
) -> Vec<T> {
    let end = Instant::now() + limit;
    let mut done = Vec::new();
    while done.len() < racers {
        match rx.recv_timeout(end.saturating_duration_since(Instant::now())) {
            Ok((_, Ok(v))) => done.push(v),
            Ok((racer, Err(e))) => panic!("racer {racer}: {e}"),
            Err(mpsc::RecvTimeoutError::Timeout) => panic!(
                "{} of {racers} racers still running after {limit:?}",
                racers - done.len()
            ),
            Err(mpsc::RecvTimeoutError::Disconnected) => panic!(
                "{} of {racers} racers ended without a result (they panicked)",
                racers - done.len()
            ),
        }
    }
    done
}

/// The start gate and the watchdog, without a daemon: a racer that panics
/// before the start releases the others at once, and the race then fails
/// well within its limit, naming what went wrong, instead of hanging.
#[test]
fn a_racer_that_fails_before_the_start_fails_the_race_without_a_hang() {
    const RACERS: usize = 4;
    let limit = Duration::from_secs(30);
    let started = Instant::now();
    let gate = StartGate::new(RACERS);
    let (tx, rx) = mpsc::channel::<(usize, Result<bool, String>)>();
    for racer in 0..RACERS {
        let (ticket, tx) = (gate.ticket(), tx.clone());
        std::thread::spawn(move || {
            if racer == 2 {
                // Stands in for a failed connect: the ticket is dropped
                // while this thread unwinds. (Its message goes to stderr.)
                panic!("racer {racer} failed before the start (on purpose)");
            }
            let all = ticket.start(limit);
            let _ = tx.send((racer, Ok(all)));
        });
    }
    drop(tx);
    let released: Vec<bool> = (0..RACERS - 1)
        .map(|_| {
            rx.recv_timeout(limit)
                .expect("a racer was left waiting")
                .1
                .unwrap()
        })
        .collect();
    assert_eq!(released, [false; RACERS - 1], "told the race is off");
    assert!(started.elapsed() < limit / 2, "{:?}", started.elapsed());
    let why = std::panic::catch_unwind(|| finish_race(&rx, 1, limit)).unwrap_err();
    assert!(
        why.downcast_ref::<String>()
            .is_some_and(|m| m.contains("ended without a result")),
        "{why:?}"
    );

    // Control: with every racer there, all start together.
    let gate = StartGate::new(RACERS);
    let (tx, rx) = mpsc::channel();
    for racer in 0..RACERS {
        let (ticket, tx) = (gate.ticket(), tx.clone());
        std::thread::spawn(move || {
            let _ = tx.send((racer, Ok(ticket.start(limit))));
        });
    }
    drop(tx);
    assert_eq!(finish_race(&rx, RACERS, limit), [true; RACERS]);
}

/// Gate 30: of concurrent requests on a `once` grant, exactly one is
/// covered; the others are pending.
///
/// The daemon serves at most 8 connections per process (MAX_PER_PROCESS),
/// and a connection this test closed a moment ago may not be given back
/// yet. So 7 requests race, one place fewer than the cap: each gets its
/// place without waiting for the daemon to see an earlier connection
/// closed (the retry below is for that rare case only).
#[test]
fn concurrent_requests_on_a_once_grant_cover_exactly_one() {
    const RACERS: usize = 7;
    let f = Fixture::new();
    let id = pending(&f.request(&["./emit"]));
    let grant = f.approve_ok(&id, ApprovalOptions::once(Duration::from_secs(600)));
    let params = f.params(&["./emit"]);
    let paths = common::run_paths(&f.home);
    let gate = StartGate::new(RACERS);
    let (tx, rx) = mpsc::channel();
    for racer in 0..RACERS {
        let (params, paths, ticket, tx) =
            (params.clone(), paths.clone(), gate.ticket(), tx.clone());
        std::thread::spawn(move || {
            // A connection is kept once it is served, so all are open at
            // the start.
            let end = Instant::now() + Duration::from_secs(10);
            let served = loop {
                let tried = match Client::connect(&paths) {
                    Ok(mut c) => c.status().map(|_| c).map_err(|e| format!("{e:?}")),
                    Err(e) => Err(format!("{e:?}")),
                };
                match tried {
                    Ok(c) => break Ok(c),
                    Err(e) if Instant::now() >= end => break Err(e),
                    Err(_) => std::thread::sleep(Duration::from_millis(50)),
                }
            };
            // Every racer reaches the start, served or not; one that fails
            // before it releases the others too (see StartGate).
            let all_started = ticket.start(RACE_LIMIT);
            let decision = served
                .map_err(|e| format!("never served: {e}"))
                .and_then(|mut c| {
                    if !all_started {
                        return Err("another racer never reached the start".to_owned());
                    }
                    c.run_request(&params)
                        .map(|r| r.decision)
                        .map_err(|e| format!("{e:?}"))
                });
            let _ = tx.send((racer, decision));
        });
    }
    drop(tx);
    let decisions = finish_race(&rx, RACERS, RACE_LIMIT);
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
    assert_eq!(pendings.len(), RACERS - 1);
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
        covered(&client(&f.home).run_request(&via_link).unwrap().decision),
        grant
    );

    let copy = project(&f.home, "acme-copy", MANIFEST);
    let mut via_copy = f.params(&["./emit"]);
    via_copy.manifest = copy.to_str().unwrap().to_owned();
    assert!(matches!(
        client(&f.home).run_request(&via_copy).unwrap().decision,
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

/// Review T5 open 3 (gate 17, the card half): a slug does not say its
/// item's class, so a reference to a card or an issuer credential parses,
/// and `run.request` rejects it when it binds the references to the
/// vault's items (`bind_items`, the only source of the item ids a request
/// releases). A card and an issuer credential planted through the core
/// API: a manifest naming either, beside a secret or alone, and a `--ref`
/// to one, with or without a field, are `manifest_invalid` with the class
/// in the reason; no request is pending, no grant made and no value sent,
/// and the story's manifest still opens a request.
#[test]
fn a_reference_to_a_card_is_rejected_when_bound() {
    common::terminal_session();
    let mut cs = canaries(fresh_seed());
    let home = TestHome::new();
    let kit = seed_vault(&home, &cs);
    cs.push(kit);
    let digits = |seed: u64| -> String {
        (0..16)
            .map(|i| char::from(b'0' + u8::try_from((seed >> (i * 4)) % 10).unwrap()))
            .collect()
    };
    let card = Canary::new("CARD_NUMBER", digits(fresh_seed()));
    let issuer = Canary::new(
        "ISSUER_CREDENTIAL",
        format!("{}{}", digits(fresh_seed()), digits(fresh_seed())),
    );
    {
        use envcloak_core::crypto::ItemClass;
        use envcloak_core::vault::{FieldName, ItemDetails, LockedVault, NewItem, Slug};
        let mut v = LockedVault::open(&VaultPaths::under(data_dir(&home)))
            .unwrap()
            .unlock_with_passphrase(&passphrase(&cs))
            .map_err(|(_, e)| e)
            .unwrap();
        v.transact(|t| {
            for (class, slug, c) in [
                (ItemClass::Card, "card/acme-web", &card),
                (ItemClass::IssuerCredential, "issuer/acme-web", &issuer),
            ] {
                let id = t.create_item(NewItem {
                    class,
                    slug: Slug::new(slug).unwrap(),
                    details: ItemDetails {
                        title: slug.to_owned(),
                        ..ItemDetails::default()
                    },
                })?;
                t.add_field(
                    id,
                    FieldName::new("value").unwrap(),
                    SecretBytes::copy_from(c.value()),
                )?;
            }
            Ok(())
        })
        .unwrap();
    }
    cs.push(card);
    cs.push(issuer);
    let d = start(&home);
    let mut c = client(&home);
    c.unlock(passphrase(&cs), &[]).unwrap();
    let story = project(&home, "acme-web", MANIFEST);
    let ask = |manifest: &std::path::Path, refs: &[&str]| {
        client(&home).run_request(&RunRequestParams {
            manifest: manifest.to_str().unwrap().to_owned(),
            profile: None,
            refs: refs.iter().map(|r| (*r).to_owned()).collect(),
            env_file: None,
            argv: vec!["./emit".to_owned()],
            claims: Vec::new(),
        })
    };
    let card_only = project(&home, "card-only", "[env]\nCARD = \"card/acme-web\"\n");
    let beside = project(
        &home,
        "beside",
        "[env]\nOPENAI_API_KEY = \"openai/acme-web\"\nISSUER = \"issuer/acme-web#value\"\n",
    );
    for (manifest, refs, reason) in [
        (&card_only, &[][..], "card_reference"),
        (&beside, &[], "issuer_credential_reference"),
        (&story, &["CARD=card/acme-web"], "card_reference"),
        (&story, &["CARD=card/acme-web#value"], "card_reference"),
        (
            &story,
            &["ISSUER=issuer/acme-web"],
            "issuer_credential_reference",
        ),
    ] {
        let e = ask(manifest, refs).unwrap_err();
        let shown = format!("{e:?}");
        assert_eq!(
            rpc_kind(e),
            (ErrorKind::ManifestInvalid, Some(reason)),
            "{refs:?}"
        );
        assert_no_canary(shown.as_bytes(), &cs);
    }
    let st = c.status().unwrap();
    assert_eq!((st.approvals.grants, st.approvals.pending), (0, 0));
    // The story's manifest, on the same vault, opens a request.
    assert!(matches!(
        ask(&story, &[]).unwrap().decision,
        DecisionView::Pending { .. }
    ));
    assert_eq!(c.status().unwrap().approvals.pending, 1);
    drop(c);
    assert_no_canary(&d.log_bytes(), &cs);
    home.assert_clean(&cs);
}

/// No grant is evaluated, and no proof taken, from a vault whose
/// integrity check failed (T3's rule for `projects()` and `header()`,
/// carried to the grant path).
#[test]
fn a_tampered_vault_gives_no_decision_and_takes_no_proof() {
    common::terminal_session();
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
            env_file: None,
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
