//! The operation store, case by case (SPEC §6.8 "Retries", "Approval" and
//! "Delivery"; R-M2b-08, R-M2b-13 to R-M2b-17, R-M2b-27, R-M2b-28,
//! R-M2b-35, R-M2b-44 to R-M2b-46, R-M2b-51, R-M2b-54; SI-05 to SI-10).
//! `tests/enumeration.rs` checks the same rules under every ordering of
//! events; these name each rule once, with a clock and a world the test
//! moves by hand.
#![allow(clippy::unwrap_used)]

mod common;

use std::time::Duration;

use common::{
    DAEMON, MCP, OTHER_MCP, OTHER_ROOT, ROOT, SIBLING, Spec, TestWorld, at, identity, scope,
};
use envcloak_signin::{
    ApproveError, AttemptError, AttemptFailure, Channel, Cleanup, DaemonInstance, Effect, Fresh,
    Generation, Lookup, Nonce, NotFound, Operation, OperationKey, OperationStore, Options, Phase,
    PublishDecision, RETRY_WINDOW, Refusal, Request, RequestError, RequestId, Revocation,
    SignInScope, State, Status, Step, StopReason, StoreLimits,
};

struct H {
    store: OperationStore,
    world: TestWorld,
    t: u64,
    draws: u8,
}

impl H {
    fn new() -> Self {
        H::with_limits(StoreLimits::default())
    }

    fn with_limits(limits: StoreLimits) -> Self {
        H {
            store: OperationStore::with_limits(DAEMON, limits),
            world: TestWorld::new(),
            t: 0,
            draws: 0,
        }
    }

    fn tick(&mut self, secs: u64) {
        self.t += secs;
        self.store.reconcile(&at(self.t), &self.world);
    }

    fn scope(&self, spec: &Spec) -> SignInScope {
        scope(spec, &self.world)
    }

    fn request(&mut self, key: &str, scope: SignInScope) -> Result<Lookup, RequestError> {
        self.draws += 1;
        let fresh = Fresh {
            request: RequestId::from_bytes([self.draws; 16]),
            nonce: Nonce::from_bytes([self.draws; 32]),
        };
        let r = Request {
            key: OperationKey::parse(key).unwrap(),
            scope,
        };
        self.store
            .lookup_or_reserve(r, fresh, &at(self.t), &self.world)
    }

    fn open(&mut self, key: &str, spec: &Spec) -> RequestId {
        let s = self.scope(spec);
        match self.request(key, s).unwrap() {
            Lookup::Reserved(st) => st.request,
            Lookup::Joined(st) => panic!("joined {st:?}"),
        }
    }

    fn approve(&mut self, id: &RequestId, options: Options) -> Result<Status, ApproveError> {
        let digest = self.store.statement(id, options).map(|s| s.digest());
        let digest = digest.unwrap_or([0; 32]);
        self.store
            .approve(id, options, &digest, &at(self.t), &self.world)
    }

    fn op(&self, id: &RequestId) -> &Operation {
        self.store.operation(id).unwrap()
    }

    fn generation(&self, id: &RequestId) -> Generation {
        self.op(id).generation().unwrap()
    }

    fn status(&mut self, id: &RequestId) -> Status {
        let owner = self.op(id).owner();
        self.store
            .status(&owner, id, &at(self.t), &self.world)
            .unwrap()
    }

    fn captured(&mut self, id: &RequestId) {
        let g = self.generation(id);
        self.store
            .worker_captured(id, g, &at(self.t), &self.world)
            .unwrap();
    }

    fn supervisor(&self, id: &RequestId) -> Channel {
        Channel::Supervisor(self.op(id).supervisor().unwrap())
    }

    fn inject(&mut self, id: &RequestId) {
        let from = self.supervisor(id);
        self.store
            .inject_state(&from, id, &at(self.t), &self.world)
            .unwrap();
    }

    fn decide(&mut self, id: &RequestId, role: &str) -> PublishDecision {
        let from = self.supervisor(id);
        self.store
            .identity_response(&from, id, &identity(role), &at(self.t), &self.world)
            .unwrap()
    }

    /// Request, approve, capture and inject: ready for the decision.
    fn ready(&mut self, key: &str, spec: &Spec, options: Options) -> RequestId {
        let id = self.open(key, spec);
        self.approve(&id, options).unwrap();
        self.captured(&id);
        self.inject(&id);
        id
    }
}

fn dev(attempts: u8) -> Options {
    Options::Dev {
        window: Duration::from_secs(3600),
        attempts,
    }
}

/// Same owner, key and scope: the same operation and its current status;
/// no new statement, context, prompt, worker or attempt, and nothing in
/// the store changes. A fresh request id and nonce (a fresh MCP call)
/// change nothing (R-M2b-13, R-M2b-44, SI-06).
#[test]
fn a_retry_with_the_same_key_and_scope_joins_its_operation() {
    let mut h = H::new();
    let spec = Spec::dev();
    let id = h.open("intent-1", &spec);
    assert_eq!(h.op(&id).phase(), Phase::PendingApproval);
    let digest = h.store.statement(&id, dev(2)).unwrap().digest();
    let before = h.store.clone();
    h.tick(30);
    let before_tick = h.store.clone();
    for _ in 0..3 {
        let s = h.scope(&spec);
        match h.request("intent-1", s).unwrap() {
            Lookup::Joined(st) => assert_eq!(st.request, id),
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(h.store, before_tick);
    assert_eq!(h.store.operations().count(), 1);
    assert_eq!(h.store.statement(&id, dev(2)).unwrap().digest(), digest);
    // The context reserved for it stays its own; the next operation gets
    // the next one: no retry reserved one.
    let other = h.open("intent-2", &spec);
    assert_eq!(
        h.op(&id).context(),
        before.operation(&id).unwrap().context()
    );
    assert_eq!(h.op(&other).context().get(), h.op(&id).context().get() + 1);
    // Approved and running: a retry still starts nothing.
    h.approve(&id, dev(2)).unwrap();
    assert_eq!(h.store.drain_effects().len(), 1);
    let s = h.scope(&spec);
    assert!(matches!(h.request("intent-1", s), Ok(Lookup::Joined(_))));
    assert!(h.store.drain_effects().is_empty());
}

/// The same key with any one scope field changed is `request_conflict`,
/// and the existing operation, its statement and its reserved context are
/// untouched (R-M2b-13, R-M2b-44).
#[test]
fn the_same_key_with_any_scope_field_changed_conflicts_and_changes_nothing() {
    let mut h = H::new();
    let spec = Spec::dev();
    let id = h.open("k", &spec);
    let digest = h.store.statement(&id, dev(2)).unwrap().digest();
    let before = h.store.clone();
    let mut changed: Vec<SignInScope> = Vec::new();
    for s in [
        Spec {
            role: "admin",
            ..spec.clone()
        },
        Spec {
            role: "Editor",
            ..spec.clone()
        },
        Spec {
            requester: SIBLING,
            ..spec.clone()
        },
        Spec {
            tier: envcloak_signin::Tier::Each,
            attempts: 1,
            ..spec.clone()
        },
        Spec {
            attempts: 4,
            ..spec.clone()
        },
        Spec {
            attempt_timeout: Duration::from_secs(901),
            ..spec.clone()
        },
        Spec {
            session_lifetime: Duration::from_secs(3601),
            ..spec.clone()
        },
    ] {
        changed.push(h.scope(&s));
    }
    for change in [
        |w: &mut TestWorld| w.browser += 1,
        |w: &mut TestWorld| w.login += 1,
        |w: &mut TestWorld| w.target += 1,
        |w: &mut TestWorld| w.adapter += 1,
        |w: &mut TestWorld| w.epochs.vault += 1,
        |w: &mut TestWorld| w.epochs.policy += 1,
    ] {
        let mut w = h.world.clone();
        change(&mut w);
        changed.push(scope(&spec, &w));
    }
    for s in changed {
        assert_ne!(s, h.scope(&spec));
        assert_eq!(h.request("k", s), Err(RequestError::Conflict));
        assert_eq!(h.store, before);
    }
    assert_eq!(h.store.statement(&id, dev(2)).unwrap().digest(), digest);
}

/// The key is looked up within the owner root only: another root's same
/// key is its own operation, and status, cancel and end from any other
/// root answer exactly as for an id that never existed, changing nothing
/// (R-M2b-13: "refused before any metadata is returned").
#[test]
fn another_root_never_reaches_an_operation() {
    let mut h = H::new();
    let mine = h.open("k", &Spec::dev());
    let theirs = h.open(
        "k",
        &Spec {
            root: OTHER_ROOT,
            requester: OTHER_MCP,
            ..Spec::dev()
        },
    );
    assert_ne!(mine, theirs);
    let before = h.store.clone();
    let unknown = RequestId::from_bytes([0xee; 16]);
    for caller in [OTHER_ROOT, MCP, SIBLING] {
        let now = at(h.t);
        let w = h.world.clone();
        assert_eq!(h.store.status(&caller, &mine, &now, &w), Err(NotFound));
        assert_eq!(h.store.cancel(&caller, &mine, &now, &w), Err(NotFound));
        assert_eq!(h.store.end(&caller, &mine, &now, &w), Err(NotFound));
        assert_eq!(h.store.status(&caller, &unknown, &now, &w), Err(NotFound));
    }
    assert_eq!(h.store, before);
    assert_eq!(h.status(&mine).state, State::PendingApproval);
}

/// The store refuses new work when full, per root and in all, and never
/// forgets a receipt to make room; retries still join. Room comes back
/// only when a stopped operation's `retry_until` has passed and its
/// cleanup is not pending (R-M2b-13, L-08).
#[test]
fn a_full_store_refuses_rather_than_evicting() {
    let mut h = H::with_limits(StoreLimits {
        per_root: 2,
        total: 3,
        authorizations: 8,
    });
    let a = h.open("a", &Spec::dev());
    let b = h.open("b", &Spec::dev());
    let s = h.scope(&Spec::dev());
    assert_eq!(h.request("c", s.clone()), Err(RequestError::Full));
    assert!(matches!(h.request("a", s.clone()), Ok(Lookup::Joined(_))));
    let other = Spec {
        root: OTHER_ROOT,
        requester: OTHER_MCP,
        ..Spec::dev()
    };
    h.open("x", &other);
    let o2 = h.scope(&other);
    assert_eq!(h.request("y", o2), Err(RequestError::Full));
    let owner = h.op(&a).owner();
    h.store
        .cancel(&owner, &a, &at(h.t), &h.world.clone())
        .unwrap();
    assert_eq!(h.request("c", s.clone()), Err(RequestError::Full));
    h.tick(RETRY_WINDOW.as_secs() - 1);
    assert_eq!(h.request("c", s.clone()), Err(RequestError::Full));
    assert!(h.store.operation(&a).is_some() && h.store.operation(&b).is_some());
    h.tick(1);
    assert!(h.store.operation(&a).is_none());
    assert!(matches!(h.request("c", s), Ok(Lookup::Reserved(_))));
}

/// A finished, failed or cancelled operation answers its result to a
/// retry and never starts a new authentication (R-M2b-13).
#[test]
fn a_finished_operation_answers_its_result_never_a_new_attempt() {
    let mut h = H::new();
    let spec = Spec::dev();
    let id = h.open("k", &spec);
    h.approve(&id, dev(3)).unwrap();
    let g = h.generation(&id);
    h.store.drain_effects();
    h.store
        .worker_failed(
            &id,
            g,
            AttemptFailure::CredentialsRejected,
            &at(h.t),
            &h.world.clone(),
        )
        .unwrap();
    let s = h.scope(&spec);
    match h.request("k", s).unwrap() {
        Lookup::Joined(st) => {
            assert_eq!(st.state, State::Failed);
            assert_eq!(
                st.receipt.reason,
                Some(StopReason::AttemptFailed(
                    AttemptFailure::CredentialsRejected
                ))
            );
            assert!(st.retry_until.is_some());
        }
        other => panic!("{other:?}"),
    }
    let effects = h.store.drain_effects();
    assert!(
        effects
            .iter()
            .all(|e| !matches!(e, Effect::StartAttempt { .. }))
    );
}

/// A `once` approval: one attempt, one password submission and at most two
/// one-time codes; a second credit never comes from it, and a new key
/// with the same scope needs a new proof (R-M2b-16, R-M2b-51).
#[test]
fn a_once_approval_gives_one_attempt() {
    let mut h = H::new();
    let spec = Spec::each();
    let id = h.open("k", &spec);
    let st = h.approve(&id, Options::Once).unwrap();
    assert_eq!(st.state, State::AttemptRunning);
    let a = h.op(&id).authorization().unwrap();
    assert_eq!(h.store.authorization(&a).unwrap().remaining(), 0);
    let g = h.generation(&id);
    let (now, w) = (at(h.t), h.world.clone());
    assert_eq!(h.store.permit(&id, g, Step::Password, &now, &w), Ok(()));
    assert_eq!(
        h.store.permit(&id, g, Step::Password, &now, &w),
        Err(AttemptError::Spent)
    );
    assert_eq!(h.store.permit(&id, g, Step::Code, &now, &w), Ok(()));
    assert_eq!(h.store.permit(&id, g, Step::Code, &now, &w), Ok(()));
    assert_eq!(
        h.store.permit(&id, g, Step::Code, &now, &w),
        Err(AttemptError::Spent)
    );
    let other = h.open("k2", &spec);
    assert_eq!(h.op(&other).phase(), Phase::PendingApproval);
    // Dev options are refused for an `each` scope.
    assert_eq!(
        h.approve(&other, dev(2)),
        Err(ApproveError::Options(envcloak_signin::OptionsError::NotDev))
    );
}

/// A `dev` authorization covers new keys of exactly its scope while it has
/// credits and its window lasts; polls, retries and new keys never add a
/// credit or move its deadline; a credit is never refunded, whatever
/// happens to its attempt (R-M2b-15, R-M2b-16, R-M2b-45).
#[test]
fn a_dev_budget_only_shrinks_and_its_deadline_never_moves() {
    let mut h = H::new();
    let spec = Spec::dev();
    let a = h.open("a", &spec);
    h.approve(&a, dev(2)).unwrap();
    let auth = h.op(&a).authorization().unwrap();
    let deadline = h.store.authorization(&auth).unwrap().deadline();
    assert_eq!(h.store.authorization(&auth).unwrap().remaining(), 1);
    h.tick(600);
    for _ in 0..5 {
        let s = h.scope(&spec);
        h.request("a", s).unwrap();
        h.status(&a);
    }
    let g = h.generation(&a);
    h.store
        .worker_failed(
            &a,
            g,
            AttemptFailure::CodeRejected,
            &at(h.t),
            &h.world.clone(),
        )
        .unwrap();
    assert_eq!(h.store.authorization(&auth).unwrap().remaining(), 1);
    let b = h.open("b", &spec);
    assert_eq!(h.op(&b).authorization(), Some(auth));
    assert_eq!(h.store.authorization(&auth).unwrap().remaining(), 0);
    assert_eq!(h.store.authorization(&auth).unwrap().deadline(), deadline);
    let c = h.open("c", &spec);
    assert_eq!(h.op(&c).phase(), Phase::PendingApproval);
    // Another role, recipient or project is another scope: never covered.
    let admin = h.open(
        "d",
        &Spec {
            role: "admin",
            ..spec.clone()
        },
    );
    let sibling = h.open(
        "e",
        &Spec {
            requester: SIBLING,
            ..spec.clone()
        },
    );
    for id in [admin, sibling] {
        assert_eq!(h.op(&id).phase(), Phase::PendingApproval);
        assert_eq!(h.op(&id).authorization(), None);
    }
}

/// The window is absolute: a new key after it has passed asks for a proof
/// even with credits left, and an approved attempt waiting for its login
/// stops when the authorization ends.
#[test]
fn a_dev_window_ends_at_its_deadline() {
    let mut h = H::new();
    let spec = Spec::dev();
    let a = h.open("a", &spec);
    h.approve(&a, dev(5)).unwrap();
    // b waits for a's attempt on the same login.
    let b = h.open("b", &spec);
    assert_eq!(h.op(&b).phase(), Phase::Approved);
    h.tick(3599);
    let c = h.open("c", &spec);
    assert_eq!(h.op(&c).phase(), Phase::Approved);
    h.tick(1);
    assert_eq!(
        h.status(&b).receipt.reason,
        Some(StopReason::AuthorizationEnded)
    );
    assert_eq!(h.status(&c).state, State::Failed);
    let d = h.open("d", &spec);
    assert_eq!(h.op(&d).phase(), Phase::PendingApproval);
    // The grant is checked again at publication, not only at the start: an
    // attempt that outlives its authorization's window stops, and its
    // captured state is never published.
    let mut h = H::new();
    let short = Options::Dev {
        window: Duration::from_secs(600),
        attempts: 2,
    };
    let id = h.ready("k", &spec, short);
    h.tick(600);
    assert_eq!(
        h.decide(&id, "editor"),
        PublishDecision::Refuse(Refusal::Stopped)
    );
    assert_eq!(
        h.status(&id).receipt.reason,
        Some(StopReason::AuthorizationEnded)
    );
    assert!(!h.status(&id).receipt.delivered);
}

/// Attempts on one login are serialized: the next starts once the running
/// one captured or stopped and its teardown was confirmed.
#[test]
fn attempts_on_one_login_are_serialized() {
    let mut h = H::new();
    let spec = Spec::dev();
    let a = h.open("a", &spec);
    h.approve(&a, dev(3)).unwrap();
    let b = h.open("b", &spec);
    let c = h.open(
        "c",
        &Spec {
            role: "admin",
            ..spec.clone()
        },
    );
    h.approve(&c, dev(3)).unwrap();
    assert_eq!(h.op(&b).phase(), Phase::Approved);
    assert_eq!(h.op(&c).phase(), Phase::Approved);
    let ga = h.generation(&a);
    h.store
        .worker_failed(
            &a,
            ga,
            AttemptFailure::WorkerLost,
            &at(h.t),
            &h.world.clone(),
        )
        .unwrap();
    assert_eq!(h.op(&b).phase(), Phase::Approved);
    h.store
        .cleanup_result(&a, ga, true, &at(h.t), &h.world.clone())
        .unwrap();
    assert_eq!(h.op(&b).phase(), Phase::AttemptRunning);
    assert_eq!(h.op(&c).phase(), Phase::Approved);
    h.captured(&b);
    assert_eq!(h.op(&c).phase(), Phase::AttemptRunning);
}

/// A change of the login's authorization revision ends its pending
/// statements and authorizations, stops its attempts and tears down its
/// delivered contexts, unlike a key rotation (R-M2b-17).
#[test]
fn a_revision_change_ends_everything_bound_to_it() {
    let mut h = H::new();
    let spec = Spec::dev();
    let delivered = h.ready("a", &spec, dev(3));
    assert_eq!(h.decide(&delivered, "editor"), PublishDecision::Publish);
    let running = h.open(
        "b",
        &Spec {
            role: "admin",
            ..spec.clone()
        },
    );
    h.approve(&running, dev(3)).unwrap();
    let pending = h.open(
        "c",
        &Spec {
            role: "viewer",
            ..spec.clone()
        },
    );
    h.store.drain_effects();
    h.world.login += 1;
    h.store.reconcile(&at(h.t), &h.world.clone());
    for id in [delivered, running, pending] {
        assert_eq!(
            h.status(&id).receipt.reason,
            Some(StopReason::RevisionChanged)
        );
    }
    assert_eq!(h.status(&delivered).state, State::Ended);
    assert_eq!(h.status(&running).state, State::Failed);
    assert!(h.store.authorizations().all(|a| a.ended()));
    let mut teardowns: Vec<(RequestId, bool)> = h
        .store
        .drain_effects()
        .into_iter()
        .filter_map(|e| match e {
            Effect::TearDown {
                request, delivered, ..
            } => Some((request, delivered)),
            _ => None,
        })
        .collect();
    teardowns.sort();
    let mut want = vec![(delivered, true), (running, false)];
    want.sort();
    assert_eq!(teardowns, want);
    // The statement for the old revision can no longer be approved.
    assert_eq!(h.approve(&pending, dev(3)), Err(ApproveError::NotPending));
}

/// A target edit or a browser replacement while the proof is checked:
/// the stale proof mints nothing, and nothing reaches the changed target
/// (R-M2b-44, R-M2b-51, SI-05).
#[test]
fn a_stale_proof_mints_nothing() {
    for change in [
        |w: &mut TestWorld| w.target += 1,
        |w: &mut TestWorld| w.browser += 1,
        |w: &mut TestWorld| w.adapter += 1,
        |w: &mut TestWorld| w.epochs.policy += 1,
    ] {
        let mut h = H::new();
        let id = h.open("k", &Spec::dev());
        let digest = h.store.statement(&id, dev(2)).unwrap().digest();
        change(&mut h.world);
        let got = h
            .store
            .approve(&id, dev(2), &digest, &at(h.t), &h.world.clone());
        assert_eq!(got, Err(ApproveError::NotPending));
        assert_eq!(h.store.authorizations().count(), 0);
        assert!(h.store.drain_effects().is_empty());
    }
}

/// A proof names one statement: another digest, or options the scope does
/// not allow, approve nothing.
#[test]
fn a_proof_for_another_statement_is_refused() {
    let mut h = H::new();
    let id = h.open("k", &Spec::dev());
    let other = h.open("k2", &Spec::dev());
    let theirs = h.store.statement(&other, dev(2)).unwrap().digest();
    let before = h.store.clone();
    let (now, w) = (at(h.t), h.world.clone());
    assert_eq!(
        h.store.approve(&id, dev(2), &theirs, &now, &w),
        Err(ApproveError::DigestMismatch)
    );
    let three = h.store.statement(&id, dev(3)).unwrap().digest();
    assert_eq!(
        h.store.approve(&id, dev(2), &three, &now, &w),
        Err(ApproveError::DigestMismatch)
    );
    let six = Options::Dev {
        window: Duration::from_secs(60),
        attempts: 6,
    };
    let d6 = h.store.statement(&id, six).unwrap().digest();
    assert!(matches!(
        h.store.approve(&id, six, &d6, &now, &w),
        Err(ApproveError::Options(_))
    ));
    assert_eq!(h.store, before);
}

/// Publication is one decision: after cancel, lock or root exit nothing
/// is published, and late worker results are discarded (R-M2b-28,
/// R-M2b-46, R-M2b-54).
#[test]
fn a_stop_before_publication_wins() {
    let stops: [fn(&mut H, &RequestId); 5] = [
        |h, id| {
            let o = h.op(id).owner();
            h.store.cancel(&o, id, &at(h.t), &h.world.clone()).unwrap();
        },
        |h, id| {
            let o = h.op(id).owner();
            h.store.end(&o, id, &at(h.t), &h.world.clone()).unwrap();
        },
        |h, _| h.store.lock(&at(h.t), &h.world.clone()),
        |h, _| {
            h.world.exited.insert(ROOT);
            h.store.reconcile(&at(h.t), &h.world.clone());
        },
        |h, _| {
            h.world.exited.insert(MCP);
            h.store.reconcile(&at(h.t), &h.world.clone());
        },
    ];
    for stop in stops {
        let mut h = H::new();
        let id = h.ready("k", &Spec::dev(), dev(2));
        let g = h.generation(&id);
        stop(&mut h, &id);
        let before = h.store.clone();
        assert_eq!(
            h.decide(&id, "editor"),
            PublishDecision::Refuse(Refusal::Stopped)
        );
        let (now, w) = (at(h.t), h.world.clone());
        assert!(h.store.worker_captured(&id, g, &now, &w).is_err());
        let from = h.supervisor(&id);
        assert!(h.store.published(&from, &id, &now, &w).is_err());
        assert!(h.store.check(&from, &id, &now, &w).is_err());
        assert_eq!(h.store, before);
        let st = h.status(&id);
        assert!(!st.receipt.delivered);
        assert_ne!(st.state, State::Ended);
    }
}

/// Publication followed by cancel with a forced close failure reports
/// delivered and `cleanup_failed`, and never claims revocation
/// (R-M2b-46, SI-10).
#[test]
fn a_cancel_after_publication_reports_delivered_and_a_failed_close() {
    let mut h = H::new();
    let id = h.ready("k", &Spec::dev(), dev(2));
    assert_eq!(h.decide(&id, "editor"), PublishDecision::Publish);
    let from = h.supervisor(&id);
    h.store
        .published(&from, &id, &at(h.t), &h.world.clone())
        .unwrap();
    h.store
        .check(&from, &id, &at(h.t), &h.world.clone())
        .unwrap();
    h.store.drain_effects();
    let owner = h.op(&id).owner();
    let st = h
        .store
        .cancel(&owner, &id, &at(h.t), &h.world.clone())
        .unwrap();
    assert_eq!(st.state, State::Ended);
    assert!(st.receipt.delivered);
    assert_eq!(st.receipt.cleanup, Cleanup::Pending);
    let g = h.generation(&id);
    assert_eq!(
        h.store.drain_effects(),
        vec![Effect::TearDown {
            request: id,
            generation: g,
            delivered: true
        }]
    );
    assert!(
        h.store
            .check(&from, &id, &at(h.t), &h.world.clone())
            .is_err()
    );
    h.store
        .cleanup_result(&id, g, false, &at(h.t), &h.world.clone())
        .unwrap();
    let st = h.status(&id);
    assert_eq!(st.receipt.cleanup, Cleanup::Failed);
    assert_eq!(st.receipt.revocation, Revocation::Unknown);
    // Idempotent: a second cancel changes nothing.
    let before = h.store.clone();
    h.store
        .cancel(&owner, &id, &at(h.t), &h.world.clone())
        .unwrap();
    assert_eq!(h.store, before);
}

/// The daemon matches the identity read in the recipient context itself:
/// anything but exactly the expected account, tenant and role delivers
/// nothing (SPEC §6.8 "Identity check").
#[test]
fn only_the_exact_identity_publishes() {
    use envcloak_signin::{IdentityResponse, Label};
    let l = |s: &str| Label::new(s).unwrap();
    let wrong = [
        IdentityResponse {
            role: l("Editor"),
            ..identity("editor")
        },
        IdentityResponse {
            tenant: None,
            ..identity("editor")
        },
        IdentityResponse {
            tenant: Some(l("acme2")),
            ..identity("editor")
        },
        IdentityResponse {
            account: l("other@fixture.test"),
            ..identity("editor")
        },
        identity("admin"),
    ];
    for who in wrong {
        let mut h = H::new();
        let id = h.ready("k", &Spec::dev(), dev(2));
        let from = h.supervisor(&id);
        let got = h
            .store
            .identity_response(&from, &id, &who, &at(h.t), &h.world.clone())
            .unwrap();
        assert_eq!(got, PublishDecision::Refuse(Refusal::IdentityUnverified));
        let st = h.status(&id);
        assert_eq!(st.state, State::Failed);
        assert_eq!(st.receipt.reason, Some(StopReason::IdentityUnverified));
        assert!(!st.receipt.delivered);
        assert_eq!(st.receipt.cleanup, Cleanup::Pending);
    }
}

/// Declared state leaves the store only towards the operation's own
/// generation's supervisor; no client (the requesting `envcloak mcp`, a
/// sibling instance in the same root, the root itself, another root) and
/// no other generation's supervisor can claim, publish or check (plan
/// D-31, D-36; R-M2b-27).
#[test]
fn declared_state_goes_only_to_the_generations_supervisor() {
    let mut h = H::new();
    let spec = Spec::dev();
    let a = h.open("a", &spec);
    h.approve(&a, dev(3)).unwrap();
    h.captured(&a);
    let b = h.open("b", &spec);
    assert_eq!(h.op(&b).phase(), Phase::AttemptRunning);
    let other = h.supervisor(&b);
    let before = h.store.clone();
    let (now, w) = (at(h.t), h.world.clone());
    // Worker results carrying another attempt's generation are discarded:
    // `a`'s generation says nothing about `b`'s running attempt.
    let ga = h.generation(&a);
    assert!(h.store.worker_captured(&b, ga, &now, &w).is_err());
    assert!(
        h.store
            .worker_failed(&b, ga, AttemptFailure::WorkerLost, &now, &w)
            .is_err()
    );
    assert!(h.store.permit(&b, ga, Step::Password, &now, &w).is_err());
    assert!(h.store.cleanup_result(&b, ga, true, &now, &w).is_err());
    assert_eq!(h.store, before);
    for from in [
        Channel::Client(MCP),
        Channel::Client(SIBLING),
        Channel::Client(ROOT),
        Channel::Client(OTHER_ROOT),
        other,
    ] {
        assert!(
            h.store.inject_state(&from, &a, &now, &w).is_err(),
            "{from:?}"
        );
        let d = h
            .store
            .identity_response(&from, &a, &identity("editor"), &now, &w);
        assert!(!matches!(d, Ok(PublishDecision::Publish)), "{from:?}");
        assert!(h.store.published(&from, &a, &now, &w).is_err());
        assert!(h.store.check(&from, &a, &now, &w).is_err());
    }
    assert_eq!(h.store, before);
    let own = h.supervisor(&a);
    let inj = h.store.inject_state(&own, &a, &now, &w).unwrap();
    assert_eq!(inj.context, h.op(&a).context());
    // Once only.
    assert!(h.store.inject_state(&own, &a, &now, &w).is_err());
    assert_eq!(h.decide(&a, "editor"), PublishDecision::Publish);
}

/// Deadlines are anchored where they began: a retry's arrival never moves
/// the statement's expiry, and the attempt times out on its own clock
/// (SI-07, R-M2b-54).
#[test]
fn deadlines_never_move_with_retries() {
    let mut h = H::new();
    let spec = Spec::dev();
    let id = h.open("k", &spec);
    let first = h.op(&id).statement_deadline();
    h.tick(540);
    let s = h.scope(&spec);
    h.request("k", s).unwrap();
    assert_eq!(h.op(&id).statement_deadline(), first);
    h.tick(60);
    let st = h.status(&id);
    assert_eq!(st.receipt.reason, Some(StopReason::StatementExpired));
    // An attempt past its timeout stops, and its late result is discarded.
    let id = h.open("k2", &spec);
    h.approve(&id, dev(2)).unwrap();
    let g = h.generation(&id);
    h.tick(900);
    assert_eq!(
        h.status(&id).receipt.reason,
        Some(StopReason::AttemptTimedOut)
    );
    assert!(
        h.store
            .worker_captured(&id, g, &at(h.t), &h.world.clone())
            .is_err()
    );
}

/// The store answers one daemon instance: a scope resolved by another is
/// refused, and a new store (a daemon restart) knows no earlier request.
#[test]
fn a_restart_ends_every_operation() {
    let mut h = H::new();
    let id = h.open("k", &Spec::dev());
    let mut w = h.world.clone();
    w.epochs.daemon = DaemonInstance::from_bytes([8; 16]);
    let foreign = scope(&Spec::dev(), &w);
    assert_eq!(h.request("k2", foreign), Err(RequestError::WrongDaemon));
    let mut fresh = OperationStore::new(DaemonInstance::from_bytes([8; 16]));
    assert_eq!(fresh.status(&ROOT, &id, &at(h.t), &w), Err(NotFound));
}

/// Status revisions increase with every change of what status answers,
/// and polls change nothing (R-M2b-08).
#[test]
fn status_revisions_increase_with_every_change_and_only_then() {
    let mut h = H::new();
    let id = h.open("k", &Spec::dev());
    let mut last = h.status(&id);
    let mut check = |h: &mut H, changed: bool| {
        let st = h.status(&id);
        if changed {
            assert!(st.revision > last.revision, "{st:?} after {last:?}");
            assert_ne!(st.state, last.state);
        } else {
            assert_eq!(st, last);
        }
        last = st;
    };
    check(&mut h, false);
    h.approve(&id, dev(2)).unwrap();
    check(&mut h, true);
    check(&mut h, false);
    h.captured(&id);
    check(&mut h, true);
    h.inject(&id);
    check(&mut h, false);
    h.decide(&id, "editor");
    check(&mut h, true);
    let from = h.supervisor(&id);
    h.store
        .published(&from, &id, &at(h.t), &h.world.clone())
        .unwrap();
    check(&mut h, true);
    h.tick(3600);
    check(&mut h, true);
    assert_eq!(
        h.status(&id).receipt.reason,
        Some(StopReason::SessionExpired)
    );
}

/// Nothing of the key, the scope's labels or any value shows in the
/// store's or a status's `Debug`.
#[test]
fn debug_output_holds_no_key() {
    let mut h = H::new();
    let id = h.open("intent-marker-55aa", &Spec::dev());
    let st = h.status(&id);
    let all = format!("{:?} {st:?}", h.store);
    assert!(!all.contains("intent-marker-55aa"));
    assert!(all.contains("OperationKey(..)"));
    let st = format!("{:?}", h.status(&id));
    assert!(!st.contains("editor"));
}
