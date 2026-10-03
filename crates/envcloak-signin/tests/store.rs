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
    DAEMON, MCP, OTHER_MCP, OTHER_ROOT, ROOT, SIBLING, Spec, TestWorld, at, clock, identity, scope,
};
use envcloak_policy::Now;
use envcloak_signin::store::STATEMENT_TTL;
use envcloak_signin::{
    ApproveError, AttemptError, AttemptFailure, Authorization, AuthorizationId, Channel,
    ChannelRefused, Checkpoint, Cleanup, DaemonInstance, Deadline, Discarded, Effect, Fresh,
    Generation, Instance, Lookup, Nonce, NotFound, Operation, OperationKey, OperationStore,
    Options, Phase, PublishDecision, RETRY_WINDOW, Refusal, Request, RequestError, RequestId,
    Revisions, Revocation, SignInScope, SignInStatement, State, Status, Step, StopReason,
    StoreLimits, publication_decision,
};

struct H {
    store: OperationStore,
    world: TestWorld,
    /// The wall clock and the awake clock, in seconds from the origin;
    /// [`H::tick`] moves both.
    wall: u64,
    awake: u64,
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
            wall: 0,
            awake: 0,
            draws: 0,
        }
    }

    fn now(&self) -> Now {
        clock(self.wall, self.awake)
    }

    /// Moves both clocks and lets the daemon react.
    fn tick(&mut self, secs: u64) {
        self.pass(secs);
        self.store.reconcile(&self.now(), &self.world);
    }

    /// Moves both clocks with no call: the next call sees the time.
    fn pass(&mut self, secs: u64) {
        self.wall += secs;
        self.awake += secs;
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
            .lookup_or_reserve(r, fresh, &self.now(), &self.world)
    }

    fn open(&mut self, key: &str, spec: &Spec) -> RequestId {
        let s = self.scope(spec);
        match self.request(key, s).unwrap() {
            Lookup::Reserved(st) => st.request,
            Lookup::Joined(st) => panic!("joined {st:?}"),
        }
    }

    fn statement(&mut self, id: &RequestId, options: Options) -> Option<SignInStatement> {
        let (now, w) = (self.now(), self.world.clone());
        self.store.statement(id, options, &now, &w)
    }

    fn approve(&mut self, id: &RequestId, options: Options) -> Result<Status, ApproveError> {
        let digest = self.statement(id, options).map(|s| s.digest());
        let digest = digest.unwrap_or([0; 32]);
        self.store
            .approve(id, options, &digest, &self.now(), &self.world)
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
            .status(&owner, id, &self.now(), &self.world)
            .unwrap()
    }

    fn captured(&mut self, id: &RequestId) {
        let g = self.generation(id);
        self.store
            .worker_captured(id, g, &self.now(), &self.world)
            .unwrap();
    }

    fn supervisor(&self, id: &RequestId) -> Channel {
        Channel::Supervisor(self.op(id).supervisor().unwrap())
    }

    fn inject(&mut self, id: &RequestId) {
        let from = self.supervisor(id);
        self.store
            .inject_state(&from, id, &self.now(), &self.world)
            .unwrap();
    }

    fn decide(&mut self, id: &RequestId, role: &str) -> PublishDecision {
        let from = self.supervisor(id);
        self.store
            .identity_response(&from, id, &identity(role), &self.now(), &self.world)
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
    let digest = h.statement(&id, dev(2)).unwrap().digest();
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
    assert_eq!(h.statement(&id, dev(2)).unwrap().digest(), digest);
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
    let digest = h.statement(&id, dev(2)).unwrap().digest();
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
    assert_eq!(h.statement(&id, dev(2)).unwrap().digest(), digest);
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
        let now = h.now();
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
        .cancel(&owner, &a, &h.now(), &h.world.clone())
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
            &h.now(),
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
    let (now, w) = (h.now(), h.world.clone());
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
            &h.now(),
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
            &h.now(),
            &h.world.clone(),
        )
        .unwrap();
    assert_eq!(h.op(&b).phase(), Phase::Approved);
    h.store
        .cleanup_result(&a, ga, true, &h.now(), &h.world.clone())
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
    h.store.reconcile(&h.now(), &h.world.clone());
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
/// the statement is no longer shown, the stale proof mints nothing, and
/// nothing reaches the changed target (R-M2b-44, R-M2b-51, SI-05; L-09).
/// Mutations: "statement without settle", "approve without settle".
#[test]
fn a_stale_proof_mints_nothing() {
    for change in [
        |w: &mut TestWorld| w.target += 1,
        |w: &mut TestWorld| w.browser += 1,
        |w: &mut TestWorld| w.adapter += 1,
        |w: &mut TestWorld| w.epochs.policy += 1,
    ] {
        // Not shown any more: the change stopped it at that call.
        let mut h = H::new();
        let id = h.open("k", &Spec::dev());
        assert!(h.statement(&id, dev(2)).is_some());
        change(&mut h.world);
        assert!(h.statement(&id, dev(2)).is_none());
        // A proof checked meanwhile is refused by the approval itself.
        let mut h = H::new();
        let id = h.open("k", &Spec::dev());
        let digest = h.statement(&id, dev(2)).unwrap().digest();
        change(&mut h.world);
        let got = h
            .store
            .approve(&id, dev(2), &digest, &h.now(), &h.world.clone());
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
    let theirs = h.statement(&other, dev(2)).unwrap().digest();
    let before = h.store.clone();
    let (now, w) = (h.now(), h.world.clone());
    assert_eq!(
        h.store.approve(&id, dev(2), &theirs, &now, &w),
        Err(ApproveError::DigestMismatch)
    );
    let three = h.statement(&id, dev(3)).unwrap().digest();
    assert_eq!(
        h.store.approve(&id, dev(2), &three, &now, &w),
        Err(ApproveError::DigestMismatch)
    );
    let six = Options::Dev {
        window: Duration::from_secs(60),
        attempts: 6,
    };
    let d6 = h.statement(&id, six).unwrap().digest();
    assert!(matches!(
        h.store.approve(&id, six, &d6, &now, &w),
        Err(ApproveError::Options(_))
    ));
    assert_eq!(h.store, before);
}

/// Publication is one decision: after cancel, lock or root exit nothing
/// is published, and late worker results are discarded (R-M2b-28,
/// R-M2b-46, R-M2b-54). The owner's cancel and end before delivery read
/// `cancelled`; any other stop before delivery reads `failed`.
#[test]
fn a_stop_before_publication_wins() {
    let states = [
        State::Cancelled,
        State::Cancelled,
        State::Failed,
        State::Failed,
        State::Failed,
    ];
    let stops: [fn(&mut H, &RequestId); 5] = [
        |h, id| {
            let o = h.op(id).owner();
            h.store.cancel(&o, id, &h.now(), &h.world.clone()).unwrap();
        },
        |h, id| {
            let o = h.op(id).owner();
            h.store.end(&o, id, &h.now(), &h.world.clone()).unwrap();
        },
        |h, _| h.store.lock(&h.now(), &h.world.clone()),
        |h, _| {
            h.world.exited.insert(ROOT);
            h.store.reconcile(&h.now(), &h.world.clone());
        },
        |h, _| {
            h.world.exited.insert(MCP);
            h.store.reconcile(&h.now(), &h.world.clone());
        },
    ];
    for (stop, state) in stops.into_iter().zip(states) {
        let mut h = H::new();
        let id = h.ready("k", &Spec::dev(), dev(2));
        let g = h.generation(&id);
        stop(&mut h, &id);
        let before = h.store.clone();
        assert_eq!(
            h.decide(&id, "editor"),
            PublishDecision::Refuse(Refusal::Stopped)
        );
        let (now, w) = (h.now(), h.world.clone());
        assert!(h.store.worker_captured(&id, g, &now, &w).is_err());
        let from = h.supervisor(&id);
        assert!(h.store.published(&from, &id, &now, &w).is_err());
        assert!(h.store.check(&from, &id, &now, &w).is_err());
        assert_eq!(h.store, before);
        let st = h.status(&id);
        assert!(!st.receipt.delivered);
        assert_eq!(st.state, state);
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
        .published(&from, &id, &h.now(), &h.world.clone())
        .unwrap();
    h.store
        .check(&from, &id, &h.now(), &h.world.clone())
        .unwrap();
    h.store.drain_effects();
    let owner = h.op(&id).owner();
    let st = h
        .store
        .cancel(&owner, &id, &h.now(), &h.world.clone())
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
            .check(&from, &id, &h.now(), &h.world.clone())
            .is_err()
    );
    h.store
        .cleanup_result(&id, g, false, &h.now(), &h.world.clone())
        .unwrap();
    let st = h.status(&id);
    assert_eq!(st.receipt.cleanup, Cleanup::Failed);
    assert_eq!(st.receipt.revocation, Revocation::Unknown);
    // Idempotent: a second cancel changes nothing.
    let before = h.store.clone();
    h.store
        .cancel(&owner, &id, &h.now(), &h.world.clone())
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
            .identity_response(&from, &id, &who, &h.now(), &h.world.clone())
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
    let (now, w) = (h.now(), h.world.clone());
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
            .worker_captured(&id, g, &h.now(), &h.world.clone())
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
    assert_eq!(fresh.status(&ROOT, &id, &h.now(), &w), Err(NotFound));
}

/// Status revisions increase with every change of what status answers,
/// and polls change nothing (R-M2b-08).
#[test]
fn status_revisions_increase_with_every_change_and_only_then() {
    let mut h = H::new();
    let id = h.open("k", &Spec::dev());
    let mut last = h.status(&id);
    // A window longer than the session, so the session's own end is what
    // stops it.
    let long = Options::Dev {
        window: Duration::from_secs(7200),
        attempts: 2,
    };
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
    h.approve(&id, long).unwrap();
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
        .published(&from, &id, &h.now(), &h.world.clone())
        .unwrap();
    check(&mut h, true);
    h.tick(3600);
    check(&mut h, true);
    assert_eq!(
        h.status(&id).receipt.reason,
        Some(StopReason::SessionExpired)
    );
}

/// `dev` options with a window longer than every other limit of
/// [`Spec::dev`], so only what a test does ends the attempt or the
/// session.
fn long() -> Options {
    Options::Dev {
        window: Duration::from_secs(7200),
        attempts: 2,
    }
}

/// `dev` options whose window (600 s) ends before the attempt's timeout
/// (900 s) and the session's lifetime (3600 s).
fn short() -> Options {
    Options::Dev {
        window: Duration::from_secs(600),
        attempts: 2,
    }
}

impl H {
    fn owner_of(&self, id: &RequestId) -> Instance {
        self.op(id).owner()
    }

    /// Request and approve: the attempt is running.
    fn running(&mut self, key: &str, spec: &Spec, options: Options) -> RequestId {
        let id = self.open(key, spec);
        self.approve(&id, options).unwrap();
        assert_eq!(self.op(&id).phase(), Phase::AttemptRunning);
        id
    }

    /// Request, approve, capture, inject, decide and publish.
    fn delivered(&mut self, key: &str, spec: &Spec, options: Options) -> RequestId {
        let id = self.ready(key, spec, options);
        assert_eq!(self.decide(&id, spec.role), PublishDecision::Publish);
        let from = self.supervisor(&id);
        let (now, w) = (self.now(), self.world.clone());
        self.store.published(&from, &id, &now, &w).unwrap();
        assert_eq!(self.op(&id).phase(), Phase::Published);
        id
    }

    fn check_call(&mut self, id: &RequestId) -> Result<(), ChannelRefused> {
        let from = self.supervisor(id);
        let (now, w) = (self.now(), self.world.clone());
        self.store.check(&from, id, &now, &w)
    }

    fn teardowns(&mut self) -> Vec<(RequestId, bool)> {
        self.store
            .drain_effects()
            .into_iter()
            .filter_map(|e| match e {
                Effect::TearDown {
                    request, delivered, ..
                } => Some((request, delivered)),
                _ => None,
            })
            .collect()
    }

    /// Whether the authorization `id` still authorizes anything now: the
    /// store keeps it while in force, or forgets it once it ended.
    fn in_force(&self, id: &AuthorizationId) -> bool {
        self.store
            .authorization(id)
            .is_some_and(|a| a.in_force(&self.world.epochs, &self.now()))
    }
}

/// A change made with no call: the next call is the first to see it, as
/// when the world moves at a barrier before a worker, driver or supervisor
/// message (b9, b17). Owner calls are changes too, made through the store.
#[derive(Clone, Copy)]
struct Change {
    name: &'static str,
    apply: fn(&mut H, &RequestId),
    reason: StopReason,
    options: Options,
}

fn world_change(name: &'static str, apply: fn(&mut H, &RequestId), reason: StopReason) -> Change {
    Change {
        name,
        apply,
        reason,
        options: long(),
    }
}

/// What ends an operation in any phase, with no call.
fn silent_changes() -> Vec<Change> {
    vec![
        world_change(
            "root exit",
            |h, _| {
                h.world.exited.insert(ROOT);
            },
            StopReason::RootExited,
        ),
        world_change(
            "requester exit",
            |h, _| {
                h.world.exited.insert(MCP);
            },
            StopReason::RecipientReplaced,
        ),
        world_change(
            "vault epoch",
            |h, _| h.world.epochs.vault += 1,
            StopReason::EpochChanged,
        ),
        world_change(
            "policy epoch",
            |h, _| h.world.epochs.policy += 1,
            StopReason::EpochChanged,
        ),
        world_change(
            "login revision",
            |h, _| h.world.login += 1,
            StopReason::RevisionChanged,
        ),
        world_change(
            "target revision",
            |h, _| h.world.target += 1,
            StopReason::RevisionChanged,
        ),
        world_change(
            "adapter revision",
            |h, _| h.world.adapter += 1,
            StopReason::RevisionChanged,
        ),
        world_change(
            "browser replaced",
            |h, _| h.world.browser += 1,
            StopReason::RecipientReplaced,
        ),
        Change {
            name: "authorization window",
            apply: |h, _| h.pass(600),
            reason: StopReason::AuthorizationEnded,
            options: short(),
        },
    ]
}

/// The silent changes for an attempt (running or captured), its timeout
/// included.
fn attempt_changes() -> Vec<Change> {
    let mut v = silent_changes();
    v.push(world_change(
        "attempt timeout",
        |h, _| h.pass(900),
        StopReason::AttemptTimedOut,
    ));
    v
}

/// The silent changes for a delivered session, its lifetime included.
fn session_changes() -> Vec<Change> {
    let mut v = silent_changes();
    v.push(world_change(
        "session lifetime",
        |h, _| h.pass(3600),
        StopReason::SessionExpired,
    ));
    v
}

/// A password or one-time-code step is permitted only for a running
/// attempt that has not stopped, as it stands at that call: after cancel,
/// end or lock, and after a root exit, an epoch, revision or recipient
/// change, the attempt's timeout or its authorization's end with no call
/// in between, nothing is permitted (SPEC §6.8: a code only inside a bound
/// attempt; R-M2b-54). Mutations: "permit ignores the stop", "permit
/// without settle".
#[test]
fn a_credential_step_needs_a_running_attempt_at_that_call() {
    // Positive control: a running attempt gets its password and a code.
    let mut h = H::new();
    let id = h.running("k", &Spec::dev(), long());
    let g = h.generation(&id);
    let (now, w) = (h.now(), h.world.clone());
    assert_eq!(h.store.permit(&id, g, Step::Password, &now, &w), Ok(()));
    assert_eq!(h.store.permit(&id, g, Step::Code, &now, &w), Ok(()));
    let mut stops = attempt_changes();
    stops.extend([
        world_change(
            "cancel",
            |h, id| {
                let (o, now, w) = (h.owner_of(id), h.now(), h.world.clone());
                h.store.cancel(&o, id, &now, &w).unwrap();
            },
            StopReason::Cancelled,
        ),
        world_change(
            "end",
            |h, id| {
                let (o, now, w) = (h.owner_of(id), h.now(), h.world.clone());
                h.store.end(&o, id, &now, &w).unwrap();
            },
            StopReason::EndedByOwner,
        ),
        world_change(
            "lock",
            |h, _| {
                let (now, w) = (h.now(), h.world.clone());
                h.store.lock(&now, &w);
            },
            StopReason::Locked,
        ),
    ]);
    for c in stops {
        let mut h = H::new();
        let id = h.running("k", &Spec::dev(), c.options);
        let g = h.generation(&id);
        (c.apply)(&mut h, &id);
        let (now, w) = (h.now(), h.world.clone());
        for step in [Step::Password, Step::Code] {
            assert_eq!(
                h.store.permit(&id, g, step, &now, &w),
                Err(AttemptError::NotRunning),
                "{} {step:?}",
                c.name
            );
        }
        assert_eq!((h.op(&id).passwords(), h.op(&id).codes()), (0, 0));
        assert_eq!(h.status(&id).receipt.reason, Some(c.reason), "{}", c.name);
    }
}

/// Every call reads the world and the clock as they are at that call, and
/// brings the store up to date before it acts: a change made with no call
/// in between stops the operation first, so the worker's capture or
/// failure is discarded, no declared state is given, the decision refuses
/// as stopped, publication and the per-call check are refused, the
/// owner's cancel and a lock keep the change's reason, a status shows it,
/// and the teardown the change asked for can be confirmed at once
/// (b9, b17; R-M2b-28, R-M2b-46, R-M2b-54). Mutations: removing the
/// entry settle from worker_captured, worker_failed, inject_state,
/// identity_response, published, check, cancel, lock or cleanup_result.
#[test]
fn every_call_sees_a_change_made_before_it() {
    for c in attempt_changes() {
        let n = c.name;
        // The worker's results.
        let mut h = H::new();
        let id = h.running("k", &Spec::dev(), c.options);
        let g = h.generation(&id);
        h.store.drain_effects();
        (c.apply)(&mut h, &id);
        let (now, w) = (h.now(), h.world.clone());
        assert_eq!(
            h.store.worker_captured(&id, g, &now, &w),
            Err(Discarded),
            "{n}"
        );
        assert!(
            !h.store
                .drain_effects()
                .iter()
                .any(|e| matches!(e, Effect::StartSupervisor { .. })),
            "{n}"
        );
        assert_eq!(h.status(&id).receipt.reason, Some(c.reason), "{n}");
        let mut h = H::new();
        let id = h.running("k", &Spec::dev(), c.options);
        let g = h.generation(&id);
        (c.apply)(&mut h, &id);
        let (now, w) = (h.now(), h.world.clone());
        let failed = h
            .store
            .worker_failed(&id, g, AttemptFailure::WorkerLost, &now, &w);
        assert_eq!(failed, Err(Discarded), "{n}");
        assert_eq!(h.status(&id).receipt.reason, Some(c.reason), "{n}");
        // The owner's cancel and a lock come after the change.
        for owner_call in [true, false] {
            let mut h = H::new();
            let id = h.running("k", &Spec::dev(), c.options);
            (c.apply)(&mut h, &id);
            let (o, now, w) = (h.owner_of(&id), h.now(), h.world.clone());
            if owner_call {
                let st = h.store.cancel(&o, &id, &now, &w).unwrap();
                assert_eq!(st.receipt.reason, Some(c.reason), "{n} cancel");
                assert_eq!(st.state, State::Failed, "{n} cancel");
            } else {
                h.store.lock(&now, &w);
                assert_eq!(h.status(&id).receipt.reason, Some(c.reason), "{n} lock");
            }
        }
        // The teardown the change asked for is confirmed by the next report.
        let mut h = H::new();
        let id = h.running("k", &Spec::dev(), c.options);
        let g = h.generation(&id);
        (c.apply)(&mut h, &id);
        let (now, w) = (h.now(), h.world.clone());
        assert_eq!(
            h.store.cleanup_result(&id, g, true, &now, &w),
            Ok(()),
            "{n}"
        );
        assert_eq!(h.op(&id).cleanup(), Cleanup::Done, "{n}");
        // The supervisor's claim of captured state.
        let mut h = H::new();
        let id = h.running("k", &Spec::dev(), c.options);
        h.captured(&id);
        (c.apply)(&mut h, &id);
        let (from, now, w) = (h.supervisor(&id), h.now(), h.world.clone());
        assert_eq!(
            h.store.inject_state(&from, &id, &now, &w),
            Err(ChannelRefused),
            "{n}"
        );
        // The decision, with the state injected.
        let mut h = H::new();
        let id = h.ready("k", &Spec::dev(), c.options);
        (c.apply)(&mut h, &id);
        assert_eq!(
            h.decide(&id, "editor"),
            PublishDecision::Refuse(Refusal::Stopped),
            "{n}"
        );
        let st = h.status(&id);
        assert_eq!(
            (st.state, st.receipt.reason),
            (State::Failed, Some(c.reason))
        );
        assert!(!st.receipt.delivered, "{n}");
    }
    for c in session_changes() {
        let n = c.name;
        // Publication after the decision.
        let mut h = H::new();
        let id = h.ready("k", &Spec::dev(), c.options);
        assert_eq!(h.decide(&id, "editor"), PublishDecision::Publish);
        (c.apply)(&mut h, &id);
        let (from, now, w) = (h.supervisor(&id), h.now(), h.world.clone());
        assert_eq!(
            h.store.published(&from, &id, &now, &w),
            Err(ChannelRefused),
            "{n}"
        );
        assert_eq!(h.op(&id).phase(), Phase::PublishDecided, "{n}");
        // The per-call check on a published session.
        let mut h = H::new();
        let id = h.delivered("k", &Spec::dev(), c.options);
        h.store.drain_effects();
        (c.apply)(&mut h, &id);
        assert_eq!(h.check_call(&id), Err(ChannelRefused), "{n}");
        assert_eq!(h.teardowns(), vec![(id, true)], "{n}");
        let st = h.status(&id);
        assert_eq!(
            (st.state, st.receipt.reason),
            (State::Ended, Some(c.reason))
        );
        assert!(st.receipt.delivered, "{n}");
    }
}

/// A retry is answered from the store as it stands at the retry: a
/// receipt whose window passed with no call in between is gone, so the
/// same key is a new intent, and a pending statement whose expiry passed
/// is answered stopped (R-M2b-13). Mutation: "lookup without settle".
#[test]
fn a_retry_sees_the_store_as_it_stands_at_the_retry() {
    let mut h = H::new();
    let spec = Spec::dev();
    let id = h.open("k", &spec);
    let o = h.owner_of(&id);
    let (now, w) = (h.now(), h.world.clone());
    h.store.cancel(&o, &id, &now, &w).unwrap();
    h.pass(RETRY_WINDOW.as_secs() - 1);
    let s = h.scope(&spec);
    assert!(matches!(h.request("k", s), Ok(Lookup::Joined(_))));
    h.pass(1);
    let s = h.scope(&spec);
    match h.request("k", s).unwrap() {
        Lookup::Reserved(st) => assert_ne!(st.request, id),
        other => panic!("{other:?}"),
    }
    let mut h = H::new();
    let id = h.open("k", &spec);
    h.pass(STATEMENT_TTL.as_secs());
    let s = h.scope(&spec);
    match h.request("k", s).unwrap() {
        Lookup::Joined(st) => {
            assert_eq!(st.request, id);
            assert_eq!(st.receipt.reason, Some(StopReason::StatementExpired));
        }
        other => panic!("{other:?}"),
    }
}

/// `publication_decision` on its own, one refusal at a time, each against
/// a checkpoint that publishes (the positive control): the stop, the
/// generation, the injected state, the identity, the root, the three
/// epochs, the three revisions, the recipient, the attempt's deadline and
/// the authorization (plan M2b-01 Interfaces; R-M2b-28, R-M2b-46).
/// Mutations: each check dropped in turn.
#[test]
fn the_publication_decision_refuses_each_reason_on_its_own() {
    use PublishDecision::{Publish, Refuse};
    let mut h = H::new();
    let spec = Spec::dev();
    let id = h.ready("a", &spec, long());
    // `a` captured, so the login is free: `b`, covered by the same `dev`
    // authorization, runs with another generation.
    let b = h.open("b", &spec);
    let other = h.generation(&b);
    let op = h.op(&id).clone();
    let g = op.generation().unwrap();
    let auth = h
        .store
        .authorization(&op.authorization().unwrap())
        .unwrap()
        .clone();
    let me = identity("editor");
    let base = Checkpoint {
        now: h.now(),
        epochs: h.world.epochs,
        revisions: Revisions::of(op.scope()),
        root_alive: true,
    };
    assert_eq!(
        publication_decision(&op, Some(&auth), g, &me, &base),
        Publish
    );
    // Stopped: the same operation after the owner's cancel.
    let mut stopped = h.store.clone();
    let (o, w) = (h.owner_of(&id), h.world.clone());
    stopped.cancel(&o, &id, &base.now, &w).unwrap();
    let x = stopped.operation(&id).unwrap();
    assert_eq!(
        publication_decision(x, Some(&auth), g, &me, &base),
        Refuse(Refusal::Stopped)
    );
    assert_eq!(
        publication_decision(&op, Some(&auth), other, &me, &base),
        Refuse(Refusal::WrongGeneration)
    );
    // Not ready: captured but not injected, and a decision already taken.
    let mut fresh = H::new();
    let c = fresh.running("c", &spec, long());
    fresh.captured(&c);
    let x = fresh.op(&c).clone();
    let xa = fresh
        .store
        .authorization(&x.authorization().unwrap())
        .unwrap()
        .clone();
    let xg = x.generation().unwrap();
    assert_eq!(
        publication_decision(&x, Some(&xa), xg, &me, &base),
        Refuse(Refusal::NotReady)
    );
    let mut decided = h.store.clone();
    let from = Channel::Supervisor(op.supervisor().unwrap());
    decided
        .identity_response(&from, &id, &me, &base.now, &w)
        .unwrap();
    let x = decided.operation(&id).unwrap();
    assert_eq!(x.phase(), Phase::PublishDecided);
    assert_eq!(
        publication_decision(x, Some(&auth), g, &me, &base),
        Refuse(Refusal::NotReady)
    );
    assert_eq!(
        publication_decision(&op, Some(&auth), g, &identity("admin"), &base),
        Refuse(Refusal::IdentityUnverified)
    );
    let with = |f: fn(&mut Checkpoint)| {
        let mut c = base;
        f(&mut c);
        c
    };
    type Edit = fn(&mut Checkpoint);
    let cases: [(Edit, Refusal); 9] = [
        (|c| c.root_alive = false, Refusal::RootExited),
        (|c| c.epochs.vault += 1, Refusal::EpochChanged),
        (|c| c.epochs.policy += 1, Refusal::EpochChanged),
        (
            |c| c.epochs.daemon = DaemonInstance::from_bytes([9; 16]),
            Refusal::EpochChanged,
        ),
        (|c| c.revisions.login += 1, Refusal::RevisionChanged),
        (|c| c.revisions.target += 1, Refusal::RevisionChanged),
        (|c| c.revisions.adapter += 1, Refusal::RevisionChanged),
        (|c| c.revisions.browser += 1, Refusal::RecipientChanged),
        (
            |c| c.revisions.requester_alive = false,
            Refusal::RecipientChanged,
        ),
    ];
    for (f, why) in cases {
        assert_eq!(
            publication_decision(&op, Some(&auth), g, &me, &with(f)),
            Refuse(why)
        );
    }
    // The attempt's deadline: 900 s after it started at 0.
    let late = |t| Checkpoint { now: at(t), ..base };
    assert_eq!(
        publication_decision(&op, Some(&auth), g, &me, &late(899)),
        Publish
    );
    assert_eq!(
        publication_decision(&op, Some(&auth), g, &me, &late(900)),
        Refuse(Refusal::Expired)
    );
    // The authorization: missing, another one, ended, run out.
    let ended = {
        let mut a = auth.clone();
        a.end();
        a
    };
    let another = Authorization::once(AuthorizationId::new(99), op.scope(), &base.now);
    let short_window =
        Authorization::dev(auth.id(), op.scope(), Duration::from_secs(600), 2, &at(0)).unwrap();
    assert_eq!(
        publication_decision(&op, Some(&short_window), g, &me, &late(599)),
        Publish
    );
    for (a, at) in [
        (None, base),
        (Some(&another), base),
        (Some(&ended), base),
        (Some(&short_window), late(600)),
    ] {
        assert_eq!(
            publication_decision(&op, a, g, &me, &at),
            Refuse(Refusal::AuthorizationEnded)
        );
    }
}

/// A lock ends a delivered session as it ends everything else: the
/// supervisor's next check is refused, the teardown says delivered, the
/// receipt reads ended, and the `dev` authorization is over, so a new key
/// with the same scope needs a new proof (SPEC §5 "Lock ... drops every
/// grant"; §6.8 "clamped by ... lock"; R-M2b-54). Without the lock the new
/// key is covered (the positive control). Mutations: "lock leaves the
/// authorizations in force", "lock skips delivered sessions".
#[test]
fn a_lock_ends_a_delivered_session_and_its_authorization() {
    let spec = Spec::dev();
    let mut h = H::new();
    h.delivered("a", &spec, long());
    let covered = h.open("b", &spec);
    assert_eq!(h.op(&covered).phase(), Phase::AttemptRunning);
    let mut h = H::new();
    let id = h.delivered("a", &spec, long());
    let auth = h.op(&id).authorization().unwrap();
    assert_eq!(h.check_call(&id), Ok(()));
    h.store.drain_effects();
    let (now, w) = (h.now(), h.world.clone());
    h.store.lock(&now, &w);
    assert_eq!(h.check_call(&id), Err(ChannelRefused));
    assert_eq!(h.teardowns(), vec![(id, true)]);
    let st = h.status(&id);
    assert_eq!(
        (st.state, st.receipt.reason),
        (State::Ended, Some(StopReason::Locked))
    );
    assert!(!h.in_force(&auth));
    let after = h.open("b", &spec);
    assert_eq!(h.op(&after).phase(), Phase::PendingApproval);
    assert_eq!(h.op(&after).authorization(), None);
}

/// Every change that ends an attempt ends a delivered session too, with
/// no call in between: its check is refused, its teardown says delivered,
/// its receipt reads ended with the change's reason, and its
/// authorization no longer authorizes anything (R-M2b-17, R-M2b-28,
/// R-M2b-54). Mutation: "the world checks skip delivered phases".
#[test]
fn every_change_ends_a_delivered_session() {
    for c in session_changes() {
        let n = c.name;
        let mut h = H::new();
        let id = h.delivered("a", &Spec::dev(), c.options);
        let auth = h.op(&id).authorization().unwrap();
        h.store.drain_effects();
        (c.apply)(&mut h, &id);
        h.store.reconcile(&h.now(), &h.world.clone());
        assert_eq!(h.teardowns(), vec![(id, true)], "{n}");
        assert_eq!(h.check_call(&id), Err(ChannelRefused), "{n}");
        let st = h.status(&id);
        assert_eq!(
            (st.state, st.receipt.reason),
            (State::Ended, Some(c.reason))
        );
        if c.reason != StopReason::SessionExpired {
            assert!(!h.in_force(&auth), "{n}");
        }
    }
}

/// A delivered session ends with its authorization: a `dev` window shorter
/// than the session's lifetime stops the session when the window ends,
/// and no tool call is checked after it (SPEC §6.8: the supervisor checks
/// the grant on every call). Mutation: "a delivered session is checked
/// against its own lifetime only".
#[test]
fn a_delivered_session_ends_with_its_authorization() {
    let mut h = H::new();
    let id = h.delivered("a", &Spec::dev(), short());
    h.store.drain_effects();
    h.pass(599);
    assert_eq!(h.check_call(&id), Ok(()));
    h.pass(1);
    assert_eq!(h.check_call(&id), Err(ChannelRefused));
    assert_eq!(h.teardowns(), vec![(id, true)]);
    let st = h.status(&id);
    assert_eq!(
        (st.state, st.receipt.reason),
        (State::Ended, Some(StopReason::AuthorizationEnded))
    );
    assert!(st.receipt.delivered);
}

/// A failed teardown is not a teardown: the worker may still run with the
/// credentials it was sent, so the login stays held and the next attempt
/// waits until a later report confirms the close; a failure reported
/// again changes nothing (SPEC §6.8 "Attempts on one account are
/// serialised"; `cleanup_unconfirmed`). Mutation: "a failed close frees
/// the login".
#[test]
fn a_failed_teardown_holds_the_login_until_a_close_is_confirmed() {
    let mut h = H::new();
    let spec = Spec::dev();
    let a = h.running("a", &spec, long());
    let b = h.open("b", &spec);
    assert_eq!(h.op(&b).phase(), Phase::Approved);
    let g = h.generation(&a);
    let (now, w) = (h.now(), h.world.clone());
    h.store
        .worker_failed(&a, g, AttemptFailure::WorkerLost, &now, &w)
        .unwrap();
    h.store.cleanup_result(&a, g, false, &now, &w).unwrap();
    assert_eq!(h.op(&a).cleanup(), Cleanup::Failed);
    assert_eq!(h.op(&b).phase(), Phase::Approved);
    h.tick(60);
    assert_eq!(h.op(&b).phase(), Phase::Approved);
    let (now, w) = (h.now(), h.world.clone());
    assert_eq!(
        h.store.cleanup_result(&a, g, false, &now, &w),
        Err(Discarded)
    );
    assert_eq!(h.op(&b).phase(), Phase::Approved);
    // The confirmation frees the login: `b` starts.
    h.store.drain_effects();
    assert_eq!(h.store.cleanup_result(&a, g, true, &now, &w), Ok(()));
    assert_eq!(h.op(&a).cleanup(), Cleanup::Done);
    assert_eq!(h.op(&b).phase(), Phase::AttemptRunning);
    assert!(
        h.store
            .drain_effects()
            .iter()
            .any(|e| matches!(e, Effect::StartAttempt { request, .. } if *request == b))
    );
    assert_eq!(
        h.store.cleanup_result(&a, g, true, &now, &w),
        Err(Discarded)
    );
}

/// An unconfirmed teardown (pending, or failed) outlives its retry window
/// as a tombstone: the retry still gets the receipt, and a later report
/// that the close succeeded is taken; only then, its window being over,
/// is it forgotten (L-08;
/// docs/GRANTS.md "while its cleanup is unconfirmed"). Mutations: "the
/// sweep forgets a failed close", "a failed close can never be
/// confirmed".
#[test]
fn an_unconfirmed_teardown_is_kept_until_it_is_confirmed() {
    for fail_first in [true, false] {
        let mut h = H::new();
        let spec = Spec::dev();
        let id = h.running("k", &spec, long());
        let g = h.generation(&id);
        let (o, now, w) = (h.owner_of(&id), h.now(), h.world.clone());
        h.store.cancel(&o, &id, &now, &w).unwrap();
        if fail_first {
            h.store.cleanup_result(&id, g, false, &now, &w).unwrap();
        }
        h.tick(RETRY_WINDOW.as_secs() * 3);
        let want = if fail_first {
            Cleanup::Failed
        } else {
            Cleanup::Pending
        };
        assert_eq!(h.status(&id).receipt.cleanup, want);
        let s = h.scope(&spec);
        assert!(matches!(h.request("k", s), Ok(Lookup::Joined(_))));
        let (now, w) = (h.now(), h.world.clone());
        assert_eq!(h.store.cleanup_result(&id, g, true, &now, &w), Ok(()));
        // Confirmed, and past its window: forgotten at once.
        assert!(h.store.operation(&id).is_none());
    }
}

/// A `once` authorization lasts the scope's approval duration, the one
/// lifetime its statement carries: a 30-second approval ends a 900-second
/// attempt at 30 seconds, and a 4-hour approval does not cut a delivered
/// session at the attempt's timeout. Mutations: "once lasts the attempt
/// timeout" (the first case runs on), "once lasts the shorter of the
/// approval and the attempt timeout" (the session is cut at 900 s).
#[test]
fn a_once_authorization_lasts_the_approval_duration() {
    let spec = Spec {
        approval: Duration::from_secs(30),
        ..Spec::each()
    };
    let mut h = H::new();
    let id = h.running("k", &spec, Options::Once);
    let auth = h.op(&id).authorization().unwrap();
    assert_eq!(
        h.store.authorization(&auth).unwrap().deadline().wall(),
        common::wall(30)
    );
    h.tick(29);
    assert_eq!(h.status(&id).state, State::AttemptRunning);
    h.tick(1);
    assert_eq!(
        h.status(&id).receipt.reason,
        Some(StopReason::AuthorizationEnded)
    );
    let mut h = H::new();
    let id = h.delivered("k", &Spec::each(), Options::Once);
    h.tick(1800);
    assert_eq!(h.check_call(&id), Ok(()));
    h.tick(1800);
    assert_eq!(h.check_call(&id), Err(ChannelRefused));
    assert_eq!(
        h.status(&id).receipt.reason,
        Some(StopReason::SessionExpired)
    );
}

/// A deadline has passed once either clock reaches it: the wall clock
/// alone (awake time stands still across a sleep) or the awake clock
/// alone (the wall clock set back). Unit cases on [`Deadline`], then each
/// deadline the store keeps, on each clock alone: the statement's expiry,
/// the authorization's window, the attempt's timeout, the session's
/// lifetime and `retry_until`. Mutations: "passed reads the wall clock
/// only", "passed reads the awake clock only".
#[test]
fn every_deadline_passes_on_either_clock() {
    let start = clock(1000, 1000);
    let d = Deadline::after(&start, Duration::from_secs(100));
    assert!(!d.passed(&clock(1099, 1099)));
    assert!(d.passed(&clock(1100, 1000)), "asleep: wall only");
    assert!(d.passed(&clock(1000, 1100)), "awake only");
    assert!(d.passed(&clock(0, 1100)), "wall clock set back");
    assert!(!d.passed(&clock(0, 1099)), "set back, not yet");
    #[derive(Clone, Copy, Debug)]
    enum Only {
        Wall,
        Awake,
    }
    let only = |h: &mut H, which: Only, secs: u64| match which {
        Only::Wall => h.wall += secs,
        Only::Awake => h.awake += secs,
    };
    for which in [Only::Wall, Only::Awake] {
        // (setup, seconds to its deadline, reason)
        type Setup = fn(&mut H) -> RequestId;
        let kinds: [(&str, Setup, u64, Option<StopReason>); 5] = [
            (
                "statement",
                |h| h.open("k", &Spec::dev()),
                STATEMENT_TTL.as_secs(),
                Some(StopReason::StatementExpired),
            ),
            (
                "authorization",
                |h| h.running("k", &Spec::dev(), short()),
                600,
                Some(StopReason::AuthorizationEnded),
            ),
            (
                "attempt",
                |h| h.running("k", &Spec::dev(), long()),
                900,
                Some(StopReason::AttemptTimedOut),
            ),
            (
                "session",
                |h| h.delivered("k", &Spec::dev(), long()),
                3600,
                Some(StopReason::SessionExpired),
            ),
            (
                "retry_until",
                |h| {
                    let id = h.open("k", &Spec::dev());
                    let (o, now, w) = (h.owner_of(&id), h.now(), h.world.clone());
                    h.store.cancel(&o, &id, &now, &w).unwrap();
                    id
                },
                RETRY_WINDOW.as_secs(),
                None,
            ),
        ];
        for (name, setup, secs, reason) in kinds {
            let mut h = H::new();
            let id = setup(&mut h);
            let before = h.status(&id);
            only(&mut h, which, secs - 1);
            assert_eq!(h.status(&id), before, "{name} {which:?} early");
            only(&mut h, which, 1);
            match reason {
                Some(r) => assert_eq!(h.status(&id).receipt.reason, Some(r), "{name} {which:?}"),
                None => {
                    let (o, now, w) = (h.owner_of(&id), h.now(), h.world.clone());
                    assert_eq!(
                        h.store.status(&o, &id, &now, &w),
                        Err(NotFound),
                        "{which:?}"
                    );
                }
            }
        }
    }
}

/// Nothing a registration or a request gave shows in the `Debug` of the
/// store, a status, a scope, a statement or an identity response: not
/// the key, the account, tenant or role, a cookie name, a storage key,
/// the identity check's locator, a host or the project's directory (L-12).
/// The detector's positive control finds every marker in the labels' own
/// text.
#[test]
fn debug_output_holds_no_key_label_host_or_path() {
    use envcloak_core::vault::ItemId;
    use envcloak_signin::{
        Account, AdapterId, CheckKind, DeclaredCookie, DeclaredStorage, Delivery, DeliveryMode,
        Environment, Host, IdentityCheck, IdentityResponse, Label, Limits, Origin, ProjectScope,
        Scheme, SortedSet, Subject, Target, TargetId, Tier, TransferScope,
    };
    let markers = [
        "intent-marker-55aa",
        "acct-marker-1f2e",
        "tenant-marker-3d4c",
        "role-marker-5b6a",
        "cookie-marker-7988",
        "storage-marker-a9b8",
        "locator-marker-c7d6",
        "host-marker-e5f4",
        "dir-marker-0a1b",
    ];
    let found = |s: &str| markers.iter().filter(|m| s.contains(*m)).count();
    let l = |s: &str| Label::new(s).unwrap();
    let host = Host::name("host-marker-e5f4.localhost").unwrap();
    let app = Origin::new(Scheme::Http, host.clone(), 3000).unwrap();
    let w = TestWorld::new();
    let scope = SignInScope::new(
        Subject {
            root: ROOT,
            evidence: [1; 32],
        },
        ProjectScope {
            dir: b"/work/dir-marker-0a1b".to_vec(),
            dev: 1,
            ino: 2,
            config: [3; 32],
        },
        Account {
            login_item: ItemId::from_bytes(common::LOGIN),
            authorization_revision: w.login,
            account: l("acct-marker-1f2e"),
            tenant: Some(l("tenant-marker-3d4c")),
            role: l("role-marker-5b6a"),
            environment: Environment::Test,
        },
        Target {
            id: TargetId::from_bytes([4; 16]),
            revision: w.target,
            adapter: AdapterId::from_bytes([5; 16]),
            adapter_revision: w.adapter,
            entry_origins: SortedSet::new(vec![app.clone()]).unwrap(),
            identity_check: IdentityCheck {
                kind: CheckKind::Element,
                locator: l("locator-marker-c7d6"),
            },
            transfer: TransferScope {
                cookies: SortedSet::new(vec![DeclaredCookie {
                    host,
                    name: l("cookie-marker-7988"),
                }])
                .unwrap(),
                storage: SortedSet::new(vec![DeclaredStorage {
                    origin: app,
                    key: l("storage-marker-a9b8"),
                }])
                .unwrap(),
            },
        },
        Delivery {
            mode: DeliveryMode::BrowserSession,
            requester: MCP,
            browser: w.browser,
        },
        Limits::new(
            Tier::Dev,
            3,
            Duration::from_secs(3600),
            Duration::from_secs(900),
            Duration::from_secs(3600),
        )
        .unwrap(),
        w.epochs,
    )
    .unwrap();
    // The positive control: the labels' own text holds every marker but
    // the key's.
    let a: &Account = scope.account();
    let plain = format!(
        "{} {} {} {} {}",
        a.account.as_str(),
        a.tenant.as_ref().unwrap().as_str(),
        a.role.as_str(),
        scope.target().identity_check.locator.as_str(),
        String::from_utf8_lossy(&scope.project().dir),
    );
    assert_eq!(found(&plain), 5);
    let mut h = H::new();
    let id = match h.request("intent-marker-55aa", scope.clone()).unwrap() {
        Lookup::Reserved(st) => st.request,
        other => panic!("{other:?}"),
    };
    let st = h.status(&id);
    let statement = h.statement(&id, Options::Once).unwrap();
    let who = IdentityResponse {
        account: l("acct-marker-1f2e"),
        tenant: None,
        role: l("role-marker-5b6a"),
    };
    let all = format!("{:?} {st:?} {scope:?} {statement:?} {who:?}", h.store);
    assert_eq!(found(&all), 0, "{all}");
    assert!(all.contains("OperationKey(..)"));
}

/// A drawn request id already in use opens nothing and changes nothing
/// (the daemon draws again): an operation is never overwritten.
/// Mutation: "no check of the drawn id".
#[test]
fn a_request_id_in_use_is_refused() {
    let mut h = H::new();
    let a = h.open("a", &Spec::dev());
    let before = h.store.clone();
    let fresh = Fresh {
        request: a,
        nonce: Nonce::from_bytes([0x77; 32]),
    };
    let r = Request {
        key: OperationKey::parse("b").unwrap(),
        scope: h.scope(&Spec::dev()),
    };
    let (now, w) = (h.now(), h.world.clone());
    assert_eq!(
        h.store.lookup_or_reserve(r, fresh, &now, &w),
        Err(RequestError::IdInUse)
    );
    assert_eq!(h.store, before);
}

/// The store holds at most its bound of authorizations: one proof more is
/// refused and changes nothing, and an authorization that ended (here by
/// a lock) and that no live operation holds is forgotten, which makes
/// room (L-08). Mutations: "approve past the bound", "keep ended
/// authorizations".
#[test]
fn authorizations_are_bounded_and_ended_ones_make_room() {
    let mut h = H::with_limits(StoreLimits {
        per_root: 8,
        total: 8,
        authorizations: 1,
    });
    let spec = Spec::dev();
    let a = h.open("a", &spec);
    h.approve(&a, long()).unwrap();
    let admin = Spec {
        role: "admin",
        ..spec.clone()
    };
    let b = h.open("b", &admin);
    let before = h.store.clone();
    assert_eq!(h.approve(&b, long()), Err(ApproveError::Full));
    assert_eq!(h.store, before);
    let (now, w) = (h.now(), h.world.clone());
    h.store.lock(&now, &w);
    assert_eq!(h.store.authorizations().count(), 0);
    let c = h.open("c", &admin);
    assert!(h.approve(&c, long()).is_ok());
}

/// `reserve_credit` and `in_force` on their own, one reason at a time:
/// ended, past the deadline (on either clock), under other epochs, out of
/// credits; each reservation takes the next credit, a refusal takes none,
/// and nothing gives one back (plan M2b-01 Interfaces; R-M2b-16). The
/// constructors keep to the scope's limits. Mutations: each check
/// dropped in turn.
#[test]
fn reserving_a_credit_refuses_each_reason_on_its_own() {
    use envcloak_signin::{BudgetError, Epochs, OptionsError};
    let w = TestWorld::new();
    let sc = scope(&Spec::dev(), &w);
    let e = w.epochs;
    let t0 = at(0);
    let new = || {
        Authorization::dev(
            AuthorizationId::new(1),
            &sc,
            Duration::from_secs(600),
            2,
            &t0,
        )
        .unwrap()
    };
    let mut a = new();
    assert!(a.in_force(&e, &at(599)));
    assert_eq!(a.reserve_credit(&e, &at(0)).map(|l| l.credit()), Ok(1));
    assert_eq!(a.reserve_credit(&e, &at(599)).map(|l| l.credit()), Ok(2));
    assert_eq!(a.reserve_credit(&e, &at(1)), Err(BudgetError::Exhausted));
    assert_eq!(a.remaining(), 0);
    let mut a = new();
    a.end();
    assert!(!a.in_force(&e, &t0));
    assert_eq!(a.reserve_credit(&e, &t0), Err(BudgetError::Ended));
    let mut a = new();
    for late in [at(600), clock(600, 0), clock(0, 600)] {
        assert!(!a.in_force(&e, &late));
        assert_eq!(a.reserve_credit(&e, &late), Err(BudgetError::Expired));
    }
    let other = Epochs { vault: 2, ..e };
    assert!(!a.in_force(&other, &t0));
    assert_eq!(a.reserve_credit(&other, &t0), Err(BudgetError::StaleEpochs));
    assert_eq!(a.remaining(), 2);
    // The constructors keep to the scope's limits (approval 4 h, 5
    // attempts) and to `dev`'s own.
    let id = AuthorizationId::new(2);
    let hours = |n: u64| Duration::from_secs(n * 3600);
    assert!(Authorization::dev(id, &sc, hours(4), 5, &t0).is_ok());
    assert_eq!(
        Authorization::dev(id, &sc, hours(4) + Duration::from_secs(1), 5, &t0).unwrap_err(),
        OptionsError::Window
    );
    assert_eq!(
        Authorization::dev(id, &sc, hours(4), 6, &t0).unwrap_err(),
        OptionsError::Attempts
    );
    let each = scope(&Spec::each(), &w);
    assert_eq!(
        Authorization::dev(id, &each, hours(1), 1, &t0).unwrap_err(),
        OptionsError::NotDev
    );
    let once = Authorization::once(id, &each, &t0);
    assert_eq!((once.credits(), once.remaining()), (1, 1));
    assert_eq!(once.deadline(), Deadline::after(&t0, hours(4)));
}
