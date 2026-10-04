//! The operation store, case by case (SPEC §6.8 "Retries", "Approval" and
//! "Delivery"; R-M2b-08, R-M2b-13 to R-M2b-17, R-M2b-27, R-M2b-28,
//! R-M2b-35, R-M2b-44 to R-M2b-46, R-M2b-51, R-M2b-54; SI-05 to SI-10).
//! `tests/enumeration.rs` checks the same rules under every ordering of
//! events; these name each rule once, with a clock and a world the test
//! moves by hand.
#![allow(clippy::unwrap_used)]

mod common;

use std::collections::BTreeMap;
use std::time::Duration;

use common::{
    DAEMON, MCP, OTHER_MCP, OTHER_ROOT, ROOT, SIBLING, Spec, TestWorld, Vary, at, clock, identity,
    label, origin, scope, variations, varied,
};
use envcloak_policy::Now;
use envcloak_signin::store::STATEMENT_TTL;
use envcloak_signin::{
    AdapterId, ApproveError, AttemptError, AttemptFailure, Authorization, AuthorizationId, Channel,
    ChannelRefused, Checkpoint, Cleanup, Current, DaemonInstance, Deadline, Discarded, Effect,
    Environment, Fresh, Generation, Instance, Limits, Lookup, Nonce, NotFound, Operation,
    OperationKey, OperationStore, Options, Phase, PublishDecision, RETRY_WINDOW, Refusal, Request,
    RequestError, RequestId, Requester, Revocation, Scheme, SignInScope, SignInStatement,
    SortedSet, State, Status, Step, StopReason, StoreLimits, SupervisorId, TargetId, WorkerId,
    publication_decision,
};

struct H {
    store: OperationStore,
    world: TestWorld,
    /// The wall clock and the awake clock, in seconds from the origin;
    /// [`H::tick`] moves both.
    wall: u64,
    awake: u64,
    draws: u8,
    /// What the store asked the daemon to do, in order, as [`H::drain`]
    /// has not yet returned it; and the worker and supervisor ids the
    /// start effects handed out, the only place a test (or the daemon)
    /// gets them.
    effects: Vec<Effect>,
    workers: BTreeMap<RequestId, WorkerId>,
    supervisors: BTreeMap<RequestId, SupervisorId>,
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
            effects: Vec::new(),
            workers: BTreeMap::new(),
            supervisors: BTreeMap::new(),
        }
    }

    /// Takes the store's effects, keeping the ids the start effects hand
    /// out, as the daemon does.
    fn harvest(&mut self) {
        for e in self.store.drain_effects() {
            match e {
                Effect::StartAttempt {
                    request, worker, ..
                } => {
                    assert!(self.workers.insert(request, worker).is_none());
                }
                Effect::StartSupervisor {
                    request,
                    supervisor,
                } => {
                    assert!(self.supervisors.insert(request, supervisor).is_none());
                }
                Effect::TearDown { .. } => {}
            }
            self.effects.push(e);
        }
    }

    /// Every effect not yet returned, oldest first.
    fn drain(&mut self) -> Vec<Effect> {
        self.harvest();
        std::mem::take(&mut self.effects)
    }

    /// `id`'s worker, as [`Effect::StartAttempt`] handed it out.
    fn worker(&mut self, id: &RequestId) -> WorkerId {
        if !self.workers.contains_key(id) {
            self.harvest();
        }
        self.workers[id]
    }

    /// `id`'s supervisor channel, as [`Effect::StartSupervisor`] handed
    /// its id out.
    fn supervisor(&mut self, id: &RequestId) -> Channel {
        if !self.supervisors.contains_key(id) {
            self.harvest();
        }
        Channel::Supervisor(self.supervisors[id])
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
        let w = self.worker(id);
        self.store
            .worker_captured(id, &w, &self.now(), &self.world)
            .unwrap();
        self.harvest();
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
    // Approved and running: the approval asked for one attempt, with the
    // worker id of the attempt's generation and the reserved lease; a retry
    // still starts nothing.
    h.approve(&id, dev(2)).unwrap();
    let (worker, lease) = (h.worker(&id), h.op(&id).lease().unwrap());
    assert_eq!(worker.generation(), h.generation(&id));
    assert_eq!(
        h.drain(),
        vec![Effect::StartAttempt {
            request: id,
            worker,
            lease
        }]
    );
    let s = h.scope(&spec);
    assert!(matches!(h.request("intent-1", s), Ok(Lookup::Joined(_))));
    assert!(h.drain().is_empty());
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
    // Every part of the scope changed alone, each field and each part of a
    // declared cookie, storage key and origin: a conflict that changes
    // nothing. A scope of another daemon is refused before the lookup, and
    // another root's same key is that root's own operation.
    let base = h.scope(&spec);
    let mut tried = 0;
    for v in variations() {
        let Some(s) = varied(&base, v) else {
            continue;
        };
        match (v, h.request("k", s)) {
            (Vary::Field(29), Err(RequestError::WrongDaemon)) => {}
            (Vary::Field(1), Ok(Lookup::Reserved(st))) => {
                assert_ne!(st.request, id);
                h.store = before.clone();
            }
            (Vary::Field(1 | 29), got) => panic!("{v:?}: {got:?}"),
            (_, got) => assert_eq!(got, Err(RequestError::Conflict), "{v:?}"),
        }
        assert_eq!(h.store, before, "{v:?}");
        tried += 1;
    }
    assert_eq!(tried, variations().len() - 2);
    assert_eq!(h.statement(&id, dev(2)).unwrap().digest(), digest);
    // The positive control: the same key and scope join.
    assert!(matches!(h.request("k", base), Ok(Lookup::Joined(st)) if st.request == id));
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
    let g = h.worker(&id);
    h.drain();
    h.store
        .worker_failed(
            &id,
            &g,
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
    let effects = h.drain();
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
    let g = h.worker(&id);
    let (now, w) = (h.now(), h.world.clone());
    assert_eq!(h.store.permit(&id, &g, Step::Password, &now, &w), Ok(()));
    assert_eq!(
        h.store.permit(&id, &g, Step::Password, &now, &w),
        Err(AttemptError::Spent)
    );
    assert_eq!(h.store.permit(&id, &g, Step::Code, &now, &w), Ok(()));
    assert_eq!(h.store.permit(&id, &g, Step::Code, &now, &w), Ok(()));
    assert_eq!(
        h.store.permit(&id, &g, Step::Code, &now, &w),
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
    let g = h.worker(&a);
    h.store
        .worker_failed(
            &a,
            &g,
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
    let ga = h.worker(&a);
    h.store
        .worker_failed(
            &a,
            &ga,
            AttemptFailure::WorkerLost,
            &h.now(),
            &h.world.clone(),
        )
        .unwrap();
    assert_eq!(h.op(&b).phase(), Phase::Approved);
    h.store
        .cleanup_result(&a, &ga, true, &h.now(), &h.world.clone())
        .unwrap();
    assert_eq!(h.op(&b).phase(), Phase::AttemptRunning);
    assert_eq!(h.op(&c).phase(), Phase::Approved);
    h.captured(&b);
    assert_eq!(h.op(&c).phase(), Phase::AttemptRunning);
}

/// `scope` for another login item, with its account, target and origin
/// changed as `edit` says.
fn another_item(
    h: &H,
    edit: impl Fn(&mut envcloak_signin::Account, &mut envcloak_signin::Target),
) -> SignInScope {
    let s = h.scope(&Spec::dev());
    let mut account = s.account().clone();
    let mut target = s.target().clone();
    account.login_item = envcloak_core::vault::ItemId::from_bytes([0x66; 16]);
    edit(&mut account, &mut target);
    SignInScope::new(
        s.subject().clone(),
        s.project().clone(),
        account,
        target,
        s.delivery().clone(),
        s.limits().clone(),
        *s.epochs(),
    )
    .unwrap()
}

/// Attempts on one account are serialized whatever login item names it
/// (SPEC §6.8 "Attempts on one account are serialised"): a second item
/// for the same account at the same target (a duplicate registration), in
/// another tenant, spelled in another case, or under another target id
/// that shares a credential-entry origin, waits until the running attempt
/// captured, or stopped with its teardown confirmed. The positive
/// controls: another account at the same target, and the same account
/// name at another app (another target, no shared origin), start at once.
/// Mutation: "attempts serialized per login item".
#[test]
fn attempts_on_one_account_are_serialized() {
    type Edit = fn(&mut envcloak_signin::Account, &mut envcloak_signin::Target);
    let same: [(&str, Edit); 4] = [
        ("a duplicate item", |_, _| {}),
        ("another tenant", |a, _| a.tenant = Some(label("globex"))),
        ("another case", |a, _| {
            a.account = label("Editor@Fixture.TEST");
        }),
        ("another target sharing an origin", |_, t| {
            t.id = TargetId::from_bytes([0x42; 16]);
        }),
    ];
    let other: [(&str, Edit); 2] = [
        ("another account", |a, _| {
            a.account = label("viewer@fixture.test");
        }),
        ("the same name at another app", |_, t| {
            t.id = TargetId::from_bytes([0x42; 16]);
            t.entry_origins =
                SortedSet::new(vec![origin(Scheme::Https, "other.example", 443)]).unwrap();
        }),
    ];
    for (n, edit) in same {
        let mut h = H::new();
        let a = h.running("a", &Spec::dev(), long());
        let s = another_item(&h, edit);
        assert!(s.shares_account(h.op(&a).scope()), "{n}");
        let b = match h.request("b", s).unwrap() {
            Lookup::Reserved(st) => st.request,
            got => panic!("{n}: {got:?}"),
        };
        h.approve(&b, long()).unwrap();
        assert_eq!(h.op(&b).phase(), Phase::Approved, "{n}");
        // A failed close holds the account too.
        let wa = h.worker(&a);
        let (now, w) = (h.now(), h.world.clone());
        h.store
            .worker_failed(&a, &wa, AttemptFailure::WorkerLost, &now, &w)
            .unwrap();
        h.store.cleanup_result(&a, &wa, false, &now, &w).unwrap();
        assert_eq!(h.op(&b).phase(), Phase::Approved, "{n}");
        h.store.cleanup_result(&a, &wa, true, &now, &w).unwrap();
        assert_eq!(h.op(&b).phase(), Phase::AttemptRunning, "{n}");
        // And a capture frees it.
        let mut h = H::new();
        let a = h.running("a", &Spec::dev(), long());
        let b = match h.request("b", another_item(&h, edit)).unwrap() {
            Lookup::Reserved(st) => st.request,
            got => panic!("{n}: {got:?}"),
        };
        h.approve(&b, long()).unwrap();
        assert_eq!(h.op(&b).phase(), Phase::Approved, "{n}");
        h.captured(&a);
        assert_eq!(h.op(&b).phase(), Phase::AttemptRunning, "{n}");
    }
    for (n, edit) in other {
        let mut h = H::new();
        let a = h.running("a", &Spec::dev(), long());
        let s = another_item(&h, edit);
        assert!(!s.shares_account(h.op(&a).scope()), "{n}");
        let b = match h.request("b", s).unwrap() {
            Lookup::Reserved(st) => st.request,
            got => panic!("{n}: {got:?}"),
        };
        h.approve(&b, long()).unwrap();
        assert_eq!(h.op(&b).phase(), Phase::AttemptRunning, "{n}");
        assert_eq!(h.op(&a).phase(), Phase::AttemptRunning, "{n}");
    }
}

/// `grants revoke <id>` for a sign-in authorization (SPEC §10b: any client
/// may revoke; tightening needs no proof): its delivered session, its
/// running attempt and its queued operation stop with `revoked`, their
/// teardowns are asked for (delivered as each was), and it covers no new
/// key; another authorization is untouched: its delivered session's check
/// passes, its running attempt takes its password, and it still covers a
/// new key of its own scope. Revoking it again, an unknown id, or after
/// the lock changes nothing. Mutations: "revoke leaves the authorization
/// in force", "revoke stops no operation", "revoke stops every operation".
#[test]
fn revoking_one_authorization_ends_only_what_it_authorizes() {
    let editor = Spec::dev();
    let admin = Spec {
        role: "admin",
        ..Spec::dev()
    };
    let mut h = H::new();
    // Five credits: three are taken below, so a refusal to cover a new key
    // is never a spent budget.
    let opts = Options::Dev {
        window: Duration::from_secs(7200),
        attempts: 5,
    };
    let delivered = h.delivered("a", &editor, opts);
    // The other authorization, for another role.
    let kept = h.delivered("d", &admin, opts);
    let running = h.open("b", &editor);
    let queued = h.open("c", &editor);
    let auth = h.op(&delivered).authorization().unwrap();
    let kept_auth = h.op(&kept).authorization().unwrap();
    assert_ne!(kept_auth, auth);
    assert_eq!(h.op(&running).authorization(), Some(auth));
    assert_eq!(h.op(&running).phase(), Phase::AttemptRunning);
    assert_eq!(h.op(&queued).authorization(), Some(auth));
    assert_eq!(h.op(&queued).phase(), Phase::Approved);
    assert_eq!(h.store.authorization(&auth).unwrap().remaining(), 2);
    h.drain();
    let (now, w) = (h.now(), h.world.clone());
    assert!(h.store.revoke(&auth, &now, &w));
    let mut teardowns = h.teardowns();
    teardowns.sort();
    let mut want = vec![(delivered, true), (running, false)];
    want.sort();
    assert_eq!(teardowns, want);
    for (id, state) in [
        (delivered, State::Ended),
        (running, State::Failed),
        (queued, State::Failed),
    ] {
        let st = h.status(&id);
        assert_eq!(
            (st.state, st.receipt.reason),
            (state, Some(StopReason::Revoked))
        );
    }
    assert!(!h.in_force(&auth));
    assert_eq!(h.check_call(&delivered), Err(ChannelRefused));
    // Nothing else changed.
    assert!(h.in_force(&kept_auth));
    assert_eq!(h.check_call(&kept), Ok(()));
    assert_eq!(h.op(&kept).stop(), None);
    // A new key of the revoked scope asks for a proof; one of the kept
    // scope is covered and runs once the account is free.
    let again = h.open("e", &editor);
    assert_eq!(h.op(&again).authorization(), None);
    assert_eq!(h.op(&again).phase(), Phase::PendingApproval);
    let more = h.open("f", &admin);
    assert_eq!(h.op(&more).authorization(), Some(kept_auth));
    // Revoking again, or an unknown id, changes nothing.
    let before = h.store.clone();
    let (now, w) = (h.now(), h.world.clone());
    assert!(!h.store.revoke(&auth, &now, &w));
    assert!(!h.store.revoke(&AuthorizationId::new(999), &now, &w));
    assert_eq!(h.store, before);
    // `--all` ends the rest.
    assert_eq!(h.store.revoke_all(&now, &w), 1);
    assert!(!h.in_force(&kept_auth));
    assert_eq!(h.check_call(&kept), Err(ChannelRefused));
    assert_eq!(h.status(&kept).receipt.reason, Some(StopReason::Revoked));
    assert_eq!(h.store.revoke_all(&now, &w), 0);
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
    h.drain();
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
        .drain()
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

/// Any change of the world while the proof is checked (a target edit, a
/// browser replacement, the requester leaving the root's tree or an agent
/// coming between them, the project replaced, the login item deleted, ...)
/// is seen before the authorization: the statement is no longer shown, the
/// stale proof mints nothing, nothing reaches the changed target, and the
/// operation reads the change's reason (R-M2b-44, R-M2b-51, SI-05; L-09;
/// SPEC §10b "Match" rules 3 to 5). Mutations: "statement without settle",
/// "approve without settle", "the world's subject, project, login item,
/// target or limits left out of the freshness check".
#[test]
fn a_stale_proof_mints_nothing() {
    for c in world_changes() {
        let n = c.name;
        // Not shown any more: the change stopped it at that call.
        let mut h = H::new();
        let id = h.open("k", &Spec::dev());
        assert!(h.statement(&id, dev(2)).is_some(), "{n}");
        (c.apply)(&mut h, &id);
        assert!(h.statement(&id, dev(2)).is_none(), "{n}");
        // A proof checked meanwhile is refused by the approval itself.
        let mut h = H::new();
        let id = h.open("k", &Spec::dev());
        let digest = h.statement(&id, dev(2)).unwrap().digest();
        (c.apply)(&mut h, &id);
        let got = h
            .store
            .approve(&id, dev(2), &digest, &h.now(), &h.world.clone());
        assert_eq!(got, Err(ApproveError::NotPending), "{n}");
        assert_eq!(h.store.authorizations().count(), 0, "{n}");
        assert!(h.drain().is_empty(), "{n}");
        assert_eq!(h.status(&id).receipt.reason, Some(c.reason), "{n}");
    }
    // The positive control: with no change the same proof approves.
    let mut h = H::new();
    let id = h.open("k", &Spec::dev());
    let digest = h.statement(&id, dev(2)).unwrap().digest();
    let (now, w) = (h.now(), h.world.clone());
    assert!(h.store.approve(&id, dev(2), &digest, &now, &w).is_ok());
}

/// A `dev` authorization covers no new key once the world no longer holds
/// what its scope took, though the key's scope is exactly its own (as a
/// request the daemon resolved before the change and passed after it):
/// the authorization ended at that call, the new operation waits for a
/// proof and is stopped for the change's reason, and no credit is taken
/// (SPEC §10b "Match": a sign-in is matched after rules 1 to 4, and rule
/// 5's project). The positive control: with no change the key is covered.
/// Mutation: "settle ends no authorization the world made stale".
#[test]
fn a_changed_world_covers_no_new_key() {
    let spec = Spec::dev();
    let mut h = H::new();
    let a = h.running("a", &spec, long());
    let auth = h.op(&a).authorization().unwrap();
    let covered = h.open("b", &spec);
    assert_eq!(h.op(&covered).authorization(), Some(auth));
    for c in world_changes() {
        let n = c.name;
        let mut h = H::new();
        let a = h.running("a", &spec, long());
        let auth = h.op(&a).authorization().unwrap();
        let s = h.scope(&spec);
        (c.apply)(&mut h, &a);
        let b = match h.request("b", s) {
            Ok(Lookup::Reserved(st)) => st.request,
            got => panic!("{n}: {got:?}"),
        };
        assert_eq!(h.op(&b).authorization(), None, "{n}");
        assert_eq!(h.op(&b).phase(), Phase::PendingApproval, "{n}");
        assert_eq!(h.status(&b).receipt.reason, Some(c.reason), "{n}");
        assert!(!h.in_force(&auth), "{n}");
        assert!(
            h.store
                .authorization(&auth)
                .is_none_or(|x| x.remaining() == 1),
            "{n}"
        );
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
        let g = h.worker(&id);
        stop(&mut h, &id);
        let before = h.store.clone();
        assert_eq!(
            h.decide(&id, "editor"),
            PublishDecision::Refuse(Refusal::Stopped)
        );
        let (now, w) = (h.now(), h.world.clone());
        assert!(h.store.worker_captured(&id, &g, &now, &w).is_err());
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
    h.drain();
    let owner = h.op(&id).owner();
    let st = h
        .store
        .cancel(&owner, &id, &h.now(), &h.world.clone())
        .unwrap();
    assert_eq!(st.state, State::Ended);
    assert!(st.receipt.delivered);
    assert_eq!(st.receipt.cleanup, Cleanup::Pending);
    let (g, wk) = (h.generation(&id), h.worker(&id));
    assert_eq!(
        h.drain(),
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
        .cleanup_result(&id, &wk, false, &h.now(), &h.world.clone())
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
/// no other generation's supervisor can claim, publish or check, and no
/// other attempt's worker reaches a running attempt (plan D-31, D-36;
/// R-M2b-27). The ids are the ones the start effects handed out, as the
/// daemon gets them; each own id is accepted (the positive controls).
#[test]
fn declared_state_goes_only_to_the_generations_supervisor() {
    let mut h = H::new();
    let spec = Spec::dev();
    let a = h.open("a", &spec);
    h.approve(&a, dev(3)).unwrap();
    h.captured(&a);
    // `a` captured, so the login is free: `b` runs and captures, then `c`
    // runs; all three under one authorization, each its own generation.
    let b = h.open("b", &spec);
    h.captured(&b);
    let c = h.open("c", &spec);
    assert_eq!(h.op(&c).phase(), Phase::AttemptRunning);
    let other = h.supervisor(&b);
    let (wa, wb, wc) = (h.worker(&a), h.worker(&b), h.worker(&c));
    h.harvest();
    let before = h.store.clone();
    let (now, w) = (h.now(), h.world.clone());
    // Worker results carrying another attempt's id are discarded: `a`'s
    // and `b`'s workers say nothing about `c`'s running attempt.
    for wrong in [wa, wb] {
        assert!(h.store.worker_captured(&c, &wrong, &now, &w).is_err());
        assert!(
            h.store
                .worker_failed(&c, &wrong, AttemptFailure::WorkerLost, &now, &w)
                .is_err()
        );
        assert!(
            h.store
                .permit(&c, &wrong, Step::Password, &now, &w)
                .is_err()
        );
        assert!(h.store.cleanup_result(&c, &wrong, true, &now, &w).is_err());
    }
    assert_eq!(h.store, before);
    let mut own = h.store.clone();
    assert_eq!(own.permit(&c, &wc, Step::Password, &now, &w), Ok(()));
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
    let g = h.worker(&id);
    h.tick(900);
    assert_eq!(
        h.status(&id).receipt.reason,
        Some(StopReason::AttemptTimedOut)
    );
    assert!(
        h.store
            .worker_captured(&id, &g, &h.now(), &h.world.clone())
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
        self.drain()
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

/// Revokes the authorization `id` holds, as any client may.
fn revoke_own(h: &mut H, id: &RequestId) {
    let auth = h.op(id).authorization().unwrap();
    let (now, w) = (h.now(), h.world.clone());
    assert!(h.store.revoke(&auth, &now, &w));
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

/// What ends an operation in any phase, with no call: every change of
/// the world.
fn silent_changes() -> Vec<Change> {
    let mut v = world_changes();
    v.push(Change {
        name: "authorization window",
        apply: |h, _| h.pass(600),
        reason: StopReason::AuthorizationEnded,
        options: short(),
    });
    v
}

/// The limits [`Spec::dev`] resolves to, with the session lifetime one
/// second shorter: a person edited them.
fn edited_limits(h: &mut H) {
    let l = h.scope(&Spec::dev()).limits().clone();
    let shorter = Limits::new(
        l.tier(),
        l.attempts(),
        l.approval(),
        l.attempt_timeout(),
        l.session_lifetime() - Duration::from_secs(1),
    )
    .unwrap();
    h.world.limits_edit = Some((l, shorter));
}

/// Every change of the world (not the clock) that ends what a scope
/// authorizes: each item of SPEC §10b's "A grant ends on" and "Match"
/// rules 1 to 5 the world can change, and each part of §6.8's sign-in
/// scope taken from the world.
fn world_changes() -> Vec<Change> {
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
        world_change(
            "requester left the root's tree",
            |h, _| h.world.leave_root(),
            StopReason::SubjectIneligible,
        ),
        world_change(
            "an agent between the root and the requester",
            |h, _| h.world.agent_between(),
            StopReason::SubjectIneligible,
        ),
        world_change(
            "project replaced",
            |h, _| h.world.project.ino += 1,
            StopReason::ProjectChanged,
        ),
        world_change(
            "project on another device",
            |h, _| h.world.project.dev += 1,
            StopReason::ProjectChanged,
        ),
        world_change(
            "project moved",
            |h, _| h.world.project.dir.push(b'2'),
            StopReason::ProjectChanged,
        ),
        world_change(
            "project gone",
            |h, _| h.world.project_gone = true,
            StopReason::ProjectChanged,
        ),
        world_change(
            "sign-in configuration changed",
            |h, _| h.world.project.config[0] ^= 1,
            StopReason::ProjectChanged,
        ),
        world_change(
            "login item deleted",
            |h, _| h.world.login_deleted = true,
            StopReason::RevisionChanged,
        ),
        world_change(
            "login item made live",
            |h, _| h.world.environment = Environment::Live,
            StopReason::RevisionChanged,
        ),
        world_change(
            "target removed",
            |h, _| h.world.target_removed = true,
            StopReason::RevisionChanged,
        ),
        world_change(
            "adapter replaced",
            |h, _| h.world.adapter_id = AdapterId::from_bytes([0x52; 16]),
            StopReason::RevisionChanged,
        ),
        world_change(
            "limits edited",
            |h, _| edited_limits(h),
            StopReason::LimitsChanged,
        ),
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
    let g = h.worker(&id);
    let (now, w) = (h.now(), h.world.clone());
    assert_eq!(h.store.permit(&id, &g, Step::Password, &now, &w), Ok(()));
    assert_eq!(h.store.permit(&id, &g, Step::Code, &now, &w), Ok(()));
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
        world_change("revoke", revoke_own, StopReason::Revoked),
    ]);
    for c in stops {
        let mut h = H::new();
        let id = h.running("k", &Spec::dev(), c.options);
        let g = h.worker(&id);
        (c.apply)(&mut h, &id);
        let (now, w) = (h.now(), h.world.clone());
        for step in [Step::Password, Step::Code] {
            assert_eq!(
                h.store.permit(&id, &g, step, &now, &w),
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
        let g = h.worker(&id);
        h.drain();
        (c.apply)(&mut h, &id);
        let (now, w) = (h.now(), h.world.clone());
        assert_eq!(
            h.store.worker_captured(&id, &g, &now, &w),
            Err(Discarded),
            "{n}"
        );
        // Only the change's teardown: no supervisor is started for it.
        assert_eq!(
            h.drain(),
            vec![Effect::TearDown {
                request: id,
                generation: g.generation(),
                delivered: false
            }],
            "{n}"
        );
        assert_eq!(h.status(&id).receipt.reason, Some(c.reason), "{n}");
        let mut h = H::new();
        let id = h.running("k", &Spec::dev(), c.options);
        let g = h.worker(&id);
        (c.apply)(&mut h, &id);
        let (now, w) = (h.now(), h.world.clone());
        let failed = h
            .store
            .worker_failed(&id, &g, AttemptFailure::WorkerLost, &now, &w);
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
        let g = h.worker(&id);
        (c.apply)(&mut h, &id);
        let (now, w) = (h.now(), h.world.clone());
        assert_eq!(
            h.store.cleanup_result(&id, &g, true, &now, &w),
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
        h.drain();
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
/// epochs, everything the scope took from the world (the project's
/// directory, device, inode and configuration, or a project that no
/// longer opens; the login item's revision and class, or a deleted item;
/// the target's revision, adapter and adapter revision, or a removed
/// target; the limits; the browser; the requesting instance exited, out
/// of the root's tree or behind an agent), the attempt's deadline and the
/// authorization (plan M2b-01 Interfaces; R-M2b-28, R-M2b-46; SPEC §10b
/// "Match" rules 3 to 5). Mutations: each check dropped in turn.
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
        current: Current::of(op.scope()),
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
    let from = h.supervisor(&id);
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
        let mut c = base.clone();
        f(&mut c);
        c
    };
    type Edit = fn(&mut Checkpoint);
    let cases: [(Edit, Refusal); 21] = [
        (|c| c.root_alive = false, Refusal::RootExited),
        (|c| c.epochs.vault += 1, Refusal::EpochChanged),
        (|c| c.epochs.policy += 1, Refusal::EpochChanged),
        (
            |c| c.epochs.daemon = DaemonInstance::from_bytes([9; 16]),
            Refusal::EpochChanged,
        ),
        (
            |c| c.current.project.as_mut().unwrap().dir.push(b'x'),
            Refusal::ProjectChanged,
        ),
        (
            |c| c.current.project.as_mut().unwrap().dev ^= 1,
            Refusal::ProjectChanged,
        ),
        (
            |c| c.current.project.as_mut().unwrap().ino ^= 1,
            Refusal::ProjectChanged,
        ),
        (
            |c| c.current.project.as_mut().unwrap().config[0] ^= 1,
            Refusal::ProjectChanged,
        ),
        (|c| c.current.project = None, Refusal::ProjectChanged),
        (
            |c| c.current.login.as_mut().unwrap().revision += 1,
            Refusal::RevisionChanged,
        ),
        (
            |c| c.current.login.as_mut().unwrap().environment = Environment::Live,
            Refusal::RevisionChanged,
        ),
        (|c| c.current.login = None, Refusal::RevisionChanged),
        (
            |c| c.current.target.as_mut().unwrap().revision += 1,
            Refusal::RevisionChanged,
        ),
        (
            |c| c.current.target.as_mut().unwrap().adapter_revision += 1,
            Refusal::RevisionChanged,
        ),
        (
            |c| c.current.target.as_mut().unwrap().adapter = AdapterId::from_bytes([9; 16]),
            Refusal::RevisionChanged,
        ),
        (|c| c.current.target = None, Refusal::RevisionChanged),
        (
            |c| {
                let l = &c.current.limits;
                c.current.limits = Limits::new(
                    l.tier(),
                    l.attempts(),
                    l.approval(),
                    l.attempt_timeout() + Duration::from_secs(1),
                    l.session_lifetime(),
                )
                .unwrap();
            },
            Refusal::LimitsChanged,
        ),
        (
            |c| {
                let l = &c.current.limits;
                c.current.limits = Limits::new(
                    l.tier(),
                    l.attempts() - 1,
                    l.approval(),
                    l.attempt_timeout(),
                    l.session_lifetime(),
                )
                .unwrap();
            },
            Refusal::LimitsChanged,
        ),
        (|c| c.current.browser += 1, Refusal::RecipientChanged),
        (
            |c| c.current.requester = Requester::Exited,
            Refusal::RecipientChanged,
        ),
        (
            |c| c.current.requester = Requester::Uncovered,
            Refusal::SubjectIneligible,
        ),
    ];
    for (f, why) in cases {
        assert_eq!(
            publication_decision(&op, Some(&auth), g, &me, &with(f)),
            Refuse(why)
        );
    }
    // The attempt's deadline: 900 s after it started at 0.
    let late = |t| Checkpoint {
        now: at(t),
        ..base.clone()
    };
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
        (None, base.clone()),
        (Some(&another), base.clone()),
        (Some(&ended), base.clone()),
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
    h.drain();
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
        h.drain();
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
    h.drain();
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
    let g = h.worker(&a);
    let (now, w) = (h.now(), h.world.clone());
    h.store
        .worker_failed(&a, &g, AttemptFailure::WorkerLost, &now, &w)
        .unwrap();
    h.store.cleanup_result(&a, &g, false, &now, &w).unwrap();
    assert_eq!(h.op(&a).cleanup(), Cleanup::Failed);
    assert_eq!(h.op(&b).phase(), Phase::Approved);
    h.tick(60);
    assert_eq!(h.op(&b).phase(), Phase::Approved);
    let (now, w) = (h.now(), h.world.clone());
    assert_eq!(
        h.store.cleanup_result(&a, &g, false, &now, &w),
        Err(Discarded)
    );
    assert_eq!(h.op(&b).phase(), Phase::Approved);
    // The confirmation frees the login: `b` starts.
    h.drain();
    assert_eq!(h.store.cleanup_result(&a, &g, true, &now, &w), Ok(()));
    assert_eq!(h.op(&a).cleanup(), Cleanup::Done);
    assert_eq!(h.op(&b).phase(), Phase::AttemptRunning);
    let started = h.drain();
    assert!(
        matches!(started.as_slice(), [Effect::StartAttempt { request, .. }] if *request == b),
        "{started:?}"
    );
    assert_eq!(
        h.store.cleanup_result(&a, &g, true, &now, &w),
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
        let g = h.worker(&id);
        let (o, now, w) = (h.owner_of(&id), h.now(), h.world.clone());
        h.store.cancel(&o, &id, &now, &w).unwrap();
        if fail_first {
            h.store.cleanup_result(&id, &g, false, &now, &w).unwrap();
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
        assert_eq!(h.store.cleanup_result(&id, &g, true, &now, &w), Ok(()));
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
/// the key, the account, tenant or role, a cookie name, a cookie's domain,
/// path or partition site, a storage key, the identity check's locator, a
/// host or the project's directory (L-12). The detector's positive
/// control finds every marker in the labels' and paths' own text.
#[test]
fn debug_output_holds_no_key_label_host_or_path() {
    use envcloak_core::vault::ItemId;
    use envcloak_signin::{
        Account, AdapterId, CheckKind, CookieDomain, CookiePartition, CookiePath, DeclaredCookie,
        DeclaredStorage, Delivery, DeliveryMode, Environment, Host, HostName, IdentityCheck,
        IdentityResponse, Label, Limits, Origin, ProjectScope, Scheme, Site, SortedSet, Subject,
        Target, TargetId, Tier, TransferScope,
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
        "path-marker-4c3d",
        "domain-marker-9e8f",
        "site-marker-2b1a",
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
                cookies: SortedSet::new(vec![
                    DeclaredCookie {
                        name: l("cookie-marker-7988"),
                        domain: CookieDomain::HostOnly(host),
                        path: CookiePath::new("/path-marker-4c3d").unwrap(),
                        partition: CookiePartition::Partitioned {
                            site: Site {
                                scheme: Scheme::Https,
                                host: Host::name("site-marker-2b1a.example").unwrap(),
                            },
                            cross_site_ancestor: true,
                        },
                    },
                    DeclaredCookie {
                        name: l("cookie-marker-7988"),
                        domain: CookieDomain::Domain(
                            HostName::new("domain-marker-9e8f.localhost").unwrap(),
                        ),
                        path: CookiePath::new("/").unwrap(),
                        partition: CookiePartition::Unpartitioned,
                    },
                ])
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
    let cookies: Vec<String> = scope
        .target()
        .transfer
        .cookies
        .iter()
        .map(|c| {
            let domain = match &c.domain {
                CookieDomain::HostOnly(Host::Name(n)) | CookieDomain::Domain(n) => n.as_str(),
                CookieDomain::HostOnly(_) => "",
            };
            let site = match &c.partition {
                CookiePartition::Partitioned {
                    site:
                        Site {
                            host: Host::Name(n),
                            ..
                        },
                    ..
                } => n.as_str(),
                _ => "",
            };
            format!("{} {domain} {} {site}", c.name.as_str(), c.path.as_str())
        })
        .collect();
    let plain = format!(
        "{} {} {} {} {} {} {}",
        a.account.as_str(),
        a.tenant.as_ref().unwrap().as_str(),
        a.role.as_str(),
        scope.target().identity_check.locator.as_str(),
        String::from_utf8_lossy(&scope.project().dir),
        cookies.join(" "),
        scope
            .target()
            .transfer
            .storage
            .iter()
            .map(|k| k.key.as_str())
            .collect::<String>(),
    );
    assert_eq!(found(&plain), markers.len() - 1);
    let mut h = H::new();
    h.world.project = scope.project().clone();
    h.world.adapter_id = scope.target().adapter;
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
    let at = Checkpoint {
        now: h.now(),
        epochs: h.world.epochs,
        current: Current::of(&scope),
        root_alive: true,
    };
    let all = format!(
        "{:?} {st:?} {scope:?} {statement:?} {who:?} {at:?}",
        h.store
    );
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

/// A valid capture asks the daemon to start exactly one supervisor, for
/// this operation and its attempt's generation, and the id that effect
/// hands out is the channel the declared state then goes to: the only way
/// to a supervisor. A capture that is discarded asks for nothing
/// (`every_call_sees_a_change_made_before_it`). Mutation: "worker_captured
/// asks for no supervisor".
#[test]
fn a_valid_capture_starts_the_generations_supervisor() {
    let mut h = H::new();
    let id = h.running("k", &Spec::dev(), long());
    let wk = h.worker(&id);
    assert!(
        h.drain()
            .iter()
            .all(|e| !matches!(e, Effect::StartSupervisor { .. }))
    );
    let (now, w) = (h.now(), h.world.clone());
    h.store.worker_captured(&id, &wk, &now, &w).unwrap();
    let effects = h.drain();
    let [
        Effect::StartSupervisor {
            request,
            supervisor,
        },
    ] = effects.as_slice()
    else {
        panic!("{effects:?}");
    };
    assert_eq!(*request, id);
    assert_eq!(supervisor.generation(), h.generation(&id));
    let inj = h
        .store
        .inject_state(&Channel::Supervisor(*supervisor), &id, &now, &w)
        .unwrap();
    assert_eq!(
        (inj.generation, inj.context),
        (h.generation(&id), h.op(&id).context())
    );
}

/// Each supervisor message takes exactly its own phase. The per-call check
/// is only for a published session: after the decision and before the
/// supervisor's acknowledgement it is refused and changes nothing.
/// Publication is one transition: a second acknowledgement, and a second
/// identity response after it, are refused and change nothing. The
/// positive controls: the first acknowledgement is taken, and the check
/// passes after it. Mutations: "check takes a decided session",
/// "published takes a published session".
#[test]
fn the_check_and_the_publication_each_take_their_own_phase() {
    let mut h = H::new();
    let id = h.ready("k", &Spec::dev(), long());
    assert_eq!(h.decide(&id, "editor"), PublishDecision::Publish);
    let from = h.supervisor(&id);
    h.harvest();
    let (now, w) = (h.now(), h.world.clone());
    let before = h.store.clone();
    assert_eq!(h.store.check(&from, &id, &now, &w), Err(ChannelRefused));
    assert_eq!(h.store, before);
    assert_eq!(h.store.published(&from, &id, &now, &w), Ok(()));
    assert_eq!(h.op(&id).phase(), Phase::Published);
    let before = h.store.clone();
    assert_eq!(h.store.published(&from, &id, &now, &w), Err(ChannelRefused));
    assert_eq!(
        h.store
            .identity_response(&from, &id, &identity("editor"), &now, &w),
        Ok(PublishDecision::Refuse(Refusal::NotReady))
    );
    assert_eq!(h.store, before);
    assert_eq!(h.store.check(&from, &id, &now, &w), Ok(()));
}

/// A `dev` authorization that is in force and has credits left covers a
/// new key only for exactly its scope. Every part of the scope changed
/// alone (each field of the encoding, and each part of a declared cookie,
/// storage key and credential-entry origin) asks for a fresh proof,
/// reserves nothing, starts nothing and leaves the budget as it was; then,
/// in the same store, the exact scope under a new key is covered (the
/// positive control, so no refusal comes from a spent budget). Fields 12
/// and 24 cannot change alone in a `dev` scope with credits to spare (a
/// live identity takes `each`, and `each` one attempt), and a scope of
/// another daemon (29) is refused before any lookup (R-M2b-35, R-M2b-45;
/// SPEC §6.8: "a new role, project or browser is a new scope and a new
/// approval"). Mutations: the cover check ignoring the project, the
/// account, the target, the transfer scope, a cookie's domain or path.
#[test]
fn every_scope_part_needs_its_own_approval() {
    let spec = Spec::dev();
    let mut tried = 0;
    for v in variations() {
        let mut h = H::new();
        let base = h.scope(&spec);
        let Some(changed) = varied(&base, v) else {
            assert!(matches!(v, Vary::Field(12 | 24)), "{v:?}");
            continue;
        };
        assert_ne!(changed.fingerprint(), base.fingerprint(), "{v:?}");
        let a = h.open("a", &spec);
        h.approve(&a, long()).unwrap();
        let auth = h.op(&a).authorization().unwrap();
        assert_eq!(h.store.authorization(&auth).unwrap().remaining(), 1);
        h.drain();
        match h.request("b", changed) {
            Err(RequestError::WrongDaemon) if v == Vary::Field(29) => {}
            Ok(Lookup::Reserved(st)) if v != Vary::Field(29) => {
                let b = h.op(&st.request);
                assert_eq!(
                    (b.authorization(), b.lease(), b.phase()),
                    (None, None, Phase::PendingApproval),
                    "{v:?}"
                );
            }
            got => panic!("{v:?}: {got:?}"),
        }
        assert_eq!(
            h.store.authorization(&auth).unwrap().remaining(),
            1,
            "{v:?}"
        );
        assert!(
            h.drain()
                .iter()
                .all(|e| !matches!(e, Effect::StartAttempt { .. })),
            "{v:?}"
        );
        let c = h.open("c", &spec);
        assert_eq!(h.op(&c).authorization(), Some(auth), "{v:?}");
        assert_eq!(h.store.authorization(&auth).unwrap().remaining(), 0);
        tried += 1;
    }
    assert_eq!(tried, variations().len() - 2);
}
