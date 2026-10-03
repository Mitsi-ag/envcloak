//! The sign-in contract under every ordering of its events (plan M2b-01,
//! gates b7, b8, b9, b14 and b17 at the model level; K-05).
//!
//! Each configuration below is two operations (slots A and B, each a key,
//! a root, a requesting instance and a role) and the options an approval
//! chooses. From an empty store, a depth-first search applies every
//! sequence of up to [`DEPTH`] events drawn from: a request with the
//! slot's key and scope, the same key with the role changed, an approval
//! of the statement the slot was shown, cancel and end from the owner,
//! the driver's password step, the worker's captured and failed results
//! with the attempt's generation, claim and publish from the generation's
//! supervisor, the same messages and worker results from every other
//! channel (another generation's supervisor, the requesting client, a
//! sibling `envcloak mcp` in the same root, another root's client) with
//! status, cancel and end from another root, the cleanup result, lock,
//! root exit, an epoch bump, a revision change, a replaced recipient and
//! a clock tick. Two states that are equal (the store, the world, the
//! clock, the ids drawn and the monitor's history) have the same futures,
//! so a state already explored with at least as many events left is not
//! explored again: every ordering is covered, each distinct state once.
//!
//! After every event the monitor checks, from outside the store:
//! - declared state and publication reach only the generation's
//!   supervisor, and every other channel's message changes nothing;
//! - at most one password per attempt and no more attempts or passwords
//!   than credits reserved; a `once` authorization starts at most one;
//! - nothing is published or injected after an accepted cancel, end,
//!   lock, root exit, epoch, revision or recipient change, and a
//!   publication is checked against the world independently;
//! - an authorization's remaining credits never grow and no deadline
//!   (authorization, statement, attempt, session, `retry_until`) moves
//!   later;
//! - the same key and scope give the same operation and change nothing; a
//!   changed field gives `request_conflict` and changes nothing; another
//!   root's key is never this root's;
//! - status revisions only increase, and increase whenever the status
//!   changed;
//! - a full store refuses and no operation disappears before its
//!   `retry_until`;
//! - late results (another generation, or a stopped operation) are
//!   discarded without effect;
//! - status, cancel and end from another root answer exactly as for an id
//!   that never existed.
//!
//! Each configuration also counts the cases its detectors judged
//! (publications, refusals, conflicts, joins, discarded results), and the
//! test requires them reached, so no invariant holds only because its case
//! never occurred.
#![allow(clippy::unwrap_used)]

mod common;

use std::collections::{BTreeMap, HashMap};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::time::{Duration, SystemTime};

use common::{MCP, OTHER_MCP, OTHER_ROOT, ROOT, SIBLING, Spec, TestWorld, at, identity, scope};
use envcloak_policy::Now;
use envcloak_signin::{
    AttemptFailure, AuthorizationId, Channel, Deadline, Effect, Fresh, Generation, Instance,
    Lookup, Nonce, NotFound, Operation, OperationKey, OperationStore, Options, Phase,
    PublishDecision, Request, RequestError, RequestId, Revisions, SignInScope, Status, Step,
    StopReason, StoreLimits, World,
};

/// Events per ordering.
const DEPTH: usize = 7;
/// One clock tick.
const TICK: u64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Ev {
    Request(usize),
    Changed(usize),
    Approve(usize),
    Cancel(usize),
    End(usize),
    Password(usize),
    Captured(usize),
    Failed(usize),
    Claim(usize),
    Publish(usize),
    Foreign(usize),
    Cleanup(usize),
    Lock,
    RootExit,
    EpochBump,
    RevisionChange,
    RecipientReplaced,
    Tick,
}

fn events() -> Vec<Ev> {
    let mut v = Vec::new();
    for o in 0..2 {
        v.extend([
            Ev::Request(o),
            Ev::Changed(o),
            Ev::Approve(o),
            Ev::Cancel(o),
            Ev::End(o),
            Ev::Password(o),
            Ev::Captured(o),
            Ev::Failed(o),
            Ev::Claim(o),
            Ev::Publish(o),
            Ev::Foreign(o),
            Ev::Cleanup(o),
        ]);
    }
    v.extend([
        Ev::Lock,
        Ev::RootExit,
        Ev::EpochBump,
        Ev::RevisionChange,
        Ev::RecipientReplaced,
        Ev::Tick,
    ]);
    v
}

#[derive(Debug, Clone)]
struct Slot {
    key: &'static str,
    spec: Spec,
}

#[derive(Debug, Clone)]
struct Config {
    name: &'static str,
    slots: [Slot; 2],
    options: Options,
    limits: StoreLimits,
    /// The cleanup result reports a failed close.
    close_fails: bool,
}

/// What the monitor remembers of one operation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Seen {
    slot: usize,
    status: Status,
    /// The digest of the statement the slot was shown when it opened, if
    /// it waited for a proof.
    shown: Option<[u8; 32]>,
    stopped_unpublished: bool,
    passwords: u8,
    injections: u8,
    statement: Deadline,
    attempt: Option<Deadline>,
    session: Option<Deadline>,
    retry_until: Option<SystemTime>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
struct Monitor {
    ops: BTreeMap<RequestId, Seen>,
    /// Remaining credits and deadline last seen, per authorization.
    auths: BTreeMap<AuthorizationId, (u8, u8, Deadline)>,
    /// Attempts started, per authorization.
    started: BTreeMap<AuthorizationId, u8>,
    /// The slot whose statement each authorization approved.
    approved_for: BTreeMap<AuthorizationId, usize>,
    passwords: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Sim {
    store: OperationStore,
    world: TestWorld,
    t: u64,
    draws: u8,
    slots: [Option<RequestId>; 2],
    mon: Monitor,
}

/// Counts of what the detectors judged.
#[derive(Debug, Default)]
struct Reached {
    states: usize,
    steps: usize,
    joins: usize,
    conflicts: usize,
    full: usize,
    approvals: usize,
    /// New operations covered by an authorization approved for the same
    /// slot (a key used again after its retry window), and by one approved
    /// for the other slot.
    covered: usize,
    covered_across: usize,
    published: usize,
    refused_publication: usize,
    stopped_before_publication: usize,
    late_discarded: usize,
    foreign_refused: usize,
    delivered_then_stopped: usize,
    cleanup_failed: usize,
    passwords_refused: usize,
    other_root_own_operation: usize,
    /// Attempts stopped because their authorization ran out under them.
    authorization_ran_out: usize,
}

type Violation = String;

fn now_of(sim: &Sim) -> Now {
    at(sim.t)
}

fn slot_scope(cfg: &Config, o: usize, world: &TestWorld) -> SignInScope {
    scope(&cfg.slots[o].spec, world)
}

fn op(sim: &Sim, o: usize) -> Option<&Operation> {
    sim.slots[o].and_then(|id| sim.store.operation(&id))
}

fn request(cfg: &Config, o: usize, scope: SignInScope) -> Request {
    Request {
        key: OperationKey::parse(cfg.slots[o].key).unwrap(),
        scope,
    }
}

fn fresh(sim: &mut Sim) -> Fresh {
    sim.draws += 1;
    let mut id = [0u8; 16];
    id[0] = 0xa0;
    id[15] = sim.draws;
    Fresh {
        request: RequestId::from_bytes(id),
        nonce: Nonce::from_bytes([sim.draws; 32]),
    }
}

/// Every caller root an operation owned by `owner` must refuse.
fn other_roots(owner: Instance) -> Vec<Instance> {
    [ROOT, OTHER_ROOT, MCP, SIBLING]
        .into_iter()
        .filter(|r| *r != owner)
        .collect()
}

/// Applies `ev`. `None` when it does not apply in this state.
fn step(cfg: &Config, prev: &Sim, ev: Ev, reached: &mut Reached) -> Result<Option<Sim>, Violation> {
    let mut sim = prev.clone();
    let now = now_of(&sim);
    match ev {
        Ev::Request(o) | Ev::Changed(o) => {
            let mut sc = slot_scope(cfg, o, &sim.world);
            let live = op(prev, o).is_some();
            if let Ev::Changed(_) = ev {
                if !live {
                    return Ok(None);
                }
                let mut spec = cfg.slots[o].spec.clone();
                spec.role = "admin";
                sc = scope(&spec, &sim.world);
            }
            let existing = op(prev, o).map(|x| (x.request(), x.scope().clone()));
            let f = fresh(&mut sim);
            let got = sim
                .store
                .lookup_or_reserve(request(cfg, o, sc.clone()), f, &now, &sim.world);
            match (&existing, got) {
                (Some((id, s)), Ok(Lookup::Joined(st))) if *s == sc => {
                    if st.request != *id {
                        return Err(format!("a retry joined {:?}, not {id:?}", st.request));
                    }
                    if sim.store != prev.store {
                        return Err("a joined retry changed the store".into());
                    }
                    reached.joins += 1;
                }
                (Some((_, s)), Err(RequestError::Conflict)) if *s != sc => {
                    if sim.store != prev.store {
                        return Err("a conflicting request changed the store".into());
                    }
                    reached.conflicts += 1;
                }
                (Some(_), other) => {
                    return Err(format!(
                        "the key in use gave {other:?} (same scope: {})",
                        existing.as_ref().is_some_and(|(_, s)| *s == sc)
                    ));
                }
                (None, Ok(Lookup::Reserved(st))) => {
                    if prev.store.operation(&st.request).is_some()
                        || prev.mon.ops.contains_key(&st.request)
                    {
                        return Err("a new operation reused a request id".into());
                    }
                    let mine = prev
                        .store
                        .operations()
                        .filter(|x| x.owner() == sc.owner())
                        .count();
                    if mine >= cfg.limits.per_root
                        || prev.store.operations().count() >= cfg.limits.total
                    {
                        return Err("a full store opened an operation".into());
                    }
                    if (0..2).any(|p| {
                        p != o && op(prev, p).is_some() && cfg.slots[p].key == cfg.slots[o].key
                    }) {
                        reached.other_root_own_operation += 1;
                    }
                    sim.slots[o] = Some(st.request);
                    let shown = sim
                        .store
                        .statement(&st.request, cfg.options, &now, &sim.world)
                        .map(|s| s.digest());
                    let x = sim.store.operation(&st.request).unwrap();
                    if let Some(a) = x.authorization() {
                        if prev.mon.approved_for.get(&a) == Some(&o) {
                            reached.covered += 1;
                        } else {
                            reached.covered_across += 1;
                        }
                    }
                    sim.mon.ops.insert(
                        st.request,
                        Seen {
                            slot: o,
                            status: st,
                            shown,
                            stopped_unpublished: false,
                            passwords: 0,
                            injections: 0,
                            statement: x.statement_deadline(),
                            attempt: None,
                            session: None,
                            retry_until: None,
                        },
                    );
                }
                (None, Err(RequestError::Full)) => {
                    let mine = prev
                        .store
                        .operations()
                        .filter(|x| x.owner() == sc.owner())
                        .count();
                    if mine < cfg.limits.per_root
                        && prev.store.operations().count() < cfg.limits.total
                    {
                        return Err("a store with room refused".into());
                    }
                    if sim.store != prev.store {
                        return Err("a refused request changed the store".into());
                    }
                    reached.full += 1;
                }
                (None, other) => {
                    return Err(format!("a key not in use gave {other:?}"));
                }
            }
        }
        Ev::Approve(o) => {
            let Some(x) = op(prev, o) else {
                return Ok(None);
            };
            let id = x.request();
            let Some(digest) = prev.mon.ops.get(&id).and_then(|s| s.shown) else {
                return Ok(None);
            };
            let waiting = x.stop().is_none() && x.phase() == Phase::PendingApproval;
            match sim
                .store
                .approve(&id, cfg.options, &digest, &now, &sim.world)
            {
                Ok(_) if !waiting => return Err("a proof approved an operation not waiting".into()),
                Ok(_) => {
                    let a = sim.store.operation(&id).and_then(Operation::authorization);
                    sim.mon
                        .approved_for
                        .insert(a.ok_or("approved without an authorization")?, o);
                    reached.approvals += 1;
                }
                Err(_) => {
                    if sim.store != prev.store {
                        return Err("a refused proof changed the store".into());
                    }
                }
            }
        }
        Ev::Cancel(o) | Ev::End(o) => {
            let Some(x) = op(prev, o) else {
                return Ok(None);
            };
            let id = x.request();
            let owner = x.owner();
            let got = if let Ev::Cancel(_) = ev {
                sim.store.cancel(&owner, &id, &now, &sim.world)
            } else {
                sim.store.end(&owner, &id, &now, &sim.world)
            };
            let st = got.map_err(|_| "the owner's cancel was refused".to_string())?;
            if st.retry_until.is_none() {
                return Err("a cancelled operation has no retry_until".into());
            }
            if x.phase().delivered() && x.stop().is_none() {
                reached.delivered_then_stopped += 1;
            }
        }
        Ev::Password(o) => {
            let Some(x) = op(prev, o) else {
                return Ok(None);
            };
            let Some(g) = x.generation() else {
                return Ok(None);
            };
            let id = x.request();
            match sim.store.permit(&id, g, Step::Password, &now, &sim.world) {
                Ok(()) => {
                    let seen = sim.mon.ops.get_mut(&id).unwrap();
                    seen.passwords += 1;
                    sim.mon.passwords += 1;
                    if seen.passwords > 1 {
                        return Err("a second password in one attempt".into());
                    }
                }
                Err(_) => {
                    if sim.store != prev.store {
                        return Err("a refused password step changed the store".into());
                    }
                    reached.passwords_refused += 1;
                }
            }
        }
        Ev::Captured(o) | Ev::Failed(o) => {
            let Some(x) = op(prev, o) else {
                return Ok(None);
            };
            let Some(g) = x.generation() else {
                return Ok(None);
            };
            let id = x.request();
            let running = x.stop().is_none() && x.phase() == Phase::AttemptRunning;
            let got = if let Ev::Captured(_) = ev {
                sim.store.worker_captured(&id, g, &now, &sim.world)
            } else {
                sim.store.worker_failed(
                    &id,
                    g,
                    AttemptFailure::CredentialsRejected,
                    &now,
                    &sim.world,
                )
            };
            match (running, got) {
                (true, Ok(())) => {}
                (false, Err(_)) => {
                    if sim.store != prev.store {
                        return Err("a late worker result changed the store".into());
                    }
                    reached.late_discarded += 1;
                }
                (r, g) => return Err(format!("worker result {g:?} for a running={r} attempt")),
            }
        }
        Ev::Claim(o) => {
            let Some(x) = op(prev, o) else {
                return Ok(None);
            };
            let Some(sup) = x.supervisor() else {
                return Ok(None);
            };
            let id = x.request();
            let ready = x.stop().is_none() && x.phase() == Phase::Captured;
            match sim
                .store
                .inject_state(&Channel::Supervisor(sup), &id, &now, &sim.world)
            {
                Ok(inj) => {
                    if !ready {
                        return Err("state injected into a stopped or uncaptured operation".into());
                    }
                    if Some(inj.generation) != x.generation() || inj.context != x.context() {
                        return Err("state injected for another generation or context".into());
                    }
                    sim.mon.ops.get_mut(&id).unwrap().injections += 1;
                }
                Err(_) => {
                    if sim.store != prev.store {
                        return Err("a refused claim changed the store".into());
                    }
                }
            }
        }
        Ev::Publish(o) => {
            let Some(x) = op(prev, o) else {
                return Ok(None);
            };
            let Some(sup) = x.supervisor() else {
                return Ok(None);
            };
            let id = x.request();
            let from = Channel::Supervisor(sup);
            if x.phase() == Phase::PublishDecided {
                let _ = sim.store.published(&from, &id, &now, &sim.world);
            } else {
                let role = x.scope().account().role.as_str().to_owned();
                let got = sim
                    .store
                    .identity_response(&from, &id, &identity(&role), &now, &sim.world)
                    .map_err(|_| "the generation's supervisor was refused".to_string())?;
                match got {
                    PublishDecision::Publish => {
                        published_independently(prev, x, &now)?;
                        reached.published += 1;
                    }
                    PublishDecision::Refuse(_) => {
                        if sim.store != prev.store {
                            return Err("a refused publication changed the store".into());
                        }
                        reached.refused_publication += 1;
                    }
                }
            }
        }
        Ev::Foreign(o) => {
            let Some(x) = op(prev, o) else {
                return Ok(None);
            };
            foreign(cfg, &mut sim, x, o, &now)?;
            if sim.store != prev.store {
                return Err("a message from another channel or root changed the store".into());
            }
            reached.foreign_refused += 1;
        }
        Ev::Cleanup(o) => {
            let Some(x) = op(prev, o) else {
                return Ok(None);
            };
            let Some(g) = x.generation() else {
                return Ok(None);
            };
            let id = x.request();
            let _ = sim
                .store
                .cleanup_result(&id, g, !cfg.close_fails, &now, &sim.world);
            if cfg.close_fails
                && sim
                    .store
                    .operation(&id)
                    .is_some_and(|y| y.status().receipt.delivered)
            {
                reached.cleanup_failed += 1;
            }
        }
        Ev::Lock => {
            sim.store.lock(&now, &sim.world);
        }
        Ev::RootExit => {
            if !sim.world.exited.insert(ROOT) {
                return Ok(None);
            }
            sim.store.reconcile(&now, &sim.world);
        }
        Ev::EpochBump => {
            sim.world.epochs.vault += 1;
            sim.store.reconcile(&now, &sim.world);
        }
        Ev::RevisionChange => {
            sim.world.login += 1;
            sim.store.reconcile(&now, &sim.world);
        }
        Ev::RecipientReplaced => {
            sim.world.browser += 1;
            sim.store.reconcile(&now, &sim.world);
        }
        Ev::Tick => {
            sim.t += TICK;
            let now = now_of(&sim);
            sim.store.reconcile(&now, &sim.world);
        }
    }
    let effects = sim.store.drain_effects();
    check(prev, &mut sim, ev, &effects, reached)?;
    Ok(Some(sim))
}

/// A publication the store decided, checked against the world by the
/// monitor rather than by the store's own decision.
fn published_independently(prev: &Sim, x: &Operation, now: &Now) -> Result<(), Violation> {
    let w = &prev.world;
    let s = x.scope();
    let seen = &prev.mon.ops[&x.request()];
    let why = if seen.stopped_unpublished {
        "after the operation stopped"
    } else if x.stop().is_some() {
        "for a stopped operation"
    } else if seen.injections == 0 {
        "without state injected by its own supervisor"
    } else if w.epochs != *s.epochs() {
        "under other epochs"
    } else if w.revisions(s) != Revisions::of(s) {
        "after a revision or recipient change"
    } else if !w.alive(&s.owner()) {
        "after the root exited"
    } else if x.attempt_deadline().is_none_or(|d| d.passed(now)) {
        "after the attempt's deadline"
    } else if !x
        .authorization()
        .and_then(|a| prev.store.authorization(&a))
        .is_some_and(|a| !a.ended() && !a.deadline().passed(now) && *a.scope() == *s)
    {
        "without its authorization in force"
    } else {
        return Ok(());
    };
    Err(format!("published {why}"))
}

/// Every message `x` must refuse from a channel that is not its
/// generation's supervisor, worker results of another generation, and
/// status, cancel and end from other roots.
fn foreign(
    cfg: &Config,
    sim: &mut Sim,
    x: &Operation,
    o: usize,
    now: &Now,
) -> Result<(), Violation> {
    let id = x.request();
    let other = 1 - o;
    let other_gen: Option<Generation> = op(sim, other)
        .and_then(Operation::generation)
        .filter(|g| Some(*g) != x.generation());
    let mut channels = vec![
        Channel::Client(cfg.slots[o].spec.requester),
        Channel::Client(SIBLING),
        Channel::Client(OTHER_MCP),
        Channel::Client(x.owner()),
    ];
    if let Some(s) = op(sim, other).and_then(Operation::supervisor) {
        if Some(s.generation()) != x.generation() {
            channels.push(Channel::Supervisor(s));
        }
    }
    let role = x.scope().account().role.as_str().to_owned();
    for from in &channels {
        if sim.store.inject_state(from, &id, now, &sim.world).is_ok() {
            return Err(format!("declared state given to {from:?}"));
        }
        if let Ok(PublishDecision::Publish) =
            sim.store
                .identity_response(from, &id, &identity(&role), now, &sim.world)
        {
            return Err(format!("published for {from:?}"));
        }
        if sim.store.published(from, &id, now, &sim.world).is_ok() {
            return Err(format!("publication acknowledged from {from:?}"));
        }
        if sim.store.check(from, &id, now, &sim.world).is_ok() {
            return Err(format!("a tool call checked for {from:?}"));
        }
    }
    if let Some(g) = other_gen {
        let late = [
            sim.store.worker_captured(&id, g, now, &sim.world).is_ok(),
            sim.store
                .worker_failed(&id, g, AttemptFailure::WorkerLost, now, &sim.world)
                .is_ok(),
            sim.store
                .permit(&id, g, Step::Password, now, &sim.world)
                .is_ok(),
            sim.store
                .cleanup_result(&id, g, true, now, &sim.world)
                .is_ok(),
        ];
        if late.iter().any(|ok| *ok) {
            return Err("a result of another generation was taken".into());
        }
    }
    let unknown = RequestId::from_bytes([0xee; 16]);
    for caller in other_roots(x.owner()) {
        let answers = [
            sim.store.status(&caller, &id, now, &sim.world).err(),
            sim.store.cancel(&caller, &id, now, &sim.world).err(),
            sim.store.end(&caller, &id, now, &sim.world).err(),
        ];
        let baseline = sim.store.status(&caller, &unknown, now, &sim.world).err();
        if baseline != Some(NotFound) || answers.iter().any(|a| *a != baseline) {
            return Err(format!("another root's call answered {answers:?}"));
        }
    }
    Ok(())
}

/// The invariants that hold after every event.
fn check(
    prev: &Sim,
    sim: &mut Sim,
    ev: Ev,
    effects: &[Effect],
    reached: &mut Reached,
) -> Result<(), Violation> {
    let now = now_of(sim);
    // No eviction: an operation goes only once its retry window passed
    // and its cleanup is not pending (or was just reported).
    for x in prev.store.operations() {
        let reported = prev
            .mon
            .ops
            .get(&x.request())
            .is_some_and(|s| ev == Ev::Cleanup(s.slot));
        let may_go = x.stop().is_some_and(|s| s.retry_until.passed(&now))
            && (x.cleanup() != envcloak_signin::Cleanup::Pending || reported);
        if !may_go && sim.store.operation(&x.request()).is_none() {
            return Err(format!(
                "{:?} disappeared before its retry_until",
                x.request()
            ));
        }
    }
    // One operation per slot.
    for o in 0..2 {
        let n = sim
            .store
            .operations()
            .filter(|x| sim.mon.ops.get(&x.request()).is_some_and(|s| s.slot == o))
            .count();
        if n > 1 {
            return Err(format!("slot {o} has {n} operations"));
        }
    }
    // Attempts started only for live operations, within credits.
    for e in effects {
        if let Effect::StartAttempt { request, lease, .. } = e {
            if sim
                .store
                .operation(request)
                .is_none_or(|x| x.stop().is_some())
            {
                return Err("an attempt started for a stopped operation".into());
            }
            *sim.mon.started.entry(lease.authorization()).or_default() += 1;
        }
    }
    let mut started_total: u32 = 0;
    for (a, n) in &sim.mon.started {
        started_total += u32::from(*n);
        let (credits, _, _) = sim
            .store
            .authorization(a)
            .map(|x| (x.credits(), x.remaining(), x.deadline()))
            .or_else(|| sim.mon.auths.get(a).copied())
            .ok_or("an attempt under an unknown authorization")?;
        if *n > credits {
            return Err(format!("{n} attempts under {credits} credits"));
        }
    }
    if sim.mon.passwords > started_total {
        return Err("more passwords than attempts".into());
    }
    // Budgets never grow; deadlines never move later.
    for a in sim.store.authorizations() {
        let seen = (a.credits(), a.remaining(), a.deadline());
        if let Some((credits, remaining, deadline)) = sim.mon.auths.get(&a.id()) {
            if seen.0 != *credits || seen.1 > *remaining {
                return Err(format!("{:?}'s budget grew", a.id()));
            }
            if !seen.2.not_later_than(deadline) {
                return Err(format!("{:?}'s deadline moved later", a.id()));
            }
        }
        if let Some(n) = sim.mon.started.get(&a.id()) {
            if *n > a.credits() - a.remaining() {
                return Err("more attempts than credits reserved".into());
            }
        }
        sim.mon.auths.insert(a.id(), seen);
    }
    for x in sim.store.operations() {
        let id = x.request();
        let Some(seen) = sim.mon.ops.get_mut(&id) else {
            return Err("an operation the monitor never saw opened".into());
        };
        let later = |old: Option<Deadline>, new: Option<Deadline>| match (old, new) {
            (Some(o), Some(n)) => !n.not_later_than(&o),
            (Some(_), None) => true,
            _ => false,
        };
        if later(Some(seen.statement), Some(x.statement_deadline()))
            || later(seen.attempt, x.attempt_deadline())
            || later(seen.session, x.session_deadline())
        {
            return Err(format!("{id:?}: a deadline moved later"));
        }
        let retry = x.stop().map(|s| s.retry_until.wall());
        if seen.retry_until.is_some() && retry != seen.retry_until {
            return Err(format!("{id:?}: retry_until moved"));
        }
        seen.statement = x.statement_deadline();
        seen.attempt = x.attempt_deadline();
        seen.session = x.session_deadline();
        seen.retry_until = retry;
        // Nothing published after a stop.
        if seen.stopped_unpublished && x.phase().delivered() {
            return Err(format!("{id:?} was published after it stopped"));
        }
        if x.stop()
            .is_some_and(|s| s.reason == StopReason::AuthorizationEnded)
            && seen.status.receipt.reason.is_none()
            && matches!(x.phase(), Phase::AttemptRunning | Phase::Captured)
        {
            reached.authorization_ran_out += 1;
        }
        if x.stop().is_some() && !x.phase().delivered() {
            if !seen.stopped_unpublished && x.phase() == Phase::Captured {
                reached.stopped_before_publication += 1;
            }
            seen.stopped_unpublished = true;
        }
        // Status revisions.
        let st = x.status();
        if st.revision < seen.status.revision {
            return Err(format!("{id:?}: status revision went back"));
        }
        let mut same = st;
        same.revision = seen.status.revision;
        if same != seen.status && st.revision == seen.status.revision {
            return Err(format!("{id:?}: status changed without a new revision"));
        }
        seen.status = st;
        if x.passwords() > 1 || x.codes() > 2 {
            return Err(format!("{id:?}: over its submissions"));
        }
    }
    Ok(())
}

fn digest(sim: &Sim) -> u128 {
    let mut a = DefaultHasher::new();
    sim.hash(&mut a);
    let mut b = DefaultHasher::new();
    0x5eed_u32.hash(&mut b);
    sim.hash(&mut b);
    (u128::from(a.finish()) << 64) | u128::from(b.finish())
}

fn explore(cfg: &Config, depth: usize) -> Reached {
    let start = Sim {
        store: OperationStore::with_limits(common::DAEMON, cfg.limits),
        world: TestWorld::new(),
        t: 0,
        draws: 0,
        slots: [None, None],
        mon: Monitor::default(),
    };
    let events = events();
    let mut visited: HashMap<u128, usize> = HashMap::new();
    let mut reached = Reached::default();
    let mut trace = Vec::new();
    dfs(
        cfg,
        &events,
        &start,
        depth,
        &mut visited,
        &mut trace,
        &mut reached,
    );
    reached.states = visited.len();
    reached
}

fn dfs(
    cfg: &Config,
    events: &[Ev],
    sim: &Sim,
    left: usize,
    visited: &mut HashMap<u128, usize>,
    trace: &mut Vec<Ev>,
    reached: &mut Reached,
) {
    if left == 0 {
        return;
    }
    for ev in events {
        let next = match step(cfg, sim, *ev, reached) {
            Ok(Some(next)) => next,
            Ok(None) => continue,
            Err(v) => panic!("{}: {v}\n  after {trace:?}\n  then {ev:?}", cfg.name),
        };
        reached.steps += 1;
        let h = digest(&next);
        if visited.get(&h).is_some_and(|d| *d >= left - 1) {
            continue;
        }
        visited.insert(h, left - 1);
        trace.push(*ev);
        dfs(cfg, events, &next, left - 1, visited, trace, reached);
        trace.pop();
    }
}

fn slot(key: &'static str, root: Instance, requester: Instance, role: &'static str) -> Slot {
    Slot {
        key,
        spec: Spec {
            root,
            requester,
            role,
            approval: Duration::from_secs(4 * TICK),
            attempt_timeout: Duration::from_secs(3 * TICK),
            session_lifetime: Duration::from_secs(2 * TICK),
            ..Spec::dev()
        },
    }
}

/// `dev` options whose window (2 ticks) ends before an attempt started
/// with it times out (3 ticks), so an authorization can run out under a
/// running attempt within the depth.
fn dev(attempts: u8) -> Options {
    Options::Dev {
        window: Duration::from_secs(2 * TICK),
        attempts,
    }
}

fn run(cfg: Config) -> Reached {
    let r = explore(&cfg, DEPTH);
    eprintln!("{}: {r:?}", cfg.name);
    assert!(r.published > 0, "{}: no publication reached", cfg.name);
    assert!(
        r.stopped_before_publication > 0,
        "{}: no stop between capture and publication",
        cfg.name
    );
    assert!(
        r.late_discarded > 0 && r.foreign_refused > 0,
        "{}",
        cfg.name
    );
    assert!(r.joins > 0 && r.conflicts > 0, "{}", cfg.name);
    assert!(r.delivered_then_stopped > 0, "{}", cfg.name);
    r
}

/// Two keys, one scope, a `dev` budget of two: the second key is covered
/// by the first approval's authorization while it has a credit.
#[test]
fn new_keys_share_a_dev_budget_without_growing_it() {
    let r = run(Config {
        name: "dev budget 2",
        slots: [
            slot("a", ROOT, MCP, "editor"),
            slot("b", ROOT, MCP, "editor"),
        ],
        options: dev(2),
        limits: StoreLimits::default(),
        close_fails: false,
    });
    assert!(r.covered_across > 0);
    assert!(r.authorization_ran_out > 0);
}

/// A budget of one: the second key asks for a proof; a failed close after
/// publication stays visible.
#[test]
fn a_spent_dev_budget_covers_nothing_and_a_failed_close_is_reported() {
    let r = run(Config {
        name: "dev budget 1",
        slots: [
            slot("a", ROOT, MCP, "editor"),
            slot("b", ROOT, MCP, "editor"),
        ],
        options: dev(1),
        limits: StoreLimits::default(),
        close_fails: true,
    });
    assert_eq!(r.covered_across, 0);
    assert!(r.cleanup_failed > 0);
    assert!(r.authorization_ran_out > 0);
}

/// `once`: each operation needs its own proof and gets one attempt.
#[test]
fn once_requests_yield_at_most_one_attempt_each() {
    let r = run(Config {
        name: "once",
        slots: [
            slot("a", ROOT, MCP, "editor"),
            slot("b", ROOT, MCP, "editor"),
        ],
        options: Options::Once,
        limits: StoreLimits::default(),
        close_fails: false,
    });
    assert_eq!(r.covered_across, 0);
    assert!(r.passwords_refused > 0);
}

/// A sibling `envcloak mcp` in the same root is another recipient: its
/// own scope, never the first instance's authorization or state.
#[test]
fn a_sibling_instance_is_another_recipient() {
    let r = run(Config {
        name: "sibling recipient",
        slots: [
            slot("a", ROOT, MCP, "editor"),
            slot("b", ROOT, SIBLING, "editor"),
        ],
        options: dev(2),
        limits: StoreLimits::default(),
        close_fails: false,
    });
    assert_eq!(r.covered_across, 0);
}

/// Another role under a new key never uses the first role's
/// authorization.
#[test]
fn another_role_never_uses_an_earlier_authorization() {
    let r = run(Config {
        name: "other role",
        slots: [
            slot("a", ROOT, MCP, "editor"),
            slot("b", ROOT, MCP, "admin"),
        ],
        options: dev(2),
        limits: StoreLimits::default(),
        close_fails: false,
    });
    assert_eq!(r.covered_across, 0);
}

/// The same key in another root is that root's own operation.
#[test]
fn the_same_key_in_another_root_is_another_operation() {
    let r = run(Config {
        name: "other root",
        slots: [
            slot("a", ROOT, MCP, "editor"),
            slot("a", OTHER_ROOT, OTHER_MCP, "editor"),
        ],
        options: dev(2),
        limits: StoreLimits::default(),
        close_fails: false,
    });
    assert!(r.other_root_own_operation > 0);
    assert_eq!(r.covered_across, 0);
}

/// A store with room for one operation refuses the second while the first
/// is remembered, and never evicts it.
#[test]
fn a_full_store_refuses_rather_than_evicting() {
    let r = run(Config {
        name: "full store",
        slots: [
            slot("a", ROOT, MCP, "editor"),
            slot("b", ROOT, MCP, "editor"),
        ],
        options: dev(2),
        limits: StoreLimits {
            per_root: 1,
            total: 1,
            authorizations: 1,
        },
        close_fails: false,
    });
    assert!(r.full > 0);
}
