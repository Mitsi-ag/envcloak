//! The sign-in contract under every ordering of its events (plan M2b-01,
//! gates b7, b8, b9, b14 and b17 at the model level; K-05).
//!
//! Each configuration below is two operations (slots A and B, each a key,
//! a root, a requesting instance and a role) and the options an approval
//! chooses. A depth-first search applies every sequence of up to [`DEPTH`]
//! events from two starting states, an empty store and one where slot A's
//! session was already delivered, drawn from: a request with the slot's
//! key and scope, the same key with the role changed, an approval of the
//! statement the slot was shown, cancel and end from the owner, the
//! driver's password and one-time-code steps, the worker's captured and
//! failed results with the attempt's generation, the supervisor's claim
//! and its next message (the identity response, the publication, or a
//! per-call check on a delivered session) on the generation's channel,
//! the same messages and worker results from every other channel (another
//! generation's supervisor, the requesting client, a sibling `envcloak
//! mcp` in the same root, another root's client) with status, cancel and
//! end from another root, the cleanup result (a configuration where a
//! close fails reports a failure first and a success after it), lock, and
//! the world's own changes: root exit, an epoch bump, a revision change, a
//! replaced recipient and a clock tick. Those last five are silent: they
//! change the world or the clock and nothing calls the store, so the next
//! call (a worker result, a supervisor message, a driver step) is the
//! first to see them, as at the daemon's barriers (b9, b17). Two states
//! that are equal (the store, the world, the clock and the monitor's
//! history) have the same futures, so a state already explored with at
//! least as many events left is not explored again: every ordering is
//! covered, each distinct state once.
//!
//! Every call is judged against the previous store brought up to date at
//! that call's clock and world (`base`): what the call may do is what
//! that store allows, exactly, and a call that is refused leaves the store
//! as `base` is. After every event the monitor checks, from outside the
//! store:
//! - from its own record of times, locks, owners' stops and the world,
//!   that nothing goes on that must have stopped (the store brought up to
//!   date is checked after every event, the silent ones included): a
//!   cancel, end or lock, a root exit, an epoch, revision or recipient
//!   change, a statement's expiry, the authorization's end or window (a
//!   delivered session included), the attempt's timeout, the session's
//!   lifetime;
//! - declared state, the decision, publication and the per-call check go
//!   only to the generation's supervisor, and every other channel's
//!   message changes nothing;
//! - a password or code step is permitted only for an attempt running at
//!   that call: one password and two codes per attempt, no more attempts
//!   than credits approved, a `once` authorization at most one attempt;
//! - two attempts on one login never overlap: an attempt holds its login
//!   from its start until it captured or its teardown was confirmed (a
//!   failed close is not a confirmation);
//! - nothing is published or injected after a stop, and each authorization
//!   ends at its window measured from its approval, never later, whatever
//!   retries, polls and new keys do; no deadline or `retry_until` moves;
//!   remaining credits never grow;
//! - no new key is covered by an authorization that a lock, its window or
//!   the world ended;
//! - the same key and scope give the same operation and change nothing; a
//!   changed field gives `request_conflict` and changes nothing; another
//!   root's key is never this root's;
//! - the owner's cancel and end before delivery read `cancelled`, after it
//!   `ended`;
//! - status revisions only increase, and increase whenever the status
//!   changed;
//! - a full store refuses, and no operation disappears before its
//!   `retry_until` or while its teardown is unconfirmed;
//! - status, cancel and end from another root answer exactly as for an id
//!   that never existed.
//!
//! Each configuration also counts the cases its detectors judged
//! (publications, refusals at a barrier, conflicts, joins, discarded
//! results, checks), and the test requires them reached, so no invariant
//! holds only because its case never occurred.
#![allow(clippy::unwrap_used)]

mod common;

use std::collections::{BTreeMap, HashMap};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::time::{Duration, SystemTime};

use common::{
    MCP, OTHER_MCP, OTHER_ROOT, ROOT, SIBLING, Spec, TestWorld, Vary, at, scope, variations, varied,
};
use envcloak_core::vault::ItemId;
use envcloak_policy::Now;
use envcloak_signin::store::STATEMENT_TTL;
use envcloak_signin::{
    ApproveError, AttemptFailure, AuthorizationId, Channel, Cleanup, Deadline, Effect, Fresh,
    Generation, IdentityResponse, Instance, Lookup, Nonce, NotFound, Operation, OperationKey,
    OperationStore, Options, Phase, PublishDecision, RETRY_WINDOW, Request, RequestError,
    RequestId, Revisions, SignInScope, State, Status, Step, StopReason, StoreLimits, World,
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
    Code(usize),
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
            Ev::Code(o),
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

/// Slot A's operation delivered: the second starting state.
const DELIVERED: [Ev; 6] = [
    Ev::Request(0),
    Ev::Approve(0),
    Ev::Captured(0),
    Ev::Claim(0),
    Ev::Publish(0),
    Ev::Publish(0),
];

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
    /// A cleanup result reports a failed close first, then a confirmed one.
    close_fails: bool,
}

impl Config {
    /// How long an authorization the options open for `scope` lasts, in
    /// seconds: the `dev` window, or for `once` the scope's approval
    /// duration.
    fn window(&self, scope: &SignInScope) -> u64 {
        match self.options {
            Options::Dev { window, .. } => window.as_secs(),
            Options::Once => scope.limits().approval().as_secs(),
        }
    }

    fn credits(&self) -> u8 {
        match self.options {
            Options::Dev { attempts, .. } => attempts,
            Options::Once => 1,
        }
    }
}

/// What the monitor remembers of one operation, from the events it saw.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Seen {
    slot: usize,
    login: ItemId,
    status: Status,
    /// The digest of the statement the slot was shown when it opened, if
    /// it waited for a proof.
    shown: Option<[u8; 32]>,
    /// When it opened, when its attempt started, when publication was
    /// decided, when the monitor first saw it stopped.
    opened: u64,
    started: Option<u64>,
    decided: Option<u64>,
    stopped: Option<u64>,
    /// The owner cancelled or ended it; a lock came after it opened.
    by_owner: bool,
    locked: bool,
    stopped_unpublished: bool,
    passwords: u8,
    codes: u8,
    injections: u8,
    /// Its attempt may still use the login: started, and neither
    /// captured nor confirmed torn down.
    holds_login: bool,
    teardown_asked: bool,
    teardown_confirmed: bool,
    /// A close was reported failed.
    close_failed: bool,
    statement: Deadline,
    attempt: Option<Deadline>,
    session: Option<Deadline>,
    retry_until: Option<SystemTime>,
}

/// What the monitor remembers of one authorization.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AuthSeen {
    /// The slot whose statement it approved, and its scope.
    slot: usize,
    scope: SignInScope,
    approved: u64,
    window: u64,
    credits: u8,
    /// A lock came after its approval.
    locked: bool,
    /// Attempts started under it.
    started: u8,
    /// Remaining credits and deadline the store last showed.
    remaining: u8,
    deadline: Deadline,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
struct Monitor {
    ops: BTreeMap<RequestId, Seen>,
    auths: BTreeMap<AuthorizationId, AuthSeen>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Sim {
    store: OperationStore,
    world: TestWorld,
    t: u64,
    slots: [Option<RequestId>; 2],
    mon: Monitor,
}

/// A state and its store brought up to date at its clock and world, with
/// the effects that took (not hashed: it follows from the state).
struct Node {
    sim: Sim,
    base: OperationStore,
    base_effects: Vec<Effect>,
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
    /// New operations of one slot opened while an authorization approved
    /// for the other slot was in force with a credit left: the moments a
    /// cover across slots is possible.
    coverable_across: usize,
    /// A new key not covered because a lock ended the authorization that
    /// would have covered it.
    not_covered_after_lock: usize,
    published: usize,
    refused_publication: usize,
    stopped_before_publication: usize,
    late_discarded: usize,
    foreign_refused: usize,
    delivered_then_stopped: usize,
    cleanup_failed: usize,
    confirmed_after_failure: usize,
    /// An attempt kept waiting while another on its login had a failed
    /// close.
    held_by_failed_close: usize,
    passwords_refused: usize,
    codes: usize,
    other_root_own_operation: usize,
    /// Attempts stopped because their authorization ran out under them,
    /// and delivered sessions stopped so.
    authorization_ran_out: usize,
    session_authorization_ended: usize,
    checks: usize,
    /// Calls refused because a silent change, seen first by that call,
    /// had stopped the operation.
    refused_at_barrier: usize,
}

type Violation = String;

fn now_of(sim: &Sim) -> Now {
    at(sim.t)
}

fn slot_scope(cfg: &Config, o: usize, world: &TestWorld) -> SignInScope {
    scope(&cfg.slots[o].spec, world)
}

fn request(cfg: &Config, o: usize, scope: SignInScope) -> Request {
    Request {
        key: OperationKey::parse(cfg.slots[o].key).unwrap(),
        scope,
    }
}

/// The request id and nonce for a request: numbered by the operations
/// opened so far, so a retry or a conflict draws nothing that stays.
fn fresh(sim: &Sim) -> Fresh {
    let n = u8::try_from(sim.mon.ops.len() + 1).unwrap();
    let mut id = [0u8; 16];
    id[0] = 0xa0;
    id[15] = n;
    Fresh {
        request: RequestId::from_bytes(id),
        nonce: Nonce::from_bytes([n; 32]),
    }
}

/// Every caller root an operation owned by `owner` must refuse.
fn other_roots(owner: Instance) -> Vec<Instance> {
    [ROOT, OTHER_ROOT, MCP, SIBLING]
        .into_iter()
        .filter(|r| *r != owner)
        .collect()
}

/// `store` brought up to date at `now` in `world`, and what that took.
fn settled(store: &OperationStore, now: &Now, world: &TestWorld) -> (OperationStore, Vec<Effect>) {
    let mut s = store.clone();
    s.reconcile(now, world);
    let effects = s.drain_effects();
    (s, effects)
}

/// A refused call leaves the store as the store brought up to date.
fn unchanged(node: &Node, sim: &mut Sim, what: &str) -> Result<(), Violation> {
    let effects = sim.store.drain_effects();
    if sim.store != node.base || effects != node.base_effects {
        return Err(format!("{what} changed the store"));
    }
    Ok(())
}

/// Why `x` must have stopped by `t` in `world`, from the monitor's own
/// record: `None` if it may go on.
fn must_stop(x: &Operation, mon: &Monitor, world: &TestWorld, t: u64) -> Option<&'static str> {
    let seen = mon.ops.get(&x.request())?;
    let s = x.scope();
    let limits = s.limits();
    if seen.by_owner {
        return Some("after the owner's cancel or end");
    }
    if seen.locked {
        return Some("after a lock");
    }
    if !world.alive(&s.owner()) {
        return Some("after its root exited");
    }
    if world.epochs != *s.epochs() {
        return Some("after an epoch change");
    }
    let (now, pinned) = (world.revisions(s), Revisions::of(s));
    if (now.login, now.target, now.adapter) != (pinned.login, pinned.target, pinned.adapter) {
        return Some("after a revision change");
    }
    if now.browser != pinned.browser || !now.requester_alive {
        return Some("after its recipient was replaced");
    }
    if matches!(x.phase(), Phase::Requested | Phase::PendingApproval) {
        return (t >= seen.opened + STATEMENT_TTL.as_secs())
            .then_some("after its statement expired");
    }
    let Some(a) = x.authorization().and_then(|a| mon.auths.get(&a)) else {
        return Some("past approval with no authorization the monitor saw approved");
    };
    if a.locked {
        return Some("after a lock ended its authorization");
    }
    if t >= a.approved + a.window {
        return Some("after its authorization's window");
    }
    match x.phase() {
        Phase::AttemptRunning | Phase::Captured => seen
            .started
            .is_some_and(|st| t >= st + limits.attempt_timeout().as_secs())
            .then_some("after its attempt timed out"),
        Phase::PublishDecided | Phase::Published => seen
            .decided
            .is_some_and(|d| t >= d + limits.session_lifetime().as_secs())
            .then_some("after its session's lifetime"),
        _ => None,
    }
}

/// Applies `ev`. `None` when it does not apply in this state.
fn step(
    cfg: &Config,
    node: &Node,
    ev: Ev,
    reached: &mut Reached,
) -> Result<Option<Node>, Violation> {
    let prev = &node.sim;
    let base = &node.base;
    let mut sim = prev.clone();
    let now = now_of(&sim);
    // The operation of slot `o`: as the caller last knew it, and as the
    // store brought up to date has it.
    let known = |o: usize| prev.slots[o].and_then(|id| prev.store.operation(&id));
    let current = |o: usize| prev.slots[o].and_then(|id| base.operation(&id));
    let mut store_call = true;
    match ev {
        Ev::Request(o) | Ev::Changed(o) => {
            let existing = current(o).map(|x| (x.request(), x.scope().clone()));
            let mut sc = slot_scope(cfg, o, &sim.world);
            if let Ev::Changed(_) = ev {
                if existing.is_none() {
                    return Ok(None);
                }
                let mut spec = cfg.slots[o].spec.clone();
                spec.role = "admin";
                sc = scope(&spec, &sim.world);
            }
            let f = fresh(&sim);
            let got = sim
                .store
                .lookup_or_reserve(request(cfg, o, sc.clone()), f, &now, &sim.world);
            match (&existing, got) {
                (Some((id, s)), Ok(Lookup::Joined(st))) if *s == sc => {
                    if st.request != *id {
                        return Err(format!("a retry joined {:?}, not {id:?}", st.request));
                    }
                    unchanged(node, &mut sim, "a joined retry")?;
                    reached.joins += 1;
                }
                (Some((_, s)), Err(RequestError::Conflict)) if *s != sc => {
                    unchanged(node, &mut sim, "a conflicting request")?;
                    reached.conflicts += 1;
                }
                (Some(_), other) => {
                    return Err(format!(
                        "the key in use gave {other:?} (same scope: {})",
                        existing.as_ref().is_some_and(|(_, s)| *s == sc)
                    ));
                }
                (None, Ok(Lookup::Reserved(st))) => {
                    reserved(cfg, node, &mut sim, o, &sc, st, reached)?;
                }
                (None, Err(RequestError::Full)) => {
                    let mine = base
                        .operations()
                        .filter(|x| x.owner() == sc.owner())
                        .count();
                    if mine < cfg.limits.per_root && base.operations().count() < cfg.limits.total {
                        return Err("a store with room refused".into());
                    }
                    unchanged(node, &mut sim, "a refused request")?;
                    reached.full += 1;
                }
                (None, other) => return Err(format!("a key not in use gave {other:?}")),
            }
        }
        Ev::Approve(o) => {
            let Some(id) = prev.slots[o] else {
                return Ok(None);
            };
            let Some(digest) = prev.mon.ops.get(&id).and_then(|s| s.shown) else {
                return Ok(None);
            };
            let waiting = current(o)
                .is_some_and(|x| x.stop().is_none() && x.phase() == Phase::PendingApproval);
            match sim
                .store
                .approve(&id, cfg.options, &digest, &now, &sim.world)
            {
                Ok(_) if !waiting => return Err("a proof approved an operation not waiting".into()),
                Ok(_) => {
                    let x = sim.store.operation(&id).unwrap();
                    let window = cfg.window(x.scope());
                    let a = x
                        .authorization()
                        .ok_or("approved without an authorization")?;
                    if prev.mon.auths.contains_key(&a) {
                        return Err("an approval reused an authorization".into());
                    }
                    sim.mon.auths.insert(
                        a,
                        AuthSeen {
                            slot: o,
                            scope: x.scope().clone(),
                            approved: sim.t,
                            window,
                            credits: cfg.credits(),
                            locked: false,
                            started: 0,
                            remaining: cfg.credits(),
                            deadline: Deadline::after(&now, Duration::from_secs(window)),
                        },
                    );
                    reached.approvals += 1;
                }
                Err(e) => {
                    if waiting
                        && !(e == ApproveError::Full
                            && base.authorizations().count() >= cfg.limits.authorizations)
                    {
                        return Err(format!("a waiting operation's proof was refused: {e:?}"));
                    }
                    unchanged(node, &mut sim, "a refused proof")?;
                }
            }
        }
        Ev::Cancel(o) | Ev::End(o) => {
            let Some(id) = prev.slots[o] else {
                return Ok(None);
            };
            let owner = slot_scope(cfg, o, &prev.world).owner();
            let got = if let Ev::Cancel(_) = ev {
                sim.store.cancel(&owner, &id, &now, &sim.world)
            } else {
                sim.store.end(&owner, &id, &now, &sim.world)
            };
            match (current(o), got) {
                (None, Err(NotFound)) => {
                    unchanged(node, &mut sim, "a cancel of a forgotten operation")?
                }
                (Some(x), Ok(st)) if x.stop().is_some() => {
                    if st != x.status() {
                        return Err("a second cancel changed the status".into());
                    }
                    unchanged(node, &mut sim, "a second cancel")?;
                }
                (Some(x), Ok(st)) => {
                    let (reason, state) = match (ev, x.phase().delivered()) {
                        (Ev::Cancel(_), false) => (StopReason::Cancelled, State::Cancelled),
                        (_, false) => (StopReason::EndedByOwner, State::Cancelled),
                        (Ev::Cancel(_), true) => (StopReason::Cancelled, State::Ended),
                        (_, true) => (StopReason::EndedByOwner, State::Ended),
                    };
                    if (st.state, st.receipt.reason) != (state, Some(reason))
                        || st.retry_until.is_none()
                        || st.receipt.delivered != x.phase().delivered()
                    {
                        return Err(format!("the owner's stop read {st:?}"));
                    }
                    if x.phase().delivered() {
                        reached.delivered_then_stopped += 1;
                    }
                    sim.mon.ops.get_mut(&id).unwrap().by_owner = true;
                }
                (x, got) => return Err(format!("the owner's cancel gave {got:?} for {x:?}")),
            }
        }
        Ev::Password(o) | Ev::Code(o) => {
            let Some((id, g)) = known(o).and_then(|x| Some((x.request(), x.generation()?))) else {
                return Ok(None);
            };
            let (kind, done, max) = match ev {
                Ev::Password(_) => (Step::Password, prev.mon.ops[&id].passwords, 1),
                _ => (Step::Code, prev.mon.ops[&id].codes, 2),
            };
            let running = current(o).is_some_and(|x| {
                x.stop().is_none()
                    && x.phase() == Phase::AttemptRunning
                    && x.generation() == Some(g)
            });
            let got = sim.store.permit(&id, g, kind, &now, &sim.world);
            match (running && done < max, got) {
                (true, Ok(())) => {
                    let seen = sim.mon.ops.get_mut(&id).unwrap();
                    if kind == Step::Password {
                        seen.passwords += 1;
                    } else {
                        seen.codes += 1;
                        reached.codes += 1;
                    }
                }
                (false, Err(_)) => {
                    unchanged(node, &mut sim, "a refused credential step")?;
                    reached.passwords_refused += usize::from(kind == Step::Password);
                    if known(o).is_some_and(|x| x.stop().is_none()) && !running {
                        reached.refused_at_barrier += 1;
                    }
                }
                (true, got) => return Err(format!("a running attempt's step gave {got:?}")),
                (false, Ok(())) => {
                    return Err(format!(
                        "a {kind:?} step permitted for an attempt not running at that call"
                    ));
                }
            }
        }
        Ev::Captured(o) | Ev::Failed(o) => {
            let Some((id, g)) = known(o).and_then(|x| Some((x.request(), x.generation()?))) else {
                return Ok(None);
            };
            let running = current(o).is_some_and(|x| {
                x.stop().is_none()
                    && x.phase() == Phase::AttemptRunning
                    && x.generation() == Some(g)
            });
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
                (true, Ok(())) => {
                    if let Ev::Captured(_) = ev {
                        sim.mon.ops.get_mut(&id).unwrap().holds_login = false;
                    }
                }
                (false, Err(_)) => {
                    unchanged(node, &mut sim, "a late worker result")?;
                    reached.late_discarded += 1;
                    if known(o).is_some_and(|x| x.stop().is_none()) {
                        reached.refused_at_barrier += 1;
                    }
                }
                (r, g) => return Err(format!("worker result {g:?} for a running={r} attempt")),
            }
        }
        Ev::Claim(o) => {
            let Some((id, sup)) = known(o).and_then(|x| Some((x.request(), x.supervisor()?)))
            else {
                return Ok(None);
            };
            let ready = current(o).is_some_and(|x| {
                x.stop().is_none()
                    && x.phase() == Phase::Captured
                    && x.generation() == Some(sup.generation())
                    && prev.mon.ops[&id].injections == 0
            });
            match sim
                .store
                .inject_state(&Channel::Supervisor(sup), &id, &now, &sim.world)
            {
                Ok(inj) => {
                    if !ready {
                        return Err(
                            "state injected into an operation not ready at that call".into()
                        );
                    }
                    let x = current(o).unwrap();
                    if Some(inj.generation) != x.generation() || inj.context != x.context() {
                        return Err("state injected for another generation or context".into());
                    }
                    sim.mon.ops.get_mut(&id).unwrap().injections += 1;
                }
                Err(_) if ready => return Err("the ready generation's claim was refused".into()),
                Err(_) => {
                    unchanged(node, &mut sim, "a refused claim")?;
                    if known(o).is_some_and(|x| x.stop().is_none() && x.phase() == Phase::Captured)
                        && current(o).is_some_and(|x| x.stop().is_some())
                    {
                        reached.refused_at_barrier += 1;
                    }
                }
            }
        }
        Ev::Publish(o) => {
            let Some(x) = known(o).filter(|x| {
                matches!(
                    x.phase(),
                    Phase::Captured | Phase::PublishDecided | Phase::Published
                )
            }) else {
                return Ok(None);
            };
            let Some(sup) = x.supervisor() else {
                return Ok(None);
            };
            supervisor_message(node, &mut sim, x, sup, &now, reached)?;
        }
        Ev::Foreign(o) => {
            let Some(x) = known(o) else {
                return Ok(None);
            };
            foreign(&mut sim, x, o, &now)?;
            unchanged(node, &mut sim, "a message from another channel or root")?;
            reached.foreign_refused += 1;
        }
        Ev::Cleanup(o) => {
            let Some((id, g)) = known(o).and_then(|x| Some((x.request(), x.generation()?))) else {
                return Ok(None);
            };
            let closed = !cfg.close_fails || prev.mon.ops[&id].close_failed;
            let takes = current(o).is_some_and(|x| {
                x.generation() == Some(g)
                    && (x.cleanup() == Cleanup::Pending
                        || (x.cleanup() == Cleanup::Failed && closed))
            });
            let waiting =
                current(1 - o).is_some_and(|y| y.stop().is_none() && y.phase() == Phase::Approved);
            match (
                takes,
                sim.store.cleanup_result(&id, g, closed, &now, &sim.world),
            ) {
                (true, Ok(())) => {
                    let seen = sim.mon.ops.get_mut(&id).unwrap();
                    if closed {
                        if seen.close_failed {
                            reached.confirmed_after_failure += 1;
                        }
                        seen.teardown_confirmed = true;
                        seen.holds_login = false;
                    } else {
                        seen.close_failed = true;
                        if seen.status.receipt.delivered {
                            reached.cleanup_failed += 1;
                        }
                        if waiting {
                            reached.held_by_failed_close += 1;
                        }
                    }
                }
                (false, Err(_)) => unchanged(node, &mut sim, "a discarded cleanup result")?,
                (t, got) => return Err(format!("cleanup result {got:?} where taken={t}")),
            }
        }
        Ev::Lock => {
            sim.store.lock(&now, &sim.world);
            for seen in sim.mon.ops.values_mut() {
                seen.locked = true;
            }
            for a in sim.mon.auths.values_mut() {
                a.locked = true;
            }
        }
        Ev::RootExit => {
            store_call = false;
            if !sim.world.exited.insert(ROOT) {
                return Ok(None);
            }
        }
        Ev::EpochBump => {
            store_call = false;
            sim.world.epochs.vault += 1;
        }
        Ev::RevisionChange => {
            store_call = false;
            sim.world.login += 1;
        }
        Ev::RecipientReplaced => {
            store_call = false;
            sim.world.browser += 1;
        }
        Ev::Tick => {
            store_call = false;
            sim.t += TICK;
        }
    }
    let effects = sim.store.drain_effects();
    if store_call {
        if sim.store.authorizations().count() > cfg.limits.authorizations {
            return Err("more authorizations than the store's bound".into());
        }
        check(prev, &mut sim, &effects, reached)?;
    }
    // The store brought up to date now, the silent events included: what
    // must have stopped has.
    let (probe, probe_effects) = settled(&sim.store, &now_of(&sim), &sim.world);
    for x in probe.operations().filter(|x| x.stop().is_none()) {
        if let Some(why) = must_stop(x, &sim.mon, &sim.world, sim.t) {
            return Err(format!("{:?} goes on {why}", x.request()));
        }
    }
    Ok(Some(Node {
        sim,
        base: probe,
        base_effects: probe_effects,
    }))
}

/// A request that opened slot `o`'s operation.
fn reserved(
    cfg: &Config,
    node: &Node,
    sim: &mut Sim,
    o: usize,
    sc: &SignInScope,
    st: Status,
    reached: &mut Reached,
) -> Result<(), Violation> {
    let base = &node.base;
    if base.operation(&st.request).is_some() || node.sim.mon.ops.contains_key(&st.request) {
        return Err("a new operation reused a request id".into());
    }
    let mine = base
        .operations()
        .filter(|x| x.owner() == sc.owner())
        .count();
    if mine >= cfg.limits.per_root || base.operations().count() >= cfg.limits.total {
        return Err("a full store opened an operation".into());
    }
    if (0..2).any(|p| {
        p != o
            && node.sim.slots[p].is_some_and(|id| base.operation(&id).is_some())
            && cfg.slots[p].key == cfg.slots[o].key
    }) {
        reached.other_root_own_operation += 1;
    }
    let world = &sim.world;
    if node.sim.mon.auths.values().any(|a| {
        a.slot != o
            && !a.locked
            && node.sim.t < a.approved + a.window
            && a.remaining > 0
            && world.epochs == *a.scope.epochs()
            && world.revisions(&a.scope) == Revisions::of(&a.scope)
            && world.alive(&a.scope.owner())
    }) {
        reached.coverable_across += 1;
    }
    sim.slots[o] = Some(st.request);
    let shown = sim
        .store
        .statement(&st.request, cfg.options, &at(sim.t), &sim.world)
        .map(|s| s.digest());
    let x = sim.store.operation(&st.request).unwrap();
    let t = sim.t;
    match x.authorization() {
        Some(a) => {
            let Some(seen) = sim.mon.auths.get(&a) else {
                return Err("a new key covered by an authorization never approved".into());
            };
            if seen.locked {
                return Err("a new key covered by an authorization a lock ended".into());
            }
            if t >= seen.approved + seen.window {
                return Err("a new key covered after its authorization's window".into());
            }
            if seen.scope != *sc {
                return Err("a new key covered by another scope's authorization".into());
            }
            if seen.slot == o {
                reached.covered += 1;
            } else {
                reached.covered_across += 1;
            }
        }
        None => {
            // An authorization for this exact scope that would cover it
            // but for a lock.
            if node
                .sim
                .mon
                .auths
                .values()
                .any(|a| a.locked && a.scope == *sc && t < a.approved + a.window && a.remaining > 0)
            {
                reached.not_covered_after_lock += 1;
            }
        }
    }
    sim.mon.ops.insert(
        st.request,
        Seen {
            slot: o,
            login: sc.account().login_item,
            status: st,
            shown,
            opened: t,
            started: None,
            decided: None,
            stopped: None,
            by_owner: false,
            locked: false,
            stopped_unpublished: false,
            passwords: 0,
            codes: 0,
            injections: 0,
            holds_login: false,
            teardown_asked: false,
            teardown_confirmed: false,
            close_failed: false,
            statement: x.statement_deadline(),
            attempt: None,
            session: None,
            retry_until: None,
        },
    );
    Ok(())
}

/// The identity the fixture app names for `scope`: exactly the expected
/// account, tenant and role.
fn expected(scope: &SignInScope) -> IdentityResponse {
    let a = scope.account();
    IdentityResponse {
        account: a.account.clone(),
        tenant: a.tenant.clone(),
        role: a.role.clone(),
    }
}

/// The supervisor's next message on its own channel, chosen by what it
/// last knew: the identity response, the publication, or a per-call
/// check. Each is judged by the store brought up to date at that call.
fn supervisor_message(
    node: &Node,
    sim: &mut Sim,
    x: &Operation,
    sup: envcloak_signin::SupervisorId,
    now: &Now,
    reached: &mut Reached,
) -> Result<(), Violation> {
    let id = x.request();
    let from = Channel::Supervisor(sup);
    let current = node.base.operation(&id);
    let live = |p: Phase| {
        current.is_some_and(|y| {
            y.stop().is_none() && y.phase() == p && y.generation() == Some(sup.generation())
        })
    };
    let at_barrier = x.stop().is_none() && current.is_some_and(|y| y.stop().is_some());
    match x.phase() {
        Phase::Captured => {
            let ready = live(Phase::Captured) && node.sim.mon.ops[&id].injections > 0;
            match sim
                .store
                .identity_response(&from, &id, &expected(x.scope()), now, &sim.world)
            {
                Ok(PublishDecision::Publish) if ready => {
                    let seen = sim.mon.ops.get_mut(&id).unwrap();
                    seen.decided = Some(sim.t);
                    reached.published += 1;
                }
                Ok(PublishDecision::Publish) => {
                    return Err("published an operation not ready at that call".into());
                }
                Ok(PublishDecision::Refuse(r)) if !ready => {
                    unchanged(node, sim, "a refused publication")?;
                    reached.refused_publication += 1;
                    if at_barrier {
                        reached.refused_at_barrier += 1;
                        if r != envcloak_signin::Refusal::Stopped {
                            return Err(format!("a stopped operation refused as {r:?}"));
                        }
                    }
                }
                Err(_) if current.is_none() => {
                    unchanged(node, sim, "a message for a forgotten operation")?
                }
                got => return Err(format!("the decision gave {got:?} where ready={ready}")),
            }
        }
        Phase::PublishDecided => {
            let ok = live(Phase::PublishDecided);
            match (ok, sim.store.published(&from, &id, now, &sim.world)) {
                (true, Ok(())) => {}
                (false, Err(_)) => {
                    unchanged(node, sim, "a refused publication")?;
                    reached.refused_at_barrier += usize::from(at_barrier);
                }
                (ok, got) => return Err(format!("publication gave {got:?} where ok={ok}")),
            }
        }
        Phase::Published => {
            let ok = live(Phase::Published);
            match (ok, sim.store.check(&from, &id, now, &sim.world)) {
                (true, Ok(())) => reached.checks += 1,
                (false, Err(_)) => {
                    unchanged(node, sim, "a refused check")?;
                    reached.refused_at_barrier += usize::from(at_barrier);
                }
                (ok, got) => return Err(format!("a tool call's check gave {got:?} where ok={ok}")),
            }
        }
        _ => {}
    }
    Ok(())
}

/// Every message `x` must refuse from a channel that is not its
/// generation's supervisor, worker results of another generation, and
/// status, cancel and end from other roots.
fn foreign(sim: &mut Sim, x: &Operation, o: usize, now: &Now) -> Result<(), Violation> {
    let id = x.request();
    let other = 1 - o;
    let other_op = sim.slots[other]
        .and_then(|i| sim.store.operation(&i))
        .cloned();
    let other_gen: Option<Generation> = other_op
        .as_ref()
        .and_then(Operation::generation)
        .filter(|g| Some(*g) != x.generation());
    let mut channels = vec![
        Channel::Client(x.scope().delivery().requester),
        Channel::Client(SIBLING),
        Channel::Client(OTHER_MCP),
        Channel::Client(x.owner()),
    ];
    if let Some(s) = other_op.as_ref().and_then(Operation::supervisor) {
        if Some(s.generation()) != x.generation() {
            channels.push(Channel::Supervisor(s));
        }
    }
    for from in &channels {
        if sim.store.inject_state(from, &id, now, &sim.world).is_ok() {
            return Err(format!("declared state given to {from:?}"));
        }
        if let Ok(PublishDecision::Publish) =
            sim.store
                .identity_response(from, &id, &expected(x.scope()), now, &sim.world)
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
                .permit(&id, g, Step::Code, now, &sim.world)
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

/// The invariants that hold after every call.
fn check(
    prev: &Sim,
    sim: &mut Sim,
    effects: &[Effect],
    reached: &mut Reached,
) -> Result<(), Violation> {
    let t = sim.t;
    // Attempts started only for live operations, one login at a time,
    // within the credits approved.
    for e in effects {
        match e {
            Effect::StartAttempt { request, lease, .. } => {
                if sim
                    .store
                    .operation(request)
                    .is_none_or(|x| x.stop().is_some())
                {
                    return Err("an attempt started for a stopped operation".into());
                }
                let login = sim.mon.ops.get(request).ok_or("an unseen attempt")?.login;
                for (other, seen) in &sim.mon.ops {
                    if other != request && seen.login == login && seen.holds_login {
                        return Err(format!(
                            "{request:?} started while {other:?} may still use the login"
                        ));
                    }
                }
                let seen = sim.mon.ops.get_mut(request).ok_or("an unseen attempt")?;
                seen.started = Some(t);
                seen.holds_login = true;
                let a = sim
                    .mon
                    .auths
                    .get_mut(&lease.authorization())
                    .ok_or("an attempt under an authorization never approved")?;
                a.started += 1;
                if a.started > a.credits {
                    return Err(format!(
                        "{} attempts under {} credits",
                        a.started, a.credits
                    ));
                }
            }
            Effect::TearDown { request, .. } => {
                let seen = sim.mon.ops.get_mut(request).ok_or("an unseen teardown")?;
                seen.teardown_asked = true;
            }
            Effect::StartSupervisor { .. } => {}
        }
    }
    // No eviction: an operation goes only once its retry window passed
    // and its teardown, if one was asked for, was confirmed.
    for x in prev.store.operations() {
        if sim.store.operation(&x.request()).is_some() {
            continue;
        }
        let seen = &sim.mon.ops[&x.request()];
        let window = seen
            .stopped
            .is_some_and(|s| t >= s + RETRY_WINDOW.as_secs());
        if !window || (seen.teardown_asked && !seen.teardown_confirmed) {
            return Err(format!(
                "{:?} disappeared before its retry_until or its confirmed teardown",
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
    // Budgets never grow; an authorization's deadline is its window from
    // its approval.
    for a in sim.store.authorizations() {
        let seen = sim
            .mon
            .auths
            .get_mut(&a.id())
            .ok_or("an authorization never approved")?;
        if a.credits() != seen.credits || a.remaining() > seen.remaining {
            return Err(format!("{:?}'s budget grew", a.id()));
        }
        if a.deadline() != seen.deadline {
            return Err(format!(
                "{:?}'s deadline is not its window from its approval",
                a.id()
            ));
        }
        if seen.started > a.credits() - a.remaining() {
            return Err("more attempts than credits reserved".into());
        }
        seen.remaining = a.remaining();
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
        seen.statement = x.statement_deadline();
        seen.attempt = x.attempt_deadline();
        seen.session = x.session_deadline();
        if let Some(stop) = x.stop() {
            let stopped = *seen.stopped.get_or_insert(t);
            if stop.retry_until != Deadline::after(&at(stopped), RETRY_WINDOW) {
                return Err(format!(
                    "{id:?}: retry_until is not the window from its stop"
                ));
            }
            seen.retry_until = Some(stop.retry_until.wall());
        }
        // Nothing published after a stop.
        if seen.stopped_unpublished && x.phase().delivered() {
            return Err(format!("{id:?} was published after it stopped"));
        }
        if let Some(stop) = x.stop() {
            if seen.status.receipt.reason.is_none() && stop.reason == StopReason::AuthorizationEnded
            {
                if matches!(x.phase(), Phase::AttemptRunning | Phase::Captured) {
                    reached.authorization_ran_out += 1;
                }
                if x.phase().delivered() {
                    reached.session_authorization_ended += 1;
                }
            }
            if !x.phase().delivered() {
                if !seen.stopped_unpublished && x.phase() == Phase::Captured {
                    reached.stopped_before_publication += 1;
                }
                seen.stopped_unpublished = true;
            }
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
        if x.passwords() > 1
            || x.codes() > 2
            || x.passwords() != seen.passwords
            || x.codes() != seen.codes
        {
            return Err(format!("{id:?}: steps not as permitted"));
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

fn start(cfg: &Config) -> Node {
    let sim = Sim {
        store: OperationStore::with_limits(common::DAEMON, cfg.limits),
        world: TestWorld::new(),
        t: 0,
        slots: [None, None],
        mon: Monitor::default(),
    };
    Node {
        base: sim.store.clone(),
        base_effects: Vec::new(),
        sim,
    }
}

fn explore(cfg: &Config, depth: usize) -> Reached {
    let events = events();
    let mut visited: HashMap<u128, usize> = HashMap::new();
    let mut reached = Reached::default();
    let empty = start(cfg);
    // The delivered start: slot A through its whole lifecycle, checked
    // along the way.
    let mut delivered = start(cfg);
    for ev in DELIVERED {
        delivered = step(cfg, &delivered, ev, &mut reached)
            .unwrap_or_else(|v| panic!("{}: {v} at {ev:?}", cfg.name))
            .unwrap_or_else(|| panic!("{}: {ev:?} did not apply", cfg.name));
    }
    let a = delivered.sim.slots[0].unwrap();
    assert_eq!(
        delivered.sim.store.operation(&a).map(Operation::phase),
        Some(Phase::Published),
        "{}",
        cfg.name
    );
    for (prefix, node) in [(Vec::new(), empty), (DELIVERED.to_vec(), delivered)] {
        let mut trace = prefix;
        dfs(
            cfg,
            &events,
            &node,
            depth,
            &mut visited,
            &mut trace,
            &mut reached,
        );
    }
    reached.states = visited.len();
    reached
}

fn dfs(
    cfg: &Config,
    events: &[Ev],
    node: &Node,
    left: usize,
    visited: &mut HashMap<u128, usize>,
    trace: &mut Vec<Ev>,
    reached: &mut Reached,
) {
    if left == 0 {
        return;
    }
    for ev in events {
        let next = match step(cfg, node, *ev, reached) {
            Ok(Some(next)) => next,
            Ok(None) => continue,
            Err(v) => panic!("{}: {v}\n  after {trace:?}\n  then {ev:?}", cfg.name),
        };
        reached.steps += 1;
        let h = digest(&next.sim);
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

/// `dev` options whose window (one tick) ends before an attempt started
/// with it times out (three ticks) and before a session delivered with it
/// ends (two ticks), so an authorization runs out under a running attempt
/// and under a delivered session within the depth.
fn dev(attempts: u8) -> Options {
    Options::Dev {
        window: Duration::from_secs(TICK),
        attempts,
    }
}

fn run(cfg: Config) -> Reached {
    let r = explore(&cfg, DEPTH);
    eprintln!("{}: {r:?}", cfg.name);
    let n = cfg.name;
    assert!(r.published > 0, "{n}: no publication reached");
    assert!(
        r.stopped_before_publication > 0,
        "{n}: no stop between capture and publication"
    );
    assert!(r.late_discarded > 0 && r.foreign_refused > 0, "{n}");
    assert!(r.joins > 0 && r.conflicts > 0, "{n}");
    assert!(r.delivered_then_stopped > 0, "{n}");
    assert!(
        r.checks > 0 && r.codes > 0 && r.passwords_refused > 0,
        "{n}"
    );
    assert!(
        r.refused_at_barrier > 0,
        "{n}: no call met a change it was the first to see"
    );
    r
}

/// Two keys, one scope, a `dev` budget of two: the second key is covered
/// by the first approval's authorization while it has a credit, its
/// window and no lock; a window ends under a running attempt and under a
/// delivered session.
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
    assert!(r.not_covered_after_lock > 0);
    assert!(r.authorization_ran_out > 0);
    assert!(r.session_authorization_ended > 0);
}

/// A budget of one: the second key asks for a proof; a failed close keeps
/// the login held until a later report confirms it, and stays visible
/// after publication.
#[test]
fn a_spent_dev_budget_covers_nothing_and_a_failed_close_holds_the_login() {
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
    assert!(r.held_by_failed_close > 0);
    assert!(r.confirmed_after_failure > 0);
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

/// Events per ordering for the scope-isolation runs: enough for an
/// approval of one slot, a new key of the other and the world's changes
/// around them.
const ISOLATION_DEPTH: usize = 5;

/// Every part of the scope is its own scope under every ordering: slot B
/// differs from slot A in that part alone (each field of the encoding, and
/// each part of a declared cookie, storage key and credential-entry
/// origin), and no new key of B is ever covered by A's authorization,
/// though B opens new keys while A's authorization is in force with a
/// credit left (counted, so the refusal is never a spent or ended
/// budget), with every other invariant checked after every event. The
/// positive control: with the same scope in both slots, B's new keys are
/// covered at this depth. Fields 12 and 24 cannot change alone in a `dev`
/// scope with credits to spare, and a scope of another daemon (29) is
/// refused before any lookup (`tests/store.rs` covers it). Mutations: the
/// cover check ignoring the project, the account, the target, the
/// transfer scope, a cookie's domain or path (R-M2b-35, b7, b8).
#[test]
fn every_scope_part_is_its_own_scope_under_every_ordering() {
    let config = |name: &'static str, vary: Option<Vary>| {
        let mut b = slot("b", ROOT, MCP, "editor");
        b.spec.vary = vary;
        Config {
            name,
            slots: [slot("a", ROOT, MCP, "editor"), b],
            options: dev(2),
            limits: StoreLimits::default(),
            close_fails: false,
        }
    };
    let control = explore(&config("isolation control", None), ISOLATION_DEPTH);
    assert!(control.covered_across > 0, "{control:?}");
    let base = scope(&slot("b", ROOT, MCP, "editor").spec, &TestWorld::new());
    let parts: Vec<Vary> = variations()
        .into_iter()
        .filter(|v| *v != Vary::Field(29) && varied(&base, *v).is_some())
        .collect();
    assert_eq!(parts.len(), variations().len() - 3);
    let threads = std::thread::available_parallelism().map_or(2, |n| n.get().clamp(2, 6));
    let results: Vec<(Vary, Reached)> = std::thread::scope(|s| {
        let chunks: Vec<Vec<Vary>> = (0..threads)
            .map(|i| parts.iter().copied().skip(i).step_by(threads).collect())
            .collect();
        let handles: Vec<_> = chunks
            .into_iter()
            .map(|chunk| {
                s.spawn(move || {
                    chunk
                        .into_iter()
                        .map(|v| (v, explore(&config("isolation", Some(v)), ISOLATION_DEPTH)))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect()
    });
    assert_eq!(results.len(), parts.len());
    for (v, r) in results {
        assert_eq!(r.covered_across, 0, "{v:?}");
        assert!(r.coverable_across > 0 && r.approvals > 0, "{v:?}: {r:?}");
    }
}
