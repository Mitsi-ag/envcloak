//! The operation store (SPEC §6.8 "Retries", "Approval" and "Delivery";
//! R-M2b-13 to R-M2b-17, R-M2b-28, SI-06 to SI-10): every sign-in
//! operation of one daemon instance, its authorizations, and every event
//! that moves them. The daemon holds one store under a lock and calls it
//! as its only implementation of the contract (plan M2b-05).
//!
//! **Retries.** An operation is found by its owner root (the scope's
//! subject root), the daemon instance (the store's) and the caller's
//! [`OperationKey`], compared in constant time and never logged. The same
//! key and scope join the operation and get its current status: no new
//! statement, prompt, worker or attempt, and a finished, failed or
//! cancelled operation answers its result. The same key with any scope
//! field changed is [`RequestError::Conflict`] and changes nothing. A new
//! key is a new operation: its recipient context is reserved only then,
//! after the lookup, and a `dev` authorization of exactly the same scope
//! covers it only while it is in force and has a credit left; anything
//! else asks for a proof. The store holds at most [`MAX_PER_ROOT`]
//! operations per root and [`MAX_OPERATIONS`] in all, and refuses new work
//! when full ([`RequestError::Full`]) rather than forgetting one: a
//! stopped operation's value-free receipt stays until its `retry_until`
//! ([`crate::RETRY_WINDOW`] after it stopped) has passed and its teardown,
//! if one was asked for, was confirmed: a pending or failed close keeps it
//! as a tombstone (and keeps its login from starting another attempt)
//! until a report confirms it. A daemon restart starts an empty store: no
//! operation is claimed exactly-once across one.
//!
//! **Owners.** Status, cancel and end answer only the owner root; to any
//! other caller an operation is [`NotFound`], the same answer as an id
//! that never existed, before anything about it is read.
//!
//! **Deadlines** are absolute, fixed when the operation, its attempt or
//! its delivery began (the statement's expiry, the attempt timeout, the
//! session lifetime, `retry_until`) or when the authorization was made;
//! nothing a retry, a poll or a new key does moves them (SI-07).
//!
//! **Time and the world.** Every call takes the injected clock and a
//! [`World`] (the current epochs, the revisions a scope pins, and which
//! processes still run), and first brings every operation up to date:
//! stops what a lock, root exit, epoch or revision change, replaced
//! recipient or passed deadline ended, starts approved attempts whose
//! login is free (attempts on one login are serialized), and forgets
//! receipts past their window. What the daemon has to do in the world
//! (start a worker, start a supervisor, tear something down) comes back
//! from [`OperationStore::drain_effects`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::time::{Duration, UNIX_EPOCH};

use envcloak_policy::Now;
use subtle::ConstantTimeEq;

use crate::authorization::{
    Authorization, AuthorizationId, AuthorizationKind, BudgetError, CreditLease, Deadline,
};
use crate::operation::{
    AttemptFailure, Channel, Checkpoint, Cleanup, Generation, IdentityResponse, Operation, Phase,
    PublishDecision, RETRY_WINDOW, Refusal, Revisions, Stop, StopReason, publication_decision,
};
use crate::scope::{DaemonInstance, Epochs, Instance, SignInScope};
use crate::statement::{ContextId, Nonce, Options, OptionsError, RequestId, SignInStatement};
use crate::status::{Status, project};

/// The longest operation key, in bytes.
pub const MAX_KEY: usize = 128;
/// Operations (live and remembered) per owner root.
pub const MAX_PER_ROOT: usize = 256;
/// Operations in all.
pub const MAX_OPERATIONS: usize = 4096;
/// Authorizations held at once.
pub const MAX_AUTHORIZATIONS: usize = 256;
/// How long a pending statement waits for a proof (as a pending request
/// does, `envcloak_policy::PENDING_TTL`).
pub const STATEMENT_TTL: Duration = envcloak_policy::PENDING_TTL;
/// Password submissions per attempt.
pub const MAX_PASSWORDS: u8 = 1;
/// One-time-code submissions per attempt.
pub const MAX_CODES: u8 = 2;

/// The caller's key for one intent (SPEC §6.8 "Retries"): 1 to
/// [`MAX_KEY`] characters of `[A-Za-z0-9._-]`. Memory only. It has no
/// `Display`, its `Debug` shows nothing of it, and it is compared in
/// constant time over its whole capacity.
#[derive(Clone)]
pub struct OperationKey {
    bytes: [u8; MAX_KEY],
    len: u8,
}

/// Why a key was refused. Fixed; never the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyError {
    Empty,
    TooLong,
    Character,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            KeyError::Empty => "empty operation key",
            KeyError::TooLong => "operation key too long",
            KeyError::Character => "operation key outside [A-Za-z0-9._-]",
        })
    }
}

impl std::error::Error for KeyError {}

impl OperationKey {
    pub fn parse(s: &str) -> Result<Self, KeyError> {
        let b = s.as_bytes();
        if b.is_empty() {
            return Err(KeyError::Empty);
        }
        if b.len() > MAX_KEY {
            return Err(KeyError::TooLong);
        }
        if !b
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
        {
            return Err(KeyError::Character);
        }
        let mut bytes = [0u8; MAX_KEY];
        bytes[..b.len()].copy_from_slice(b);
        Ok(OperationKey {
            bytes,
            len: u8::try_from(b.len()).unwrap_or(u8::MAX),
        })
    }
}

impl PartialEq for OperationKey {
    fn eq(&self, other: &Self) -> bool {
        (self.bytes[..].ct_eq(&other.bytes[..]) & self.len.ct_eq(&other.len)).into()
    }
}

impl Eq for OperationKey {}

impl Hash for OperationKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
        self.len.hash(state);
    }
}

impl fmt::Debug for OperationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OperationKey(..)")
    }
}

/// The world as the daemon sees it at a call.
pub trait World {
    /// The current daemon instance, vault and policy epochs.
    fn epochs(&self) -> Epochs;
    /// The current values of what `scope` pins.
    fn revisions(&self, scope: &SignInScope) -> Revisions;
    /// Whether `instance` still runs.
    fn alive(&self, instance: &Instance) -> bool;
}

/// The store's bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StoreLimits {
    pub per_root: usize,
    pub total: usize,
    pub authorizations: usize,
}

impl Default for StoreLimits {
    fn default() -> Self {
        StoreLimits {
            per_root: MAX_PER_ROOT,
            total: MAX_OPERATIONS,
            authorizations: MAX_AUTHORIZATIONS,
        }
    }
}

/// A sign-in request, as the daemon resolved it.
#[derive(Debug, Clone)]
pub struct Request {
    pub key: OperationKey,
    pub scope: SignInScope,
}

/// What the daemon drew for a request, used only if it opens a new
/// operation.
#[derive(Debug, Clone, Copy)]
pub struct Fresh {
    pub request: RequestId,
    pub nonce: Nonce,
}

/// What a request found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup {
    /// The same key and scope: the existing operation.
    Joined(Status),
    /// A new operation.
    Reserved(Status),
}

impl Lookup {
    pub fn status(&self) -> Status {
        match *self {
            Lookup::Joined(s) | Lookup::Reserved(s) => s,
        }
    }
}

/// Why a request opened nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestError {
    /// The key is the owner's for another scope; that operation is
    /// untouched (`request_conflict`).
    Conflict,
    /// The store is full for this root or in all.
    Full,
    /// The scope names another daemon instance.
    WrongDaemon,
    /// The drawn request id is taken; the daemon draws again.
    IdInUse,
}

/// Why an approval made nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApproveError {
    NoSuchRequest,
    /// The operation is not waiting for a proof (stopped, approved,
    /// covered).
    NotPending,
    Options(OptionsError),
    /// The proof names another statement.
    DigestMismatch,
    /// [`StoreLimits::authorizations`] are held.
    Full,
    Budget(BudgetError),
}

/// Status, cancel or end for an operation the caller does not own, or
/// that does not exist: the same answer, with nothing about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotFound;

/// A worker message that does not apply: another generation, an operation
/// that stopped or moved on. Discarded without effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Discarded;

/// A control message that did not come from the operation's own
/// generation's supervisor, or does not apply. Refused without effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelRefused;

/// A credential step the driver reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Step {
    Password,
    Code,
}

/// Why a credential step was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptError {
    /// Not this operation's running attempt.
    NotRunning,
    /// The attempt used its one password or its two codes.
    Spent,
}

/// The declared state of a captured operation may go to the supervisor
/// that asked, for this recipient context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Injection {
    pub generation: Generation,
    pub context: ContextId,
}

/// What the daemon has to do after a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Effect {
    /// Write the intent audit entry, then start the attempt's reaper and
    /// driver; an audit failure is reported back as
    /// [`AttemptFailure::AuditFailed`] and starts nothing.
    StartAttempt {
        request: RequestId,
        generation: Generation,
        lease: CreditLease,
    },
    /// Start the generation's browser supervisor for the captured state.
    StartSupervisor {
        request: RequestId,
        generation: Generation,
    },
    /// Stop the attempt, drop the captured state and close the recipient
    /// context; report back with [`OperationStore::cleanup_result`].
    TearDown {
        request: RequestId,
        generation: Generation,
        delivered: bool,
    },
}

/// The store. See the module documentation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OperationStore {
    daemon: DaemonInstance,
    limits: StoreLimits,
    ops: BTreeMap<RequestId, Operation>,
    auths: BTreeMap<AuthorizationId, Authorization>,
    seq: u64,
    next_context: u64,
    next_generation: u64,
    next_authorization: u64,
    effects: Vec<Effect>,
}

fn unix_secs(now: &Now) -> u64 {
    now.wall
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(crate) fn wall_secs(d: &Deadline) -> u64 {
    d.wall()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl OperationStore {
    /// An empty store for daemon instance `daemon`.
    pub fn new(daemon: DaemonInstance) -> Self {
        OperationStore::with_limits(daemon, StoreLimits::default())
    }

    /// An empty store with other bounds (tests).
    pub fn with_limits(daemon: DaemonInstance, limits: StoreLimits) -> Self {
        OperationStore {
            daemon,
            limits,
            ops: BTreeMap::new(),
            auths: BTreeMap::new(),
            seq: 0,
            next_context: 1,
            next_generation: 1,
            next_authorization: 1,
            effects: Vec::new(),
        }
    }

    pub fn daemon(&self) -> DaemonInstance {
        self.daemon
    }

    /// Finds the owner's operation for `request.key`, or opens one. See
    /// the module documentation.
    pub fn lookup_or_reserve(
        &mut self,
        request: Request,
        fresh: Fresh,
        now: &Now,
        world: &dyn World,
    ) -> Result<Lookup, RequestError> {
        self.settle(now, world);
        let found = self.lookup_settled(request, fresh, now, world);
        self.finish(now, world);
        let (joined, id) = found?;
        // Present: the operation was just found or made, and refresh gave
        // every operation its status.
        let status = self.status_of(&id).ok_or(RequestError::Full)?;
        Ok(if joined {
            Lookup::Joined(status)
        } else {
            Lookup::Reserved(status)
        })
    }

    fn lookup_settled(
        &mut self,
        request: Request,
        fresh: Fresh,
        now: &Now,
        world: &dyn World,
    ) -> Result<(bool, RequestId), RequestError> {
        if request.scope.epochs().daemon != self.daemon {
            return Err(RequestError::WrongDaemon);
        }
        let Request { key, scope } = request;
        let owner = scope.owner();
        // The statement this request would open with: a retry is found by
        // its lookup fingerprint, which leaves out the nonce drawn for it
        // and the context it would reserve.
        let statement_deadline = Deadline::after(now, STATEMENT_TTL);
        let candidate = SignInStatement {
            options: Options::default_for(scope.limits()),
            scope,
            request: fresh.request,
            nonce: fresh.nonce,
            created_unix: unix_secs(now),
            expires_unix: wall_secs(&statement_deadline),
            context: ContextId::new(self.next_context),
        };
        let fingerprint = candidate.lookup_fingerprint();
        // Every entry of the owner is compared, so the time taken does not
        // depend on where the key matched.
        let mut hit = None;
        for op in self.ops.values() {
            if op.owner() == owner && op.key == key {
                hit = Some(op.request);
            }
        }
        if let Some(id) = hit {
            let op = &self.ops[&id];
            return if op.fingerprint == fingerprint && op.scope == candidate.scope {
                Ok((true, id))
            } else {
                Err(RequestError::Conflict)
            };
        }
        if self.ops.contains_key(&fresh.request) {
            return Err(RequestError::IdInUse);
        }
        let mine = self.ops.values().filter(|o| o.owner() == owner).count();
        if mine >= self.limits.per_root || self.ops.len() >= self.limits.total {
            return Err(RequestError::Full);
        }
        // Reserved only now, for a new operation, after the lookup.
        let context = ContextId::new(self.next_context);
        self.next_context += 1;
        self.seq += 1;
        let mut op = Operation {
            seq: self.seq,
            key,
            scope: candidate.scope,
            fingerprint,
            request: fresh.request,
            nonce: fresh.nonce,
            created_unix: candidate.created_unix,
            statement_deadline,
            context,
            phase: Phase::Requested,
            stop: None,
            authorization: None,
            lease: None,
            generation: None,
            attempt_deadline: None,
            passwords: 0,
            codes: 0,
            injected: false,
            session_deadline: None,
            cleanup: Cleanup::NotNeeded,
            revision: 0,
            shown: None,
        };
        let epochs = world.epochs();
        let covering = self.auths.values_mut().find(|a| {
            a.kind() == AuthorizationKind::Dev
                && a.for_scope(&op.scope)
                && a.in_force(&epochs, now)
                && a.remaining() > 0
        });
        match covering.map(|a| a.reserve_credit(&epochs, now)) {
            Some(Ok(lease)) => {
                op.authorization = Some(lease.authorization());
                op.lease = Some(lease);
                op.phase = Phase::Approved;
            }
            _ => op.phase = Phase::PendingApproval,
        }
        let id = op.request;
        self.ops.insert(id, op);
        Ok((false, id))
    }

    /// The statement a proof for `request` with `options` approves, while
    /// it waits for one, read after the world and the clock stopped what
    /// they ended: a statement is rebuilt when it is shown (L-09), so the
    /// approval screen never shows one for a scope that already changed.
    pub fn statement(
        &mut self,
        request: &RequestId,
        options: Options,
        now: &Now,
        world: &dyn World,
    ) -> Option<SignInStatement> {
        self.finish(now, world);
        self.ops
            .get(request)
            .filter(|op| op.stop.is_none() && op.phase == Phase::PendingApproval)
            .map(|op| op.statement(options))
    }

    /// A verified proof over `digest` approves `request` with `options`:
    /// an authorization for its exact scope is made and the operation's
    /// credit reserved from it at once. Refused, changing nothing, unless
    /// the operation still waits for a proof and `digest` is its
    /// statement's with these options; a target edit, a browser
    /// replacement or a cancel while the proof was checked has stopped
    /// the operation by now, so the stale proof mints nothing.
    pub fn approve(
        &mut self,
        request: &RequestId,
        options: Options,
        digest: &[u8; 32],
        now: &Now,
        world: &dyn World,
    ) -> Result<Status, ApproveError> {
        self.settle(now, world);
        let done = self.approve_settled(request, options, digest, now, world);
        self.finish(now, world);
        done?;
        self.status_of(request).ok_or(ApproveError::NoSuchRequest)
    }

    fn approve_settled(
        &mut self,
        request: &RequestId,
        options: Options,
        digest: &[u8; 32],
        now: &Now,
        world: &dyn World,
    ) -> Result<(), ApproveError> {
        let op = self.ops.get(request).ok_or(ApproveError::NoSuchRequest)?;
        if op.stop.is_some() || op.phase != Phase::PendingApproval {
            return Err(ApproveError::NotPending);
        }
        options
            .allowed_by(op.scope.limits())
            .map_err(ApproveError::Options)?;
        if op.statement(options).digest() != *digest {
            return Err(ApproveError::DigestMismatch);
        }
        if self.auths.len() >= self.limits.authorizations {
            return Err(ApproveError::Full);
        }
        let id = AuthorizationId::new(self.next_authorization);
        let mut auth = Authorization::from_options(id, &op.scope, options, now)
            .map_err(ApproveError::Options)?;
        let lease = auth
            .reserve_credit(&world.epochs(), now)
            .map_err(ApproveError::Budget)?;
        self.next_authorization += 1;
        self.auths.insert(id, auth);
        if let Some(op) = self.ops.get_mut(request) {
            op.authorization = Some(id);
            op.lease = Some(lease);
            op.phase = Phase::Approved;
        }
        Ok(())
    }

    /// `request`'s status, to its owner root only.
    pub fn status(
        &mut self,
        caller: &Instance,
        request: &RequestId,
        now: &Now,
        world: &dyn World,
    ) -> Result<Status, NotFound> {
        self.finish(now, world);
        self.owned(caller, request)?;
        self.status_of(request).ok_or(NotFound)
    }

    /// `cancel_sign_in`: ends the whole operation, a context published in
    /// a race included. Idempotent; to the owner root only.
    pub fn cancel(
        &mut self,
        caller: &Instance,
        request: &RequestId,
        now: &Now,
        world: &dyn World,
    ) -> Result<Status, NotFound> {
        self.owner_stop(caller, request, StopReason::Cancelled, now, world)
    }

    /// `end_sign_in_session`: the same teardown, for a delivered session.
    /// Idempotent; to the owner root only.
    pub fn end(
        &mut self,
        caller: &Instance,
        request: &RequestId,
        now: &Now,
        world: &dyn World,
    ) -> Result<Status, NotFound> {
        self.owner_stop(caller, request, StopReason::EndedByOwner, now, world)
    }

    fn owner_stop(
        &mut self,
        caller: &Instance,
        request: &RequestId,
        reason: StopReason,
        now: &Now,
        world: &dyn World,
    ) -> Result<Status, NotFound> {
        self.settle(now, world);
        if self.owned(caller, request).is_ok()
            && self.ops.get(request).is_some_and(|op| op.stop.is_none())
        {
            self.stop_op(request, reason, now);
        }
        self.finish(now, world);
        self.owned(caller, request)?;
        self.status_of(request).ok_or(NotFound)
    }

    /// The daemon locked: every operation stops and every authorization
    /// ends.
    pub fn lock(&mut self, now: &Now, world: &dyn World) {
        self.settle(now, world);
        let live: Vec<RequestId> = self
            .ops
            .values()
            .filter(|op| op.stop.is_none())
            .map(|op| op.request)
            .collect();
        for id in live {
            self.stop_op(&id, StopReason::Locked, now);
        }
        for a in self.auths.values_mut() {
            a.end();
        }
        self.finish(now, world);
    }

    /// Brings every operation up to date with `world` at `now`: after a
    /// root exit, an epoch or revision change, a replaced recipient, and
    /// on the clock's tick.
    pub fn reconcile(&mut self, now: &Now, world: &dyn World) {
        self.finish(now, world);
    }

    /// The driver reached a credential step of `request`'s attempt of
    /// `generation`: at most [`MAX_PASSWORDS`] password and [`MAX_CODES`]
    /// code submissions per attempt.
    pub fn permit(
        &mut self,
        request: &RequestId,
        generation: Generation,
        step: Step,
        now: &Now,
        world: &dyn World,
    ) -> Result<(), AttemptError> {
        self.settle(now, world);
        let done = self.permit_settled(request, generation, step);
        self.finish(now, world);
        done
    }

    fn permit_settled(
        &mut self,
        request: &RequestId,
        generation: Generation,
        step: Step,
    ) -> Result<(), AttemptError> {
        let op = self.ops.get_mut(request).ok_or(AttemptError::NotRunning)?;
        if op.stop.is_some()
            || op.generation != Some(generation)
            || op.phase != Phase::AttemptRunning
        {
            return Err(AttemptError::NotRunning);
        }
        let (used, max) = match step {
            Step::Password => (&mut op.passwords, MAX_PASSWORDS),
            Step::Code => (&mut op.codes, MAX_CODES),
        };
        if *used >= max {
            return Err(AttemptError::Spent);
        }
        *used += 1;
        Ok(())
    }

    /// The worker of `generation` captured the declared state. Discarded
    /// unless it is `request`'s running attempt.
    pub fn worker_captured(
        &mut self,
        request: &RequestId,
        generation: Generation,
        now: &Now,
        world: &dyn World,
    ) -> Result<(), Discarded> {
        self.settle(now, world);
        let done = match self.ops.get_mut(request) {
            Some(op)
                if op.stop.is_none()
                    && op.generation == Some(generation)
                    && op.phase == Phase::AttemptRunning =>
            {
                op.phase = Phase::Captured;
                self.effects.push(Effect::StartSupervisor {
                    request: *request,
                    generation,
                });
                Ok(())
            }
            _ => Err(Discarded),
        };
        self.finish(now, world);
        done
    }

    /// The worker of `generation` failed. Discarded unless it is
    /// `request`'s running attempt. Its credit stays spent.
    pub fn worker_failed(
        &mut self,
        request: &RequestId,
        generation: Generation,
        failure: AttemptFailure,
        now: &Now,
        world: &dyn World,
    ) -> Result<(), Discarded> {
        self.settle(now, world);
        let running = self.ops.get(request).is_some_and(|op| {
            op.stop.is_none()
                && op.generation == Some(generation)
                && op.phase == Phase::AttemptRunning
        });
        let done = if running {
            self.stop_op(request, StopReason::AttemptFailed(failure), now);
            Ok(())
        } else {
            Err(Discarded)
        };
        self.finish(now, world);
        done
    }

    /// The supervisor on `from` is ready for `request`'s declared state.
    /// Given only to the supervisor of the operation's own generation,
    /// once, while the operation is captured and not stopped.
    pub fn inject_state(
        &mut self,
        from: &Channel,
        request: &RequestId,
        now: &Now,
        world: &dyn World,
    ) -> Result<Injection, ChannelRefused> {
        self.settle(now, world);
        let done = match self.ops.get_mut(request) {
            Some(op) if from_supervisor(from, op) => match op.generation {
                Some(generation)
                    if op.stop.is_none() && op.phase == Phase::Captured && !op.injected =>
                {
                    op.injected = true;
                    Ok(Injection {
                        generation,
                        context: op.context,
                    })
                }
                _ => Err(ChannelRefused),
            },
            _ => Err(ChannelRefused),
        };
        self.finish(now, world);
        done
    }

    /// The supervisor on `from` read `identity` in `request`'s recipient
    /// context: the serialized publication decision. A client is refused;
    /// a supervisor of another generation is answered with a refusal and
    /// changes nothing. An identity that is not exactly the expected one
    /// stops the operation with nothing delivered.
    pub fn identity_response(
        &mut self,
        from: &Channel,
        request: &RequestId,
        identity: &IdentityResponse,
        now: &Now,
        world: &dyn World,
    ) -> Result<PublishDecision, ChannelRefused> {
        self.settle(now, world);
        let decided = self.decide(from, request, identity, now, world);
        self.finish(now, world);
        decided
    }

    fn decide(
        &mut self,
        from: &Channel,
        request: &RequestId,
        identity: &IdentityResponse,
        now: &Now,
        world: &dyn World,
    ) -> Result<PublishDecision, ChannelRefused> {
        let Channel::Supervisor(supervisor) = from else {
            return Err(ChannelRefused);
        };
        let op = self.ops.get(request).ok_or(ChannelRefused)?;
        let at = Checkpoint {
            now: *now,
            epochs: world.epochs(),
            revisions: world.revisions(&op.scope),
            root_alive: world.alive(&op.owner()),
        };
        let authorization = op.authorization.and_then(|a| self.auths.get(&a));
        let decision =
            publication_decision(op, authorization, supervisor.generation(), identity, &at);
        match decision {
            PublishDecision::Publish => {
                if let Some(op) = self.ops.get_mut(request) {
                    op.phase = Phase::PublishDecided;
                    op.session_deadline =
                        Some(Deadline::after(now, op.scope.limits().session_lifetime()));
                }
            }
            PublishDecision::Refuse(Refusal::IdentityUnverified) => {
                self.stop_op(request, StopReason::IdentityUnverified, now);
            }
            PublishDecision::Refuse(_) => {}
        }
        Ok(decision)
    }

    /// The supervisor on `from` made `request`'s context reachable, as
    /// the decision told it to.
    pub fn published(
        &mut self,
        from: &Channel,
        request: &RequestId,
        now: &Now,
        world: &dyn World,
    ) -> Result<(), ChannelRefused> {
        self.settle(now, world);
        let done = match self.ops.get_mut(request) {
            Some(op)
                if from_supervisor(from, op)
                    && op.stop.is_none()
                    && op.phase == Phase::PublishDecided =>
            {
                op.phase = Phase::Published;
                Ok(())
            }
            _ => Err(ChannelRefused),
        };
        self.finish(now, world);
        done
    }

    /// The per-call check before the supervisor on `from` forwards a
    /// browser tool call for `request`: only for a published session
    /// that has not stopped, read after the world and the clock stopped
    /// whatever they ended (its authorization included).
    pub fn check(
        &mut self,
        from: &Channel,
        request: &RequestId,
        now: &Now,
        world: &dyn World,
    ) -> Result<(), ChannelRefused> {
        self.settle(now, world);
        let done = match self.ops.get(request) {
            Some(op)
                if from_supervisor(from, op)
                    && op.stop.is_none()
                    && op.phase == Phase::Published =>
            {
                Ok(())
            }
            _ => Err(ChannelRefused),
        };
        self.finish(now, world);
        done
    }

    /// The reaper or supervisor of `generation` reported `request`'s
    /// teardown: `closed` false is a failed close, kept visible and never
    /// taken as done; a later report that it closed confirms it. Anything
    /// else (another generation, nothing asked for, already confirmed, a
    /// failure reported again) is discarded.
    pub fn cleanup_result(
        &mut self,
        request: &RequestId,
        generation: Generation,
        closed: bool,
        now: &Now,
        world: &dyn World,
    ) -> Result<(), Discarded> {
        self.settle(now, world);
        let done = match self.ops.get_mut(request) {
            Some(op) if op.generation == Some(generation) => match (op.cleanup, closed) {
                (Cleanup::Pending | Cleanup::Failed, true) => {
                    op.cleanup = Cleanup::Done;
                    Ok(())
                }
                (Cleanup::Pending, false) => {
                    op.cleanup = Cleanup::Failed;
                    Ok(())
                }
                _ => Err(Discarded),
            },
            _ => Err(Discarded),
        };
        self.finish(now, world);
        done
    }

    /// What the daemon has to do, oldest first; the list is emptied.
    pub fn drain_effects(&mut self) -> Vec<Effect> {
        std::mem::take(&mut self.effects)
    }

    /// `request`'s operation as the last call left it (call
    /// [`OperationStore::reconcile`] first to see it at a later moment).
    pub fn operation(&self, request: &RequestId) -> Option<&Operation> {
        self.ops.get(request)
    }

    /// Every operation, as the last call left them.
    pub fn operations(&self) -> impl Iterator<Item = &Operation> {
        self.ops.values()
    }

    /// The authorization `id`, as the last call left it.
    pub fn authorization(&self, id: &AuthorizationId) -> Option<&Authorization> {
        self.auths.get(id)
    }

    /// Every authorization, as the last call left them.
    pub fn authorizations(&self) -> impl Iterator<Item = &Authorization> {
        self.auths.values()
    }

    fn owned(&self, caller: &Instance, request: &RequestId) -> Result<(), NotFound> {
        match self.ops.get(request) {
            Some(op) if op.owner() == *caller => Ok(()),
            _ => Err(NotFound),
        }
    }

    fn status_of(&self, request: &RequestId) -> Option<Status> {
        self.ops.get(request).and_then(|op| op.shown)
    }

    /// Stops `request` for `reason`, asking for a teardown if an attempt
    /// started or a context was delivered.
    fn stop_op(&mut self, request: &RequestId, reason: StopReason, now: &Now) {
        let Some(op) = self.ops.get_mut(request) else {
            return;
        };
        if op.stop.is_some() {
            return;
        }
        let delivered = op.phase.delivered();
        op.stop = Some(Stop {
            reason,
            delivered,
            retry_until: Deadline::after(now, RETRY_WINDOW),
        });
        if let Some(generation) = op.generation {
            op.cleanup = Cleanup::Pending;
            self.effects.push(Effect::TearDown {
                request: *request,
                generation,
                delivered,
            });
        }
    }

    /// Stops what the world or the clock ended, starts what can start,
    /// forgets what has expired.
    fn settle(&mut self, now: &Now, world: &dyn World) {
        let epochs = world.epochs();
        for a in self.auths.values_mut() {
            let s = a.scope();
            if !a.ended()
                && (*s.epochs() != epochs
                    || !world.alive(&s.owner())
                    || world.revisions(s) != Revisions::of(s))
            {
                a.end();
            }
        }
        let ended: Vec<(RequestId, StopReason)> = self
            .ops
            .values()
            .filter(|op| op.stop.is_none())
            .filter_map(|op| {
                stop_reason(op, &self.auths, &epochs, now, world).map(|r| (op.request, r))
            })
            .collect();
        for (id, reason) in ended {
            self.stop_op(&id, reason, now);
        }
        self.start_ready(now);
        self.sweep(now);
    }

    /// Starts approved attempts, oldest first, whose login has no other
    /// attempt that may still be using its credentials: one running, or
    /// stopped while it ran and not yet confirmed torn down (SPEC §6.8:
    /// attempts on one account are serialised, so a worker that may still
    /// run never overlaps the next). A failed close is not a confirmation:
    /// it holds the login until a later report confirms the teardown. A
    /// captured attempt frees it, since from capture on no credential step
    /// is permitted for that generation.
    fn start_ready(&mut self, now: &Now) {
        let mut ready: Vec<(u64, RequestId)> = self
            .ops
            .values()
            .filter(|op| op.stop.is_none() && op.phase == Phase::Approved)
            .map(|op| (op.seq, op.request))
            .collect();
        ready.sort();
        for (_, id) in ready {
            let Some(login) = self.ops.get(&id).map(|op| op.scope.account().login_item) else {
                continue;
            };
            let busy = self.ops.values().any(|o| {
                o.scope.account().login_item == login
                    && o.phase == Phase::AttemptRunning
                    && (o.stop.is_none() || o.cleanup != Cleanup::Done)
            });
            if busy {
                continue;
            }
            let generation = Generation::new(self.next_generation);
            self.next_generation += 1;
            if let Some(op) = self.ops.get_mut(&id) {
                op.generation = Some(generation);
                op.phase = Phase::AttemptRunning;
                op.attempt_deadline =
                    Some(Deadline::after(now, op.scope.limits().attempt_timeout()));
                if let Some(lease) = op.lease {
                    self.effects.push(Effect::StartAttempt {
                        request: id,
                        generation,
                        lease,
                    });
                }
            }
        }
    }

    /// Forgets stopped operations past their retry window whose teardown
    /// was not needed or was confirmed (a pending or failed one stays, as
    /// a tombstone, until a report confirms it), and authorizations that
    /// ended or ran out which no live operation holds.
    fn sweep(&mut self, now: &Now) {
        self.ops.retain(|_, op| {
            !op.stop.is_some_and(|s| {
                s.retry_until.passed(now)
                    && matches!(op.cleanup, Cleanup::NotNeeded | Cleanup::Done)
            })
        });
        let held: BTreeSet<AuthorizationId> = self
            .ops
            .values()
            .filter(|op| op.stop.is_none())
            .filter_map(|op| op.authorization)
            .collect();
        self.auths
            .retain(|id, a| held.contains(id) || !(a.ended() || a.deadline().passed(now)));
    }

    /// Ends every call: brings what the call changed up to date with the
    /// world and the clock as the call began did (a new operation whose
    /// root already exited stops at once), then raises the revision of
    /// every status that changed.
    fn finish(&mut self, now: &Now, world: &dyn World) {
        self.settle(now, world);
        self.refresh();
    }

    /// Raises the revision of every operation whose status changed.
    fn refresh(&mut self) {
        for op in self.ops.values_mut() {
            let now = project(op, op.revision);
            if op.shown != Some(now) {
                op.revision += 1;
                op.shown = Some(project(op, op.revision));
            }
        }
    }
}

/// Whether `from` is the control pipe of `op`'s own generation's
/// supervisor.
fn from_supervisor(from: &Channel, op: &Operation) -> bool {
    match from {
        Channel::Supervisor(s) => op.generation == Some(s.generation()),
        Channel::Client(_) => false,
    }
}

/// Why `op` has to stop now, if it does.
fn stop_reason(
    op: &Operation,
    auths: &BTreeMap<AuthorizationId, Authorization>,
    epochs: &Epochs,
    now: &Now,
    world: &dyn World,
) -> Option<StopReason> {
    let s = &op.scope;
    if !world.alive(&s.owner()) {
        return Some(StopReason::RootExited);
    }
    if *s.epochs() != *epochs {
        return Some(StopReason::EpochChanged);
    }
    let current = world.revisions(s);
    let pinned = Revisions::of(s);
    if current.login != pinned.login
        || current.target != pinned.target
        || current.adapter != pinned.adapter
    {
        return Some(StopReason::RevisionChanged);
    }
    if current.browser != pinned.browser || !current.requester_alive {
        return Some(StopReason::RecipientReplaced);
    }
    if op.phase == Phase::Requested || op.phase == Phase::PendingApproval {
        return op
            .statement_deadline
            .passed(now)
            .then_some(StopReason::StatementExpired);
    }
    // From the approval on, in every phase, a delivered session included:
    // the authorization is the grant the supervisor checks on every call.
    let authorized = op
        .authorization
        .and_then(|a| auths.get(&a))
        .is_some_and(|a| a.in_force(epochs, now));
    if !authorized {
        return Some(StopReason::AuthorizationEnded);
    }
    let passed = |d: Option<Deadline>| d.is_some_and(|d| d.passed(now));
    match op.phase {
        Phase::Requested | Phase::PendingApproval | Phase::Approved => None,
        Phase::AttemptRunning | Phase::Captured => {
            passed(op.attempt_deadline).then_some(StopReason::AttemptTimedOut)
        }
        Phase::PublishDecided | Phase::Published => {
            passed(op.session_deadline).then_some(StopReason::SessionExpired)
        }
    }
}
