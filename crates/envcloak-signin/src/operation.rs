//! One sign-in operation and its serialized publication decision (SPEC
//! §6.8 "Delivery"; R-M2b-27, R-M2b-28, SI-09).
//!
//! **Lifecycle.** An operation moves through [`Phase`]: `requested`
//! (reserved after the retry lookup), `pending_approval` (its statement
//! waits for a proof) or straight to `approved` (a `dev` authorization of
//! the same exact scope covered it and a credit was reserved), then
//! `attempt_running` (the worker holds the credit's lease; attempts on one
//! account are serialized), `captured` (the worker's declared state is held
//! by the daemon, private to EnvCloak), `publish_decided` (the decision
//! below said publish and the supervisor was told) and `published` (the
//! supervisor made the context reachable through the agent's browser
//! tools). It ends `ended`, `cancelled` or `failed` ([`crate::State`]):
//! the end is a [`Stop`] recorded beside the phase, with its reason, so
//! the phase keeps saying how far the attempt got.
//!
//! **Generations and channels** (plan D-31, D-36). Each attempt gets a
//! [`Generation`], unique in the daemon. Its worker (the reaper and driver
//! the daemon starts for it) is named by a [`WorkerId`], and its browser
//! supervisor, a process the daemon starts once the state is captured, by
//! a [`SupervisorId`]. Each id is made only by the store's start effects
//! ([`crate::Effect::StartAttempt`], [`crate::Effect::StartSupervisor`]),
//! those of a clone of the store included; a generation read from an
//! operation does not make either. An id names a generation and carries no
//! authority of its own: the daemon's binding of it to the pipes of the
//! process it starts is what makes a message that process's (below). A
//! worker's credential steps, results and teardown report are taken only
//! with the attempt's own [`WorkerId`], and anything else is discarded.
//! Declared state leaves the store only towards the generation's
//! [`Channel::Supervisor`], and claim, publish and the per-call check are
//! accepted only from it; a client of the socket ([`Channel::Client`], a
//! sibling `envcloak mcp` in the same root included) is never one.
//!
//! **What the store trusts.** It cannot see where a message came from: it
//! takes the channel and the worker id the daemon passes with a message.
//! So the daemon (plan M2b-05, M2b-08, M2b-09) binds each id to the pipes
//! it creates for that process when it starts it, and derives the channel
//! and the id of every message from the pipe the message arrived on: never
//! from a socket message, and never from anything a message says. A
//! socket client (a sibling instance in the same root included) then
//! reaches the supervisor's entry points only as [`Channel::Client`], and
//! another generation's worker or supervisor only with its own id; the
//! store refuses both. Likewise it cannot read the world: it takes the
//! [`Current`] state of what each scope pins from the daemon at every
//! call, the requesting instance's place in the root's tree included.
//!
//! **Publication** is one decision, [`publication_decision`], taken under
//! the store's lock when the supervisor returns the identity response read
//! in the recipient context: the operation was not stopped (cancel, end,
//! lock, revocation, root exit, epoch, project, revision, limits,
//! recipient, subject, deadline), the generation is the operation's, its
//! state was captured and injected, the identity is exactly the expected
//! account, tenant and role, the root is alive, the epochs are the
//! scope's, everything else the scope took from the world is as it was
//! ([`Current`]: the project, the login item, the target and adapter, the
//! limits, the browser, and a requesting instance still covered by a grant
//! rooted at the scope's root), the attempt's deadline has not passed and
//! its authorization is in force. Every precondition is checked there and
//! nowhere else, so no path publishes around it.

use std::time::Duration;

use envcloak_policy::Now;

use crate::authorization::{Authorization, AuthorizationId, CreditLease, Deadline};
use crate::scope::{
    Account, AdapterId, Environment, Epochs, Fingerprint, Instance, Label, Limits, ProjectScope,
    SignInScope,
};
use crate::statement::{ContextId, Nonce, Options, RequestId, SignInStatement};
use crate::store::OperationKey;

/// An attempt's generation: unique in the daemon, from the store's
/// counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Generation(u64);

impl Generation {
    pub(crate) const fn new(n: u64) -> Self {
        Generation(n)
    }

    pub const fn get(&self) -> u64 {
        self.0
    }
}

/// One attempt's worker: the reaper and driver the daemon starts for it.
/// Made only by the store's [`crate::Effect::StartAttempt`] (a clone of
/// the store's included); the daemon binds it to those processes' pipes
/// and passes it with every message read from them. It names a generation
/// and carries no authority beyond that binding. See the module
/// documentation.
///
/// A generation is read from it,
///
/// ```
/// fn read(w: envcloak_signin::WorkerId) -> envcloak_signin::Generation {
///     w.generation()
/// }
/// ```
///
/// but nothing outside the store makes one from a generation:
///
/// ```compile_fail
/// fn make(g: envcloak_signin::Generation) -> envcloak_signin::WorkerId {
///     envcloak_signin::WorkerId(g)
/// }
/// ```
///
/// ```compile_fail
/// fn make(g: envcloak_signin::Generation) -> envcloak_signin::WorkerId {
///     envcloak_signin::WorkerId::new(g)
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WorkerId(Generation);

impl WorkerId {
    pub(crate) const fn new(g: Generation) -> Self {
        WorkerId(g)
    }

    pub const fn generation(&self) -> Generation {
        self.0
    }
}

/// The control pipe of one generation's browser supervisor. Made only by
/// the store's [`crate::Effect::StartSupervisor`] (a clone of the store's
/// included); the daemon starts the supervisor process with that pipe and
/// passes the id with every message read from it. It names a generation
/// and carries no authority beyond that binding. See the module
/// documentation.
///
/// A generation is read from it,
///
/// ```
/// fn read(s: envcloak_signin::SupervisorId) -> envcloak_signin::Generation {
///     s.generation()
/// }
/// ```
///
/// but nothing outside the store makes one, from a generation or from an
/// operation:
///
/// ```compile_fail
/// fn make(g: envcloak_signin::Generation) -> envcloak_signin::SupervisorId {
///     envcloak_signin::SupervisorId(g)
/// }
/// ```
///
/// ```compile_fail
/// fn make(g: envcloak_signin::Generation) -> envcloak_signin::SupervisorId {
///     envcloak_signin::SupervisorId::new(g)
/// }
/// ```
///
/// ```compile_fail
/// fn make(op: &envcloak_signin::Operation) -> Option<envcloak_signin::SupervisorId> {
///     op.supervisor()
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SupervisorId(Generation);

impl SupervisorId {
    pub(crate) const fn new(g: Generation) -> Self {
        SupervisorId(g)
    }

    pub const fn generation(&self) -> Generation {
        self.0
    }
}

/// Where a message to the store came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Channel {
    /// A client of the socket, identified by its process instance. Never
    /// given declared state, and never able to claim, publish or check.
    Client(Instance),
    /// A browser supervisor's control pipe, as the daemon bound it when it
    /// started that supervisor.
    Supervisor(SupervisorId),
}

/// How far the operation got. See the module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Phase {
    Requested,
    PendingApproval,
    Approved,
    AttemptRunning,
    Captured,
    PublishDecided,
    Published,
}

impl Phase {
    /// Whether the agent's tools can reach (or may already reach) the
    /// context: from the moment the decision said publish.
    pub fn delivered(&self) -> bool {
        matches!(self, Phase::PublishDecided | Phase::Published)
    }
}

/// How an attempt failed, as the worker reported it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AttemptFailure {
    /// The app refused the password.
    CredentialsRejected,
    /// The app refused the one-time codes.
    CodeRejected,
    /// A CAPTCHA, challenge or unknown state (SPEC §6.8, plan D-27).
    HandoffRequired,
    /// A request, frame or form left the target's origins.
    OffOrigin,
    /// The state was broader than declared or in an unsupported format.
    UnsupportedSessionScope,
    /// The intent audit entry could not be written: no worker starts.
    AuditFailed,
    /// The worker or its reaper stopped without a result.
    WorkerLost,
}

/// Why an operation stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StopReason {
    /// `cancel_sign_in` from the owner.
    Cancelled,
    /// `end_sign_in_session` from the owner.
    EndedByOwner,
    /// The daemon locked (a request, sleep, idle, logout or stop).
    Locked,
    /// The owner root exited.
    RootExited,
    /// The daemon, vault or policy epoch changed.
    EpochChanged,
    /// The project's canonical directory, its device and inode, or its
    /// effective sign-in configuration changed, or it no longer opens
    /// (SPEC §10b "A grant ends on").
    ProjectChanged,
    /// The login's authorization revision, the target's or the adapter's
    /// changed, the target's adapter was replaced, the login item was
    /// deleted or reclassified (test to live), or the target was removed.
    RevisionChanged,
    /// The limits the daemon resolves for the scope changed (the tier, the
    /// attempt count, the approval duration, the per-attempt timeout or
    /// the session lifetime).
    LimitsChanged,
    /// The requesting instance exited or the browser was replaced.
    RecipientReplaced,
    /// A grant rooted at the scope's root no longer covers the requesting
    /// instance (SPEC §10b "Match" rules 3 and 4): it left the root's
    /// tree, or a known agent now sits between them.
    SubjectIneligible,
    /// The authorization was revoked (`envcloak grants revoke`; SPEC §10b:
    /// any client may revoke).
    Revoked,
    /// The pending statement expired without a proof.
    StatementExpired,
    /// The authorization ended (lock, root exit, an epoch or revision
    /// change) or its deadline passed: before the attempt started, under
    /// it, or under the delivered session, whose every tool call it
    /// covers.
    AuthorizationEnded,
    /// The attempt's timeout passed.
    AttemptTimedOut,
    /// The session's lifetime passed after delivery.
    SessionExpired,
    /// The worker reported a failure.
    AttemptFailed(AttemptFailure),
    /// The identity read in the recipient context was not exactly the
    /// expected account, tenant and role; nothing was delivered.
    IdentityUnverified,
}

/// The end of an operation: why, whether the context had been delivered,
/// and until when its receipt answers retries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Stop {
    pub reason: StopReason,
    pub delivered: bool,
    pub retry_until: Deadline,
}

/// Local teardown of the worker, the captured state or the delivered
/// context, as the reaper or supervisor confirmed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Cleanup {
    /// Nothing was started that needs tearing down.
    NotNeeded,
    /// Asked for, not yet confirmed.
    Pending,
    /// Confirmed.
    Done,
    /// The close failed: reported, never assumed done.
    Failed,
}

/// The identity the supervisor read in the recipient context.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdentityResponse {
    pub account: Label,
    pub tenant: Option<Label>,
    pub role: Label,
}

impl IdentityResponse {
    /// Whether it is exactly `expected`'s account, tenant and role.
    pub fn matches(&self, expected: &Account) -> bool {
        self.account == expected.account
            && self.tenant == expected.tenant
            && self.role == expected.role
    }
}

/// Where the requesting instance stands against the scope's subject, as
/// the daemon reads it from the kernel at a call. A sign-in keeps SPEC
/// §10b's "Match" rules 1 to 4, so this is rules 3 and 4 for the scope's
/// root and the subject's kind, as `envcloak_policy`'s
/// `SubjectEvidence::covered_by` reads them for the requesting instance's
/// current evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Requester {
    /// It runs, its kernel-verified ancestry holds the scope's root
    /// instance (pid and start time alike), and no known agent sits
    /// between them unless the root is that agent: a grant rooted there
    /// covers it.
    Covered,
    /// It exited: the recipient of the browser tools is gone.
    Exited,
    /// It runs, but a grant rooted at the scope's root no longer covers it:
    /// an ancestor between them exited and it was reparented out of the
    /// root's tree, a known agent now sits between them (an ancestor began
    /// running an agent's executable), or its subject kind no longer
    /// matches the grant's.
    Uncovered,
}

/// The login item as it is now: its authorization revision, and whether
/// it is a test identity or a live one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LoginNow {
    pub revision: u64,
    pub environment: Environment,
}

/// The target as it is now: its revision, and its adapter's id and
/// revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TargetNow {
    pub revision: u64,
    pub adapter: AdapterId,
    pub adapter_revision: u64,
}

/// What a scope took from the world, as the daemon reads it at a call
/// ([`crate::World::current`]): every part of the scope that can change
/// after the request while the scope stays as it was. A scope is fresh
/// while this equals what [`Current::of`] gives for it; any difference
/// ends its authorizations and stops its operations, a delivered session
/// included (SPEC §6.8; §10b "Match" rules 3 to 5 and "A grant ends on").
///
/// The parts of a scope it leaves out cannot change while the scope
/// stands, or are read elsewhere: the root instance (its exit is
/// [`crate::World::alive`]), the digest of the subject's evidence (what
/// identified the subject at the request; its tree now is
/// [`Current::requester`]), the login item and target ids (what is looked
/// up), the expected account, tenant and role, the credential-entry
/// origins, the identity check and the transfer scope (a change of any of
/// them changes the login's authorization revision, SPEC §6.8 "Sign-in
/// scope"), the delivery mode (it has one value), and the epochs
/// ([`crate::World::epochs`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Current {
    /// The project's canonical directory, device and inode and the digest
    /// of its effective sign-in configuration, as the daemon opens them
    /// now; `None` once the directory no longer opens.
    pub project: Option<ProjectScope>,
    /// `None` once the login item was deleted.
    pub login: Option<LoginNow>,
    /// `None` once the target was removed.
    pub target: Option<TargetNow>,
    /// The limits the daemon resolves for the scope's request now, from
    /// the login item, the target and the subject's limits.
    pub limits: Limits,
    /// The generation of the managed browser instance.
    pub browser: u64,
    /// The requesting instance against the scope's subject.
    pub requester: Requester,
}

/// What a world departs from a scope in, the first of these in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Departure {
    Project,
    Revision,
    Limits,
    Recipient,
    Subject,
}

impl Departure {
    pub(crate) fn stop_reason(self) -> StopReason {
        match self {
            Departure::Project => StopReason::ProjectChanged,
            Departure::Revision => StopReason::RevisionChanged,
            Departure::Limits => StopReason::LimitsChanged,
            Departure::Recipient => StopReason::RecipientReplaced,
            Departure::Subject => StopReason::SubjectIneligible,
        }
    }

    fn refusal(self) -> Refusal {
        match self {
            Departure::Project => Refusal::ProjectChanged,
            Departure::Revision => Refusal::RevisionChanged,
            Departure::Limits => Refusal::LimitsChanged,
            Departure::Recipient => Refusal::RecipientChanged,
            Departure::Subject => Refusal::SubjectIneligible,
        }
    }
}

impl Current {
    /// The values `scope` was resolved with: a fresh world for it.
    pub fn of(scope: &SignInScope) -> Current {
        let (a, t) = (scope.account(), scope.target());
        Current {
            project: Some(scope.project().clone()),
            login: Some(LoginNow {
                revision: a.authorization_revision,
                environment: a.environment,
            }),
            target: Some(TargetNow {
                revision: t.revision,
                adapter: t.adapter,
                adapter_revision: t.adapter_revision,
            }),
            limits: scope.limits().clone(),
            browser: scope.delivery().browser,
            requester: Requester::Covered,
        }
    }

    /// Whether `scope` is fresh in it.
    pub fn fresh_for(&self, scope: &SignInScope) -> bool {
        self.departure(scope).is_none()
    }

    /// What in it differs from what `scope` pins, if anything.
    pub(crate) fn departure(&self, scope: &SignInScope) -> Option<Departure> {
        let pinned = Current::of(scope);
        if self.project != pinned.project {
            return Some(Departure::Project);
        }
        if self.login != pinned.login || self.target != pinned.target {
            return Some(Departure::Revision);
        }
        if self.limits != pinned.limits {
            return Some(Departure::Limits);
        }
        match self.requester {
            Requester::Exited => return Some(Departure::Recipient),
            Requester::Uncovered => return Some(Departure::Subject),
            Requester::Covered => {}
        }
        (self.browser != pinned.browser).then_some(Departure::Recipient)
    }
}

/// What the world looks like at the decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub now: Now,
    pub epochs: Epochs,
    pub current: Current,
    pub root_alive: bool,
}

/// Why publication was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Refusal {
    /// The operation was stopped (cancelled, ended, locked, revoked, its
    /// root exited, a deadline passed, ...).
    Stopped,
    /// The message is not from the operation's generation.
    WrongGeneration,
    /// No captured state was injected, or the decision was already taken.
    NotReady,
    /// The identity was not exactly the expected one.
    IdentityUnverified,
    RootExited,
    EpochChanged,
    /// The project changed ([`StopReason::ProjectChanged`]).
    ProjectChanged,
    /// The login item, the target or the adapter changed
    /// ([`StopReason::RevisionChanged`]).
    RevisionChanged,
    /// The limits changed ([`StopReason::LimitsChanged`]).
    LimitsChanged,
    /// The requesting instance exited or the browser was replaced.
    RecipientChanged,
    /// A grant rooted at the scope's root no longer covers the requesting
    /// instance ([`StopReason::SubjectIneligible`]).
    SubjectIneligible,
    /// The attempt's deadline passed.
    Expired,
    /// The authorization ended, was revoked, ran out of time or changed
    /// epochs.
    AuthorizationEnded,
}

/// The serialized decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PublishDecision {
    Publish,
    Refuse(Refusal),
}

/// One sign-in operation, as the store keeps it. Read-only outside the
/// store.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Operation {
    pub(crate) seq: u64,
    pub(crate) key: OperationKey,
    pub(crate) scope: SignInScope,
    pub(crate) fingerprint: Fingerprint,
    pub(crate) request: RequestId,
    pub(crate) nonce: Nonce,
    pub(crate) created_unix: u64,
    pub(crate) statement_deadline: Deadline,
    pub(crate) context: ContextId,
    pub(crate) phase: Phase,
    pub(crate) stop: Option<Stop>,
    pub(crate) authorization: Option<AuthorizationId>,
    pub(crate) lease: Option<CreditLease>,
    pub(crate) generation: Option<Generation>,
    pub(crate) attempt_deadline: Option<Deadline>,
    pub(crate) passwords: u8,
    pub(crate) codes: u8,
    pub(crate) injected: bool,
    pub(crate) session_deadline: Option<Deadline>,
    pub(crate) cleanup: Cleanup,
    pub(crate) revision: u64,
    pub(crate) shown: Option<crate::status::Status>,
}

impl Operation {
    pub fn request(&self) -> RequestId {
        self.request
    }

    pub fn scope(&self) -> &SignInScope {
        &self.scope
    }

    pub fn owner(&self) -> Instance {
        self.scope.owner()
    }

    pub fn context(&self) -> ContextId {
        self.context
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn stop(&self) -> Option<Stop> {
        self.stop
    }

    pub fn authorization(&self) -> Option<AuthorizationId> {
        self.authorization
    }

    pub fn lease(&self) -> Option<CreditLease> {
        self.lease
    }

    /// The attempt's generation, once it started. A value to read, never
    /// a [`WorkerId`] or a [`SupervisorId`].
    pub fn generation(&self) -> Option<Generation> {
        self.generation
    }

    /// When the pending statement expires.
    pub fn statement_deadline(&self) -> Deadline {
        self.statement_deadline
    }

    /// When the attempt times out, once it started.
    pub fn attempt_deadline(&self) -> Option<Deadline> {
        self.attempt_deadline
    }

    /// When the delivered session ends, once publication was decided.
    pub fn session_deadline(&self) -> Option<Deadline> {
        self.session_deadline
    }

    /// Password submissions permitted so far (at most 1).
    pub fn passwords(&self) -> u8 {
        self.passwords
    }

    /// One-time-code submissions permitted so far (at most 2).
    pub fn codes(&self) -> u8 {
        self.codes
    }

    pub fn cleanup(&self) -> Cleanup {
        self.cleanup
    }

    /// What the store last answered for it: its status at its current
    /// revision.
    pub fn status(&self) -> crate::status::Status {
        self.shown
            .unwrap_or_else(|| crate::status::project(self, self.revision))
    }

    /// The statement a proof approves with `options`.
    pub fn statement(&self, options: Options) -> SignInStatement {
        SignInStatement {
            scope: self.scope.clone(),
            request: self.request,
            nonce: self.nonce,
            created_unix: self.created_unix,
            expires_unix: crate::store::wall_secs(&self.statement_deadline),
            options,
            context: self.context,
        }
    }
}

/// Whether to publish `op`'s context now. See the module documentation.
/// `generation` is the one the supervisor's channel carries; `identity`
/// what it read in the recipient context; `authorization` the one whose
/// credit the attempt holds, if the store still has it.
pub fn publication_decision(
    op: &Operation,
    authorization: Option<&Authorization>,
    generation: Generation,
    identity: &IdentityResponse,
    at: &Checkpoint,
) -> PublishDecision {
    use PublishDecision::Refuse;
    if op.stop.is_some() {
        return Refuse(Refusal::Stopped);
    }
    if op.generation != Some(generation) {
        return Refuse(Refusal::WrongGeneration);
    }
    if op.phase != Phase::Captured || !op.injected {
        return Refuse(Refusal::NotReady);
    }
    if !identity.matches(op.scope.account()) {
        return Refuse(Refusal::IdentityUnverified);
    }
    if !at.root_alive {
        return Refuse(Refusal::RootExited);
    }
    if at.epochs != *op.scope.epochs() {
        return Refuse(Refusal::EpochChanged);
    }
    if let Some(d) = at.current.departure(&op.scope) {
        return Refuse(d.refusal());
    }
    if op.attempt_deadline.is_none_or(|d| d.passed(&at.now)) {
        return Refuse(Refusal::Expired);
    }
    if !authorization
        .is_some_and(|a| Some(a.id()) == op.authorization && a.in_force(&at.epochs, &at.now))
    {
        return Refuse(Refusal::AuthorizationEnded);
    }
    PublishDecision::Publish
}

/// How long a stopped operation's receipt answers retries: the published
/// retry window (`retry_until`).
pub const RETRY_WINDOW: Duration = Duration::from_secs(600);
