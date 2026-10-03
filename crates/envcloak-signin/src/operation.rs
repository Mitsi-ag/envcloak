//! One sign-in operation and its serialized publication decision (SPEC
//! §6.8 "Delivery"; R-M2b-27, R-M2b-28, SI-09).
//!
//! **Lifecycle.** An operation moves through [`Phase`]: `requested`
//! (reserved after the retry lookup), `pending_approval` (its statement
//! waits for a proof) or straight to `approved` (a `dev` authorization of
//! the same exact scope covered it and a credit was reserved), then
//! `attempt_running` (the worker holds the credit's lease; attempts on one
//! login are serialized), `captured` (the worker's declared state is held
//! by the daemon, private to EnvCloak), `publish_decided` (the decision
//! below said publish and the supervisor was told) and `published` (the
//! supervisor made the context reachable through the agent's browser
//! tools). It ends `ended`, `cancelled` or `failed` ([`crate::State`]):
//! the end is a [`Stop`] recorded beside the phase, with its reason, so
//! the phase keeps saying how far the attempt got.
//!
//! **Generations and channels** (plan D-31, D-36). Each attempt gets a
//! [`Generation`], unique in the daemon, and the worker's results carry
//! it: a result with another generation is discarded. The generation's
//! browser supervisor is a process the daemon starts; its control pipe is
//! the only [`Channel::Supervisor`], identified by a [`SupervisorId`]
//! that only the operation store makes. Declared state leaves the store
//! only towards that channel, and claim, publish and the per-call check
//! are accepted only from it; a client of the socket ([`Channel::Client`],
//! a sibling `envcloak mcp` in the same root included) is never one.
//!
//! **Publication** is one decision, [`publication_decision`], taken under
//! the store's lock when the supervisor returns the identity response read
//! in the recipient context: the operation was not stopped (cancel, end,
//! lock, root exit, epoch, revision, recipient, deadline), the generation
//! is the operation's, its state was captured and injected, the identity
//! is exactly the expected account, tenant and role, the root is alive,
//! the epochs and revisions are the scope's, the recipient is the scope's,
//! the attempt's deadline has not passed and its authorization is in
//! force. Every precondition is checked there and nowhere else, so no path
//! publishes around it.

use std::time::Duration;

use envcloak_policy::Now;

use crate::authorization::{Authorization, AuthorizationId, CreditLease, Deadline};
use crate::scope::{Account, Epochs, Fingerprint, Instance, Label, SignInScope};
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

/// The control pipe of one generation's browser supervisor. Only the
/// operation store makes one, when the attempt starts; the daemon starts
/// the supervisor process with that pipe and passes the id with every
/// message read from it.
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
    /// A browser supervisor's control pipe.
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
    /// The login's authorization revision, the target's or the adapter's
    /// changed.
    RevisionChanged,
    /// The requesting instance exited or the browser was replaced.
    RecipientReplaced,
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

/// The current values of what a scope pins: the login's authorization
/// revision, the target's and the adapter's revisions, the browser
/// instance's generation, and whether the requesting instance still runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Revisions {
    pub login: u64,
    pub target: u64,
    pub adapter: u64,
    pub browser: u64,
    pub requester_alive: bool,
}

impl Revisions {
    /// The values `scope` was resolved with.
    pub fn of(scope: &SignInScope) -> Revisions {
        Revisions {
            login: scope.account().authorization_revision,
            target: scope.target().revision,
            adapter: scope.target().adapter_revision,
            browser: scope.delivery().browser,
            requester_alive: true,
        }
    }
}

/// What the world looks like at the decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint {
    pub now: Now,
    pub epochs: Epochs,
    pub revisions: Revisions,
    pub root_alive: bool,
}

/// Why publication was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Refusal {
    /// The operation was stopped (cancelled, ended, locked, its root
    /// exited, a deadline passed, ...).
    Stopped,
    /// The message is not from the operation's generation.
    WrongGeneration,
    /// No captured state was injected, or the decision was already taken.
    NotReady,
    /// The identity was not exactly the expected one.
    IdentityUnverified,
    RootExited,
    EpochChanged,
    RevisionChanged,
    RecipientChanged,
    /// The attempt's deadline passed.
    Expired,
    /// The authorization ended, ran out of time or changed epochs.
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

    pub fn generation(&self) -> Option<Generation> {
        self.generation
    }

    /// The generation's supervisor, once the attempt started.
    pub fn supervisor(&self) -> Option<SupervisorId> {
        self.generation.map(SupervisorId::new)
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
    let pinned = Revisions::of(&op.scope);
    if at.revisions.login != pinned.login
        || at.revisions.target != pinned.target
        || at.revisions.adapter != pinned.adapter
    {
        return Refuse(Refusal::RevisionChanged);
    }
    if at.revisions.browser != pinned.browser || !at.revisions.requester_alive {
        return Refuse(Refusal::RecipientChanged);
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
