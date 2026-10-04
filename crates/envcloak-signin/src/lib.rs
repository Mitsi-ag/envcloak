//! The dev sign-in contract (SPEC §6.8, milestone M2b): the immutable
//! sign-in scope and its canonical encoding, the approval statement
//! (`envcloak-signin-statement/1`), the operation store keyed by the owner
//! root, the daemon instance and `operation_key`, authorizations and
//! attempt credits, the operation lifecycle and its serialized publication
//! decision, and the TOTP function.
//!
//! Pure code: no I/O, and the clock is injected, so the daemon can call it
//! as its only implementation of the contract and tests can enumerate every
//! interleaving of its events. Like every crate but `envcloak-sys`, it
//! forbids `unsafe`.
//!
//! - [`scope`]: [`SignInScope`], its typed parts, its encoding and its
//!   fingerprint (R-M2b-11, R-M2b-12).
//! - [`statement`]: [`SignInStatement`] and the approver's [`Options`]
//!   (R-M2b-14).
//! - [`authorization`]: [`Authorization`] (`once` or `dev`), its fixed
//!   [`Deadline`] and [`CreditLease`]s that are never refunded (R-M2b-15,
//!   R-M2b-16).
//! - [`operation`]: one [`Operation`], its [`Phase`]s, the generation's
//!   supervisor [`Channel`] and [`publication_decision`] (R-M2b-27,
//!   R-M2b-28).
//! - [`status`]: the allowlisted [`Status`] with its revision (R-M2b-08).
//! - [`store`]: the [`OperationStore`]: retries and conflicts, owners,
//!   bounds, approvals, the worker's and the supervisor's messages, lock,
//!   root exit, epochs, revisions and the clock (R-M2b-13, R-M2b-17).
//!
//! The TOTP function joins with plan task M2b-03. The contract's
//! invariants are checked by exhaustive enumeration of event orderings in
//! `tests/enumeration.rs`.

pub mod authorization;
pub mod operation;
pub mod scope;
pub mod statement;
pub mod status;
pub mod store;

pub use authorization::{
    Authorization, AuthorizationId, AuthorizationKind, BudgetError, CreditLease, Deadline,
};
pub use operation::{
    AttemptFailure, Channel, Checkpoint, Cleanup, Generation, IdentityResponse, Operation, Phase,
    PublishDecision, RETRY_WINDOW, Refusal, Revisions, Stop, StopReason, SupervisorId,
    publication_decision,
};
pub use scope::{
    Account, AdapterId, CheckKind, CookieDomain, CookiePartition, CookiePath, DaemonInstance,
    DeclaredCookie, DeclaredStorage, Delivery, DeliveryMode, Environment, Epochs, Fingerprint,
    Host, HostName, IdentityCheck, Instance, Label, Limits, Origin, ProjectScope, Scheme,
    ScopeError, SignInScope, Site, SortedSet, Subject, Target, TargetId, Tier, TransferScope,
};
pub use statement::{
    ContextId, DEFAULT_DEV_ATTEMPTS, Nonce, Options, OptionsError, RequestId, SignInStatement,
};
pub use status::{Receipt, Revocation, State, Status};
pub use store::{
    ApproveError, AttemptError, ChannelRefused, Discarded, Effect, Fresh, Injection, KeyError,
    Lookup, NotFound, OperationKey, OperationStore, Request, RequestError, Step, StoreLimits,
    World,
};
