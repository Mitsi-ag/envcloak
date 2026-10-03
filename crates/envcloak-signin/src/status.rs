//! An operation's status (SPEC §6.8 "Tools" and "Retries"; R-M2b-08,
//! SI-10): allowlisted fields only, with a revision that only increases.
//!
//! [`Status`] is what `sign_in_status`, `request_sign_in`'s answer and
//! `cancel_sign_in` report, and what a retry gets back: the request id,
//! the revision, the [`State`], `retry_until` once the operation stopped,
//! and a value-free [`Receipt`] (delivered or not, local cleanup, server
//! revocation and the reason it ended). No key, no label, no origin, no
//! value. The revision orders what a client displays (a reordered poll
//! answer never overwrites a later one); it is not authority.
//!
//! The status is derived from the operation each time it is read (L-09):
//! the store moves an operation past its deadlines before it answers, and
//! raises the revision whenever what it would answer changed.

use std::time::SystemTime;

use crate::operation::{Cleanup, Operation, Phase, StopReason};
use crate::statement::RequestId;

/// Where an operation stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum State {
    Requested,
    PendingApproval,
    Approved,
    AttemptRunning,
    Captured,
    PublishDecided,
    Published,
    /// It stopped after the context was delivered.
    Ended,
    /// The owner cancelled or ended it before delivery.
    Cancelled,
    /// It stopped before delivery for any other reason.
    Failed,
}

/// What the server side did with the session. M2b-01 never claims more
/// than `Unknown`: revocation reads verified only after a copied session
/// is rejected by the app (SPEC §6.8), which a later task checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Revocation {
    /// "server session expiry unknown".
    Unknown,
}

/// The value-free receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Receipt {
    /// The context was delivered: from the publication decision on, the
    /// agent's tools could reach it, and a copy already taken cannot be
    /// recalled.
    pub delivered: bool,
    /// Local teardown, reported apart from the broker's stop.
    pub cleanup: Cleanup,
    /// Server revocation, reported apart from both.
    pub revocation: Revocation,
    /// Why it ended, once it did.
    pub reason: Option<StopReason>,
}

/// An operation's status. See the module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Status {
    pub request: RequestId,
    pub revision: u64,
    pub state: State,
    /// Until when a retry with the same key gets this receipt, once the
    /// operation stopped; the wall clock's reading of its deadline.
    pub retry_until: Option<SystemTime>,
    pub receipt: Receipt,
}

/// What `op` would answer now, at revision `revision`.
pub(crate) fn project(op: &Operation, revision: u64) -> Status {
    let state = match op.stop {
        None => match op.phase {
            Phase::Requested => State::Requested,
            Phase::PendingApproval => State::PendingApproval,
            Phase::Approved => State::Approved,
            Phase::AttemptRunning => State::AttemptRunning,
            Phase::Captured => State::Captured,
            Phase::PublishDecided => State::PublishDecided,
            Phase::Published => State::Published,
        },
        Some(s) if s.delivered => State::Ended,
        Some(s) if matches!(s.reason, StopReason::Cancelled | StopReason::EndedByOwner) => {
            State::Cancelled
        }
        Some(_) => State::Failed,
    };
    Status {
        request: op.request,
        revision,
        state,
        retry_until: op.stop.map(|s| s.retry_until.wall()),
        receipt: Receipt {
            delivered: op.stop.map_or(op.phase.delivered(), |s| s.delivered),
            cleanup: op.cleanup,
            revocation: Revocation::Unknown,
            reason: op.stop.map(|s| s.reason),
        },
    }
}
