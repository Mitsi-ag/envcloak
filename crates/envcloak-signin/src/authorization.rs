//! Sign-in authorizations and attempt credits (SPEC §6.8 "Approval";
//! R-M2b-15, R-M2b-16, SI-08).
//!
//! A proof over a statement opens an [`Authorization`] for that
//! statement's exact scope: `once` (one credit, for the approved operation
//! only, for the scope's approval duration) or `dev` (a budget of 1 to 5
//! credits within a window of at most 24 hours from the approval, and at
//! most the scope's approval duration). Its deadline is fixed when it is
//! made and never moves: nothing a request, a retry, a poll or a new key
//! does extends it, and lock, root exit, an epoch change and a change of
//! the login's authorization revision end it (the operation store does
//! that). While it is in force it covers an attempt's start, the
//! publication decision and every tool call on a delivered session (SPEC
//! §6.8: the supervisor checks the grant on every call); once it is not,
//! each of its operations stops, a delivered one included.
//!
//! A credit is reserved with [`Authorization::reserve_credit`], which
//! checks that the authorization was not ended, that its deadline has not
//! passed and that its epochs are the current ones, and takes the credit
//! in the same call: the check and the reservation are one step under the
//! store's lock. A credit is never given back, whatever happens to the
//! attempt it was reserved for: once credentials may be used, a refund
//! would let failures buy more submissions (SPEC §6.8: "not refunded once
//! credentials may be used"), and the store does not tell the moments
//! apart. So the budget only shrinks.

use std::time::{Duration, SystemTime};

use envcloak_policy::Now;

use crate::scope::{Epochs, Fingerprint, SignInScope};
use crate::statement::{Options, OptionsError};

/// A moment on two clocks, as a grant's end is (`envcloak_policy`): it has
/// passed once either the wall clock or the awake clock reaches it, so
/// neither moving the wall clock back nor sleeping extends it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Deadline {
    wall: SystemTime,
    awake: Duration,
}

impl Deadline {
    /// `d` after `now`. A wall clock too far ahead to add to gives a
    /// deadline that has already passed.
    pub fn after(now: &Now, d: Duration) -> Deadline {
        Deadline {
            wall: now.wall.checked_add(d).unwrap_or(now.wall),
            awake: now.awake.saturating_add(d),
        }
    }

    /// Whether it has passed at `now`.
    pub fn passed(&self, now: &Now) -> bool {
        now.wall >= self.wall || now.awake >= self.awake
    }

    /// Whether it is no later than `other` on both clocks.
    pub fn not_later_than(&self, other: &Deadline) -> bool {
        self.wall <= other.wall && self.awake <= other.awake
    }

    /// On the wall clock, for display.
    pub fn wall(&self) -> SystemTime {
        self.wall
    }
}

/// An authorization's id, from the operation store's counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthorizationId(u64);

impl AuthorizationId {
    pub const fn new(n: u64) -> Self {
        AuthorizationId(n)
    }

    pub const fn get(&self) -> u64 {
        self.0
    }
}

/// `once` or `dev`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthorizationKind {
    Once,
    Dev,
}

/// Why a credit was not reserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BudgetError {
    /// Lock, root exit, an epoch or revision change ended it.
    Ended,
    /// Its deadline passed.
    Expired,
    /// The vault or policy epoch, or the daemon, changed since it was made.
    StaleEpochs,
    /// Every credit was reserved.
    Exhausted,
}

/// One reserved credit: the right to one authentication attempt (one
/// password submission and at most two one-time codes, which the
/// operation store counts on the operation). Held by the store for its
/// operation; never handed back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CreditLease {
    authorization: AuthorizationId,
    credit: u8,
}

impl CreditLease {
    pub fn authorization(&self) -> AuthorizationId {
        self.authorization
    }

    /// Which of the authorization's credits it is, from 1.
    pub fn credit(&self) -> u8 {
        self.credit
    }
}

/// A sign-in authorization. See the module documentation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Authorization {
    id: AuthorizationId,
    scope: SignInScope,
    fingerprint: Fingerprint,
    kind: AuthorizationKind,
    credits: u8,
    used: u8,
    deadline: Deadline,
    ended: bool,
}

impl Authorization {
    /// A `once` authorization for `scope`, approved at `now`: one credit,
    /// until the scope's approval duration has passed. That is the one
    /// lifetime the statement carries for it (the daemon resolves it
    /// already clamped by SPEC §10b's subject limits), so it bounds the
    /// attempt's start, the publication and every tool call on the
    /// delivered session; the attempt itself is bounded again by the
    /// per-attempt timeout from its start.
    pub fn once(id: AuthorizationId, scope: &SignInScope, now: &Now) -> Authorization {
        Authorization {
            id,
            scope: scope.clone(),
            fingerprint: scope.fingerprint(),
            kind: AuthorizationKind::Once,
            credits: 1,
            used: 0,
            deadline: Deadline::after(now, scope.limits().approval()),
            ended: false,
        }
    }

    /// A `dev` authorization for `scope`, approved at `now`: `attempts`
    /// credits until `window` has passed, both within the scope's limits.
    pub fn dev(
        id: AuthorizationId,
        scope: &SignInScope,
        window: Duration,
        attempts: u8,
        now: &Now,
    ) -> Result<Authorization, OptionsError> {
        Options::Dev { window, attempts }.allowed_by(scope.limits())?;
        Ok(Authorization {
            id,
            scope: scope.clone(),
            fingerprint: scope.fingerprint(),
            kind: AuthorizationKind::Dev,
            credits: attempts,
            used: 0,
            deadline: Deadline::after(now, window),
            ended: false,
        })
    }

    /// The authorization `options` open for `scope` at `now`.
    pub fn from_options(
        id: AuthorizationId,
        scope: &SignInScope,
        options: Options,
        now: &Now,
    ) -> Result<Authorization, OptionsError> {
        options.allowed_by(scope.limits())?;
        match options {
            Options::Once => Ok(Authorization::once(id, scope, now)),
            Options::Dev { window, attempts } => {
                Authorization::dev(id, scope, window, attempts, now)
            }
        }
    }

    /// Reserves one credit: refused once it ended, after its deadline,
    /// under other epochs, or with no credit left. The check and the
    /// reservation are this one call.
    pub fn reserve_credit(
        &mut self,
        epochs: &Epochs,
        now: &Now,
    ) -> Result<CreditLease, BudgetError> {
        if self.ended {
            return Err(BudgetError::Ended);
        }
        if self.deadline.passed(now) {
            return Err(BudgetError::Expired);
        }
        if *epochs != *self.scope.epochs() {
            return Err(BudgetError::StaleEpochs);
        }
        if self.used >= self.credits {
            return Err(BudgetError::Exhausted);
        }
        self.used += 1;
        Ok(CreditLease {
            authorization: self.id,
            credit: self.used,
        })
    }

    /// Whether it still authorizes anything at `now` under `epochs`: not
    /// ended, before its deadline, of the current epochs.
    pub fn in_force(&self, epochs: &Epochs, now: &Now) -> bool {
        !self.ended && !self.deadline.passed(now) && *epochs == *self.scope.epochs()
    }

    /// Whether it is for exactly `scope`, field for field (SPEC §10b:
    /// roles have no ordering; no other kind of grant covers a sign-in).
    pub fn for_scope(&self, scope: &SignInScope) -> bool {
        self.fingerprint == scope.fingerprint() && self.scope == *scope
    }

    /// Ends it: no credit is reserved from it again.
    pub fn end(&mut self) {
        self.ended = true;
    }

    pub fn id(&self) -> AuthorizationId {
        self.id
    }

    pub fn kind(&self) -> AuthorizationKind {
        self.kind
    }

    pub fn scope(&self) -> &SignInScope {
        &self.scope
    }

    /// Credits it was opened with.
    pub fn credits(&self) -> u8 {
        self.credits
    }

    /// Credits not yet reserved.
    pub fn remaining(&self) -> u8 {
        self.credits - self.used
    }

    pub fn deadline(&self) -> Deadline {
        self.deadline
    }

    pub fn ended(&self) -> bool {
        self.ended
    }
}
