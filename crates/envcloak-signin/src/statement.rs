//! The sign-in approval statement (SPEC §6.8 "Approval"; R-M2b-14):
//! `envcloak-signin-statement/1`.
//!
//! A statement wraps one [`SignInScope`] for one operation: the scope, the
//! request id, a fresh daemon nonce, creation and expiry, the options the
//! approver chose (`once`, or `dev` with a window and an attempt budget)
//! and the one recipient-context id reserved for the operation. Its
//! canonical encoding ([`SignInStatement::canonical`], docs/GRANTS.md
//! "Sign-in scope and statement") is the line
//! `envcloak-signin-statement/1\n`, then numbered, length-prefixed fields
//! as in the scope's encoding: 1 the scope's whole encoding, 2 the request
//! id, 3 the nonce, 4 and 5 creation and expiry in Unix seconds (8 bytes
//! each), 6 the options (`1` for once; `2`, the window in seconds as 8
//! bytes and the attempts as 1 byte for dev), 7 the context id (8 bytes).
//! [`SignInStatement::digest`] is its SHA-256, which the approver's proof
//! names.
//!
//! The nonce and the reserved context belong to the statement, never to
//! the scope: [`SignInStatement::lookup_fingerprint`] is the scope's
//! fingerprint alone, so a retry finds its operation whatever nonce the
//! daemon drew for it (SI-07).

use std::fmt;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::scope::{
    Fields, Fingerprint, Limits, MAX_APPROVAL, MAX_DEV_ATTEMPTS, SignInScope, Tier, hex,
};

/// The first line of every sign-in statement (docs/IPC.md "Statement
/// domains").
pub const STATEMENT_DOMAIN: &[u8] = b"envcloak-signin-statement/1\n";
/// The attempt budget a `dev` approval offers unless the person picks
/// another (plan M2b-01).
pub const DEFAULT_DEV_ATTEMPTS: u8 = 3;

/// An operation's request id: 16 random bytes the daemon draws. Opaque and
/// never bearer authority: status and cancel answer only the owner root.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId([u8; 16]);

impl RequestId {
    pub const fn from_bytes(b: [u8; 16]) -> Self {
        RequestId(b)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex(&self.0))
    }
}

impl fmt::Debug for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RequestId({})", hex(&self.0))
    }
}

/// A fresh daemon nonce: 32 random bytes, one per operation.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nonce([u8; 32]);

impl Nonce {
    pub const fn from_bytes(b: [u8; 32]) -> Self {
        Nonce(b)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nonce({})", hex(&self.0))
    }
}

/// The recipient-context id reserved for one operation, after the retry
/// lookup and only for a new operation (SPEC §6.8 "Approval").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContextId(u64);

impl ContextId {
    pub const fn new(n: u64) -> Self {
        ContextId(n)
    }

    pub const fn get(&self) -> u64 {
        self.0
    }
}

/// What the approver chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Options {
    /// One authentication attempt (one password submission and at most
    /// two one-time codes).
    Once,
    /// A rolling window of at most 24 hours from the approval with a
    /// budget of attempts, for this exact scope (SPEC §6.8 `dev`).
    Dev { window: Duration, attempts: u8 },
}

/// Why options were refused. Fixed and value-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OptionsError {
    /// `dev` for a scope whose tier is `each`.
    NotDev,
    /// A window that is zero, not whole seconds, over 24 hours or over the
    /// scope's approval limit.
    Window,
    /// Attempts outside 1 to 5 or over the scope's limit.
    Attempts,
}

impl Options {
    /// The `dev` options offered by default for `limits`: its whole
    /// approval window and [`DEFAULT_DEV_ATTEMPTS`], or fewer if the scope
    /// allows fewer. `Once` for an `each` scope.
    pub fn default_for(limits: &Limits) -> Options {
        match limits.tier() {
            Tier::Each => Options::Once,
            Tier::Dev => Options::Dev {
                window: limits.approval(),
                attempts: DEFAULT_DEV_ATTEMPTS.min(limits.attempts()),
            },
        }
    }

    /// Whether the scope's limits allow these options: `once` always;
    /// `dev` only for a `dev` scope, with a window of whole seconds within
    /// its approval limit and at most 24 hours, and 1 to 5 attempts within
    /// its attempt limit.
    pub fn allowed_by(&self, limits: &Limits) -> Result<(), OptionsError> {
        match *self {
            Options::Once => Ok(()),
            Options::Dev { window, attempts } => {
                if limits.tier() != Tier::Dev {
                    return Err(OptionsError::NotDev);
                }
                if window.is_zero()
                    || window.subsec_nanos() != 0
                    || window > MAX_APPROVAL
                    || window > limits.approval()
                {
                    return Err(OptionsError::Window);
                }
                if attempts == 0 || attempts > MAX_DEV_ATTEMPTS || attempts > limits.attempts() {
                    return Err(OptionsError::Attempts);
                }
                Ok(())
            }
        }
    }

    fn encode(&self) -> Vec<u8> {
        match *self {
            Options::Once => vec![1],
            Options::Dev { window, attempts } => {
                let mut v = Vec::with_capacity(10);
                v.push(2);
                v.extend_from_slice(&window.as_secs().to_be_bytes());
                v.push(attempts);
                v
            }
        }
    }
}

/// One sign-in approval statement. See the module documentation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SignInStatement {
    pub scope: SignInScope,
    pub request: RequestId,
    pub nonce: Nonce,
    /// When the operation was opened, Unix seconds.
    pub created_unix: u64,
    /// When its pending statement expires, Unix seconds.
    pub expires_unix: u64,
    pub options: Options,
    pub context: ContextId,
}

impl SignInStatement {
    /// The canonical encoding. See the module documentation.
    pub fn canonical(&self) -> Vec<u8> {
        let SignInStatement {
            scope,
            request,
            nonce,
            created_unix,
            expires_unix,
            options,
            context,
        } = self;
        let mut e = Fields::new(STATEMENT_DOMAIN);
        e.field(1, &scope.encode());
        e.field(2, request.as_bytes());
        e.field(3, nonce.as_bytes());
        e.field(4, &created_unix.to_be_bytes());
        e.field(5, &expires_unix.to_be_bytes());
        e.field(6, &options.encode());
        e.field(7, &context.get().to_be_bytes());
        e.0
    }

    /// SHA-256 of [`SignInStatement::canonical`]: what a proof approves.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.canonical()).into()
    }

    /// The key a retry is looked up by: the scope's fingerprint, without
    /// the nonce or the reserved context.
    pub fn lookup_fingerprint(&self) -> Fingerprint {
        self.scope.fingerprint()
    }
}
