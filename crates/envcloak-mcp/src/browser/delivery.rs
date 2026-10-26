//! Session delivery and teardown pipeline (`M2b-08`, SPEC §7.6, decisions
//! D-03, D-04, D-17, D-30, D-31, SI-16, and `cycle342`).
//!
//! Coordinates creating the private recipient `BrowserContext`, injecting only
//! the declared cookies and `localStorage` entries, verifying the post-import
//! cookie table (`cycle342`) and optional D-31 identity check, publishing the
//! context to the host's MCP browser tools only after all checks pass, and
//! reporting the three distinct stop outcomes on session end or cancel:
//! broker stop, local cleanup (`cleaned` vs `cleanup_failed`), and server
//! session revocation (`verified` vs `server session expiry unknown`).

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::supervisor::{
    BrowserSupervisor, DeclaredSecretState, ExpectedIdentity, IdentityResponse, SupervisorError,
};

/// Plan for delivering a verified session into a [`BrowserSupervisor`] for one
/// sign-in attempt generation.
#[derive(Debug, Clone)]
pub struct SessionDeliveryPlan {
    pub generation: String,
    pub declared_state: Value,
    pub identity_check: Option<(Value, ExpectedIdentity)>,
}

/// Receipt returned when a session is delivered and published into the
/// hosted browser supervisor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionDeliveryReceipt {
    pub generation: String,
    pub published: bool,
    pub identity_response: Option<IdentityResponse>,
}

/// Outcome of stopping the MCP browser tool broker on session end or cancel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerStopOutcome {
    /// Dispatch of `browser_*` tools for this generation is stopped.
    Stopped,
}

/// Outcome of closing the local recipient `BrowserContext` and terminating
/// the generation's browser helper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupOutcome {
    /// Local context closed and helper terminated cleanly.
    Cleaned,
    /// Local context close or helper teardown failed; stays visible in receipt.
    CleanupFailed,
}

impl CleanupOutcome {
    /// Machine-readable outcome string (`cleaned` or `cleanup_failed`).
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Cleaned => "cleaned",
            Self::CleanupFailed => "cleanup_failed",
        }
    }
}

/// Outcome of server-side session revocation on session end or cancel (b4, b10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationOutcome {
    /// The target declared no revocation endpoint, or revocation could not be
    /// verified: "server session expiry unknown".
    Unknown,
    /// The target's revocation endpoint was called and a copied session was
    /// subsequently rejected by the application.
    Verified,
}

impl RevocationOutcome {
    /// Human- and machine-readable description of the server revocation state.
    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            Self::Unknown => "server session expiry unknown",
            Self::Verified => "revoked",
        }
    }
}

/// Three-part stop outcome reported when a sign-in session ends or is cancelled
/// (Gate `b10`, R-M2b-47).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StopOutcomes {
    pub delivered: bool,
    pub broker: BrokerStopOutcome,
    pub cleanup: CleanupOutcome,
    pub revocation: RevocationOutcome,
}

/// Delivers a declared session (`SessionDeliveryPlan`) into `supervisor`:
/// 1. Creates the private recipient `BrowserContext` bound to `plan.generation`.
/// 2. Injects `plan.declared_state` over the private control pipe (refusing with
///    `traced` if under a tracer, or `unsupported_session_scope` if scope or
///    `cycle342` post-`addCookies` cookie metadata verification fails).
/// 3. Runs the D-31 identity check if present (refusing with `identity_unverified`
///    and leaving the context unpublished on mismatch), then publishes the context.
pub fn deliver_session(
    supervisor: &mut BrowserSupervisor,
    plan: &SessionDeliveryPlan,
) -> Result<SessionDeliveryReceipt, SupervisorError> {
    supervisor.create_context(&plan.generation)?;
    supervisor.inject_state(&plan.generation, plan.declared_state.clone())?;
    let identity_response = if let Some((check, expected)) = &plan.identity_check {
        Some(supervisor.verify_and_publish(&plan.generation, check.clone(), expected)?)
    } else {
        supervisor.publish(&plan.generation)?;
        None
    };
    Ok(SessionDeliveryReceipt {
        generation: plan.generation.clone(),
        published: true,
        identity_response,
    })
}

/// Delivers a [`DeclaredSecretState`] (carrying `SecretString` cookie and
/// `localStorage` values) into `supervisor` and publishes it after optional
/// D-31 identity verification.
pub fn deliver_secret_session(
    supervisor: &mut BrowserSupervisor,
    generation: &str,
    state: &DeclaredSecretState,
    identity_check: Option<(&str, &ExpectedIdentity)>,
) -> Result<SessionDeliveryReceipt, SupervisorError> {
    supervisor.create_context(generation)?;
    supervisor.inject_secret_state(generation, state)?;
    let identity_response = if let Some((url, expected)) = identity_check {
        Some(supervisor.verify_and_publish(generation, json!({ "url": url }), expected)?)
    } else {
        supervisor.publish(generation)?;
        None
    };
    Ok(SessionDeliveryReceipt {
        generation: generation.to_owned(),
        published: true,
        identity_response,
    })
}

/// Ends or cancels a sign-in session on `supervisor`, stopping broker dispatch,
/// closing the local recipient context, and recording the three separate
/// outcomes (`broker`, `cleanup`, `revocation`).
pub fn end_session(
    supervisor: &mut BrowserSupervisor,
    generation: &str,
    delivered: bool,
    revocation_verified: bool,
) -> StopOutcomes {
    supervisor.set_lease_active(false);
    let cleanup = match supervisor.close(generation) {
        Ok(_) => CleanupOutcome::Cleaned,
        Err(_) => CleanupOutcome::CleanupFailed,
    };
    let revocation = if revocation_verified {
        RevocationOutcome::Verified
    } else {
        RevocationOutcome::Unknown
    };
    StopOutcomes {
        delivered,
        broker: BrokerStopOutcome::Stopped,
        cleanup,
        revocation,
    }
}
