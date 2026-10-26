//! Worker-side identity verification (`SPEC.md` §6.8 "Identity check", M2 plan
//! gate `b6`, task `M2b-07`).
//!
//! Verifies the signed-in identity in the worker context before any cookie or
//! localStorage value is extracted:
//! - [`CheckKind::Endpoint`]: fetches the declared same-origin endpoint inside
//!   the worker page (checking its URL against [`OriginGuard`] under
//!   [`GuardPhase::IdentityCheck`]) and parses `{ account, tenant, role }`.
//! - [`CheckKind::Element`]: reads the declared selector's text or attributes
//!   (`data-account`, `data-tenant`, `data-role`, or JSON text) on a registered
//!   application origin.
//! - Compares `account`, `tenant`, and `role` byte-for-byte against the
//!   expected identity. Any mismatch stops the attempt with
//!   [`WorkerStopReason::IdentityUnverified`] before a single cookie or storage
//!   item is extracted.

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use envcloak_signin::{
    Account, AttemptFailure, CheckKind, IdentityCheck, IdentityResponse, Label, StopReason,
};

use crate::cdp::CdpClient;
use crate::origin_guard::{GuardPhase, OriginGuard};

/// Reason a sign-in worker stopped without capturing declared state (`M2b-07`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum WorkerStopReason {
    /// The app refused the password (`AttemptFailure::CredentialsRejected`).
    CredentialsRejected,
    /// The app refused the one-time codes (`AttemptFailure::CodeRejected`).
    CodeRejected,
    /// A CAPTCHA, WebAuthn prompt, or unknown login challenge (`AttemptFailure::HandoffRequired`).
    HandoffRequired,
    /// A request, frame, WebSocket, or form left the target's registered origins (`AttemptFailure::OffOrigin`).
    OffOrigin,
    /// The state was broader than declared or in an unsupported format (`AttemptFailure::UnsupportedSessionScope`).
    UnsupportedSessionScope,
    /// The signed-in identity did not match the expected account, tenant, and role (`StopReason::IdentityUnverified`).
    IdentityUnverified,
    /// The worker or its CDP channel stopped unexpectedly (`AttemptFailure::WorkerLost`).
    WorkerLost,
}

impl WorkerStopReason {
    /// Converts this worker stop reason into [`StopReason`].
    pub const fn to_stop_reason(self) -> StopReason {
        match self {
            WorkerStopReason::CredentialsRejected => {
                StopReason::AttemptFailed(AttemptFailure::CredentialsRejected)
            }
            WorkerStopReason::CodeRejected => {
                StopReason::AttemptFailed(AttemptFailure::CodeRejected)
            }
            WorkerStopReason::HandoffRequired => {
                StopReason::AttemptFailed(AttemptFailure::HandoffRequired)
            }
            WorkerStopReason::OffOrigin => StopReason::AttemptFailed(AttemptFailure::OffOrigin),
            WorkerStopReason::UnsupportedSessionScope => {
                StopReason::AttemptFailed(AttemptFailure::UnsupportedSessionScope)
            }
            WorkerStopReason::IdentityUnverified => StopReason::IdentityUnverified,
            WorkerStopReason::WorkerLost => StopReason::AttemptFailed(AttemptFailure::WorkerLost),
        }
    }
}

impl From<AttemptFailure> for WorkerStopReason {
    fn from(f: AttemptFailure) -> Self {
        match f {
            AttemptFailure::CredentialsRejected => WorkerStopReason::CredentialsRejected,
            AttemptFailure::CodeRejected => WorkerStopReason::CodeRejected,
            AttemptFailure::HandoffRequired => WorkerStopReason::HandoffRequired,
            AttemptFailure::OffOrigin => WorkerStopReason::OffOrigin,
            AttemptFailure::UnsupportedSessionScope => WorkerStopReason::UnsupportedSessionScope,
            AttemptFailure::AuditFailed | AttemptFailure::WorkerLost => {
                WorkerStopReason::WorkerLost
            }
        }
    }
}

/// Expected `(account, tenant, role)` tuple for identity verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedIdentity {
    pub account: Label,
    pub tenant: Option<Label>,
    pub role: Label,
}

impl ExpectedIdentity {
    /// Builds [`ExpectedIdentity`] from a scope [`Account`].
    pub fn from_account(account: &Account) -> Self {
        Self {
            account: account.account.clone(),
            tenant: account.tenant.clone(),
            role: account.role.clone(),
        }
    }

    /// Checks whether `response` matches `self` on `account`, `tenant`, and `role`.
    pub fn matches(&self, response: &IdentityResponse) -> bool {
        response.account == self.account
            && response.tenant == self.tenant
            && response.role == self.role
    }
}

/// Parses a JSON value (`{ account, tenant, role }`) into an [`IdentityResponse`]
/// and verifies it against `expected`.
///
/// # Errors
/// Returns [`WorkerStopReason::IdentityUnverified`] if any field is missing,
/// invalid, or does not match `expected`.
pub fn verify_identity_json(
    raw: &Value,
    expected: &ExpectedIdentity,
) -> Result<IdentityResponse, WorkerStopReason> {
    if raw.get("authenticated").and_then(Value::as_bool) == Some(false) {
        return Err(WorkerStopReason::IdentityUnverified);
    }
    let account_str = raw
        .get("account")
        .and_then(Value::as_str)
        .ok_or(WorkerStopReason::IdentityUnverified)?;
    let role_str = raw
        .get("role")
        .and_then(Value::as_str)
        .ok_or(WorkerStopReason::IdentityUnverified)?;
    let tenant_opt = match raw.get("tenant") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s.is_empty() => None,
        Some(Value::String(s)) => {
            Some(Label::new(s).map_err(|_| WorkerStopReason::IdentityUnverified)?)
        }
        _ => return Err(WorkerStopReason::IdentityUnverified),
    };

    let response = IdentityResponse {
        account: Label::new(account_str).map_err(|_| WorkerStopReason::IdentityUnverified)?,
        tenant: tenant_opt,
        role: Label::new(role_str).map_err(|_| WorkerStopReason::IdentityUnverified)?,
    };

    if !expected.matches(&response) {
        return Err(WorkerStopReason::IdentityUnverified);
    }
    Ok(response)
}

/// Executes `check` inside the worker page `session_id` over `cdp`, enforcing
/// `guard`, and verifies the resulting [`IdentityResponse`] against `expected`.
///
/// # Errors
/// Returns [`WorkerStopReason::OffOrigin`] if the current page or endpoint URL
/// is outside the registered application origins, or
/// [`WorkerStopReason::IdentityUnverified`] if the identity check fails or mismatches.
pub fn verify_worker_identity<R: Read, W: Write>(
    cdp: &mut CdpClient<R, W>,
    session_id: &str,
    guard: &mut OriginGuard,
    current_page_url: &str,
    check: &IdentityCheck,
    expected: &ExpectedIdentity,
) -> Result<IdentityResponse, WorkerStopReason> {
    let page_origin = guard
        .check_url(current_page_url, GuardPhase::IdentityCheck, false)
        .map_err(|v| WorkerStopReason::from(guard.record_violation(v)))?;

    let expr = match check.kind {
        CheckKind::Endpoint => {
            let locator = check.locator.as_str();
            let resolved_url = if locator.starts_with("http://") || locator.starts_with("https://")
            {
                locator.to_owned()
            } else if locator.starts_with('/') {
                format!("{page_origin}{locator}")
            } else {
                format!("{page_origin}/{locator}")
            };
            guard
                .check_url(&resolved_url, GuardPhase::IdentityCheck, false)
                .map_err(|v| WorkerStopReason::from(guard.record_violation(v)))?;

            let url_json = serde_json::to_string(&resolved_url)
                .map_err(|_| WorkerStopReason::IdentityUnverified)?;
            format!(
                r#"(() => fetch({url_json}, {{ credentials: "include", headers: {{ "accept": "application/json" }} }}).then(r => r.ok ? r.json() : null).catch(() => null))()"#
            )
        }
        CheckKind::Element => {
            let sel_json = serde_json::to_string(check.locator.as_str())
                .map_err(|_| WorkerStopReason::IdentityUnverified)?;
            format!(
                r#"(() => {{
                    const el = document.querySelector({sel_json});
                    if (!el) return null;
                    const acct = el.getAttribute("data-account");
                    const role = el.getAttribute("data-role");
                    const tenant = el.getAttribute("data-tenant");
                    if (acct && role) {{
                        return {{ account: acct, tenant: tenant || null, role }};
                    }}
                    try {{ return JSON.parse(el.textContent || ""); }} catch (_) {{ return null; }}
                }})()"#
            )
        }
    };

    let eval_res = guard
        .call(
            cdp,
            Some(session_id),
            "Runtime.evaluate",
            json!({
                "expression": expr,
                "awaitPromise": true,
                "returnByValue": true
            }),
        )
        .map_err(WorkerStopReason::from)?;

    let value = eval_res
        .get("result")
        .and_then(|r| r.get("value"))
        .ok_or(WorkerStopReason::IdentityUnverified)?;

    verify_identity_json(value, expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_expected() -> ExpectedIdentity {
        ExpectedIdentity {
            account: Label::new("editor@acme.test").unwrap(),
            tenant: Some(Label::new("t1").unwrap()),
            role: Label::new("editor").unwrap(),
        }
    }

    #[test]
    fn exact_match_succeeds_and_wrong_account_tenant_or_role_is_refused() {
        let expected = sample_expected();

        let ok_json = json!({
            "authenticated": true,
            "account": "editor@acme.test",
            "tenant": "t1",
            "role": "editor"
        });
        assert!(verify_identity_json(&ok_json, &expected).is_ok());

        // Wrong tenant (gate b6)
        let wrong_tenant = json!({
            "authenticated": true,
            "account": "editor@acme.test",
            "tenant": "t2",
            "role": "editor"
        });
        assert_eq!(
            verify_identity_json(&wrong_tenant, &expected),
            Err(WorkerStopReason::IdentityUnverified)
        );

        // Wrong account (gate b6)
        let wrong_account = json!({
            "authenticated": true,
            "account": "other@acme.test",
            "tenant": "t1",
            "role": "editor"
        });
        assert_eq!(
            verify_identity_json(&wrong_account, &expected),
            Err(WorkerStopReason::IdentityUnverified)
        );

        // Wrong role (gate b6)
        let wrong_role = json!({
            "authenticated": true,
            "account": "editor@acme.test",
            "tenant": "t1",
            "role": "admin"
        });
        assert_eq!(
            verify_identity_json(&wrong_role, &expected),
            Err(WorkerStopReason::IdentityUnverified)
        );
    }
}
