//! App-role wire types and methods for Secure Enclave unlock, enrolment and
//! signed approvals (SPEC §4.3, §5, §10b; M3 plan M3-08, M3-09).

use envcloak_policy::{ApprovalOptions, PendingDescriptor, PendingId, SubjectKind};
use serde::{Deserialize, Serialize};

use crate::proto::Method;
use crate::view::{ApprovedView, MAX_LISTED_BINDINGS, UnlockedView, View};

/// `app.unlock.begin`: starts a Secure Enclave unlock (SPEC §5 step 2).
/// Returns the unlocker's envelope, a 32-byte random challenge and a fresh
/// single-use X25519 daemon public key kept for 60 seconds.
#[derive(Debug)]
pub struct AppUnlockBegin;

impl Method for AppUnlockBegin {
    const NAME: &'static str = "app.unlock.begin";
    type Params = AppUnlockBeginParams;
    type Output = AppUnlockBeginOutput;
}

/// Parameters of [`AppUnlockBegin`]. When `unlocker_id` is omitted, the
/// daemon uses the vault's first enrolled Secure Enclave unlocker.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppUnlockBeginParams {
    /// 32 lowercase hex characters (`UnlockerId`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unlocker_id: Option<String>,
    /// Agent marker names in the caller's environment (`Claims::from_env`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

/// The HPKE P-256 envelope stored in the vault for a Secure Enclave unlocker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeEnvelopeView {
    /// 65-byte uncompressed P-256 encapsulated public key, lowercase hex (130 chars).
    pub enc: String,
    /// 48-byte AES-256-GCM ciphertext and tag, lowercase hex (96 chars).
    pub ciphertext: String,
}

impl View for SeEnvelopeView {}

/// Answer to [`AppUnlockBegin`]. Metadata and ciphertext only; never the VMK.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppUnlockBeginOutput {
    /// 8 Crockford base32 characters (`PendingId`).
    pub request_id: String,
    /// 32 lowercase hex characters (`UnlockerId`).
    pub unlocker_id: String,
    /// 32 lowercase hex characters (`VaultId`).
    pub vault_id: String,
    /// The vault's key epoch (`1` in M3).
    pub epoch: u32,
    /// 32-byte random challenge, lowercase hex (64 chars).
    pub challenge: String,
    /// The Secure Enclave unlocker's HPKE envelope.
    pub envelope: SeEnvelopeView,
    /// 32-byte single-use X25519 daemon public key, lowercase hex (64 chars).
    pub daemon_eph_pub: String,
}

impl View for AppUnlockBeginOutput {}

/// `app.unlock`: completes a Secure Enclave unlock with the VMK HPKE-sealed
/// to `daemon_eph_pub` with AAD `request_id || challenge` (SPEC §5 steps 3-4).
#[derive(Debug)]
pub struct AppUnlock;

impl Method for AppUnlock {
    const NAME: &'static str = "app.unlock";
    type Params = AppUnlockParams;
    type Output = UnlockedView;
}

/// Parameters of [`AppUnlock`]. `Debug` is redacted so the sealed VMK frame
/// is never printed in diagnostics.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppUnlockParams {
    /// 8 Crockford base32 characters (`PendingId`).
    pub request_id: String,
    /// 80-byte HPKE sealed VMK (`enc (32) || ct_and_tag (48)`), lowercase hex
    /// (160 chars) or standard base64 (108 chars).
    pub sealed: String,
    /// Agent marker names in the caller's environment (`Claims::from_env`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

impl core::fmt::Debug for AppUnlockParams {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AppUnlockParams([REDACTED])")
    }
}

/// `app.unlocker.enroll.begin`: opens a pending `unlocker_add` request for
/// `envcloak approve <id>` (M3 plan D3-08).
#[derive(Debug)]
pub struct AppUnlockerEnrollBegin;

impl Method for AppUnlockerEnrollBegin {
    const NAME: &'static str = "app.unlocker.enroll.begin";
    type Params = AppUnlockerEnrollBeginParams;
    type Output = AppUnlockerEnrollBeginOutput;
}

/// Parameters of [`AppUnlockerEnrollBegin`]. Public keys only; never a
/// private key or `dataRepresentation`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppUnlockerEnrollBeginParams {
    /// 65-byte uncompressed SEC1 P-256 `unlock` public key (130 hex chars or 88 base64 chars).
    pub unlock_pub: String,
    /// 65-byte uncompressed SEC1 P-256 `approve` public key (130 hex chars or 88 base64 chars).
    pub approve_pub: String,
    /// Device label (`1..=128` UTF-8 bytes, no control or format characters).
    pub label: String,
    /// Agent marker names in the caller's environment (`Claims::from_env`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

/// Answer to [`AppUnlockerEnrollBegin`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppUnlockerEnrollBeginOutput {
    /// 8 Crockford base32 characters (`PendingId`).
    pub request: String,
    /// Seconds until the pending request expires.
    pub expires_in_secs: u64,
}

impl View for AppUnlockerEnrollBeginOutput {}

/// `app.unlocker.enroll`: polls the outcome of a pending `unlocker_add`
/// request (`pending`, `enrolled`, `denied` or `expired`).
#[derive(Debug)]
pub struct AppUnlockerEnroll;

impl Method for AppUnlockerEnroll {
    const NAME: &'static str = "app.unlocker.enroll";
    type Params = AppUnlockerEnrollParams;
    type Output = AppUnlockerEnrollOutput;
}

/// Parameters of [`AppUnlockerEnroll`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppUnlockerEnrollParams {
    /// 8 Crockford base32 characters (`PendingId`).
    pub request: String,
    /// Agent marker names in the caller's environment (`Claims::from_env`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

/// Outcome of an unlocker enrolment request (`app.unlocker.enroll`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum AppUnlockerEnrollOutput {
    Pending,
    Enrolled { unlocker_id: String },
    Denied,
    Expired,
}

impl View for AppUnlockerEnrollOutput {}

/// The statement domain string `app.pending.list` names for a pending run
/// request (`envcloak-statement/2`, without the trailing newline).
pub const RUN_STATEMENT_DOMAIN: &str = "envcloak-statement/2";

/// `app.pending.list`: the pending run requests waiting for approval, oldest
/// first (at most 20), with [`PendingView`](crate::view::PendingView)'s row
/// shape plus the statement domain (SPEC §10a, §10b; M3 plan M3-09).
#[derive(Debug)]
pub struct AppPendingList;

impl Method for AppPendingList {
    const NAME: &'static str = "app.pending.list";
    type Params = AppPendingListParams;
    type Output = AppPendingListView;
}

/// Parameters of [`AppPendingList`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppPendingListParams {
    /// Agent marker names in the caller's environment (`Claims::from_env`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

/// Answer to [`AppPendingList`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppPendingListView {
    pub requests: Vec<AppPendingView>,
}

impl View for AppPendingListView {}

impl AppPendingListView {
    /// Whether every row has the canonical shape a daemon sends.
    pub fn well_formed(&self) -> bool {
        let mut seen: Vec<PendingId> = Vec::with_capacity(self.requests.len());
        for r in &self.requests {
            let Some(id) = PendingId::parse(&r.request) else {
                return false;
            };
            if id.to_string() != r.request
                || seen.contains(&id)
                || r.statement_domain != RUN_STATEMENT_DOMAIN
                || r.bindings.len() > MAX_LISTED_BINDINGS
                || (r.more_bindings > 0 && r.bindings.len() < MAX_LISTED_BINDINGS)
                || r.bindings
                    .iter()
                    .any(|b| envcloak_core::vault::Slug::new(b).is_err())
            {
                return false;
            }
            seen.push(id);
        }
        true
    }
}

/// One pending run request row in [`AppPendingListView`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppPendingView {
    /// 8 Crockford base32 characters (`PendingId`).
    pub request: String,
    /// How long it has waited, in seconds of awake time.
    pub age_secs: u64,
    /// How long it may still wait before it expires.
    pub expires_in_secs: u64,
    /// The requester's kind.
    pub kind: SubjectKind,
    /// The agent's display name, when one is involved.
    pub agent: Option<String>,
    /// The project's canonical directory.
    pub project: String,
    /// The slugs of the items its first [`MAX_LISTED_BINDINGS`] bindings
    /// name, in the request's order.
    pub bindings: Vec<String>,
    /// How many of its bindings are not in `bindings`.
    pub more_bindings: u64,
    /// The statement domain prefix without its trailing newline
    /// (`"envcloak-statement/2"`).
    pub statement_domain: String,
}

impl View for AppPendingView {}

/// `app.pending.get`: the full [`PendingDescriptor`] of a pending run request
/// for the app's approval window (SPEC §10b; M3 plan M3-09).
#[derive(Debug)]
pub struct AppPendingGet;

impl Method for AppPendingGet {
    const NAME: &'static str = "app.pending.get";
    type Params = AppPendingGetParams;
    type Output = PendingDescriptor;
}

/// Parameters of [`AppPendingGet`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppPendingGetParams {
    /// 8 Crockford base32 characters (`PendingId`).
    pub request: String,
    /// Agent marker names in the caller's environment (`Claims::from_env`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

/// `app.approve`: approves a pending run request with a P-256 ECDSA signature
/// by the `approve` key of an enrolled Secure Enclave unlocker over the
/// canonical statement digest as a prehash (SPEC §10b; M3 plan M3-09).
#[derive(Debug)]
pub struct AppApprove;

impl Method for AppApprove {
    const NAME: &'static str = "app.approve";
    type Params = AppApproveParams;
    type Output = ApprovedView;
}

/// Parameters of [`AppApprove`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppApproveParams {
    /// 8 Crockford base32 characters (`PendingId`).
    pub request: String,
    pub options: ApprovalOptions,
    /// SHA-256 of the canonical statement, 64 lowercase hex characters.
    pub digest: String,
    /// 64-byte raw P-256 ECDSA signature (`r || s`), 128 hex characters or
    /// 88 standard base64 characters.
    pub signature: String,
    /// Agent marker names in the caller's environment (`Claims::from_env`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}
