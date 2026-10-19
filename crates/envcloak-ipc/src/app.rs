//! App-role wire types and methods for Secure Enclave unlock, enrolment,
//! signed approvals, signed writes, reveal, sealed paste and asks
//! (SPEC §4.3, §5, §6.3, §6.7, §10b; M3 plan M3-08, M3-09, M3-14).

use envcloak_policy::{
    ApprovalOptions, AskSummary, PendingDescriptor, PendingId, RevealDescriptor, SubjectKind,
};
use serde::{Deserialize, Serialize};

use crate::proto::Method;
use crate::view::{
    AddedView, ApprovedView, ClassificationView, LengthClass, LockedView, MAX_LISTED_BINDINGS,
    RemovedView, RotatedView, UnlockedView, View,
};

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

/// `app.unlocker.add`: enrols another Secure Enclave unlocker under a signed
/// `envcloak-write-statement/1` by an already-enrolled `approve` key (SPEC §5,
/// §12; M3 plan M3-14).
#[derive(Debug)]
pub struct AppUnlockerAdd;

impl Method for AppUnlockerAdd {
    const NAME: &'static str = "app.unlocker.add";
    type Params = AppUnlockerAddParams;
    type Output = AppUnlockerAddedView;
}

/// Parameters of [`AppUnlockerAdd`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppUnlockerAddParams {
    /// Device label (`1..=128` UTF-8 bytes, no control or format characters).
    pub label: String,
    /// 65-byte uncompressed SEC1 P-256 `unlock` public key (130 hex or 88 base64 chars).
    pub unlock_pub: String,
    /// 65-byte uncompressed SEC1 P-256 `approve` public key (130 hex or 88 base64 chars).
    pub approve_pub: String,
    /// 32-byte single-use nonce, 64 lowercase hex characters.
    pub nonce: String,
    /// SHA-256 of the canonical `envcloak-write-statement/1`, 64 lowercase hex characters.
    pub digest: String,
    /// 64-byte raw P-256 ECDSA signature (`r || s`), 128 hex or 88 base64 chars.
    pub signature: String,
    #[serde(default)]
    pub created_secs: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

/// Answer to [`AppUnlockerAdd`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppUnlockerAddedView {
    /// 32 lowercase hex characters (`UnlockerId`).
    pub unlocker_id: String,
}

impl View for AppUnlockerAddedView {}

/// `app.unlocker.remove`: removes the passphrase unlocker or a Secure Enclave
/// unlocker under a signed `envcloak-write-statement/1` (SPEC §4.3, §5; M3-14).
/// Never removes the Recovery Kit unlocker (`no_unlocker`) or the last daily
/// unlocker (`last_unlocker`).
#[derive(Debug)]
pub struct AppUnlockerRemove;

impl Method for AppUnlockerRemove {
    const NAME: &'static str = "app.unlocker.remove";
    type Params = AppUnlockerRemoveParams;
    type Output = AppUnlockerRemovedView;
}

/// Parameters of [`AppUnlockerRemove`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppUnlockerRemoveParams {
    /// `"passphrase"` or 32 lowercase hex characters (`UnlockerId`) for a
    /// Secure Enclave unlocker.
    pub unlocker: String,
    /// 32-byte single-use nonce, 64 lowercase hex characters.
    pub nonce: String,
    /// SHA-256 of the canonical `envcloak-write-statement/1`, 64 lowercase hex characters.
    pub digest: String,
    /// 64-byte raw P-256 ECDSA signature (`r || s`), 128 hex or 88 base64 chars.
    pub signature: String,
    #[serde(default)]
    pub created_secs: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

/// Answer to [`AppUnlockerRemove`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppUnlockerRemovedView {
    pub removed: String,
}

impl View for AppUnlockerRemovedView {}

/// `app.items.target`: opens a 60-second signed-write target for `slug`
/// (and `field`), returning a single-use nonce and a daemon X25519 ephemeral
/// public key (M3-14).
#[derive(Debug)]
pub struct AppItemsTarget;

impl Method for AppItemsTarget {
    const NAME: &'static str = "app.items.target";
    type Params = AppItemsTargetParams;
    type Output = AppItemsTargetOutput;
}

/// Parameters of [`AppItemsTarget`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppItemsTargetParams {
    pub slug: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

/// Answer to [`AppItemsTarget`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppItemsTargetOutput {
    /// 8 Crockford base32 characters (`PendingId`).
    pub target: String,
    /// 32-byte single-use nonce, 64 lowercase hex characters.
    pub nonce: String,
    /// 32-byte single-use X25519 daemon public key, 64 lowercase hex characters.
    pub daemon_eph_pub: String,
    /// 32 lowercase hex characters (`VaultId`).
    pub vault_id: String,
    /// 26 Crockford base32 characters (`ItemId`).
    pub item: String,
    pub slug: String,
    /// 26 Crockford base32 characters (`FieldId`), when a single field is resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field_name: Option<String>,
    pub classification: ClassificationView,
    pub prior_count: u8,
    pub grants: u64,
    pub created_secs: u64,
    pub expires_in_secs: u64,
}

impl View for AppItemsTargetOutput {}

/// `app.items.rotate`: replaces an item field's value under a signed
/// `envcloak-write-statement/1`, with the new value HPKE-sealed to the
/// target's `daemon_eph_pub` (M3-14).
#[derive(Debug)]
pub struct AppItemsRotate;

impl Method for AppItemsRotate {
    const NAME: &'static str = "app.items.rotate";
    type Params = AppItemsRotateParams;
    type Output = RotatedView;
}

/// Parameters of [`AppItemsRotate`]. `Debug` is redacted so the sealed value
/// frame is never printed in diagnostics.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppItemsRotateParams {
    /// 8 Crockford base32 characters (`PendingId`) from [`AppItemsTarget`].
    pub target: String,
    /// HPKE-sealed secret value to `daemon_eph_pub` with AAD `target || nonce`
    /// (lowercase hex or standard base64).
    pub sealed_value: String,
    /// SHA-256 of the canonical `envcloak-write-statement/1`, 64 lowercase hex characters.
    pub digest: String,
    /// 64-byte raw P-256 ECDSA signature (`r || s`), 128 hex or 88 base64 chars.
    pub signature: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

impl core::fmt::Debug for AppItemsRotateParams {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AppItemsRotateParams([REDACTED])")
    }
}

/// `app.items.remove`: removes an item under a signed
/// `envcloak-write-statement/1` after writing an encrypted backup of the vault
/// (M3-14).
#[derive(Debug)]
pub struct AppItemsRemove;

impl Method for AppItemsRemove {
    const NAME: &'static str = "app.items.remove";
    type Params = AppItemsRemoveParams;
    type Output = RemovedView;
}

/// Parameters of [`AppItemsRemove`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppItemsRemoveParams {
    /// 8 Crockford base32 characters (`PendingId`) from [`AppItemsTarget`].
    pub target: String,
    /// SHA-256 of the canonical `envcloak-write-statement/1`, 64 lowercase hex characters.
    pub digest: String,
    /// 64-byte raw P-256 ECDSA signature (`r || s`), 128 hex or 88 base64 chars.
    pub signature: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

/// `app.reveal.begin`: starts a reveal in the app, either for an existing
/// `reveal.request` (`request`) or directly for `slug` (and `field`), returning
/// the [`RevealDescriptor`] and its single-use nonce (SPEC §6.7; M3-14).
#[derive(Debug)]
pub struct AppRevealBegin;

impl Method for AppRevealBegin {
    const NAME: &'static str = "app.reveal.begin";
    type Params = AppRevealBeginParams;
    type Output = RevealDescriptor;
}

impl View for RevealDescriptor {}

/// Parameters of [`AppRevealBegin`]. Either `request` or `slug` must be given.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppRevealBeginParams {
    /// Existing pending `reveal.request` id (8 Crockford base32 characters).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,
    /// Item slug when opening a reveal directly from the app.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

/// `app.reveal`: releases a secret value HPKE-sealed to `app_eph_pub` after
/// verifying a signed `envcloak-reveal-statement/1` and durably flushing the
/// `reveal_app` audit entry (SPEC §6.7; M3-14).
#[derive(Debug)]
pub struct AppReveal;

impl Method for AppReveal {
    const NAME: &'static str = "app.reveal";
    type Params = AppRevealParams;
    type Output = AppRevealOutput;
}

/// Parameters of [`AppReveal`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppRevealParams {
    /// 8 Crockford base32 characters (`PendingId`).
    pub request: String,
    /// SHA-256 of the canonical `envcloak-reveal-statement/1`, 64 lowercase hex characters.
    pub digest: String,
    /// 64-byte raw P-256 ECDSA signature (`r || s`), 128 hex or 88 base64 chars.
    pub signature: String,
    /// 32-byte single-use X25519 public key generated by the app (64 hex or 44 base64 chars).
    pub app_eph_pub: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

/// Answer to [`AppReveal`]. `Debug` is redacted so the sealed secret value
/// is never printed in diagnostics.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppRevealOutput {
    /// Secret value HPKE-sealed to `app_eph_pub` with AAD `request || nonce`,
    /// lowercase hex.
    pub sealed_value: String,
}

impl core::fmt::Debug for AppRevealOutput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AppRevealOutput([REDACTED])")
    }
}

/// `app.paste.begin`: opens a 2-minute paste stage with a fresh daemon X25519
/// ephemeral public key (M3-14).
#[derive(Debug)]
pub struct AppPasteBegin;

impl Method for AppPasteBegin {
    const NAME: &'static str = "app.paste.begin";
    type Params = AppPasteBeginParams;
    type Output = AppPasteBeginOutput;
}

/// Parameters of [`AppPasteBegin`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppPasteBeginParams {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

/// Answer to [`AppPasteBegin`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppPasteBeginOutput {
    /// 8 Crockford base32 characters (`PendingId`).
    pub stage: String,
    /// 32-byte single-use X25519 daemon public key, 64 lowercase hex characters.
    pub daemon_eph_pub: String,
    pub expires_in_secs: u64,
}

impl View for AppPasteBeginOutput {}

/// `app.paste.inspect`: opens the HPKE-sealed pasted value into daemon memory
/// (`SecretBytes`, wiped after 2 minutes or on lock) and returns provider,
/// classification and length metadata without storing or logging the secret
/// (M3-14).
#[derive(Debug)]
pub struct AppPasteInspect;

impl Method for AppPasteInspect {
    const NAME: &'static str = "app.paste.inspect";
    type Params = AppPasteInspectParams;
    type Output = AppPasteInspectOutput;
}

/// Parameters of [`AppPasteInspect`]. `Debug` is redacted so the sealed value
/// frame is never printed in diagnostics.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppPasteInspectParams {
    /// 8 Crockford base32 characters (`PendingId`) from [`AppPasteBegin`].
    pub stage: String,
    /// HPKE-sealed secret value to `daemon_eph_pub` with AAD `stage.as_bytes()`
    /// (lowercase hex or standard base64).
    pub sealed: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

impl core::fmt::Debug for AppPasteInspectParams {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AppPasteInspectParams([REDACTED])")
    }
}

/// Answer to [`AppPasteInspect`]. Metadata only; never the secret value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppPasteInspectOutput {
    pub provider: Option<String>,
    pub detected: Option<String>,
    pub ambiguous: bool,
    pub classification: ClassificationView,
    pub length: LengthClass,
    pub suggested_slug: Option<String>,
    pub env_hint: Option<String>,
}

impl View for AppPasteInspectOutput {}

/// `app.paste`: saves the staged value from [`AppPasteInspect`] as a new item,
/// optionally resolving an open ask (`ask`) as `added` without creating any
/// grant (M3-14).
#[derive(Debug)]
pub struct AppPaste;

impl Method for AppPaste {
    const NAME: &'static str = "app.paste";
    type Params = AppPasteParams;
    type Output = AddedView;
}

/// Parameters of [`AppPaste`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppPasteParams {
    /// 8 Crockford base32 characters (`PendingId`) from [`AppPasteInspect`].
    pub stage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_hint: Option<String>,
    #[serde(default)]
    pub allow_short: bool,
    /// Optional ask id (`PendingId`) answered by this paste.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ask: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

/// `app.asks.list`: lists open asks filed by `items.ask`, oldest first (M3-14).
#[derive(Debug)]
pub struct AppAsksList;

impl Method for AppAsksList {
    const NAME: &'static str = "app.asks.list";
    type Params = AppAsksListParams;
    type Output = AppAsksListView;
}

/// Parameters of [`AppAsksList`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppAsksListParams {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

/// Answer to [`AppAsksList`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppAsksListView {
    pub asks: Vec<AskSummary>,
}

impl View for AppAsksListView {}

/// `app.asks.decline`: declines an open ask (`ask_closed` if not open; M3-14).
#[derive(Debug)]
pub struct AppAsksDecline;

impl Method for AppAsksDecline {
    const NAME: &'static str = "app.asks.decline";
    type Params = AppAsksDeclineParams;
    type Output = AppAskDeclinedView;
}

/// Parameters of [`AppAsksDecline`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppAsksDeclineParams {
    /// 8 Crockford base32 characters (`PendingId`).
    pub ask: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

/// Answer to [`AppAsksDecline`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppAskDeclinedView {
    pub declined: String,
}

impl View for AppAskDeclinedView {}

/// `app.lock`: locks the vault for a screen lock, a graphical session resign,
/// or a user lock request from the app (`D3-11`, SPEC §5 "Lock", §10b; M3-16).
/// Answered whatever an `app` peer's evidence is.
#[derive(Debug)]
pub struct AppLock;

impl Method for AppLock {
    const NAME: &'static str = "app.lock";
    type Params = AppLockParams;
    type Output = LockedView;
}

/// Parameters of [`AppLock`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppLockParams {
    pub reason: AppLockReason,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

/// Why [`AppLock`] asked to lock the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppLockReason {
    ScreenLock,
    SessionResign,
    User,
}

/// `app.audit.list`: lists decrypted audit entries for the Activity window,
/// newest first, paginated by `before_seq` (M3-16).
#[derive(Debug)]
pub struct AppAuditList;

impl Method for AppAuditList {
    const NAME: &'static str = "app.audit.list";
    type Params = AppAuditListParams;
    type Output = AppAuditListView;
}

/// Parameters of [`AppAuditList`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppAuditListParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

/// Answer to [`AppAuditList`]. Metadata only; never a secret value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppAuditListView {
    pub entries: Vec<AppAuditEntryView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_before_seq: Option<u64>,
}

impl View for AppAuditListView {}

/// One audit entry returned by [`AppAuditList`] (design §5.4, §12.3; M3-16).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppAuditEntryView {
    pub seq: u64,
    pub time_secs: u64,
    pub kind: String,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<AppAuditSubjectView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub slugs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub argv_masked: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,
}

impl View for AppAuditEntryView {}

/// The subject recorded on an [`AppAuditEntryView`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppAuditSubjectView {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<SubjectKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    pub pid: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_pid: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_exe: Option<String>,
}

impl View for AppAuditSubjectView {}
