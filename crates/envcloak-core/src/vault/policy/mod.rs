//! M4 spend policy records (plan decisions D4-07, D4-09, D4-10, D4-16, D4-17,
//! D4-19; task M4-02): policy record kinds 5 to 11 stored in `policies.sealed`.
//!
//! Every text field in an M4 spend policy record is bounded to
//! [`MAX_SPEND_STR`] (64 bytes, printable ASCII/UTF-8 without control bytes) so
//! no spend record can hold a secret value or unbounded provider text (SPEC
//! §15.2 gate s9). [`SpendSnapshot`] is additionally capped at
//! [`MAX_SNAPSHOT_BYTES`] (48 KiB, D4-09) and [`MAX_DAILY_BUCKETS`] (35 daily
//! buckets, D4-17).

pub mod account_link;
pub mod alert_rule;
pub mod budget;
pub mod control;
pub mod fact;
pub mod snapshot;
pub mod subscription;

use crate::money::{Iso4217, MAX_SCALE, Money};

use super::codec::{Dec, Enc};
use super::error::{VaultError, VaultErrorKind};
use super::items::{ItemId, ProjectId};
use super::policies::SubjectKindRecord;

pub use account_link::AccountLinkRecord;
pub use alert_rule::{AlertRuleKind, AlertRuleRecord};
pub use budget::{BudgetPeriod, BudgetRecord, BudgetScope};
pub use control::{CapEnforcement, CapScope, ControlFactRecord, LimitResetPeriod};
pub use fact::{ManualFactRecord, ManualFactTarget};
pub use snapshot::{KeySpendMetric, SnapshotBucket, SnapshotResultClass, SpendSnapshot};
pub use subscription::{BillingCadence, SubscriptionRecord};

/// Maximum byte length of any string or identifier field in an M4 spend
/// policy record (SPEC §15.2 gate s9: refuses any byte-string field over 64
/// bytes or any unbounded string).
pub const MAX_SPEND_STR: usize = 64;

/// Maximum encoded size in bytes of a [`SpendSnapshot`] record (D4-09: 48 KiB
/// kill-criterion bound, well inside the 64 KiB `MAX_FIELD` row cap).
pub const MAX_SNAPSHOT_BYTES: usize = 48 * 1024;

/// Maximum number of daily spend buckets retained in a [`SpendSnapshot`]
/// (D4-09, D4-17: 35 days).
pub const MAX_DAILY_BUCKETS: usize = 35;

/// Maximum number of per-key metric entries in one account's [`SpendSnapshot`].
pub const MAX_SNAPSHOT_KEYS: usize = 256;

/// Maximum number of alert threshold percentages on a [`BudgetRecord`].
pub const MAX_THRESHOLDS: usize = 8;

/// Earliest plausible Unix timestamp for bounded poll/spend timestamps
/// (1970-01-01T00:00:00Z).
pub const MIN_SPEND_TIMESTAMP: u64 = 0;

/// Latest plausible Unix timestamp for bounded poll/spend timestamps
/// (2100-01-01T00:00:00Z = 4,102,444,800).
pub const MAX_SPEND_TIMESTAMP: u64 = 4_102_444_800;

pub(crate) fn corrupt() -> VaultError {
    VaultErrorKind::Corrupt.into()
}

/// Checks that `s` is 1 to [`MAX_SPEND_STR`] bytes and contains no ASCII
/// control characters.
pub fn spend_str_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_SPEND_STR && !s.bytes().any(|b| b < 0x20 || b == 0x7f)
}

pub(crate) fn opt_spend_str_ok(s: Option<&String>) -> bool {
    s.is_none_or(|v| spend_str_ok(v))
}

pub(crate) fn timestamp_ok(ts: u64) -> bool {
    ts <= MAX_SPEND_TIMESTAMP
}

pub(crate) fn opt_timestamp_ok(ts: Option<u64>) -> bool {
    ts.is_none_or(timestamp_ok)
}

pub(crate) fn money_ok(m: &Money) -> bool {
    m.scale() <= MAX_SCALE && m.within_poll_bounds()
}

pub(crate) fn non_negative_money_ok(m: &Money) -> bool {
    money_ok(m) && m.minor() >= 0
}

pub(crate) fn positive_money_ok(m: &Money) -> bool {
    money_ok(m) && m.minor() > 0
}

pub(crate) fn enc_money(e: &mut Enc, m: &Money) {
    e.u64(m.minor() as u64)
        .u8(m.scale())
        .raw(&m.currency().as_bytes());
}

pub(crate) fn dec_money(d: &mut Dec<'_>) -> Result<Money, VaultError> {
    let minor = d.u64()? as i64;
    let scale = d.u8()?;
    let cur_bytes = d.array::<3>()?;
    let currency = Iso4217::from_bytes(cur_bytes).map_err(|_| corrupt())?;
    Money::new(minor, scale, currency).map_err(|_| corrupt())
}

pub(crate) fn enc_opt_money(e: &mut Enc, m: Option<&Money>) {
    match m {
        None => {
            e.u8(0);
        }
        Some(m) => {
            e.u8(1);
            enc_money(e, m);
        }
    }
}

pub(crate) fn dec_opt_money(d: &mut Dec<'_>) -> Result<Option<Money>, VaultError> {
    if d.bool()? {
        dec_money(d).map(Some)
    } else {
        Ok(None)
    }
}

pub(crate) fn enc_opt_bool(e: &mut Enc, v: Option<bool>) {
    match v {
        None => {
            e.u8(0);
        }
        Some(b) => {
            e.u8(1).bool(b);
        }
    }
}

pub(crate) fn dec_opt_bool(d: &mut Dec<'_>) -> Result<Option<bool>, VaultError> {
    if d.bool()? {
        d.bool().map(Some)
    } else {
        Ok(None)
    }
}

pub(crate) fn enc_subject_kind(e: &mut Enc, s: SubjectKindRecord) {
    e.u8(s as u8);
}

pub(crate) fn dec_subject_kind(d: &mut Dec<'_>) -> Result<SubjectKindRecord, VaultError> {
    match d.u8()? {
        1 => Ok(SubjectKindRecord::Terminal),
        2 => Ok(SubjectKindRecord::Agent),
        3 => Ok(SubjectKindRecord::Unknown),
        _ => Err(corrupt()),
    }
}

/// Identifies a provider account in spend records (D4-10): `(provider,
/// account)`, where `account` is `org_id`, else `email`, else `label`, or
/// `"default"`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpendAccountId {
    pub provider: String,
    pub account: String,
}

impl SpendAccountId {
    pub fn in_bounds(&self) -> bool {
        spend_str_ok(&self.provider) && spend_str_ok(&self.account)
    }

    pub(crate) fn encode(&self, e: &mut Enc) {
        e.str(&self.provider).str(&self.account);
    }

    pub(crate) fn decode(d: &mut Dec<'_>) -> Result<Self, VaultError> {
        Ok(SpendAccountId {
            provider: d.string()?,
            account: d.string()?,
        })
    }
}

impl core::fmt::Debug for SpendAccountId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SpendAccountId")
            .field("provider", &self.provider)
            .field("account_len", &self.account.len())
            .finish()
    }
}

/// Provenance of a spend or control metric (D4-10).
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum SpendSource {
    /// Read directly from a provider endpoint by a daemon-started poller.
    Poll,
    /// Entered by a user via `spend set`, with the caller's subject kind.
    Manual { subject: SubjectKindRecord },
    /// Reported by an external client via `spend.ingest`, with the caller's
    /// subject kind and the tool name the client claimed (e.g. `"codexbar"`).
    ClientReported {
        subject: SubjectKindRecord,
        tool: String,
    },
}

impl SpendSource {
    pub fn in_bounds(&self) -> bool {
        match self {
            SpendSource::Poll | SpendSource::Manual { .. } => true,
            SpendSource::ClientReported { tool, .. } => spend_str_ok(tool),
        }
    }

    pub const fn is_trusted_poll(&self) -> bool {
        matches!(self, SpendSource::Poll)
    }

    pub(crate) fn encode(&self, e: &mut Enc) {
        match self {
            SpendSource::Poll => {
                e.u8(1);
            }
            SpendSource::Manual { subject } => {
                e.u8(2);
                enc_subject_kind(e, *subject);
            }
            SpendSource::ClientReported { subject, tool } => {
                e.u8(3);
                enc_subject_kind(e, *subject);
                e.str(tool);
            }
        }
    }

    pub(crate) fn decode(d: &mut Dec<'_>) -> Result<Self, VaultError> {
        match d.u8()? {
            1 => Ok(SpendSource::Poll),
            2 => Ok(SpendSource::Manual {
                subject: dec_subject_kind(d)?,
            }),
            3 => Ok(SpendSource::ClientReported {
                subject: dec_subject_kind(d)?,
                tool: d.string()?,
            }),
            _ => Err(corrupt()),
        }
    }
}

impl core::fmt::Debug for SpendSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SpendSource::Poll => f.write_str("Poll"),
            SpendSource::Manual { subject } => {
                f.debug_struct("Manual").field("subject", subject).finish()
            }
            SpendSource::ClientReported { subject, tool } => f
                .debug_struct("ClientReported")
                .field("subject", subject)
                .field("tool_len", &tool.len())
                .finish(),
        }
    }
}

/// How a spend figure is attributed to a key or account (D4-10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum SpendAttribution {
    SameKey = 1,
    AdminMatchedByHint = 2,
    AdminLinkedByPerson = 3,
    AccountWide = 4,
    Manual = 5,
}

impl SpendAttribution {
    pub(crate) fn encode(self, e: &mut Enc) {
        e.u8(self as u8);
    }

    pub(crate) fn decode(d: &mut Dec<'_>) -> Result<Self, VaultError> {
        match d.u8()? {
            1 => Ok(SpendAttribution::SameKey),
            2 => Ok(SpendAttribution::AdminMatchedByHint),
            3 => Ok(SpendAttribution::AdminLinkedByPerson),
            4 => Ok(SpendAttribution::AccountWide),
            5 => Ok(SpendAttribution::Manual),
            _ => Err(corrupt()),
        }
    }
}

pub(crate) fn enc_item_id(e: &mut Enc, id: ItemId) {
    e.raw(id.as_bytes());
}

pub(crate) fn dec_item_id(d: &mut Dec<'_>) -> Result<ItemId, VaultError> {
    Ok(ItemId::from_bytes(d.array()?))
}

pub(crate) fn enc_project_id(e: &mut Enc, id: ProjectId) {
    e.raw(id.as_bytes());
}

pub(crate) fn dec_project_id(d: &mut Dec<'_>) -> Result<ProjectId, VaultError> {
    Ok(ProjectId::from_bytes(d.array()?))
}
