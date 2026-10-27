//! Policy record kind 10: [`SpendSnapshot`] (D4-09, D4-10, D4-17, SPEC §5, §8).
//!
//! Holds only typed values, `read_at`, [`SpendSource`], [`SpendAttribution`],
//! [`SnapshotResultClass`], per-key typed metrics, and at most
//! [`MAX_DAILY_BUCKETS`] (35) daily buckets; capped at [`MAX_SNAPSHOT_BYTES`]
//! (48 KiB).

use crate::money::Money;

use super::super::codec::{Dec, Enc};
use super::super::error::VaultError;
use super::super::items::ItemId;
use super::{
    LimitResetPeriod, MAX_DAILY_BUCKETS, MAX_SNAPSHOT_BYTES, MAX_SNAPSHOT_KEYS, SpendAccountId,
    SpendAttribution, SpendSource, corrupt, dec_item_id, dec_money, dec_opt_bool, dec_opt_money,
    enc_item_id, enc_money, enc_opt_bool, enc_opt_money, money_ok, non_negative_money_ok,
    opt_timestamp_ok, timestamp_ok,
};

/// Result classification of the latest poll recorded in a [`SpendSnapshot`]
/// (D4-03, D4-04).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SnapshotResultClass {
    Ok = 1,
    InvalidKey = 2,
    RateLimited = 3,
    Redirected = 4,
    TooLarge = 5,
    Malformed = 6,
    TlsFailed = 7,
    Unreachable = 8,
    RefusedByLoader = 9,
}

impl SnapshotResultClass {
    pub(crate) fn encode(self, e: &mut Enc) {
        e.u8(self as u8);
    }

    pub(crate) fn decode(d: &mut Dec<'_>) -> Result<Self, VaultError> {
        match d.u8()? {
            1 => Ok(SnapshotResultClass::Ok),
            2 => Ok(SnapshotResultClass::InvalidKey),
            3 => Ok(SnapshotResultClass::RateLimited),
            4 => Ok(SnapshotResultClass::Redirected),
            5 => Ok(SnapshotResultClass::TooLarge),
            6 => Ok(SnapshotResultClass::Malformed),
            7 => Ok(SnapshotResultClass::TlsFailed),
            8 => Ok(SnapshotResultClass::Unreachable),
            9 => Ok(SnapshotResultClass::RefusedByLoader),
            _ => Err(corrupt()),
        }
    }
}

/// One day's spend bucket in a [`SpendSnapshot`] (D4-17).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotBucket {
    /// Days since 1970-01-01 (`1..=50_000`).
    pub day_index: u32,
    pub spend: Money,
    /// True when apportioned across a multi-day gap between polls (D4-17).
    pub partial: bool,
}

impl SnapshotBucket {
    pub fn in_bounds(&self) -> bool {
        self.day_index <= 50_000 && money_ok(&self.spend)
    }

    pub(crate) fn encode(&self, e: &mut Enc) {
        e.u32(self.day_index);
        enc_money(e, &self.spend);
        e.bool(self.partial);
    }

    pub(crate) fn decode(d: &mut Dec<'_>) -> Result<Self, VaultError> {
        Ok(SnapshotBucket {
            day_index: d.u32()?,
            spend: dec_money(d)?,
            partial: d.bool()?,
        })
    }
}

/// Per-key typed metrics inside an account's [`SpendSnapshot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySpendMetric {
    pub item: ItemId,
    pub attribution: SpendAttribution,
    pub spend_month: Option<Money>,
    pub spend_total: Option<Money>,
    pub limit: Option<Money>,
    pub limit_remaining: Option<Money>,
    pub expires_at: Option<u64>,
    pub invalid: bool,
    pub is_management_key: bool,
}

impl KeySpendMetric {
    pub fn in_bounds(&self) -> bool {
        self.spend_month.as_ref().is_none_or(non_negative_money_ok)
            && self.spend_total.as_ref().is_none_or(non_negative_money_ok)
            && self.limit.as_ref().is_none_or(non_negative_money_ok)
            && self.limit_remaining.as_ref().is_none_or(money_ok)
            && opt_timestamp_ok(self.expires_at)
    }

    pub(crate) fn encode(&self, e: &mut Enc) {
        enc_item_id(e, self.item);
        self.attribution.encode(e);
        enc_opt_money(e, self.spend_month.as_ref());
        enc_opt_money(e, self.spend_total.as_ref());
        enc_opt_money(e, self.limit.as_ref());
        enc_opt_money(e, self.limit_remaining.as_ref());
        e.opt_u64(self.expires_at)
            .bool(self.invalid)
            .bool(self.is_management_key);
    }

    pub(crate) fn decode(d: &mut Dec<'_>) -> Result<Self, VaultError> {
        Ok(KeySpendMetric {
            item: dec_item_id(d)?,
            attribution: SpendAttribution::decode(d)?,
            spend_month: dec_opt_money(d)?,
            spend_total: dec_opt_money(d)?,
            limit: dec_opt_money(d)?,
            limit_remaining: dec_opt_money(d)?,
            expires_at: d.opt_u64()?,
            invalid: d.bool()?,
            is_management_key: d.bool()?,
        })
    }
}

/// Per-account spend snapshot (policy kind 10, version 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendSnapshot {
    pub account: SpendAccountId,
    pub polling_enabled: bool,
    pub read_at: u64,
    pub source: SpendSource,
    pub attribution: SpendAttribution,
    pub last_result: SnapshotResultClass,
    pub balance: Option<Money>,
    pub credit_limit: Option<Money>,
    pub limit_remaining: Option<Money>,
    pub limit_reset: Option<LimitResetPeriod>,
    pub spend_day: Option<Money>,
    pub spend_week: Option<Money>,
    pub spend_month: Option<Money>,
    pub spend_total: Option<Money>,
    pub expires_at: Option<u64>,
    pub is_management_key: Option<bool>,
    pub byok_in_limit: Option<bool>,
    pub key_metrics: Vec<KeySpendMetric>,
    pub buckets: Vec<SnapshotBucket>,
}

impl SpendSnapshot {
    pub fn encoded_len(&self) -> usize {
        let mut e = Enc::new();
        // kind(1) + version(1) + body
        e.u8(10).u8(1);
        self.encode(&mut e);
        e.len()
    }

    pub fn in_bounds(&self) -> bool {
        let keys_unique = self
            .key_metrics
            .iter()
            .enumerate()
            .all(|(i, k)| !self.key_metrics[..i].iter().any(|prev| prev.item == k.item));
        let buckets_sorted = self
            .buckets
            .windows(2)
            .all(|w| w[0].day_index < w[1].day_index);
        self.account.in_bounds()
            && timestamp_ok(self.read_at)
            && self.source.in_bounds()
            && self.balance.as_ref().is_none_or(money_ok)
            && self.credit_limit.as_ref().is_none_or(non_negative_money_ok)
            && self.limit_remaining.as_ref().is_none_or(money_ok)
            && self.spend_day.as_ref().is_none_or(non_negative_money_ok)
            && self.spend_week.as_ref().is_none_or(non_negative_money_ok)
            && self.spend_month.as_ref().is_none_or(non_negative_money_ok)
            && self.spend_total.as_ref().is_none_or(non_negative_money_ok)
            && opt_timestamp_ok(self.expires_at)
            && self.key_metrics.len() <= MAX_SNAPSHOT_KEYS
            && keys_unique
            && self.key_metrics.iter().all(KeySpendMetric::in_bounds)
            && self.buckets.len() <= MAX_DAILY_BUCKETS
            && buckets_sorted
            && self.buckets.iter().all(SnapshotBucket::in_bounds)
            && self.encoded_len() <= MAX_SNAPSHOT_BYTES
    }

    pub(crate) fn encode(&self, e: &mut Enc) {
        self.account.encode(e);
        e.bool(self.polling_enabled).u64(self.read_at);
        self.source.encode(e);
        self.attribution.encode(e);
        self.last_result.encode(e);
        enc_opt_money(e, self.balance.as_ref());
        enc_opt_money(e, self.credit_limit.as_ref());
        enc_opt_money(e, self.limit_remaining.as_ref());
        match self.limit_reset {
            None => {
                e.u8(0);
            }
            Some(r) => {
                e.u8(1);
                r.encode(e);
            }
        }
        enc_opt_money(e, self.spend_day.as_ref());
        enc_opt_money(e, self.spend_week.as_ref());
        enc_opt_money(e, self.spend_month.as_ref());
        enc_opt_money(e, self.spend_total.as_ref());
        e.opt_u64(self.expires_at);
        enc_opt_bool(e, self.is_management_key);
        enc_opt_bool(e, self.byok_in_limit);
        e.count(self.key_metrics.len());
        for km in &self.key_metrics {
            km.encode(e);
        }
        e.count(self.buckets.len());
        for b in &self.buckets {
            b.encode(e);
        }
    }

    pub(crate) fn decode(d: &mut Dec<'_>) -> Result<Self, VaultError> {
        let account = SpendAccountId::decode(d)?;
        let polling_enabled = d.bool()?;
        let read_at = d.u64()?;
        let source = SpendSource::decode(d)?;
        let attribution = SpendAttribution::decode(d)?;
        let last_result = SnapshotResultClass::decode(d)?;
        let balance = dec_opt_money(d)?;
        let credit_limit = dec_opt_money(d)?;
        let limit_remaining = dec_opt_money(d)?;
        let limit_reset = if d.bool()? {
            Some(LimitResetPeriod::decode(d)?)
        } else {
            None
        };
        let spend_day = dec_opt_money(d)?;
        let spend_week = dec_opt_money(d)?;
        let spend_month = dec_opt_money(d)?;
        let spend_total = dec_opt_money(d)?;
        let expires_at = d.opt_u64()?;
        let is_management_key = dec_opt_bool(d)?;
        let byok_in_limit = dec_opt_bool(d)?;
        let key_n = d.count(24, MAX_SNAPSHOT_KEYS)?;
        let mut key_metrics = Vec::with_capacity(key_n);
        for _ in 0..key_n {
            key_metrics.push(KeySpendMetric::decode(d)?);
        }
        let bucket_n = d.count(17, MAX_DAILY_BUCKETS)?;
        let mut buckets = Vec::with_capacity(bucket_n);
        for _ in 0..bucket_n {
            buckets.push(SnapshotBucket::decode(d)?);
        }
        Ok(SpendSnapshot {
            account,
            polling_enabled,
            read_at,
            source,
            attribution,
            last_result,
            balance,
            credit_limit,
            limit_remaining,
            limit_reset,
            spend_day,
            spend_week,
            spend_month,
            spend_total,
            expires_at,
            is_management_key,
            byok_in_limit,
            key_metrics,
            buckets,
        })
    }
}
