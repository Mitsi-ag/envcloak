//! Policy record kind 8: [`ManualFactRecord`] (D4-09, D4-10, D4-15, SPEC §5, §8).

use crate::money::Money;

use super::super::codec::{Dec, Enc};
use super::super::error::VaultError;
use super::super::items::ItemId;
use super::{
    SpendAccountId, SpendAttribution, SpendSource, corrupt, dec_item_id, dec_opt_money,
    enc_item_id, enc_opt_money, money_ok, non_negative_money_ok, opt_spend_str_ok,
    opt_timestamp_ok, timestamp_ok,
};

/// Target of a manual or client-reported spend fact or control fact.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ManualFactTarget {
    Account(SpendAccountId),
    Key(ItemId),
}

impl ManualFactTarget {
    pub fn in_bounds(&self) -> bool {
        match self {
            ManualFactTarget::Account(a) => a.in_bounds(),
            ManualFactTarget::Key(_) => true,
        }
    }

    pub(crate) fn encode(&self, e: &mut Enc) {
        match self {
            ManualFactTarget::Account(a) => {
                e.u8(1);
                a.encode(e);
            }
            ManualFactTarget::Key(id) => {
                e.u8(2);
                enc_item_id(e, *id);
            }
        }
    }

    pub(crate) fn decode(d: &mut Dec<'_>) -> Result<Self, VaultError> {
        match d.u8()? {
            1 => Ok(ManualFactTarget::Account(SpendAccountId::decode(d)?)),
            2 => Ok(ManualFactTarget::Key(dec_item_id(d)?)),
            _ => Err(corrupt()),
        }
    }
}

/// A manual or client-reported spend fact (policy kind 8, version 1): balance,
/// month-to-date spend, renewal date, or plan name.
#[derive(Clone, PartialEq, Eq)]
pub struct ManualFactRecord {
    pub target: ManualFactTarget,
    /// Balance may be negative (e.g. Moonshot cash balance, D4-02).
    pub balance: Option<Money>,
    pub spend_mtd: Option<Money>,
    pub renewal_at: Option<u64>,
    pub plan: Option<String>,
    pub read_at: u64,
    pub source: SpendSource,
    pub attribution: SpendAttribution,
}

impl ManualFactRecord {
    pub fn in_bounds(&self) -> bool {
        let has_any = self.balance.is_some()
            || self.spend_mtd.is_some()
            || self.renewal_at.is_some()
            || self.plan.is_some();
        has_any
            && self.target.in_bounds()
            && self.balance.as_ref().is_none_or(money_ok)
            && self.spend_mtd.as_ref().is_none_or(non_negative_money_ok)
            && opt_timestamp_ok(self.renewal_at)
            && opt_spend_str_ok(self.plan.as_ref())
            && timestamp_ok(self.read_at)
            && self.source.in_bounds()
    }

    pub(crate) fn encode(&self, e: &mut Enc) {
        self.target.encode(e);
        enc_opt_money(e, self.balance.as_ref());
        enc_opt_money(e, self.spend_mtd.as_ref());
        e.opt_u64(self.renewal_at)
            .opt_str(self.plan.as_deref())
            .u64(self.read_at);
        self.source.encode(e);
        self.attribution.encode(e);
    }

    pub(crate) fn decode(d: &mut Dec<'_>) -> Result<Self, VaultError> {
        let target = ManualFactTarget::decode(d)?;
        let balance = dec_opt_money(d)?;
        let spend_mtd = dec_opt_money(d)?;
        let renewal_at = d.opt_u64()?;
        let plan = d.opt_string()?;
        let read_at = d.u64()?;
        let source = SpendSource::decode(d)?;
        let attribution = SpendAttribution::decode(d)?;
        Ok(ManualFactRecord {
            target,
            balance,
            spend_mtd,
            renewal_at,
            plan,
            read_at,
            source,
            attribution,
        })
    }
}

impl core::fmt::Debug for ManualFactRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ManualFactRecord")
            .field("target", &self.target)
            .field("balance", &self.balance)
            .field("spend_mtd", &self.spend_mtd)
            .field("renewal_at", &self.renewal_at)
            .field("plan_len", &self.plan.as_ref().map(String::len))
            .field("read_at", &self.read_at)
            .field("source", &self.source)
            .field("attribution", &self.attribution)
            .finish()
    }
}
