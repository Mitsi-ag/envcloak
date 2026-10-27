//! Policy record kind 5: [`SubscriptionRecord`] (D4-09, SPEC §2a-bis, §5).

use crate::money::Money;

use super::super::codec::{Dec, Enc};
use super::super::error::VaultError;
use super::super::items::ItemId;
use super::super::policies::MAX_LIST;
use super::{
    corrupt, dec_item_id, dec_money, enc_item_id, enc_money, non_negative_money_ok,
    opt_spend_str_ok, opt_timestamp_ok, spend_str_ok, timestamp_ok,
};

/// Billing recurrence cadence of a subscription.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BillingCadence {
    Monthly = 1,
    Annual = 2,
    Weekly = 3,
}

impl BillingCadence {
    pub(crate) fn encode(self, e: &mut Enc) {
        e.u8(self as u8);
    }

    pub(crate) fn decode(d: &mut Dec<'_>) -> Result<Self, VaultError> {
        match d.u8()? {
            1 => Ok(BillingCadence::Monthly),
            2 => Ok(BillingCadence::Annual),
            3 => Ok(BillingCadence::Weekly),
            _ => Err(corrupt()),
        }
    }
}

/// A recurring subscription record (policy kind 5, version 1).
#[derive(Clone, PartialEq, Eq)]
pub struct SubscriptionRecord {
    pub name: String,
    pub provider: Option<String>,
    pub account: Option<String>,
    pub amount: Money,
    pub cadence: BillingCadence,
    pub renewal_at: Option<u64>,
    pub linked_items: Vec<ItemId>,
    pub created_at: u64,
    pub updated_at: u64,
}

impl SubscriptionRecord {
    pub fn in_bounds(&self) -> bool {
        let unique_items = self
            .linked_items
            .iter()
            .enumerate()
            .all(|(i, id)| !self.linked_items[..i].contains(id));
        spend_str_ok(&self.name)
            && opt_spend_str_ok(self.provider.as_ref())
            && opt_spend_str_ok(self.account.as_ref())
            && non_negative_money_ok(&self.amount)
            && opt_timestamp_ok(self.renewal_at)
            && self.linked_items.len() <= MAX_LIST
            && unique_items
            && timestamp_ok(self.created_at)
            && timestamp_ok(self.updated_at)
            && self.updated_at >= self.created_at
    }

    pub(crate) fn encode(&self, e: &mut Enc) {
        e.str(&self.name)
            .opt_str(self.provider.as_deref())
            .opt_str(self.account.as_deref());
        enc_money(e, &self.amount);
        self.cadence.encode(e);
        e.opt_u64(self.renewal_at).count(self.linked_items.len());
        for item in &self.linked_items {
            enc_item_id(e, *item);
        }
        e.u64(self.created_at).u64(self.updated_at);
    }

    pub(crate) fn decode(d: &mut Dec<'_>) -> Result<Self, VaultError> {
        let name = d.string()?;
        let provider = d.opt_string()?;
        let account = d.opt_string()?;
        let amount = dec_money(d)?;
        let cadence = BillingCadence::decode(d)?;
        let renewal_at = d.opt_u64()?;
        let n = d.count(16, MAX_LIST)?;
        let mut linked_items = Vec::with_capacity(n);
        for _ in 0..n {
            linked_items.push(dec_item_id(d)?);
        }
        let created_at = d.u64()?;
        let updated_at = d.u64()?;
        Ok(SubscriptionRecord {
            name,
            provider,
            account,
            amount,
            cadence,
            renewal_at,
            linked_items,
            created_at,
            updated_at,
        })
    }
}

impl core::fmt::Debug for SubscriptionRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SubscriptionRecord")
            .field("name_len", &self.name.len())
            .field("provider", &self.provider)
            .field("account_len", &self.account.as_ref().map(String::len))
            .field("amount", &self.amount)
            .field("cadence", &self.cadence)
            .field("renewal_at", &self.renewal_at)
            .field("linked_items", &self.linked_items.len())
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}
