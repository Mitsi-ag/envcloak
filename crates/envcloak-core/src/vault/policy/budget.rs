//! Policy record kind 6: [`BudgetRecord`] (D4-07, D4-09, D4-17, SPEC §2a-bis, §5).

use crate::money::Money;

use super::super::codec::{Dec, Enc};
use super::super::error::VaultError;
use super::super::items::{ItemId, ProjectId};
use super::{
    MAX_THRESHOLDS, SpendAccountId, corrupt, dec_item_id, dec_money, dec_project_id, enc_item_id,
    enc_money, enc_project_id, positive_money_ok, spend_str_ok, timestamp_ok,
};

/// Scope a budget or alert rule applies to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BudgetScope {
    Key(ItemId),
    Provider(String),
    Project(ProjectId),
    Account(SpendAccountId),
}

impl BudgetScope {
    pub fn in_bounds(&self) -> bool {
        match self {
            BudgetScope::Key(_) | BudgetScope::Project(_) => true,
            BudgetScope::Provider(p) => spend_str_ok(p),
            BudgetScope::Account(a) => a.in_bounds(),
        }
    }

    pub(crate) fn encode(&self, e: &mut Enc) {
        match self {
            BudgetScope::Key(id) => {
                e.u8(1);
                enc_item_id(e, *id);
            }
            BudgetScope::Provider(p) => {
                e.u8(2).str(p);
            }
            BudgetScope::Project(id) => {
                e.u8(3);
                enc_project_id(e, *id);
            }
            BudgetScope::Account(a) => {
                e.u8(4);
                a.encode(e);
            }
        }
    }

    pub(crate) fn decode(d: &mut Dec<'_>) -> Result<Self, VaultError> {
        match d.u8()? {
            1 => Ok(BudgetScope::Key(dec_item_id(d)?)),
            2 => Ok(BudgetScope::Provider(d.string()?)),
            3 => Ok(BudgetScope::Project(dec_project_id(d)?)),
            4 => Ok(BudgetScope::Account(SpendAccountId::decode(d)?)),
            _ => Err(corrupt()),
        }
    }
}

/// Reset period of a budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BudgetPeriod {
    Monthly = 1,
    Daily = 2,
    Weekly = 3,
}

impl BudgetPeriod {
    pub(crate) fn encode(self, e: &mut Enc) {
        e.u8(self as u8);
    }

    pub(crate) fn decode(d: &mut Dec<'_>) -> Result<Self, VaultError> {
        match d.u8()? {
            1 => Ok(BudgetPeriod::Monthly),
            2 => Ok(BudgetPeriod::Daily),
            3 => Ok(BudgetPeriod::Weekly),
            _ => Err(corrupt()),
        }
    }
}

/// A budget record (policy kind 6, version 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetRecord {
    pub scope: BudgetScope,
    pub amount: Money,
    pub period: BudgetPeriod,
    /// IANA time zone name for local-midnight resets (e.g. `"UTC"` or
    /// `"Australia/Sydney"`, D4-17).
    pub tz: String,
    /// Alert threshold percentages (`1..=100`, strictly increasing, 1 to
    /// [`MAX_THRESHOLDS`] entries).
    pub thresholds: Vec<u8>,
    pub created_at: u64,
    pub updated_at: u64,
}

impl BudgetRecord {
    pub fn in_bounds(&self) -> bool {
        let thresholds_valid = !self.thresholds.is_empty()
            && self.thresholds.len() <= MAX_THRESHOLDS
            && self.thresholds.iter().all(|&t| (1..=100).contains(&t))
            && self.thresholds.windows(2).all(|w| w[0] < w[1]);
        self.scope.in_bounds()
            && positive_money_ok(&self.amount)
            && spend_str_ok(&self.tz)
            && thresholds_valid
            && timestamp_ok(self.created_at)
            && timestamp_ok(self.updated_at)
            && self.updated_at >= self.created_at
    }

    pub(crate) fn encode(&self, e: &mut Enc) {
        self.scope.encode(e);
        enc_money(e, &self.amount);
        self.period.encode(e);
        e.str(&self.tz).count(self.thresholds.len());
        for &t in &self.thresholds {
            e.u8(t);
        }
        e.u64(self.created_at).u64(self.updated_at);
    }

    pub(crate) fn decode(d: &mut Dec<'_>) -> Result<Self, VaultError> {
        let scope = BudgetScope::decode(d)?;
        let amount = dec_money(d)?;
        let period = BudgetPeriod::decode(d)?;
        let tz = d.string()?;
        let n = d.count(1, MAX_THRESHOLDS)?;
        let mut thresholds = Vec::with_capacity(n);
        for _ in 0..n {
            thresholds.push(d.u8()?);
        }
        let created_at = d.u64()?;
        let updated_at = d.u64()?;
        Ok(BudgetRecord {
            scope,
            amount,
            period,
            tz,
            thresholds,
            created_at,
            updated_at,
        })
    }
}
