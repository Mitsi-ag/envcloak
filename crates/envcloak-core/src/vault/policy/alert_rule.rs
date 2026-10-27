//! Policy record kind 7: [`AlertRuleRecord`] (D4-09, D4-16, SPEC §5, §8).

use crate::money::Money;

use super::super::codec::{Dec, Enc};
use super::super::error::VaultError;
use super::{
    BudgetScope, SpendSource, corrupt, dec_money, enc_money, non_negative_money_ok,
    opt_timestamp_ok, timestamp_ok,
};

/// Kind and parameter of an alert rule (D4-16).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AlertRuleKind {
    LowBalance { threshold: Money },
    Expiring { days: u16 },
    Spike,
    BudgetThreshold { percent: u8 },
    ForecastOver,
    InvalidKey,
    Leaked,
    ManagementKeyAsSecret,
}

impl AlertRuleKind {
    pub fn in_bounds(&self) -> bool {
        match self {
            AlertRuleKind::LowBalance { threshold } => non_negative_money_ok(threshold),
            AlertRuleKind::Expiring { days } => (1..=365).contains(days),
            AlertRuleKind::BudgetThreshold { percent } => (1..=100).contains(percent),
            AlertRuleKind::Spike
            | AlertRuleKind::ForecastOver
            | AlertRuleKind::InvalidKey
            | AlertRuleKind::Leaked
            | AlertRuleKind::ManagementKeyAsSecret => true,
        }
    }

    pub(crate) fn encode(&self, e: &mut Enc) {
        match self {
            AlertRuleKind::LowBalance { threshold } => {
                e.u8(1);
                enc_money(e, threshold);
            }
            AlertRuleKind::Expiring { days } => {
                e.u8(2).u32(u32::from(*days));
            }
            AlertRuleKind::Spike => {
                e.u8(3);
            }
            AlertRuleKind::BudgetThreshold { percent } => {
                e.u8(4).u8(*percent);
            }
            AlertRuleKind::ForecastOver => {
                e.u8(5);
            }
            AlertRuleKind::InvalidKey => {
                e.u8(6);
            }
            AlertRuleKind::Leaked => {
                e.u8(7);
            }
            AlertRuleKind::ManagementKeyAsSecret => {
                e.u8(8);
            }
        }
    }

    pub(crate) fn decode(d: &mut Dec<'_>) -> Result<Self, VaultError> {
        match d.u8()? {
            1 => Ok(AlertRuleKind::LowBalance {
                threshold: dec_money(d)?,
            }),
            2 => {
                let raw = d.u32()?;
                let days = u16::try_from(raw).map_err(|_| corrupt())?;
                Ok(AlertRuleKind::Expiring { days })
            }
            3 => Ok(AlertRuleKind::Spike),
            4 => Ok(AlertRuleKind::BudgetThreshold { percent: d.u8()? }),
            5 => Ok(AlertRuleKind::ForecastOver),
            6 => Ok(AlertRuleKind::InvalidKey),
            7 => Ok(AlertRuleKind::Leaked),
            8 => Ok(AlertRuleKind::ManagementKeyAsSecret),
            _ => Err(corrupt()),
        }
    }
}

/// An alert rule and its persisted evaluation/acknowledgement/snooze state
/// (policy kind 7, version 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertRuleRecord {
    pub rule: AlertRuleKind,
    pub scope: BudgetScope,
    pub raised_at: Option<u64>,
    pub raised_source: Option<SpendSource>,
    pub dedupe_period: Option<u64>,
    pub acked_at: Option<u64>,
    pub snoozed_until: Option<u64>,
    pub created_at: u64,
    pub updated_at: u64,
}

impl AlertRuleRecord {
    pub fn in_bounds(&self) -> bool {
        let source_consistent = self.raised_at.is_some() == self.raised_source.is_some();
        self.rule.in_bounds()
            && self.scope.in_bounds()
            && source_consistent
            && opt_timestamp_ok(self.raised_at)
            && self
                .raised_source
                .as_ref()
                .is_none_or(SpendSource::in_bounds)
            && opt_timestamp_ok(self.acked_at)
            && opt_timestamp_ok(self.snoozed_until)
            && timestamp_ok(self.created_at)
            && timestamp_ok(self.updated_at)
            && self.updated_at >= self.created_at
    }

    pub(crate) fn encode(&self, e: &mut Enc) {
        self.rule.encode(e);
        self.scope.encode(e);
        e.opt_u64(self.raised_at);
        match &self.raised_source {
            None => {
                e.u8(0);
            }
            Some(src) => {
                e.u8(1);
                src.encode(e);
            }
        }
        e.opt_u64(self.dedupe_period)
            .opt_u64(self.acked_at)
            .opt_u64(self.snoozed_until)
            .u64(self.created_at)
            .u64(self.updated_at);
    }

    pub(crate) fn decode(d: &mut Dec<'_>) -> Result<Self, VaultError> {
        let rule = AlertRuleKind::decode(d)?;
        let scope = BudgetScope::decode(d)?;
        let raised_at = d.opt_u64()?;
        let raised_source = if d.bool()? {
            Some(SpendSource::decode(d)?)
        } else {
            None
        };
        let dedupe_period = d.opt_u64()?;
        let acked_at = d.opt_u64()?;
        let snoozed_until = d.opt_u64()?;
        let created_at = d.u64()?;
        let updated_at = d.u64()?;
        Ok(AlertRuleRecord {
            rule,
            scope,
            raised_at,
            raised_source,
            dedupe_period,
            acked_at,
            snoozed_until,
            created_at,
            updated_at,
        })
    }
}
