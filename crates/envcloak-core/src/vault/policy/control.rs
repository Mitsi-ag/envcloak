//! Policy record kind 9: [`ControlFactRecord`] (D4-07, D4-09, SPEC §2a-bis, §5).

use crate::money::Money;

use super::super::codec::{Dec, Enc};
use super::super::error::VaultError;
use super::{
    ManualFactTarget, SpendSource, corrupt, dec_money, dec_opt_bool, dec_opt_money, enc_money,
    enc_opt_bool, enc_opt_money, money_ok, non_negative_money_ok, spend_str_ok, timestamp_ok,
};

/// Reset period of a provider spend cap (e.g. OpenRouter `limit_reset`, D4-05, D4-07).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum LimitResetPeriod {
    Daily = 1,
    Weekly = 2,
    Monthly = 3,
}

impl LimitResetPeriod {
    pub(crate) fn encode(self, e: &mut Enc) {
        e.u8(self as u8);
    }

    pub(crate) fn decode(d: &mut Dec<'_>) -> Result<Self, VaultError> {
        match d.u8()? {
            1 => Ok(LimitResetPeriod::Daily),
            2 => Ok(LimitResetPeriod::Weekly),
            3 => Ok(LimitResetPeriod::Monthly),
            _ => Err(corrupt()),
        }
    }
}

/// Scope of a provider cap (D4-07).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CapScope {
    Key = 1,
    Project = 2,
    Account = 3,
    Organization = 4,
    Provider = 5,
}

impl CapScope {
    pub(crate) fn encode(self, e: &mut Enc) {
        e.u8(self as u8);
    }

    pub(crate) fn decode(d: &mut Dec<'_>) -> Result<Self, VaultError> {
        match d.u8()? {
            1 => Ok(CapScope::Key),
            2 => Ok(CapScope::Project),
            3 => Ok(CapScope::Account),
            4 => Ok(CapScope::Organization),
            5 => Ok(CapScope::Provider),
            _ => Err(corrupt()),
        }
    }
}

/// Enforcement state of a provider cap (D4-07).
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum CapEnforcement {
    /// Read from the provider API as active/enforcing (e.g. OpenAI
    /// `enforcement.status == "enforcing"`).
    EnforcingRead,
    /// Declared enforcing by a provider registry literal with a cited
    /// documentation source (e.g. OpenRouter 402 behaviour).
    EnforcingDocumented { citation: String },
    /// Read from the provider API as inactive.
    Inactive,
    /// Unknown or entered manually without verification.
    Unknown,
}

impl CapEnforcement {
    pub fn in_bounds(&self) -> bool {
        match self {
            CapEnforcement::EnforcingRead | CapEnforcement::Inactive | CapEnforcement::Unknown => {
                true
            }
            CapEnforcement::EnforcingDocumented { citation } => spend_str_ok(citation),
        }
    }

    pub(crate) fn encode(&self, e: &mut Enc) {
        match self {
            CapEnforcement::EnforcingRead => {
                e.u8(1);
            }
            CapEnforcement::EnforcingDocumented { citation } => {
                e.u8(2).str(citation);
            }
            CapEnforcement::Inactive => {
                e.u8(3);
            }
            CapEnforcement::Unknown => {
                e.u8(4);
            }
        }
    }

    pub(crate) fn decode(d: &mut Dec<'_>) -> Result<Self, VaultError> {
        match d.u8()? {
            1 => Ok(CapEnforcement::EnforcingRead),
            2 => Ok(CapEnforcement::EnforcingDocumented {
                citation: d.string()?,
            }),
            3 => Ok(CapEnforcement::Inactive),
            4 => Ok(CapEnforcement::Unknown),
            _ => Err(corrupt()),
        }
    }
}

impl core::fmt::Debug for CapEnforcement {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CapEnforcement::EnforcingRead => f.write_str("EnforcingRead"),
            CapEnforcement::EnforcingDocumented { citation } => f
                .debug_struct("EnforcingDocumented")
                .field("citation_len", &citation.len())
                .finish(),
            CapEnforcement::Inactive => f.write_str("Inactive"),
            CapEnforcement::Unknown => f.write_str("Unknown"),
        }
    }
}

/// A provider cap / control fact record (policy kind 9, version 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlFactRecord {
    pub target: ManualFactTarget,
    pub amount: Money,
    pub reset: Option<LimitResetPeriod>,
    pub remaining: Option<Money>,
    pub scope: CapScope,
    pub enforcement: CapEnforcement,
    pub byok_in_limit: Option<bool>,
    pub source: SpendSource,
    pub read_at: u64,
}

impl ControlFactRecord {
    pub fn in_bounds(&self) -> bool {
        let same_currency = self
            .remaining
            .as_ref()
            .is_none_or(|r| r.currency() == self.amount.currency() && money_ok(r));
        self.target.in_bounds()
            && non_negative_money_ok(&self.amount)
            && same_currency
            && self.enforcement.in_bounds()
            && self.source.in_bounds()
            && timestamp_ok(self.read_at)
    }

    pub(crate) fn encode(&self, e: &mut Enc) {
        self.target.encode(e);
        enc_money(e, &self.amount);
        match self.reset {
            None => {
                e.u8(0);
            }
            Some(r) => {
                e.u8(1);
                r.encode(e);
            }
        }
        enc_opt_money(e, self.remaining.as_ref());
        self.scope.encode(e);
        self.enforcement.encode(e);
        enc_opt_bool(e, self.byok_in_limit);
        self.source.encode(e);
        e.u64(self.read_at);
    }

    pub(crate) fn decode(d: &mut Dec<'_>) -> Result<Self, VaultError> {
        let target = ManualFactTarget::decode(d)?;
        let amount = dec_money(d)?;
        let reset = if d.bool()? {
            Some(LimitResetPeriod::decode(d)?)
        } else {
            None
        };
        let remaining = dec_opt_money(d)?;
        let scope = CapScope::decode(d)?;
        let enforcement = CapEnforcement::decode(d)?;
        let byok_in_limit = dec_opt_bool(d)?;
        let source = SpendSource::decode(d)?;
        let read_at = d.u64()?;
        Ok(ControlFactRecord {
            target,
            amount,
            reset,
            remaining,
            scope,
            enforcement,
            byok_in_limit,
            source,
            read_at,
        })
    }
}
