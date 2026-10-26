//! Monthly burn aggregation per currency (D4-08, G-23, M4-02).
//!
//! Combines recurring subscriptions (normalised to a monthly figure using pure
//! integer arithmetic) with month-to-date usage per [`Iso4217`] currency. No
//! foreign-exchange conversion is performed; mixed currencies are kept side by
//! side in deterministic [`Iso4217`] order.

use std::collections::BTreeMap;

use envcloak_core::money::{Iso4217, Money, MoneyError};
use envcloak_core::vault::BillingCadence;

/// Monthly burn breakdown for one currency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CurrencyBurn {
    pub currency: Iso4217,
    pub subscriptions_monthly: Money,
    pub usage_mtd: Money,
    pub total_monthly: Money,
}

/// Per-currency monthly burn aggregator.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Burn {
    by_currency: BTreeMap<Iso4217, CurrencyBurn>,
}

/// Normalises a subscription amount of `cadence` to a monthly [`Money`] amount
/// using integer arithmetic (half-away-from-zero rounding on annual/weekly
/// division by 12).
pub fn normalise_subscription_monthly(
    amount: Money,
    cadence: BillingCadence,
) -> Result<Money, MoneyError> {
    if amount.minor() < 0 {
        return Err(MoneyError::NegativeNotAllowed);
    }
    let minor = i128::from(amount.minor());
    let monthly_minor = match cadence {
        BillingCadence::Monthly => minor,
        BillingCadence::Annual => (minor + 6) / 12,
        BillingCadence::Weekly => (minor * 52 + 6) / 12,
    };
    let m = i64::try_from(monthly_minor).map_err(|_| MoneyError::OutOfBounds)?;
    Money::new(m, amount.scale(), amount.currency())
}

impl Burn {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a subscription's monthly-normalised amount to its currency bucket.
    pub fn add_subscription(
        &mut self,
        amount: Money,
        cadence: BillingCadence,
    ) -> Result<(), MoneyError> {
        let monthly = normalise_subscription_monthly(amount, cadence)?;
        let cur = monthly.currency();
        let entry = self.by_currency.entry(cur).or_insert_with(|| {
            let zero = Money::zero_at_scale(monthly.scale(), cur);
            CurrencyBurn {
                currency: cur,
                subscriptions_monthly: zero,
                usage_mtd: zero,
                total_monthly: zero,
            }
        });
        entry.subscriptions_monthly = entry.subscriptions_monthly.checked_add(&monthly)?;
        entry.total_monthly = entry.subscriptions_monthly.checked_add(&entry.usage_mtd)?;
        Ok(())
    }

    /// Adds month-to-date usage to its currency bucket.
    pub fn add_usage_mtd(&mut self, usage: Money) -> Result<(), MoneyError> {
        if usage.minor() < 0 {
            return Err(MoneyError::NegativeNotAllowed);
        }
        let cur = usage.currency();
        let entry = self.by_currency.entry(cur).or_insert_with(|| {
            let zero = Money::zero_at_scale(usage.scale(), cur);
            CurrencyBurn {
                currency: cur,
                subscriptions_monthly: zero,
                usage_mtd: zero,
                total_monthly: zero,
            }
        });
        entry.usage_mtd = entry.usage_mtd.checked_add(&usage)?;
        entry.total_monthly = entry.subscriptions_monthly.checked_add(&entry.usage_mtd)?;
        Ok(())
    }

    pub fn get(&self, currency: Iso4217) -> Option<&CurrencyBurn> {
        self.by_currency.get(&currency)
    }

    pub fn currencies(&self) -> impl Iterator<Item = &CurrencyBurn> {
        self.by_currency.values()
    }

    pub fn len(&self) -> usize {
        self.by_currency.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_currency.is_empty()
    }
}
