//! Pure spend evaluation, control label model, budgets, forecasts, alerts, and
//! per-project cost attribution (M4, `docs/SPEC.md` §2a-bis, §8).

#![forbid(unsafe_code)]

pub mod account;
pub mod burn;
pub mod controls;
pub mod series;
pub mod status;

pub use account::{
    AccountKey, Attribution, Source, SubjectKindRecord, attribution_words, source_words,
};
pub use burn::{Burn, CurrencyBurn, normalise_subscription_monthly};
pub use controls::{
    Availability, BudgetDataFeed, BudgetEvalContext, BudgetScope, CONTROL_TABLE, CapEnforcement,
    CapResetPeriod, CapScope, Control, ControlLabel, ControlTableRow, EnforcingBasis, KeySet,
    MAX_FRESH_CAP_AGE_SECS, PROVIDER_CONTROL_NOTES, ProviderCapFact, ProviderControlNote,
    UnverifiedReason, controls_for, covers, format_cap_amount, hard_cap_words, label,
    provider_note, row_for,
};
pub use series::{DailySeries, LAST_30_DAYS_WINDOW, Last30DaysSummary, MIN_OBSERVED_DAYS_FOR_30D};
pub use status::{
    DEFAULT_EXPIRING_DAYS, KeyStatus, KeyStatusInputs, UNUSED_90_DAYS_SECS, effective_expiry,
    evaluate_key_status,
};

#[cfg(test)]
mod tests {
    use super::*;
    use envcloak_core::money::{Iso4217, Money};
    use envcloak_core::vault::{Account, BillingCadence};

    #[test]
    fn account_key_follows_org_then_email_then_label_precedence() {
        let acc = Account {
            email: Some("billing@example.com".into()),
            label: Some("team-label".into()),
            org_id: Some("org-123".into()),
        };
        assert_eq!(
            AccountKey::from_item_account("openai", &acc),
            AccountKey::new("openai", "org-123")
        );

        let no_org = Account {
            org_id: None,
            ..acc.clone()
        };
        assert_eq!(
            AccountKey::from_item_account("openai", &no_org),
            AccountKey::new("openai", "billing@example.com")
        );

        let only_label = Account {
            org_id: None,
            email: None,
            ..acc
        };
        assert_eq!(
            AccountKey::from_item_account("openai", &only_label),
            AccountKey::new("openai", "team-label")
        );

        assert_eq!(
            AccountKey::from_item_account("openai", &Account::default()),
            AccountKey::new("openai", "default")
        );
    }

    #[test]
    fn burn_separates_currencies_and_normalises_cadences() {
        let mut burn = Burn::new();
        // $20.00/month subscription + $120.00/year ($10.00/month) + $5.25 usage = $35.25 USD
        burn.add_subscription(
            Money::new(2000, 2, Iso4217::USD).unwrap(),
            BillingCadence::Monthly,
        )
        .unwrap();
        burn.add_subscription(
            Money::new(12_000, 2, Iso4217::USD).unwrap(),
            BillingCadence::Annual,
        )
        .unwrap();
        burn.add_usage_mtd(Money::new(525, 2, Iso4217::USD).unwrap())
            .unwrap();

        // EUR stays in its own bucket
        burn.add_subscription(
            Money::new(1500, 2, Iso4217::EUR).unwrap(),
            BillingCadence::Monthly,
        )
        .unwrap();

        assert_eq!(burn.len(), 2);
        let usd = burn.get(Iso4217::USD).unwrap();
        assert_eq!(
            usd.subscriptions_monthly,
            Money::new(3000, 2, Iso4217::USD).unwrap()
        );
        assert_eq!(usd.usage_mtd, Money::new(525, 2, Iso4217::USD).unwrap());
        assert_eq!(
            usd.total_monthly,
            Money::new(3525, 2, Iso4217::USD).unwrap()
        );

        let eur = burn.get(Iso4217::EUR).unwrap();
        assert_eq!(
            eur.total_monthly,
            Money::new(1500, 2, Iso4217::EUR).unwrap()
        );
    }

    #[test]
    fn daily_series_caps_at_35_buckets_marks_partial_and_counts_observed_days() {
        let mut series = DailySeries::new(Iso4217::USD, 2);
        // 3-day gap from day 100 ($10.00) to day 103 ($19.00) -> 3 partial buckets of $3.00 each
        series
            .record_cumulative_delta(
                100,
                Money::new(1000, 2, Iso4217::USD).unwrap(),
                103,
                Money::new(1900, 2, Iso4217::USD).unwrap(),
            )
            .unwrap();
        assert_eq!(series.buckets().len(), 3);
        assert!(series.buckets().iter().all(|b| b.partial));
        assert_eq!(
            series.last_30_days(103).unwrap(),
            Last30DaysSummary::NotEnoughData { observed_days: 3 }
        );

        // Add 40 consecutive daily observations: series stays capped at 35
        for day in 104..144 {
            series
                .record_daily(day, Money::new(100, 2, Iso4217::USD).unwrap())
                .unwrap();
        }
        assert_eq!(
            series.buckets().len(),
            envcloak_core::vault::MAX_DAILY_BUCKETS
        );
        assert_eq!(series.buckets().first().unwrap().day_index, 109);
        assert_eq!(series.buckets().last().unwrap().day_index, 143);
        assert_eq!(
            series.last_30_days(143).unwrap(),
            Last30DaysSummary::EnoughData {
                total: Money::new(3000, 2, Iso4217::USD).unwrap(),
                observed_days: 30,
                has_partial: false,
            }
        );
    }

    #[test]
    fn key_status_priority_and_earlier_expiry() {
        let base = KeyStatusInputs {
            leaked: false,
            invalid: false,
            low_balance: false,
            item_expires_at: Some(1_000 + 20 * 86_400),
            adapter_expires_at: Some(1_000 + 5 * 86_400),
            created_at: 1_000,
            last_used_at: Some(1_000),
            now: 1_000,
            expiring_window_days: 14,
        };
        assert_eq!(
            evaluate_key_status(&base),
            KeyStatus::Expiring {
                expires_at: 1_000 + 5 * 86_400,
                days_left: 5,
            }
        );
        assert_eq!(
            evaluate_key_status(&KeyStatusInputs {
                leaked: true,
                ..base
            }),
            KeyStatus::Leaked
        );
        assert_eq!(
            evaluate_key_status(&KeyStatusInputs {
                item_expires_at: None,
                adapter_expires_at: None,
                now: 1_000 + 91 * 86_400,
                ..base
            }),
            KeyStatus::Unused90Days
        );
    }
}
