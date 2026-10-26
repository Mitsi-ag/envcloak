//! Spend control model, five-control table, availability states and hard-cap
//! evaluation (`SPEC §2a-bis`, `D4-07`, `D4-28`, gate `s7`).

pub mod covers;
pub mod table;

use std::cmp::Ordering;

use envcloak_core::money::{Money, Rounding};
pub use envcloak_core::vault::{BudgetScope, LimitResetPeriod as CapResetPeriod};

use crate::account::Source;

pub use self::covers::{CapScope, KeySet, covers};
pub use self::table::{
    CONTROL_TABLE, ControlTableRow, PROVIDER_CONTROL_NOTES, ProviderControlNote, provider_note,
    row_for,
};

/// Maximum age in seconds (`26 hours`) for a polled provider cap to qualify as
/// fresh (`SPEC §2a-bis`, `D4-07` condition 4).
pub const MAX_FRESH_CAP_AGE_SECS: u64 = 26 * 3600;

/// Closed enum of the five spend controls in `SPEC §2a-bis` (`D4-07`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Control {
    /// Provider-enforced usage cap (`CONTROL_TABLE[0]`).
    ProviderCap,
    /// Proxy spend gate (`CONTROL_TABLE[1]`, `M6`).
    ProxyGate,
    /// Automatic key disable (`CONTROL_TABLE[2]`).
    AutoKeyDisable,
    /// Card authorization limit (`CONTROL_TABLE[3]`).
    CardAuthLimit,
    /// Alert only (`CONTROL_TABLE[4]`).
    AlertOnly,
}

impl Control {
    /// All five controls in `SPEC §2a-bis` order.
    pub const ALL: [Self; 5] = [
        Self::ProviderCap,
        Self::ProxyGate,
        Self::AutoKeyDisable,
        Self::CardAuthLimit,
        Self::AlertOnly,
    ];
}

/// Reason a configured control is [`Availability::Unverified`] (`D4-07`,
/// `D4-28`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnverifiedReason {
    /// Entered manually by the person (`spend set --cap`, `A11`).
    ManualEntry,
    /// Reported by an untrusted client (`spend.ingest`, `D4-10`).
    ClientReported,
    /// Provider reported the limit as configured but `inactive` (`A19`).
    InactiveLimit,
    /// Provider did not report an enforcement state and no documented literal
    /// applies.
    UnknownEnforcement,
    /// Cap fails condition (1) currency, (2) reset/amount, or (3) key-set
    /// coverage for this budget (`D4-07`, `A10`).
    DoesNotEnforceBudget,
}

/// Whether a control can act now on a given budget (`SPEC §2a-bis`, `D4-28`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    /// Control is active and fresh.
    Active,
    /// No cap or control is configured for this budget.
    NotSet,
    /// A cap is recorded, but it is manual, client-reported, inactive, unknown,
    /// or does not enforce this budget (`D4-07`).
    Unverified(UnverifiedReason),
    /// Polling is off and no manual figure has been entered (`D4-28`, `A10`).
    NoData,
    /// Last observation is older than the freshness threshold or polling was
    /// turned off after `since` (`D4-28`, `A8`, `A13`).
    Stale { since: u64 },
    /// Not evaluated while the vault is locked (`D4-28`).
    NotEvaluatedWhileLocked,
    /// Control does not ship in this release (`M6` proxy gate, automatic key
    /// disable, card authorization limit; `SPEC §1.1`, `D4-07`, `D4-24`).
    NotInThisRelease,
}

/// How a provider cap's `enforcing` state was established (`D4-07` condition 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforcingBasis {
    /// Read directly from the provider API (such as OpenAI
    /// `enforcement.status = "enforcing"`).
    Read,
    /// Declared by a registry literal with a cited vendor documentation source
    /// (such as OpenRouter's 402 behaviour, `D4-05`, `D4-07`).
    Documented { source: String },
}

/// Enforcement state of a provider cap (`D4-07`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapEnforcement {
    /// Provider refuses requests once the cap is reached.
    Enforcing(EnforcingBasis),
    /// Limit is configured at the provider but not enforcing.
    Inactive,
    /// Enforcement state is unknown.
    Unknown,
}

/// Observed or manually entered provider cap fact evaluated against a budget
/// (`D4-07`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderCapFact {
    /// Lowercase provider slug (`"openrouter"`, `"openai"`, ...).
    pub provider: String,
    /// Cap amount (`limit` or `threshold_amount`).
    pub amount: Money,
    /// Reset period (`Some(Monthly)` for resetting caps, `None` for non-resetting
    /// prepaid/total caps).
    pub reset: Option<CapResetPeriod>,
    /// Remaining cap amount (`limit_remaining`), used when `reset` is `None`
    /// (`D4-07` condition 2).
    pub remaining: Option<Money>,
    /// Scope of the cap at the provider.
    pub scope: CapScope,
    /// Keys covered by this cap at evaluation time (`D4-07` condition 3).
    pub keys: KeySet,
    /// Enforcement status (`Enforcing`, `Inactive`, `Unknown`).
    pub enforcement: CapEnforcement,
    /// For OpenRouter, whether bring-your-own-key usage counts toward the limit
    /// (`include_byok_in_limit`, `D4-07`).
    pub byok_in_limit: Option<bool>,
    /// Provenance of the cap (`Poll`, `Manual`, `ClientReported`).
    pub source: Source,
    /// Unix timestamp (seconds) when the cap was read or entered.
    pub read_at: u64,
    /// Optional provider-specific lag note override.
    pub lag: Option<String>,
}

/// Data feed status for a budget, used to compute `Alert only`'s availability
/// (`D4-28`, `A10`, `A13`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetDataFeed {
    /// Polling is enabled or manual figures are present and fresh.
    Active,
    /// Polling is off and nothing has been entered (`D4-28`, `A10`).
    NoDataPollingOff,
    /// Polling was turned off after `since` (`A13`).
    StalePollingOff { since: u64 },
    /// Last poll is stale since `since`.
    Stale { since: u64 },
}

/// Budget context against which controls are evaluated (`D4-07`, `D4-28`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetEvalContext {
    /// Budget scope (`Key`, `Provider`, `Project`, `Account`).
    pub scope: BudgetScope,
    /// Budget cap amount.
    pub amount: Money,
    /// Budget reset period (budgets in M4 reset monthly on the 1st, `D4-17`,
    /// or match the configured period).
    pub reset: CapResetPeriod,
    /// Remaining budget in the current period (used when comparing against a
    /// non-resetting cap, `D4-07` condition 2).
    pub remaining: Option<Money>,
    /// Every key slug the budget counts at evaluation time (`D4-07` condition 3).
    pub keys: KeySet,
    /// Optional provider cap candidate to evaluate for `Control::ProviderCap`.
    pub cap: Option<ProviderCapFact>,
    /// Data-feed state for `Control::AlertOnly`.
    pub data_feed: BudgetDataFeed,
    /// Whether the vault is currently locked (`D4-28`).
    pub vault_locked: bool,
    /// Current evaluation Unix timestamp (seconds).
    pub now: u64,
}

/// Rendered label for one control row on a budget (`SPEC §2a-bis`, `D4-07`,
/// `D4-28`, gate `s7`).
///
/// All fields are private so that `ControlLabel` can only be constructed or
/// populated by [`label`] (and [`controls_for`], which calls [`label`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlLabel {
    control: Control,
    name: &'static str,
    headline: String,
    enforced_by: String,
    stops: String,
    does_not_stop: String,
    availability: Availability,
    _sealed: (),
}

impl ControlLabel {
    /// Returns the control variant.
    #[must_use]
    pub const fn control(&self) -> Control {
        self.control
    }

    /// Returns the canonical control name from `SPEC §2a-bis`.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Returns the status headline.
    #[must_use]
    pub fn headline(&self) -> &str {
        &self.headline
    }

    /// Returns the `Enforced by` column text.
    #[must_use]
    pub fn enforced_by(&self) -> &str {
        &self.enforced_by
    }

    /// Returns the `Stops` column text.
    #[must_use]
    pub fn stops(&self) -> &str {
        &self.stops
    }

    /// Returns the `Does not stop` column text.
    #[must_use]
    pub fn does_not_stop(&self) -> &str {
        &self.does_not_stop
    }

    /// Returns the control's [`Availability`].
    #[must_use]
    pub const fn availability(&self) -> Availability {
        self.availability
    }
}

/// Formats a [`Money`] amount concisely for control headlines (`"15 USD"` when
/// fractional digits are zero, `"12.50 USD"` otherwise; `A7`, `A8`, `A10`).
#[must_use]
pub fn format_cap_amount(money: &Money) -> String {
    if let Ok(whole) = money.rescale(0, Rounding::Exact) {
        format!("{} {}", whole.format_number(), whole.currency)
    } else {
        money.to_string()
    }
}

#[must_use]
fn period_word(period: CapResetPeriod) -> &'static str {
    match period {
        CapResetPeriod::Daily => "daily",
        CapResetPeriod::Weekly => "weekly",
        CapResetPeriod::Monthly => "monthly",
    }
}

#[must_use]
fn provider_display_name(provider_id: &str) -> &str {
    provider_note(provider_id).map_or(provider_id, |n| n.display_name)
}

#[must_use]
fn format_amount_with_optional_period(amount: &Money, reset: Option<CapResetPeriod>) -> String {
    let base = format_cap_amount(amount);
    match reset {
        Some(p) => format!("{base} {}", period_word(p)),
        None => base,
    }
}

#[must_use]
fn cap_meets_budget_conditions(cap: &ProviderCapFact, budget: &BudgetEvalContext) -> bool {
    // Condition (1): cap's currency equals the budget's currency.
    if cap.amount.currency != budget.amount.currency {
        return false;
    }

    // Condition (2): reset period equals the budget's and amount <= budget's
    // amount, OR cap has no reset and its remaining amount <= budget's
    // remaining amount.
    let amount_ok = match cap.reset {
        Some(cap_reset) => {
            cap_reset == budget.reset
                && matches!(
                    cap.amount.same_currency_cmp(&budget.amount),
                    Ok(Ordering::Less | Ordering::Equal)
                )
        }
        None => match (&cap.remaining, &budget.remaining) {
            (Some(cap_rem), Some(budget_rem)) => {
                cap_rem.currency == budget.amount.currency
                    && matches!(
                        cap_rem.same_currency_cmp(budget_rem),
                        Ok(Ordering::Less | Ordering::Equal)
                    )
            }
            _ => false,
        },
    };
    if !amount_ok {
        return false;
    }

    // Condition (3): cap's scope covers every key the budget counts at
    // evaluation time (set containment over keys).
    covers(&cap.keys, &budget.keys)
}

/// The sole producer of the `"Hard cap"` headline in EnvCloak (`SPEC §2a-bis`,
/// `D4-07`, gate `s7`).
///
/// Returns `Some(headline)` if and only if all four `D4-07` conditions hold:
/// 1. `cap.amount.currency == budget.amount.currency`
/// 2. `cap.reset == Some(budget.reset)` and `cap.amount <= budget.amount`, or
///    `cap.reset.is_none()` and `cap.remaining <= budget.remaining`
/// 3. `covers(&cap.keys, &budget.keys)` holds
/// 4. `cap.source` is [`Source::Poll`], `budget.now >= cap.read_at`,
///    `budget.now - cap.read_at <= MAX_FRESH_CAP_AGE_SECS` (`26 hours`), and
///    `cap.enforcement` is [`CapEnforcement::Enforcing`].
#[must_use]
pub fn hard_cap_words(cap: &ProviderCapFact, budget: &BudgetEvalContext) -> Option<String> {
    // Condition (4): fresh poll in an enforcing state.
    if !matches!(cap.source, Source::Poll) {
        return None;
    }
    let age = budget.now.checked_sub(cap.read_at)?;
    if age > MAX_FRESH_CAP_AGE_SECS {
        return None;
    }
    let basis = match &cap.enforcement {
        CapEnforcement::Enforcing(basis) => {
            if let EnforcingBasis::Documented { source } = basis
                && source.trim().is_empty()
            {
                return None;
            }
            basis
        }
        CapEnforcement::Inactive | CapEnforcement::Unknown => return None,
    };

    // Conditions (1), (2), and (3).
    if !cap_meets_budget_conditions(cap, budget) {
        return None;
    }

    let amount_str = format_amount_with_optional_period(&cap.amount, cap.reset);
    let prov = provider_display_name(&cap.provider);
    let scope_qual = cap.scope.hard_cap_qualifier();
    let headline = match basis {
        EnforcingBasis::Read => format!("Hard cap of {amount_str} ({prov}, {scope_qual})"),
        EnforcingBasis::Documented { .. } => {
            format!("Hard cap of {amount_str} ({prov}, {scope_qual}, per {prov}'s documentation)")
        }
    };
    Some(headline)
}

/// Produces the [`ControlLabel`] for `control` on `budget` (`SPEC §2a-bis`,
/// `D4-07`, `D4-28`, gate `s7`).
#[must_use]
pub fn label(control: Control, budget: &BudgetEvalContext) -> ControlLabel {
    let base = row_for(control);
    match control {
        Control::ProviderCap => label_provider_cap(base, budget),
        Control::ProxyGate | Control::AutoKeyDisable | Control::CardAuthLimit => ControlLabel {
            control,
            name: base.name,
            headline: "Not in this release".to_owned(),
            enforced_by: base.enforced_by.to_owned(),
            stops: base.stops.to_owned(),
            does_not_stop: base.does_not_stop.to_owned(),
            availability: Availability::NotInThisRelease,
            _sealed: (),
        },
        Control::AlertOnly => label_alert_only(base, budget),
    }
}

fn label_provider_cap(base: &'static ControlTableRow, budget: &BudgetEvalContext) -> ControlLabel {
    let Some(cap) = &budget.cap else {
        return ControlLabel {
            control: Control::ProviderCap,
            name: base.name,
            headline: "Provider-enforced usage cap: not set".to_owned(),
            enforced_by: base.enforced_by.to_owned(),
            stops: base.stops.to_owned(),
            does_not_stop: base.does_not_stop.to_owned(),
            availability: Availability::NotSet,
            _sealed: (),
        };
    };

    let mut stops = base.stops.to_owned();
    let mut does_not_stop = base.does_not_stop.to_owned();

    // OpenRouter BYOK rule (`D4-07`, `A7`): "stops" excludes bring-your-own-key
    // usage unless `include_byok_in_limit` was read `true`, and "does not stop"
    // then names it.
    if cap.provider.eq_ignore_ascii_case("openrouter") && cap.byok_in_limit != Some(true) {
        stops.push_str(" (excluding bring-your-own-key usage)");
        does_not_stop.push_str("; bring-your-own-key usage");
    }

    if let Some(lag) = &cap.lag {
        if !lag.is_empty() && !does_not_stop.contains(lag.as_str()) {
            does_not_stop.push_str("; ");
            does_not_stop.push_str(lag);
        }
    } else if let Some(note) = provider_note(&cap.provider) {
        if !does_not_stop.contains(note.stated_lag) {
            does_not_stop.push_str(" (");
            does_not_stop.push_str(note.stated_lag);
            does_not_stop.push(')');
        }
    }

    let amount_str = format_cap_amount(&cap.amount);
    let amount_and_period = format_amount_with_optional_period(&cap.amount, cap.reset);
    let reset_suffix = cap
        .reset
        .map_or_else(String::new, |p| format!(" ({})", period_word(p)));
    let scope_str = cap.scope.display_scope();

    let (headline, availability) = if let Some(hard) = hard_cap_words(cap, budget) {
        (hard, Availability::Active)
    } else {
        match &cap.source {
            Source::Manual { .. } => (
                format!(
                    "Provider cap, you entered this, EnvCloak has not checked it ({amount_and_period} on {scope_str})"
                ),
                Availability::Unverified(UnverifiedReason::ManualEntry),
            ),
            Source::ClientReported { tool, .. } => (
                format!(
                    "Provider cap of {amount_and_period} on {scope_str}, reported by a client ({tool}), EnvCloak has not checked it"
                ),
                Availability::Unverified(UnverifiedReason::ClientReported),
            ),
            Source::Poll => match &cap.enforcement {
                CapEnforcement::Inactive => (
                    format!(
                        "Provider cap of {amount_and_period} on {scope_str}, configured, not enforcing"
                    ),
                    Availability::Unverified(UnverifiedReason::InactiveLimit),
                ),
                CapEnforcement::Unknown => (
                    format!(
                        "Provider cap of {amount_and_period} on {scope_str}, enforcement not confirmed"
                    ),
                    Availability::Unverified(UnverifiedReason::UnknownEnforcement),
                ),
                CapEnforcement::Enforcing(EnforcingBasis::Documented { source })
                    if source.trim().is_empty() =>
                {
                    (
                        format!(
                            "Provider cap of {amount_and_period} on {scope_str}, enforcement not confirmed"
                        ),
                        Availability::Unverified(UnverifiedReason::UnknownEnforcement),
                    )
                }
                CapEnforcement::Enforcing(_) => {
                    let age = budget.now.saturating_sub(cap.read_at);
                    if budget.now < cap.read_at || age > MAX_FRESH_CAP_AGE_SECS {
                        let hours = age / 3600;
                        (
                            format!(
                                "Provider cap of {amount_str} on {scope_str}, last checked {hours} hours ago, not confirmed{reset_suffix}"
                            ),
                            Availability::Stale { since: cap.read_at },
                        )
                    } else {
                        (
                            format!(
                                "Provider cap of {amount_str} on {scope_str}; does not enforce this budget{reset_suffix}"
                            ),
                            Availability::Unverified(UnverifiedReason::DoesNotEnforceBudget),
                        )
                    }
                }
            },
        }
    };

    ControlLabel {
        control: Control::ProviderCap,
        name: base.name,
        headline,
        enforced_by: base.enforced_by.to_owned(),
        stops,
        does_not_stop,
        availability,
        _sealed: (),
    }
}

fn label_alert_only(base: &'static ControlTableRow, budget: &BudgetEvalContext) -> ControlLabel {
    let (headline, availability) = if budget.vault_locked {
        (
            "Alert only: not evaluated while the vault is locked".to_owned(),
            Availability::NotEvaluatedWhileLocked,
        )
    } else {
        match budget.data_feed {
            BudgetDataFeed::Active => ("Stops nothing".to_owned(), Availability::Active),
            BudgetDataFeed::NoDataPollingOff => (
                "Alert only: no data, polling off".to_owned(),
                Availability::NoData,
            ),
            BudgetDataFeed::StalePollingOff { since } => (
                format!("Alert only: stale since {since}, polling off"),
                Availability::Stale { since },
            ),
            BudgetDataFeed::Stale { since } => (
                format!("Alert only: stale since {since}"),
                Availability::Stale { since },
            ),
        }
    };

    ControlLabel {
        control: Control::AlertOnly,
        name: base.name,
        headline,
        enforced_by: base.enforced_by.to_owned(),
        stops: base.stops.to_owned(),
        does_not_stop: base.does_not_stop.to_owned(),
        availability,
        _sealed: (),
    }
}

/// Returns all five [`ControlLabel`] rows in `SPEC §2a-bis` order for `budget`
/// (`D4-07`, `D4-28`, gate `s7`).
#[must_use]
pub fn controls_for(budget: &BudgetEvalContext) -> Vec<ControlLabel> {
    Control::ALL
        .into_iter()
        .map(|ctrl| label(ctrl, budget))
        .collect()
}
