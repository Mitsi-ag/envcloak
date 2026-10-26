//! Key-set containment (`covers`) and cap/budget scope types (`D4-07`, gate `s7`).

use std::collections::BTreeSet;

/// Canonical set of item slugs (`provider/name`) covered by a cap or counted by
/// a budget (`D4-07`).
pub type KeySet = BTreeSet<String>;

/// Scope of a provider-enforced usage cap (`D4-07`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapScope {
    /// Cap applies to a single key slug (`"openrouter/work"`).
    Key(String),
    /// Cap applies to a provider account (`"deepseek"`, `"acct-1"`).
    Account {
        provider: String,
        account_id: String,
    },
    /// Cap applies to an entire organization (`"openai"`, `"org-1"`).
    Organization { provider: String, org_id: String },
    /// Cap applies across an entire provider (`"openrouter"`).
    Provider(String),
}

impl CapScope {
    /// Formats the scope for `"Provider cap of <amount> on <scope>"` (`D4-07`,
    /// `A8`, `A10`).
    #[must_use]
    pub fn display_scope(&self) -> String {
        match self {
            CapScope::Key(slug) => format!("key {slug}"),
            CapScope::Account {
                provider,
                account_id,
            } => format!("account {provider}/{account_id}"),
            CapScope::Organization { provider, org_id } => {
                format!("organization {provider}/{org_id}")
            }
            CapScope::Provider(provider) => format!("provider {provider}"),
        }
    }

    /// Formats the short scope qualifier inside the parenthetical of a hard-cap
    /// headline (`A7`: `"this key only"`, `A19`: `"organization"`).
    #[must_use]
    pub const fn hard_cap_qualifier(&self) -> &'static str {
        match self {
            CapScope::Key(_) => "this key only",
            CapScope::Account { .. } => "account",
            CapScope::Organization { .. } => "organization",
            CapScope::Provider(_) => "provider",
        }
    }
}

/// Returns `true` when `cap_keys` covers every key that `budget_keys` counts
/// at evaluation time (`D4-07` condition 3: non-empty set containment).
///
/// An organization or account cap covers every key of that account; a
/// provider-wide cap covers every key of that provider and account; a key cap
/// covers only that key, so it covers a key budget for that key, and a
/// provider, account or project budget only while that budget counts exactly
/// that one key.
#[must_use]
pub fn covers(cap_keys: &KeySet, budget_keys: &KeySet) -> bool {
    !budget_keys.is_empty() && budget_keys.is_subset(cap_keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> KeySet {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn covers_checks_non_empty_set_containment() {
        let k1 = set(&["openrouter/work"]);
        let both = set(&["openrouter/work", "openrouter/ci"]);
        let empty = set(&[]);

        // Key cap covers single-key budget for the same key.
        assert!(covers(&k1, &k1));
        // Key cap does NOT cover a two-key provider budget (A10).
        assert!(!covers(&k1, &both));
        // Organization/account/provider cap covering both keys covers a single-key budget and the two-key budget.
        assert!(covers(&both, &k1));
        assert!(covers(&both, &both));
        // Empty budget key set is never covered.
        assert!(!covers(&both, &empty));
    }
}
