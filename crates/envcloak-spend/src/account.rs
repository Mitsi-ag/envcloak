//! Account identity, data source, and attribution words (D4-10, M4-02).

use envcloak_core::vault::{Account, SpendAccountId, SpendAttribution, SpendSource};

pub use envcloak_core::vault::{
    SpendAttribution as Attribution, SpendSource as Source, SubjectKindRecord,
};

/// Canonical key for a provider account (D4-10): `(provider, org_id | email |
/// label | "default")`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccountKey {
    pub provider: String,
    pub account: String,
}

impl AccountKey {
    pub fn new(provider: impl Into<String>, account: impl Into<String>) -> Self {
        let provider = provider.into();
        let account = account.into();
        let account = if account.trim().is_empty() {
            "default".to_owned()
        } else {
            account
        };
        AccountKey { provider, account }
    }

    /// Derives the account key from an item's provider and [`Account`] metadata
    /// following D4-10's precedence: `org_id`, else `email`, else `label`, else
    /// `"default"`.
    pub fn from_item_account(provider: &str, account: &Account) -> Self {
        let chosen = account
            .org_id
            .as_deref()
            .filter(|s| !s.is_empty())
            .or_else(|| account.email.as_deref().filter(|s| !s.is_empty()))
            .or_else(|| account.label.as_deref().filter(|s| !s.is_empty()))
            .unwrap_or("default");
        Self::new(provider, chosen)
    }

    pub fn to_record_id(&self) -> SpendAccountId {
        SpendAccountId {
            provider: self.provider.clone(),
            account: self.account.clone(),
        }
    }
}

impl From<SpendAccountId> for AccountKey {
    fn from(id: SpendAccountId) -> Self {
        AccountKey {
            provider: id.provider,
            account: id.account,
        }
    }
}

impl From<&SpendAccountId> for AccountKey {
    fn from(id: &SpendAccountId) -> Self {
        AccountKey {
            provider: id.provider.clone(),
            account: id.account.clone(),
        }
    }
}

/// Human-readable source label printed beside every spend figure (D4-10).
pub fn source_words(source: &SpendSource) -> String {
    match source {
        SpendSource::Poll => "polled".to_owned(),
        SpendSource::Manual { .. } => "entered by you".to_owned(),
        SpendSource::ClientReported { tool, .. } => format!("reported by a client: {tool}"),
    }
}

/// Human-readable attribution label printed beside every spend figure (D4-10).
pub const fn attribution_words(attr: SpendAttribution) -> &'static str {
    match attr {
        SpendAttribution::SameKey => "this key",
        SpendAttribution::AdminMatchedByHint => "matched by hint",
        SpendAttribution::AdminLinkedByPerson => "linked by you",
        SpendAttribution::AccountWide => "account-wide",
        SpendAttribution::Manual => "manual",
    }
}
