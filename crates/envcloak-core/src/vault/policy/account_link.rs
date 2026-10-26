//! Policy record kind 11: [`AccountLinkRecord`] (D4-09, D4-19, SPEC §5, §8).
//!
//! Links a `secret` item to a non-secret provider key identifier (e.g. OpenAI
//! `api_key_id`) reported by a usage credential poll or linked manually by a
//! person. Key hints are compared in memory and never stored in this record
//! (D4-19).

use super::super::codec::{Dec, Enc};
use super::super::error::VaultError;
use super::super::items::ItemId;
use super::{SpendAttribution, dec_item_id, enc_item_id, spend_str_ok, timestamp_ok};

/// Links a vault item to a provider key id (policy kind 11, version 1).
#[derive(Clone, PartialEq, Eq)]
pub struct AccountLinkRecord {
    pub item: ItemId,
    pub usage_credential: Option<ItemId>,
    pub provider: String,
    /// Non-secret provider key identifier (1..=64 ASCII identifier characters,
    /// never a key value or hint).
    pub provider_key_id: String,
    pub attribution: SpendAttribution,
    pub linked_at: u64,
}

impl AccountLinkRecord {
    pub fn in_bounds(&self) -> bool {
        let valid_attribution = matches!(
            self.attribution,
            SpendAttribution::AdminMatchedByHint | SpendAttribution::AdminLinkedByPerson
        );
        let valid_key_id = spend_str_ok(&self.provider_key_id)
            && self
                .provider_key_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        let distinct_items = self.usage_credential != Some(self.item);
        distinct_items
            && spend_str_ok(&self.provider)
            && valid_key_id
            && valid_attribution
            && timestamp_ok(self.linked_at)
    }

    pub(crate) fn encode(&self, e: &mut Enc) {
        enc_item_id(e, self.item);
        match self.usage_credential {
            None => {
                e.u8(0);
            }
            Some(id) => {
                e.u8(1);
                enc_item_id(e, id);
            }
        }
        e.str(&self.provider).str(&self.provider_key_id);
        self.attribution.encode(e);
        e.u64(self.linked_at);
    }

    pub(crate) fn decode(d: &mut Dec<'_>) -> Result<Self, VaultError> {
        let item = dec_item_id(d)?;
        let usage_credential = if d.bool()? {
            Some(dec_item_id(d)?)
        } else {
            None
        };
        let provider = d.string()?;
        let provider_key_id = d.string()?;
        let attribution = SpendAttribution::decode(d)?;
        let linked_at = d.u64()?;
        Ok(AccountLinkRecord {
            item,
            usage_credential,
            provider,
            provider_key_id,
            attribution,
            linked_at,
        })
    }
}

impl core::fmt::Debug for AccountLinkRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AccountLinkRecord")
            .field("item", &self.item)
            .field("usage_credential", &self.usage_credential)
            .field("provider", &self.provider)
            .field("provider_key_id_len", &self.provider_key_id.len())
            .field("attribution", &self.attribution)
            .field("linked_at", &self.linked_at)
            .finish()
    }
}
