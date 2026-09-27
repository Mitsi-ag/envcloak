//! Which provider a value belongs to, and whether it is a test or live key
//! (SPEC §6.3, §6.4: import and `add` pre-fill the item from this).
//!
//! This file is the only place in the crate that reads a value. It is
//! matched in place against the registry's patterns, which run in linear
//! time and keep no captures, so the matcher records no part of it. A
//! [`Detection`] holds provider ids and a classification: never the value,
//! a piece of it, or where in it a pattern matched. Nothing here logs.

use envcloak_core::SecretBytes;
use envcloak_core::vault::Classification;
use secrecy::ExposeSecret;

use crate::registry::{ProviderId, Registry};

/// The result of [`Registry::detect`]. Holds no part of the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    /// The provider: the one provider whose key pattern matches the whole
    /// value, or, when several do, the one of them whose env hints name the
    /// variable. `None` when no pattern matches or the tie stands.
    pub provider: Option<ProviderId>,
    /// From the provider's live and test patterns. With no provider, the
    /// classification every candidate agrees on, or unknown.
    pub classification: Classification,
    /// Several providers' key patterns match and the variable name does not
    /// pick one of them, so the caller should ask which it is.
    pub ambiguous: bool,
    /// Every provider whose key pattern matches, sorted by id.
    pub candidates: Vec<ProviderId>,
}

impl Registry {
    /// Detects the provider and classification of `value`, which was read
    /// from the variable `env_name` when there is one. Key patterns match
    /// whole values: a value with a prefix, a suffix or surrounding
    /// whitespace matches nothing. The variable name only breaks ties
    /// between providers whose patterns all match; it never overrides a
    /// pattern.
    pub fn detect(&self, value: &SecretBytes, env_name: Option<&str>) -> Detection {
        #[allow(clippy::disallowed_methods)] // Matched in place; never copied, logged or returned.
        let v: &[u8] = value.expose_secret();
        let providers = self.providers();
        let found = self.key_matches(v);
        let pick = match found.as_slice() {
            [] => None,
            [one] => Some(*one),
            many => {
                let hinted: Vec<usize> = many
                    .iter()
                    .copied()
                    .filter(|&i| env_name.is_some_and(|n| providers[i].hinted_by(n)))
                    .collect();
                match hinted.as_slice() {
                    [one] => Some(*one),
                    _ => None,
                }
            }
        };
        let classification = match pick {
            Some(i) => providers[i].classify(v),
            None => {
                let mut each = found.iter().map(|&i| providers[i].classify(v));
                match each.next() {
                    Some(first) if each.all(|c| c == first) => first,
                    _ => Classification::Unknown,
                }
            }
        };
        Detection {
            provider: pick.map(|i| providers[i].id.clone()),
            classification,
            ambiguous: pick.is_none() && !found.is_empty(),
            candidates: found.iter().map(|&i| providers[i].id.clone()).collect(),
        }
    }
}
