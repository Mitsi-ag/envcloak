//! Which provider a value belongs to, and whether it is a test or live key
//! (SPEC §6.3, §6.4: import and `add` pre-fill the item from this).
//!
//! This file is the only place in the crate that reads a value. It is
//! matched in place against the registry's patterns, which run in linear
//! time and keep no captures, so the matcher records no part of it. A
//! [`Detection`] holds provider ids and a classification: never the value,
//! a piece of it, or where in it a pattern matched. Nothing here logs.
//!
//! [`Registry::mask_keys`] reads text that may hold a pasted key (a
//! command line the audit log keeps) and returns it with every key-shaped
//! word replaced by a marker.

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

/// The bytes a key can be made of, narrowly: letters, digits, `_` and `-`,
/// as every key pattern in the registry today.
fn narrow(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

/// The bytes a key can be made of, widely: also `.`, `+`, `/`, `=` and
/// `~`, for tokens that carry base64 or dots.
fn wide(b: u8) -> bool {
    narrow(b) || matches!(b, b'.' | b'+' | b'/' | b'=' | b'~')
}

impl Registry {
    /// `text` with every word a provider's key pattern matches whole
    /// replaced by `[envcloak:key:<provider>]`. A word is a longest run of
    /// key bytes, taken twice: once of letters, digits, `_` and `-` (so
    /// `KEY=sk-...` and `Bearer sk-...` give the key alone), and once also
    /// with `.`, `+`, `/`, `=` and `~`. For a command line an agent ran,
    /// before the audit log keeps it: agents paste keys into commands.
    pub fn mask_keys(&self, text: &str) -> String {
        let b = text.as_bytes();
        let mut hits: Vec<(usize, usize, usize)> = Vec::new();
        for class in [narrow as fn(u8) -> bool, wide] {
            let mut at = 0;
            while at < b.len() {
                if !class(b[at]) {
                    at += 1;
                    continue;
                }
                let start = at;
                while at < b.len() && class(b[at]) {
                    at += 1;
                }
                if at - start >= crate::MIN_KEY_LEN {
                    if let Some(&p) = self.key_matches(&b[start..at]).first() {
                        hits.push((start, at, p));
                    }
                }
            }
        }
        if hits.is_empty() {
            return text.to_owned();
        }
        hits.sort_unstable();
        let providers = self.providers();
        let mut out = String::with_capacity(text.len());
        let mut at = 0;
        for (start, end, p) in hits {
            if end <= at {
                continue;
            }
            // Runs end at ASCII bytes, so these are character boundaries.
            out.push_str(&text[at..start.max(at)]);
            out.push_str("[envcloak:key:");
            out.push_str(providers[p].id.as_str());
            out.push(']');
            at = end;
        }
        out.push_str(&text[at..]);
        out
    }
}
