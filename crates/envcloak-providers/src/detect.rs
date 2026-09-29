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

/// The shortest run of ASCII letters and digits [`shaped_like_secret`]
/// takes for a generated key or token.
pub const SECRET_RUN: usize = 24;

/// Whether `value` looks like a credential by its shape alone, whoever
/// issued it (SPEC §6.4: an import keeps secrets, not configuration):
/// - a URL with a password in its user information (`scheme://user:pass@`
///   up to the last `@`, since real passwords hold `/` too); or
/// - a run of at least [`SECRET_RUN`] ASCII letters and digits that mixes
///   two of lowercase, uppercase and digits, as generated keys and tokens
///   do.
///
/// Read in place, like [`Registry::detect`]: nothing of the value is
/// copied, kept or returned.
pub fn shaped_like_secret(value: &SecretBytes) -> bool {
    #[allow(clippy::disallowed_methods)] // Read in place; only a yes or no leaves.
    let v: &[u8] = value.expose_secret();
    url_with_password(v) || key_shaped_run(v)
}

fn url_with_password(v: &[u8]) -> bool {
    let Some(at) = v.windows(3).position(|w| w == b"://") else {
        return false;
    };
    let rest = &v[at + 3..];
    let Some(last_at) = rest.iter().rposition(|&b| b == b'@') else {
        return false;
    };
    let userinfo = &rest[..last_at];
    userinfo
        .iter()
        .position(|&b| b == b':')
        .is_some_and(|colon| colon + 1 < userinfo.len())
}

fn key_shaped_run(v: &[u8]) -> bool {
    let (mut run, mut classes) = (0usize, 0u8);
    for &b in v {
        let class = if b.is_ascii_lowercase() {
            1
        } else if b.is_ascii_uppercase() {
            2
        } else if b.is_ascii_digit() {
            4
        } else {
            (run, classes) = (0, 0);
            continue;
        };
        run += 1;
        classes |= class;
        if run >= SECRET_RUN && classes.count_ones() >= 2 {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod shape_tests {
    use super::*;

    fn shaped(s: &[u8]) -> bool {
        shaped_like_secret(&SecretBytes::copy_from(s))
    }

    #[test]
    fn urls_with_passwords_and_generated_keys_are_secrets() {
        for yes in [
            &b"postgres://acme:pa/ss\"w+rd x\xc3\xa9y@db.acme.internal:5432/acme"[..],
            b"redis://:only-a-password@cache:6379",
            b"https://user:p@host/path@with-at",
            b"prefix-aB3dE5fG7hJ9kL1mN3pQ5rS7-suffix",
            b"0123456789abcdef0123456789abcdef",
        ] {
            assert!(shaped(yes), "{:?}", String::from_utf8_lossy(yes));
        }
        for no in [
            &b"https://example.com/path"[..],
            b"postgres://user@db/acme",
            b"postgres://user:@db/acme",
            b"production",
            b"8080",
            b"a-long-value-made-of-words-and-dashes-only",
            b"ALLUPPERCASEBUTLONGERTHANTWENTYFOUR",
            b"abcdefghijklmnopqrstuvwxyzabcdef",
            b"",
        ] {
            assert!(!shaped(no), "{:?}", String::from_utf8_lossy(no));
        }
    }
}
