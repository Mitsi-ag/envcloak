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
    url_password(v).is_some()
}

/// The password of a URL with one: the user information after its first
/// `:`, up to the last `@`. `None` when `v` is no URL, has no `@` after
/// `://`, or its password is empty.
fn url_password(v: &[u8]) -> Option<&[u8]> {
    let at = v.windows(3).position(|w| w == b"://")?;
    let rest = &v[at + 3..];
    let last_at = rest.iter().rposition(|&b| b == b'@')?;
    let userinfo = &rest[..last_at];
    let colon = userinfo.iter().position(|&b| b == b':')?;
    let password = &userinfo[colon + 1..];
    (!password.is_empty()).then_some(password)
}

/// Every reading of a URL's password a server could take, each non-empty.
/// The user information ends at an `@` after `://`, and the password is
/// what follows its first `:`. Which `@` ends it is not certain, so each
/// of these is a reading:
/// - the last `@` in the authority, which ends at the first `/`, `?` or
///   `#` (RFC 3986): an `@` in the path, query or fragment
///   (`?application_name=api@prod`) is none of the password's;
/// - the first `@` after the `:`: a password holding `/`, `?` or `#`
///   unescaped, with an `@` further on;
/// - the last `@` of all ([`url_password`]): a password holding `/` and
///   `@`.
fn url_passwords(v: &[u8]) -> Vec<&[u8]> {
    let Some(at) = v.windows(3).position(|w| w == b"://") else {
        return Vec::new();
    };
    let rest = &v[at + 3..];
    let authority = rest
        .iter()
        .position(|&b| matches!(b, b'/' | b'?' | b'#'))
        .unwrap_or(rest.len());
    let first_colon = rest.iter().position(|&b| b == b':');
    let ends = [
        rest[..authority].iter().rposition(|&b| b == b'@'),
        first_colon.and_then(|c| rest[c..].iter().position(|&b| b == b'@').map(|p| c + p)),
        rest.iter().rposition(|&b| b == b'@'),
    ];
    ends.into_iter()
        .flatten()
        .filter_map(|end| {
            let colon = rest[..end].iter().position(|&b| b == b':')?;
            let password = &rest[colon + 1..end];
            (!password.is_empty()).then_some(password)
        })
        .collect()
}

/// How many characters `password` has: a `%XX` escape counts as the byte
/// it stands for, and the bytes are counted as [`SecretBytes::utf8_chars`]
/// counts them, or, when they are not UTF-8, as four bytes a character.
/// The decoded copy is wiped.
fn password_len(password: &[u8]) -> usize {
    let mut decoded = Vec::with_capacity(password.len());
    let mut i = 0;
    while i < password.len() {
        let digit = |k: usize| {
            password
                .get(k)
                .and_then(|&b| char::from(b).to_digit(16))
                .and_then(|d| u8::try_from(d).ok())
        };
        let escaped = if password[i] == b'%' {
            digit(i + 1)
                .zip(digit(i + 2))
                .map(|(hi, lo)| (hi << 4) | lo)
        } else {
            None
        };
        match escaped {
            Some(b) => {
                decoded.push(b);
                i += 3;
            }
            None => {
                decoded.push(password[i]);
                i += 1;
            }
        }
    }
    let decoded = SecretBytes::from_vec(decoded);
    decoded.utf8_chars().unwrap_or_else(|| decoded.len() / 4)
}

/// When `value` is a URL with a password ([`shaped_like_secret`]'s first
/// shape), how many characters its password has: all of the value a
/// guesser must find, since a URL's scheme, user, host and database are
/// no secret (SPEC §6.4: a short password in a long URL is short). Where
/// the password ends is read every way a server could read it
/// ([`url_passwords`]), and the fewest characters any reading gives are
/// returned, so that a short password counts as short however the rest of
/// the URL is written. Each is counted as [`password_len`] counts. `None`
/// for any other value.
///
/// Read in place, like [`Registry::detect`]: only a count leaves, and each
/// decoded password is wiped.
pub fn url_password_chars(value: &SecretBytes) -> Option<usize> {
    #[allow(clippy::disallowed_methods)] // Read in place; only a count leaves.
    let v: &[u8] = value.expose_secret();
    url_passwords(v).into_iter().map(password_len).min()
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

    fn password_chars(s: &[u8]) -> Option<usize> {
        url_password_chars(&SecretBytes::copy_from(s))
    }

    /// Only the password of a URL counts, its `%XX` escapes decoded, in
    /// characters; every URL [`shaped_like_secret`] takes for one with a
    /// password has one, and no other value does.
    #[test]
    fn a_url_password_is_counted_alone() {
        for (url, chars) in [
            (&b"postgres://app:abcdefgh@db.internal:5432/app"[..], 8),
            (b"redis://:only-a-password@cache:6379", 15),
            (b"https://user:p@host/path@with-at", 1),
            (b"mysql://u:%41%42%43%44%45@db/x", 5),
            (b"mysql://u:%4@db/x", 2),
            (b"mysql://u:%zz%@db/x", 4),
            (b"amqp://u:caf%C3%A9-%E2%82%AC@mq/", 6),
            (b"amqp://u:\xc3\xa9\xc3\xa9@mq/", 2),
            (b"mysql://u:%+4@db/x", 3),
            (b"x://u:%FF%FF%FF%FF%FF%FF%FF%FF@h", 2),
            (
                b"postgres://acme:pa/ss\"w+rd x\xc3\xa9y@db.acme.internal:5432/acme",
                14,
            ),
        ] {
            assert_eq!(
                password_chars(url),
                Some(chars),
                "{:?}",
                String::from_utf8_lossy(url)
            );
            assert!(shaped(url), "{:?}", String::from_utf8_lossy(url));
        }
        for no in [
            &b"https://example.com/path"[..],
            b"postgres://user@db/acme",
            b"postgres://user:@db/acme",
            b"0123456789abcdef0123456789abcdef",
            b"",
        ] {
            assert_eq!(
                password_chars(no),
                None,
                "{:?}",
                String::from_utf8_lossy(no)
            );
        }
    }

    /// Review finding F-61 (Codex): the password ran to the last `@` of
    /// the URL, so an `@` in its path, query or fragment made the host and
    /// what followed count as password, and an 8-character password in
    /// `...?application_name=api@prod` counted 69. Every reading a server
    /// could take counts, and the fewest characters any gives are the
    /// count: the authority's last `@` (RFC 3986), the first `@` after the
    /// `:` (a password with `/`, `?` or `#` in it, and an `@` further on),
    /// and the last `@` of all.
    #[test]
    fn an_at_sign_after_the_authority_is_not_the_passwords() {
        for (url, chars) in [
            // An `@` in the query, the path and the fragment.
            (
                &b"postgres://app:abcdefgh@db.internal:5432/app?application_name=api@prod"[..],
                8,
            ),
            (b"postgres://app:abcdefgh@db.internal:5432/app@v2/data", 8),
            (b"https://app:abcdefgh@api.internal/v1#section@anchor", 8),
            (
                b"redis://:abcdefghij@cache.internal:6379/0?client=a@b@c",
                10,
            ),
            // Escaped, with an `@` in the query.
            (
                b"mysql://app:%61%62%63%64%65%66@db.internal:3306/app?tag=x@y",
                6,
            ),
            // A password with `/` or `#` in it, and an `@` in the query:
            // only the first `@` after the `:` ends it there.
            (
                b"postgres://app:pa/ss@db.internal:5432/app?application_name=api@prod",
                5,
            ),
            (b"postgres://app:pa#ss@db.internal:5432/app?x=a@b", 5),
            // A password with an `@` in it: its part before that `@` is a
            // reading too.
            (b"postgres://app:p@ss@db.internal:5432/app", 1),
            // Controls: 16 characters, with and without an `@` after the
            // authority, and a password holding `/` and `@` (the last `@`).
            (b"postgres://app:abcdefghijklmnop@db.internal:5432/app", 16),
            (
                b"postgres://app:abcdefghijklmnop@db.internal:5432/app?application_name=api@prod",
                16,
            ),
        ] {
            assert_eq!(
                password_chars(url),
                Some(chars),
                "{:?}",
                String::from_utf8_lossy(url)
            );
            assert!(shaped(url), "{:?}", String::from_utf8_lossy(url));
        }
        // An `@` only after the authority, and no `:` before it: no
        // password in any reading.
        for no in [
            &b"https://example.com/users/@me"[..],
            b"https://example.com/path?user=a@b",
        ] {
            assert_eq!(
                password_chars(no),
                None,
                "{:?}",
                String::from_utf8_lossy(no)
            );
        }
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
