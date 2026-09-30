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

/// Password readings of a value ([`password_chars`]), and how many bytes
/// the searches read to find them. No `Debug`: the readings are parts of
/// the value.
#[derive(Default)]
struct Readings<'a> {
    found: Vec<&'a [u8]>,
    /// Every byte a search read, counted each time one read it. The tests
    /// hold it linear in the value's length, and see it stop growing once
    /// the searches stop at [`MAX_PASSWORD_READINGS`] (review R-5): the
    /// bound is checked by what is read, not by how long it took.
    scanned: usize,
}

impl<'a> Readings<'a> {
    /// Keeps `reading`, and says whether the search goes on: not once
    /// there are more readings than [`MAX_PASSWORD_READINGS`].
    fn push(&mut self, reading: &'a [u8]) -> bool {
        self.found.push(reading);
        !self.over()
    }

    /// More readings than are counted: the value counts as short.
    fn over(&self) -> bool {
        self.found.len() > MAX_PASSWORD_READINGS
    }

    /// The first position in `hay` whose byte `pred` takes, counting each
    /// byte looked at.
    fn position(&mut self, hay: &[u8], pred: impl Fn(u8) -> bool) -> Option<usize> {
        let found = hay.iter().position(|&b| pred(b));
        self.scanned += found.map_or(hay.len(), |p| p + 1);
        found
    }

    /// Where `needle` first starts in `hay`, counting each byte up to its
    /// end (or `hay`'s) once.
    fn find(&mut self, hay: &[u8], needle: &[u8]) -> Option<usize> {
        let found = hay.windows(needle.len()).position(|w| w == needle);
        self.scanned += found.map_or(hay.len(), |p| p + needle.len());
        found
    }

    /// How many bytes at the start of `hay` `pred` takes, counting each
    /// byte looked at.
    fn run(&mut self, hay: &[u8], pred: impl Fn(u8) -> bool) -> usize {
        self.position(hay, |b| !pred(b)).unwrap_or(hay.len())
    }
}

/// Every reading of a URL's password a server could take, each non-empty,
/// in every URL the value holds: each `://` starts one, since a value may
/// list several (`redis://a:26379,redis://:<password>@b:26379`, a proxy's
/// URL before a database's), and a password in a later URL would
/// otherwise be measured from the first one's host (review R-4). From
/// each `://`, the user information ends at an `@` after it, and the
/// password is what follows its first `:`. Which `@` ends it is not
/// certain, so each of these is a reading:
/// - the last `@` in the authority, which ends at the first `/`, `?` or
///   `#` (RFC 3986): an `@` in the path, query or fragment
///   (`?application_name=api@prod`) is none of the password's;
/// - the first `@` after the `:`: a password holding `/`, `?` or `#`
///   unescaped, with an `@` further on;
/// - the last `@` of all ([`url_password`]): a password holding `/` and
///   `@`.
///
/// Each position these need is found by a cursor that only moves forward
/// as the URLs do, so every byte is read a bounded number of times
/// however many URLs the value lists.
fn url_passwords<'a>(v: &'a [u8], out: &mut Readings<'a>) {
    let is_at = |b: u8| b == b'@';
    let last_at = v.iter().rposition(|&b| is_at(b));
    out.scanned += last_at.map_or(v.len(), |p| v.len() - p);
    // The authority's end; the scan for the last `@` before it, and that
    // `@`; the first `:`; the first `@` at or after that `:`.
    let (mut authority, mut seen, mut seen_at) = (0, 0, None);
    let (mut colon, mut after) = (0, 0);
    let mut from = 0;
    while let Some(p) = out.find(&v[from..], b"://") {
        let start = from + p + 3;
        from = start;
        authority = authority.max(start);
        authority += out.run(&v[authority..], |b| !matches!(b, b'/' | b'?' | b'#'));
        while seen < authority {
            if is_at(v[seen]) {
                seen_at = Some(seen);
            }
            seen += 1;
            out.scanned += 1;
        }
        colon = colon.max(start);
        colon += out.run(&v[colon..], |b| b != b':');
        if colon == v.len() {
            // No `:` from here on: no password in this URL or any after.
            return;
        }
        after = after.max(colon);
        after += out.run(&v[after..], |b| !is_at(b));
        let ends = [
            seen_at.filter(|&a| a >= start),
            Some(after).filter(|&a| a < v.len()),
            last_at.filter(|&a| a >= start),
        ];
        for (k, end) in ends.iter().enumerate() {
            let Some(end) = *end else { continue };
            if ends[..k].contains(&Some(end)) || end <= colon + 1 {
                continue;
            }
            if !out.push(&v[colon + 1..end]) {
                return;
            }
        }
    }
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

/// Go's MySQL DSN, `user:password@tcp(host:3306)/db`, has no scheme: its
/// user information is the value up to an `@` that an address follows,
/// and the password is what follows its first `:`. An address is a
/// protocol name and `(` (`@tcp(`, `@unix(`, `@tcp6(`), a protocol name
/// and `/` (`@tcp/db`, the protocol's default address, which the driver's
/// README shows: review R-3), or `/` alone (`@/db`, the default protocol
/// and address). Each such `@` is a reading, since the password may hold
/// an `@` too. A value whose first `:` starts `://` is a URL, which
/// [`url_passwords`] reads: what follows is `//` and a user, no password
/// (`postgres://app@db/app`), so a DSN whose password starts with `//` is
/// measured whole.
fn dsn_passwords<'a>(v: &'a [u8], out: &mut Readings<'a>) {
    let Some(colon) = out.position(v, |b| b == b':') else {
        return;
    };
    if v[colon..].starts_with(b"://") {
        return;
    }
    let protocol = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-');
    let mut at = colon + 1;
    while let Some(p) = out.position(&v[at..], |b| b == b'@') {
        at += p;
        let rest = &v[at + 1..];
        let name = out.run(rest, protocol);
        let address = match rest.get(name) {
            Some(b'/') => true,
            Some(b'(') => name > 0,
            _ => false,
        };
        let password = &v[colon + 1..at];
        if address && !password.is_empty() && !out.push(password) {
            return;
        }
        at += 1;
    }
}

/// The names a password field goes by in connection strings, in any case.
const PASSWORD_FIELDS: [&[u8]; 3] = [b"password", b"passwd", b"pwd"];

/// Password fields of connection strings made of `name=value` fields: the
/// libpq keyword form (`host=db user=app password=...`), ADO.NET and ODBC
/// (`Server=db;Password=...;`, `PWD=...`) and JDBC's query (`...?user=app&
/// password=...`). A field is one of [`PASSWORD_FIELDS`] at the start of
/// the value or after a byte that is not a letter, digit or `_`, then `=`,
/// with spaces or tabs around it. Its value runs to the first `;`, `&` or
/// whitespace; when it starts with `'`, `"` or `{`, what the quotes hold
/// up to the first closing `'`, `"` or `}` is a reading too, since libpq,
/// ADO.NET and ODBC quote a value that holds a separator.
///
/// Only a field that gives a reading can read far (to the value's end);
/// the search stops after more than [`MAX_PASSWORD_READINGS`] readings, so
/// it reads each byte at most twice for each of those and a bounded
/// number of times otherwise.
fn field_passwords<'a>(v: &'a [u8], out: &mut Readings<'a>) {
    let blank = |b: u8| matches!(b, b' ' | b'\t');
    for start in 0..v.len() {
        out.scanned += 1;
        if start > 0 && (v[start - 1].is_ascii_alphanumeric() || v[start - 1] == b'_') {
            continue;
        }
        let mut name = None;
        for field in PASSWORD_FIELDS {
            out.scanned += field.len();
            if v.get(start..start + field.len())
                .is_some_and(|w| w.eq_ignore_ascii_case(field))
            {
                name = Some(field);
                break;
            }
        }
        let Some(name) = name else {
            continue;
        };
        let mut i = start + name.len();
        i += out.run(&v[i..], blank);
        if v.get(i) != Some(&b'=') {
            continue;
        }
        i += 1;
        i += out.run(&v[i..], blank);
        let value = &v[i..];
        let plain = out
            .position(value, |b| {
                matches!(b, b';' | b'&') || b.is_ascii_whitespace()
            })
            .unwrap_or(value.len());
        if plain > 0 && !out.push(&value[..plain]) {
            return;
        }
        let close = match value.first() {
            Some(b'\'') => Some(b'\''),
            Some(b'"') => Some(b'"'),
            Some(b'{') => Some(b'}'),
            _ => None,
        };
        if let Some(close) = close {
            let inner = &value[1..];
            let end = out.position(inner, |b| b == close).unwrap_or(inner.len());
            if end > 0 && !out.push(&inner[..end]) {
                return;
            }
        }
    }
}

/// The most password readings [`password_chars`] counts. A value with
/// more is counted as short, which fails closed (compared only for a
/// person), and every search stops there, so the work stays linear in the
/// value's length: the tests count the bytes read ([`Readings`]).
pub const MAX_PASSWORD_READINGS: usize = 64;

/// Every password reading of `v` in the forms [`password_chars`] knows,
/// the searches stopping once there are more than
/// [`MAX_PASSWORD_READINGS`].
fn readings(v: &[u8]) -> Readings<'_> {
    let mut out = Readings::default();
    url_passwords(v, &mut out);
    if !out.over() {
        dsn_passwords(v, &mut out);
    }
    if !out.over() {
        field_passwords(v, &mut out);
    }
    out
}

/// When `value` holds a password in a form this knows, how many
/// characters it has: all of the value a guesser must find, since the
/// rest (scheme, user, host, port, database, options) is no secret (SPEC
/// §6.4: a short password in a long value is short). The forms:
/// - a URL with a password ([`shaped_like_secret`]'s first shape), where
///   the password is read at every `@` a server could end it at, in every
///   URL the value lists (`url_passwords`);
/// - Go's MySQL DSN, `user:password@tcp(host)/db`, `@tcp/db` or `@/db`
///   (`dsn_passwords`);
/// - a `password=`, `passwd=` or `pwd=` field of a libpq, ADO.NET, ODBC or
///   JDBC connection string (`field_passwords`).
///
/// Every reading counts, and the fewest characters any gives are returned,
/// so a short password counts as short however the rest is written. Each
/// is counted as `password_len` counts; more than
/// [`MAX_PASSWORD_READINGS`] readings count as 0. `None` when no form
/// finds a password.
///
/// Read in place, like [`Registry::detect`]: only a count leaves, and each
/// decoded password is wiped.
pub fn password_chars(value: &SecretBytes) -> Option<usize> {
    #[allow(clippy::disallowed_methods)] // Read in place; only a count leaves.
    let v: &[u8] = value.expose_secret();
    let readings = readings(v);
    if readings.over() {
        return Some(0);
    }
    readings.found.into_iter().map(password_len).min()
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
        super::password_chars(&SecretBytes::copy_from(s))
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

    /// Review T13 open 2: only `scheme://user:password@` was known, so a
    /// short password in Go's MySQL DSN, the libpq keyword form or a JDBC
    /// query was measured with the whole value. Each form's password is
    /// counted alone, every reading of it, the fewest characters winning.
    #[test]
    fn connection_string_passwords_are_counted_alone() {
        for (value, chars) in [
            // Go's MySQL DSN.
            (
                &b"app:abcdefgh@tcp(db.internal:3306)/app?parseTime=true"[..],
                8,
            ),
            (b"app:abcdefgh@unix(/var/run/mysqld/mysqld.sock)/app", 8),
            (b"app:abcdefgh@tcp6([::1]:3306)/app", 8),
            (b"app:abcdefgh@/app", 8),
            (b"app:p@ssword1@tcp(db.internal:3306)/app", 9),
            // libpq's keyword form, spaces around `=`, and quoted.
            (
                b"host=db.internal port=5432 dbname=app user=app password=abcdefgh sslmode=require",
                8,
            ),
            (b"host=db.internal password = abcdefgh dbname=app", 8),
            (b"host=db.internal password='abc def ghij' dbname=app", 4),
            // Quoted: the quotes are no part of it.
            (b"host=db.internal password='abcdefghijklmn' dbname=app", 14),
            (b"Driver=x;Server=db.internal;PWD={abcdefghijklmn};", 14),
            // ADO.NET and ODBC, `;`-separated, in any case, braced.
            (
                b"Server=db.internal;Database=app;User Id=app;Password=abcdefgh;",
                8,
            ),
            (
                b"Driver={PostgreSQL};Server=db.internal;UID=app;PWD=abcdefgh;",
                8,
            ),
            (b"Server=db.internal;PASSWD=abcdefgh", 8),
            // Braced, holding `;`: up to the `;` with its brace (18), or
            // what the braces hold (20).
            (
                b"Driver=x;Server=db.internal;UID=app;PWD={abcdefghijklmnopq;rs};",
                18,
            ),
            // JDBC's query, escaped too.
            (
                b"jdbc:postgresql://db.internal:5432/app?user=app&password=abcdefgh&ssl=true",
                8,
            ),
            (
                b"jdbc:sqlserver://db.internal:1433;databaseName=app;user=app;password=abcdefgh;",
                8,
            ),
            (
                b"jdbc:mysql://db.internal:3306/app?password=%61%62%63%64%65%66&user=app",
                6,
            ),
            // Controls: 16 characters in each form.
            (
                b"app:abcdefghijklmnop@tcp(db.internal:3306)/app?parseTime=true",
                16,
            ),
            (b"host=db.internal user=app password=abcdefghijklmnop", 16),
            (
                b"jdbc:postgresql://db.internal:5432/app?user=app&password=abcdefghijklmnop",
                16,
            ),
        ] {
            assert_eq!(
                password_chars(value),
                Some(chars),
                "{:?}",
                String::from_utf8_lossy(value)
            );
        }
        for no in [
            // Not a field: the name runs on, no `=`, or nothing after it.
            &b"mypassword=abcdefgh"[..],
            b"db_password=abcdefgh",
            b"the password is abcdefgh",
            b"host=db.internal dbname=app password=",
            b"host=db.internal password=;",
            // Not a DSN: no `:` before the `@`, or no address after it.
            b"app@tcp(db.internal:3306)/app",
            b"app:abcdefgh@db.internal",
        ] {
            assert_eq!(
                password_chars(no),
                None,
                "{:?}",
                String::from_utf8_lossy(no)
            );
        }
        // More readings than are counted: short, whatever they hold.
        let many = |n: usize| "password=abcdefghijklmnopq ".repeat(n).into_bytes();
        assert_eq!(password_chars(&many(MAX_PASSWORD_READINGS)), Some(17));
        assert_eq!(password_chars(&many(MAX_PASSWORD_READINGS + 1)), Some(0));
        // Hostile runs the size of the field cap, fields with no separator
        // and DSN addresses: the search stops at the cap, so each is
        // counted short at once rather than read at every field.
        let run = |unit: &str| unit.repeat(65_536 / unit.len()).into_bytes();
        assert_eq!(password_chars(&run("password=")), Some(0));
        assert_eq!(password_chars(&run("pwd='{\"")), Some(0));
        let dsn = [b"app:".to_vec(), run("x@tcp(")].concat();
        assert_eq!(password_chars(&dsn), Some(0));
        // Empty fields are no readings, however many.
        assert_eq!(password_chars(&run("password=;")), None);
    }

    /// Review R-3: Go's MySQL DSN with a protocol and no address
    /// (`user:pw@tcp/dbname`, the protocol's default address, a form the
    /// go-sql-driver README shows) was not read, since a protocol name had
    /// to be followed by `(`, so an 8-character password was measured
    /// with the whole value. A protocol name followed by `/` is an address
    /// too.
    #[test]
    fn a_dsn_with_a_protocol_and_no_address_is_read() {
        for (value, chars) in [
            (&b"app:abcdefgh@tcp/app"[..], 8),
            (b"app:abcdefgh@unix/app?parseTime=true", 8),
            (b"app:abcdefgh@tcp6/", 8),
            (b"app:p@ssword1@tcp/app", 9),
            // Control: 16 characters.
            (b"app:abcdefghijklmnop@tcp/app", 16),
        ] {
            assert_eq!(
                password_chars(value),
                Some(chars),
                "{:?}",
                String::from_utf8_lossy(value)
            );
        }
        // No address: a protocol name with nothing after it, or `(` with
        // no protocol name. A URL with a user and no password, whose host
        // and path look like a protocol and its address, is no DSN.
        for no in [
            &b"app:abcdefgh@tcp"[..],
            b"app:abcdefgh@(db)/app",
            b"postgres://app@db/app",
            b"redis://cache@localhost/0",
            b"mysql://app@/app",
        ] {
            assert_eq!(
                password_chars(no),
                None,
                "{:?}",
                String::from_utf8_lossy(no)
            );
        }
    }

    /// Review R-4: only the first `://` was read, so in a value listing
    /// several URLs a password in a later one was measured from the first
    /// one's port, and an 8-character password counted 23 or 30. Every
    /// `://` starts a URL whose password is read; 16 characters there
    /// stay 16.
    #[test]
    fn a_password_in_a_later_url_is_counted_alone() {
        for (value, chars) in [
            (
                &b"redis://s1.internal:26379,redis://:abcdefgh@s2.internal:26379"[..],
                8,
            ),
            (
                b"https://proxy.internal:8443/x postgres://app:abcdefgh@db.internal/app",
                8,
            ),
            (
                b"amqp://mq1.internal amqp://mq2.internal amqp://app:%61%62%63%64@mq3.internal/",
                4,
            ),
            // Controls: 16 characters in the later URL.
            (
                b"redis://s1.internal:26379,redis://:abcdefghijklmnop@s2.internal:26379",
                16,
            ),
            (
                b"https://proxy.internal:8443/x postgres://app:abcdefghijklmnop@db.internal/app",
                16,
            ),
        ] {
            assert_eq!(
                password_chars(value),
                Some(chars),
                "{:?}",
                String::from_utf8_lossy(value)
            );
        }
        for no in [
            &b"https://a.internal/x https://b.internal/y"[..],
            b"x://x://x://",
        ] {
            assert_eq!(
                password_chars(no),
                None,
                "{:?}",
                String::from_utf8_lossy(no)
            );
        }
    }

    /// Where each reading is in `v`: its offset and length.
    fn spans(v: &[u8], found: &[&[u8]]) -> Vec<(usize, usize)> {
        found
            .iter()
            .map(|r| (r.as_ptr().addr() - v.as_ptr().addr(), r.len()))
            .collect()
    }

    /// The URL readings as the one-URL search made them before review
    /// R-4, repeated from every `://`: the reference the cursors must
    /// agree with.
    fn url_spans_by_restarting(v: &[u8]) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        for start in (0..v.len().saturating_sub(2))
            .filter(|&p| &v[p..p + 3] == b"://")
            .map(|p| p + 3)
        {
            let rest = &v[start..];
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
            for (k, end) in ends.iter().enumerate() {
                let Some(end) = *end else { continue };
                if ends[..k].contains(&Some(end)) {
                    continue;
                }
                let Some(colon) = rest[..end].iter().position(|&b| b == b':') else {
                    continue;
                };
                if colon + 1 < end {
                    out.push((start + colon + 1, end - colon - 1));
                }
            }
        }
        out
    }

    /// The cursors of `url_passwords` give exactly the readings a search
    /// restarted at every `://` gives, on values made of the bytes that
    /// matter to it.
    #[test]
    fn url_readings_agree_with_a_search_from_every_scheme() {
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..50_000 {
            let len = usize::try_from(next() % 40).unwrap();
            let v: Vec<u8> = (0..len)
                .map(|_| b"a:/@?#"[usize::try_from(next() % 6).unwrap()])
                .collect();
            let mut r = Readings::default();
            url_passwords(&v, &mut r);
            assert!(!r.over());
            assert_eq!(
                spans(&v, &r.found),
                url_spans_by_restarting(&v),
                "{:?}",
                String::from_utf8_lossy(&v)
            );
        }
    }

    /// At most how many times the searches read each byte of a value:
    /// twice for each counted reading that runs to the value's end, and a
    /// bounded number of passes besides (URLs 6, the DSN 4, the fields' 18
    /// at each start and 2 for blanks), with room to spare.
    const READS_PER_BYTE: usize = 2 * (MAX_PASSWORD_READINGS + 1) + 40;

    /// Review R-5: removing the searches' stop at the reading cap left
    /// every result the same and only made them slower, so no test failed.
    /// The bytes read are counted. A value with more readings than are
    /// counted is read only up to the reading past the cap: the same bytes
    /// however long it runs on. Any value is read at most
    /// [`READS_PER_BYTE`] times a byte, and twice as long a value at most
    /// twice as much, including values that read to their end at every
    /// counted reading and values with no reading at all.
    #[test]
    fn the_searches_stop_at_the_cap_and_stay_linear() {
        let run = |unit: &str, len: usize| unit.repeat(len / unit.len()).into_bytes();
        // Each search on its own, since the others read such a value to
        // its end looking for their forms.
        type Search = for<'a> fn(&'a [u8], &mut Readings<'a>);
        let past_cap: [(Search, &str, &str); 4] = [
            (field_passwords, "", "password=abcdefghijklmnopq "),
            (field_passwords, "", "pwd={abcdefghijklmnop};"),
            (url_passwords, "", "a://u:abcdefghijklmnop@h/ "),
            (dsn_passwords, "app:", "x@tcp("),
        ];
        for (search, head, unit) in past_cap {
            let read = |len: usize| {
                let v = [head.as_bytes(), &run(unit, len)].concat();
                let mut r = Readings::default();
                search(&v, &mut r);
                (r.over(), r.scanned)
            };
            let ((over, a), (over_long, b)) = (read(1 << 16), read(1 << 17));
            assert!(over && over_long, "{unit:?}");
            assert_eq!(a, b, "{unit:?}");
        }

        for unit in [
            "password=",
            "pwd='{\"",
            "password  ",
            "passwor",
            "x://",
            "://a:",
            "a:@",
            "@tcp(",
            "a",
        ] {
            let (short, long) = (run(unit, 1 << 15), run(unit, 1 << 16));
            let (a, b) = (readings(&short).scanned, readings(&long).scanned);
            assert!(a <= READS_PER_BYTE * short.len(), "{unit:?}: {a}");
            assert!(b <= READS_PER_BYTE * long.len(), "{unit:?}: {b}");
            // Twice as long, at most a little over twice as much (four
            // times for a search that reads the rest at every field).
            assert!(4 * b <= 9 * a, "{unit:?}: {a} then {b}");
        }
        // Just under the cap, each reading running to the end: the most a
        // value is read.
        let mut v = run("password=", 9 * MAX_PASSWORD_READINGS);
        v.extend(run("x", 1 << 16));
        let r = readings(&v);
        assert!(!r.over());
        assert!(r.scanned <= READS_PER_BYTE * v.len(), "{}", r.scanned);
        assert!(
            r.scanned >= MAX_PASSWORD_READINGS * (1 << 16),
            "{}",
            r.scanned
        );
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
