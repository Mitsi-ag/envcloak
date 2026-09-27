//! The registry loader's safety rules (SPEC §8 "Registry safety", gate 18),
//! and the checked types they produce.
//!
//! A registry entry decides where a key may be sent: the daemon's balance
//! polling and the proxy (M6) send it only to the entry's hosts, in the
//! entry's auth slots. An entry that names the wrong host exfiltrates the
//! key, so the loader refuses:
//! - a request URL whose host no allowed host matches
//!   ([`RegistryErrorKind::RequestHostNotAllowed`]);
//! - any URL that is not `https://` ([`RegistryErrorKind::NotHttps`]);
//! - a wildcard allowed host under a multi-tenant suffix
//!   ([`RegistryErrorKind::WildcardUnderMultiTenantSuffix`]) or over one
//!   ([`RegistryErrorKind::WildcardOverMultiTenantSuffix`]), and one over a
//!   whole top-level domain or public suffix of two labels (`*.co.kr`);
//! - hosts and URLs in any but one canonical spelling: lowercase DNS names,
//!   no user name, port, IP address, trailing dot or backslash, so what a
//!   reviewer reads is the host the key goes to;
//! - a request that puts the key in a slot the entry does not declare.
//!
//! Key patterns are compiled for linear-time matching on bytes and keep no
//! captures. A key pattern must match whole values of at least
//! [`MIN_KEY_LEN`] bytes, so a pattern cannot claim every short value (doctor
//! reports registry-pattern matches of any length, SPEC §6.5). It must also
//! start with a literal of at least [`MIN_KEY_PREFIX`] bytes, such as `sk-`:
//! detection pre-fills an item's allowed hosts from the provider it names,
//! so a pattern that matched values of any shape, such as `^(?s:.){16,}$`,
//! would attach its hosts to unrelated secrets (a database URL, a generic
//! token). The prefix makes a pattern's reach plain in review; it does not
//! prove the pattern narrow.
//!
//! [`RegistryErrorKind::RequestHostNotAllowed`]: crate::RegistryErrorKind::RequestHostNotAllowed
//! [`RegistryErrorKind::NotHttps`]: crate::RegistryErrorKind::NotHttps
//! [`RegistryErrorKind::WildcardUnderMultiTenantSuffix`]: crate::RegistryErrorKind::WildcardUnderMultiTenantSuffix
//! [`RegistryErrorKind::WildcardOverMultiTenantSuffix`]: crate::RegistryErrorKind::WildcardOverMultiTenantSuffix

use regex::bytes::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};
use regex_syntax::hir::literal::{ExtractKind, Extractor};
use regex_syntax::hir::{Hir, Look};

use crate::error::RegistryErrorKind as K;

/// The longest pattern accepted, in bytes.
pub const MAX_PATTERN: usize = 256;
/// The shortest value a key pattern may match, in bytes.
pub const MIN_KEY_LEN: usize = 16;
/// The shortest literal a key pattern must start with, in bytes: `sk-`.
pub const MIN_KEY_PREFIX: usize = 3;
const MAX_URL: usize = 2048;
const MAX_JSON_PATH: usize = 256;
const MAX_JSON_SEGMENTS: usize = 16;
const MAX_DENIED_PATH: usize = 256;
/// Bounds the compiled size and nesting of patterns; the registry's
/// patterns are small.
const REGEX_SIZE_LIMIT: usize = 1 << 20;
const NEST_LIMIT: u32 = 32;

/// How a pattern must be anchored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Anchor {
    /// Matches whole values: a key pattern, `^...$`.
    Whole,
    /// Matches from the start: a live or test pattern, `^...`.
    Start,
}

/// Checks `src` against the pattern rules and compiles it: bytes, no
/// Unicode classes, linear time.
pub(crate) fn compile_pattern(src: &str, anchor: Anchor) -> Result<Regex, K> {
    check_pattern(src, anchor)?;
    RegexBuilder::new(src)
        .unicode(false)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_SIZE_LIMIT)
        .nest_limit(NEST_LIMIT)
        .build()
        .map_err(|_| K::InvalidPattern)
}

/// One set over every key pattern, so detection is one pass.
pub(crate) fn pattern_set<'a>(patterns: impl IntoIterator<Item = &'a str>) -> Result<RegexSet, K> {
    RegexSetBuilder::new(patterns)
        .unicode(false)
        .size_limit(REGEX_SIZE_LIMIT.saturating_mul(16))
        .dfa_size_limit(REGEX_SIZE_LIMIT.saturating_mul(16))
        .nest_limit(NEST_LIMIT)
        .build()
        .map_err(|_| K::InvalidPattern)
}

/// The rules are checked on the pattern's syntax tree, so they hold for
/// what the pattern means, not how it is spelled: `^a|b$` is not anchored,
/// and neither is `(?m)^...$`, whose `^` also matches after a newline.
fn check_pattern(src: &str, anchor: Anchor) -> Result<(), K> {
    if src.is_empty() || src.len() > MAX_PATTERN || !src.bytes().all(printable) {
        return Err(K::InvalidPattern);
    }
    let hir = regex_syntax::ParserBuilder::new()
        .unicode(false)
        .utf8(false)
        .nest_limit(NEST_LIMIT)
        .build()
        .parse(src)
        .map_err(|_| K::InvalidPattern)?;
    let p = hir.properties();
    if p.explicit_captures_len() > 0 {
        return Err(K::PatternHasCaptures);
    }
    if !p.look_set_prefix().contains(Look::Start) {
        return Err(K::PatternNotAnchored);
    }
    if anchor == Anchor::Whole {
        if !p.look_set_suffix().contains(Look::End) {
            return Err(K::PatternNotAnchored);
        }
        if p.minimum_len().is_none_or(|n| n < MIN_KEY_LEN) {
            return Err(K::PatternTooShort);
        }
        if !has_literal_prefix(&hir) {
            return Err(K::PatternNoLiteralPrefix);
        }
    }
    Ok(())
}

/// Every value the pattern matches starts with one of a finite set of
/// literals, each at least [`MIN_KEY_PREFIX`] bytes long. The extractor's
/// limits give up on classes of more than 10 bytes and on sets of more than
/// 250 literals, so `.`, `[a-f0-9]` or `[0-9]{3}` at the start leave no
/// literal of that length, and a pattern that could claim values of any
/// shape fails.
fn has_literal_prefix(hir: &Hir) -> bool {
    let seq = Extractor::new().kind(ExtractKind::Prefix).extract(hir);
    seq.literals()
        .is_some_and(|lits| !lits.is_empty() && lits.iter().all(|l| l.len() >= MIN_KEY_PREFIX))
}

fn printable(b: u8) -> bool {
    (0x20..0x7f).contains(&b)
}

/// A DNS label: 1 to 63 lowercase letters, digits and `-`, not starting or
/// ending with `-`.
fn valid_label(l: &str) -> bool {
    let b = l.as_bytes();
    (1..=63).contains(&b.len())
        && b.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        && b.first() != Some(&b'-')
        && b.last() != Some(&b'-')
}

/// A lowercase DNS name of two or more labels, at most 253 bytes, whose
/// last label starts with a letter. That rules out IP addresses, ports,
/// user names, trailing dots, uppercase and non-ASCII spellings.
pub(crate) fn valid_host(s: &str) -> bool {
    let mut labels = 0usize;
    let mut last = "";
    for l in s.split('.') {
        if !valid_label(l) {
            return false;
        }
        labels += 1;
        last = l;
    }
    s.len() <= 253 && labels >= 2 && last.as_bytes()[0].is_ascii_lowercase()
}

/// `domain` is `parent` or a name under it.
fn under(domain: &str, parent: &str) -> bool {
    domain == parent
        || domain
            .strip_suffix(parent)
            .is_some_and(|rest| rest.ends_with('.'))
}

/// The multi-tenant suffix list, `providers/multi-tenant-suffixes.txt`.
#[derive(Debug, Clone, Default)]
pub(crate) struct Suffixes(Vec<String>);

impl Suffixes {
    /// One DNS name per line; `#` starts a comment. Fails with the line of
    /// the first entry that is not a lowercase name of two or more labels.
    pub(crate) fn parse(text: &str) -> Result<Self, (K, u32)> {
        let mut out = Vec::new();
        for (n, line) in text.split('\n').enumerate() {
            let entry = line.split('#').next().unwrap_or("").trim();
            if entry.is_empty() {
                continue;
            }
            if !valid_host(entry) {
                let line = u32::try_from(n).unwrap_or(u32::MAX).saturating_add(1);
                return Err((K::InvalidSuffix, line));
            }
            out.push(entry.to_owned());
        }
        Ok(Suffixes(out))
    }

    pub(crate) fn as_slice(&self) -> &[String] {
        &self.0
    }

    /// Whether a wildcard over `domain` and the multi-tenant zone of a
    /// listed suffix overlap. Under or at a suffix, the wildcard covers
    /// tenant hosts; above one, it covers every tenant host under it.
    fn check_wildcard(&self, domain: &str) -> Result<(), K> {
        if self.0.iter().any(|s| under(domain, s)) {
            return Err(K::WildcardUnderMultiTenantSuffix);
        }
        if self.0.iter().any(|s| under(s, domain)) {
            return Err(K::WildcardOverMultiTenantSuffix);
        }
        Ok(())
    }
}

/// Second-level labels under which many country-code domains register
/// names for anyone: `co.kr`, `com.sg` and `org.il` are public suffixes, so
/// a wildcard over a two-label domain that starts with one covers hosts
/// anyone can register, whether or not the list names it.
const PUBLIC_SECOND_LEVEL: &[&str] = &[
    "ac", "biz", "co", "com", "edu", "gen", "go", "gob", "gov", "govt", "gv", "info", "int", "ltd",
    "me", "mil", "ne", "net", "nic", "nom", "or", "org", "plc", "sch", "web",
];

/// A wildcard domain of one label (`com`), or of two whose first is a
/// public second-level label (`co.kr`).
fn public_suffix_shaped(domain: &str) -> bool {
    match domain.split_once('.') {
        None => true,
        Some((first, rest)) => !rest.contains('.') && PUBLIC_SECOND_LEVEL.contains(&first),
    }
}

/// An allowed host: an exact host (`api.openai.com`), or a wildcard
/// (`*.example.com`) that matches every host under its domain but not the
/// domain itself.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HostPattern {
    text: String,
    wildcard: bool,
}

impl HostPattern {
    pub(crate) fn parse(s: &str, suffixes: &Suffixes) -> Result<Self, K> {
        let (wildcard, domain) = match s.strip_prefix("*.") {
            Some(d) => (true, d),
            None => (false, s),
        };
        if !valid_host(domain) {
            if wildcard && valid_label(domain) {
                return Err(K::WildcardTooBroad);
            }
            return Err(K::InvalidHost);
        }
        if wildcard {
            suffixes.check_wildcard(domain)?;
            if public_suffix_shaped(domain) {
                return Err(K::WildcardTooBroad);
            }
        }
        Ok(HostPattern {
            text: s.to_owned(),
            wildcard,
        })
    }

    /// As written in the registry: `api.openai.com` or `*.example.com`.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn is_wildcard(&self) -> bool {
        self.wildcard
    }

    /// The host, or the domain a wildcard covers.
    pub fn domain(&self) -> &str {
        if self.wildcard {
            &self.text[2..]
        } else {
            &self.text
        }
    }

    /// Whether `host` is this host, or for a wildcard a host under its
    /// domain. ASCII case is ignored; a trailing dot does not match.
    pub fn matches(&self, host: &str) -> bool {
        let d = self.domain();
        if !self.wildcard {
            return host.eq_ignore_ascii_case(d);
        }
        host.len() > d.len() + 1
            && host.is_char_boundary(host.len() - d.len())
            && host[host.len() - d.len()..].eq_ignore_ascii_case(d)
            && host.as_bytes()[host.len() - d.len() - 1] == b'.'
    }
}

impl core::fmt::Display for HostPattern {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.text)
    }
}

/// An `https://` URL whose host is a [`HostPattern`]-style lowercase DNS
/// name, with no user name, port, whitespace or backslash.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HttpsUrl {
    text: String,
    host_end: usize,
}

impl HttpsUrl {
    const SCHEME: &'static str = "https://";

    /// `fragment`: whether a `#` part is accepted (in a link, not in a
    /// request).
    pub(crate) fn parse(s: &str, fragment: bool) -> Result<Self, K> {
        let rest = s.strip_prefix(Self::SCHEME).ok_or(K::NotHttps)?;
        if s.len() > MAX_URL || !s.bytes().all(|b| printable(b) && b != b' ' && b != b'\\') {
            return Err(K::InvalidUrl);
        }
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        if !valid_host(&rest[..end]) || (!fragment && rest[end..].contains('#')) {
            return Err(K::InvalidUrl);
        }
        Ok(HttpsUrl {
            text: s.to_owned(),
            host_end: Self::SCHEME.len() + end,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn host(&self) -> &str {
        &self.text[Self::SCHEME.len()..self.host_end]
    }

    /// The path, without the query or fragment; `/` when the URL has none.
    pub fn path(&self) -> &str {
        let rest = &self.text[self.host_end..];
        match &rest[..rest.find(['?', '#']).unwrap_or(rest.len())] {
            "" => "/",
            path => path,
        }
    }
}

impl core::fmt::Display for HttpsUrl {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.text)
    }
}

/// Headers an auth slot may not be: framing, hop-by-hop and routing
/// headers, cookies, and the proxy's own credentials.
const FORBIDDEN_HEADERS: &[&str] = &[
    "connection",
    "content-length",
    "content-type",
    "cookie",
    "expect",
    "forwarded",
    "host",
    "keep-alive",
    "proxy-authorization",
    "proxy-connection",
    "set-cookie",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "via",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
];

/// Where a provider takes its key (SPEC §6.2 step 3). The proxy (M6)
/// substitutes a placeholder only when it is the entire value of a declared
/// slot.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AuthSlot {
    /// A request header, lowercase, whose value is the key, after `scheme`
    /// and a space when there is one (`Authorization: Bearer <key>`,
    /// `x-api-key: <key>`).
    Header {
        name: String,
        scheme: Option<String>,
    },
    /// The user-name part of `Authorization: Basic`.
    BasicUser,
    /// The password part of `Authorization: Basic`.
    BasicPassword,
    /// A query parameter.
    Query { name: String },
}

impl AuthSlot {
    /// From a slot table's keys: `header` with an optional `scheme`,
    /// `basic` (`"user"` or `"password"`), or `query`.
    pub(crate) fn from_parts(
        header: Option<&str>,
        scheme: Option<&str>,
        basic: Option<&str>,
        query: Option<&str>,
    ) -> Result<Self, K> {
        match (header, scheme, basic, query) {
            (Some(name), scheme, None, None) => {
                let name_ok = (1..=64).contains(&name.len())
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                    && !FORBIDDEN_HEADERS.contains(&name);
                let scheme_ok = scheme.is_none_or(|s| {
                    (1..=32).contains(&s.len())
                        && s.as_bytes()[0].is_ascii_alphabetic()
                        && s.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
                        && !s.eq_ignore_ascii_case("basic")
                });
                if !name_ok || !scheme_ok {
                    return Err(K::InvalidAuthSlot);
                }
                Ok(AuthSlot::Header {
                    name: name.to_owned(),
                    scheme: scheme.map(str::to_owned),
                })
            }
            (None, None, Some("user"), None) => Ok(AuthSlot::BasicUser),
            (None, None, Some("password"), None) => Ok(AuthSlot::BasicPassword),
            (None, None, None, Some(name)) => {
                if (1..=64).contains(&name.len())
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
                {
                    Ok(AuthSlot::Query {
                        name: name.to_owned(),
                    })
                } else {
                    Err(K::InvalidAuthSlot)
                }
            }
            _ => Err(K::InvalidAuthSlot),
        }
    }

    /// Whether two slots are the same slot: header names and schemes
    /// compare without ASCII case, as HTTP does.
    pub(crate) fn same(&self, other: &AuthSlot) -> bool {
        let eq = |a: &str, b: &str| a.eq_ignore_ascii_case(b);
        match (self, other) {
            (
                AuthSlot::Header { name, scheme },
                AuthSlot::Header {
                    name: n2,
                    scheme: s2,
                },
            ) => {
                eq(name, n2)
                    && match (scheme, s2) {
                        (Some(a), Some(b)) => eq(a, b),
                        (None, None) => true,
                        _ => false,
                    }
            }
            (AuthSlot::Query { name }, AuthSlot::Query { name: n2 }) => name == n2,
            _ => self == other,
        }
    }

    /// The slot a request's `auth` names among `slots`: `bearer`
    /// (`Authorization: Bearer`), `header:<name>` (the one header slot of
    /// that name), `basic:user`, `basic:password` or `query:<name>`.
    pub(crate) fn resolve(label: &str, slots: &[AuthSlot]) -> Result<AuthSlot, K> {
        let wanted: Vec<&AuthSlot> = match label.split_once(':') {
            None if label == "bearer" => slots
                .iter()
                .filter(|s| {
                    matches!(s, AuthSlot::Header { name, scheme: Some(sc) }
                        if name == "authorization" && sc.eq_ignore_ascii_case("bearer"))
                })
                .collect(),
            Some(("header", n)) => slots
                .iter()
                .filter(|s| matches!(s, AuthSlot::Header { name, .. } if name == n))
                .collect(),
            Some(("basic", "user")) => slots
                .iter()
                .filter(|s| **s == AuthSlot::BasicUser)
                .collect(),
            Some(("basic", "password")) => slots
                .iter()
                .filter(|s| **s == AuthSlot::BasicPassword)
                .collect(),
            Some(("query", n)) => slots
                .iter()
                .filter(|s| matches!(s, AuthSlot::Query { name } if name == n))
                .collect(),
            _ => return Err(K::InvalidAuthSlot),
        };
        match wanted.as_slice() {
            [one] => Ok((*one).clone()),
            [] => Err(K::AuthSlotNotDeclared),
            _ => Err(K::InvalidAuthSlot),
        }
    }
}

/// A denied path: `/`, then segments of letters, digits and `._~-`, where a
/// segment `*` stands for any one segment. It covers the paths it is a
/// prefix of, segment by segment.
pub(crate) fn valid_denied_path(s: &str) -> bool {
    let Some(rest) = s.strip_prefix('/') else {
        return false;
    };
    s.len() <= MAX_DENIED_PATH
        && rest.split('/').all(|seg| {
            seg == "*"
                || (!seg.is_empty()
                    && seg != "."
                    && seg != ".."
                    && seg.bytes().all(|b| {
                        b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-')
                    }))
        })
}

/// A byte a request path segment may hold and still count as normalized:
/// the path characters of RFC 3986 (unreserved, sub-delimiters, `:` and
/// `@`), except `%`, which starts an escape, and `;`, which starts path
/// parameters that some servers strip from a segment.
fn plain_path_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"-._~!$&'()*+,=:@".contains(&b)
}

/// Whether the request path `path` (a query and fragment are ignored)
/// falls under the denied path `pattern`. Segments compare without ASCII
/// case. It fails closed: a path that is not normalized counts as denied,
/// so a server that normalizes it cannot reach a denied endpoint. That is
/// a path with an empty segment (other than a trailing `/`), a segment
/// that ends in `.` (so `.` and `..` as well), or any byte
/// [`plain_path_byte`] refuses: a `%` escape, `;` path parameters, a
/// backslash, whitespace, control or non-ASCII bytes. The proxy (M6)
/// normalizes paths before asking.
pub(crate) fn path_under(pattern: &str, path: &str) -> bool {
    let path = path.split(['?', '#']).next().unwrap_or("");
    let Some(path) = path.strip_prefix('/') else {
        return true;
    };
    let segs: Vec<&str> = path.split('/').collect();
    let last = segs.len() - 1;
    let odd = segs.iter().enumerate().any(|(i, s)| {
        (s.is_empty() && i != last) || s.ends_with('.') || !s.bytes().all(plain_path_byte)
    });
    if odd {
        return true;
    }
    let mut segs = segs.into_iter();
    pattern[1..].split('/').all(|p| {
        segs.next()
            .is_some_and(|s| !s.is_empty() && (p == "*" || s.eq_ignore_ascii_case(p)))
    })
}

/// One step of a [`JsonPath`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PathSegment {
    /// `.name`
    Key(String),
    /// `[index]`
    Index(u32),
}

/// Where an adapter reads a number or string in a JSON response: `$`, then
/// up to 16 `.name` or `[index]` steps, such as
/// `$.balance_infos[0].total_balance`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JsonPath {
    text: String,
    segments: Vec<PathSegment>,
}

impl JsonPath {
    pub(crate) fn parse(s: &str) -> Result<Self, K> {
        let b = s.as_bytes();
        if s.len() > MAX_JSON_PATH || b.first() != Some(&b'$') {
            return Err(K::InvalidJsonPath);
        }
        let mut segments = Vec::new();
        let mut i = 1;
        while i < b.len() {
            let start = i + 1;
            let seg = match b[i] {
                b'.' => {
                    let end = b[start..]
                        .iter()
                        .position(|c| !(c.is_ascii_alphanumeric() || *c == b'_'))
                        .map_or(b.len(), |p| start + p);
                    let name = &s[start..end];
                    if name.is_empty() || name.len() > 64 || name.as_bytes()[0].is_ascii_digit() {
                        return Err(K::InvalidJsonPath);
                    }
                    i = end;
                    PathSegment::Key(name.to_owned())
                }
                b'[' => {
                    let close = b[start..]
                        .iter()
                        .position(|c| *c == b']')
                        .map(|p| start + p)
                        .ok_or(K::InvalidJsonPath)?;
                    let digits = &s[start..close];
                    let canonical = digits == "0" || !digits.starts_with('0');
                    if !(1..=4).contains(&digits.len())
                        || !canonical
                        || !digits.bytes().all(|c| c.is_ascii_digit())
                    {
                        return Err(K::InvalidJsonPath);
                    }
                    i = close + 1;
                    PathSegment::Index(digits.parse().map_err(|_| K::InvalidJsonPath)?)
                }
                _ => return Err(K::InvalidJsonPath),
            };
            segments.push(seg);
        }
        if segments.is_empty() || segments.len() > MAX_JSON_SEGMENTS {
            return Err(K::InvalidJsonPath);
        }
        Ok(JsonPath {
            text: s.to_owned(),
            segments,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn segments(&self) -> &[PathSegment] {
        &self.segments
    }
}

impl core::fmt::Display for JsonPath {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn suffixes() -> Suffixes {
        Suffixes::parse("vercel.app\n# comment\n\nco.uk  # trailing\n").unwrap()
    }

    #[test]
    fn hosts() {
        for ok in [
            "api.openai.com",
            "a.b",
            "xn--bcher-kva.example",
            "a-1.example.com",
        ] {
            assert!(valid_host(ok), "{ok}");
        }
        for bad in [
            "",
            "com",
            "API.openai.com",
            "api.openai.com.",
            ".api.openai.com",
            "api..openai.com",
            "127.0.0.1",
            "[::1]",
            "api.openai.com:443",
            "user@api.openai.com",
            "-a.example.com",
            "a-.example.com",
            "a_b.example.com",
            "b\u{fc}cher.example",
            "example.123",
        ] {
            assert!(!valid_host(bad), "{bad}");
        }
        assert!(!valid_host(&format!("{}.com", "a".repeat(64))));
        assert!(valid_host(&format!("{}.com", "a".repeat(63))));
    }

    #[test]
    fn host_patterns() {
        let s = suffixes();
        let p = |x: &str| HostPattern::parse(x, &s);
        assert_eq!(p("*.com"), Err(K::WildcardTooBroad));
        assert_eq!(p("*"), Err(K::InvalidHost));
        assert_eq!(p("*.*.example.com"), Err(K::InvalidHost));
        assert_eq!(p("api.*.example.com"), Err(K::InvalidHost));
        assert_eq!(p("*example.com"), Err(K::InvalidHost));
        assert_eq!(p("*.vercel.app"), Err(K::WildcardUnderMultiTenantSuffix));
        assert_eq!(
            p("*.acme.vercel.app"),
            Err(K::WildcardUnderMultiTenantSuffix)
        );
        assert_eq!(p("*.example.co.uk"), Err(K::WildcardUnderMultiTenantSuffix));
        // Suffix, not substring: these domains are not under vercel.app.
        assert!(p("*.vercel.app.example.com").is_ok());
        assert!(p("*.notvercel.app").is_ok());
        // Exact tenant hosts are not wildcards.
        assert!(p("acme.vercel.app").is_ok());
        // A wildcard over a whole public suffix of two labels.
        for broad in ["*.com.sg", "*.co.kr", "*.com.tw", "*.org.il", "*.ac.jp"] {
            assert_eq!(p(broad), Err(K::WildcardTooBroad), "{broad}");
        }
        assert!(p("*.coms.sg").is_ok() && p("*.com.sg.example.com").is_ok());

        // A wildcard over a suffix matches every tenant host under it, so a
        // wildcard at or above a listed suffix is refused as well as one
        // under it; a sibling is not.
        let deep = Suffixes::parse("tenants.example.net\napp.region.example.org\n").unwrap();
        let q = |x: &str| HostPattern::parse(x, &deep);
        for over in ["*.example.net", "*.example.org", "*.region.example.org"] {
            assert_eq!(q(over), Err(K::WildcardOverMultiTenantSuffix), "{over}");
        }
        for under in [
            "*.tenants.example.net",
            "*.acme.tenants.example.net",
            "*.app.region.example.org",
        ] {
            assert_eq!(q(under), Err(K::WildcardUnderMultiTenantSuffix), "{under}");
        }
        for ok in [
            "*.other.example.net",
            "*.other.region.example.org",
            "*.tenants.example.net.example.com",
            "*.xtenants.example.net",
            "evil.tenants.example.net",
            "example.net",
        ] {
            assert!(q(ok).is_ok(), "{ok}");
        }

        let w = p("*.example.com").unwrap();
        assert!(w.is_wildcard());
        assert_eq!(w.domain(), "example.com");
        assert_eq!(w.to_string(), "*.example.com");
        assert!(w.matches("api.example.com"));
        assert!(w.matches("a.b.EXAMPLE.com"));
        assert!(!w.matches("example.com"));
        assert!(!w.matches(".example.com"));
        assert!(!w.matches("evilexample.com"));
        assert!(!w.matches("api.example.com.evil.test"));
        assert!(!w.matches("api.example.com."));
        let e = p("api.example.com").unwrap();
        assert!(e.matches("api.example.com") && e.matches("API.example.com"));
        assert!(!e.matches("x.api.example.com") && !e.matches("example.com"));
        // Multi-byte text does not panic the suffix comparison.
        assert!(!w.matches("\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}"));
    }

    #[test]
    fn suffix_list() {
        assert_eq!(suffixes().as_slice(), ["vercel.app", "co.uk"]);
        assert_eq!(
            Suffixes::parse("a.b\n*.vercel.app\n").unwrap_err(),
            (K::InvalidSuffix, 2)
        );
        assert_eq!(
            Suffixes::parse("Vercel.app").unwrap_err(),
            (K::InvalidSuffix, 1)
        );
        assert_eq!(
            Suffixes::parse("\n\napp\n").unwrap_err(),
            (K::InvalidSuffix, 3)
        );
    }

    #[test]
    fn urls() {
        let u = HttpsUrl::parse("https://api.example.com/v1/x?y=1", false).unwrap();
        assert_eq!(u.host(), "api.example.com");
        assert_eq!(
            HttpsUrl::parse("https://api.example.com", false)
                .unwrap()
                .host(),
            "api.example.com"
        );
        assert_eq!(
            HttpsUrl::parse("https://a.example?q", false)
                .unwrap()
                .host(),
            "a.example"
        );
        let l = HttpsUrl::parse("https://console.example.com/iam#/keys", true).unwrap();
        assert_eq!(l.host(), "console.example.com");
        for (s, path) in [
            ("https://api.example.com/v1/x?y=1", "/v1/x"),
            ("https://api.example.com/v1/x/", "/v1/x/"),
            ("https://api.example.com", "/"),
            ("https://api.example.com?y=/v1/keys", "/"),
            ("https://api.example.com/?y=1", "/"),
        ] {
            assert_eq!(HttpsUrl::parse(s, false).unwrap().path(), path, "{s}");
        }
        assert_eq!(l.path(), "/iam");
        for (s, k) in [
            ("http://api.example.com/", K::NotHttps),
            ("HTTPS://api.example.com/", K::NotHttps),
            ("//api.example.com/", K::NotHttps),
            (" https://api.example.com/", K::NotHttps),
            ("https://api.example.com/#x", K::InvalidUrl),
            ("https://evil.test#@api.example.com", K::InvalidUrl),
            ("https://api.example.com@evil.test/", K::InvalidUrl),
            ("https://api.example.com:443/", K::InvalidUrl),
            ("https://API.example.com/", K::InvalidUrl),
            ("https://api.example.com./", K::InvalidUrl),
            ("https://127.0.0.1/", K::InvalidUrl),
            ("https://[::1]/", K::InvalidUrl),
            ("https://api.example.com\\@evil.test/", K::InvalidUrl),
            ("https://api.example.com/a b", K::InvalidUrl),
            ("https:///x", K::InvalidUrl),
            ("https://", K::InvalidUrl),
        ] {
            assert_eq!(HttpsUrl::parse(s, false), Err(k), "{s}");
        }
    }

    #[test]
    fn patterns() {
        let c = |s: &str, a| compile_pattern(s, a).map(|_| ());
        assert_eq!(c("^sk-[a-f0-9]{32}$", Anchor::Whole), Ok(()));
        assert_eq!(c("^sk-(?:a|b)[a-f0-9]{32}$", Anchor::Whole), Ok(()));
        assert_eq!(c("^sk-", Anchor::Start), Ok(()));
        assert_eq!(
            c("^sk-(a)[a-f0-9]{32}$", Anchor::Whole),
            Err(K::PatternHasCaptures)
        );
        assert_eq!(
            c("^sk-(?P<n>a)[a-f0-9]{32}$", Anchor::Whole),
            Err(K::PatternHasCaptures)
        );
        assert_eq!(c("^(sk)-", Anchor::Start), Err(K::PatternHasCaptures));
        assert_eq!(
            c("sk-[a-f0-9]{32}$", Anchor::Whole),
            Err(K::PatternNotAnchored)
        );
        assert_eq!(
            c("^sk-[a-f0-9]{32}", Anchor::Whole),
            Err(K::PatternNotAnchored)
        );
        assert_eq!(
            c("^a{20}|b{20}$", Anchor::Whole),
            Err(K::PatternNotAnchored)
        );
        assert_eq!(
            c("(?m)^sk-[a-f0-9]{32}$", Anchor::Whole),
            Err(K::PatternNotAnchored)
        );
        assert_eq!(c("sk-", Anchor::Start), Err(K::PatternNotAnchored));
        assert_eq!(c("^.{15}$", Anchor::Whole), Err(K::PatternTooShort));
        assert_eq!(c("^abc.{13}$", Anchor::Whole), Ok(()));
        assert_eq!(c("^sk-[a-z]*$", Anchor::Whole), Err(K::PatternTooShort));
        assert_eq!(c("^[a&&b]{20}$", Anchor::Whole), Err(K::PatternTooShort));
        assert_eq!(c("^sk-[a-f0-9$", Anchor::Whole), Err(K::InvalidPattern));
        assert_eq!(c("", Anchor::Start), Err(K::InvalidPattern));
        assert_eq!(c("^sk-\t", Anchor::Start), Err(K::InvalidPattern));
        let long = format!("^{}$", "a".repeat(MAX_PATTERN));
        assert_eq!(c(&long, Anchor::Whole), Err(K::InvalidPattern));
        // Unicode classes are not compiled in; patterns are ASCII.
        assert_eq!(c("^\\p{L}{20}$", Anchor::Whole), Err(K::InvalidPattern));

        // A key pattern starts with a literal of at least 3 bytes, so it
        // cannot claim values of every shape.
        for broad in [
            "^.{16}$",
            "^(?s:.){16,}$",
            "^[A-Za-z0-9]{24}$",
            "^[a-f0-9]{32}$",
            // Ten digits expand to 100 two-digit prefixes, then give up.
            "^[0-9]{16,}$",
            "^ab[a-z]{16}$",
            "^(?:sk-|[a-z]{3})[a-z]{16}$",
            "^(?:|sk-)[a-z]{16}$",
            "^(?:sk-)?[a-z]{16}$",
            "^[a-z]?sk-[a-z]{16}$",
        ] {
            assert_eq!(
                c(broad, Anchor::Whole),
                Err(K::PatternNoLiteralPrefix),
                "{broad}"
            );
        }
        for ok in [
            "^sk-[a-f0-9]{32}$",
            "^sk-ant-[a-z]{2,10}[0-9]{2}-[A-Za-z0-9_-]{20,}$",
            "^(?:AKIA|ASIA)[A-Z2-7]{16}$",
            "^[rsp]k_(?:live|test)_[0-9A-Za-z]{10,247}$",
            "^gh[pousr]_[A-Za-z0-9]{36,251}$",
            "(?i)^sk-[a-z]{16}$",
            "^(?:sk-|pk-)[a-z]{16}$",
        ] {
            assert_eq!(c(ok, Anchor::Whole), Ok(()), "{ok}");
        }
        // Live and test patterns need no prefix: they are tried only on a
        // value a key pattern matched.
        assert_eq!(c("^[a-z]", Anchor::Start), Ok(()));
    }

    #[test]
    fn auth_slots() {
        let h = |n, s| AuthSlot::from_parts(Some(n), s, None, None);
        assert!(h("authorization", Some("Bearer")).is_ok());
        assert!(h("x-api-key", None).is_ok());
        for bad in ["cookie", "host", "content-length", "X-Api-Key", "x api", ""] {
            assert_eq!(h(bad, None), Err(K::InvalidAuthSlot), "{bad}");
        }
        assert_eq!(h("authorization", Some("Basic")), Err(K::InvalidAuthSlot));
        assert_eq!(
            h("authorization", Some("Bearer x")),
            Err(K::InvalidAuthSlot)
        );
        assert_eq!(
            AuthSlot::from_parts(None, None, Some("user"), None),
            Ok(AuthSlot::BasicUser)
        );
        assert_eq!(
            AuthSlot::from_parts(None, None, Some("both"), None),
            Err(K::InvalidAuthSlot)
        );
        assert_eq!(
            AuthSlot::from_parts(Some("x-key"), None, None, Some("key")),
            Err(K::InvalidAuthSlot)
        );
        assert_eq!(
            AuthSlot::from_parts(None, Some("Bearer"), None, None),
            Err(K::InvalidAuthSlot)
        );
        assert_eq!(
            AuthSlot::from_parts(None, None, None, None),
            Err(K::InvalidAuthSlot)
        );

        let slots = [
            h("authorization", Some("Bearer")).unwrap(),
            h("x-api-key", None).unwrap(),
            AuthSlot::BasicUser,
            AuthSlot::from_parts(None, None, None, Some("key")).unwrap(),
        ];
        assert_eq!(AuthSlot::resolve("bearer", &slots), Ok(slots[0].clone()));
        assert_eq!(
            AuthSlot::resolve("header:x-api-key", &slots),
            Ok(slots[1].clone())
        );
        assert_eq!(
            AuthSlot::resolve("basic:user", &slots),
            Ok(AuthSlot::BasicUser)
        );
        assert_eq!(AuthSlot::resolve("query:key", &slots), Ok(slots[3].clone()));
        assert_eq!(
            AuthSlot::resolve("basic:password", &slots),
            Err(K::AuthSlotNotDeclared)
        );
        assert_eq!(
            AuthSlot::resolve("query:token", &slots),
            Err(K::AuthSlotNotDeclared)
        );
        assert_eq!(
            AuthSlot::resolve("cookie:x", &slots),
            Err(K::InvalidAuthSlot)
        );
        assert_eq!(AuthSlot::resolve("Bearer", &slots), Err(K::InvalidAuthSlot));
        let two = [
            h("authorization", Some("Bearer")).unwrap(),
            h("authorization", Some("token")).unwrap(),
        ];
        assert_eq!(
            AuthSlot::resolve("header:authorization", &two),
            Err(K::InvalidAuthSlot)
        );
        let spelled = AuthSlot::Header {
            name: "Authorization".into(),
            scheme: Some("bearer".into()),
        };
        assert!(two[0].same(&spelled));
        assert!(!two[0].same(&two[1]));
        assert!(!two[0].same(&AuthSlot::BasicUser));
        assert!(AuthSlot::BasicUser.same(&AuthSlot::BasicUser));
    }

    #[test]
    fn denied_paths() {
        for ok in ["/v1/organization", "/repos/*/*/keys", "/a.b_c~d-e", "/*"] {
            assert!(valid_denied_path(ok), "{ok}");
        }
        for bad in [
            "", "/", "v1/x", "/v1/", "/v1//x", "/v1/./x", "/v1/../x", "/v1/x?y", "/v1/a*",
            "/v1/%41",
        ] {
            assert!(!valid_denied_path(bad), "{bad}");
        }
        let p = "/v1/organization";
        assert!(path_under(p, "/v1/organization"));
        assert!(path_under(p, "/v1/organization/"));
        assert!(path_under(p, "/v1/organization/admin_api_keys?limit=1"));
        assert!(path_under(p, "/V1/Organization/x"));
        assert!(!path_under(p, "/v1/organizations"));
        assert!(!path_under(p, "/v1/chat/completions"));
        assert!(!path_under(p, "/v1"));
        assert!(!path_under(p, "/v1/chat?next=/v1/organization"));
        // Not normalized: denied wherever the oddity is.
        for odd in [
            "/v1/%6frganization/x",
            "/v1/chat/../organization",
            "/v1/./organization",
            "/v1//organization",
            "//v1/organization",
            "/v1/chat\\..\\organization",
            "v1/organization",
            "",
            // Path parameters, which some servers strip from a segment.
            "/v1/organization;x=1/admin_api_keys",
            "/v1/organization;/admin_api_keys",
            "/v1/chat;/../organization",
            // A trailing dot or space, which some servers strip.
            "/v1/organization./admin_api_keys",
            "/v1/organization.",
            "/v1/chat.../x",
            "/v1/organization /admin_api_keys",
            "/v1/organization\t/x",
            "/v1/organization\u{0}/x",
            // Bytes outside the path characters of RFC 3986.
            "/v1/organization\u{e9}/x",
            "/v1/organization\"/x",
            "/v1/organization|/x",
            "/v1/organization{x}",
            "/v1/[organization]",
        ] {
            assert!(path_under(p, odd), "{odd:?}");
        }
        // Path characters servers do not strip stay plain, so an API that
        // uses them is not denied wholesale.
        for plain in [
            "/v1/models/gpt-4o:generate",
            "/v1/files/file-1@2",
            "/v1/a!$&'()*+,=b",
            "/v1/chat.completions",
            "/v1/chat/completions/",
            "/v1/chat?x=;.%20",
        ] {
            assert!(!path_under(p, plain), "{plain}");
        }
        let g = "/repos/*/*/keys";
        assert!(path_under(g, "/repos/o/r/keys/1"));
        assert!(!path_under(g, "/repos/o/r/contents/keys"));
        assert!(!path_under(g, "/repos/o/keys"));
    }

    #[test]
    fn json_paths() {
        let p = JsonPath::parse("$.balance_infos[0].total_balance").unwrap();
        assert_eq!(
            p.segments(),
            [
                PathSegment::Key("balance_infos".into()),
                PathSegment::Index(0),
                PathSegment::Key("total_balance".into())
            ]
        );
        assert!(JsonPath::parse("$[10].a_1").is_ok());
        for bad in [
            "",
            "$",
            "balance",
            "$.",
            "$..a",
            "$.a[",
            "$.a[]",
            "$.a[01]",
            "$.a[x]",
            "$.a[12345]",
            "$.1a",
            "$.a.b c",
            "$['a']",
            "$.a[-1]",
        ] {
            assert_eq!(JsonPath::parse(bad), Err(K::InvalidJsonPath), "{bad}");
        }
        let deep = format!("${}", ".a".repeat(MAX_JSON_SEGMENTS + 1));
        assert_eq!(JsonPath::parse(&deep), Err(K::InvalidJsonPath));
    }
}
