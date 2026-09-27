//! Provider files and the registry built from them (SPEC §8; the format is
//! in docs/PROVIDERS.md).
//!
//! The registry ships inside the release: [`load_embedded`] parses the
//! files compiled into `embedded.rs`. Nothing here reads a registry from
//! disk or the network. Local registry overrides are M2+ and need an
//! approval proof (SPEC §8 "Registry safety").
//!
//! Every file is checked with the rules in `safety.rs`, and one bad file
//! fails the whole registry: a provider is never silently left out.

use std::ops::Range;

use envcloak_core::vault::{Classification, ItemDetails, Links};
use regex::bytes::{Regex, RegexSet};
use toml_edit::{Document, Item, TableLike};

use crate::detect::Detection;
use crate::embedded;
use crate::error::{RegistryError, RegistryErrorKind as K};
use crate::safety::{self, Anchor, AuthSlot, HostPattern, HttpsUrl, JsonPath, Suffixes};

/// The multi-tenant suffix list's file name in `providers/`.
pub const SUFFIX_FILE: &str = "multi-tenant-suffixes.txt";
/// The largest registry file accepted, in bytes.
pub const MAX_FILE: usize = 64 * 1024;
/// The longest list in a provider file.
const MAX_LIST: usize = 64;

/// A provider's registry id, such as `openai`: 1 to 32 lowercase letters,
/// digits and `-`, starting with a letter or digit. Its file is
/// `providers/<id>.toml`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProviderId(String);

impl ProviderId {
    fn parse(s: &str) -> Option<Self> {
        let b = s.as_bytes();
        let ok = (1..=32).contains(&b.len())
            && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
            && b.iter()
                .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-');
        ok.then(|| ProviderId(s.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for ProviderId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq<str> for ProviderId {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for ProviderId {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// A pattern as written in the registry, compiled for linear-time matching
/// on bytes, with no captures.
#[derive(Debug, Clone)]
pub struct KeyPattern {
    source: String,
    regex: Regex,
}

impl KeyPattern {
    /// The pattern as written.
    pub fn as_str(&self) -> &str {
        &self.source
    }

    pub(crate) fn is_match(&self, value: &[u8]) -> bool {
        self.regex.is_match(value)
    }
}

/// The request method an adapter may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    Get,
}

/// An adapter's HTTP request. M4 sends it, and never follows a redirect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: Method,
    /// Its host is matched by one of the provider's allowed hosts.
    pub url: HttpsUrl,
    /// One of the provider's declared auth slots.
    pub auth: AuthSlot,
}

/// A balance adapter (SPEC §8): one request, and where its JSON response
/// holds the balance and, optionally, the currency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adapter {
    pub request: Request,
    pub value: JsonPath,
    pub currency: Option<JsonPath>,
}

/// One provider, as loaded from `providers/<id>.toml`.
#[derive(Debug, Clone)]
pub struct Provider {
    pub id: ProviderId,
    /// Display name.
    pub name: String,
    /// Whole-value patterns: a value is this provider's when one matches.
    pub key_patterns: Vec<KeyPattern>,
    /// Start-anchored patterns, tried on a value that matched a key
    /// pattern: a match makes it live.
    pub live_patterns: Vec<KeyPattern>,
    /// As `live_patterns`, for test keys.
    pub test_patterns: Vec<KeyPattern>,
    /// Environment variables the key usually goes in, uppercase.
    pub env_hints: Vec<String>,
    /// The hosts the key may be sent to (SPEC §6.2, §8).
    pub allowed_hosts: Vec<HostPattern>,
    /// Where requests carry the key (SPEC §6.2 step 3).
    pub auth_slots: Vec<AuthSlot>,
    /// Key-management, admin and credential-minting paths (SPEC §6.2 step
    /// 4), as `/`-separated segments where `*` is any one segment.
    pub denied_paths: Vec<String>,
    pub links: Links,
    pub balance: Option<Adapter>,
}

impl Provider {
    /// Whether the variable `env_name` names one of this provider's env
    /// hints: equal to one, or containing one between `_` or the ends
    /// (`VITE_OPENAI_API_KEY`, `OPENAI_API_KEY_2`), ignoring ASCII case.
    pub fn hinted_by(&self, env_name: &str) -> bool {
        self.env_hints.iter().any(|h| names_hint(env_name, h))
    }

    /// Whether an allowed host matches `host`.
    pub fn host_allowed(&self, host: &str) -> bool {
        self.allowed_hosts.iter().any(|h| h.matches(host))
    }

    /// Whether the request path `path` is under a denied path. A path
    /// that is not normalized (empty, `.` or `..` segments, `%` escapes,
    /// backslashes) counts as denied.
    pub fn path_denied(&self, path: &str) -> bool {
        self.denied_paths
            .iter()
            .any(|p| safety::path_under(p, path))
    }

    /// Test, live or unknown, for a value that matched a key pattern. Both
    /// or neither kinds of pattern matching gives unknown.
    pub(crate) fn classify(&self, value: &[u8]) -> Classification {
        let live = self.live_patterns.iter().any(|p| p.is_match(value));
        let test = self.test_patterns.iter().any(|p| p.is_match(value));
        match (live, test) {
            (true, false) => Classification::Live,
            (false, true) => Classification::Test,
            _ => Classification::Unknown,
        }
    }
}

/// `hint` appears in `name`, ignoring ASCII case, with `_` or an end of
/// `name` on each side.
fn names_hint(name: &str, hint: &str) -> bool {
    let (n, h) = (name.as_bytes(), hint.as_bytes());
    if h.is_empty() || h.len() > n.len() {
        return false;
    }
    (0..=n.len() - h.len()).any(|i| {
        let end = i + h.len();
        n[i..end].eq_ignore_ascii_case(h)
            && (i == 0 || n[i - 1] == b'_')
            && (end == n.len() || n[end] == b'_')
    })
}

/// The loaded provider registry.
#[derive(Debug)]
pub struct Registry {
    /// Sorted by id.
    providers: Vec<Provider>,
    /// Every provider's key patterns, in provider order.
    keys: RegexSet,
    /// For each pattern in `keys`, its provider's index.
    key_owner: Vec<usize>,
    suffixes: Vec<String>,
}

impl Registry {
    /// Every provider, sorted by id.
    pub fn providers(&self) -> &[Provider] {
        &self.providers
    }

    pub fn get(&self, id: &str) -> Option<&Provider> {
        self.providers
            .binary_search_by(|p| p.id.as_str().cmp(id))
            .ok()
            .map(|i| &self.providers[i])
    }

    /// The multi-tenant suffixes the loader checked wildcards against.
    pub fn multi_tenant_suffixes(&self) -> &[String] {
        &self.suffixes
    }

    /// The provider whose env hints name `env_name`, when exactly one
    /// does. A suggestion for a value no key pattern matched, such as an
    /// AWS secret access key; it is not a detection, and
    /// [`Registry::prefill`] does not use it.
    pub fn by_env_hint(&self, env_name: &str) -> Option<&Provider> {
        let mut hinted = self.providers.iter().filter(|p| p.hinted_by(env_name));
        let first = hinted.next()?;
        hinted.next().is_none().then_some(first)
    }

    /// Pre-fills a new item's metadata from a detection (SPEC §6.3, §6.4):
    /// the provider, its links, a snapshot of its allowed hosts, the
    /// classification, and a title and env hint when those are empty. Only
    /// empty fields are filled. When `details` already names a provider
    /// and the detection does not agree, nothing changes.
    pub fn prefill(&self, d: &Detection, details: &mut ItemDetails) {
        if let Some(set) = details.provider.as_deref() {
            if d.provider.as_ref().is_none_or(|id| id.as_str() != set) {
                return;
            }
        }
        if details.classification == Classification::Unknown {
            details.classification = d.classification;
        }
        let Some(p) = d.provider.as_ref().and_then(|id| self.get(id.as_str())) else {
            return;
        };
        details.provider.get_or_insert_with(|| p.id.to_string());
        if details.title.is_empty() {
            details.title.clone_from(&p.name);
        }
        if details.env_hint.is_none() {
            details.env_hint = p.env_hints.first().cloned();
        }
        if details.allowed_hosts.is_empty() {
            details.allowed_hosts = p.allowed_hosts.iter().map(|h| h.to_string()).collect();
        }
        let l = &mut details.links;
        for (mine, theirs) in [
            (&mut l.docs, &p.links.docs),
            (&mut l.billing, &p.links.billing),
            (&mut l.keys_page, &p.links.keys_page),
            (&mut l.dashboard, &p.links.dashboard),
        ] {
            if mine.is_none() {
                mine.clone_from(theirs);
            }
        }
    }

    /// The indices of the providers with a key pattern that matches
    /// `value` whole, ascending.
    pub(crate) fn key_matches(&self, value: &[u8]) -> Vec<usize> {
        let mut out: Vec<usize> = self
            .keys
            .matches(value)
            .iter()
            .map(|i| self.key_owner[i])
            .collect();
        out.dedup();
        out
    }
}

/// The registry files compiled into this build, as `(file name, contents)`
/// sorted by name: every `providers/*.toml` and [`SUFFIX_FILE`].
pub fn embedded_files() -> &'static [(&'static str, &'static str)] {
    embedded::FILES
}

/// Loads the registry compiled into this build.
///
/// # Errors
/// When a file breaks a rule of docs/PROVIDERS.md. The crate's tests load
/// it, so a shipped build does not fail here.
pub fn load_embedded() -> Result<Registry, RegistryError> {
    let files: Vec<(&str, &[u8])> = embedded::FILES
        .iter()
        .map(|(name, text)| (*name, text.as_bytes()))
        .collect();
    load(&files)
}

/// Loads a registry from `(file name, contents)` pairs laid out like
/// `providers/`: [`SUFFIX_FILE`] and `<id>.toml` files. Test support only:
/// shipped builds load the embedded registry.
///
/// # Errors
/// When a file breaks a rule of docs/PROVIDERS.md.
#[cfg(feature = "testing")]
pub fn load_from(files: &[(&str, &[u8])]) -> Result<Registry, RegistryError> {
    load(files)
}

fn load(files: &[(&str, &[u8])]) -> Result<Registry, RegistryError> {
    let (_, bytes) = files
        .iter()
        .find(|(name, _)| *name == SUFFIX_FILE)
        .ok_or_else(|| RegistryError::new(K::MissingFile, SUFFIX_FILE, None))?;
    let text = utf8(SUFFIX_FILE, bytes)?;
    let suffixes = Suffixes::parse(text)
        .map_err(|(kind, line)| RegistryError::new(kind, SUFFIX_FILE, Some(line)))?;

    let mut providers = Vec::new();
    for (name, bytes) in files {
        if *name == SUFFIX_FILE {
            continue;
        }
        if !name.ends_with(".toml") {
            return Err(RegistryError::new(K::UnknownFile, name, None));
        }
        providers.push(parse_provider(name, bytes, &suffixes)?);
    }
    if providers.is_empty() {
        return Err(RegistryError::new(K::MissingFile, "*.toml", None));
    }
    providers.sort_by(|a, b| a.id.cmp(&b.id));
    if let Some(w) = providers.windows(2).find(|w| w[0].id == w[1].id) {
        let file = format!("{}.toml", w[1].id);
        return Err(RegistryError::new(K::DuplicateId, &file, None));
    }

    let mut key_owner = Vec::new();
    let mut sources = Vec::new();
    for (i, p) in providers.iter().enumerate() {
        for k in &p.key_patterns {
            sources.push(k.as_str());
            key_owner.push(i);
        }
    }
    let keys =
        safety::pattern_set(sources).map_err(|kind| RegistryError::new(kind, "*.toml", None))?;
    Ok(Registry {
        providers,
        keys,
        key_owner,
        suffixes: suffixes.as_slice().to_vec(),
    })
}

/// The line of byte `offset` in `bytes`, from 1.
fn line_at(bytes: &[u8], offset: usize) -> u32 {
    let end = offset.min(bytes.len());
    let n = bytes[..end].iter().filter(|&&b| b == b'\n').count();
    u32::try_from(n).unwrap_or(u32::MAX).saturating_add(1)
}

fn utf8<'a>(file: &str, bytes: &'a [u8]) -> Result<&'a str, RegistryError> {
    if bytes.len() > MAX_FILE {
        return Err(RegistryError::new(K::TooLarge, file, None));
    }
    std::str::from_utf8(bytes)
        .map_err(|e| RegistryError::new(K::NotUtf8, file, Some(line_at(bytes, e.valid_up_to()))))
}

type Span = Option<Range<usize>>;

/// A top-level entry: its value and its key's place.
type Entry<'d> = (&'d Item, Span);

/// The top-level keys of a provider file.
#[derive(Default)]
struct Root<'d> {
    id: Option<Entry<'d>>,
    name: Option<Entry<'d>>,
    key_patterns: Option<Entry<'d>>,
    live_patterns: Option<Entry<'d>>,
    test_patterns: Option<Entry<'d>>,
    env_hints: Option<Entry<'d>>,
    allowed_hosts: Option<Entry<'d>>,
    auth: Option<Entry<'d>>,
    denied_paths: Option<Entry<'d>>,
    links: Option<Entry<'d>>,
    balance: Option<Entry<'d>>,
}

/// Errors placed in one file.
struct Parser<'a> {
    file: &'a str,
    bytes: &'a [u8],
}

impl Parser<'_> {
    fn err(&self, kind: K, at: Span) -> RegistryError {
        RegistryError::new(kind, self.file, at.map(|r| line_at(self.bytes, r.start)))
    }

    /// A required top-level entry.
    fn need<'d>(&self, e: Option<Entry<'d>>) -> Result<Entry<'d>, RegistryError> {
        e.ok_or_else(|| self.err(K::MissingKey, None))
    }

    fn string<'d>(&self, (item, at): Entry<'d>) -> Result<(&'d str, Span), RegistryError> {
        match item.as_str() {
            Some(s) => Ok((s, at)),
            None => Err(self.err(K::WrongType, at)),
        }
    }

    fn table<'d>(&self, item: &'d Item, at: Span) -> Result<&'d dyn TableLike, RegistryError> {
        item.as_table_like()
            .ok_or_else(|| self.err(K::WrongType, at))
    }

    /// A list of strings, each with its place.
    fn strings<'d>(&self, (item, at): Entry<'d>) -> Result<Vec<(&'d str, Span)>, RegistryError> {
        let arr = item
            .as_array()
            .ok_or_else(|| self.err(K::WrongType, at.clone()))?;
        if arr.len() > MAX_LIST {
            return Err(self.err(K::TooManyEntries, at));
        }
        arr.iter()
            .map(|v| {
                let place = v.span().or_else(|| at.clone());
                v.as_str()
                    .map(|s| (s, place.clone()))
                    .ok_or_else(|| self.err(K::WrongType, place))
            })
            .collect()
    }

    fn patterns(
        &self,
        e: Option<Entry<'_>>,
        anchor: Anchor,
    ) -> Result<Vec<KeyPattern>, RegistryError> {
        let Some(e) = e else {
            return Ok(Vec::new());
        };
        self.strings(e)?
            .into_iter()
            .map(|(s, at)| {
                safety::compile_pattern(s, anchor)
                    .map(|regex| KeyPattern {
                        source: s.to_owned(),
                        regex,
                    })
                    .map_err(|kind| self.err(kind, at))
            })
            .collect()
    }

    fn auth_slots(&self, e: Option<Entry<'_>>) -> Result<Vec<AuthSlot>, RegistryError> {
        let Some((item, at)) = e else {
            return Ok(Vec::new());
        };
        let arr = item
            .as_array()
            .ok_or_else(|| self.err(K::WrongType, at.clone()))?;
        if arr.len() > MAX_LIST {
            return Err(self.err(K::TooManyEntries, at));
        }
        let mut out: Vec<AuthSlot> = Vec::new();
        for v in arr.iter() {
            let place = v.span().or_else(|| at.clone());
            let t = v
                .as_inline_table()
                .ok_or_else(|| self.err(K::WrongType, place.clone()))?;
            let (mut header, mut scheme, mut basic, mut query) = (None, None, None, None);
            for (key, x) in t.iter() {
                let kat = t.key(key).and_then(|k| k.span()).or_else(|| place.clone());
                let slot = match key {
                    "header" => &mut header,
                    "scheme" => &mut scheme,
                    "basic" => &mut basic,
                    "query" => &mut query,
                    _ => return Err(self.err(K::UnknownKey, kat)),
                };
                *slot = Some(x.as_str().ok_or_else(|| self.err(K::WrongType, kat))?);
            }
            let slot = AuthSlot::from_parts(header, scheme, basic, query)
                .map_err(|kind| self.err(kind, place.clone()))?;
            if out.iter().any(|o| o.same(&slot)) {
                return Err(self.err(K::DuplicateAuthSlot, place));
            }
            out.push(slot);
        }
        Ok(out)
    }

    fn links(&self, e: Option<Entry<'_>>) -> Result<Links, RegistryError> {
        let mut links = Links::default();
        let Some((item, at)) = e else {
            return Ok(links);
        };
        let t = self.table(item, at)?;
        for (key, v) in t.iter() {
            let kat = t.key(key).and_then(|k| k.span());
            let slot = match key {
                "docs" => &mut links.docs,
                "billing" => &mut links.billing,
                "keys" => &mut links.keys_page,
                "dashboard" => &mut links.dashboard,
                _ => return Err(self.err(K::UnknownKey, kat)),
            };
            let s = v
                .as_str()
                .ok_or_else(|| self.err(K::WrongType, kat.clone()))?;
            HttpsUrl::parse(s, true).map_err(|kind| self.err(kind, kat))?;
            *slot = Some(s.to_owned());
        }
        Ok(links)
    }

    fn json_path(&self, item: &Item, at: Span) -> Result<JsonPath, RegistryError> {
        let s = item
            .as_str()
            .ok_or_else(|| self.err(K::WrongType, at.clone()))?;
        JsonPath::parse(s).map_err(|kind| self.err(kind, at))
    }

    fn balance(
        &self,
        e: Option<Entry<'_>>,
        hosts: &[HostPattern],
        slots: &[AuthSlot],
    ) -> Result<Option<Adapter>, RegistryError> {
        let Some((item, at)) = e else {
            return Ok(None);
        };
        let t = self.table(item, at.clone())?;
        let (mut request, mut value, mut currency) = (None, None, None);
        for (key, v) in t.iter() {
            let kat = t.key(key).and_then(|k| k.span()).or_else(|| at.clone());
            match key {
                "request" => request = Some(self.request(v, kat, hosts, slots)?),
                "value" => value = Some(self.json_path(v, kat)?),
                "currency" => currency = Some(self.json_path(v, kat)?),
                _ => return Err(self.err(K::UnknownKey, kat)),
            }
        }
        let (Some(request), Some(value)) = (request, value) else {
            return Err(self.err(K::MissingKey, at));
        };
        Ok(Some(Adapter {
            request,
            value,
            currency,
        }))
    }

    /// `{ method = "GET", url = "https://...", auth = "<slot>" }`: the URL's
    /// host must be allowed, and the key must go in a declared slot.
    fn request(
        &self,
        item: &Item,
        at: Span,
        hosts: &[HostPattern],
        slots: &[AuthSlot],
    ) -> Result<Request, RegistryError> {
        let t = self.table(item, at.clone())?;
        let (mut method, mut url, mut auth) = (None, None, None);
        for (key, v) in t.iter() {
            let kat = t.key(key).and_then(|k| k.span()).or_else(|| at.clone());
            let slot = match key {
                "method" => &mut method,
                "url" => &mut url,
                "auth" => &mut auth,
                _ => return Err(self.err(K::UnknownKey, kat)),
            };
            let s = v
                .as_str()
                .ok_or_else(|| self.err(K::WrongType, kat.clone()))?;
            *slot = Some((s, kat));
        }
        let (Some((method, m_at)), Some((url, u_at)), Some((auth, a_at))) = (method, url, auth)
        else {
            return Err(self.err(K::MissingKey, at));
        };
        let method = match method {
            "GET" => Method::Get,
            _ => return Err(self.err(K::InvalidMethod, m_at)),
        };
        let url = HttpsUrl::parse(url, false).map_err(|kind| self.err(kind, u_at.clone()))?;
        if !hosts.iter().any(|h| h.matches(url.host())) {
            return Err(self.err(K::RequestHostNotAllowed, u_at));
        }
        let auth = AuthSlot::resolve(auth, slots).map_err(|kind| self.err(kind, a_at))?;
        Ok(Request { method, url, auth })
    }
}

/// 1 to 64 bytes, with no control characters and none of the invisible
/// ones a display could be spoofed with.
fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && !s.chars().any(|c| {
            c.is_control()
                || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2069}' | '\u{feff}')
        })
}

/// An uppercase environment variable name, at most 128 bytes.
fn valid_env_hint(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=128).contains(&b.len())
        && (b[0].is_ascii_uppercase() || b[0] == b'_')
        && b.iter()
            .all(|&c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
}

/// Parses and checks one provider file. See docs/PROVIDERS.md.
fn parse_provider(
    file: &str,
    bytes: &[u8],
    suffixes: &Suffixes,
) -> Result<Provider, RegistryError> {
    let text = utf8(file, bytes)?;
    let p = Parser { file, bytes };
    let doc = Document::parse(text).map_err(|e| {
        // Classified by its fixed description; the message itself quotes
        // the source and is dropped.
        let kind = if e.message().starts_with("duplicate key") {
            K::DuplicateKey
        } else {
            K::Syntax
        };
        p.err(kind, e.span())
    })?;
    let root = doc.as_table();
    let mut r = Root::default();
    for (key, item) in root.iter() {
        let at = root.key(key).and_then(|k| k.span());
        let slot = match key {
            "id" => &mut r.id,
            "name" => &mut r.name,
            "key_patterns" => &mut r.key_patterns,
            "live_patterns" => &mut r.live_patterns,
            "test_patterns" => &mut r.test_patterns,
            "env_hints" => &mut r.env_hints,
            "allowed_hosts" => &mut r.allowed_hosts,
            "auth" => &mut r.auth,
            "denied_paths" => &mut r.denied_paths,
            "links" => &mut r.links,
            "balance" => &mut r.balance,
            _ => return Err(p.err(K::UnknownKey, at)),
        };
        *slot = Some((item, at));
    }
    let (id, at) = p.string(p.need(r.id)?)?;
    let id_ok = ProviderId::parse(id).ok_or_else(|| p.err(K::InvalidId, at.clone()))?;
    if file.strip_suffix(".toml") != Some(id) {
        return Err(p.err(K::IdNotFileName, at));
    }
    let (name, at) = p.string(p.need(r.name)?)?;
    if !valid_name(name) {
        return Err(p.err(K::InvalidName, at));
    }

    let key_entry = p.need(r.key_patterns)?;
    let key_at = key_entry.1.clone();
    let key_patterns = p.patterns(Some(key_entry), Anchor::Whole)?;
    if key_patterns.is_empty() {
        return Err(p.err(K::NoKeyPatterns, key_at));
    }
    let live_patterns = p.patterns(r.live_patterns, Anchor::Start)?;
    let test_patterns = p.patterns(r.test_patterns, Anchor::Start)?;

    let mut env_hints = Vec::new();
    if let Some(e) = r.env_hints {
        for (s, at) in p.strings(e)? {
            if !valid_env_hint(s) {
                return Err(p.err(K::InvalidEnvHint, at));
            }
            env_hints.push(s.to_owned());
        }
    }

    let mut allowed_hosts: Vec<HostPattern> = Vec::new();
    for (s, at) in p.strings(p.need(r.allowed_hosts)?)? {
        let h = HostPattern::parse(s, suffixes).map_err(|kind| p.err(kind, at.clone()))?;
        if allowed_hosts.contains(&h) {
            return Err(p.err(K::DuplicateHost, at));
        }
        allowed_hosts.push(h);
    }

    let auth_slots = p.auth_slots(r.auth)?;

    let mut denied_paths = Vec::new();
    if let Some(e) = r.denied_paths {
        for (s, at) in p.strings(e)? {
            if !safety::valid_denied_path(s) {
                return Err(p.err(K::InvalidDeniedPath, at));
            }
            denied_paths.push(s.to_owned());
        }
    }

    let links = p.links(r.links)?;
    let balance = p.balance(r.balance, &allowed_hosts, &auth_slots)?;

    Ok(Provider {
        id: id_ok,
        name: name.to_owned(),
        key_patterns,
        live_patterns,
        test_patterns,
        env_hints,
        allowed_hosts,
        auth_slots,
        denied_paths,
        links,
        balance,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hints() {
        let h = "OPENAI_API_KEY";
        for yes in [
            "OPENAI_API_KEY",
            "openai_api_key",
            "VITE_OPENAI_API_KEY",
            "OPENAI_API_KEY_2",
            "MY_OPENAI_API_KEY_PROD",
        ] {
            assert!(names_hint(yes, h), "{yes}");
        }
        for no in [
            "OPENAI_API_KEYS",
            "XOPENAI_API_KEY",
            "OPENAI_API",
            "",
            "API_KEY",
        ] {
            assert!(!names_hint(no, h), "{no}");
        }
        assert!(!names_hint("A", ""));
    }

    #[test]
    fn ids_names_and_hints() {
        for ok in ["openai", "a", "0x", "open-ai", &"a".repeat(32)] {
            assert!(ProviderId::parse(ok).is_some(), "{ok}");
        }
        for bad in ["", "-a", "Open", "open_ai", "open ai", &"a".repeat(33)] {
            assert!(ProviderId::parse(bad).is_none(), "{bad}");
        }
        assert!(valid_name("OpenAI (work)"));
        for bad in ["", "a\u{202e}b", "a\nb", &"n".repeat(65)] {
            assert!(!valid_name(bad), "{bad:?}");
        }
        assert!(valid_env_hint("OPENAI_API_KEY") && valid_env_hint("_X1"));
        for bad in ["", "openai_api_key", "1X", "A-B", &"A".repeat(129)] {
            assert!(!valid_env_hint(bad), "{bad}");
        }
    }

    #[test]
    fn lines() {
        assert_eq!(
            [0, 1, 2, 4, 5, 99].map(|o| line_at(b"a\nb\n\nc", o)),
            [1, 1, 2, 3, 4, 4]
        );
    }
}
