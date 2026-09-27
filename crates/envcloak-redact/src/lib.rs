//! Streaming redaction of secret values.
//!
//! A [`Redactor`] is built from a set of labelled secrets. It replaces every
//! occurrence of each secret, and of the encodings listed below, with a
//! marker such as `[envcloak:openai/work]`.
//!
//! [`StreamRedactor`] applies a redactor to a byte stream that arrives in
//! arbitrary chunks (a child process's stdout, for example). It holds back
//! only as many bytes as could still turn out to be the start of a secret, so
//! a value split across two reads is still caught.
//!
//! # Coverage
//!
//! Coverage is bounded and explicit. For each secret the redactor matches:
//!
//! - the raw bytes;
//! - base64 and base64url of the whole value, padded and unpadded;
//! - the value embedded inside a longer base64 or base64url stream at each of
//!   the three byte alignments (only the 3-byte groups wholly inside the
//!   value; up to two boundary characters on each side can remain). Fragments
//!   shorter than 12 characters are skipped to avoid false positives, and the
//!   secret is then reported in [`BuildReport::partial`];
//! - lowercase and uppercase hex;
//! - percent-encoding as produced by common encoders (RFC 3986 strict,
//!   `encodeURIComponent`, Python `quote` and `quote_plus`, WHATWG form
//!   encoding, .NET `WebUtility`/`HttpUtility.UrlEncode`, Go `PathEscape`,
//!   lenient path/query encoders), each with uppercase and lowercase hex
//!   digits. Mixed-case hex within one value is not covered;
//! - JSON string escaping as produced by common serializers: `\"` or `\u0022`
//!   quotes, optional `\/`,
//!   short or `\u` control escapes, raw or `\u`-escaped non-ASCII (with
//!   surrogate pairs), optional HTML-safe, apostrophe, plus, backtick, DEL and
//!   line-separator escapes, with uppercase or lowercase hex. The default
//!   styles of serde_json, JavaScript, Python, Go, .NET, PHP and Ruby are
//!   always generated; other combinations are capped and a capped secret is
//!   listed in [`BuildReport::truncated`].
//!
//! Anything else (compression, encryption, custom transforms, partial
//! values) is not covered. Redaction is a guard against accidents, never a
//! boundary against a process that holds the secret; EnvCloak's proxy mode
//! exists for that threat.
//!
//! # Memory
//!
//! Buffers that may hold secret bytes are wiped before release and are never
//! grown in place (growth would free an unwiped copy). The Aho-Corasick
//! automata keep their own copies of the patterns, which are not wiped on
//! drop; the redactor should live only in a process that already holds the
//! secrets.

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};

use aho_corasick::{AhoCorasick, MatchKind};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use zeroize::{Zeroize, Zeroizing};

/// Secrets shorter than this are not redacted: short values such as `true`
/// or `8080` would destroy ordinary output. They are listed in
/// [`BuildReport::skipped`].
pub const DEFAULT_MIN_SECRET_LEN: usize = 8;

/// Embedded base64 fragments shorter than this are skipped to avoid false
/// positives.
const MIN_FRAGMENT_LEN: usize = 12;

/// Upper bound on JSON style combinations generated per secret.
const MAX_JSON_VARIANTS: usize = 512;

/// What a build could not fully cover. Labels only, never values.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BuildReport {
    /// Secrets shorter than the minimum length. They are not redacted at all.
    pub skipped: Vec<String>,
    /// Secrets whose embedded-base64 fragments were too short to match at
    /// every alignment. The raw value and whole-value encodings are still
    /// redacted.
    pub partial: Vec<String>,
    /// Secrets whose value mixes so many JSON escape classes that not every
    /// combination of serializer options was generated. The named styles of
    /// real serializers are always generated first, so they stay covered.
    pub truncated: Vec<String>,
}

/// Builds a [`Redactor`].
#[derive(Default)]
pub struct RedactorBuilder {
    secrets: Vec<(String, Zeroizing<Vec<u8>>)>,
    min_len: Option<usize>,
}

impl std::fmt::Debug for RedactorBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedactorBuilder")
            .field("secrets", &self.secrets.len())
            .finish_non_exhaustive()
    }
}

impl RedactorBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Minimum length for a secret to be redacted. Defaults to
    /// [`DEFAULT_MIN_SECRET_LEN`].
    pub fn min_secret_len(mut self, len: usize) -> Self {
        self.min_len = Some(len.max(1));
        self
    }

    /// Adds a secret. `label` names it in the replacement marker and must not
    /// itself be secret. Two labels may share one value; both are reported by
    /// [`Redactor::find_labels`].
    pub fn secret(mut self, label: impl Into<String>, value: impl AsRef<[u8]>) -> Self {
        let value = value.as_ref();
        let mut owned = Zeroizing::new(Vec::with_capacity(value.len()));
        owned.extend_from_slice(value);
        self.secrets.push((label.into(), owned));
        self
    }

    /// Builds the redactor and a report of anything it could not cover.
    pub fn build(self) -> (Redactor, BuildReport) {
        let min_len = self.min_len.unwrap_or(DEFAULT_MIN_SECRET_LEN);
        let mut patterns: Vec<Zeroizing<Vec<u8>>> = Vec::new();
        let mut owners: Vec<Vec<usize>> = Vec::new();
        let mut index: HashMap<u64, Vec<usize>> = HashMap::new();
        let mut labels: Vec<String> = Vec::new();
        let mut report = BuildReport::default();

        for (label, value) in self.secrets {
            if value.len() < min_len {
                report.skipped.push(label);
                continue;
            }
            let owner = labels.len();
            let (vars, partial, truncated) = variants(&value);
            if partial {
                report.partial.push(label.clone());
            }
            if truncated {
                report.truncated.push(label.clone());
            }
            labels.push(label);
            for v in vars {
                let slot = index.entry(hash_bytes(&v)).or_default();
                match slot
                    .iter()
                    .find(|&&i| patterns[i].as_slice() == v.as_slice())
                {
                    Some(&i) => {
                        if !owners[i].contains(&owner) {
                            owners[i].push(owner);
                        }
                    }
                    None => {
                        slot.push(patterns.len());
                        patterns.push(v);
                        owners.push(vec![owner]);
                    }
                }
            }
        }

        let max_len = patterns.iter().map(|p| p.len()).max().unwrap_or(0);
        let build = |kind| {
            AhoCorasick::builder()
                .match_kind(kind)
                .build(patterns.iter().map(|p| p.as_slice()))
                .expect("aho-corasick build cannot fail for literal patterns")
        };
        let (automaton, scanner) = if patterns.is_empty() {
            (None, None)
        } else {
            (
                Some(build(MatchKind::LeftmostLongest)),
                Some(build(MatchKind::Standard)),
            )
        };
        let replacements = labels
            .iter()
            .map(|l| format!("[envcloak:{l}]").into_bytes())
            .collect();

        (
            Redactor {
                automaton,
                scanner,
                patterns,
                owners,
                labels,
                replacements,
                max_len,
            },
            report,
        )
    }
}

fn hash_bytes(b: &[u8]) -> u64 {
    let mut h = DefaultHasher::new();
    b.hash(&mut h);
    h.finish()
}

/// Every form of `value` the redactor looks for, the raw value first, plus
/// whether some embedded-base64 fragment was too short to include and whether
/// the JSON style combinations were capped.
fn variants(value: &[u8]) -> (Vec<Zeroizing<Vec<u8>>>, bool, bool) {
    let mut out: Vec<Zeroizing<Vec<u8>>> = Vec::new();
    let mut push = |v: Zeroizing<Vec<u8>>| {
        if !v.is_empty() && !out.iter().any(|o| o.as_slice() == v.as_slice()) {
            out.push(v);
        }
    };

    let mut raw = Zeroizing::new(Vec::with_capacity(value.len()));
    raw.extend_from_slice(value);
    push(raw);

    // Whole-value encodings, as produced by `base64 <<< $KEY` and friends.
    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        push(Zeroizing::new(engine.encode(value).into_bytes()));
    }

    // The value embedded inside a longer base64 stream (for example
    // `Authorization: Basic base64("user:" + key)`) can start at any of three
    // byte alignments. For each, the 3-byte groups wholly inside the value
    // encode to a fixed string no matter what surrounds it.
    let mut partial = false;
    for skip in 0..3 {
        let rest = value.get(skip..).unwrap_or_default();
        let whole = rest.len() - rest.len() % 3;
        if whole / 3 * 4 < MIN_FRAGMENT_LEN {
            partial = true;
            continue;
        }
        push(Zeroizing::new(
            STANDARD_NO_PAD.encode(&rest[..whole]).into_bytes(),
        ));
        push(Zeroizing::new(
            URL_SAFE_NO_PAD.encode(&rest[..whole]).into_bytes(),
        ));
    }

    push(hex(value, b"0123456789abcdef"));
    push(hex(value, b"0123456789ABCDEF"));
    for profile in PERCENT_PROFILES {
        for upper in [true, false] {
            push(percent_encode(value, profile, upper));
        }
    }
    let mut truncated = false;
    if let Ok(s) = std::str::from_utf8(value) {
        let (json, capped) = json_variants(s);
        truncated = capped;
        for v in json {
            push(v);
        }
    }
    (out, partial, truncated)
}

fn hex(value: &[u8], digits: &[u8; 16]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(value.len() * 2));
    for b in value {
        out.push(digits[(b >> 4) as usize]);
        out.push(digits[(b & 0x0f) as usize]);
    }
    out
}

/// A percent-encoding style: bytes left unescaped besides ASCII letters and
/// digits, and whether a space becomes `+`.
struct PercentProfile {
    safe: &'static [u8],
    space_plus: bool,
}

const PERCENT_PROFILES: &[PercentProfile] = &[
    // RFC 3986 unreserved only.
    PercentProfile {
        safe: b"-._~",
        space_plus: false,
    },
    // JavaScript encodeURIComponent.
    PercentProfile {
        safe: b"-._~!'()*",
        space_plus: false,
    },
    // Python urllib.parse.quote with its default safe="/".
    PercentProfile {
        safe: b"-._~/",
        space_plus: false,
    },
    // Python quote_plus, Go QueryEscape.
    PercentProfile {
        safe: b"-._~",
        space_plus: true,
    },
    // WHATWG application/x-www-form-urlencoded, Java URLEncoder.
    PercentProfile {
        safe: b"*-._",
        space_plus: true,
    },
    // .NET WebUtility.UrlEncode and HttpUtility.UrlEncode (lowercase hex).
    PercentProfile {
        safe: b"-_.!*()",
        space_plus: true,
    },
    // Go url.PathEscape: escapes , ; / ? and leaves $ & + : = @ raw.
    PercentProfile {
        safe: b"-._~$&+:=@",
        space_plus: false,
    },
    // Lenient path/query encoders that keep sub-delimiters.
    PercentProfile {
        safe: b"-._~!$&'()*+,;=:@/?",
        space_plus: false,
    },
];

fn percent_encode(value: &[u8], profile: &PercentProfile, upper: bool) -> Zeroizing<Vec<u8>> {
    let digits: &[u8; 16] = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    let mut out = Zeroizing::new(Vec::with_capacity(value.len() * 3));
    for &b in value {
        if b.is_ascii_alphanumeric() || profile.safe.contains(&b) {
            out.push(b);
        } else if b == b' ' && profile.space_plus {
            out.push(b'+');
        } else {
            out.extend_from_slice(&[b'%', digits[(b >> 4) as usize], digits[(b & 0x0f) as usize]]);
        }
    }
    out
}

/// One JSON serializer style. Each flag only matters when the value contains
/// a character of that class.
#[derive(Clone, Copy, Default)]
struct JsonStyle {
    esc_quote: bool,
    esc_slash: bool,
    u_controls: bool,
    esc_nonascii: bool,
    esc_html: bool,
    esc_apos: bool,
    esc_plus: bool,
    esc_backtick: bool,
    esc_del: bool,
    esc_line_sep: bool,
    upper_hex: bool,
}

type StyleSetter = fn(&mut JsonStyle);

/// Default output styles of real serializers, generated before any
/// combination so a cap can never drop them.
const JSON_PRESETS: &[JsonStyle] = &[
    // serde_json, JavaScript JSON.stringify, Ruby, Python ensure_ascii=False.
    JsonStyle::PLAIN,
    // Python json.dumps default (ensure_ascii=True).
    JsonStyle {
        esc_nonascii: true,
        esc_del: true,
        esc_line_sep: true,
        ..JsonStyle::PLAIN
    },
    // Go encoding/json (HTML-safe by default).
    JsonStyle {
        esc_html: true,
        esc_line_sep: true,
        ..JsonStyle::PLAIN
    },
    // .NET System.Text.Json default encoder.
    JsonStyle {
        esc_quote: true,
        esc_nonascii: true,
        esc_html: true,
        esc_apos: true,
        esc_plus: true,
        esc_backtick: true,
        esc_del: true,
        esc_line_sep: true,
        upper_hex: true,
        ..JsonStyle::PLAIN
    },
    // PHP json_encode default.
    JsonStyle {
        esc_slash: true,
        esc_nonascii: true,
        esc_line_sep: true,
        ..JsonStyle::PLAIN
    },
];

impl JsonStyle {
    const PLAIN: JsonStyle = JsonStyle {
        esc_quote: false,
        esc_slash: false,
        u_controls: false,
        esc_nonascii: false,
        esc_html: false,
        esc_apos: false,
        esc_plus: false,
        esc_backtick: false,
        esc_del: false,
        esc_line_sep: false,
        upper_hex: false,
    };
}

/// JSON encodings of `s`: the named presets, then every combination of the
/// escape classes present in `s` up to [`MAX_JSON_VARIANTS`]. The flag is
/// true when combinations were capped.
fn json_variants(s: &str) -> (Vec<Zeroizing<Vec<u8>>>, bool) {
    let has = |f: fn(char) -> bool| s.chars().any(f);
    let mut dims: Vec<StyleSetter> = vec![|st| st.upper_hex = true];
    if has(|c| c == '"') {
        dims.push(|st| st.esc_quote = true);
    }
    if has(|c| c == '/') {
        dims.push(|st| st.esc_slash = true);
    }
    if has(|c| matches!(c, '\u{8}' | '\u{c}' | '\n' | '\r' | '\t')) {
        dims.push(|st| st.u_controls = true);
    }
    if has(|c| !c.is_ascii() && !matches!(c, '\u{2028}' | '\u{2029}')) {
        dims.push(|st| st.esc_nonascii = true);
    }
    if has(|c| matches!(c, '<' | '>' | '&')) {
        dims.push(|st| st.esc_html = true);
    }
    if has(|c| c == '\'') {
        dims.push(|st| st.esc_apos = true);
    }
    if has(|c| c == '+') {
        dims.push(|st| st.esc_plus = true);
    }
    if has(|c| c == '`') {
        dims.push(|st| st.esc_backtick = true);
    }
    if has(|c| c == '\u{7f}') {
        dims.push(|st| st.esc_del = true);
    }
    if has(|c| matches!(c, '\u{2028}' | '\u{2029}')) {
        dims.push(|st| st.esc_line_sep = true);
    }

    let total = 1usize << dims.len();
    let combos = total.min(MAX_JSON_VARIANTS);
    let mut out = Vec::with_capacity(JSON_PRESETS.len() + combos);
    for &preset in JSON_PRESETS {
        out.push(json_encode(s, preset));
    }
    for mask in 0..combos {
        let mut st = JsonStyle::default();
        for (bit, set) in dims.iter().enumerate() {
            if mask & (1 << bit) != 0 {
                set(&mut st);
            }
        }
        out.push(json_encode(s, st));
    }
    (out, total > MAX_JSON_VARIANTS)
}

fn json_encode(s: &str, st: JsonStyle) -> Zeroizing<Vec<u8>> {
    // 12 bytes is the longest escape of one char (a surrogate pair).
    let mut out = Zeroizing::new(Vec::with_capacity(s.len() * 12));
    let digits: &[u8; 16] = if st.upper_hex {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    let u = |out: &mut Vec<u8>, unit: u16| {
        out.extend_from_slice(b"\\u");
        for shift in [12, 8, 4, 0] {
            out.push(digits[((unit >> shift) & 0xf) as usize]);
        }
    };
    let mut units = [0u16; 2];
    for c in s.chars() {
        match c {
            '"' if st.esc_quote => u(&mut out, 0x22),
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '/' if st.esc_slash => out.extend_from_slice(b"\\/"),
            '\u{8}' if !st.u_controls => out.extend_from_slice(b"\\b"),
            '\u{c}' if !st.u_controls => out.extend_from_slice(b"\\f"),
            '\n' if !st.u_controls => out.extend_from_slice(b"\\n"),
            '\r' if !st.u_controls => out.extend_from_slice(b"\\r"),
            '\t' if !st.u_controls => out.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => u(&mut out, c as u16),
            '\u{7f}' if st.esc_del => u(&mut out, 0x7f),
            '<' | '>' | '&' if st.esc_html => u(&mut out, c as u16),
            '\'' if st.esc_apos => u(&mut out, c as u16),
            '+' if st.esc_plus => u(&mut out, c as u16),
            '`' if st.esc_backtick => u(&mut out, c as u16),
            '\u{2028}' | '\u{2029}' if st.esc_line_sep || st.esc_nonascii => u(&mut out, c as u16),
            c if !c.is_ascii() && st.esc_nonascii => {
                for &unit in c.encode_utf16(&mut units).iter() {
                    u(&mut out, unit);
                }
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out
}

/// Replaces secrets, and their encodings, with labelled markers.
pub struct Redactor {
    /// Leftmost-longest matcher used for replacement.
    automaton: Option<AhoCorasick>,
    /// Overlapping matcher used for leak scanning.
    scanner: Option<AhoCorasick>,
    patterns: Vec<Zeroizing<Vec<u8>>>,
    /// Every label that owns each pattern, in registration order.
    owners: Vec<Vec<usize>>,
    labels: Vec<String>,
    replacements: Vec<Vec<u8>>,
    max_len: usize,
}

impl std::fmt::Debug for Redactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Redactor")
            .field("labels", &self.labels.len())
            .field("patterns", &self.patterns.len())
            .field("max_len", &self.max_len)
            .finish_non_exhaustive()
    }
}

impl Redactor {
    /// A redactor that changes nothing.
    pub fn empty() -> Self {
        RedactorBuilder::new().build().0
    }

    /// True when there is nothing to redact.
    pub fn is_empty(&self) -> bool {
        self.automaton.is_none()
    }

    /// Redacts a complete buffer.
    pub fn redact(&self, input: &[u8]) -> Vec<u8> {
        self.redact_complete(input)
    }

    /// Redacts a complete string. Markers are ASCII, so valid UTF-8 input
    /// stays valid unless a secret boundary splits a multi-byte character, in
    /// which case invalid sequences are replaced.
    pub fn redact_str(&self, input: &str) -> String {
        String::from_utf8_lossy(&self.redact(input.as_bytes())).into_owned()
    }

    /// Starts redacting a stream.
    pub fn stream(&self) -> StreamRedactor<'_> {
        StreamRedactor {
            redactor: self,
            carry: Zeroizing::new(Vec::new()),
        }
    }

    /// Returns the label of every secret found anywhere in `input`, including
    /// secrets that share a value and secrets nested inside other secrets, in
    /// registration order. Used by leak scanning; nothing is modified.
    pub fn find_labels(&self, input: &[u8]) -> Vec<&str> {
        let Some(scanner) = &self.scanner else {
            return Vec::new();
        };
        let mut seen = vec![false; self.labels.len()];
        for m in scanner.find_overlapping_iter(input) {
            for &o in &self.owners[m.pattern().as_usize()] {
                seen[o] = true;
            }
        }
        seen.iter()
            .enumerate()
            .filter(|(_, s)| **s)
            .map(|(i, _)| self.labels[i].as_str())
            .collect()
    }

    fn replacement(&self, pattern: usize) -> &[u8] {
        &self.replacements[self.owners[pattern][0]]
    }

    fn redact_complete(&self, input: &[u8]) -> Vec<u8> {
        let Some(ac) = &self.automaton else {
            return input.to_vec();
        };
        let mut out = Vec::with_capacity(input.len());
        let mut pos = 0;
        for m in ac.find_iter(input) {
            out.extend_from_slice(&input[pos..m.start()]);
            out.extend_from_slice(self.replacement(m.pattern().as_usize()));
            pos = m.end();
        }
        out.extend_from_slice(&input[pos..]);
        out
    }
}

/// Incremental redaction over a chunked byte stream.
pub struct StreamRedactor<'a> {
    redactor: &'a Redactor,
    carry: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for StreamRedactor<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamRedactor")
            .field("held_back", &self.carry.len())
            .finish_non_exhaustive()
    }
}

impl StreamRedactor<'_> {
    /// Feeds a chunk. Appends everything that is safe to release to `out`.
    pub fn push(&mut self, chunk: &[u8], out: &mut Vec<u8>) {
        let Some(ac) = &self.redactor.automaton else {
            out.extend_from_slice(chunk);
            return;
        };
        // Build the working buffer at its final size: growing a buffer that
        // holds secret bytes would free an unwiped copy.
        let mut buf = Zeroizing::new(Vec::with_capacity(self.carry.len() + chunk.len()));
        buf.extend_from_slice(&self.carry);
        buf.extend_from_slice(chunk);
        self.carry.zeroize();

        // A match that starts before `safe` is fully decided: every pattern is
        // at most `max_len` long, so any pattern starting there already fits
        // inside `buf`, and leftmost-longest picks the right one.
        let safe = buf.len().saturating_sub(self.redactor.max_len - 1);
        let mut pos = 0;
        for m in ac.find_iter(buf.as_slice()) {
            if m.start() >= safe {
                break;
            }
            out.extend_from_slice(&buf[pos..m.start()]);
            out.extend_from_slice(self.redactor.replacement(m.pattern().as_usize()));
            pos = m.end();
        }
        let keep_from = pos.max(safe);
        out.extend_from_slice(&buf[pos..keep_from]);
        self.keep(&buf[keep_from..]);
    }

    /// Releases held-back bytes that cannot be the start of any secret. Call
    /// this when the stream goes idle (an interactive prompt waiting for
    /// input, for example) so output is not delayed indefinitely. Bytes that
    /// might still begin a secret stay held.
    pub fn flush_idle(&mut self, out: &mut Vec<u8>) {
        let Some(ac) = &self.redactor.automaton else {
            return;
        };
        if self.carry.is_empty() {
            return;
        }
        let carry = Zeroizing::new(std::mem::take(&mut *self.carry));
        // The earliest position where more input could still complete a
        // pattern: its suffix is a proper prefix of some pattern. Nothing at
        // or after it may be released yet.
        let hold_from = (0..carry.len())
            .find(|&i| {
                let tail = &carry[i..];
                self.redactor
                    .patterns
                    .iter()
                    .any(|p| p.len() > tail.len() && p.starts_with(tail))
            })
            .unwrap_or(carry.len());
        // Matches that start before `hold_from` are final (no longer pattern
        // can start there), even if they run past it, so release them whole.
        let mut pos = 0;
        for m in ac.find_iter(carry.as_slice()) {
            if m.start() >= hold_from {
                break;
            }
            out.extend_from_slice(&carry[pos..m.start()]);
            out.extend_from_slice(self.redactor.replacement(m.pattern().as_usize()));
            pos = m.end();
        }
        let keep_from = pos.max(hold_from);
        out.extend_from_slice(&carry[pos..keep_from]);
        self.keep(&carry[keep_from..]);
    }

    /// Ends the stream, releasing everything that is left.
    pub fn finish(&mut self, out: &mut Vec<u8>) {
        let carry = Zeroizing::new(std::mem::take(&mut *self.carry));
        out.extend_from_slice(&self.redactor.redact_complete(&carry));
    }

    fn keep(&mut self, tail: &[u8]) {
        let mut next = Zeroizing::new(Vec::with_capacity(tail.len()));
        next.extend_from_slice(tail);
        self.carry = next;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const KEY: &str = "tk-demo-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
    const M: &str = "[envcloak:openai/work]";

    fn redactor() -> Redactor {
        RedactorBuilder::new().secret("openai/work", KEY).build().0
    }

    fn assert_redacted(r: &Redactor, label: &str, encoded: &str, case: &str) {
        let marker = format!("[envcloak:{label}]");
        let out = r.redact_str(&format!("<<{encoded}>>"));
        assert_eq!(out, format!("<<{marker}>>"), "{case}: {encoded}");
    }

    #[test]
    fn redacts_raw_value_everywhere() {
        let r = redactor();
        assert_eq!(r.redact_str(&format!("key={KEY}\n")), format!("key={M}\n"));
        assert_eq!(
            r.redact_str(&format!("{KEY} and {KEY}")),
            format!("{M} and {M}")
        );
    }

    #[test]
    fn redacts_whole_value_encodings() {
        let r = redactor();
        for (case, encoded) in [
            ("base64", STANDARD.encode(KEY)),
            ("base64url", URL_SAFE_NO_PAD.encode(KEY)),
            ("hex", KEY.bytes().map(|b| format!("{b:02x}")).collect()),
            ("HEX", KEY.bytes().map(|b| format!("{b:02X}")).collect()),
        ] {
            assert_redacted(&r, "openai/work", &encoded, case);
        }
    }

    #[test]
    fn redacts_key_inside_basic_auth_at_every_alignment() {
        let r = redactor();
        for prefix in ["u:", "us:", "use:", "user:"] {
            let blob = STANDARD.encode(format!("{prefix}{KEY}"));
            let out = r.redact_str(&blob);
            assert!(out.contains(M), "prefix {prefix}: {out}");
            let leftover = out.replace(M, "");
            assert!(leftover.len() <= 12, "prefix {prefix}: leftover {leftover}");
        }
    }

    /// A synthetic value that exercises every JSON escape class.
    const TRICKY: &str = "ab/cd\"ef\\gh\u{8}ij\u{e9}kl\u{1F600}mn+op qr'st<uv";

    #[test]
    fn json_from_independent_serializers() {
        let r = RedactorBuilder::new().secret("t", TRICKY).build().0;
        // serde_json (Rust) as an in-process oracle. Output of other
        // runtimes is tested from generated files in tests/serializers.rs.
        let serde = serde_json::to_string(TRICKY).unwrap();
        assert_redacted(&r, "t", &serde[1..serde.len() - 1], "serde_json");
    }

    #[test]
    fn url_encodings_from_independent_encoders() {
        let v = "tok/en+val ue~!*'()&=x";
        let r = RedactorBuilder::new().secret("u", v).build().0;
        let form: String = form_urlencoded::byte_serialize(v.as_bytes()).collect();
        assert_redacted(&r, "u", &form, "WHATWG form");
        assert_redacted(&r, "u", &lower_percent(&form), "WHATWG form lowercase");
    }

    fn lower_percent(s: &str) -> String {
        let mut out = String::new();
        let mut rest = s;
        while let Some(i) = rest.find('%') {
            out.push_str(&rest[..i]);
            out.push('%');
            out.push_str(&rest[i + 1..i + 3].to_ascii_lowercase());
            rest = &rest[i + 3..];
        }
        out.push_str(rest);
        out
    }

    #[test]
    fn short_accepted_secret_keeps_whole_value_encodings() {
        let eight = "Ab3$xY9!";
        let (r, report) = RedactorBuilder::new().secret("e", eight).build();
        assert!(report.skipped.is_empty());
        assert_eq!(report.partial, vec!["e".to_string()]);
        assert_redacted(&r, "e", &STANDARD_NO_PAD.encode(eight), "unpadded base64");
        assert_redacted(&r, "e", &STANDARD.encode(eight), "padded base64");
        let json = serde_json::to_string(eight).unwrap();
        assert_redacted(&r, "e", &json[1..json.len() - 1], "json");
    }

    #[test]
    fn skips_and_reports_too_short_secrets() {
        let (r, report) = RedactorBuilder::new()
            .secret("port", "8080")
            .secret("real", KEY)
            .build();
        assert_eq!(report.skipped, vec!["port".to_string()]);
        assert_eq!(r.redact_str("8080"), "8080");
    }

    #[test]
    fn find_labels_reports_every_owner_of_a_shared_value() {
        let r = RedactorBuilder::new()
            .secret("openai/work", KEY)
            .secret("openai/copy", KEY)
            .secret("other", "another-secret-value-123")
            .build()
            .0;
        let text = format!("zz {} zz", STANDARD.encode(KEY));
        assert_eq!(
            r.find_labels(text.as_bytes()),
            vec!["openai/work", "openai/copy"]
        );
        // Replacement is deterministic: the first registered label.
        assert_eq!(r.redact_str(KEY), M);
    }

    #[test]
    fn find_labels_reports_nested_secrets() {
        let inner = "inner-secret-123";
        let outer = format!("prefix-{inner}-suffix");
        let r = RedactorBuilder::new()
            .secret("outer", &outer)
            .secret("inner", inner)
            .build()
            .0;
        assert_eq!(r.find_labels(outer.as_bytes()), vec!["outer", "inner"]);
        assert_eq!(r.redact_str(&outer), "[envcloak:outer]");
    }

    #[test]
    fn empty_redactor_passes_through() {
        let r = Redactor::empty();
        assert!(r.is_empty());
        assert_eq!(r.redact_str("anything"), "anything");
        let mut s = r.stream();
        let mut out = Vec::new();
        s.push(b"abc", &mut out);
        s.flush_idle(&mut out);
        s.finish(&mut out);
        assert_eq!(out, b"abc");
        assert!(r.find_labels(b"abc").is_empty());
    }

    #[test]
    fn stream_catches_value_split_at_every_position_with_idle_flush() {
        let r = redactor();
        let text = format!("start {KEY} end");
        for split in 0..=text.len() {
            let mut s = r.stream();
            let mut out = Vec::new();
            s.push(&text.as_bytes()[..split], &mut out);
            s.flush_idle(&mut out);
            s.push(&text.as_bytes()[split..], &mut out);
            s.finish(&mut out);
            assert_eq!(
                String::from_utf8(out).unwrap(),
                format!("start {M} end"),
                "split {split}"
            );
        }
    }

    #[test]
    fn flush_idle_releases_prompt_but_holds_possible_secret_prefix() {
        let r = redactor();
        let mut s = r.stream();
        let mut out = Vec::new();
        s.push(b"Enter your name: ", &mut out);
        s.flush_idle(&mut out);
        assert_eq!(out, b"Enter your name: ");

        let mut out = Vec::new();
        let mut s = r.stream();
        s.push(b"token tk-demo-Ab", &mut out);
        s.flush_idle(&mut out);
        assert_eq!(out, b"token ");
        s.push(&KEY.as_bytes()[10..], &mut out);
        s.finish(&mut out);
        assert_eq!(String::from_utf8(out).unwrap(), format!("token {M}"));
    }

    #[test]
    fn debug_output_never_contains_secret() {
        let r = redactor();
        let dbg = format!("{r:?} {:?}", r.stream());
        assert!(!dbg.contains(KEY));
        let b = RedactorBuilder::new().secret("x", KEY);
        assert!(!format!("{b:?}").contains(KEY));
    }

    mod props {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn chunked_with_idle_flush_equals_one_shot(
                noise in proptest::collection::vec(any::<u8>(), 0..400),
                insert_at in 0usize..400,
                cuts in proptest::collection::vec(0usize..600, 0..8),
            ) {
                let r = redactor();
                let mut input = noise.clone();
                let at = insert_at.min(input.len());
                input.splice(at..at, KEY.bytes());

                let expected = r.redact(&input);
                let mut cuts = cuts.into_iter().map(|c| c.min(input.len())).collect::<Vec<_>>();
                cuts.sort_unstable();
                let mut s = r.stream();
                let mut out = Vec::new();
                let mut prev = 0;
                for c in cuts {
                    s.push(&input[prev..c], &mut out);
                    s.flush_idle(&mut out);
                    prev = c;
                }
                s.push(&input[prev..], &mut out);
                s.finish(&mut out);
                prop_assert_eq!(&out, &expected);
                prop_assert!(!out.windows(KEY.len()).any(|w| w == KEY.as_bytes()));
            }
        }
    }
}
