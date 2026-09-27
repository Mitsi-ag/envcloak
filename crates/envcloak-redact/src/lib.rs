//! Streaming redaction of secret values.
//!
//! A [`Redactor`] is built from a set of labelled secrets. It replaces every
//! occurrence of each secret, and of its common encodings (base64 at every
//! byte alignment, base64url, hex, percent-encoding, JSON escaping), with a
//! marker such as `[envcloak:openai/work]`.
//!
//! [`StreamRedactor`] applies a redactor to a byte stream that arrives in
//! arbitrary chunks (a child process's stdout, for example). It holds back
//! only as many bytes as could still turn out to be the start of a secret, so
//! a value split across two reads is still caught.
//!
//! Redaction is a guard against accidents. A process that holds a secret can
//! always transform it into a form no redactor recognises; EnvCloak's proxy
//! mode exists for that threat.

use aho_corasick::{AhoCorasick, MatchKind};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use zeroize::Zeroizing;

/// Secrets shorter than this are not redacted: short values such as `true`
/// or `8080` would destroy ordinary output. The builder reports them instead.
pub const DEFAULT_MIN_SECRET_LEN: usize = 8;

/// Encoded variants shorter than this are dropped to avoid false positives.
const MIN_VARIANT_LEN: usize = 12;

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
    /// itself be secret.
    pub fn secret(mut self, label: impl Into<String>, value: impl AsRef<[u8]>) -> Self {
        self.secrets
            .push((label.into(), Zeroizing::new(value.as_ref().to_vec())));
        self
    }

    /// Builds the redactor. Returns it together with the labels of secrets
    /// that were too short to redact safely, so callers can warn about them.
    pub fn build(self) -> (Redactor, Vec<String>) {
        let min_len = self.min_len.unwrap_or(DEFAULT_MIN_SECRET_LEN);
        let mut patterns: Vec<Zeroizing<Vec<u8>>> = Vec::new();
        let mut owners: Vec<usize> = Vec::new();
        let mut labels: Vec<String> = Vec::new();
        let mut too_short = Vec::new();

        for (label, value) in self.secrets {
            if value.len() < min_len {
                too_short.push(label);
                continue;
            }
            let idx = labels.len();
            labels.push(label);
            for variant in variants(&value) {
                if !patterns.iter().any(|p| p.as_slice() == variant.as_slice()) {
                    patterns.push(variant);
                    owners.push(idx);
                }
            }
        }

        let max_len = patterns.iter().map(|p| p.len()).max().unwrap_or(0);
        let automaton = if patterns.is_empty() {
            None
        } else {
            Some(
                AhoCorasick::builder()
                    .match_kind(MatchKind::LeftmostLongest)
                    .build(patterns.iter().map(|p| p.as_slice()))
                    .expect("aho-corasick build cannot fail for literal patterns"),
            )
        };
        let replacements = labels
            .iter()
            .map(|l| format!("[envcloak:{l}]").into_bytes())
            .collect();

        (
            Redactor {
                automaton,
                patterns,
                owners,
                replacements,
                max_len,
            },
            too_short,
        )
    }
}

/// Every form of `value` the redactor looks for, the raw value first.
fn variants(value: &[u8]) -> Vec<Zeroizing<Vec<u8>>> {
    let mut out: Vec<Zeroizing<Vec<u8>>> = vec![Zeroizing::new(value.to_vec())];
    let mut push = |v: Vec<u8>| {
        let v = Zeroizing::new(v);
        if v.len() >= MIN_VARIANT_LEN && !out.iter().any(|o| o.as_slice() == v.as_slice()) {
            out.push(v);
        }
    };

    // Whole-value encodings, as produced by `base64 <<< $KEY` and friends.
    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        push(engine.encode(value).into_bytes());
    }

    // The value embedded inside a longer base64 stream (for example
    // `Authorization: Basic base64("user:" + key)`) can start at any of three
    // byte alignments. For each, the 3-byte groups that lie wholly inside the
    // value encode to a fixed string no matter what surrounds it.
    for skip in 0..3 {
        if value.len() <= skip {
            break;
        }
        let rest = &value[skip..];
        let whole = rest.len() - rest.len() % 3;
        if whole > 0 {
            push(STANDARD_NO_PAD.encode(&rest[..whole]).into_bytes());
            push(URL_SAFE_NO_PAD.encode(&rest[..whole]).into_bytes());
        }
    }

    push(hex(value, b"0123456789abcdef"));
    push(hex(value, b"0123456789ABCDEF"));
    push(percent_encode(value));
    push(json_escape(value));
    out
}

fn hex(value: &[u8], digits: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() * 2);
    for b in value {
        out.push(digits[(b >> 4) as usize]);
        out.push(digits[(b & 0x0f) as usize]);
    }
    out
}

fn percent_encode(value: &[u8]) -> Vec<u8> {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = Vec::with_capacity(value.len());
    for &b in value {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b);
        } else {
            out.extend_from_slice(&[b'%', DIGITS[(b >> 4) as usize], DIGITS[(b & 0x0f) as usize]]);
        }
    }
    out
}

fn json_escape(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len());
    for &b in value {
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'/' => out.extend_from_slice(b"\\/"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x00..=0x1f => out.extend_from_slice(format!("\\u{b:04x}").as_bytes()),
            _ => out.push(b),
        }
    }
    out
}

/// Replaces secrets, and their encodings, with labelled markers.
pub struct Redactor {
    automaton: Option<AhoCorasick>,
    patterns: Vec<Zeroizing<Vec<u8>>>,
    owners: Vec<usize>,
    replacements: Vec<Vec<u8>>,
    max_len: usize,
}

impl std::fmt::Debug for Redactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Redactor")
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
        let mut out = Vec::with_capacity(input.len());
        let mut stream = self.stream();
        stream.push(input, &mut out);
        stream.finish(&mut out);
        out
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

    /// Scans `input` and returns the labels of every secret found in it,
    /// without modifying anything. Used by leak scanning.
    pub fn find_labels(&self, input: &[u8]) -> Vec<&str> {
        let Some(ac) = &self.automaton else {
            return Vec::new();
        };
        let mut seen = vec![false; self.replacements.len()];
        for m in ac.find_iter(input) {
            seen[self.owners[m.pattern().as_usize()]] = true;
        }
        seen.iter()
            .enumerate()
            .filter(|(_, s)| **s)
            .map(|(i, _)| self.label(i))
            .collect()
    }

    fn label(&self, owner: usize) -> &str {
        let r = &self.replacements[owner];
        // "[envcloak:" .. "]"
        std::str::from_utf8(&r[10..r.len() - 1]).unwrap_or("")
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
        let mut buf = Zeroizing::new(std::mem::take(&mut *self.carry));
        buf.extend_from_slice(chunk);

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
            out.extend_from_slice(
                &self.redactor.replacements[self.redactor.owners[m.pattern().as_usize()]],
            );
            pos = m.end();
        }
        let keep_from = pos.max(safe);
        out.extend_from_slice(&buf[pos..keep_from]);
        self.carry.extend_from_slice(&buf[keep_from..]);
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
            out.extend_from_slice(
                &self.redactor.replacements[self.redactor.owners[m.pattern().as_usize()]],
            );
            pos = m.end();
        }
        let keep_from = pos.max(hold_from);
        out.extend_from_slice(&carry[pos..keep_from]);
        self.carry.extend_from_slice(&carry[keep_from..]);
    }

    /// Ends the stream, releasing everything that is left.
    pub fn finish(&mut self, out: &mut Vec<u8>) {
        let carry = Zeroizing::new(std::mem::take(&mut *self.carry));
        out.append(&mut self.redactor.redact_complete(&carry));
    }
}

impl Redactor {
    fn redact_complete(&self, input: &[u8]) -> Vec<u8> {
        let Some(ac) = &self.automaton else {
            return input.to_vec();
        };
        let mut out = Vec::with_capacity(input.len());
        let mut pos = 0;
        for m in ac.find_iter(input) {
            out.extend_from_slice(&input[pos..m.start()]);
            out.extend_from_slice(&self.replacements[self.owners[m.pattern().as_usize()]]);
            pos = m.end();
        }
        out.extend_from_slice(&input[pos..]);
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const KEY: &str = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";

    fn redactor() -> Redactor {
        RedactorBuilder::new().secret("openai/work", KEY).build().0
    }

    #[test]
    fn redacts_raw_value() {
        let out = redactor().redact_str(&format!("key={KEY}\n"));
        assert_eq!(out, "key=[envcloak:openai/work]\n");
    }

    #[test]
    fn redacts_every_occurrence() {
        let out = redactor().redact_str(&format!("{KEY} and {KEY}"));
        assert_eq!(out, "[envcloak:openai/work] and [envcloak:openai/work]");
    }

    #[test]
    fn redacts_whole_value_encodings() {
        let r = redactor();
        for encoded in [
            STANDARD.encode(KEY),
            URL_SAFE_NO_PAD.encode(KEY),
            String::from_utf8(hex(KEY.as_bytes(), b"0123456789abcdef")).unwrap(),
            String::from_utf8(hex(KEY.as_bytes(), b"0123456789ABCDEF")).unwrap(),
        ] {
            let out = r.redact_str(&format!("x {encoded} y"));
            assert_eq!(out, "x [envcloak:openai/work] y", "variant {encoded}");
        }
    }

    #[test]
    fn redacts_key_inside_basic_auth_at_every_alignment() {
        let r = redactor();
        for prefix in ["u:", "us:", "use:", "user:"] {
            let blob = STANDARD.encode(format!("{prefix}{KEY}"));
            let out = r.redact_str(&blob);
            assert!(
                out.contains("[envcloak:openai/work]"),
                "prefix {prefix}: {out}"
            );
            // What survives around the marker is at most a few boundary chars.
            let leftover = out.replace("[envcloak:openai/work]", "");
            assert!(leftover.len() <= 12, "prefix {prefix}: leftover {leftover}");
        }
    }

    #[test]
    fn redacts_percent_and_json_escaped_forms() {
        let key = "abc/def+ghi=jkl\"mno";
        let r = RedactorBuilder::new().secret("x", key).build().0;
        let url = String::from_utf8(percent_encode(key.as_bytes())).unwrap();
        let json = String::from_utf8(json_escape(key.as_bytes())).unwrap();
        assert_eq!(r.redact_str(&format!("?k={url}&")), "?k=[envcloak:x]&");
        assert_eq!(
            r.redact_str(&format!("{{\"k\":\"{json}\"}}")),
            "{\"k\":\"[envcloak:x]\"}"
        );
    }

    #[test]
    fn skips_and_reports_short_secrets() {
        let (r, short) = RedactorBuilder::new()
            .secret("port", "8080")
            .secret("real", KEY)
            .build();
        assert_eq!(short, vec!["port".to_string()]);
        assert_eq!(r.redact_str("8080"), "8080");
    }

    #[test]
    fn empty_redactor_passes_through() {
        let r = Redactor::empty();
        assert!(r.is_empty());
        assert_eq!(r.redact_str("anything"), "anything");
        let mut s = r.stream();
        let mut out = Vec::new();
        s.push(b"abc", &mut out);
        s.finish(&mut out);
        assert_eq!(out, b"abc");
    }

    #[test]
    fn stream_catches_value_split_across_chunks() {
        let r = redactor();
        let text = format!("start {KEY} end");
        for split in 0..=text.len() {
            let mut s = r.stream();
            let mut out = Vec::new();
            s.push(&text.as_bytes()[..split], &mut out);
            s.push(&text.as_bytes()[split..], &mut out);
            s.finish(&mut out);
            assert_eq!(
                String::from_utf8(out).unwrap(),
                "start [envcloak:openai/work] end",
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
        s.push(b"token sk-proj-Ab", &mut out);
        s.flush_idle(&mut out);
        assert_eq!(out, b"token ");
        s.push(&KEY.as_bytes()[10..], &mut out);
        s.finish(&mut out);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "token [envcloak:openai/work]"
        );
    }

    #[test]
    fn find_labels_reports_without_modifying() {
        let r = RedactorBuilder::new()
            .secret("a", KEY)
            .secret("b", "another-secret-value-123")
            .build()
            .0;
        let labels = r.find_labels(format!("zz {} zz", STANDARD.encode(KEY)).as_bytes());
        assert_eq!(labels, vec!["a"]);
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
            fn chunked_equals_one_shot(
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
