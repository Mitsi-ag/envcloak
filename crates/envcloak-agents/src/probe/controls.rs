//! What a probe and its control count as evidence (M2 plan M2-09): read
//! from what the scripted model recorded and from the host's own stores,
//! never from the host's exit code or what it printed (Codex cycle177: a
//! completed turn proves neither a block nor a delivery).
//!
//! - A control *reached* the model when a request the model accepted (the
//!   run's token, a known API, answered 200 whole) holds its marker: a
//!   socket connection, a refused token, an unknown route or a malformed
//!   body is no control ([`reached`]; Codex cycle354's receiver corpus).
//! - A probe's value is *kept out* only when no recorded request holds it
//!   in any form ([`forms`]: as it is, base64 in both alphabets, padded or
//!   not and at every alignment, hexadecimal, percent-encoded, JSON
//!   `\u` escapes), as it is or in any decoded reading of what was sent
//!   ([`holds`]: JSON string escapes of any serializer decoded, also
//!   within a string held in a string, and percent-encodings of any
//!   encoder decoded: the encodings SPEC §6.1's redaction covers), in any
//!   part of any request: its method, path and query, every header's name
//!   and value, its body, and a refused tunnel's forwarded target
//!   ([`seen`]).
//! - A tool's result is the last tool result in the request that came
//!   after the call ([`last_tool_output`]), the place a host puts what a
//!   command printed or a hook's denial.
//! - The host's stores are read by [`sweep`], which looks in every file's
//!   contents and every entry's name, decoded as above, and counts a
//!   needle found only within what it read whole: a file it could not
//!   read, or past its caps, makes the sweep incomplete, which no probe
//!   counts as clean (L-08).

use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use serde_json::Value;
use zeroize::Zeroizing;

use super::model::Recorded;
use super::model::wire::Api;

/// A marker for a control: `ecp-<what>-` and four groups of four
/// hexadecimal digits, so that it never looks like a key to the prompt
/// hook (no run of 24 letters and digits) and is unique to its run.
///
/// # Errors
/// When the system has no random bytes to give.
pub fn marker(what: &str) -> std::io::Result<String> {
    let mut raw = [0u8; 8];
    getrandom::fill(&mut raw).map_err(std::io::Error::other)?;
    let h = crate::coverage::hex(&raw);
    Ok(format!(
        "ecp-{what}-{}-{}-{}-{}",
        &h[..4],
        &h[4..8],
        &h[8..12],
        &h[12..16]
    ))
}

/// A token shaped like a key, to stand for one a person pastes: `ecpk`
/// and 32 hexadecimal digits, one run of letters and digits that holds
/// both, which the prompt hook takes for a key (`hook::prompt::RUN`).
///
/// # Errors
/// When the system has no random bytes to give.
pub fn key_shaped() -> std::io::Result<Zeroizing<String>> {
    let mut raw = Zeroizing::new([0u8; 16]);
    getrandom::fill(&mut *raw).map_err(std::io::Error::other)?;
    let mut s = Zeroizing::new(String::from("ecpk"));
    s.push_str(&crate::coverage::hex(&*raw));
    Ok(s)
}

/// `marker` in two pieces, for a command that prints it whole only when
/// it runs: the call carrying the pieces never holds the whole.
pub fn halves(marker: &str) -> (&str, &str) {
    marker.split_at(marker.len() / 2)
}

/// Whether `haystack` holds `needle`.
pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// How many times [`each_view`] decodes JSON escapes: a value in a JSON
/// string that is itself held in a JSON string (a tool's arguments, a
/// result kept as a string) is escaped twice.
const UNESCAPE_DEPTH: usize = 3;

/// Visits each decoded reading of `bytes` a value may be in, beside the
/// bytes themselves (Codex's round-3 review: a value holding a quote or a
/// line break reaches the model as `\"` or `\n` in a JSON body, which no
/// form of it matched), until `visit` says it is done: every JSON string
/// escape decoded wherever it is, from any serializer (short escapes,
/// `\/`, `\u` escapes in either case, surrogate pairs; up to
/// [`UNESCAPE_DEPTH`] times, for a string within a string), and each of
/// those and the bytes percent-decoded, `+` as itself and as a space
/// (common encoders leave different characters as they are, and a form's
/// `+` is a space). One reading at a time is kept, wiped when dropped.
fn each_view(bytes: &[u8], visit: &mut dyn FnMut(&[u8]) -> bool) {
    let percent = |from: &[u8], visit: &mut dyn FnMut(&[u8]) -> bool| {
        [false, true]
            .into_iter()
            .filter_map(|plus| percent_decoded(from, plus))
            .any(|p| visit(&p))
    };
    if percent(bytes, visit) {
        return;
    }
    let mut last: Option<Zeroizing<Vec<u8>>> = None;
    for _ in 0..UNESCAPE_DEPTH {
        let from: &[u8] = last.as_deref().map_or(bytes, Vec::as_slice);
        let Some(next) = unescaped(from) else {
            return;
        };
        if visit(&next) || percent(&next, visit) {
            return;
        }
        last = Some(next);
    }
}

/// Whether `bytes`, or any decoded reading of them ([`each_view`]), holds
/// any of `forms`.
pub fn holds(bytes: &[u8], forms: &[Zeroizing<Vec<u8>>]) -> bool {
    holds_any(bytes, &[forms]).into_iter().any(|x| x)
}

/// For each set of forms, whether `bytes` or a decoded reading of them
/// holds one: each reading made once for every set.
fn holds_any(bytes: &[u8], sets: &[&[Zeroizing<Vec<u8>>]]) -> Vec<bool> {
    let mut found: Vec<bool> = sets
        .iter()
        .map(|forms| forms.iter().any(|f| contains(bytes, f)))
        .collect();
    if found.iter().all(|x| *x) {
        return found;
    }
    each_view(bytes, &mut |v| {
        for (i, forms) in sets.iter().enumerate() {
            found[i] |= forms.iter().any(|f| contains(v, f));
        }
        found.iter().all(|x| *x)
    });
    found
}

/// `bytes` with every JSON string escape decoded, left to right (`\\` is
/// one backslash, so `\\n` is a backslash and an `n`); an escape that is
/// not one is kept as it is. `None` when there is no backslash.
fn unescaped(bytes: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if !bytes.contains(&b'\\') {
        return None;
    }
    let hex4 = |at: usize| -> Option<u32> {
        let h = bytes.get(at..at + 4)?;
        if !h.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        u32::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok()
    };
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b != b'\\' || i + 1 >= bytes.len() {
            out.push(b);
            i += 1;
            continue;
        }
        let short = match bytes[i + 1] {
            b'"' => Some(b'"'),
            b'\\' => Some(b'\\'),
            b'/' => Some(b'/'),
            b'b' => Some(8),
            b'f' => Some(12),
            b'n' => Some(b'\n'),
            b'r' => Some(b'\r'),
            b't' => Some(b'\t'),
            _ => None,
        };
        if let Some(c) = short {
            out.push(c);
            i += 2;
            continue;
        }
        if bytes[i + 1] == b'u' {
            if let Some(u) = hex4(i + 2) {
                // A surrogate pair is one character.
                let pair = (0xD800..0xDC00).contains(&u)
                    && bytes.get(i + 6..i + 8) == Some(&b"\\u"[..])
                    && hex4(i + 8).is_some_and(|l| (0xDC00..0xE000).contains(&l));
                let (c, len) = if pair {
                    let lo = hex4(i + 8).unwrap_or(0);
                    (
                        char::from_u32(0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00)),
                        12,
                    )
                } else {
                    (char::from_u32(u), 6)
                };
                if let Some(c) = c {
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                    i += len;
                    continue;
                }
            }
        }
        out.push(b);
        i += 1;
    }
    Some(out)
}

/// `bytes` with every `%XX` decoded (either case), and with `plus`, every
/// `+` a space. `None` when there is nothing to decode.
fn percent_decoded(bytes: &[u8], plus: bool) -> Option<Zeroizing<Vec<u8>>> {
    if !bytes.contains(&b'%') && !(plus && bytes.contains(&b'+')) {
        return None;
    }
    let digit = |b: u8| char::from(b).to_digit(16);
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => match (
                bytes.get(i + 1).and_then(|b| digit(*b)),
                bytes.get(i + 2).and_then(|b| digit(*b)),
            ) {
                (Some(h), Some(l)) => {
                    out.push(u8::try_from(h * 16 + l).unwrap_or(0));
                    i += 3;
                }
                _ => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b'+' if plus => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    Some(out)
}

/// Whether the model accepted `r`: a request to one of its two APIs, with
/// the run's token, answered 200 whole.
pub fn accepted(r: &Recorded) -> bool {
    r.status == 200 && r.answered && matches!(r.api.as_deref(), Some("messages" | "responses"))
}

/// Whether any accepted request's body holds `marker`, as it is or in a
/// decoded reading of the body ([`holds`]): the control reached the model.
pub fn reached(requests: &[Recorded], marker: &str) -> bool {
    let m = [Zeroizing::new(marker.as_bytes().to_vec())];
    requests.iter().any(|r| accepted(r) && holds(&r.body, &m))
}

/// Whether anything recorded holds any of `forms`, in any part of any
/// request, accepted or not, as it is or in a decoded reading of that
/// part ([`holds`]): its method, path, query, header names and values,
/// body and forwarded target (Codex review of M2-09: a value in a
/// request's path or query went uncounted; round 3: a value JSON escapes
/// in a body went uncounted).
pub fn seen(requests: &[Recorded], forms: &[Zeroizing<Vec<u8>>]) -> bool {
    requests.iter().any(|r| {
        holds(&r.body, forms)
            || holds(&r.forward, forms)
            || holds(r.method.as_bytes(), forms)
            || holds(r.path.as_bytes(), forms)
            || r.query.as_ref().is_some_and(|q| holds(q.as_bytes(), forms))
            || r.headers.iter().any(|h| holds(h.as_bytes(), forms))
            || r.values.iter().any(|v| holds(v, forms))
    })
}

/// The accepted request that the script answered with step `n`: the one
/// carrying step `n - 1`'s result.
pub fn picked(requests: &[Recorded], n: usize) -> Option<&Recorded> {
    let want = format!("step {n}");
    requests
        .iter()
        .find(|r| accepted(r) && r.pick.as_deref() == Some(want.as_str()))
}

/// The last tool result a request carries, as text: a Messages
/// `tool_result` (its string, or its text parts joined), or a Responses
/// `*_output` item's `output`. Empty when there is none.
pub fn last_tool_output(r: &Recorded) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::new());
    let Some(v) = r.json() else {
        return out;
    };
    let text = |c: &Value| -> String {
        match c {
            Value::String(s) => s.clone(),
            Value::Array(parts) => parts
                .iter()
                .filter_map(|p| p.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n"),
            Value::Object(o) => o
                .get("content")
                .map(|c| match c {
                    Value::Array(parts) => parts
                        .iter()
                        .filter_map(|p| p.get("text").and_then(Value::as_str))
                        .collect::<Vec<_>>()
                        .join("\n"),
                    Value::String(s) => s.clone(),
                    _ => String::new(),
                })
                .unwrap_or_default(),
            _ => String::new(),
        }
    };
    match r.api.as_deref() {
        Some(a) if a == Api::Messages.name() => {
            for m in v
                .get("messages")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                for c in m
                    .get("content")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    if c.get("type").and_then(Value::as_str) == Some("tool_result") {
                        *out = text(c.get("content").unwrap_or(&Value::Null));
                    }
                }
            }
        }
        Some(a) if a == Api::Responses.name() => {
            for item in v
                .get("input")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let output = item
                    .get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|t| t.ends_with("_output"));
                if output {
                    *out = text(item.get("output").unwrap_or(&Value::Null));
                }
            }
        }
        _ => {}
    }
    out
}

/// EnvCloak's fixed denial marker for `reason` (M2-08):
/// `[envcloak:<reason>]`.
pub fn denial(reason: crate::hook::Reason) -> String {
    format!("[envcloak:{}]", reason.name())
}

/// The refusal a host gives a call under one of EnvCloak's own host
/// rules, recognised by its fixed text: Claude Code's for a deny rule
/// (`Read(**/.env*)`), Codex's for a `forbidden` rule, which carries the
/// rule's justification, EnvCloak's own text ([`codex_rule_refused`]).
/// Names the source, or `None`.
pub fn rule_refusal(host: crate::hook::Host, result: &str) -> Option<&'static str> {
    use crate::hook::Host;
    match host {
        Host::ClaudeCode => result
            .contains("denied by your permission settings")
            .then_some("the host's own permission settings, under EnvCloak's deny rule"),
        Host::Codex => codex_rule_refused(result)
            .then_some("Codex's exec policy, under EnvCloak's forbidden rule"),
    }
}

/// Whether `result` is Codex's refusal of a command under one of the
/// `forbidden` rules EnvCloak writes: measured on the pinned 0.159.2 as
/// ``exec_command failed: CreateProcess { message: "Rejected(\"`<shell>
/// -lc '<command>'` rejected: <justification>\")" }``, the justification
/// one of [`crate::hosts::codex::RULES`]'.
pub fn codex_rule_refused(result: &str) -> bool {
    codex_justifications().any(|j| result.contains(&format!("` rejected: {j}")))
}

/// The justifications of the rules EnvCloak writes for Codex.
pub fn codex_justifications() -> impl Iterator<Item = &'static str> {
    crate::hosts::codex::RULES.lines().filter_map(|l| {
        l.trim()
            .strip_prefix("justification = \"")?
            .strip_suffix("\",")
    })
}

/// What answered a probe call when EnvCloak's marker for it is not in
/// the result the model got, named from a fixed list: the result itself
/// is never printed, since it could hold fixture data (M2-08's refusal
/// sources, Codex's cycle 321 review). The first text found names it.
pub fn unmarked(result: &str) -> &'static str {
    const SOURCES: [(&str, &str); 4] = [
        (
            "[envcloak:",
            "EnvCloak's hook denied it, with another reason",
        ),
        (
            "denied by your permission settings",
            "the host's own permission settings refused it first, without EnvCloak's marker",
        ),
        (
            "would block or produce infinite output",
            "the host's device-file check refused it first, without EnvCloak's marker",
        ),
        (
            "` rejected: ",
            "the host's exec policy refused it first, without EnvCloak's marker",
        ),
    ];
    if result.is_empty() {
        return "no result of the probe call reached the model";
    }
    SOURCES
        .iter()
        .find(|(text, _)| result.contains(text))
        .map_or(
            "a result without EnvCloak's marker, from no known source, reached the model",
            |(_, source)| source,
        )
}

/// Every form `value` is looked for in: as it is; base64 (standard and
/// URL-safe alphabets, with and without padding, and the groups wholly
/// inside it at the two other alignments in a longer stream);
/// hexadecimal (both cases); percent-encoded (every byte but RFC 3986's
/// unreserved ones, both cases); JSON `\u` escapes of every character
/// (both cases). Each form once.
pub fn forms(value: &[u8]) -> Vec<Zeroizing<Vec<u8>>> {
    let mut out: Vec<Zeroizing<Vec<u8>>> = Vec::new();
    let mut add = |f: Vec<u8>| {
        let f = Zeroizing::new(f);
        if !f.is_empty() && !out.iter().any(|o| **o == *f) {
            out.push(f);
        }
    };
    add(value.to_vec());
    for e in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        add(e.encode(value).into_bytes());
    }
    for skip in 1..3 {
        let body = value.get(skip..).unwrap_or_default();
        let whole = body.len() / 3 * 3;
        if whole >= 6 {
            for e in [&STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
                add(e.encode(&body[..whole]).into_bytes());
            }
        }
    }
    for upper in [false, true] {
        let digits: &[u8; 16] = if upper {
            b"0123456789ABCDEF"
        } else {
            b"0123456789abcdef"
        };
        add(value
            .iter()
            .flat_map(|b| [digits[usize::from(b >> 4)], digits[usize::from(b & 15)]])
            .collect());
        let mut pct = Vec::new();
        for &b in value {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                pct.push(b);
            } else {
                pct.extend([
                    b'%',
                    digits[usize::from(b >> 4)],
                    digits[usize::from(b & 15)],
                ]);
            }
        }
        add(pct);
        if let Ok(text) = std::str::from_utf8(value) {
            let mut esc = Vec::new();
            for unit in text.encode_utf16() {
                esc.extend(b"\\u");
                for shift in [12, 8, 4, 0] {
                    esc.push(digits[usize::from((unit >> shift) & 15)]);
                }
            }
            add(esc);
        }
    }
    out
}

/// What a sweep of a host's stores found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Swept {
    /// For each needle, in the order given, whether some file held it.
    pub found: Vec<bool>,
    /// For each needle, the files whose contents or names held it.
    pub holders: Vec<Vec<PathBuf>>,
    /// Every file was read whole: nothing unreadable, nothing past a cap,
    /// no link to what the sweep does not read.
    pub complete: bool,
    /// Files read.
    pub files: usize,
}

/// The most bytes of one file a sweep reads.
pub const SWEEP_FILE_CAP: u64 = 64 * 1024 * 1024;
/// The most bytes a sweep reads in all.
pub const SWEEP_TOTAL_CAP: u64 = 1024 * 1024 * 1024;
/// The most files a sweep reads.
pub const SWEEP_FILES_CAP: usize = 100_000;

/// Looks for each of `needles` (each a set of forms) in every regular
/// file under `roots` (a root may be a file; with a name filter, only the
/// entries directly in it whose names hold the filter), and in the name of
/// every entry met there (a store can name a file by what it holds),
/// never following a link. A root that is not there holds nothing.
///
/// A link is not read through, so it is told apart (Codex review of
/// M2-09: a store behind a link was skipped and the sweep still said it
/// read everything): one that leads within what the sweep reads (a root,
/// or an entry a filter takes) is covered there; one that leads nowhere
/// holds nothing; one that leads anywhere else, or cannot be followed,
/// makes the sweep incomplete. A socket or a pipe holds nothing at rest:
/// only its name is looked at.
pub fn sweep(roots: &[(PathBuf, Option<String>)], needles: &[&[Zeroizing<Vec<u8>>]]) -> Swept {
    let mut s = Swept {
        found: vec![false; needles.len()],
        holders: vec![Vec::new(); needles.len()],
        complete: true,
        files: 0,
    };
    let mut total = 0u64;
    let mut stack: Vec<PathBuf> = Vec::new();
    // What the walk reads, resolved: where a link may lead.
    let mut covered: Vec<PathBuf> = Vec::new();
    let cover = |p: &Path, covered: &mut Vec<PathBuf>| {
        if std::fs::symlink_metadata(p).is_ok_and(|m| !m.file_type().is_symlink()) {
            if let Ok(c) = std::fs::canonicalize(p) {
                covered.push(c);
            }
        }
    };
    for (root, names) in roots {
        match names {
            Some(part) => match std::fs::read_dir(root) {
                Ok(rd) => {
                    for e in rd {
                        match e {
                            Ok(e) if e.file_name().to_string_lossy().contains(part.as_str()) => {
                                cover(&e.path(), &mut covered);
                                stack.push(e.path());
                            }
                            Ok(_) => {}
                            Err(_) => s.complete = false,
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => s.complete = false,
            },
            None => {
                cover(root, &mut covered);
                stack.push(root.clone());
            }
        }
    }
    let hold = |s: &mut Swept, p: &Path, bytes: &[u8]| {
        for (i, hit) in holds_any(bytes, needles).into_iter().enumerate() {
            if hit {
                s.found[i] = true;
                if !s.holders[i].iter().any(|h| h == p) {
                    s.holders[i].push(p.to_path_buf());
                }
            }
        }
    };
    while let Some(p) = stack.pop() {
        let meta = match std::fs::symlink_metadata(&p) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                s.complete = false;
                continue;
            }
        };
        if let Some(name) = p.file_name() {
            use std::os::unix::ffi::OsStrExt as _;
            hold(&mut s, &p, name.as_bytes());
        }
        if meta.file_type().is_symlink() {
            match std::fs::canonicalize(&p) {
                Ok(to) if covered.iter().any(|c| to.starts_with(c)) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                _ => s.complete = false,
            }
            continue;
        }
        if meta.is_dir() {
            match std::fs::read_dir(&p) {
                Ok(rd) => {
                    for e in rd {
                        match e {
                            Ok(e) => stack.push(e.path()),
                            Err(_) => s.complete = false,
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => s.complete = false,
            }
            continue;
        }
        if !meta.is_file() {
            continue;
        }
        s.files += 1;
        if s.files > SWEEP_FILES_CAP
            || meta.len() > SWEEP_FILE_CAP
            || total.saturating_add(meta.len()) > SWEEP_TOTAL_CAP
        {
            s.complete = false;
            continue;
        }
        let Ok(bytes) = read_whole(&p) else {
            s.complete = false;
            continue;
        };
        total += bytes.len() as u64;
        hold(&mut s, &p, &bytes);
    }
    s
}

/// Watches what a host prints for fixed texts, as it comes, keeping
/// nothing of it but the last few bytes (a text cut across two reads is
/// still found): whether each text was printed.
#[derive(Debug)]
pub struct Watch {
    texts: Vec<&'static str>,
    found: Vec<bool>,
    tail: Zeroizing<Vec<u8>>,
}

impl Watch {
    pub fn new(texts: &[&'static str]) -> Watch {
        Watch {
            texts: texts.to_vec(),
            found: vec![false; texts.len()],
            tail: Zeroizing::new(Vec::new()),
        }
    }

    /// The next bytes printed.
    pub fn feed(&mut self, chunk: &[u8]) {
        let keep = self.texts.iter().map(|t| t.len()).max().unwrap_or(0);
        if keep == 0 {
            return;
        }
        let mut window = Zeroizing::new(Vec::with_capacity(self.tail.len() + chunk.len()));
        window.extend_from_slice(&self.tail);
        window.extend_from_slice(chunk);
        for (i, t) in self.texts.iter().enumerate() {
            if !self.found[i] && contains(&window, t.as_bytes()) {
                self.found[i] = true;
            }
        }
        let from = window.len().saturating_sub(keep - 1);
        self.tail = Zeroizing::new(window[from..].to_vec());
    }

    /// For each text, in the order given, whether it was printed.
    pub fn found(&self) -> Vec<bool> {
        self.found.clone()
    }
}

/// A random version-4 UUID, the session id the probe gives Claude Code
/// (`--session-id`).
///
/// # Errors
/// When the system has no random bytes to give.
pub fn session_uuid() -> std::io::Result<String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(std::io::Error::other)?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = crate::coverage::hex(&b);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    ))
}

/// Whether `s` is shaped as a UUID (8-4-4-4-12 hexadecimal digits).
pub fn uuid_shaped(s: &str) -> bool {
    let groups: Vec<&str> = s.split('-').collect();
    groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(g, n)| g.len() == n && g.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// A file read whole into a wiping buffer, without following a link at
/// its last component, within [`SWEEP_FILE_CAP`].
fn read_whole(p: &Path) -> std::io::Result<Zeroizing<Vec<u8>>> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p)?;
    let mut out = Zeroizing::new(Vec::new());
    f.take(SWEEP_FILE_CAP + 1).read_to_end(&mut out)?;
    if out.len() as u64 > SWEEP_FILE_CAP {
        return Err(std::io::ErrorKind::FileTooLarge.into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(status: u16, answered: bool, api: Option<&str>, body: &[u8]) -> Recorded {
        Recorded {
            seq: 1,
            at_ms: 0,
            method: "POST".to_owned(),
            path: "/v1/messages".to_owned(),
            query: None,
            headers: Vec::new(),
            values: Vec::new(),
            forward: Zeroizing::new(Vec::new()),
            status,
            answered,
            api: api.map(str::to_owned),
            pick: Some("step 0".to_owned()),
            body: Zeroizing::new(body.to_vec()),
        }
    }

    #[test]
    fn markers_are_not_key_shaped_and_tokens_are() {
        let m = marker("ctl").unwrap_or_default();
        assert!(m.starts_with("ecp-ctl-"));
        assert!(!crate::hook::prompt::holds_key(&format!("say {m}")), "{m}");
        let k = key_shaped().unwrap_or_default();
        assert!(crate::hook::prompt::holds_key(&format!(
            "use {}",
            k.as_str()
        )));
        let (a, b) = halves(&m);
        assert_eq!(format!("{a}{b}"), m);
        assert!(!a.contains(&m) && !b.contains(&m));
    }

    /// What refused a probe call is named, never shown: the Linux CI run
    /// measured Claude Code 2.1.280's permission settings refusing `Read
    /// .env` before EnvCloak's hook, which this names.
    ///
    /// Mutation checked: the permission settings' row dropped from the
    /// list: the refusal reads as from no known source and this fails.
    #[test]
    fn an_unmarked_result_is_named_from_a_fixed_list() {
        let fixture = "ecp-env-0000-1111-2222-3333";
        for (result, source) in [
            ("", "no result of the probe call reached the model"),
            (
                "Permission to read /p/.env has been denied by your permission settings.",
                "the host's own permission settings refused it first, without EnvCloak's marker",
            ),
            (
                "Reading this file would block or produce infinite output.",
                "the host's device-file check refused it first, without EnvCloak's marker",
            ),
            (
                "Refused: [envcloak:env_dump] (EnvCloak)",
                "EnvCloak's hook denied it, with another reason",
            ),
            (
                fixture,
                "a result without EnvCloak's marker, from no known source, reached the model",
            ),
        ] {
            let named = unmarked(result);
            assert_eq!(named, source, "{result}");
            assert!(!named.contains(fixture));
        }
    }

    /// Codex's refusal under EnvCloak's rules is recognised by the rules'
    /// own justifications, as the pinned Codex gives it, and nothing else
    /// is.
    #[test]
    fn codex_refusals_are_read_by_the_rules_justifications() {
        assert_eq!(codex_justifications().count(), 4);
        let measured = "exec_command failed: CreateProcess { message: \"Rejected(\\\"`/bin/zsh -lc \
                        'cat .env'` rejected: It reads a .env file, whose values would reach the \
                        model. Run the command that needs them as `envcloak run -- <command>`.\\\")\" }";
        assert!(codex_rule_refused(measured), "{measured}");
        for other in [
            "exec_command failed: rejected: something else",
            "Permission to read /p/.env has been denied by your permission settings.",
            "",
        ] {
            assert!(!codex_rule_refused(other), "{other}");
        }
    }

    /// The receiver corpus (Codex cycle354): only an accepted request
    /// counts as a control reaching the model.
    #[test]
    fn only_an_accepted_request_is_a_control() {
        let m = b"ecp-ctl-0000-1111-2222-3333";
        let ok = rec(200, true, Some("messages"), m);
        assert!(reached(
            std::slice::from_ref(&ok),
            "ecp-ctl-0000-1111-2222-3333"
        ));
        for bad in [
            rec(401, true, Some("messages"), m),
            rec(404, true, None, m),
            rec(400, true, Some("messages"), m),
            rec(200, false, Some("messages"), m),
            rec(403, true, Some("connect"), m),
        ] {
            assert!(!reached(&[bad], "ecp-ctl-0000-1111-2222-3333"));
        }
        assert!(!reached(&[], "ecp-ctl-0000-1111-2222-3333"));
    }

    #[test]
    fn a_value_is_seen_in_every_form_and_every_place() {
        let v = b"ecpk-value/with+chars=";
        let f = forms(v);
        for form in [
            STANDARD.encode(v).into_bytes(),
            URL_SAFE_NO_PAD.encode(v).into_bytes(),
            b"6563706b".to_vec(),
            b"%2F".to_vec(),
        ] {
            assert!(
                f.iter().any(|x| contains(x, &form)),
                "{}",
                String::from_utf8_lossy(&form)
            );
        }
        let mut r = rec(403, true, Some("connect"), b"");
        r.forward = Zeroizing::new(format!("https://x/{}", STANDARD.encode(v)).into_bytes());
        assert!(seen(&[r], &f));
        let mut r = rec(401, true, None, b"");
        r.values = vec![Zeroizing::new(hexify(v))];
        assert!(seen(&[r], &f));
        assert!(!seen(&[rec(200, true, Some("messages"), b"nothing")], &f));
    }

    /// A value is seen in every part of a request the model recorded, each
    /// part a positive control of its own: its path, its query, a header's
    /// name, its method (Codex review of M2-09: the path and query of a
    /// request to the model's own endpoint went uncounted).
    ///
    /// Mutation checked: `seen` without the path and query (`r.path`,
    /// `r.query` dropped): the first two cases are not seen and this
    /// fails.
    #[test]
    fn a_value_is_seen_in_every_part_of_a_request() {
        let v = b"ecpk0123456789abcdef0123456789abcdef";
        let f = forms(v);
        let text = String::from_utf8_lossy(v).into_owned();
        let b64 = URL_SAFE_NO_PAD.encode(v);
        type Put<'a> = Box<dyn Fn(&mut Recorded) + 'a>;
        let parts: [Put<'_>; 6] = [
            Box::new(|r| r.path = format!("/v1/messages/{text}")),
            Box::new(|r| r.query = Some(format!("k={b64}"))),
            Box::new(|r| r.headers = vec![format!("x-{text}")]),
            Box::new(|r| r.method = text.clone()),
            Box::new(|r| r.values = vec![Zeroizing::new(v.to_vec())]),
            Box::new(|r| r.body = Zeroizing::new(v.to_vec())),
        ];
        for (i, put) in parts.iter().enumerate() {
            let mut r = rec(200, true, Some("messages"), b"{}");
            assert!(!seen(std::slice::from_ref(&r), &f), "{i}: before");
            put(&mut r);
            assert!(seen(&[r], &f), "part {i}");
        }
    }

    fn hexify(v: &[u8]) -> Vec<u8> {
        v.iter()
            .flat_map(|b| format!("{b:02X}").into_bytes())
            .collect()
    }

    #[test]
    fn tool_results_are_read_from_both_apis() {
        let m = serde_json::json!({"messages": [
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": [{"type": "tool_use", "id": "a", "name": "Bash", "input": {}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "a",
              "content": [{"type": "text", "text": "out"}]}]},
        ]});
        let r = rec(200, true, Some("messages"), m.to_string().as_bytes());
        assert_eq!(last_tool_output(&r).as_str(), "out");
        let x = serde_json::json!({"input": [
            {"type": "function_call", "call_id": "c", "name": "exec_command", "arguments": "{}"},
            {"type": "function_call_output", "call_id": "c", "output": "printed"},
        ]});
        let r = rec(200, true, Some("responses"), x.to_string().as_bytes());
        assert_eq!(last_tool_output(&r).as_str(), "printed");
    }

    #[test]
    fn a_sweep_finds_and_says_when_it_could_not_read() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let a = dir.path().join("a");
        std::fs::create_dir_all(a.join("b")).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(a.join("b").join("t.jsonl"), b"x ecp-one y")
            .unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(a.join("h.backup1"), b"two").unwrap_or_else(|e| panic!("{e}"));
        std::os::unix::fs::symlink(a.join("b"), a.join("link")).unwrap_or_else(|e| panic!("{e}"));
        let one = forms(b"ecp-one");
        let two = forms(b"two");
        let three = forms(b"three");
        let s = sweep(
            &[(a.clone(), None), (dir.path().join("absent"), None)],
            &[&one, &two, &three],
        );
        assert_eq!(s.found, [true, true, false]);
        assert!(s.complete);
        let s = sweep(&[(a.clone(), Some(".backup".to_owned()))], &[&two, &one]);
        assert_eq!(s.found, [true, false]);
        // A store that names a file by what it holds: found by its name.
        let named = forms(b"ecp-named-0000-1111");
        assert!(!sweep(&[(a.clone(), None)], &[&named]).found[0]);
        std::fs::write(a.join("b").join("ecp-named-0000-1111.json"), b"{}")
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(sweep(&[(a.clone(), None)], &[&named]).found[0]);
        // A file it cannot read makes the sweep incomplete.
        let locked = a.join("b").join("locked");
        std::fs::write(&locked, b"x").unwrap_or_else(|e| panic!("{e}"));
        std::fs::set_permissions(&locked, std::os::unix::fs::PermissionsExt::from_mode(0o000))
            .unwrap_or_else(|e| panic!("{e}"));
        let s = sweep(&[(a, None)], &[&one]);
        let _ =
            std::fs::set_permissions(&locked, std::os::unix::fs::PermissionsExt::from_mode(0o600));
        assert!(!s.complete);
    }

    /// A link is never read through, so a store behind one is told apart
    /// (Codex review of M2-09: a linked store was skipped and the sweep
    /// still said it read everything): a link that leads within what the
    /// sweep reads is covered there, one that leads nowhere holds nothing,
    /// and one that leads anywhere else, a root or an entry, makes the
    /// sweep incomplete. A socket holds nothing at rest. The files holding
    /// each needle are named.
    ///
    /// Mutation checked: links skipped as before (`if
    /// meta.file_type().is_symlink()` arm dropped, the link falling to `!
    /// meta.is_file()`): the store behind a link outside reads complete
    /// and this fails.
    #[test]
    fn a_link_out_of_the_stores_makes_the_sweep_incomplete() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let root = dir.path().join("store");
        let outside = dir.path().join("outside");
        for d in [&root, &outside] {
            std::fs::create_dir_all(d).unwrap_or_else(|e| panic!("{e}"));
        }
        let ctl = forms(b"ecp-ctl-0000");
        let token = forms(b"ecpk-token-0000");
        std::fs::write(root.join("session.jsonl"), b"x ecp-ctl-0000 y")
            .unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(outside.join("kept.jsonl"), b"ecpk-token-0000")
            .unwrap_or_else(|e| panic!("{e}"));
        // The control: the regular store alone is read whole, the control
        // found in its one file.
        let s = sweep(&[(root.clone(), None)], &[&ctl, &token]);
        assert!(s.complete);
        assert_eq!(s.found, [true, false]);
        assert_eq!(s.holders[0], [root.join("session.jsonl")]);
        // A link within the store, and one to nothing: still whole.
        std::fs::create_dir_all(root.join("sub")).unwrap_or_else(|e| panic!("{e}"));
        std::os::unix::fs::symlink(root.join("sub"), root.join("latest"))
            .unwrap_or_else(|e| panic!("{e}"));
        std::os::unix::fs::symlink(root.join("gone"), root.join("dangling"))
            .unwrap_or_else(|e| panic!("{e}"));
        let _listener = std::os::unix::net::UnixListener::bind(root.join("sock"))
            .unwrap_or_else(|e| panic!("{e}"));
        let s = sweep(&[(root.clone(), None)], &[&ctl, &token]);
        assert!(s.complete, "{s:?}");
        // A link out of the stores, to where the token is kept: not read,
        // so not whole.
        std::os::unix::fs::symlink(outside.join("kept.jsonl"), root.join("linked.jsonl"))
            .unwrap_or_else(|e| panic!("{e}"));
        let s = sweep(&[(root.clone(), None)], &[&ctl, &token]);
        assert!(!s.complete, "{s:?}");
        assert_eq!(s.found, [true, false]);
        // A root that is a link out, beside a regular one holding the
        // control: not whole either.
        std::fs::remove_file(root.join("linked.jsonl")).unwrap_or_else(|e| panic!("{e}"));
        let linked_root = dir.path().join("linked-store");
        std::os::unix::fs::symlink(&outside, &linked_root).unwrap_or_else(|e| panic!("{e}"));
        let s = sweep(
            &[(root.clone(), None), (linked_root.clone(), None)],
            &[&ctl, &token],
        );
        assert!(!s.complete, "{s:?}");
        // The same through a filtered root's entry.
        let s = sweep(
            &[
                (root.clone(), None),
                (dir.path().to_path_buf(), Some("linked-".to_owned())),
            ],
            &[&ctl, &token],
        );
        assert!(!s.complete, "{s:?}");
        // A linked root whose target the sweep reads is covered.
        let inner = dir.path().join("inner-link");
        std::os::unix::fs::symlink(root.join("sub"), &inner).unwrap_or_else(|e| panic!("{e}"));
        let s = sweep(&[(root, None), (inner, None)], &[&ctl, &token]);
        assert!(s.complete, "{s:?}");
    }

    /// What a host prints is watched for fixed texts as it comes, a text
    /// cut across two reads found, and nothing else said.
    #[test]
    fn a_watched_text_is_found_across_reads() {
        let mut w = Watch::new(&["hook: UserPromptSubmit Blocked", "[envcloak:key_in_prompt]"]);
        w.feed(b"noise hook: UserPromptSub");
        w.feed(b"mit Blo");
        assert_eq!(w.found(), [false, false]);
        w.feed(b"cked\n");
        assert_eq!(w.found(), [true, false]);
        let mut w = Watch::new(&["[envcloak:key_in_prompt]"]);
        for b in b"x [envcloak:key_in_prompt] y" {
            w.feed(&[*b]);
        }
        assert_eq!(w.found(), [true]);
        let mut none = Watch::new(&[]);
        none.feed(b"anything");
        assert!(none.found().is_empty());
    }

    #[test]
    fn session_ids_are_uuids() {
        let id = session_uuid().unwrap_or_default();
        assert!(uuid_shaped(&id), "{id}");
        assert_eq!(&id[14..15], "4");
        assert!(uuid_shaped("01a10b22-4b5f-75c1-bae8-8ad8d35a305e"));
        for bad in [
            "",
            "01a10b22-4b5f-75c1-bae8-8ad8d35a305",
            "01a10b22x4b5f-75c1-bae8-8ad8d35a305e",
            "g1a10b22-4b5f-75c1-bae8-8ad8d35a305e",
        ] {
            assert!(!uuid_shaped(bad), "{bad}");
        }
    }
}
