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
//!   `\u` escapes), in any part of any request: its method, path and
//!   query, every header's name and value, its body, and a refused
//!   tunnel's forwarded target ([`seen`]).
//! - A tool's result is the last tool result in the request that came
//!   after the call ([`last_tool_output`]), the place a host puts what a
//!   command printed or a hook's denial.
//! - The host's stores are read by [`sweep`], which looks in every file's
//!   contents and every entry's name, and counts a needle found only
//!   within what it read whole: a file it could not read, or past its
//!   caps, makes the sweep incomplete, which no probe counts as clean
//!   (L-08).

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

/// Whether the model accepted `r`: a request to one of its two APIs, with
/// the run's token, answered 200 whole.
pub fn accepted(r: &Recorded) -> bool {
    r.status == 200 && r.answered && matches!(r.api.as_deref(), Some("messages" | "responses"))
}

/// Whether any accepted request's body holds `marker`: the control
/// reached the model.
pub fn reached(requests: &[Recorded], marker: &str) -> bool {
    requests
        .iter()
        .any(|r| accepted(r) && contains(&r.body, marker.as_bytes()))
}

/// Whether anything recorded holds any of `forms`, in any part of any
/// request, accepted or not: its method, path, query, header names and
/// values, body and forwarded target (Codex review of M2-09: a value in a
/// request's path or query went uncounted).
pub fn seen(requests: &[Recorded], forms: &[Zeroizing<Vec<u8>>]) -> bool {
    requests.iter().any(|r| {
        forms.iter().any(|f| {
            contains(&r.body, f)
                || contains(&r.forward, f)
                || contains(r.method.as_bytes(), f)
                || contains(r.path.as_bytes(), f)
                || r.query.as_ref().is_some_and(|q| contains(q.as_bytes(), f))
                || r.headers.iter().any(|h| contains(h.as_bytes(), f))
                || r.values.iter().any(|v| contains(v, f))
        })
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
    /// Every file was read whole: nothing unreadable, nothing past a cap.
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
/// files directly in it whose names hold the filter), and in the name of
/// every entry met there (a store can name a file by what it holds),
/// never following a link. A root that is not there holds nothing.
pub fn sweep(roots: &[(PathBuf, Option<String>)], needles: &[&[Zeroizing<Vec<u8>>]]) -> Swept {
    let mut s = Swept {
        found: vec![false; needles.len()],
        complete: true,
        files: 0,
    };
    let mut total = 0u64;
    let mut stack: Vec<PathBuf> = Vec::new();
    for (root, names) in roots {
        match names {
            Some(part) => match std::fs::read_dir(root) {
                Ok(rd) => {
                    for e in rd {
                        match e {
                            Ok(e) if e.file_name().to_string_lossy().contains(part.as_str()) => {
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
            None => stack.push(root.clone()),
        }
    }
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
            for (i, forms) in needles.iter().enumerate() {
                if !s.found[i] && forms.iter().any(|f| contains(name.as_bytes(), f)) {
                    s.found[i] = true;
                }
            }
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
        for (i, forms) in needles.iter().enumerate() {
            if !s.found[i] && forms.iter().any(|f| contains(&bytes, f)) {
                s.found[i] = true;
            }
        }
    }
    s
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
}
