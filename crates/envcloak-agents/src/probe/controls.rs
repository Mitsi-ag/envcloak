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
//!   `\u` escapes), whatever its path: a refused tunnel's forwarded
//!   target and every header value are read as well as the bodies
//!   ([`seen`]).
//! - A tool's result is the last tool result in the request that came
//!   after the call ([`last_tool_output`]), the place a host puts what a
//!   command printed or a hook's denial.
//! - The host's stores are read by [`sweep`], which counts a needle found
//!   only within what it read whole: a file it could not read, or past its
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

/// Whether anything recorded holds any of `forms`: a body, a header value
/// or a forwarded target, of any request, accepted or not.
pub fn seen(requests: &[Recorded], forms: &[Zeroizing<Vec<u8>>]) -> bool {
    requests.iter().any(|r| {
        forms.iter().any(|f| {
            contains(&r.body, f)
                || contains(&r.forward, f)
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
/// files directly in it whose names hold the filter), never following a
/// link. A root that is not there holds nothing.
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
