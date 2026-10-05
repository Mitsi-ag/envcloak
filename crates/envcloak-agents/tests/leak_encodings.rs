//! The probes' leak check against what real serializers and URL encoders
//! write (Codex's round-3 review of M2-09: a value holding a quote or a
//! line break reaches the model JSON-escaped, `\"` and `\n`, which no
//! form of the value matched, so an output probe could pass with the
//! value in a tool result): every fixture `envcloak-redact`'s
//! `tests/fixtures/generate.sh` made with the real runtimes (Python,
//! Node, Go, .NET, Ruby), the encodings SPEC §6.1's redaction covers, is
//! loaded as bytes and first decoded to its value (a fixture that does not
//! decode fails, never tests nothing). Each is put where a host sends a
//! tool's result or a request's target: a request's body, as a JSON
//! string and as a string within a string (a tool's arguments); its query
//! and path; a store's line. The leak check must see it there
//! (`controls::seen`, `controls::sweep`); the same places holding the
//! value with its last character changed must not be seen (the positive
//! controls: the check does not see everything).
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use envcloak_agents::probe::controls::{forms, holds, reached, seen, sweep};
use envcloak_agents::probe::model::Recorded;
use zeroize::Zeroizing;

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../envcloak-redact/tests/fixtures")
}

fn value(file: &str) -> String {
    std::fs::read_to_string(fixtures_dir().join(file)).unwrap()
}

fn fixtures(kind: &str) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>)> = std::fs::read_dir(fixtures_dir().join(kind))
        .unwrap()
        .map(|e| {
            let p = e.unwrap().path();
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            (name, std::fs::read(&p).unwrap())
        })
        .collect();
    out.sort();
    assert!(out.len() >= 6, "{kind}: {} fixtures", out.len());
    out
}

fn request(path: &str, query: Option<&str>, body: &[u8]) -> Recorded {
    Recorded {
        seq: 1,
        at_ms: 0,
        method: "POST".to_owned(),
        path: path.to_owned(),
        query: query.map(str::to_owned),
        headers: Vec::new(),
        values: Vec::new(),
        forward: Zeroizing::new(Vec::new()),
        status: 200,
        answered: true,
        api: Some("messages".to_owned()),
        pick: Some("step 1".to_owned()),
        body: Zeroizing::new(body.to_vec()),
    }
}

/// `v` with its last character another: a value the fixtures do not hold.
fn near(v: &str) -> String {
    let mut s: String = v.chars().take(v.chars().count() - 1).collect();
    s.push('Q');
    s
}

/// A tool result holding `json` (a JSON string, as written), and a tool
/// call whose arguments are a JSON string holding it (escaped twice).
fn bodies(json: &[u8]) -> Vec<Vec<u8>> {
    let text = std::str::from_utf8(json).unwrap();
    let result = format!(
        "{{\"messages\":[{{\"role\":\"user\",\"content\":[{{\"type\":\"tool_result\",\
         \"tool_use_id\":\"a\",\"content\":{text}}}]}}]}}"
    );
    let args = serde_json::to_string(&format!("{{\"output\":{text}}}")).unwrap();
    let call = format!("{{\"input\":[{{\"type\":\"function_call\",\"arguments\":{args}}}]}}");
    vec![result.into_bytes(), call.into_bytes()]
}

/// Mutation checked: `seen` reading the wire bytes alone (each `holds(..)`
/// in `seen` replaced by a plain search of the forms): the escaped
/// fixtures go unseen and this fails.
#[test]
fn a_value_every_serializer_escapes_is_seen_in_a_request() {
    let v = value("value-json.txt");
    let found = forms(v.as_bytes());
    let other = forms(near(&v).as_bytes());
    for (name, json) in fixtures("json") {
        let decoded: String = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded, v, "{name} does not decode to the value");
        for (i, body) in bodies(&json).into_iter().enumerate() {
            let r = request("/v1/messages", None, &body);
            assert!(
                seen(std::slice::from_ref(&r), &found),
                "{name} ({i}): the value went unseen"
            );
            assert!(!seen(&[r], &other), "{name} ({i}): the control was seen");
        }
    }
}

/// Mutation checked: no percent-decoded reading (`each_view` without its
/// `percent` readings): the encoders that leave characters as they are, or
/// write a space as `+`, go unseen and this fails.
#[test]
fn a_value_every_url_encoder_writes_is_seen_in_a_request() {
    let v = value("value-url.txt");
    let found = forms(v.as_bytes());
    let other = forms(near(&v).as_bytes());
    for (name, enc) in fixtures("url") {
        let text = std::str::from_utf8(&enc).unwrap();
        for r in [
            request("/v1/messages", Some(&format!("k={text}")), b"{}"),
            request(&format!("/v1/messages/{text}"), None, b"{}"),
            request("/v1/messages", None, format!("q={text}").as_bytes()),
        ] {
            assert!(
                seen(std::slice::from_ref(&r), &found),
                "{name}: the value went unseen in {} {:?}",
                r.path,
                r.query
            );
            assert!(!seen(&[r], &other), "{name}: the control was seen");
        }
    }
}

/// A store's line holding an escaped value is found by the sweep, as a
/// request's body is by the leak check.
///
/// Mutation checked: the sweep reading the bytes alone (its `hold`
/// searching the forms without `holds_any`): the escaped line is not
/// found and this fails.
#[test]
fn a_value_every_serializer_escapes_is_found_in_a_store() {
    let dir = tempfile::Builder::new()
        .prefix("ecl")
        .tempdir_in("/tmp")
        .unwrap();
    let v = value("value-json.txt");
    let found = forms(v.as_bytes());
    let other = forms(near(&v).as_bytes());
    for (name, json) in fixtures("json") {
        let file = dir.path().join("session.jsonl");
        let mut line = b"{\"type\":\"user\",\"message\":".to_vec();
        line.extend_from_slice(&json);
        line.extend_from_slice(b"}\n");
        std::fs::write(&file, &line).unwrap();
        let s = sweep(&[(dir.path().to_path_buf(), None)], &[&found, &other]);
        assert!(s.complete, "{name}");
        assert_eq!(s.found, [true, false], "{name}");
    }
}

/// Hand-made readings a serializer can mix: some characters `\u`-escaped
/// in either case, `\/`, a surrogate pair, an escape that is none; a
/// control marker escaped this way still reaches the model, and a lone
/// backslash before a letter is not taken for an escape.
#[test]
fn mixed_escapes_are_read_as_a_decoder_reads_them() {
    let v = "ab/cd\"e\u{1F600}f\\g";
    let found = forms(v.as_bytes());
    for (name, wire) in [
        ("upper-case escapes", r#"ab\/cd"e😀f\\g"#),
        ("lower-case escapes", r#"ab/cd\"e😀f\\g"#),
        ("escaped twice", r#"ab\\/cd\\\"e\\ud83d\\ude00f\\\\g"#),
    ] {
        assert!(holds(wire.as_bytes(), &found), "{name}");
    }
    for (name, wire) in [
        ("a backslash kept", r#"ab/cd"e\x1F600f\g"#),
        ("half a pair", r#"ab/cd\"e\ud83df\\g"#),
    ] {
        assert!(!holds(wire.as_bytes(), &found), "{name}");
    }
    let marker = "ecp-ctl-0a1b-2c3d-4e5f-6a7b";
    let escaped: String = marker
        .chars()
        .map(|c| format!("\\u{:04X}", u32::from(c)))
        .collect();
    let r = request(
        "/v1/messages",
        None,
        format!("{{\"messages\":[{{\"role\":\"user\",\"content\":\"{escaped}\"}}]}}").as_bytes(),
    );
    assert!(reached(std::slice::from_ref(&r), marker));
    assert!(!reached(&[r], "ecp-ctl-0a1b-2c3d-4e5f-6a7c"));
}
