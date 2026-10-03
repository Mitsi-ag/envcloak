//! Hostile input for the scripted model's request handling (L-06): random
//! bytes, and real requests with random damage, through the same code a
//! connection runs (`serve_bytes`). Whatever comes in, the server answers
//! with whole responses of the statuses it knows, or nothing; never
//! panics; never records more than its caps; and never sends back a byte
//! the request held. The libFuzzer target over the same entry point
//! (`fuzz/`) is M2-25's: libfuzzer-sys's `fuzz_target!` expands to
//! `#[no_mangle]` functions, which the workspace's `unsafe_code` rule
//! forbids outside envcloak-sys.
#![allow(clippy::unwrap_used)]

use envcloak_agents::probe::model::{Handle, Limits, Script, Server, serve_bytes};
use proptest::prelude::*;
use serde_json::json;

/// In every request below, never in the script: a reply holding it echoed
/// the request.
const MARK: &[u8] = b"QZXJMARK";

fn server() -> Server {
    let script = json!({"steps": [{"say": "one", "shell": "echo one"},
                                  {"tool": "Read", "input": {"file_path": "/x"}},
                                  {"say": "done"}]});
    let limits = Limits {
        body: 2048,
        total: 8192,
        records: 6,
        meta: 4096,
        ..Limits::default()
    };
    Server::bind(
        Script::parse(script.to_string().as_bytes()).unwrap(),
        limits,
    )
    .unwrap()
}

/// Splits `out` into responses and checks each, then the run's caps.
fn check(out: &[u8], handle: &Handle) -> Result<(), TestCaseError> {
    let mut rest = out;
    while !rest.is_empty() {
        prop_assert!(rest.starts_with(b"HTTP/1.1 "), "not a response");
        let end = rest
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|i| i + 4);
        prop_assert!(end.is_some(), "a response head cut short");
        let end = end.unwrap_or(0);
        let head = std::str::from_utf8(&rest[..end]).unwrap_or("");
        let status: u16 = head.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0);
        prop_assert!(
            [200, 400, 401, 403, 404, 413, 431, 503].contains(&status),
            "status {status}"
        );
        let len: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("Content-Length: "))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(usize::MAX);
        prop_assert!(rest.len() >= end + len, "a response body cut short");
        let body = &rest[end..end + len];
        prop_assert!(!body.windows(MARK.len()).any(|w| w == MARK), "echoed");
        if status != 200 {
            let v: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
            let msg = v["error"]["message"].as_str().unwrap_or("");
            prop_assert!(msg.starts_with("envcloak-probe-model: "), "{msg}");
        }
        rest = &rest[end + len..];
    }
    let outcome = handle.outcome();
    prop_assert!(outcome.recorded_bytes <= 8192, "recorded past the cap");
    prop_assert!(outcome.recorded_meta <= 4096, "metadata past its cap");
    prop_assert!(handle.requests().len() <= 6, "records past their cap");
    Ok(())
}

fn valid(token: &str, body: &[u8], path: &str) -> Vec<u8> {
    let mut r = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nx-api-key: {token}\r\nX-Note: QZXJMARK\r\n\
         Content-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    r.extend_from_slice(body);
    r
}

fn body(api: bool) -> Vec<u8> {
    if api {
        json!({"stream": true, "tools": [{"name": "Bash"}],
               "messages": [{"role": "user", "content": "QZXJMARK"}]})
    } else {
        json!({"stream": true, "tools": [{"name": "exec_command"}],
               "input": [{"type": "message", "content": "QZXJMARK"}]})
    }
    .to_string()
    .into_bytes()
}

#[derive(Debug, Clone)]
enum Damage {
    Flip(usize, u8),
    Insert(usize, Vec<u8>),
    Remove(usize, usize),
    Truncate(usize),
}

fn damage() -> impl Strategy<Value = Damage> {
    prop_oneof![
        (any::<usize>(), any::<u8>()).prop_map(|(i, b)| Damage::Flip(i, b)),
        (
            any::<usize>(),
            proptest::collection::vec(any::<u8>(), 1..64)
        )
            .prop_map(|(i, v)| Damage::Insert(i, v)),
        (any::<usize>(), 1usize..32).prop_map(|(i, n)| Damage::Remove(i, n)),
        any::<usize>().prop_map(Damage::Truncate),
    ]
}

fn apply(mut v: Vec<u8>, d: &[Damage]) -> Vec<u8> {
    for d in d {
        let at = |i: usize, v: &Vec<u8>| if v.is_empty() { 0 } else { i % v.len() };
        match d {
            Damage::Flip(i, b) => {
                let i = at(*i, &v);
                if let Some(x) = v.get_mut(i) {
                    *x ^= b | 1;
                }
            }
            Damage::Insert(i, bytes) => {
                let i = at(*i, &v);
                v.splice(i..i, bytes.iter().copied());
            }
            Damage::Remove(i, n) => {
                let i = at(*i, &v);
                let end = (i + n).min(v.len());
                v.drain(i..end);
            }
            Damage::Truncate(i) => {
                let i = at(*i, &v);
                v.truncate(i);
            }
        }
    }
    v
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 600, ..ProptestConfig::default() })]

    #[test]
    fn random_bytes(input in proptest::collection::vec(any::<u8>(), 0..3000)) {
        let s = server();
        let handle = s.handle();
        let mut input = input;
        input.extend_from_slice(MARK);
        let out = serve_bytes(&handle, &input);
        check(&out, &handle)?;
    }

    #[test]
    fn damaged_requests(
        api in any::<bool>(),
        twice in any::<bool>(),
        damage in proptest::collection::vec(damage(), 0..4),
    ) {
        let s = server();
        let handle = s.handle();
        let token = s.api_key().as_str().to_owned();
        let path = if api { "/v1/messages" } else { "/v1/responses" };
        let mut input = valid(&token, &body(api), path);
        if twice {
            input.extend(valid(&token, &body(api), path));
        }
        let input = apply(input, &damage);
        let out = serve_bytes(&handle, &input);
        check(&out, &handle)?;
        if damage.is_empty() {
            let report = handle.requests();
            prop_assert_eq!(report.len(), if twice { 2 } else { 1 });
            prop_assert!(handle.outcome().clean());
        }
    }
}

#[test]
fn oversized_and_capped_input_through_the_same_path() {
    let s = server();
    let handle = s.handle();
    let token = s.api_key().as_str().to_owned();
    let big = vec![b'a'; 4096];
    let out = serve_bytes(&handle, &valid(&token, &big, "/v1/messages"));
    assert!(out.starts_with(b"HTTP/1.1 413 "));
    assert_eq!(handle.outcome().incomplete, ["body_cap"]);
    assert!(handle.requests().is_empty());
    let one = vec![b' '; 2000];
    let mut many = Vec::new();
    for _ in 0..5 {
        many.extend(valid(&token, &one, "/v1/other"));
    }
    let out = serve_bytes(&handle, &many);
    check(&out, &handle).unwrap();
    assert!(
        handle
            .outcome()
            .incomplete
            .contains(&"total_cap".to_owned())
    );
    assert_eq!(handle.requests().len(), 4);
}
