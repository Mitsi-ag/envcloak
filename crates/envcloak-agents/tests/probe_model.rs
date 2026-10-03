//! `envcloak-probe-model` end to end (M2 plan task M2-04): the program as
//! it ships, started by `ModelStub` over its pipes, spoken to over
//! loopback with a hand-written HTTP/1.1 client. The real hosts drive it
//! in crates/envcloak-e2e/tests/agent_hosts.rs; this file holds the
//! refusals and caps.
#![allow(clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use envcloak_agents::probe::model::{
    Limits, ModelStub, RECORD_OVERHEAD, Report, SERVER, Script, Server, admit_as, serve_bytes,
};
use serde_json::{Value, json};

const EXE: &str = env!("CARGO_BIN_EXE_envcloak-probe-model");
const MIB: usize = 1024 * 1024;

fn script() -> Vec<u8> {
    json!({"steps": [{"say": "one", "shell": "echo one"}, {"say": "done"}]})
        .to_string()
        .into_bytes()
}

fn start() -> ModelStub {
    ModelStub::start(Path::new(EXE), &script(), Duration::from_secs(120)).unwrap()
}

/// A response: status, header lines and body.
struct Got {
    status: u16,
    head: String,
    body: Vec<u8>,
}

/// Sends `request` on a new connection and reads one response, or `None`
/// when the server closes without answering.
fn send(addr: SocketAddr, request: &[u8]) -> Option<Got> {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    // The server may close before reading all of an oversized request.
    let _ = s.write_all(request);
    read_response(&mut s)
}

fn read_response(s: &mut TcpStream) -> Option<Got> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 65536];
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8(buf[..end].to_vec()).unwrap();
    let status: u16 = head[9..12].parse().unwrap();
    let len: usize = head
        .lines()
        .find_map(|l| l.strip_prefix("Content-Length: "))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let mut body = buf[end..].to_vec();
    while body.len() < len {
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }
    Some(Got { status, head, body })
}

fn post(path: &str, auth: &str, body: &[u8]) -> Vec<u8> {
    let mut r = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{auth}Content-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    r.extend_from_slice(body);
    r
}

fn key(stub: &ModelStub) -> String {
    format!("x-api-key: {}\r\n", stub.api_key().as_str())
}

fn bearer(stub: &ModelStub) -> String {
    format!("Authorization: Bearer {}\r\n", stub.api_key().as_str())
}

fn messages_body(marker: &str) -> Vec<u8> {
    json!({"model": "m", "stream": true, "max_tokens": 10,
           "tools": [{"name": "Bash"}],
           "messages": [{"role": "user", "content": marker}]})
    .to_string()
    .into_bytes()
}

fn responses_body(marker: &str) -> Vec<u8> {
    json!({"model": "m", "stream": true, "tools": [{"type": "function", "name": "exec_command"}],
           "input": [{"type": "message", "role": "user", "content": marker}]})
    .to_string()
    .into_bytes()
}

#[test]
fn both_apis_are_served_from_the_script_and_every_request_is_recorded() {
    let mut stub = start();
    let a = send(
        stub.addr(),
        &post(
            "/v1/messages?beta=true",
            &key(&stub),
            &messages_body("MARK-A"),
        ),
    )
    .unwrap();
    assert_eq!(a.status, 200);
    assert!(
        a.head.contains("Content-Type: text/event-stream"),
        "{}",
        a.head
    );
    assert!(a.head.contains(&format!("Server: {SERVER}")), "{}", a.head);
    let text = String::from_utf8(a.body).unwrap();
    assert!(text.starts_with("event: message_start\n"), "{text}");
    assert!(text.contains("\"name\":\"Bash\""), "{text}");
    let b = send(
        stub.addr(),
        &post("/v1/responses", &bearer(&stub), &responses_body("MARK-B")),
    )
    .unwrap();
    assert_eq!(b.status, 200);
    let text = String::from_utf8(b.body).unwrap();
    assert!(text.contains("event: response.completed\n"), "{text}");
    assert!(text.contains("exec_command"), "{text}");

    // A snapshot, then the end of the run.
    let snap = stub.requests().unwrap();
    assert!(!snap.last);
    assert_eq!(snap.requests.len(), 2);
    let report = stub.finish().unwrap();
    assert!(report.last);
    assert!(report.outcome.clean(), "{:?}", report.outcome);
    let r = &report.requests;
    assert_eq!(r.len(), 2);
    assert_eq!(
        (r[0].path.as_str(), r[0].query.as_deref()),
        ("/v1/messages", Some("beta=true"))
    );
    assert_eq!(r[0].api.as_deref(), Some("messages"));
    assert_eq!(r[0].pick.as_deref(), Some("step 0"));
    assert_eq!(r[0].json().unwrap()["messages"][0]["content"], "MARK-A");
    assert_eq!(r[1].api.as_deref(), Some("responses"));
    assert_eq!(r[1].json().unwrap()["input"][0]["content"], "MARK-B");
    // Header names only, never their values.
    assert!(r[0].headers.contains(&"x-api-key".to_owned()));
    let shown = format!("{report:?}");
    assert!(!shown.contains("MARK-A"), "{shown}");
}

#[test]
fn an_unknown_endpoint_is_answered_404_and_fails_the_run_loudly() {
    let stub = start();
    let got = send(
        stub.addr(),
        &post("/v1/messages/count_tokens", &key(&stub), b"{\"x\":1}"),
    )
    .unwrap();
    assert_eq!(got.status, 404);
    let get = format!("GET /v1/models HTTP/1.1\r\nHost: x\r\n{}\r\n", key(&stub));
    assert_eq!(send(stub.addr(), get.as_bytes()).unwrap().status, 404);
    let report = stub.finish().unwrap();
    assert_eq!(report.outcome.unknown, 2);
    assert!(report.outcome.complete() && !report.outcome.clean());
    let paths: Vec<&str> = report.requests.iter().map(|r| r.path.as_str()).collect();
    assert_eq!(paths, ["/v1/messages/count_tokens", "/v1/models"]);
    assert_eq!(&*report.requests[0].body, b"{\"x\":1}");
}

#[test]
fn a_wrong_or_missing_token_is_refused_and_its_body_never_read() {
    let stub = start();
    let wrong = "x-api-key: ecp_0000000000000000000000000000000000000000\r\n";
    let body = messages_body("MARK-REFUSED");
    for auth in [wrong, "", "Authorization: Bearer nope\r\n"] {
        let got = send(stub.addr(), &post("/v1/messages", auth, &body)).unwrap();
        assert_eq!(got.status, 401, "{auth:?}");
        assert!(!String::from_utf8_lossy(&got.body).contains("MARK"));
    }
    // The right token in one header and a wrong one in the other.
    let mixed = format!("{}Authorization: Bearer nope\r\n", key(&stub));
    assert_eq!(
        send(stub.addr(), &post("/v1/messages", &mixed, &body))
            .unwrap()
            .status,
        401
    );
    let report = stub.finish().unwrap();
    assert_eq!(report.outcome.bad_token, 4);
    assert!(
        report
            .requests
            .iter()
            .all(|r| r.status == 401 && r.body.is_empty())
    );
    assert_eq!(report.outcome.recorded_bytes, 0);
}

#[test]
fn claude_codes_connectivity_check_is_answered_without_a_token() {
    let stub = start();
    let got = send(stub.addr(), b"HEAD /api/hello HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    assert_eq!(got.status, 200);
    // Only that one: another HEAD needs the token.
    let other = send(stub.addr(), b"HEAD /api/other HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    assert_eq!(other.status, 401);
    let report = stub.finish().unwrap();
    assert_eq!(report.requests[0].api.as_deref(), Some("hello"));
    assert_eq!(report.outcome.bad_token, 1);
}

#[test]
fn a_connection_from_a_non_loopback_address_is_closed_unanswered() {
    let server = Server::bind(Script::parse(&script()).unwrap(), Limits::default()).unwrap();
    let handle = server.handle();
    let token = server.api_key().as_str().to_owned();
    // A real socket, handed to the server's accept path as if its peer
    // were a documentation address (RFC 5737).
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    // Before the server can close it: macOS refuses socket options on a
    // connection its peer has reset.
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let (accepted, _) = listener.accept().unwrap();
    admit_as(&handle, accepted, "192.0.2.7:4000".parse().unwrap());
    let req = post(
        "/v1/messages",
        &format!("x-api-key: {token}\r\n"),
        &messages_body("x"),
    );
    let _ = client.write_all(&req);
    let mut got = Vec::new();
    let _ = client.read_to_end(&mut got);
    assert!(got.is_empty(), "the server answered a non-loopback peer");
    assert_eq!(handle.outcome().bad_peer, 1);
    assert!(handle.requests().is_empty());

    // The same path with a loopback peer is served.
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (accepted, peer) = listener.accept().unwrap();
    admit_as(&handle, accepted, peer);
    client.write_all(&req).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    assert_eq!(read_response(&mut client).unwrap().status, 200);
    handle.stop();
}

#[test]
fn a_body_over_the_cap_is_refused_unread_and_the_run_is_incomplete() {
    let stub = start();
    // Exactly the cap is accepted and recorded whole.
    let mut at_cap = br#"{"tools":[],"messages":[],"pad":""#.to_vec();
    at_cap.resize(4 * MIB - 2, b'a');
    at_cap.extend_from_slice(b"\"}");
    assert_eq!(at_cap.len(), 4 * MIB);
    let got = send(stub.addr(), &post("/v1/messages", &key(&stub), &at_cap)).unwrap();
    assert_eq!(got.status, 200);
    // One byte more is refused before it is read.
    let mut over = at_cap.clone();
    over.insert(over.len() - 2, b'a');
    let got = send(stub.addr(), &post("/v1/messages", &key(&stub), &over)).unwrap();
    assert_eq!(got.status, 413);
    assert!(!got.body.windows(4).any(|w| w == b"aaaa"));
    let report = stub.finish().unwrap();
    assert_eq!(report.outcome.incomplete, ["body_cap"]);
    assert_eq!(report.requests.len(), 1);
    assert_eq!(report.requests[0].body.len(), 4 * MIB);
    assert_eq!(report.outcome.recorded_bytes, 4 * MIB as u64);
}

#[test]
fn the_run_records_at_most_16_mib_then_refuses_and_is_incomplete() {
    let stub = start();
    let mut body = br#"{"tools":[],"messages":[],"pad":""#.to_vec();
    body.resize(4 * MIB - 2, b'b');
    body.extend_from_slice(b"\"}");
    for _ in 0..4 {
        let got = send(stub.addr(), &post("/v1/messages", &key(&stub), &body)).unwrap();
        assert_eq!(got.status, 200);
    }
    let got = send(stub.addr(), &post("/v1/messages", &key(&stub), b"{}")).unwrap();
    assert_eq!(got.status, 503);
    let report = stub.finish().unwrap();
    assert_eq!(report.outcome.incomplete, ["total_cap"]);
    assert_eq!(report.requests.len(), 4);
    assert_eq!(report.outcome.recorded_bytes, 16 * MIB as u64);
}

/// Every path that records a request counts it: Claude Code's
/// connectivity check (no token, no body), a refused token and a tunnel
/// request all stop being recorded at the record cap, are answered 503
/// after it, and leave the run incomplete. The program as it ships, with
/// its default cap of 1,024, pipelined on one connection.
#[test]
fn requests_without_a_body_are_recorded_up_to_the_record_cap_then_refused() {
    assert_eq!(Limits::default().records, 1024);
    assert_eq!(Limits::default().meta, MIB);
    let stub = start();
    let mut s = TcpStream::connect(stub.addr()).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let hello = b"HEAD /api/hello HTTP/1.1\r\nHost: x\r\n\r\n";
    let mut w = s.try_clone().unwrap();
    let writer = std::thread::spawn(move || {
        for _ in 0..1025 {
            if w.write_all(hello).is_err() {
                break;
            }
        }
    });
    // Pipelined responses arrive several to a read: split them here.
    let mut statuses = Vec::new();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 65536];
    'read: loop {
        while let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8(buf[..end + 4].to_vec()).unwrap();
            let len: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("Content-Length: "))
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            // HEAD responses carry no body; the 503 carries its own.
            let body = if head.starts_with("HTTP/1.1 200 ") {
                0
            } else {
                len
            };
            if buf.len() < end + 4 + body {
                break;
            }
            let status: u16 = head[9..12].parse().unwrap();
            statuses.push(status);
            buf.drain(..end + 4 + body);
            if status != 200 {
                break 'read;
            }
        }
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    writer.join().unwrap();
    assert_eq!(statuses.len(), 1025, "{statuses:?}");
    assert!(statuses[..1024].iter().all(|&st| st == 200));
    assert_eq!(statuses[1024], 503);
    // After the cap, a refused token and a tunnel are not recorded either.
    let wrong = "x-api-key: ecp_0000000000000000000000000000000000000000\r\n";
    let got = send(stub.addr(), &post("/v1/messages", wrong, b"{}")).unwrap();
    assert_eq!(got.status, 503);
    let got = send(
        stub.addr(),
        b"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n",
    )
    .unwrap();
    assert_eq!(got.status, 503);
    let report = stub.finish().unwrap();
    assert_eq!(report.requests.len(), 1024);
    assert_eq!(report.outcome.incomplete, ["record_cap"]);
    assert_eq!(report.outcome.bad_token, 1);
    assert_eq!(report.outcome.connect, 1);
    assert_eq!(report.outcome.recorded_bytes, 0);
    let meta: u64 = report.requests.iter().map(|r| r.meta_len() as u64).sum();
    assert_eq!(report.outcome.recorded_meta, meta);
}

/// The same caps on each recording path on its own, with small limits:
/// the record count, then the metadata a request's target and header
/// names add, which a request with no body at all still counts.
#[test]
fn each_recording_path_stops_at_the_record_and_metadata_caps() {
    let script = Script::parse(&script()).unwrap();
    let hello = b"HEAD /api/hello HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
    let wrong = post(
        "/v1/messages",
        "x-api-key: ecp_0000000000000000000000000000000000000000\r\n",
        b"{}",
    );
    let tunnel = b"CONNECT a.example:443 HTTP/1.1\r\nHost: a.example:443\r\n\r\n".to_vec();
    for (name, request) in [
        ("hello", &hello),
        ("bad token", &wrong),
        ("tunnel", &tunnel),
    ] {
        let limits = Limits {
            records: 8,
            ..Limits::default()
        };
        let server = Server::bind(script.clone(), limits).unwrap();
        let handle = server.handle();
        let mut refused = 0;
        for _ in 0..20 {
            let out = serve_bytes(&handle, request);
            if out.starts_with(b"HTTP/1.1 503 ") {
                refused += 1;
            }
        }
        assert_eq!(handle.requests().len(), 8, "{name}");
        assert_eq!(refused, 12, "{name}");
        assert_eq!(handle.outcome().incomplete, ["record_cap"], "{name}");
    }
    // Long targets, no body: the metadata cap ends it first.
    let limits = Limits {
        meta: 4 * 1024,
        ..Limits::default()
    };
    let server = Server::bind(script, limits).unwrap();
    let handle = server.handle();
    let long = format!("GET /{} HTTP/1.1\r\nHost: x\r\n\r\n", "p".repeat(1500));
    for _ in 0..20 {
        let _ = serve_bytes(&handle, long.as_bytes());
    }
    let outcome = handle.outcome();
    assert!(outcome.recorded_meta <= 4 * 1024, "{outcome:?}");
    assert!(outcome.recorded_meta >= 2 * (1500 + RECORD_OVERHEAD) as u64);
    assert_eq!(handle.requests().len(), 2);
    assert_eq!(outcome.incomplete, ["record_cap"]);
}

#[test]
fn malformed_requests_get_a_fixed_error_that_echoes_nothing() {
    let stub = start();
    let k = key(&stub);
    let cases: Vec<Vec<u8>> = vec![
        b"POST /v1/messages HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nMARK: 1\r\n\r\n0\r\n\r\n".to_vec(),
        b"GARBAGE-MARK\r\n\r\n".to_vec(),
        b"POST /v1/MARK HTTP/1.0\r\nHost: x\r\n\r\n".to_vec(),
        format!("POST /v1/messages HTTP/1.1\r\nHost: x\r\n{k}X-Mark: \u{e9}\r\n\r\n").into_bytes(),
        format!("POST /v1/messages HTTP/1.1\r\nHost: x\r\n{k}Content-Length: 1\r\nContent-Length: 1\r\n\r\nM").into_bytes(),
        [b"GET /".as_slice(), &vec![b'M'; 70 * 1024], b" HTTP/1.1\r\n\r\n"].concat(),
        // Well-formed HTTP whose body is not its API's JSON.
        post("/v1/messages", &k, b"MARK not json"),
        post("/v1/responses", &k, br#"{"input": 3, "mark": "MARK"}"#),
    ];
    for case in &cases {
        let got = send(stub.addr(), case).unwrap();
        assert!(matches!(got.status, 400 | 431), "{}", got.status);
        let body = String::from_utf8(got.body).unwrap();
        assert!(!body.contains("MARK") && !body.contains("Mark"), "{body}");
        assert!(body.contains("envcloak-probe-model: "), "{body}");
    }
    let report = stub.finish().unwrap();
    assert_eq!(report.outcome.malformed, cases.len() as u64);
    // Only the two well-formed requests were read, and they are recorded.
    assert_eq!(report.requests.len(), 2);
}

#[test]
fn the_time_limit_ends_the_run_incomplete_on_its_own() {
    let mut child = Command::new(EXE)
        .args(["--time-limit", "1"])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(&script()).unwrap();
    stdin.write_all(b"\n").unwrap();
    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    let status = child.wait().unwrap();
    drop(stdin);
    assert_eq!(status.code(), Some(3));
    let last: Report = serde_json::from_str(out.lines().last().unwrap()).unwrap();
    assert!(last.last);
    assert_eq!(last.outcome.incomplete, ["time_limit"]);
}

#[test]
fn the_end_of_input_ends_the_run() {
    let mut child = Command::new(EXE)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(&script()).unwrap();
    stdin.write_all(b"\n").unwrap();
    drop(stdin);
    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    assert_eq!(child.wait().unwrap().code(), Some(0));
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 2, "{out}");
    let ready: Value = serde_json::from_str(lines[0]).unwrap();
    assert!(ready["addr"].as_str().unwrap().starts_with("127.0.0.1:"));
    let last: Report = serde_json::from_str(lines[1]).unwrap();
    assert!(last.last && last.outcome.clean());
}

#[test]
fn a_bad_script_or_argument_is_refused_without_echo() {
    for (args, input) in [
        (
            vec![],
            b"{\"steps\":[{\"say\":\"MARK\",\"bogus\":1}]}\n".to_vec(),
        ),
        (vec![], b"not json MARK\n".to_vec()),
        (vec![], b"{\"steps\":[{\"say\":\"MARK\"}]}".to_vec()),
        (
            vec!["--time-limit", "0"],
            b"{\"steps\":[{\"say\":\"x\"}]}\n".to_vec(),
        ),
        (vec!["--MARK"], Vec::new()),
    ] {
        let mut child = Command::new(EXE)
            .args(&args)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let _ = stdin.write_all(&input);
        drop(stdin);
        let out = child.wait_with_output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(out.stdout.is_empty());
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!err.contains("MARK"), "{err}");
    }
}

#[test]
fn a_proxy_tunnel_request_is_refused_and_recorded_by_its_target() {
    let stub = start();
    let got = send(
        stub.addr(),
        b"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n",
    )
    .unwrap();
    assert_eq!(got.status, 403);
    let report = stub.finish().unwrap();
    assert_eq!(report.outcome.connect, 1);
    assert!(report.outcome.clean());
    let r = &report.requests[0];
    assert_eq!(
        (r.method.as_str(), r.path.as_str()),
        ("CONNECT", "api.example.com:443")
    );
    assert_eq!(r.api.as_deref(), Some("connect"));
}

/// A tunnel in HTTP/1.0 with no `Host`, and a request to forward (an
/// absolute target), each refused and recorded by where it goes: what a
/// client of the proxy the harness names sends, whatever its HTTP version
/// (verifier, low: these were refused as malformed and never recorded, so
/// a test that no request reached the proxy could not fail).
#[test]
fn every_request_meant_for_a_proxy_is_refused_and_recorded() {
    let stub = start();
    for request in [
        &b"CONNECT a.example:443 HTTP/1.0\r\n\r\n"[..],
        b"GET http://b.example/MARK?MARK HTTP/1.1\r\nHost: b.example\r\n\r\n",
        b"GET http://c.example:8080/ HTTP/1.0\r\n\r\n",
    ] {
        assert_eq!(send(stub.addr(), request).unwrap().status, 403);
    }
    let report = stub.finish().unwrap();
    assert!(report.outcome.clean(), "{:?}", report.outcome);
    assert_eq!(report.outcome.connect, 3);
    let seen: Vec<(&str, &str, &str)> = report
        .requests
        .iter()
        .map(|r| {
            (
                r.api.as_deref().unwrap_or(""),
                r.method.as_str(),
                r.path.as_str(),
            )
        })
        .collect();
    assert_eq!(
        seen,
        [
            ("connect", "CONNECT", "a.example:443"),
            ("proxy", "GET", "b.example:80"),
            ("proxy", "GET", "c.example:8080"),
        ]
    );
    assert!(
        report
            .requests
            .iter()
            .all(|r| r.query.is_none() && r.answered)
    );
    let forwards: Vec<&[u8]> = report.requests.iter().map(|r| &r.forward[..]).collect();
    assert_eq!(
        forwards,
        [
            &b""[..],
            b"http://b.example/MARK?MARK",
            b"http://c.example:8080/"
        ]
    );
}

/// A request to forward is recorded whole: its target as sent (path and
/// query included), its header values and its body, which is read (up to
/// the body cap) and counted like any other (Codex review, medium: the
/// path, query and body of a refused proxy request were dropped, so a
/// value there was never swept). The run stays clean: a refusal is what
/// the stub does with every request meant for a proxy.
#[test]
fn a_request_to_forward_is_recorded_whole_with_its_header_values_and_body() {
    let stub = start();
    let body = b"MARK-BODY-1";
    let mut request = format!(
        "POST http://b.example/MARK-P?MARK-Q HTTP/1.1\r\nHost: b.example\r\n\
         X-Leak: MARK-H\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);
    let got = send(stub.addr(), &request).unwrap();
    assert_eq!(got.status, 403);
    assert!(!String::from_utf8_lossy(&got.body).contains("MARK"));
    let report = stub.finish().unwrap();
    assert!(report.outcome.clean(), "{:?}", report.outcome);
    assert_eq!(report.outcome.recorded_bytes, body.len() as u64);
    let r = &report.requests[0];
    assert_eq!(r.api.as_deref(), Some("proxy"));
    assert_eq!(r.path, "b.example:80");
    assert_eq!(&r.forward[..], b"http://b.example/MARK-P?MARK-Q");
    assert_eq!(&r.body[..], body);
    let values: Vec<&[u8]> = r.values.iter().map(|v| &v[..]).collect();
    assert_eq!(values, [&b"b.example"[..], b"MARK-H", b"11"]);
    assert_eq!(r.headers, ["Host", "X-Leak", "Content-Length"]);
    // Debug shows none of it.
    let shown = format!("{r:?}");
    assert!(!shown.contains("MARK"), "{shown}");
}

/// Every header's value is recorded, in order (Codex review, medium: a
/// value in a request's header was discarded): a header a host made up,
/// on a request the script served, and the credentials of a refused
/// token as they were sent. A credential that presents the run's token
/// is recorded as `<token>`, so the token is in no record; the token
/// itself is checked against what was sent, never the record.
#[test]
fn header_values_are_recorded_and_the_run_s_token_is_not() {
    let stub = start();
    let token = stub.api_key().as_str().to_owned();
    let auth = format!("{}{}X-Leak:  MARK-VALUE \r\n", key(&stub), bearer(&stub));
    let got = send(
        stub.addr(),
        &post("/v1/messages", &auth, &messages_body("x")),
    )
    .unwrap();
    assert_eq!(got.status, 200);
    let wrong = "x-api-key: MARK-WRONG\r\n";
    let got = send(stub.addr(), &post("/v1/messages", wrong, b"{}")).unwrap();
    assert_eq!(got.status, 401);
    let report = stub.finish().unwrap();
    let value = |r: &envcloak_agents::probe::model::Recorded, name: &str| -> Vec<u8> {
        let at = r
            .headers
            .iter()
            .position(|h| h.eq_ignore_ascii_case(name))
            .unwrap();
        r.values[at].to_vec()
    };
    let served = &report.requests[0];
    assert_eq!(served.values.len(), served.headers.len());
    assert_eq!(value(served, "x-leak"), b"MARK-VALUE");
    assert_eq!(value(served, "x-api-key"), b"<token>");
    assert_eq!(value(served, "authorization"), b"Bearer <token>");
    assert_eq!(value(served, "host"), b"127.0.0.1");
    let refused = &report.requests[1];
    assert_eq!(refused.status, 401);
    assert_eq!(value(refused, "x-api-key"), b"MARK-WRONG");
    assert!(refused.body.is_empty());
    for r in &report.requests {
        for v in &r.values {
            assert!(!v.windows(token.len()).any(|w| w == token.as_bytes()));
        }
    }
    let meta: u64 = report.requests.iter().map(|r| r.meta_len() as u64).sum();
    assert_eq!(report.outcome.recorded_meta, meta);
    assert!(meta > (2 * RECORD_OVERHEAD + "MARK-VALUE".len()) as u64);
}

/// Python's own `urllib`, pointed at the stub by its proxy variables, for
/// an `https://` and an `http://` URL: both refused by the stub, both
/// recorded, nothing malformed. The independent client the egress probe
/// in agent_hosts uses.
#[test]
fn python_s_proxied_requests_are_refused_and_recorded() {
    let stub = start();
    let probe = "import sys, urllib.error, urllib.request\n\
        for url in ('https://example.com/', 'http://example.com/x'):\n\
        \x20   try:\n\
        \x20       urllib.request.urlopen(url, timeout=10)\n\
        \x20       print('reached', url)\n\
        \x20   except urllib.error.HTTPError as e:\n\
        \x20       print('refused', e.code)\n\
        \x20   except Exception as e:\n\
        \x20       print('refused', type(e).__name__, '403' in str(e))\n";
    let proxy = format!("http://{}", stub.addr());
    let out = Command::new("python3")
        .args(["-c", probe])
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
        .env("HTTPS_PROXY", &proxy)
        .env("HTTP_PROXY", &proxy)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(!text.contains("reached"), "{text}");
    assert_eq!(text.matches("refused").count(), 2, "{text}");
    let report = stub.finish().unwrap();
    assert_eq!(report.outcome.malformed, 0, "{:?}", report.outcome);
    let seen: Vec<(&str, &str)> = report
        .requests
        .iter()
        .map(|r| (r.api.as_deref().unwrap_or(""), r.path.as_str()))
        .collect();
    assert_eq!(
        seen,
        [("connect", "example.com:443"), ("proxy", "example.com:80")],
        "{text}"
    );
}

/// What `Debug` shows of a recorded request: the endpoint by name or its
/// target by length, never the target itself (L-12); and a method or a
/// header name a client made up only by its length (Codex review,
/// medium: both were shown verbatim). The record keeps them whole: the
/// control that the requests carried them.
#[test]
fn a_record_s_debug_shows_no_target() {
    let stub = start();
    let auth = format!("{}X-Markheader: 1\r\n", key(&stub));
    let got = send(stub.addr(), &post("/MARK-P/x?MARK-Q", &auth, b"{}")).unwrap();
    assert_eq!(got.status, 404);
    let mut odd = post("/v1/messages", &key(&stub), b"{}");
    odd.splice(..4, b"MARKMETHOD".iter().copied());
    let got = send(stub.addr(), &odd).unwrap();
    assert_ne!(got.status, 200);
    let report = stub.finish().unwrap();
    assert_eq!(report.requests.len(), 2, "{:?}", report.requests);
    assert_eq!(report.requests[1].method, "MARKMETHOD");
    assert!(
        report.requests[0]
            .headers
            .contains(&"X-Markheader".to_owned())
    );
    let shown = format!("{:?}", report.requests);
    assert!(!shown.to_ascii_lowercase().contains("mark"), "{shown}");
    assert!(shown.contains("<16 bytes>"), "{shown}");
    assert!(shown.contains("<method of 10 bytes>"), "{shown}");
    assert!(shown.contains("\"<12 bytes>\""), "{shown}");
}

/// An owner that stops reading cannot keep the program alive: once the
/// run ends (here by its time limit), the last report waits at most 10 s
/// for its reader, then the program wipes its records and exits 3
/// (verifier, low, F-84: with a report larger than the pipe holds and
/// nobody reading, it blocked forever). The program is started by hand:
/// its standard output is read for the address line only.
#[test]
fn a_last_report_nobody_reads_does_not_keep_the_program_alive() {
    use std::io::BufRead as _;
    let mut child = Command::new(EXE)
        .args(["--time-limit", "1"])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(&script()).unwrap();
    stdin.write_all(b"\n").unwrap();
    let mut stdout = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut ready = String::new();
    stdout.read_line(&mut ready).unwrap();
    let ready: Value = serde_json::from_str(&ready).unwrap();
    let addr: SocketAddr = ready["addr"].as_str().unwrap().parse().unwrap();
    let auth = format!("x-api-key: {}\r\n", ready["token"].as_str().unwrap());
    // 300 KB of body, recorded: a last report of 400 KB of base64, far
    // more than a pipe holds.
    let got = send(addr, &post("/v1/other", &auth, &vec![b'a'; 300 * 1024])).unwrap();
    assert_eq!(got.status, 404);
    // Standard output stays open and unread; standard input stays open,
    // so only the time limit ends the run.
    let end = std::time::Instant::now() + Duration::from_secs(40);
    let status = loop {
        if let Some(st) = child.try_wait().unwrap() {
            break Some(st);
        }
        if std::time::Instant::now() > end {
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    if status.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    drop((stdin, stdout));
    assert_eq!(
        status.and_then(|s| s.code()),
        Some(3),
        "the program was still running 40 s after a 1 s run, its report unread"
    );
}

fn held_script() -> Vec<u8> {
    json!({"steps": [{"say": "held", "after": "approved"}]})
        .to_string()
        .into_bytes()
}

/// Sends a Messages request from another thread; its response, if any.
fn send_in_thread(stub: &ModelStub) -> std::thread::JoinHandle<Option<Got>> {
    let (addr, req) = (
        stub.addr(),
        post("/v1/messages", &key(stub), &messages_body("x")),
    );
    std::thread::spawn(move || send(addr, &req))
}

/// Waits until the run has recorded `n` requests (each poll a round trip
/// to the program, so no timing is assumed).
fn wait_recorded(stub: &mut ModelStub, n: usize) {
    for _ in 0..10_000 {
        if stub.requests().unwrap().requests.len() >= n {
            return;
        }
    }
    panic!("the request was never recorded");
}

#[test]
fn a_held_step_is_answered_only_once_released() {
    let mut stub =
        ModelStub::start(Path::new(EXE), &held_script(), Duration::from_secs(120)).unwrap();
    let pending = send_in_thread(&stub);
    wait_recorded(&mut stub, 1);
    stub.release("approved").unwrap();
    let got = pending.join().unwrap().unwrap();
    assert_eq!(got.status, 200);
    assert!(String::from_utf8(got.body).unwrap().contains("held"));
    // Released stays released.
    let again = send(
        stub.addr(),
        &post("/v1/messages", &key(&stub), &messages_body("y")),
    )
    .unwrap();
    assert_eq!(again.status, 200);
    assert!(stub.finish().unwrap().outcome.clean());
}

#[test]
fn a_held_step_never_released_is_never_answered() {
    let mut stub =
        ModelStub::start(Path::new(EXE), &held_script(), Duration::from_secs(120)).unwrap();
    let pending = send_in_thread(&stub);
    wait_recorded(&mut stub, 1);
    // The run ends with the reply still held: the connection closes
    // unanswered, the record says so, and the run is incomplete.
    let report = stub.finish().unwrap();
    assert_eq!(report.requests.len(), 1);
    assert!(pending.join().unwrap().is_none(), "a held reply was sent");
    let r = &report.requests[0];
    assert_eq!((r.status, r.answered), (200, false), "{r:?}");
    assert_eq!(report.outcome.incomplete, ["held_reply"]);
    assert_eq!(report.outcome.unanswered, 1);
    assert!(!report.outcome.clean());
}

/// A reply sent whole is recorded as answered, and only then: while it is
/// held, the record says it has not been.
#[test]
fn a_held_reply_is_recorded_unanswered_until_it_is_sent() {
    let mut stub =
        ModelStub::start(Path::new(EXE), &held_script(), Duration::from_secs(120)).unwrap();
    let pending = send_in_thread(&stub);
    wait_recorded(&mut stub, 1);
    assert!(!stub.requests().unwrap().requests[0].answered);
    stub.release("approved").unwrap();
    assert_eq!(pending.join().unwrap().unwrap().status, 200);
    let report = stub.finish().unwrap();
    assert!(report.requests[0].answered, "{:?}", report.requests);
    assert!(report.outcome.clean(), "{:?}", report.outcome);
}

/// Two connections that each reserve a record while the other's request
/// is still being read cannot pass the record cap between them (Codex
/// review): the reservation counts from the moment it is made, not once
/// the body has been read and the record kept. With room for one record,
/// the first request's body is held back after its head; the second
/// request, sent whole meanwhile, is refused, and the run keeps one record
/// and is incomplete.
#[test]
fn concurrent_requests_cannot_pass_the_record_cap_while_bodies_are_read() {
    let script = Script::parse(&script()).unwrap();
    let limits = Limits {
        records: 1,
        ..Limits::default()
    };
    let server = Server::bind(script, limits).unwrap();
    let (addr, handle) = (server.addr(), server.handle());
    let auth = format!("x-api-key: {}\r\n", server.api_key().as_str());
    let serving = std::thread::spawn(move || server.serve());
    let body = messages_body("first");
    let request = post("/v1/messages", &auth, &body);
    let head_len = request.len() - body.len();
    let mut first = TcpStream::connect(addr).unwrap();
    first
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    first.write_all(&request[..head_len]).unwrap();
    // The barrier: the first request has reserved its record (its
    // metadata is counted) and is reading its body.
    let end = std::time::Instant::now() + Duration::from_secs(30);
    while handle.outcome().recorded_meta == 0 {
        assert!(
            std::time::Instant::now() < end,
            "the first request never reserved"
        );
        std::thread::yield_now();
    }
    let second = send(addr, &post("/v1/messages", &auth, &messages_body("second"))).unwrap();
    assert_eq!(second.status, 503, "a second record passed the cap");
    first.write_all(&body).unwrap();
    assert_eq!(read_response(&mut first).unwrap().status, 200);
    drop(first);
    handle.stop();
    serving.join().unwrap();
    assert_eq!(handle.requests().len(), 1);
    assert_eq!(handle.outcome().incomplete, ["record_cap"]);
}
