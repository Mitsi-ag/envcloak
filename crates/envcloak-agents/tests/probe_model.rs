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
    format!("x-api-key: {}\r\n", stub.token().as_str())
}

fn bearer(stub: &ModelStub) -> String {
    format!("Authorization: Bearer {}\r\n", stub.token().as_str())
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
    let token = server.token().as_str().to_owned();
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
    // unanswered.
    let report = stub.finish().unwrap();
    assert_eq!(report.requests.len(), 1);
    assert!(pending.join().unwrap().is_none(), "a held reply was sent");
}
