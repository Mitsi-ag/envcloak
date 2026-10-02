//! `envcloak mcp` end to end on the built binaries (M2 plan task M2-06;
//! gate 35, and gate 13 through the MCP server): the server is started by
//! `fixture-agent`, so it and the `envcloak run` it starts are an agent's
//! subjects, and this test drives it over its pipes as a host does. The
//! person is this test process's own command on a terminal of its own
//! (`common::run_on_terminal`), and reads request ids from `envcloak
//! pending`, never from the agent's output.
//!
//! Every line the server writes on standard output must be one JSON-RPC
//! answer to a request this test sent: a child's output, or the server's
//! own diagnostics, there would break the protocol. Everything it writes
//! on either stream, the daemon's log and the home are swept for every
//! canary in every encoding.
//!
//! The independent client (the official MCP TypeScript SDK, pinned) and
//! gate 8's serializers through `run_with_secrets` are in crates/envcloak-e2e
//! (`m2_story`, step S7 and S8's module).
#![allow(clippy::unwrap_used)]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{
    MANIFEST, daemon_exe, outside_dir, project, python3, run_on_terminal, secret_file, seed_vault,
    stderr, stdout,
};
use envcloak_testkit::{
    Canary, Daemon, TestHome, assert_no_canary, by_label, canaries, fresh_seed, labels, testkit_bin,
};
use serde_json::{Value, json};

/// The command the covered runs start: for each variable named, the
/// SHA-256 of its value and the value itself, on standard output.
const EMIT: &str = r#"import hashlib, os, sys
for name in sys.argv[1:]:
    v = os.environb[name.encode()]
    sys.stdout.buffer.write(b"%s sha256=%s\n" % (name.encode(), hashlib.sha256(v).hexdigest().encode()))
    sys.stdout.buffer.write(b"raw=" + v + b"\n")
    sys.stdout.flush()
sys.stderr.write("emitted\n")
"#;

/// Takes an exclusive lock on argv[1], forks a child that keeps it, then
/// marks argv[2] and waits while argv[3] exists (at most 600 s): the lock
/// is free again only once both are gone. With argv[4] `stubborn`, both
/// ignore SIGTERM first. argv[3] is the test's own directory, gone when
/// the test ends however it ends, so a run the test failed to stop ends
/// by itself (L-03).
const HOLD: &str = r#"import fcntl, os, signal, sys, time
lock, ready, life = sys.argv[1], sys.argv[2], sys.argv[3]
if sys.argv[4:] == ["stubborn"]:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
f = open(lock, "a")
fcntl.flock(f, fcntl.LOCK_EX)
deadline = time.time() + 600
def wait():
    while os.path.exists(life) and time.time() < deadline:
        time.sleep(0.05)
if os.fork() == 0:
    wait()
    os._exit(0)
open(ready, "w").close()
wait()
"#;

/// Reads its standard input to the end and says how much it read.
const READ_STDIN: &str = r#"import sys
data = sys.stdin.buffer.read()
print("stdin=%d" % len(data))
"#;

/// The fixtures shaped like a key, which every tool refuses as an
/// argument (`value_on_argv`) wherever a name or a path goes.
const KEY_SHAPED: [&str; 4] = [
    labels::OPENAI_API_KEY,
    labels::OPENAI_API_KEY_ROTATED,
    labels::STRIPE_SECRET_KEY,
    labels::GITHUB_TOKEN,
];

fn sha256_hex(v: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(v)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A home with a seeded vault, a daemon that has it unlocked, the project
/// `acme-web` (OPENAI_API_KEY and STRIPE_SECRET_KEY bound) and its
/// scripts.
struct Fixture {
    cs: Vec<Canary>,
    home: TestHome,
    d: Option<Daemon>,
    project: PathBuf,
    _files: tempfile::TempDir,
    pass: PathBuf,
}

impl Fixture {
    /// With a daemon, unlocked.
    fn new() -> Self {
        let mut f = Self::without_daemon();
        let mut cmd = Command::new(daemon_exe());
        f.home
            .apply(&mut cmd)
            .env(envcloak_sys::testing::TRACE, "1");
        f.d = Some(Daemon::start_command(cmd, &[]));
        let out = run_on_terminal(
            &f.home,
            &["unlock", "--passphrase-fd", "3"],
            &[(3, &f.pass, true)],
        );
        assert!(out.status.success(), "{}", stderr(&out));
        f
    }

    /// With a vault on disk and no daemon running.
    fn without_daemon() -> Self {
        let cs = canaries(fresh_seed());
        let home = TestHome::new();
        let kit = seed_vault(&home, &cs);
        let mut cs = cs;
        cs.push(kit);
        let files = outside_dir();
        let pass = secret_file(
            files.path(),
            "pass",
            by_label(&cs, labels::VAULT_PASSPHRASE).value(),
        );
        let project = project(&home, "acme-web", MANIFEST);
        for (name, body) in [
            ("emit.py", EMIT),
            ("hold.py", HOLD),
            ("read_stdin.py", READ_STDIN),
        ] {
            std::fs::write(project.join(name), body).unwrap();
        }
        Fixture {
            cs,
            home,
            d: None,
            project,
            _files: files,
            pass,
        }
    }

    /// `envcloak <args>` by the person, on a terminal of their own.
    fn person(&self, args: &[&str]) -> std::process::Output {
        let out = run_on_terminal(&self.home, args, &[(3, &self.pass, true)]);
        assert_no_canary(&out.stdout, &self.cs);
        assert_no_canary(&out.stderr, &self.cs);
        out
    }

    /// The request ids `envcloak pending --json` lists to the person.
    fn listed(&self) -> Vec<String> {
        let out = self.person(&["pending", "--json"]);
        assert!(out.status.success(), "{}", stderr(&out));
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        v["requests"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["request"].as_str().unwrap().to_owned())
            .collect()
    }

    fn approve(&self, id: &str) {
        let out = self.person(&["approve", id, "--for", "1h", "--passphrase-fd", "3"]);
        assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    }

    fn sweep(&self) {
        if let Some(d) = &self.d {
            assert_no_canary(&d.log_bytes(), &self.cs);
        }
        self.home.assert_clean(&self.cs);
    }
}

/// A running `envcloak mcp`, started by `fixture-agent`.
struct Mcp {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<Vec<u8>>,
    out: Arc<Mutex<Vec<u8>>>,
    err: Arc<Mutex<Vec<u8>>>,
    /// Answers read while waiting for another.
    kept: Vec<Value>,
    next_id: i64,
    cs: Vec<Canary>,
}

impl Mcp {
    fn start(home: &TestHome, cwd: &Path, args: &[&str], cs: &[Canary]) -> Mcp {
        let mut cmd = Command::new(testkit_bin("fixture-agent"));
        home.apply(&mut cmd).arg("--").arg(common::cli());
        Mcp::spawn(cmd, cwd, args, cs)
    }

    /// The server as this test's own child, with no agent above it: a
    /// process the test may signal while it is unreaped.
    fn start_direct(home: &TestHome, cwd: &Path, args: &[&str], cs: &[Canary]) -> Mcp {
        let mut cmd = Command::new(common::cli());
        home.apply(&mut cmd);
        Mcp::spawn(cmd, cwd, args, cs)
    }

    fn spawn(mut cmd: Command, cwd: &Path, args: &[&str], cs: &[Canary]) -> Mcp {
        cmd.arg("mcp")
            .args(args)
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        let stdin = child.stdin.take();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut stderr = child.stderr.take().unwrap();
        let out = Arc::new(Mutex::new(Vec::new()));
        let err = Arc::new(Mutex::new(Vec::new()));
        let (tx, lines) = mpsc::channel();
        let all = Arc::clone(&out);
        std::thread::spawn(move || {
            loop {
                let mut line = Vec::new();
                match stdout.read_until(b'\n', &mut line) {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {
                        all.lock().unwrap().extend_from_slice(&line);
                        if tx.send(line).is_err() {
                            return;
                        }
                    }
                }
            }
        });
        let all = Arc::clone(&err);
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = stderr.read(&mut buf) {
                if n == 0 {
                    return;
                }
                all.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        });
        Mcp {
            child,
            stdin,
            lines,
            out,
            err,
            kept: Vec::new(),
            next_id: 1,
            cs: cs.to_vec(),
        }
    }

    fn send_raw(&mut self, bytes: &[u8]) {
        let stdin = self.stdin.as_mut().unwrap();
        stdin.write_all(bytes).unwrap();
        stdin.flush().unwrap();
    }

    fn send(&mut self, v: &Value) {
        let mut line = serde_json::to_vec(v).unwrap();
        line.push(b'\n');
        self.send_raw(&line);
    }

    /// The next line on standard output, which must be one JSON-RPC
    /// answer: an object with `jsonrpc` 2.0, an id, and a result or an
    /// error. Swept before it is parsed.
    fn next(&mut self, limit: Duration) -> Option<Value> {
        let line = self.lines.recv_timeout(limit).ok()?;
        assert_no_canary(&line, &self.cs);
        let v: Value = serde_json::from_slice(&line).unwrap_or_else(|_| {
            panic!(
                "not JSON on the protocol stream: {}",
                String::from_utf8_lossy(&line)
            )
        });
        assert_eq!(v["jsonrpc"], "2.0", "{v}");
        assert!(v.get("id").is_some(), "{v}");
        assert!(
            v.get("result").is_some() != v.get("error").is_some(),
            "neither a result nor an error, or both: {v}"
        );
        Some(v)
    }

    /// The answer to request `id`, within `limit`; others read meanwhile
    /// are kept.
    fn answer(&mut self, id: i64, limit: Duration) -> Value {
        if let Some(i) = self.kept.iter().position(|v| v["id"] == id) {
            return self.kept.remove(i);
        }
        let end = Instant::now() + limit;
        loop {
            let left = end.saturating_duration_since(Instant::now());
            let v = self.next(left).unwrap_or_else(|| {
                panic!(
                    "no answer to {id} within {limit:?}; stderr: {}",
                    self.stderr()
                )
            });
            if v["id"] == id {
                return v;
            }
            self.kept.push(v);
        }
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        self.answer(id, Duration::from_secs(120))
    }

    fn initialize(&mut self) {
        let v = self.request(
            "initialize",
            json!({"protocolVersion": "2025-11-25", "capabilities": {},
                   "clientInfo": {"name": "envcloak-test", "version": "1"}}),
        );
        assert_eq!(v["result"]["protocolVersion"], "2025-11-25", "{v}");
        self.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
    }

    /// Calls `tool` and returns the `tools/call` result.
    fn call(&mut self, tool: &str, args: Value) -> Value {
        let v = self.request("tools/call", json!({"name": tool, "arguments": args}));
        v.get("result")
            .cloned()
            .unwrap_or_else(|| panic!("{tool}: {v}"))
    }

    /// Sends a call without waiting; returns its id.
    fn call_async(&mut self, tool: &str, args: Value) -> i64 {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": tool, "arguments": args}}));
        id
    }

    fn stderr(&self) -> String {
        String::from_utf8_lossy(&self.err.lock().unwrap()).into_owned()
    }

    /// Ends the input and waits for the server to exit; returns all it
    /// wrote on each stream, swept.
    fn finish(mut self) -> (Vec<u8>, Vec<u8>) {
        drop(self.stdin.take());
        let end = Instant::now() + Duration::from_secs(60);
        while self.child.try_wait().unwrap().is_none() {
            assert!(
                Instant::now() < end,
                "the server did not exit after its input ended"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        while let Some(v) = self.next(Duration::from_millis(200)) {
            self.kept.push(v);
        }
        let out = self.out.lock().unwrap().clone();
        let err = self.err.lock().unwrap().clone();
        assert_no_canary(&out, &self.cs);
        assert_no_canary(&err, &self.cs);
        (out, err)
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The structured result of a successful call.
fn structured(r: &Value) -> &Value {
    assert_eq!(r["isError"], false, "{r}");
    let s = &r["structuredContent"];
    // The same JSON as text.
    let text: Value = serde_json::from_str(r["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(&text, s);
    s
}

/// The error token of a failed call.
fn failed(r: &Value) -> String {
    assert_eq!(r["isError"], true, "{r}");
    let text: Value = serde_json::from_str(r["content"][0]["text"].as_str().unwrap()).unwrap();
    text["error"].as_str().unwrap().to_owned()
}

/// What an answer in [`check_answers`] must be.
#[derive(Debug, Clone, Copy)]
enum Want {
    /// A protocol error with this code.
    Error(i64),
    /// A result.
    Result,
    /// A tool's answer: a failure with exactly this token, or (`None`)
    /// one with a fixed token, or a result.
    Tool(Option<&'static str>),
}

/// Gate 13 and the server's own parser (L-06): hostile input of every kind
/// is answered with a fixed error, and nothing from it, a canary included
/// in any position, is ever echoed, on either stream. No daemon runs:
/// every refusal comes before one would be asked, and a key-shaped fixture
/// wherever a name or a path goes is refused as one (`value_on_argv`),
/// never left to fail later for want of a daemon. A request id holding a
/// fixture is answered with a `null` id, the generated Recovery Kit
/// included; only the 10-character token is not sent as one, being a
/// plain string of an id's shape.
///
/// Mutations checked: `invalid()` naming the first unknown property (an
/// unknown argument echoed in an error): the canary sweep fails. A string
/// id's letters and digits not counted: the Recovery Kit is echoed as an
/// id and the sweep fails.
#[test]
fn hostile_input_gets_fixed_errors_and_echoes_nothing() {
    let f = Fixture::without_daemon();
    let mut m = Mcp::start(&f.home, &f.project, &[], &f.cs);
    m.initialize();
    let dir = f.project.to_str().unwrap().to_owned();
    let mut expected: Vec<(Value, Want)> = Vec::new();
    for (i, c) in f.cs.iter().enumerate() {
        let v = c.as_str();
        let base = 100 * (i as i64 + 1);
        // Not JSON, not UTF-8, a batch, a message cut by a newline.
        m.send_raw(format!("{v}\n").as_bytes());
        expected.push((Value::Null, Want::Error(-32700)));
        let mut bad = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"\xff".to_vec();
        bad.extend_from_slice(c.value());
        bad.extend_from_slice(b"\"}\n");
        m.send_raw(&bad);
        expected.push((Value::Null, Want::Error(-32700)));
        m.send(&json!([{"jsonrpc": "2.0", "id": 1, "method": v}]));
        expected.push((Value::Null, Want::Error(-32600)));
        m.send_raw(
            format!("{{\"jsonrpc\":\"2.0\",\"id\":{base},\n\"method\":\"{v}\"}}\n").as_bytes(),
        );
        expected.push((Value::Null, Want::Error(-32700)));
        expected.push((Value::Null, Want::Error(-32700)));
        // An id shaped like a key, a URL, a passphrase or a Recovery Kit is
        // answered null, never echoed. JSON-RPC makes an answer echo its
        // id, and the host chose it, so a plain one is echoed: the short
        // token (10 letters and digits) cannot be told from such an id by
        // its shape, and is not sent as one.
        if c.label != labels::SHORT_TOKEN {
            m.send(&json!({"jsonrpc": "2.0", "id": v, "method": "ping"}));
            expected.push((Value::Null, Want::Error(-32600)));
        }
        // An unknown method, an unknown tool, params of the wrong shape.
        m.send(&json!({"jsonrpc": "2.0", "id": base + 1, "method": v}));
        expected.push((json!(base + 1), Want::Error(-32601)));
        m.send(
            &json!({"jsonrpc": "2.0", "id": base + 2, "method": "tools/call",
            "params": {"name": v, "arguments": {}}}),
        );
        expected.push((json!(base + 2), Want::Error(-32602)));
        m.send(&json!({"jsonrpc": "2.0", "id": base + 3, "method": "tools/call", "params": [v]}));
        expected.push((json!(base + 3), Want::Error(-32602)));
        // Tool arguments: an unknown property named by the value, one
        // holding it, a value where a name goes, a value in argv. A
        // key-shaped fixture where a name, a path or an argument goes is
        // refused as one; any other is answered with a fixed token or a
        // result, never echoed.
        let key = KEY_SHAPED.contains(&c.label.as_str());
        let as_value = Want::Tool(key.then_some("value_on_argv"));
        let calls = [
            (
                "list_secrets",
                json!({ v: 1 }),
                Want::Tool(Some("invalid_params")),
            ),
            (
                "list_secrets",
                json!({"project_dir": dir, "extra": v}),
                Want::Tool(Some("invalid_params")),
            ),
            ("list_secrets", json!({"project_dir": v}), as_value),
            ("request_new_secret", json!({"provider": v}), as_value),
            (
                "run_with_secrets",
                json!({"project_dir": dir, "argv": ["curl", "-H", v]}),
                as_value,
            ),
            (
                "run_with_secrets",
                json!({"project_dir": dir, "argv": ["sh"], "profile": v}),
                as_value,
            ),
            (
                "add_reference",
                json!({"project_dir": dir, "env_name": "A", "slug": v}),
                as_value,
            ),
            (
                "add_reference",
                json!({"project_dir": dir, "env_name": v, "slug": "openai/acme-web"}),
                as_value,
            ),
            (
                "add_reference",
                json!({"project_dir": dir, "env_name": "A", "slug": "openai/acme-web",
                       "profile": v}),
                as_value,
            ),
            ("project_status", json!({"project_dir": v}), as_value),
        ];
        for (j, (tool, args, want)) in calls.iter().enumerate() {
            let id = base + 10 + j as i64;
            m.send(&json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
                "params": {"name": tool, "arguments": args}}));
            expected.push((json!(id), *want));
        }
        // Each canary's calls are answered before the next one's are sent:
        // all at once they would pass the queue and be answered `busy`.
        check_answers(&mut m, std::mem::take(&mut expected));
    }
    // A line over the 1 MiB cap, made of canaries.
    let mut huge = Vec::new();
    while huge.len() <= envcloak_mcp::stdio::MAX_LINE {
        for c in &f.cs {
            huge.extend_from_slice(c.value());
        }
    }
    huge.push(b'\n');
    m.send_raw(&huge);
    expected.push((Value::Null, Want::Error(-32700)));
    m.send(&json!({"jsonrpc": "2.0", "id": 9999, "method": "ping"}));
    expected.push((json!(9999), Want::Result));
    check_answers(&mut m, expected);
    let (out, err) = m.finish();
    assert!(!out.is_empty());
    assert_no_canary(&err, &f.cs);
    f.sweep();
}

/// Reads the answers to `expected` (`(id, what it must be)`) and checks
/// each. Errors the reader answers at once can overtake a tool's answer:
/// answers are matched by id, and those without one by their codes.
fn check_answers(m: &mut Mcp, expected: Vec<(Value, Want)>) {
    let mut got: Vec<Value> = Vec::new();
    while got.len() < expected.len() {
        let v = m.next(Duration::from_secs(60)).unwrap_or_else(|| {
            panic!(
                "{} answers of {}; stderr: {}",
                got.len(),
                expected.len(),
                m.stderr()
            )
        });
        got.push(v);
    }
    let codes = |vs: &mut dyn Iterator<Item = i64>| {
        let mut c: Vec<i64> = vs.collect();
        c.sort_unstable();
        c
    };
    assert_eq!(
        codes(
            &mut got
                .iter()
                .filter(|v| v["id"].is_null())
                .map(|v| v["error"]["code"].as_i64().unwrap())
        ),
        codes(
            &mut expected
                .iter()
                .filter(|(id, _)| id.is_null())
                .map(|(_, w)| match w {
                    Want::Error(c) => *c,
                    other => panic!("an answer with no id cannot be {other:?}"),
                })
        ),
    );
    for (id, want) in expected.into_iter().filter(|(id, _)| !id.is_null()) {
        let v = got
            .iter()
            .find(|v| v["id"] == id)
            .unwrap_or_else(|| panic!("no answer for {id}"));
        match want {
            Want::Result => assert!(v.get("result").is_some(), "{v}"),
            Want::Tool(Some(token)) => {
                assert_eq!(failed(&v["result"]), token, "{id}: {v}");
            }
            // A tool's answer to a canary that is not shaped like a key (a
            // passphrase of words): a refusal with a fixed token, or
            // whatever the tool answers for it; neither echoes it
            // (Mcp::next sweeps every line).
            Want::Tool(None) => {
                let r = &v["result"];
                if r["isError"] == true {
                    let token = failed(r);
                    assert!(
                        [
                            "invalid_params",
                            "value_on_argv",
                            "invalid_path",
                            "invalid_reference",
                            "invalid_profile_name",
                            "daemon_unavailable",
                        ]
                        .contains(&token.as_str()),
                        "{token}"
                    );
                } else {
                    assert!(r.get("structuredContent").is_some(), "{v}");
                }
            }
            Want::Error(c) => assert_eq!(v["error"]["code"], c, "{v}"),
        }
    }
}

/// The line cap: a line over 1 MiB is refused as soon as it passes the
/// cap, before its end; the rest of it is read and dropped, so a 64 MiB
/// line costs the server no more memory than the cap (its peak resident
/// size, as the kernel counts it for a reaped child, stays under 48 MiB);
/// and the next line is served.
///
/// Mutation checked: the reader keeps a line however long it is (no cap):
/// the refusal does not come before the line's end, and the peak resident
/// size passes 64 MiB.
#[test]
fn an_oversized_line_is_refused_early_and_costs_no_more_than_the_cap() {
    let home = TestHome::new();
    const DRIVE: &str = r#"import json, os, resource, select, subprocess, sys
p = subprocess.Popen(sys.argv[1:], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
def line(limit):
    r, _, _ = select.select([p.stdout], [], [], limit)
    return p.stdout.readline() if r else b""
chunk = b"a" * (1 << 16)
for _ in range(17):
    p.stdin.write(chunk)
p.stdin.flush()
early = line(20)
for _ in range(1024):
    p.stdin.write(chunk)
p.stdin.write(b"\n" + json.dumps({"jsonrpc": "2.0", "id": 7, "method": "ping"}).encode() + b"\n")
p.stdin.flush()
after = line(60)
p.stdin.close()
p.wait()
rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
if sys.platform != "darwin":
    rss *= 1024
print(json.dumps({"early": early.decode("utf-8", "replace"), "after": after.decode("utf-8", "replace"), "rss": rss, "code": p.returncode}))
"#;
    let mut cmd = Command::new(python3());
    home.apply(&mut cmd)
        .args(["-c", DRIVE])
        .arg(common::cli())
        .arg("mcp")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = common::finish_within(cmd, Duration::from_secs(120));
    assert!(out.status.success(), "{}", stderr(&out));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    let early: Value = serde_json::from_str(v["early"].as_str().unwrap())
        .unwrap_or_else(|_| panic!("no refusal before the line's end: {v}"));
    assert_eq!(early["error"]["code"], -32700, "{early}");
    let after: Value = serde_json::from_str(v["after"].as_str().unwrap()).unwrap();
    assert_eq!(after["id"], 7, "{after}");
    assert_eq!(v["code"], 0);
    let rss = v["rss"].as_u64().unwrap();
    assert!(rss < 48 << 20, "peak resident size {rss} bytes");
}

/// While the daemon is down, every tool fails as a result with a fixed
/// token, and standard output holds answers and nothing else (`envcloak
/// run`'s and `envcloak check`'s output included).
#[test]
fn standard_output_holds_only_messages_while_the_daemon_is_down() {
    let f = Fixture::without_daemon();
    let mut m = Mcp::start(&f.home, &f.project, &["--wait-ms", "1000"], &f.cs);
    m.initialize();
    let dir = f.project.to_str().unwrap();
    let py = python3();
    let r = m.call("list_secrets", json!({"project_dir": dir}));
    assert_eq!(failed(&r), "daemon_unavailable");
    let r = m.call("project_status", json!({"project_dir": dir}));
    assert_eq!(failed(&r), "daemon_unavailable");
    let r = m.call(
        "add_reference",
        json!({"project_dir": dir, "env_name": "GITHUB_TOKEN", "slug": "github/acme-web"}),
    );
    assert_eq!(failed(&r), "daemon_unavailable");
    let r = m.call(
        "run_with_secrets",
        json!({"project_dir": dir, "argv": [py.to_str().unwrap(), "emit.py", "OPENAI_API_KEY"]}),
    );
    let s = structured(&r);
    assert_eq!(s["status"], "refused", "{s}");
    assert_eq!(s["token"], "daemon_unavailable", "{s}");
    let r = m.call("request_new_secret", json!({"provider": "openai"}));
    assert_eq!(structured(&r)["command"], "envcloak add openai");
    let (out, _) = m.finish();
    // Every line was read as an answer (Mcp::next checks each one).
    assert_eq!(out.iter().filter(|b| **b == b'\n').count(), 6);
    f.sweep();
}

/// Story S8 through the MCP server, and gate 35: `run_with_secrets` first
/// answers with the pending request, says how the person approves it and
/// that the command runs outside the host's sandbox, and never invites the
/// agent to approve; the person finds it with `envcloak pending` and
/// approves it from a terminal of their own; the call made again runs the
/// command with the values (their digests match) and its output redacted.
/// No answer holds a value, and nothing but answers reaches standard
/// output. `project_status` shows the grant and no request left pending;
/// `list_secrets` shows the items and the project's bindings, never a
/// value; `add_reference` binds a secret; a command reading its input gets
/// end of input at once.
///
/// Mutations checked: run argv directly instead of through `envcloak run`
/// (no value is injected): the digest check fails. `envcloak run` not
/// redacting under `envcloak mcp`: the sweep fails. The child given the
/// server's standard output: the protocol check fails (a command's line
/// on the stream). The child given the server's standard input: the stdin
/// check fails (the command reads the protocol, or waits on it).
#[test]
fn run_with_secrets_waits_for_the_person_and_redacts() {
    let f = Fixture::new();
    let mut m = Mcp::start(&f.home, &f.project, &["--wait-ms", "2000"], &f.cs);
    m.initialize();
    let dir = f.project.to_str().unwrap();
    let py = python3();
    let argv = json!([
        py.to_str().unwrap(),
        "emit.py",
        "OPENAI_API_KEY",
        "STRIPE_SECRET_KEY"
    ]);

    let start = Instant::now();
    let r = m.call(
        "run_with_secrets",
        json!({"project_dir": dir, "argv": argv}),
    );
    let s = structured(&r).clone();
    assert!(
        start.elapsed() < Duration::from_secs(9),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(s["status"], "approval_required", "{s}");
    let id = s["request"].as_str().unwrap().to_owned();
    let message = s["message"].as_str().unwrap();
    for part in [
        &format!("Request {id} needs the person's approval"),
        "`envcloak pending`",
        "terminal of their own",
        "approvals from this session are refused",
        "outside this host's sandbox",
    ] {
        assert!(message.contains(part), "{part}: {message}");
    }
    assert!(!r.to_string().contains("envcloak approve"), "{r}");
    // The person reads the id from `envcloak pending`, not from here.
    assert_eq!(f.listed(), std::slice::from_ref(&id));
    let status = structured(&m.call("project_status", json!({"project_dir": dir}))).clone();
    assert_eq!(
        status["pending_requests"],
        json!([{"request": id, "state": "pending"}])
    );
    f.approve(&id);

    let r = m.call(
        "run_with_secrets",
        json!({"project_dir": dir, "argv": argv}),
    );
    let s = structured(&r);
    assert_eq!(s["status"], "completed", "{s}");
    assert_eq!(s["exit_code"], 0, "{s}");
    let out = s["stdout"].as_str().unwrap();
    for (name, label, slug) in [
        ("OPENAI_API_KEY", labels::OPENAI_API_KEY, "openai/acme-web"),
        (
            "STRIPE_SECRET_KEY",
            labels::STRIPE_SECRET_KEY,
            "stripe/acme-web",
        ),
    ] {
        let digest = sha256_hex(by_label(&f.cs, label).value());
        assert!(out.contains(&format!("{name} sha256={digest}\n")), "{out}");
        assert!(out.contains(&format!("raw=[envcloak:{slug}]\n")), "{out}");
    }
    assert_eq!(s["stderr"], "emitted\n");
    assert_eq!(s["stdout_left_out"], 0);

    // A command reading its input gets end of input at once.
    let r = m.call(
        "run_with_secrets",
        json!({"project_dir": dir, "argv": [py.to_str().unwrap(), "read_stdin.py"]}),
    );
    let s = structured(&r);
    assert_eq!(s["exit_code"], 0, "{s}");
    assert_eq!(s["stdout"], "stdin=0\n", "{s}");

    // The grant, rooted at the agent above this server, by the id the
    // person's own `envcloak grants list` shows; nothing pending.
    let status = structured(&m.call("project_status", json!({"project_dir": dir}))).clone();
    assert_eq!(status["pending_requests"], json!([]), "{status}");
    let grants = status["grants"].as_array().unwrap();
    assert_eq!(grants.len(), 1, "{status}");
    assert_eq!(grants[0]["uses"], "session", "{status}");
    let theirs = f.person(&["grants", "list", "--json"]);
    assert!(theirs.status.success(), "{}", stderr(&theirs));
    let theirs: Value = serde_json::from_slice(&theirs.stdout).unwrap();
    assert_eq!(grants[0]["id"], theirs["grants"][0]["id"], "{status}");
    assert_eq!(grants[0]["id"].as_str().unwrap().len(), 26, "{status}");
    assert_eq!(status["bindings_resolved"], 3, "{status}");
    assert_eq!(status["vault"], "unlocked");
    assert_eq!(status["coverage"], Value::Null);

    // Metadata only.
    let list = structured(&m.call("list_secrets", json!({"project_dir": dir}))).clone();
    let slugs: Vec<&str> = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["slug"].as_str().unwrap())
        .collect();
    let mut want = common::SLUGS.to_vec();
    want.sort_unstable();
    assert_eq!(slugs, want, "{list}");
    assert_eq!(
        list["project"]["bindings"].as_array().unwrap().len(),
        3,
        "{list}"
    );

    // A secret is bound; the manifest says so, and the next run asks.
    let r = m.call(
        "add_reference",
        json!({"project_dir": dir, "env_name": "GITHUB_TOKEN", "slug": "github/acme-web"}),
    );
    let s = structured(&r);
    assert_eq!(s["change"], "added", "{s}");
    assert_eq!(s["resolves"], "ok", "{s}");
    let manifest = std::fs::read_to_string(f.project.join("envcloak.toml")).unwrap();
    assert!(
        manifest.contains("GITHUB_TOKEN = \"github/acme-web\""),
        "{manifest}"
    );
    let r = m.call(
        "add_reference",
        json!({"project_dir": dir, "env_name": "X", "slug": "no-such/item"}),
    );
    assert_eq!(failed(&r), "no_such_item");

    m.finish();
    f.sweep();
}

/// Host cancellation (`notifications/cancelled`) of a running
/// `run_with_secrets`: the call is answered nothing, ever, and the
/// command's whole process tree ends, its forked child too (a lock both
/// hold is free again), by its process group, never a bare pid. The
/// server goes on answering.
///
/// Mutations checked: `Call::cancel` killing only the child's pid
/// (`SIGKILL` to `envcloak run` alone, nothing passed on): the lock stays
/// held and this fails. Answering a cancelled call: the answer arrives
/// and this fails.
#[test]
fn a_cancelled_run_is_answered_nothing_and_leaves_no_process() {
    let f = Fixture::new();
    let mut m = Mcp::start(&f.home, &f.project, &["--wait-ms", "1000"], &f.cs);
    m.initialize();
    let dir = f.project.to_str().unwrap();
    let py = python3();
    let files = outside_dir();
    let lock = files.path().join("lock");
    let ready = files.path().join("ready");
    let argv = json!([
        py.to_str().unwrap(),
        "hold.py",
        lock.to_str().unwrap(),
        ready.to_str().unwrap(),
        files.path().to_str().unwrap()
    ]);
    // Approved once, so the next call runs.
    let r = m.call(
        "run_with_secrets",
        json!({"project_dir": dir, "argv": argv}),
    );
    let id = structured(&r)["request"].as_str().unwrap().to_owned();
    f.approve(&id);
    let call = m.call_async(
        "run_with_secrets",
        json!({"project_dir": dir, "argv": argv}),
    );
    let end = Instant::now() + Duration::from_secs(60);
    while !ready.exists() {
        assert!(
            Instant::now() < end,
            "the command did not start: {}",
            m.stderr()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let held = std::fs::File::open(&lock).unwrap();
    assert!(!envcloak_sys::try_lock_exclusive(&held).unwrap());
    m.send(
        &json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
        "params": {"requestId": call, "reason": "the host gave up"}}),
    );
    let end = Instant::now() + Duration::from_secs(15);
    while !envcloak_sys::try_lock_exclusive(&held).unwrap() {
        assert!(
            Instant::now() < end,
            "a process of the cancelled command still holds its lock"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    // This test holds the lock now: let it go for the next run.
    drop(held);
    // Whatever the call would have answered had time to come.
    std::thread::sleep(envcloak_mcp::child::DRAIN + Duration::from_secs(1));
    let ping = m.request("ping", json!({}));
    assert_eq!(ping["result"], json!({}));
    assert!(
        m.kept.iter().all(|v| v["id"] != call),
        "the cancelled call was answered: {:?}",
        m.kept
    );

    // The host ends the session (its standard input closes) while a run
    // holds the lock again: that run is stopped the same way, and the
    // server exits.
    std::fs::remove_file(&ready).unwrap();
    m.call_async(
        "run_with_secrets",
        json!({"project_dir": dir, "argv": argv}),
    );
    let end = Instant::now() + Duration::from_secs(60);
    while !ready.exists() {
        assert!(
            Instant::now() < end,
            "the command did not start again: {}",
            m.stderr()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let held = std::fs::File::open(&lock).unwrap();
    assert!(!envcloak_sys::try_lock_exclusive(&held).unwrap());
    let (_, _) = m.finish();
    let end = Instant::now() + Duration::from_secs(15);
    while !envcloak_sys::try_lock_exclusive(&held).unwrap() {
        assert!(
            Instant::now() < end,
            "a process of the command still holds its lock after the session ended"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    f.sweep();
}

/// `SIGTERM` to the server (the host stopping it) stops the calls in hand
/// first: a running `run_with_secrets` has its whole tree ended (a lock its
/// command's forked child holds is freed), and the server then ends by the
/// signal. The server is this test's own child here, with no agent above
/// it, signalled while unreaped.
///
/// Mutation checked: the signal thread exiting without stopping the calls:
/// the orphaned `envcloak run` and its command go on, the lock stays held,
/// and this fails.
#[test]
fn sigterm_stops_the_calls_in_hand_first() {
    let f = Fixture::new();
    let mut m = Mcp::start_direct(&f.home, &f.project, &["--wait-ms", "1000"], &f.cs);
    m.initialize();
    let dir = f.project.to_str().unwrap();
    let py = python3();
    let files = outside_dir();
    let lock = files.path().join("lock");
    let ready = files.path().join("ready");
    let argv = json!([
        py.to_str().unwrap(),
        "hold.py",
        lock.to_str().unwrap(),
        ready.to_str().unwrap(),
        files.path().to_str().unwrap()
    ]);
    let r = m.call(
        "run_with_secrets",
        json!({"project_dir": dir, "argv": argv}),
    );
    let id = structured(&r)["request"].as_str().unwrap().to_owned();
    f.approve(&id);
    m.call_async(
        "run_with_secrets",
        json!({"project_dir": dir, "argv": argv}),
    );
    let end = Instant::now() + Duration::from_secs(60);
    while !ready.exists() {
        assert!(
            Instant::now() < end,
            "the command did not start: {}",
            m.stderr()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let held = std::fs::File::open(&lock).unwrap();
    assert!(!envcloak_sys::try_lock_exclusive(&held).unwrap());
    let pid = i32::try_from(m.child.id()).unwrap();
    envcloak_sys::signal_process(pid, libc::SIGTERM).unwrap();
    let end = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(s) = m.child.try_wait().unwrap() {
            break s;
        }
        assert!(Instant::now() < end, "the server did not end on SIGTERM");
        std::thread::sleep(Duration::from_millis(20));
    };
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(status.signal(), Some(libc::SIGTERM), "{status:?}");
    let end = Instant::now() + Duration::from_secs(15);
    while !envcloak_sys::try_lock_exclusive(&held).unwrap() {
        assert!(
            Instant::now() < end,
            "a process of the command still holds its lock after SIGTERM"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let (_, _) = m.finish();
    f.sweep();
}

/// With a slow approval, each `--host` default answers with the pending
/// request before that host's tool cutoff, as the installer sets it up:
/// 60 s for Claude Code and Codex (their per-server timeout), 10 s for any
/// other host (SI-17, K-08); and it does wait for the person first, its
/// default less the grace it keeps for the daemon's last answer.
///
/// Mutation checked: the default for an unknown host at its cutoff plus 2
/// s (12 s): its answer comes after the 10 s cutoff and this fails.
#[test]
fn each_hosts_default_wait_answers_before_its_cutoff() {
    let f = Fixture::new();
    let py = python3();
    let hosts: [Option<&str>; 3] = [Some("claude-code"), Some("codex"), None];
    let runs: Vec<_> = hosts
        .iter()
        .map(|host| {
            let args: Vec<&str> = match host {
                Some(h) => vec!["--host", h],
                None => vec![],
            };
            let mut m = Mcp::start(&f.home, &f.project, &args, &f.cs);
            m.initialize();
            let start = Instant::now();
            let id = m.call_async(
                "run_with_secrets",
                json!({"project_dir": f.project.to_str().unwrap(),
                       "argv": [py.to_str().unwrap(), "emit.py", "OPENAI_API_KEY"]}),
            );
            // Each server's answer is waited for on a thread of its own,
            // so each is timed from its own call.
            let host = host.map(str::to_owned);
            std::thread::spawn(move || {
                let v = m.answer(id, Duration::from_secs(120));
                (host, m, v, start.elapsed())
            })
        })
        .collect();
    for run in runs {
        let (host, m, v, took) = run.join().unwrap();
        let host = host.as_deref();
        let s = structured(&v["result"]).clone();
        assert_eq!(s["status"], "approval_required", "{host:?}: {s}");
        let cutoff = envcloak_agents::tool_timeouts::cutoff(host);
        let wait = envcloak_agents::tool_timeouts::default_wait(host);
        let person = envcloak_agents::tool_timeouts::person_wait(wait);
        assert!(
            took >= person && took < cutoff,
            "{host:?}: answered after {took:?}; its wait is {wait:?} ({person:?} for the \
             person) and its cutoff {cutoff:?}"
        );
        println!(
            "measurement: run_with_secrets --host {host:?}: pending answered after {took:?} (cutoff {cutoff:?})"
        );
        m.finish();
    }
    f.sweep();
}

/// Gate 13 through every tool, with the daemon up and the vault unlocked:
/// each key-shaped fixture, in each string a tool takes (a project
/// directory, a variable's name, a slug and its field, a profile, a
/// provider, a command's argument), is refused with `value_on_argv`,
/// unechoed, before anything is asked of the daemon or written: no
/// connection reaches the daemon (its trace, with a positive control
/// that one does), envcloak.toml is byte for byte what it was, and no
/// request is opened.
///
/// Mutations checked: `refuse_value_like` removed from `add_reference`: a
/// key-shaped `env_name` is a variable name to EnvName's grammar, the
/// binding is written into envcloak.toml after the daemon is asked about
/// the slug, and this fails on the file. Removed from `request_new_secret`,
/// `list_secrets` or `project_status`: a key-shaped argument is answered
/// otherwise (`list_secrets` and `project_status` reach `invalid_path`),
/// and this fails.
#[test]
fn key_shaped_arguments_are_refused_before_the_daemon_is_asked() {
    let f = Fixture::new();
    let mut m = Mcp::start(&f.home, &f.project, &["--wait-ms", "1000"], &f.cs);
    m.initialize();
    let dir = f.project.to_str().unwrap();
    let py = python3();
    let py = py.to_str().unwrap();
    let manifest_path = f.project.join("envcloak.toml");
    let manifest = std::fs::read(&manifest_path).unwrap();
    let opened = || {
        f.d.as_ref()
            .unwrap()
            .log()
            .matches("envcloakd: test: connection opened")
            .count()
    };
    // Each connection the daemon takes is logged before it is served, so
    // once a call that connects has been answered, its line comes; every
    // line before it has come by then.
    let control = |m: &mut Mcp, after: usize| {
        structured(&m.call("list_secrets", json!({})));
        let end = Instant::now() + Duration::from_secs(30);
        while opened() <= after {
            assert!(Instant::now() < end, "the trace shows no connection");
            std::thread::sleep(Duration::from_millis(10));
        }
        opened()
    };
    let before = control(&mut m, 0);
    // Every call is made before anything is checked, so a mutation that
    // writes shows in the file, not only in the first answer.
    let mut answers = Vec::new();
    for label in KEY_SHAPED {
        let v = by_label(&f.cs, label).as_str();
        let field = format!("openai/acme-web#{v}");
        for (tool, args) in [
            ("list_secrets", json!({"project_dir": v})),
            ("project_status", json!({"project_dir": v})),
            ("request_new_secret", json!({"provider": v})),
            (
                "add_reference",
                json!({"project_dir": v, "env_name": "X", "slug": "openai/acme-web"}),
            ),
            (
                "add_reference",
                json!({"project_dir": dir, "env_name": v, "slug": "openai/acme-web"}),
            ),
            (
                "add_reference",
                json!({"project_dir": dir, "env_name": "X", "slug": v}),
            ),
            (
                "add_reference",
                json!({"project_dir": dir, "env_name": "X", "slug": field}),
            ),
            (
                "add_reference",
                json!({"project_dir": dir, "env_name": "X", "slug": "openai/acme-web",
                       "profile": v}),
            ),
            (
                "run_with_secrets",
                json!({"project_dir": v, "argv": [py, "emit.py"]}),
            ),
            (
                "run_with_secrets",
                json!({"project_dir": dir, "argv": [py, "emit.py", v]}),
            ),
            ("run_with_secrets", json!({"project_dir": dir, "argv": [v]})),
            (
                "run_with_secrets",
                json!({"project_dir": dir, "argv": [py, "emit.py"], "profile": v}),
            ),
        ] {
            answers.push((tool, label, m.call(tool, args)));
        }
    }
    // Never printed: it could hold a fixture now.
    assert!(
        std::fs::read(&manifest_path).unwrap() == manifest,
        "a refused call changed envcloak.toml"
    );
    // The positive control: its one connection is the only one since.
    assert_eq!(
        control(&mut m, before),
        before + 1,
        "a refused call reached the daemon"
    );
    assert!(f.listed().is_empty(), "a refused call opened a request");
    for (tool, label, r) in &answers {
        assert_eq!(failed(r), "value_on_argv", "{tool} with {label}: {r}");
    }
    m.finish();
    f.sweep();
}

/// Host cancellation of a command that ignores `SIGTERM`, and whose forked
/// child does too: the server's first `SIGTERM` reaches it through
/// `envcloak run` and is ignored; its second makes `envcloak run` kill the
/// command's whole group (`SIGKILL` through the handle `envcloak run`
/// owns), so nothing holding the injected keys outlives the call (a lock
/// both hold is free again), and the server goes on answering. The end of
/// the session ends such a command the same way.
///
/// Mutations checked: `envcloak run` passing the second `SIGTERM` on as it
/// is (no `SIGKILL` in its place): the command and its child outlive
/// `envcloak run`, the lock stays held and this fails. The server sending
/// `SIGKILL` after one `SIGTERM` (no second): the same.
#[test]
fn a_cancelled_command_that_ignores_sigterm_is_ended_with_its_group() {
    let f = Fixture::new();
    let mut m = Mcp::start(&f.home, &f.project, &["--wait-ms", "1000"], &f.cs);
    m.initialize();
    let dir = f.project.to_str().unwrap();
    let py = python3();
    let files = outside_dir();
    let lock = files.path().join("lock");
    let ready = files.path().join("ready");
    let argv = json!([
        py.to_str().unwrap(),
        "hold.py",
        lock.to_str().unwrap(),
        ready.to_str().unwrap(),
        files.path().to_str().unwrap(),
        "stubborn"
    ]);
    let r = m.call(
        "run_with_secrets",
        json!({"project_dir": dir, "argv": argv}),
    );
    let id = structured(&r)["request"].as_str().unwrap().to_owned();
    f.approve(&id);
    let started = |m: &Mcp| {
        let end = Instant::now() + Duration::from_secs(60);
        while !ready.exists() {
            assert!(
                Instant::now() < end,
                "the command did not start: {}",
                m.stderr()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let held = std::fs::File::open(&lock).unwrap();
        assert!(!envcloak_sys::try_lock_exclusive(&held).unwrap());
        held
    };
    let freed = |held: &std::fs::File, what: &str| {
        let end = Instant::now() + Duration::from_secs(20);
        while !envcloak_sys::try_lock_exclusive(held).unwrap() {
            assert!(Instant::now() < end, "{what}");
            std::thread::sleep(Duration::from_millis(50));
        }
    };
    let call = m.call_async(
        "run_with_secrets",
        json!({"project_dir": dir, "argv": argv}),
    );
    let held = started(&m);
    m.send(
        &json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
        "params": {"requestId": call}}),
    );
    freed(
        &held,
        "a process of the cancelled command, which ignores SIGTERM, still holds its lock",
    );
    drop(held);
    let ping = m.request("ping", json!({}));
    assert_eq!(ping["result"], json!({}));
    assert!(
        m.kept.iter().all(|v| v["id"] != call),
        "the cancelled call was answered: {:?}",
        m.kept
    );

    // The session's end, with such a command running again.
    std::fs::remove_file(&ready).unwrap();
    m.call_async(
        "run_with_secrets",
        json!({"project_dir": dir, "argv": argv}),
    );
    let held = started(&m);
    let (_, _) = m.finish();
    freed(
        &held,
        "a process of the command, which ignores SIGTERM, outlived the session",
    );
    f.sweep();
}

/// A daemon slow to answer at the wait's deadline cannot push a tool's
/// answer past its host's cutoff: `run_with_secrets` gives `envcloak run`
/// its wait less a grace for the daemon's last answer (`--wait-grace`), so
/// the two together end within the wait. A stand-in for the daemon
/// answers the run's request as pending and then answers nothing more, so
/// every later call of the wait is held to its limit; each `--host`
/// default's answer, `daemon_unavailable`, still comes before that host's
/// cutoff, after it waited for the person.
///
/// Mutation checked: `--wait-grace` not passed (`envcloak run`'s 5 s for a
/// last answer): an unknown host's answer comes 12 s after its call, past
/// its 10 s cutoff, and this fails.
#[test]
fn a_daemon_that_stops_answering_cannot_hold_an_answer_past_the_cutoff() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    use envcloak_ipc::proto::{IncomingRequest, RunAnswer, result_frame};
    use envcloak_ipc::view::DecisionView;

    let f = Fixture::without_daemon();
    let run_dir = envcloak_testkit::daemon_run_dir(&f.home);
    std::fs::create_dir_all(&run_dir).unwrap();
    std::fs::set_permissions(&run_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let l = UnixListener::bind(envcloak_testkit::daemon_socket(&f.home)).unwrap();
    // The run's request is answered pending; every other call is read and
    // held, unanswered.
    std::thread::spawn(move || {
        let mut held = Vec::new();
        while let Ok((mut s, _)) = l.accept() {
            let Ok(frame) = envcloak_ipc::Frame::read_from(&mut s) else {
                continue;
            };
            let pending = RunAnswer::decided(DecisionView::Pending {
                request: "ABCDEFGH".to_owned(),
            });
            match IncomingRequest::parse(&frame) {
                Ok(r) if r.method == "run.request" => {
                    let _ = result_frame(r.id, &pending).unwrap().write_to(&mut s);
                }
                _ => held.push(s),
            }
        }
    });
    let py = python3();
    let hosts: [Option<&str>; 3] = [Some("claude-code"), Some("codex"), None];
    let runs: Vec<_> = hosts
        .iter()
        .map(|host| {
            let args: Vec<&str> = host.map_or_else(Vec::new, |h| vec!["--host", h]);
            let mut m = Mcp::start(&f.home, &f.project, &args, &f.cs);
            m.initialize();
            let start = Instant::now();
            let id = m.call_async(
                "run_with_secrets",
                json!({"project_dir": f.project.to_str().unwrap(),
                       "argv": [py.to_str().unwrap(), "emit.py", "OPENAI_API_KEY"]}),
            );
            let host = host.map(str::to_owned);
            std::thread::spawn(move || {
                let v = m.answer(id, Duration::from_secs(120));
                (host, m, v, start.elapsed())
            })
        })
        .collect();
    for run in runs {
        let (host, m, v, took) = run.join().unwrap();
        let host = host.as_deref();
        let s = structured(&v["result"]).clone();
        assert_eq!(s["status"], "refused", "{host:?}: {s}");
        assert_eq!(s["token"], "daemon_unavailable", "{host:?}: {s}");
        let cutoff = envcloak_agents::tool_timeouts::cutoff(host);
        let person = envcloak_agents::tool_timeouts::person_wait(
            envcloak_agents::tool_timeouts::default_wait(host),
        );
        assert!(
            took >= person && took < cutoff,
            "{host:?}: answered after {took:?}, waiting {person:?} for the person, with a \
             cutoff of {cutoff:?}"
        );
        println!(
            "measurement: run_with_secrets --host {host:?} with the daemon silent at the \
             deadline: answered after {took:?} (cutoff {cutoff:?})"
        );
        m.finish();
    }
    f.sweep();
}

/// A host that goes on sending but stops reading the answers: the answers
/// waiting for it are bounded, and once they reach their bound the session
/// ends. The server stops reading, stops the calls in hand and exits,
/// failing with `output_stalled`, within the time the end of a session
/// takes and with its memory bounded (a peak resident size under 64 MiB,
/// where the 20,000 answers asked for come to about 145 MB), never blocked
/// for ever on a write the host does not read.
///
/// Mutation checked: no bound on the answers waiting (every one queued):
/// the server reads on, its peak resident size passes 64 MiB, and it ends
/// as if the session had ended well; this fails.
#[test]
fn a_host_that_stops_reading_ends_the_session() {
    const DRIVE: &str = r#"import json, resource, subprocess, sys, threading
p = subprocess.Popen(sys.argv[1:], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
def send():
    try:
        p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}}).encode() + b"\n")
        for i in range(1, 20001):
            p.stdin.write(b'{"jsonrpc":"2.0","id":%d,"method":"tools/list"}\n' % i)
        p.stdin.close()
    except OSError:
        pass
threading.Thread(target=send, daemon=True).start()
err = []
reader = threading.Thread(target=lambda: err.append(p.stderr.read()), daemon=True)
reader.start()
try:
    code = p.wait(timeout=90)
    exited = True
except subprocess.TimeoutExpired:
    p.kill()
    code = p.wait()
    exited = False
reader.join(10)
rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
if sys.platform != "darwin":
    rss *= 1024
print(json.dumps({"exited": exited, "code": code, "rss": rss, "stderr": (err[0] if err else b"").decode("utf-8", "replace")}))
"#;
    let home = TestHome::new();
    let mut cmd = Command::new(python3());
    home.apply(&mut cmd)
        .args(["-c", DRIVE])
        .arg(common::cli())
        .arg("mcp")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = common::finish_within(cmd, Duration::from_secs(150));
    assert!(out.status.success(), "{}", stderr(&out));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["exited"], true, "the server did not end: {v}");
    assert_eq!(v["code"], 1, "{v}");
    let err = v["stderr"].as_str().unwrap();
    assert!(err.starts_with("envcloak: output_stalled: "), "{err}");
    assert_eq!(err.lines().count(), 1, "{err}");
    let rss = v["rss"].as_u64().unwrap();
    assert!(rss < 64 << 20, "peak resident size {rss} bytes");
}

/// `project_status` answers within its wait whatever pace the daemon keeps:
/// the project's check and every daemon call share one deadline, and the
/// daemon is asked on one connection bounded by it. A stand-in in front of
/// the real daemon passes every call on, but answers each `run.request` as
/// pending with a request of its own (so the server remembers three) and
/// each `pending.state` itself; once those are made, it answers each
/// `pending.state` 1.5 s late, inside the 2 s wait. The answer, a failure
/// with a fixed token, still comes within the wait and the 2 s margin. A
/// positive control first: at the daemon's pace the three are shown
/// pending.
///
/// Mutation checked: a connection of its own, given the whole wait, for
/// each request's state (as the tool asked before): the three states come
/// 4.5 s after the check, past the margin, and this fails.
#[test]
fn project_status_answers_within_its_wait_however_slow_the_daemon() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::atomic::{AtomicBool, Ordering};

    use envcloak_ipc::proto::{IncomingRequest, RunAnswer, result_frame};
    use envcloak_ipc::view::{DecisionView, PendingStateView};
    use envcloak_policy::{PendingId, PendingState};

    let real = Fixture::new();
    let f = Fixture::without_daemon();
    let run_dir = envcloak_testkit::daemon_run_dir(&f.home);
    std::fs::create_dir_all(&run_dir).unwrap();
    std::fs::set_permissions(&run_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let l = UnixListener::bind(envcloak_testkit::daemon_socket(&f.home)).unwrap();
    let upstream = envcloak_testkit::daemon_socket(&real.home);
    let slow = Arc::new(AtomicBool::new(false));
    let slowed = Arc::clone(&slow);
    std::thread::spawn(move || {
        while let Ok((mut s, _)) = l.accept() {
            let upstream = upstream.clone();
            let slow = Arc::clone(&slowed);
            std::thread::spawn(move || {
                let mut up: Option<UnixStream> = None;
                while let Ok(frame) = envcloak_ipc::Frame::read_from(&mut s) {
                    let Ok(r) = IncomingRequest::parse(&frame) else {
                        return;
                    };
                    let answer = match r.method {
                        "run.request" => {
                            let pending = DecisionView::Pending {
                                request: PendingId::generate().to_string(),
                            };
                            result_frame(r.id, &RunAnswer::decided(pending)).unwrap()
                        }
                        "pending.state" => {
                            // The daemon's pace, slowed: inside the wait.
                            if slow.load(Ordering::SeqCst) {
                                std::thread::sleep(Duration::from_millis(1500));
                            }
                            let state = PendingStateView {
                                state: PendingState::Pending,
                            };
                            result_frame(r.id, &state).unwrap()
                        }
                        _ => {
                            let u = match &mut up {
                                Some(u) => u,
                                None => match UnixStream::connect(&upstream) {
                                    Ok(u) => up.insert(u),
                                    Err(_) => return,
                                },
                            };
                            if frame.write_to(u).is_err() {
                                return;
                            }
                            match envcloak_ipc::Frame::read_from(u) {
                                Ok(a) => a,
                                Err(_) => return,
                            }
                        }
                    };
                    if answer.write_to(&mut s).is_err() {
                        return;
                    }
                }
            });
        }
    });
    let wait = Duration::from_millis(2000);
    let mut m = Mcp::start(&f.home, &f.project, &["--wait-ms", "2000"], &f.cs);
    m.initialize();
    let dir = f.project.to_str().unwrap();
    let py = python3();
    for _ in 0..3 {
        let r = m.call(
            "run_with_secrets",
            json!({"project_dir": dir, "argv": [py.to_str().unwrap(), "emit.py", "OPENAI_API_KEY"]}),
        );
        assert_eq!(structured(&r)["status"], "approval_required", "{r}");
    }
    let status = structured(&m.call("project_status", json!({"project_dir": dir}))).clone();
    assert_eq!(
        status["pending_requests"].as_array().unwrap().len(),
        3,
        "{status}"
    );
    assert_eq!(status["vault"], "unlocked", "{status}");
    slow.store(true, Ordering::SeqCst);
    let start = Instant::now();
    let r = m.call("project_status", json!({"project_dir": dir}));
    let took = start.elapsed();
    println!(
        "measurement: project_status with the daemon's states 1.5 s late: answered after {took:?}"
    );
    assert!(
        took < wait + envcloak_agents::tool_timeouts::MARGIN,
        "answered after {took:?}, with a wait of {wait:?}: {r}"
    );
    assert_eq!(failed(&r), "daemon_unavailable", "{r}");
    m.finish();
    f.sweep();
    real.sweep();
}
