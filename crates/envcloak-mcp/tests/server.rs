//! The server in process, over in-memory pipes: the session's lifecycle,
//! the call queue's bounds, cancellation, and what `tools/list` shows,
//! with tools of the test's own where a call must block (barriers, never
//! sleeps). The real binary, the daemon and the real tools are tested in
//! crates/envcloak-cli/tests/mcp.rs and crates/envcloak-e2e.
#![allow(clippy::unwrap_used)]

use std::io::{self, Read, Write};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Barrier, Mutex};
use std::time::{Duration, Instant};

use envcloak_mcp::{
    Annotations, Call, Ctx, QUEUE, Router, Server, Tool, ToolResult, ToolSchema, WORKERS,
};
use serde_json::{Map, Value, json};

/// The server's standard input: chunks the test sends, then end of input
/// when the sender is dropped.
struct Input {
    rx: Receiver<Vec<u8>>,
    held: Vec<u8>,
}

impl Read for Input {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.held.is_empty() {
            match self.rx.recv() {
                Ok(v) => self.held = v,
                Err(_) => return Ok(0),
            }
        }
        let n = buf.len().min(self.held.len());
        buf[..n].copy_from_slice(&self.held[..n]);
        self.held.drain(..n);
        Ok(n)
    }
}

/// The server's standard output, as lines the test reads.
struct Output {
    tx: Sender<Vec<u8>>,
}

impl Write for Output {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tx
            .send(buf.to_vec())
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A server running on its own thread.
struct Running {
    input: Option<Sender<Vec<u8>>>,
    output: Receiver<Vec<u8>>,
    pending: Vec<u8>,
    done: Option<std::thread::JoinHandle<io::Result<()>>>,
}

impl Running {
    fn start(server: Server) -> Running {
        let (in_tx, in_rx) = mpsc::channel();
        let (out_tx, out_rx) = mpsc::channel();
        let ctx = Ctx::new("/nonexistent/envcloak".into(), None, Duration::from_secs(1));
        let done = std::thread::spawn(move || {
            server.run(
                Input {
                    rx: in_rx,
                    held: Vec::new(),
                },
                Output { tx: out_tx },
                ctx,
            )
        });
        Running {
            input: Some(in_tx),
            output: out_rx,
            pending: Vec::new(),
            done: Some(done),
        }
    }

    fn send_raw(&self, bytes: &[u8]) {
        self.input.as_ref().unwrap().send(bytes.to_vec()).unwrap();
    }

    fn send(&self, v: &Value) {
        let mut line = serde_json::to_vec(v).unwrap();
        line.push(b'\n');
        self.send_raw(&line);
    }

    /// The next message the server wrote, within `limit`.
    fn next(&mut self, limit: Duration) -> Option<Value> {
        let deadline = std::time::Instant::now() + limit;
        loop {
            if let Some(i) = self.pending.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = self.pending.drain(..=i).collect();
                return Some(serde_json::from_slice(&line).unwrap());
            }
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            match self.output.recv_timeout(left) {
                Ok(chunk) => self.pending.extend(chunk),
                Err(_) => return None,
            }
        }
    }

    fn expect(&mut self) -> Value {
        self.next(Duration::from_secs(30))
            .unwrap_or_else(|| panic!("no answer"))
    }

    fn initialize(&mut self) {
        self.send(&json!({"jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                       "clientInfo": {"name": "test", "version": "1"}}}));
        let v = self.expect();
        assert_eq!(v["result"]["protocolVersion"], "2025-11-25");
        self.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
    }

    fn call(&self, id: i64, name: &str, args: Value) {
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": name, "arguments": args}}));
    }

    /// Ends the input and waits for the server to return.
    fn end(mut self) -> Vec<Value> {
        drop(self.input.take());
        self.done.take().unwrap().join().unwrap().unwrap();
        let mut rest = Vec::new();
        while let Some(v) = self.next(Duration::from_millis(100)) {
            rest.push(v);
        }
        rest
    }
}

fn schema(name: &'static str) -> ToolSchema {
    ToolSchema {
        name,
        title: "test",
        description: "test",
        input: json!({"type": "object", "additionalProperties": true}),
        output: json!({"type": "object"}),
        annotations: Annotations::default(),
    }
}

/// A tool whose calls each say they started and then wait at `gate`, so a
/// test knows when calls are running and decides when they end.
struct Gated {
    name: &'static str,
    gate: Arc<Barrier>,
    started: Mutex<Sender<()>>,
}

impl Tool for Gated {
    fn schema(&self) -> ToolSchema {
        schema(self.name)
    }

    fn call(&self, _: &Map<String, Value>, _: &Ctx, _: &Call) -> ToolResult {
        let _ = self.started.lock().unwrap().send(());
        self.gate.wait();
        ToolResult::Ok(json!({"done": true}))
    }
}

/// A tool that answers at once.
struct Echo(&'static str);

impl Tool for Echo {
    fn schema(&self) -> ToolSchema {
        schema(self.0)
    }

    fn call(&self, _: &Map<String, Value>, _: &Ctx, _: &Call) -> ToolResult {
        ToolResult::Ok(json!({"tool": self.0}))
    }
}

/// A tool that runs until its call is cancelled, says it saw the
/// cancellation, then answers.
struct UntilCancelled {
    started: Mutex<Sender<()>>,
    saw_cancel: Mutex<Sender<()>>,
}

impl Tool for UntilCancelled {
    fn schema(&self) -> ToolSchema {
        schema("until_cancelled")
    }

    fn call(&self, _: &Map<String, Value>, _: &Ctx, call: &Call) -> ToolResult {
        let _ = self.started.lock().unwrap().send(());
        while !call.cancelled() {
            std::thread::sleep(Duration::from_millis(5));
        }
        let _ = self.saw_cancel.lock().unwrap().send(());
        ToolResult::Ok(json!({"answered_after_cancel": true}))
    }
}

#[test]
fn requests_follow_the_lifecycle() {
    let mut r = Running::start(Server::new());
    // Before initialize: ping only.
    r.send(&json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}));
    assert_eq!(r.expect(), json!({"jsonrpc": "2.0", "id": 1, "result": {}}));
    r.send(&json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}));
    assert_eq!(r.expect()["error"]["code"], -32600);
    // An older version this server speaks is answered with that version;
    // one it does not, with its latest.
    r.send(&json!({"jsonrpc": "2.0", "id": 3, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}}}));
    let v = r.expect();
    assert_eq!(v["id"], 3);
    assert_eq!(v["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(
        v["result"]["capabilities"],
        json!({"tools": {"listChanged": false}})
    );
    r.send(&json!({"jsonrpc": "2.0", "id": 4, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18"}}));
    assert_eq!(r.expect()["error"]["code"], -32600);
    for (id, method) in [
        (5, "resources/list"),
        (6, "prompts/list"),
        (7, "logging/setLevel"),
    ] {
        r.send(&json!({"jsonrpc": "2.0", "id": id, "method": method}));
        let v = r.expect();
        assert_eq!(v["id"], id);
        assert_eq!(v["error"]["code"], -32601, "{method}");
    }
    r.send(&json!({"jsonrpc": "2.0", "id": 8, "method": "tools/list", "params": {"cursor": "x"}}));
    assert_eq!(r.expect()["error"]["code"], -32602);
    // Notifications are never answered; a client's response is dropped.
    r.send(&json!({"jsonrpc": "2.0", "method": "notifications/whatever"}));
    r.send(&json!({"jsonrpc": "2.0", "id": 99, "result": {}}));
    r.send(&json!({"jsonrpc": "2.0", "id": 9, "method": "ping"}));
    assert_eq!(r.expect()["id"], 9);
    assert!(r.end().is_empty());

    let mut r = Running::start(Server::new());
    r.send(
        &json!({"jsonrpc": "2.0", "id": "a-1", "method": "initialize",
        "params": {"protocolVersion": "1999-01-01"}}),
    );
    let v = r.expect();
    assert_eq!(v["id"], "a-1");
    assert_eq!(v["result"]["protocolVersion"], "2025-11-25");
    r.end();
}

/// `tools/list` shows the five M2 tools and nothing else: no reveal or
/// doctor tool, and no `usage_summary` before M4 (gates 34, 35, 36). A
/// tool registered but unlisted is answered as a tool that does not exist.
#[test]
fn only_listed_tools_are_shown_and_called() {
    let mut r = Running::start(Server::new());
    r.initialize();
    r.send(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}));
    let v = r.expect();
    let names: Vec<&str> = v["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "list_secrets",
            "project_status",
            "add_reference",
            "run_with_secrets",
            "request_new_secret"
        ]
    );
    r.end();

    let mut router = Router::new();
    router.register(Box::new(Echo("shown"))).unwrap();
    router.register_unlisted(Box::new(Echo("hidden"))).unwrap();
    let mut r = Running::start(Server::with_router(router));
    r.initialize();
    r.call(1, "shown", json!({}));
    assert_eq!(r.expect()["result"]["structuredContent"]["tool"], "shown");
    let mut answers = Vec::new();
    for (id, name) in [(2, "hidden"), (3, "nothing")] {
        r.call(id, name, json!({}));
        let mut v = r.expect();
        assert_eq!(v["id"], id);
        v["id"] = Value::Null;
        answers.push(v);
    }
    assert_eq!(answers[0], answers[1], "an unlisted tool is told apart");
    assert_eq!(answers[0]["error"]["code"], -32602);
    r.end();
}

/// At most [`WORKERS`] calls run and [`QUEUE`] more wait; one beyond that
/// is answered `busy` at once, and every other call is answered once the
/// running ones end.
#[test]
fn calls_beyond_the_queue_are_answered_busy() {
    let gate = Arc::new(Barrier::new(WORKERS + 1));
    let (started_tx, started) = mpsc::channel();
    let mut router = Router::new();
    router
        .register(Box::new(Gated {
            name: "gated",
            gate: Arc::clone(&gate),
            started: Mutex::new(started_tx),
        }))
        .unwrap();
    let mut r = Running::start(Server::with_router(router));
    r.initialize();
    let in_hand = WORKERS + QUEUE;
    for id in 0..WORKERS {
        r.call(id as i64, "gated", json!({}));
    }
    // All workers are inside a call now.
    for _ in 0..WORKERS {
        started.recv_timeout(Duration::from_secs(30)).unwrap();
    }
    for id in WORKERS..in_hand {
        r.call(id as i64, "gated", json!({}));
    }
    r.call(1000, "gated", json!({}));
    let v = r.expect();
    assert_eq!(v["id"], 1000);
    assert_eq!(v["error"]["code"], -32008);
    // Each round of the barrier ends one call per worker.
    let mut answered = Vec::new();
    for _ in 0..in_hand / WORKERS {
        gate.wait();
        for _ in 0..WORKERS {
            let v = r.expect();
            assert_eq!(v["result"]["structuredContent"]["done"], true);
            answered.push(v["id"].as_i64().unwrap());
        }
        if answered.len() < in_hand {
            for _ in 0..WORKERS {
                started.recv_timeout(Duration::from_secs(30)).unwrap();
            }
        }
    }
    answered.sort_unstable();
    assert_eq!(answered, (0..in_hand as i64).collect::<Vec<_>>());
    assert!(r.end().is_empty());
}

/// A cancelled call is answered nothing, whether it was running or still
/// waiting; the server goes on answering the rest. The running call sees
/// its cancellation while the session goes on, not at its end, when every
/// call in hand is stopped anyway (verifier, M2-06 round 2).
///
/// Mutation checked: `notifications/cancelled` ignored (no
/// `inflight.cancel`): the call never sees a cancellation before the end
/// of input, and this fails.
#[test]
fn a_cancelled_call_is_answered_nothing() {
    let (started_tx, started) = mpsc::channel();
    let (saw_tx, saw_cancel) = mpsc::channel();
    let mut router = Router::new();
    router
        .register(Box::new(UntilCancelled {
            started: Mutex::new(started_tx),
            saw_cancel: Mutex::new(saw_tx),
        }))
        .unwrap();
    router.register(Box::new(Echo("echo"))).unwrap();
    let mut r = Running::start(Server::with_router(router));
    r.initialize();
    r.call(1, "until_cancelled", json!({}));
    started.recv_timeout(Duration::from_secs(30)).unwrap();
    r.send(
        &json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
        "params": {"requestId": 1, "reason": "test"}}),
    );
    saw_cancel
        .recv_timeout(Duration::from_secs(30))
        .expect("the running call never saw its cancellation");
    // An id that is not in hand, and one of a shape not taken, change
    // nothing.
    r.send(
        &json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
        "params": {"requestId": 77}}),
    );
    r.send(
        &json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
        "params": {"requestId": {"x": 1}}}),
    );
    r.call(2, "echo", json!({}));
    let v = r.expect();
    assert_eq!(v["id"], 2, "{v}");
    // Nothing more comes for the cancelled call, now or at the end.
    assert!(r.next(Duration::from_millis(500)).is_none());
    let rest = r.end();
    assert!(rest.iter().all(|v| v["id"] != 1), "{rest:?}");
}

/// A request whose id is in hand already is refused, and the first call
/// is still answered once.
#[test]
fn an_id_in_hand_is_not_taken_twice() {
    let gate = Arc::new(Barrier::new(2));
    let (started_tx, started) = mpsc::channel();
    let mut router = Router::new();
    router
        .register(Box::new(Gated {
            name: "gated",
            gate: Arc::clone(&gate),
            started: Mutex::new(started_tx),
        }))
        .unwrap();
    let mut r = Running::start(Server::with_router(router));
    r.initialize();
    r.call(5, "gated", json!({}));
    started.recv_timeout(Duration::from_secs(30)).unwrap();
    r.call(5, "gated", json!({}));
    let v = r.expect();
    assert_eq!(v["id"], 5);
    assert_eq!(v["error"]["code"], -32600);
    gate.wait();
    let v = r.expect();
    assert_eq!(v["result"]["structuredContent"]["done"], true);
    assert!(r.end().is_empty());
}

/// The host closes its end of standard output while it keeps standard
/// input open and sends nothing more, with one call answering and another
/// still running: the answer's write fails, and the server ends the
/// session at once, cancelling the running call, without waiting for input
/// that may never come (Codex review of M2-06, medium).
///
/// Mutation checked: the writer's failure not waking the server (its
/// `on_close` doing nothing): the server waits for input, the running call
/// is never cancelled, and this fails.
#[test]
fn closed_output_ends_the_session_while_input_stays_open() {
    let gate = Arc::new(Barrier::new(2));
    let (started_tx, started) = mpsc::channel();
    let (saw_tx, saw_cancel) = mpsc::channel();
    let mut router = Router::new();
    router
        .register(Box::new(Gated {
            name: "gated",
            gate: Arc::clone(&gate),
            started: Mutex::new(started_tx.clone()),
        }))
        .unwrap();
    router
        .register(Box::new(UntilCancelled {
            started: Mutex::new(started_tx),
            saw_cancel: Mutex::new(saw_tx),
        }))
        .unwrap();
    let mut r = Running::start(Server::with_router(router));
    r.initialize();
    r.call(1, "gated", json!({}));
    r.call(2, "until_cancelled", json!({}));
    for _ in 0..2 {
        started.recv_timeout(Duration::from_secs(30)).unwrap();
    }
    // The host's end of standard output closes; its input stays open.
    let Running {
        input,
        output,
        done,
        ..
    } = r;
    drop(output);
    // The gated call answers now, and the write fails.
    gate.wait();
    let done = done.unwrap();
    let end = Instant::now() + Duration::from_secs(30);
    while !done.is_finished() {
        assert!(
            Instant::now() < end,
            "the server went on waiting for input after its output closed"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    done.join().unwrap().unwrap();
    saw_cancel
        .recv_timeout(Duration::from_secs(1))
        .expect("the running call was not stopped");
    drop(input);
}
