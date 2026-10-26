//! M2b-06 tests: the D-28 test-session adapter reference middleware
//! (`integrations/test-session/node/index.cjs` and the sign-in fixture app)
//! and the MCP sign-in tools (`request_sign_in`, `sign_in_status`,
//! `cancel_sign_in`, `end_sign_in_session`).
#![allow(clippy::unwrap_used)]

use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use envcloak_ipc::frame::Frame;
use envcloak_ipc::paths::RunPaths;
use envcloak_ipc::proto::{
    IncomingRequest, Method, SigninCancel, SigninEnd, SigninRequest, SigninStatus, result_frame,
};
use envcloak_ipc::view::SigninStatusView;
use envcloak_mcp::tools::signin::{
    is_forbidden_signin_arg, validate_operation_key, validate_request_id, validate_role,
    validate_session_id, validate_target,
};
use envcloak_mcp::{Ctx, RegisterError, Router, Server, SignInTools, ToolSchema};
use envcloak_testkit::signin::{
    SigninFixture, browser_versions_path, http_request, read_browser_pins, resolve_node_binary,
    sign_test_session_request,
};
use envcloak_testkit::{Canary, assert_no_canary, canaries, fresh_seed, labels};
use serde_json::{Value, json};

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

struct Running {
    input: Option<Sender<Vec<u8>>>,
    output: Receiver<Vec<u8>>,
    pending: Vec<u8>,
    transcript: Vec<u8>,
    done: Option<std::thread::JoinHandle<io::Result<()>>>,
}

impl Running {
    fn start(server: Server, ctx: Ctx) -> Running {
        let (in_tx, in_rx) = mpsc::channel();
        let (out_tx, out_rx) = mpsc::channel();
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
            transcript: Vec::new(),
            done: Some(done),
        }
    }

    fn send(&self, v: &Value) {
        let mut line = serde_json::to_vec(v).unwrap();
        line.push(b'\n');
        self.input.as_ref().unwrap().send(line).unwrap();
    }

    fn next(&mut self, limit: Duration) -> Option<Value> {
        let deadline = std::time::Instant::now() + limit;
        loop {
            if let Some(i) = self.pending.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = self.pending.drain(..=i).collect();
                self.transcript.extend_from_slice(&line);
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
        self.next(Duration::from_secs(15))
            .unwrap_or_else(|| panic!("no answer from MCP server"))
    }

    fn initialize(&mut self) {
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"}
            }
        }));
        let v = self.expect();
        assert_eq!(v["result"]["protocolVersion"], "2025-11-25");
        self.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
    }

    fn call(&mut self, id: i64, name: &str, args: Value) -> Value {
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {"name": name, "arguments": args}
        }));
        self.expect()
    }

    fn end(mut self) -> Vec<u8> {
        drop(self.input.take());
        self.done.take().unwrap().join().unwrap().unwrap();
        while self.next(Duration::from_millis(50)).is_some() {}
        self.transcript
    }
}

fn make_isolated_run_paths() -> (tempfile::TempDir, RunPaths) {
    let tmp = tempfile::Builder::new()
        .prefix("ec-mcp-si-")
        .tempdir_in("/tmp")
        .unwrap();
    let dir = tmp.path().join("run");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = dir.join("envcloakd.sock");
    let lock = dir.join("envcloakd.lock");
    (
        tmp,
        RunPaths {
            dir,
            socket,
            lock,
            fallback: false,
        },
    )
}

fn tool_err_token(res: &Value) -> String {
    let text = res["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("expected tool error content text in {res}"));
    let parsed: Value = serde_json::from_str(text)
        .unwrap_or_else(|e| panic!("expected JSON tool error in {text:?}: {e}"));
    parsed["error"]
        .as_str()
        .unwrap_or_else(|| panic!("expected error field in {parsed}"))
        .to_owned()
}

fn listed_signin_schemas() -> Value {
    let mut router = Router::new();
    SignInTools::register(&mut router, true).unwrap();
    let tools: Vec<Value> = router.list().iter().map(ToolSchema::to_json).collect();
    json!({ "tools": tools })
}

#[test]
fn signin_tools_descriptions_and_schemas_match_snapshot() {
    let v = listed_signin_schemas();
    let got = serde_json::to_string_pretty(&v).unwrap() + "\n";
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/snapshots/signin-tools.json");
    if std::env::var_os("ENVCLOAK_SNAPSHOT_UPDATE").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &got).unwrap();
    }
    let want = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("no snapshot: run with ENVCLOAK_SNAPSHOT_UPDATE=1"));
    assert_eq!(
        got, want,
        "signin tools schema snapshot changed; review it and update with ENVCLOAK_SNAPSHOT_UPDATE=1"
    );

    let tools = v["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        [
            "request_sign_in",
            "sign_in_status",
            "cancel_sign_in",
            "end_sign_in_session"
        ]
    );

    for t in tools {
        let name = t["name"].as_str().unwrap();
        let desc = t["description"].as_str().unwrap();
        assert_eq!(t["inputSchema"]["type"], "object", "{name}");
        assert_eq!(t["inputSchema"]["additionalProperties"], false, "{name}");
        assert_eq!(t["outputSchema"]["type"], "object", "{name}");
        assert_eq!(t["outputSchema"]["additionalProperties"], false, "{name}");

        // R-M2b-09 / SPEC §6.8: every sign-in tool description states plainly
        // that sign-in uses stored credentials after the person approves in
        // EnvCloak, that the resulting session acts as that account, and that
        // cancelling a tool call only stops waiting while cancel_sign_in ends
        // the operation.
        assert!(desc.contains("stored credentials"), "{name}: {desc}");
        assert!(desc.contains("approv"), "{name}: {desc}");
        assert!(desc.contains("acts as that account"), "{name}: {desc}");
        assert!(desc.contains("stops waiting"), "{name}: {desc}");
        assert!(desc.contains("cancel_sign_in"), "{name}: {desc}");

        let a = &t["annotations"];
        assert!(
            !(a["readOnlyHint"] == true && a["destructiveHint"] == true),
            "{name} carries both read-only and destructive hints"
        );
        match name {
            "request_sign_in" => {
                assert!(a.get("readOnlyHint").is_none(), "{name}");
                assert_eq!(a["destructiveHint"], true, "{name}");
                assert_eq!(a["idempotentHint"], true, "{name}");
                assert_eq!(a["openWorldHint"], true, "{name}");
            }
            "sign_in_status" => {
                assert_eq!(a["readOnlyHint"], true, "{name}");
                assert!(a.get("destructiveHint").is_none(), "{name}");
            }
            "cancel_sign_in" | "end_sign_in_session" => {
                assert_eq!(a["readOnlyHint"], false, "{name}");
                assert_eq!(a["destructiveHint"], false, "{name}");
                assert_eq!(a["idempotentHint"], true, "{name}");
            }
            _ => panic!("unexpected tool {name}"),
        }
    }
}

/// With `SignInTools` registered unlisted in `Server::new()`, `tools/list`
/// omits all four sign-in tools, `tools/call` for `request_sign_in` (and the
/// other three) returns the exact same unknown-tool error as a made-up tool
/// name, and no `signin.request` reaches the daemon.
///
/// Mutation checked: registering `SignInTools` with `listed = true` or
/// dispatching unlisted tools in `Router::call` causes this test to fail.
#[test]
fn unlisted_signin_tools_return_same_unknown_tool_error_and_never_contact_daemon() {
    // Verify `SignInTools` are registered in the unlisted table so duplicate
    // registration is rejected.
    let mut router = Router::new();
    SignInTools::register(&mut router, false).unwrap();
    let dup: Result<(), RegisterError> = SignInTools::register(&mut router, false);
    assert!(dup.is_err());

    let (_tmp, paths) = make_isolated_run_paths();
    let listener = UnixListener::bind(&paths.socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let daemon_hits = Arc::new(AtomicUsize::new(0));
    let hits_bg = Arc::clone(&daemon_hits);
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_bg = Arc::clone(&stop);
    let spy = std::thread::spawn(move || {
        while !stop_bg.load(Ordering::Relaxed) {
            if listener.accept().is_ok() {
                hits_bg.fetch_add(1, Ordering::SeqCst);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    });

    let ctx = Ctx::new("/nonexistent/envcloak".into(), None, Duration::from_secs(2))
        .with_run_paths(paths);
    let mut r = Running::start(Server::new(), ctx);
    r.initialize();

    r.send(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}));
    let listed = r.expect();
    let names: Vec<&str> = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    for signin_name in [
        "request_sign_in",
        "sign_in_status",
        "cancel_sign_in",
        "end_sign_in_session",
    ] {
        assert!(
            !names.contains(&signin_name),
            "unexpectedly listed {signin_name}"
        );
    }

    let made_up = r.call(
        2,
        "made_up_nonexistent_tool",
        json!({"target": "acme-console", "operation_key": "op-1"}),
    );
    assert_eq!(made_up["error"]["code"], -32602);
    assert!(made_up.get("result").is_none());

    for (id, name, args) in [
        (
            3,
            "request_sign_in",
            json!({"target": "acme-console", "operation_key": "op-1"}),
        ),
        (
            4,
            "sign_in_status",
            json!({"request": "0123456789abcdef0123456789abcdef"}),
        ),
        (
            5,
            "cancel_sign_in",
            json!({"request": "0123456789abcdef0123456789abcdef"}),
        ),
        (6, "end_sign_in_session", json!({"session": "ctx-1"})),
    ] {
        let got = r.call(id, name, args);
        assert_eq!(
            got["error"], made_up["error"],
            "{name} must return the exact same unknown-tool error as a made-up tool name"
        );
        assert!(got.get("result").is_none());
    }

    let _ = r.end();
    stop.store(true, Ordering::Relaxed);
    spy.join().unwrap();
    assert_eq!(
        daemon_hits.load(Ordering::SeqCst),
        0,
        "no connection or signin.request may reach the daemon when sign-in tools are unlisted"
    );
}

/// URL, script, callback, CDP-address, and secret-shaped arguments are refused
/// unechoed before any daemon connection is attempted (`R-M2b-07`, `L-06`).
///
/// Mutation checked: removing `is_forbidden_signin_arg` or allowing `:`/`/` in
/// `validate_target` / `validate_role` / `validate_operation_key` causes this
/// test to fail.
#[test]
fn url_script_callback_cdp_and_secret_arguments_refused_unechoed() {
    let cs: Vec<Canary> = canaries(fresh_seed());
    let (_tmp, paths) = make_isolated_run_paths();
    let listener = UnixListener::bind(&paths.socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let daemon_hits = Arc::new(AtomicUsize::new(0));

    let project_tmp = tempfile::Builder::new()
        .prefix("ec-proj-")
        .tempdir_in("/tmp")
        .unwrap();
    std::fs::write(
        project_tmp.path().join("envcloak.toml"),
        "[project]\nname = \"acme-web\"\n[env]\n",
    )
    .unwrap();
    let project_dir_str = project_tmp.path().to_string_lossy().into_owned();

    let mut router = Router::new();
    SignInTools::register(&mut router, true).unwrap();
    let ctx = Ctx::new("/nonexistent/envcloak".into(), None, Duration::from_secs(2))
        .with_run_paths(paths);
    let mut r = Running::start(Server::with_router(router), ctx);
    r.initialize();

    let forbidden_inputs = [
        "https://evil.example/login",
        "http://127.0.0.1:8080/callback",
        "ws://127.0.0.1:9222/devtools/browser/1",
        "wss://evil.example/socket",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "file:///etc/passwd",
        "chrome://settings",
        "devtools://devtools/bundled/inspector.html",
        "<script>fetch('https://evil.example')</script>",
        "eval(document.cookie)",
        "onload=alert(1)",
        "acme?callback=https://evil.example",
        "acme&redirect_uri=http://evil.localhost",
        "acme#return_to=evil",
        "--remote-debugging-port=9222",
        "--remote-debugging-pipe",
        "127.0.0.1:9222/json/version",
        "localhost:9222/devtools/page/1",
        "[::1]:9222",
    ];

    let mut id = 10;
    for bad in forbidden_inputs {
        assert!(
            is_forbidden_signin_arg(bad),
            "expected {bad:?} to be flagged as forbidden"
        );
        for args in [
            json!({
                "target": bad,
                "operation_key": "valid-op-key-1",
                "project_dir": project_dir_str,
            }),
            json!({
                "target": "acme-console",
                "role": bad,
                "operation_key": "valid-op-key-1",
                "project_dir": project_dir_str,
            }),
            json!({
                "target": "acme-console",
                "operation_key": bad,
                "project_dir": project_dir_str,
            }),
        ] {
            id += 1;
            let res = r.call(id, "request_sign_in", args);
            assert_eq!(res["result"]["isError"], true, "accepted {bad:?}: {res}");
            assert_eq!(
                tool_err_token(&res),
                "invalid_params",
                "wrong error token for {bad:?}: {res}"
            );
            let serialized = serde_json::to_string(&res).unwrap();
            assert!(
                !serialized.contains(bad),
                "forbidden input {bad:?} was echoed in error response: {serialized}"
            );
        }

        for tool in ["sign_in_status", "cancel_sign_in"] {
            id += 1;
            let res = r.call(id, tool, json!({"request": bad}));
            assert_eq!(res["result"]["isError"], true, "{tool} accepted {bad:?}");
            assert_eq!(tool_err_token(&res), "invalid_params");
            let serialized = serde_json::to_string(&res).unwrap();
            assert!(!serialized.contains(bad));
        }

        id += 1;
        let res = r.call(id, "end_sign_in_session", json!({"session": bad}));
        assert_eq!(
            res["result"]["isError"], true,
            "end_sign_in_session accepted {bad:?}"
        );
        assert_eq!(tool_err_token(&res), "invalid_params");
        let serialized = serde_json::to_string(&res).unwrap();
        assert!(!serialized.contains(bad));
    }

    // Secret-shaped canary inputs must fail with value_on_argv and never be echoed.
    for c in &cs {
        if !matches!(
            c.label.as_str(),
            labels::OPENAI_API_KEY
                | labels::OPENAI_API_KEY_ROTATED
                | labels::STRIPE_SECRET_KEY
                | labels::GITHUB_TOKEN
        ) {
            continue;
        }
        for (tool, args) in [
            (
                "request_sign_in",
                json!({
                    "target": c.as_str(),
                    "operation_key": "op-1",
                    "project_dir": project_dir_str,
                }),
            ),
            (
                "request_sign_in",
                json!({
                    "target": "acme-console",
                    "operation_key": c.as_str(),
                    "project_dir": project_dir_str,
                }),
            ),
            ("sign_in_status", json!({"request": c.as_str()})),
            ("cancel_sign_in", json!({"request": c.as_str()})),
            ("end_sign_in_session", json!({"session": c.as_str()})),
        ] {
            id += 1;
            let res = r.call(id, tool, args);
            assert_eq!(res["result"]["isError"], true);
            assert_eq!(
                tool_err_token(&res),
                "value_on_argv",
                "{tool} for {}",
                c.label
            );
        }
    }

    let transcript = r.end();
    assert_no_canary(&transcript, &cs);
    assert!(
        listener.accept().is_err() && daemon_hits.load(Ordering::SeqCst) == 0,
        "invalid or forbidden arguments must never contact the daemon"
    );
}

#[test]
fn fuzz_signin_argument_grammars_accept_valid_and_reject_injections() {
    for valid_slash_target in ["acme/local", "acme.org/staging_1", "stripe/dev-01"] {
        assert!(
            validate_target(valid_slash_target).is_ok(),
            "expected {valid_slash_target:?} to be accepted"
        );
    }
    for invalid_target in [
        "http://acme.localhost",
        "acme//local",
        "acme/../local",
        "/acme",
        "acme/",
        "localhost:9222",
    ] {
        assert!(
            validate_target(invalid_target).is_err(),
            "expected {invalid_target:?} to be rejected"
        );
    }

    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next_u64 = || -> u64 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    const TARGET_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789-";
    const TARGET_EDGE: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    const ROLE_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
    const ROLE_START: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const HEX_CHARS: &[u8] = b"0123456789abcdef";

    for i in 0..2_000usize {
        let t_len = 2 + (next_u64() as usize % 30);
        let mut valid_target = String::with_capacity(t_len);
        valid_target.push(TARGET_EDGE[next_u64() as usize % TARGET_EDGE.len()] as char);
        for _ in 1..(t_len - 1) {
            valid_target.push(TARGET_CHARS[next_u64() as usize % TARGET_CHARS.len()] as char);
        }
        valid_target.push(TARGET_EDGE[next_u64() as usize % TARGET_EDGE.len()] as char);

        let r_len = 1 + (next_u64() as usize % 32);
        let mut valid_role = String::with_capacity(r_len);
        valid_role.push(ROLE_START[next_u64() as usize % ROLE_START.len()] as char);
        for _ in 1..r_len {
            valid_role.push(ROLE_CHARS[next_u64() as usize % ROLE_CHARS.len()] as char);
        }

        let k_len = 1 + (next_u64() as usize % 64);
        let mut valid_op_key = String::with_capacity(k_len);
        for _ in 0..k_len {
            valid_op_key.push(ROLE_CHARS[next_u64() as usize % ROLE_CHARS.len()] as char);
        }

        let mut valid_req = String::with_capacity(32);
        for _ in 0..32 {
            valid_req.push(HEX_CHARS[next_u64() as usize % HEX_CHARS.len()] as char);
        }
        let valid_ctx = 1 + (next_u64() % 1_000_000);

        assert!(
            validate_target(&valid_target).is_ok(),
            "case {i}: {valid_target}"
        );
        assert!(validate_role(&valid_role).is_ok(), "case {i}: {valid_role}");
        assert!(
            validate_operation_key(&valid_op_key).is_ok(),
            "case {i}: {valid_op_key}"
        );
        assert!(
            validate_request_id(&valid_req).is_ok(),
            "case {i}: {valid_req}"
        );
        assert!(
            validate_session_id(&valid_req).is_ok(),
            "case {i}: {valid_req}"
        );
        assert!(validate_session_id(&format!("ctx-{valid_ctx}")).is_ok());

        for injected in [
            format!("https://{valid_target}"),
            format!("{valid_role}<script>"),
            format!("{valid_op_key}?callback=1"),
            format!("--remote-debugging-port={valid_ctx}"),
            format!("127.0.0.1:9222/{valid_target}"),
        ] {
            assert!(validate_target(&injected).is_err());
            assert!(validate_role(&injected).is_err());
            assert!(validate_operation_key(&injected).is_err());
            assert!(validate_request_id(&injected).is_err());
            assert!(validate_session_id(&injected).is_err());
        }
    }
}

#[test]
fn listed_signin_tools_round_trip_over_ipc_without_echoing_operation_key() {
    let cs = canaries(fresh_seed());
    let op_key_canary = "opkey-acme-console-signin-roundtrip-01".to_owned();
    let (_tmp, paths) = make_isolated_run_paths();
    let listener = UnixListener::bind(&paths.socket).unwrap();

    let project_tmp = tempfile::Builder::new()
        .prefix("ec-proj-")
        .tempdir_in("/tmp")
        .unwrap();
    std::fs::write(
        project_tmp.path().join("envcloak.toml"),
        "[project]\nname = \"acme-web\"\n[env]\n",
    )
    .unwrap();
    let project_dir_str = project_tmp.path().to_string_lossy().into_owned();

    let observed_methods: Arc<Mutex<Vec<(String, usize)>>> = Arc::new(Mutex::new(Vec::new()));
    let observed_bg = Arc::clone(&observed_methods);
    let req_id = "0123456789abcdef0123456789abcdef";
    let expected_op_key = op_key_canary.clone();

    let daemon_thread = std::thread::spawn(move || {
        struct FdReader<'a> {
            stream: &'a std::os::unix::net::UnixStream,
            fds: Vec<std::os::fd::OwnedFd>,
        }
        impl Read for FdReader<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                envcloak_sys::fdpass::recv_with_fds(self.stream.as_fd(), buf, &mut self.fds)
            }
        }

        for _ in 0..5 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = FdReader {
                stream: &stream,
                fds: Vec::new(),
            };
            let frame = Frame::read_from(&mut reader).unwrap();
            let fds = reader.fds;
            let req = IncomingRequest::parse(&frame).unwrap();
            observed_bg
                .lock()
                .unwrap()
                .push((req.method.to_owned(), fds.len()));

            let reply = match req.method {
                SigninRequest::NAME => {
                    let p = req.params::<<SigninRequest as Method>::Params>().unwrap();
                    assert_eq!(p.target, "acme/local");
                    assert_eq!(p.role.as_deref(), Some("editor"));
                    assert_eq!(p.operation_key, expected_op_key);
                    let view = SigninStatusView {
                        request: req_id.to_owned(),
                        revision: 1,
                        state: "awaiting_approval".to_owned(),
                        retry_until_secs: 1_700_000_900,
                        delivered_context: None,
                        cleanup: "not_needed".to_owned(),
                        revocation: "not_configured".to_owned(),
                        reason: None,
                        shared_loopback_cookie_jar: false,
                        authorization: Some("required".to_owned()),
                    };
                    result_frame(req.id, &view).unwrap()
                }
                SigninStatus::NAME => {
                    let p = req.params::<<SigninStatus as Method>::Params>().unwrap();
                    assert_eq!(p.request, req_id);
                    let view = SigninStatusView {
                        request: req_id.to_owned(),
                        revision: 2,
                        state: "ready".to_owned(),
                        retry_until_secs: 1_700_000_900,
                        delivered_context: Some("ctx-7".to_owned()),
                        cleanup: "pending".to_owned(),
                        revocation: "pending".to_owned(),
                        reason: None,
                        shared_loopback_cookie_jar: true,
                        authorization: Some("approved_once".to_owned()),
                    };
                    result_frame(req.id, &view).unwrap()
                }
                SigninCancel::NAME => {
                    let p = req.params::<<SigninCancel as Method>::Params>().unwrap();
                    assert_eq!(p.request, req_id);
                    let view = SigninStatusView {
                        request: req_id.to_owned(),
                        revision: 3,
                        state: "cancelled".to_owned(),
                        retry_until_secs: 0,
                        delivered_context: None,
                        cleanup: "confirmed".to_owned(),
                        revocation: "not_configured".to_owned(),
                        reason: Some("cancelled_by_requester".to_owned()),
                        shared_loopback_cookie_jar: false,
                        authorization: None,
                    };
                    result_frame(req.id, &view).unwrap()
                }
                SigninEnd::NAME => {
                    let p = req.params::<<SigninEnd as Method>::Params>().unwrap();
                    assert!(p.session == "ctx-7" || p.session == req_id);
                    let view = SigninStatusView {
                        request: req_id.to_owned(),
                        revision: 4,
                        state: "ended".to_owned(),
                        retry_until_secs: 0,
                        delivered_context: None,
                        cleanup: "confirmed".to_owned(),
                        revocation: "confirmed".to_owned(),
                        reason: Some("ended_by_requester".to_owned()),
                        shared_loopback_cookie_jar: false,
                        authorization: None,
                    };
                    result_frame(req.id, &view).unwrap()
                }
                other => panic!("unexpected method {other}"),
            };
            reply.write_to(&mut stream).unwrap();
        }
    });

    let mut router = Router::new();
    SignInTools::register(&mut router, true).unwrap();
    let ctx = Ctx::new("/nonexistent/envcloak".into(), None, Duration::from_secs(5))
        .with_run_paths(paths);
    let mut r = Running::start(Server::with_router(router), ctx);
    r.initialize();

    let req_ans = r.call(
        1,
        "request_sign_in",
        json!({
            "target": "acme/local",
            "role": "editor",
            "operation_key": op_key_canary,
            "project_dir": project_dir_str,
        }),
    );
    assert_eq!(req_ans["result"]["isError"], false, "{req_ans}");
    assert_eq!(req_ans["result"]["structuredContent"]["request"], req_id);
    assert_eq!(
        req_ans["result"]["structuredContent"]["state"],
        "awaiting_approval"
    );

    let status_ans = r.call(2, "sign_in_status", json!({"request": req_id}));
    assert_eq!(status_ans["result"]["isError"], false);
    assert_eq!(status_ans["result"]["structuredContent"]["state"], "ready");
    assert_eq!(
        status_ans["result"]["structuredContent"]["delivered_context"],
        "ctx-7"
    );

    let cancel_ans = r.call(3, "cancel_sign_in", json!({"request": req_id}));
    assert_eq!(cancel_ans["result"]["isError"], false);
    assert_eq!(
        cancel_ans["result"]["structuredContent"]["state"],
        "cancelled"
    );

    let end_ctx_ans = r.call(4, "end_sign_in_session", json!({"session": "ctx-7"}));
    assert_eq!(end_ctx_ans["result"]["isError"], false);
    assert_eq!(end_ctx_ans["result"]["structuredContent"]["state"], "ended");

    let end_req_ans = r.call(5, "end_sign_in_session", json!({"session": req_id}));
    assert_eq!(end_req_ans["result"]["isError"], false);
    assert_eq!(end_req_ans["result"]["structuredContent"]["state"], "ended");

    let transcript = r.end();
    daemon_thread.join().unwrap();

    let transcript_str = String::from_utf8_lossy(&transcript);
    assert!(
        !transcript_str.contains(&op_key_canary),
        "operation_key must never appear in MCP tool output"
    );
    assert_no_canary(&transcript, &cs);

    let calls = observed_methods.lock().unwrap().clone();
    assert_eq!(
        calls,
        vec![
            ("signin.request".to_owned(), 2),
            ("signin.status".to_owned(), 0),
            ("signin.cancel".to_owned(), 0),
            ("signin.end".to_owned(), 0),
            ("signin.end".to_owned(), 0),
        ]
    );
}

/// D-28 / R-M2b-56 / gate b19 reference middleware and fixture app verification:
/// - refuses to load when `NODE_ENV=production`;
/// - off outside test configuration (`NODE_ENV` != `"test"` and
///   `ENVCLOAK_TEST_SESSION` != `"1"`) and when `enabled` is not `true`;
/// - refuses unauthenticated, wrong-HMAC, timestamp-skewed, nonce-replayed, and
///   cross-origin (`Origin` header or `Sec-Fetch-Site: cross-site`) requests
///   with `401` and no mint;
/// - minted sessions expire on the server when the fixture clock advances past
///   `ttl`;
/// - the `adapter_key` never appears in any response, error, or log (canary sweep).
///
/// Mutation checked: defaulting the middleware to on, or skipping the `Origin`
/// header check in `integrations/test-session/node/index.cjs`, causes this test
/// to fail.
#[test]
fn test_session_middleware_guards_production_flag_origin_hmac_replay_expiry_and_canary_sweep() {
    let pins = read_browser_pins(&browser_versions_path()).expect("read browser-versions.json");
    let node_exe = resolve_node_binary(&pins).expect("resolve pinned node binary");
    let middleware_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("integrations/test-session/node/index.cjs");
    assert!(
        middleware_path.is_file(),
        "missing {}",
        middleware_path.display()
    );

    // 1. Refuses to load under NODE_ENV=production.
    let prod_out = Command::new(&node_exe)
        .env_clear()
        .env("NODE_ENV", "production")
        .arg("-e")
        .arg(format!("require({:?});", middleware_path))
        .output()
        .unwrap();
    assert!(
        !prod_out.status.success(),
        "middleware must refuse to load when NODE_ENV=production"
    );
    let prod_stderr = String::from_utf8_lossy(&prod_out.stderr);
    assert!(
        prod_stderr.contains("NODE_ENV=production"),
        "unexpected stderr: {prod_stderr}"
    );

    // 2. Off by default when `enabled` is omitted/false OR outside test config.
    let off_probe = r#"
const http = require("node:http");
const { createTestSessionHandler, signTestSessionRequest } = require(process.argv[1]);
const key = process.argv[2];

async function checkCase(envSetup, handlerOpts) {
  const prevNodeEnv = process.env.NODE_ENV;
  const prevFlag = process.env.ENVCLOAK_TEST_SESSION;
  envSetup();
  let mints = 0;
  const handler = createTestSessionHandler({
    ...handlerOpts,
    key,
    mint: () => { mints += 1; return { cookies: [], storage: [] }; },
  });
  const srv = http.createServer((req, res) => { handler(req, res); });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const port = srv.address().port;
  const body = JSON.stringify({ identity: "editor@acme.test", tenant: "t1", role: "editor", ttl: 60 });
  const signed = signTestSessionRequest({ key, body });
  const res = await fetch(`http://127.0.0.1:${port}/__envcloak/test-session`, {
    method: "POST",
    headers: signed.headers,
    body,
  });
  const text = await res.text();
  srv.close();
  process.env.NODE_ENV = prevNodeEnv;
  process.env.ENVCLOAK_TEST_SESSION = prevFlag;
  if (res.status !== 404 || mints !== 0) {
    throw new Error(`expected 404 and 0 mints, got status=${res.status} mints=${mints} body=${text}`);
  }
  return text;
}

(async () => {
  // Case A: test env active, but enabled omitted (default off).
  const a = await checkCase(
    () => { process.env.NODE_ENV = "test"; process.env.ENVCLOAK_TEST_SESSION = "1"; },
    {}
  );
  // Case B: enabled: false in test env.
  const b = await checkCase(
    () => { process.env.NODE_ENV = "test"; process.env.ENVCLOAK_TEST_SESSION = "1"; },
    { enabled: false }
  );
  // Case C: enabled: true, but outside test configuration.
  const c = await checkCase(
    () => { process.env.NODE_ENV = "development"; delete process.env.ENVCLOAK_TEST_SESSION; },
    { enabled: true }
  );
  process.stdout.write(JSON.stringify({ a, b, c }) + "\n");
})().catch((e) => { console.error(e); process.exit(1); });
"#;
    let cs = canaries(fresh_seed());
    let key_canary = cs[0].as_str();
    let off_out = Command::new(&node_exe)
        .env_clear()
        .arg("-e")
        .arg(off_probe)
        .arg(&middleware_path)
        .arg(key_canary)
        .output()
        .unwrap();
    assert!(
        off_out.status.success(),
        "off-by-default probe failed: {}",
        String::from_utf8_lossy(&off_out.stderr)
    );
    assert_no_canary(&off_out.stdout, &cs);
    assert_no_canary(&off_out.stderr, &cs);

    // 3. Exercise the real fixture server (`server.cjs`) wired to `integrations/test-session/node/index.cjs`.
    let (origins, control) = SigninFixture::start();
    control.reset_counters().unwrap();
    let mut collected_outputs = Vec::new();

    let body = r#"{"identity":"editor@acme.test","tenant":"t1","role":"editor","ttl":10}"#;
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let ts_str = now_secs.to_string();
    let nonce = "nonce-valid-000000000001";
    let valid_sig = sign_test_session_request(
        &origins.adapter_key,
        "POST",
        "/__envcloak/test-session",
        now_secs,
        nonce,
        body,
    );

    // 3a. Unauthenticated request (missing headers) -> 401, 0 mints.
    let (st_unauth, body_unauth) = http_request(
        "POST",
        &format!("{}/__envcloak/test-session", origins.app),
        &[("content-type", "application/json")],
        body,
    )
    .unwrap();
    assert_eq!(st_unauth, 401, "{body_unauth}");
    collected_outputs.extend_from_slice(body_unauth.as_bytes());

    // 3b. Wrong HMAC signature -> 401, 0 mints.
    let (st_bad_sig, body_bad_sig) = http_request(
        "POST",
        &format!("{}/__envcloak/test-session", origins.app),
        &[
            ("content-type", "application/json"),
            ("x-envcloak-timestamp", &ts_str),
            ("x-envcloak-nonce", "nonce-wrong-sig-000001"),
            (
                "x-envcloak-signature",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
        ],
        body,
    )
    .unwrap();
    assert_eq!(st_bad_sig, 401, "{body_bad_sig}");
    collected_outputs.extend_from_slice(body_bad_sig.as_bytes());

    // 3c. Timestamp outside replay window -> 401, 0 mints.
    let stale_ts = now_secs.saturating_sub(3_600);
    let stale_ts_str = stale_ts.to_string();
    let stale_sig = sign_test_session_request(
        &origins.adapter_key,
        "POST",
        "/__envcloak/test-session",
        stale_ts,
        "nonce-stale-ts-0000001",
        body,
    );
    let (st_stale, body_stale) = http_request(
        "POST",
        &format!("{}/__envcloak/test-session", origins.app),
        &[
            ("content-type", "application/json"),
            ("x-envcloak-timestamp", &stale_ts_str),
            ("x-envcloak-nonce", "nonce-stale-ts-0000001"),
            ("x-envcloak-signature", &stale_sig),
        ],
        body,
    )
    .unwrap();
    assert_eq!(st_stale, 401, "{body_stale}");
    collected_outputs.extend_from_slice(body_stale.as_bytes());

    // 3d. Cross-origin request (`Origin` header present, even with a valid signature) -> 401, 0 mints.
    for (idx, origin_hdr) in ["https://evil.example", &origins.app, "null"]
        .into_iter()
        .enumerate()
    {
        let origin_nonce = format!("nonce-origin-check-{idx:04}");
        let origin_sig = sign_test_session_request(
            &origins.adapter_key,
            "POST",
            "/__envcloak/test-session",
            now_secs,
            &origin_nonce,
            body,
        );
        let (st_origin, body_origin) = http_request(
            "POST",
            &format!("{}/__envcloak/test-session", origins.app),
            &[
                ("content-type", "application/json"),
                ("origin", origin_hdr),
                ("x-envcloak-timestamp", &ts_str),
                ("x-envcloak-nonce", &origin_nonce),
                ("x-envcloak-signature", &origin_sig),
            ],
            body,
        )
        .unwrap();
        assert_eq!(
            st_origin, 401,
            "Origin header {origin_hdr:?} must be refused with 401: {body_origin}"
        );
        assert!(
            body_origin.contains("origin_forbidden"),
            "Origin header {origin_hdr:?} must fail with origin_forbidden: {body_origin}"
        );
        collected_outputs.extend_from_slice(body_origin.as_bytes());
    }

    // 3d-host. Non-loopback `Host` header (DNS-rebinding defense) -> 403 loopback_required, 0 mints.
    let bad_host_nonce = "nonce-bad-host-0000001";
    let bad_host_sig = sign_test_session_request(
        &origins.adapter_key,
        "POST",
        "/__envcloak/test-session",
        now_secs,
        bad_host_nonce,
        body,
    );
    let (st_bad_host, body_bad_host) = http_request(
        "POST",
        &format!("{}/__envcloak/test-session", origins.app),
        &[
            ("host", "evil.example.com:4100"),
            ("content-type", "application/json"),
            ("x-envcloak-timestamp", &ts_str),
            ("x-envcloak-nonce", bad_host_nonce),
            ("x-envcloak-signature", &bad_host_sig),
        ],
        body,
    )
    .unwrap();
    assert_eq!(st_bad_host, 403, "{body_bad_host}");
    assert!(
        body_bad_host.contains("loopback_required"),
        "{body_bad_host}"
    );
    collected_outputs.extend_from_slice(body_bad_host.as_bytes());

    assert_eq!(
        control.counters().unwrap().mints,
        0,
        "no session may be minted for unauthenticated, stale, non-loopback Host, or Origin-carrying requests"
    );

    // 3e. Valid signed request -> 200 OK, mints == 1.
    let (st_ok, body_ok) = http_request(
        "POST",
        &format!("{}/__envcloak/test-session", origins.app),
        &[
            ("content-type", "application/json"),
            ("x-envcloak-timestamp", &ts_str),
            ("x-envcloak-nonce", nonce),
            ("x-envcloak-signature", &valid_sig),
        ],
        body,
    )
    .unwrap();
    assert_eq!(st_ok, 200, "{body_ok}");
    collected_outputs.extend_from_slice(body_ok.as_bytes());
    assert_eq!(control.counters().unwrap().mints, 1);

    let minted_json: Value = serde_json::from_str(&body_ok).unwrap();
    assert_eq!(minted_json["ok"], true);
    assert_eq!(minted_json["identity"], "editor@acme.test");
    assert_eq!(minted_json["tenant"], "t1");
    assert_eq!(minted_json["role"], "editor");
    assert_eq!(minted_json["ttl"], 10);
    let session_token = minted_json["session_token"].as_str().unwrap();

    // 3f. Replaying the exact same signed request (same nonce) -> 401, mints stays 1.
    let (st_replay, body_replay) = http_request(
        "POST",
        &format!("{}/__envcloak/test-session", origins.app),
        &[
            ("content-type", "application/json"),
            ("x-envcloak-timestamp", &ts_str),
            ("x-envcloak-nonce", nonce),
            ("x-envcloak-signature", &valid_sig),
        ],
        body,
    )
    .unwrap();
    assert_eq!(
        st_replay, 401,
        "nonce replay must be refused with 401: {body_replay}"
    );
    collected_outputs.extend_from_slice(body_replay.as_bytes());
    assert_eq!(control.counters().unwrap().mints, 1);

    // 3g. Minted session is active before TTL and expires on the server once the
    // fixture clock advances past `ttl` (10s = 10_000ms).
    let cookie_hdr = format!("session={session_token}");
    let (who_before, who_body_before) = http_request(
        "GET",
        &format!("{}/api/whoami", origins.app),
        &[("cookie", &cookie_hdr)],
        "",
    )
    .unwrap();
    assert_eq!(who_before, 200, "{who_body_before}");
    collected_outputs.extend_from_slice(who_body_before.as_bytes());

    control.advance_clock(11_000).unwrap();
    let (who_after, who_body_after) = http_request(
        "GET",
        &format!("{}/api/whoami", origins.app),
        &[("cookie", &cookie_hdr)],
        "",
    )
    .unwrap();
    assert_eq!(
        who_after, 401,
        "minted session must expire on the server after TTL: {who_body_after}"
    );
    collected_outputs.extend_from_slice(who_body_after.as_bytes());

    // 3h. Adapter key never appears in any response or error.
    let all_text = String::from_utf8_lossy(&collected_outputs);
    assert!(
        !all_text.contains(&origins.adapter_key),
        "adapter_key leaked in middleware output"
    );
}
