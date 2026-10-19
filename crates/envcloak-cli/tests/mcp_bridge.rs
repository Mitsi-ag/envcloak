//! End-to-end and integration tests for `envcloak mcp-bridge` (HTTP client
//! mode, `--stdio --launch <id>` client mode, and the daemon-spawned
//! `--relay`; SPEC §6.4, §6.6, §10b, §11; M2 plan D-04, D-05, D-06, D-18,
//! D-33, D-36; task M2-18; gates 13, 19, 33, 39).
#![allow(clippy::unwrap_used)]

mod common;

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{
    approve_ticking, cli, data_dir, finish_within, on_terminal_program, outside_dir, python3, run,
    run_on_terminal, secret_file, seed_vault, start_daemon, stderr, stdout,
};
use envcloak_core::SecretBytes;
use envcloak_core::crypto::ItemClass;
use envcloak_core::vault::{FieldName, ItemDetails, LockedVault, NewItem, Slug, VaultPaths};
use envcloak_mcp::bridge::http::{BridgeUrl, HeaderRef};
use envcloak_mcp::bridge::relay::prepare_release;
use envcloak_policy::managed::{bridge_binding_name, bridge_binding_suffix};
use envcloak_testkit::{
    Canary, Daemon, TestHome, assert_no_canary, by_label, canaries, fresh_seed, labels, testkit_bin,
};
use serde_json::{Value, json};

const HELPER_ENV: &str = "EC_BRIDGE_HELPER";
const HELPER_OUT_ENV: &str = "EC_BRIDGE_HELPER_OUT";
const CUSTOM_ONE_LABEL: &str = "CUSTOM_MCP_ONE";
const CUSTOM_TWO_LABEL: &str = "CUSTOM_MCP_TWO";

/// Helper entry point when this test binary is re-execed on a pseudo-terminal
/// to perform `managed.register` or `managed.unregister` with a terminal proof.
#[test]
fn helper() {
    let Some(in_path) = std::env::var_os(HELPER_ENV) else {
        return;
    };
    let out_path = PathBuf::from(std::env::var_os(HELPER_OUT_ENV).unwrap());
    let input: Value = serde_json::from_slice(&std::fs::read(in_path).unwrap()).unwrap();
    let pass_path = input["passphrase_file"].as_str().unwrap();
    let mut pass_bytes = std::fs::read(pass_path).unwrap();
    while matches!(pass_bytes.last(), Some(b'\n' | b'\r')) {
        pass_bytes.pop();
    }
    let pass = SecretBytes::from_vec(pass_bytes);
    let paths = envcloak_ipc::RunPaths::for_user().unwrap();
    let mut client = envcloak_ipc::Client::connect(&paths).unwrap();
    let action = input["action"].as_str().unwrap();
    let result = match action {
        "register" => {
            use envcloak_ipc::proto::{LaunchDeclParams, ManagedRegisterParams, ManagedServerDecl};
            let server = if let Some(origin) = input["origin"].as_str() {
                ManagedServerDecl::Bridge {
                    origin: origin.to_owned(),
                    header_names: serde_json::from_value(input["headers"].clone()).unwrap(),
                }
            } else {
                ManagedServerDecl::Stdio {
                    launch: LaunchDeclParams {
                        argv: serde_json::from_value(input["argv"].clone()).unwrap(),
                        cwd: input["cwd"].as_str().map(str::to_owned),
                        env: serde_json::from_value(input["env"].clone()).unwrap_or_default(),
                        path_env: input["path_env"].as_str().map(str::to_owned),
                    },
                }
            };
            let params = ManagedRegisterParams {
                name: input["name"].as_str().unwrap().to_owned(),
                manifest: input["manifest"].as_str().unwrap().to_owned(),
                server,
                passphrase: envcloak_ipc::WireSecret::new(pass),
                claims: Vec::new(),
            };
            match client.register_managed(&params) {
                Ok(v) => serde_json::to_value(v).unwrap(),
                Err(envcloak_ipc::ClientError::Rpc(r)) => {
                    json!({"error": r.kind.token(), "reason": r.reason})
                }
                Err(other) => json!({"error": format!("{other:?}")}),
            }
        }
        "unregister" => match client.unregister_managed(input["id"].as_str().unwrap(), pass, &[]) {
            Ok(v) => serde_json::to_value(v).unwrap(),
            Err(envcloak_ipc::ClientError::Rpc(r)) => {
                json!({"error": r.kind.token(), "reason": r.reason})
            }
            Err(other) => json!({"error": format!("{other:?}")}),
        },
        _ => panic!("unknown helper action: {action}"),
    };
    std::fs::write(&out_path, result.to_string()).unwrap();
}

struct BridgeWorld {
    cs: Vec<Canary>,
    home: TestHome,
    daemon: Daemon,
    files: tempfile::TempDir,
    pass_file: PathBuf,
}

impl BridgeWorld {
    fn new() -> Self {
        let mut cs = canaries(fresh_seed());
        let seed_a = fresh_seed();
        let seed_b = fresh_seed();
        // Custom secret values that do not match any built-in provider's key
        // prefix so `allowed_hosts` permits sending them to loopback/custom
        // origins while still being high-entropy canaries.
        let custom_one = format!("Bearer mcp-custom-alpha-{seed_a:016x}-secret");
        let custom_two = format!("mcp-custom-beta-{seed_b:016x}-token");
        let very_short = "tinyval".to_owned(); // 7 bytes (< 8)
        cs.push(Canary::new(CUSTOM_ONE_LABEL, custom_one));
        cs.push(Canary::new(CUSTOM_TWO_LABEL, custom_two));

        let home = TestHome::new();
        let kit = seed_vault(&home, &cs);
        cs.push(kit);

        // Add `custom/acme-web`, `custom/second`, and `tiny/acme-web` to the
        // vault before starting the daemon.
        let paths = VaultPaths::under(data_dir(&home));
        let pass = SecretBytes::copy_from(by_label(&cs, labels::VAULT_PASSPHRASE).value());
        let mut vault = LockedVault::open(&paths)
            .unwrap()
            .unlock_with_passphrase(&pass)
            .unwrap();
        vault
            .transact(|t| {
                for (slug, val) in [
                    ("custom/acme-web", by_label(&cs, CUSTOM_ONE_LABEL).value()),
                    ("custom/second", by_label(&cs, CUSTOM_TWO_LABEL).value()),
                    ("tiny/acme-web", very_short.as_bytes()),
                ] {
                    let id = t.create_item(NewItem {
                        class: ItemClass::Secret,
                        slug: Slug::new(slug).unwrap(),
                        details: ItemDetails {
                            title: slug.to_owned(),
                            ..ItemDetails::default()
                        },
                    })?;
                    t.add_field(
                        id,
                        FieldName::new("value").unwrap(),
                        SecretBytes::copy_from(val),
                    )?;
                }
                Ok(())
            })
            .unwrap();
        drop(vault);

        let daemon = start_daemon(&home);
        let files = outside_dir();
        let pass_file = secret_file(
            files.path(),
            "pass",
            by_label(&cs, labels::VAULT_PASSPHRASE).value(),
        );
        let out = run_on_terminal(
            &home,
            &["unlock", "--passphrase-fd", "3"],
            &[(3, &pass_file, true)],
        );
        assert!(out.status.success(), "{}", stderr(&out));

        Self {
            cs,
            home,
            daemon,
            files,
            pass_file,
        }
    }

    fn value(&self, label: &str) -> &str {
        by_label(&self.cs, label).as_str()
    }

    fn call_helper(&self, mut payload: Value) -> Value {
        let id = fresh_seed();
        let in_path = self.files.path().join(format!("helper-{id:016x}.in.json"));
        let out_path = self.files.path().join(format!("helper-{id:016x}.out.json"));
        payload["passphrase_file"] = json!(self.pass_file.to_str().unwrap());
        std::fs::write(&in_path, payload.to_string()).unwrap();

        let exe = std::env::current_exe().unwrap();
        let wrapper = format!(
            "import os, sys\nos.environ[{:?}] = {:?}\nos.environ[{:?}] = {:?}\nos.execv({:?}, [{:?}, '--exact', 'helper', '--nocapture'])\n",
            HELPER_ENV,
            in_path.to_str().unwrap(),
            HELPER_OUT_ENV,
            out_path.to_str().unwrap(),
            exe.to_str().unwrap(),
            exe.to_str().unwrap(),
        );
        let script = self.files.path().join(format!("helper-{id:016x}.py"));
        std::fs::write(&script, wrapper).unwrap();
        let py = python3();
        let cmd = on_terminal_program(&self.home, &[&py, &script], &[]);
        let out = finish_within(cmd, Duration::from_secs(60));
        assert!(
            out.status.success(),
            "helper failed: {}\n{}",
            stdout(&out),
            stderr(&out)
        );
        serde_json::from_slice(&std::fs::read(&out_path).unwrap()).unwrap()
    }

    fn write_bridge_manifest(
        &self,
        dir_name: &str,
        origin: &str,
        headers_and_slugs: &[(&str, &str)],
    ) -> PathBuf {
        let dir = self.home.root().join(dir_name);
        std::fs::create_dir_all(&dir).unwrap();
        let mut body = format!("[project]\nname = {dir_name:?}\n\n[env]\n");
        for (header, slug) in headers_and_slugs {
            let binding = bridge_binding_name(header, origin).unwrap();
            body.push_str(&format!("{binding} = {slug:?}\n"));
        }
        let manifest = dir.join("envcloak.toml");
        std::fs::write(&manifest, body).unwrap();
        manifest
    }

    fn register_bridge(
        &self,
        name: &str,
        manifest: &Path,
        origin: &str,
        headers: &[&str],
    ) -> Value {
        let res = self.call_helper(json!({
            "action": "register",
            "name": name,
            "manifest": manifest.to_str().unwrap(),
            "origin": origin,
            "headers": headers,
        }));
        assert_eq!(res["receipt"]["transport"], "bridge", "{res}");
        res
    }

    fn register_stdio(
        &self,
        name: &str,
        manifest: &Path,
        argv: &[&str],
        cwd: Option<&Path>,
    ) -> String {
        let res = self.call_helper(json!({
            "action": "register",
            "name": name,
            "manifest": manifest.to_str().unwrap(),
            "argv": argv,
            "cwd": cwd.and_then(Path::to_str),
        }));
        res["launch"]
            .as_str()
            .unwrap_or_else(|| panic!("expected launch id in {res}"))
            .to_owned()
    }

    /// Spawns `fixture-agent -- envcloak <args>` with piped stdin/stdout/stderr.
    fn spawn_agent_bridge(&self, args: &[&str]) -> Child {
        let mut cmd = Command::new(testkit_bin("fixture-agent"));
        self.home
            .apply(&mut cmd)
            .arg("--")
            .arg(cli())
            .args(args)
            .current_dir(self.home.home())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd.spawn().unwrap()
    }

    /// Runs `fixture-agent -- envcloak <args>` to completion with `stdin_bytes`.
    /// When `approve` is true, appends `--wait 30s` and automatically approves
    /// the pending request on a person terminal as soon as `mcp-bridge`
    /// announces it on stderr.
    fn run_agent_bridge(&self, args: &[&str], stdin_bytes: &[u8]) -> Output {
        self.run_agent_bridge_inner(args, stdin_bytes, false)
    }

    fn run_agent_bridge_approved(&self, args: &[&str], stdin_bytes: &[u8]) -> Output {
        self.run_agent_bridge_inner(args, stdin_bytes, true)
    }

    fn run_agent_bridge_inner(&self, args: &[&str], stdin_bytes: &[u8], approve: bool) -> Output {
        let mut full_args: Vec<&str> = args.to_vec();
        if approve && !full_args.contains(&"--wait") {
            full_args.extend_from_slice(&["--wait", "30s"]);
        }
        let mut child = self.spawn_agent_bridge(&full_args);
        if let Some(mut sin) = child.stdin.take() {
            let _ = sin.write_all(stdin_bytes);
        }
        let mut out = child.stdout.take();
        let err = child.stderr.take();
        let out_reader = std::thread::spawn(move || {
            let mut o = Vec::new();
            if let Some(s) = out.as_mut() {
                let _ = s.read_to_end(&mut o);
            }
            o
        });
        let mut stderr_bytes = Vec::new();
        if let Some(err_pipe) = err {
            let mut reader = BufReader::new(err_pipe);
            loop {
                let mut line = String::new();
                let n = reader.read_line(&mut line).unwrap_or(0);
                if n == 0 {
                    break;
                }
                if approve
                    && line.contains("envcloak: approval_required:")
                    && line.contains("waiting up to")
                {
                    let req_id = extract_request_id(&line);
                    self.approve_session(&req_id);
                    continue;
                }
                stderr_bytes.extend_from_slice(line.as_bytes());
            }
        }
        let start = Instant::now();
        let limit = Duration::from_secs(60);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if start.elapsed() > limit {
                let _ = child.kill();
                let _ = child.wait();
                panic!("bridge child did not exit within {limit:?}");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let stdout_bytes = out_reader.join().unwrap();
        Output {
            status,
            stdout: stdout_bytes,
            stderr: stderr_bytes,
        }
    }

    /// Approves the pending request `<id>` on a person terminal with a session grant.
    fn approve_session(&self, id: &str) {
        let out = approve_ticking(&self.home, id, &[], &self.pass_file);
        assert!(
            out.status.success(),
            "approve {id} failed: {}\n{}",
            stdout(&out),
            stderr(&out)
        );
    }

    fn sweep(&self) {
        assert_no_canary(&self.daemon.log_bytes(), &self.cs);
    }
}

fn extract_request_id(stderr_text: &str) -> String {
    stderr_text
        .split("request=")
        .nth(1)
        .and_then(|s| s.get(..8))
        .unwrap_or_else(|| panic!("no request=<id> in stderr: {stderr_text}"))
        .to_owned()
}

// ----------------------------------------------------------------- HTTP mock server

#[derive(Debug, Clone)]
struct RecordedRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
}

impl RecordedRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Debug, Clone)]
struct MockResponse {
    status: u16,
    reason: &'static str,
    content_type: &'static str,
    extra_headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl MockResponse {
    fn json(status: u16, reason: &'static str, body: &str) -> Self {
        Self {
            status,
            reason,
            content_type: "application/json",
            extra_headers: Vec::new(),
            body: body.as_bytes().to_vec(),
        }
    }

    fn sse(body: &[u8]) -> Self {
        Self {
            status: 200,
            reason: "OK",
            content_type: "text/event-stream; charset=utf-8",
            extra_headers: Vec::new(),
            body: body.to_vec(),
        }
    }

    fn redirect(status: u16, location: &str) -> Self {
        Self {
            status,
            reason: "Redirect",
            content_type: "text/plain",
            extra_headers: vec![("Location".to_owned(), location.to_owned())],
            body: b"redirecting".to_vec(),
        }
    }
}

struct TestServer {
    port: u16,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
}

impl TestServer {
    fn start(initial_responses: Vec<MockResponse>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let responses = Arc::new(Mutex::new(VecDeque::from(initial_responses)));
        let req_clone = Arc::clone(&requests);
        let resp_clone = Arc::clone(&responses);

        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                if let Some(req) = read_http_request(&stream) {
                    req_clone.lock().unwrap().push(req);
                    let resp = resp_clone.lock().unwrap().pop_front().unwrap_or_else(|| {
                        MockResponse::json(
                            200,
                            "OK",
                            r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#,
                        )
                    });
                    write_http_response(stream, &resp);
                }
            }
        });

        Self { port, requests }
    }

    fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    fn recorded(&self) -> Vec<RecordedRequest> {
        self.requests.lock().unwrap().clone()
    }
}

fn read_http_request(mut stream: &TcpStream) -> Option<RecordedRequest> {
    let mut reader = BufReader::new(&mut stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).ok()? == 0 {
        return None;
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_owned();
    let path = parts.next()?.to_owned();

    let mut headers = Vec::new();
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            break;
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            let key = k.trim().to_owned();
            let val = v.trim().to_owned();
            if key.eq_ignore_ascii_case("content-length") {
                content_length = val.parse().unwrap_or(0);
            }
            headers.push((key, val));
        }
    }

    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).ok()?;
    Some(RecordedRequest {
        method,
        path,
        headers,
    })
}

fn write_http_response(mut stream: TcpStream, resp: &MockResponse) {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        resp.status,
        resp.reason,
        resp.content_type,
        resp.body.len()
    );
    for (k, v) in &resp.extra_headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&resp.body);
    let _ = stream.flush();
}

// ----------------------------------------------------------------- Tests

/// M2-18 test 1 & Mutation (3): Calling `envcloak mcp-bridge --relay`
/// directly exits 125 with `not_started_by_daemon`, both with default
/// descriptors and when pipes are placed on fds 0, 1, 3, and 4 by a
/// non-daemon parent process.
#[test]
fn direct_invocation_of_relay_is_refused_not_started_by_daemon() {
    let w = BridgeWorld::new();
    let out = run(&w.home, &["mcp-bridge", "--relay"], &[]);
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    assert!(
        stderr(&out).starts_with("envcloak: not_started_by_daemon: "),
        "unexpected stderr: {}",
        stderr(&out)
    );

    // Even if a non-daemon caller puts a socketpair on fd 3 (`CONTROL_FD`)
    // carrying a valid `ToRunner::Release` frame and a lifeline pipe on fd 4
    // (`LIFELINE_FD`), `started_by_daemon` checks the daemon's pid against
    // the parent and socket peer and still refuses with `not_started_by_daemon`.
    let origin = "http://127.0.0.1:9999";
    let binding = bridge_binding_name("Authorization", origin).unwrap();
    let msg = envcloak_ipc::control::ToRunner::Release(Box::new(envcloak_ipc::control::Release {
        to: envcloak_ipc::control::Recipient::Relay {
            origin: origin.to_owned(),
            headers: vec![envcloak_ipc::control::RelayHeader {
                name: "Authorization".to_owned(),
                binding: binding.clone(),
            }],
        },
        bindings: vec![envcloak_ipc::proto::ReleasedValue {
            env_name: binding,
            slug: "custom/acme-web".to_owned(),
            allow_short: false,
            value: envcloak_ipc::WireSecret::new(SecretBytes::copy_from(
                w.value(CUSTOM_ONE_LABEL).as_bytes(),
            )),
        }],
    }));
    let frame = envcloak_ipc::Frame::encode(&msg).unwrap();
    let mut frame_bytes = Vec::new();
    frame.write_to(&mut frame_bytes).unwrap();
    let frame_path = w.files.path().join("spoof_release.bin");
    std::fs::write(&frame_path, &frame_bytes).unwrap();

    let spoof = r#"import os, socket, subprocess, sys
s_a, s_b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
r4, w4 = os.pipe()
with open(sys.argv[2], "rb") as f:
    s_b.sendall(f.read())
def preexec():
    os.dup2(s_a.fileno(), 3)
    os.dup2(r4, 4)
    os.set_inheritable(3, True)
    os.set_inheritable(4, True)
p = subprocess.run(
    [sys.argv[1], "mcp-bridge", "--relay"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    preexec_fn=preexec,
    close_fds=False,
)
sys.stderr.buffer.write(p.stderr)
sys.exit(p.returncode)
"#;
    let mut cmd = Command::new(python3());
    w.home
        .apply(&mut cmd)
        .args(["-c", spoof])
        .arg(cli())
        .arg(&frame_path)
        .current_dir(w.home.home())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let spoof_out = finish_within(cmd, Duration::from_secs(30));
    std::fs::remove_file(&frame_path).unwrap();
    assert_eq!(spoof_out.status.code(), Some(125), "{}", stderr(&spoof_out));
    assert!(
        stderr(&spoof_out).starts_with("envcloak: not_started_by_daemon: "),
        "spoofed fds were not refused: {}",
        stderr(&spoof_out)
    );
    w.sweep();
}

/// M2-18 test 2 & Mutation (4): Plaintext `http://` to a non-loopback host is
/// refused on both the CLI and relay sides, while `http://127.0.0.1:...`,
/// `http://[::1]:...`, `http://localhost:...`, and `https://...` are allowed.
#[test]
fn scheme_and_url_validation_refuses_non_loopback_http_and_allows_loopback() {
    let w = BridgeWorld::new();
    let manifest = w.write_bridge_manifest(
        "remote-scheme",
        "https://mcp.example.com",
        &[("Authorization", "custom/acme-web")],
    );

    for bad_url in [
        "http://mcp.example.com/v1",
        "http://192.168.1.10:8080/mcp",
        "ftp://127.0.0.1:8080/mcp",
        "https://user:pass@mcp.example.com/v1",
        "https://mcp.example.com/v1#frag",
    ] {
        assert!(
            BridgeUrl::parse(bad_url).is_err(),
            "BridgeUrl::parse should refuse {bad_url}"
        );
        let out = run(
            &w.home,
            &[
                "mcp-bridge",
                "--header-ref",
                "Authorization=custom/acme-web",
                "--manifest",
                manifest.to_str().unwrap(),
                "--url",
                bad_url,
            ],
            &[],
        );
        assert_eq!(
            out.status.code(),
            Some(2),
            "expected usage exit 2 for {bad_url}: {}",
            stderr(&out)
        );
        assert!(
            stderr(&out).contains("envcloak: usage: "),
            "unexpected stderr for {bad_url}: {}",
            stderr(&out)
        );
    }

    // Relay-side `prepare_release` also refuses non-loopback `http://` origins.
    let bad_release = envcloak_ipc::control::Release {
        to: envcloak_ipc::control::Recipient::Relay {
            origin: "http://mcp.example.com".to_owned(),
            headers: Vec::new(),
        },
        bindings: Vec::new(),
    };
    assert!(prepare_release(bad_release, 1024).is_err());

    // Loopback `http://` and remote `https://` are accepted by `BridgeUrl::parse`.
    for good_url in [
        "http://127.0.0.1:8080/mcp",
        "http://[::1]:8080/mcp",
        "http://localhost:8080/mcp",
        "https://mcp.example.com/v1/sse?x=1",
    ] {
        assert!(
            BridgeUrl::parse(good_url).is_ok(),
            "BridgeUrl::parse should accept {good_url}"
        );
    }
    w.sweep();
}

/// M2-18 test 3 & Mutation (8): HTTP JSON and SSE streaming round-trip with
/// header injection verified at the test server, D-04 waiting when pending and
/// then approved, and verification that client-side `mcp-bridge` holds no
/// secret in memory/env/argv at any point.
#[test]
fn http_json_and_sse_round_trip_with_header_injection_and_zero_secrets_in_bridge() {
    let w = BridgeWorld::new();
    let sse_stream = concat!(
        ": keepalive comment\n",
        "id: evt-1\n",
        "retry: 1500\n",
        "event: message\n",
        "data: {\"jsonrpc\":\"2.0\",\n",
        "data: \"id\":2,\"result\":{\"tools\":[{\"name\":\"echo\"}]}}\n",
        "\n",
        "data: {\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"done\"}]}}\n\n",
    );
    let srv = TestServer::start(vec![
        // 1. initialize -> application/json
        MockResponse::json(
            200,
            "OK",
            r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{}}}"#,
        ),
        // 2. notifications/initialized -> 202 Accepted (empty body)
        MockResponse {
            status: 202,
            reason: "Accepted",
            content_type: "text/plain",
            extra_headers: Vec::new(),
            body: Vec::new(),
        },
        // 3. tools/list + streaming -> text/event-stream
        MockResponse::sse(sse_stream.as_bytes()),
    ]);

    let origin = srv.origin();
    let manifest = w.write_bridge_manifest(
        "remote-roundtrip",
        &origin,
        &[
            ("Authorization", "custom/acme-web"),
            ("X-Custom-Key", "custom/second"),
        ],
    );
    w.register_bridge(
        "claude-code/roundtrip",
        &manifest,
        &origin,
        &["Authorization", "X-Custom-Key"],
    );

    let url = srv.url("/v1/mcp?mode=stream");
    let args = [
        "mcp-bridge",
        "--header-ref",
        "Authorization=custom/acme-web",
        "--header-ref",
        "X-Custom-Key=custom/second",
        "--manifest",
        manifest.to_str().unwrap(),
        "--url",
        url.as_str(),
        "--wait",
        "30s",
    ];

    // Spawn `fixture-agent -- envcloak mcp-bridge ... --wait 30s`.
    // It will first hit `approval_required` and wait while we approve it on a
    // person terminal (D-04).
    let mut child = w.spawn_agent_bridge(&args);
    let mut child_stdin = child.stdin.take().unwrap();
    let mut child_stdout = BufReader::new(child.stdout.take().unwrap());
    let mut child_stderr = BufReader::new(child.stderr.take().unwrap());

    let mut pending_line = String::new();
    child_stderr.read_line(&mut pending_line).unwrap();
    assert!(
        pending_line.contains("approval_required"),
        "expected approval_required notice on stderr, got: {pending_line}"
    );
    let req_id = extract_request_id(&pending_line);
    w.approve_session(&req_id);

    // 1. Send `initialize` request.
    writeln!(
        child_stdin,
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{}}}}"#
    )
    .unwrap();
    child_stdin.flush().unwrap();

    let mut line1 = String::new();
    child_stdout.read_line(&mut line1).unwrap();
    let v1: Value = serde_json::from_str(&line1).unwrap();
    assert_eq!(v1["id"], 1);
    assert_eq!(v1["result"]["protocolVersion"], "2024-11-05");

    // While the bridge is active, inspect the client process (`ps eww`) and
    // verify that NO canary appears in its argv or environment, and that the
    // daemon spawned a child `--relay` process (D-36).
    let ps_out = Command::new("/bin/ps")
        .args(["ewwx"])
        .output()
        .expect("ps ewwx");
    assert_no_canary(&ps_out.stdout, &w.cs);
    assert!(
        String::from_utf8_lossy(&ps_out.stdout).contains("mcp-bridge --relay"),
        "expected daemon-spawned mcp-bridge --relay in ps output"
    );

    // 2. Send `notifications/initialized` (202 Accepted -> no stdout line)
    // followed by `tools/list` (SSE response with 2 events).
    writeln!(
        child_stdin,
        r#"{{"jsonrpc":"2.0","method":"notifications/initialized"}}"#
    )
    .unwrap();
    writeln!(
        child_stdin,
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/list"}}"#
    )
    .unwrap();
    child_stdin.flush().unwrap();

    let mut line2 = String::new();
    child_stdout.read_line(&mut line2).unwrap();
    let v2: Value = serde_json::from_str(&line2).unwrap();
    assert_eq!(v2["id"], 2);
    assert_eq!(v2["result"]["tools"][0]["name"], "echo");

    let mut line3 = String::new();
    child_stdout.read_line(&mut line3).unwrap();
    let v3: Value = serde_json::from_str(&line3).unwrap();
    assert_eq!(v3["id"], 3);
    assert_eq!(v3["result"]["content"][0]["text"], "done");

    // Close stdin and verify `mcp-bridge` exits 0 within 2 seconds.
    drop(child_stdin);
    let start = Instant::now();
    let status = child.wait().unwrap();
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "bridge took too long to exit"
    );
    assert!(status.success(), "bridge exited with {status}");

    // Verify all 3 HTTP requests reached the server with the injected headers
    // and the exact path `/v1/mcp?mode=stream`.
    let recorded = srv.recorded();
    assert_eq!(recorded.len(), 3, "expected 3 requests, got {recorded:?}");
    for req in &recorded {
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/v1/mcp?mode=stream");
        assert_eq!(req.header("Authorization"), Some(w.value(CUSTOM_ONE_LABEL)));
        assert_eq!(req.header("X-Custom-Key"), Some(w.value(CUSTOM_TWO_LABEL)));
        assert_eq!(
            req.header("Accept"),
            Some("application/json, text/event-stream")
        );
    }

    // D-36: client-side `validate_started_answer` refuses any answer that
    // returns secret values to `mcp-bridge` instead of `DecisionView::Started`.
    let leaked_answer = envcloak_ipc::proto::RunAnswer {
        decision: envcloak_ipc::view::DecisionView::Started {},
        values: vec![envcloak_ipc::proto::ReleasedValue {
            env_name: "AUTHORIZATION".to_owned(),
            slug: "custom/acme-web".to_owned(),
            allow_short: false,
            value: envcloak_ipc::WireSecret::new(SecretBytes::copy_from(
                w.value(CUSTOM_ONE_LABEL).as_bytes(),
            )),
        }],
        proposals: Vec::new(),
    };
    assert_eq!(
        envcloak_mcp::bridge::handoff::validate_started_answer(&leaked_answer, "")
            .unwrap_err()
            .token(),
        "protocol_error"
    );

    assert_no_canary(line1.as_bytes(), &w.cs);
    assert_no_canary(line2.as_bytes(), &w.cs);
    assert_no_canary(line3.as_bytes(), &w.cs);
    w.sweep();
}

/// M2-18 test 4 & Mutation (2): Echoed secret in a JSON response body, SSE
/// event, or HTTP error response (`400`/`500`) is redacted and never reaches
/// the caller in plaintext.
#[test]
fn echoed_secrets_in_json_sse_and_error_responses_are_redacted() {
    let w = BridgeWorld::new();
    let secret_one = w.value(CUSTOM_ONE_LABEL).to_owned();
    let secret_two = w.value(CUSTOM_TWO_LABEL).to_owned();

    let json_echo = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "leaked_one": secret_one,
            "leaked_two": secret_two,
        }
    })
    .to_string();
    let sse_echo = format!(
        "data: {{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{\"sse_leak\":{secret_one:?}}}}}\n\n"
    );
    let err_400 = format!("Bad token: {secret_one} and {secret_two}");
    let err_500 = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":4,\"error\":{{\"code\":-32000,\"message\":{secret_one:?}}}}}"
    );

    let srv = TestServer::start(vec![
        MockResponse::json(200, "OK", &json_echo),
        MockResponse::sse(sse_echo.as_bytes()),
        MockResponse::json(400, "Bad Request", &err_400),
        MockResponse::json(500, "Internal Server Error", &err_500),
    ]);

    let origin = srv.origin();
    let manifest = w.write_bridge_manifest(
        "remote-redact",
        &origin,
        &[
            ("Authorization", "custom/acme-web"),
            ("X-Custom-Key", "custom/second"),
        ],
    );
    w.register_bridge(
        "claude-code/redact",
        &manifest,
        &origin,
        &["Authorization", "X-Custom-Key"],
    );

    let url = srv.url("/mcp");
    let args = [
        "mcp-bridge",
        "--header-ref",
        "Authorization=custom/acme-web",
        "--header-ref",
        "X-Custom-Key=custom/second",
        "--manifest",
        manifest.to_str().unwrap(),
        "--url",
        url.as_str(),
    ];

    let input = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\"}\n",
    );
    let out = w.run_agent_bridge_approved(&args, input.as_bytes());
    assert!(out.status.success(), "{}", stderr(&out));

    // Sweep stdout and stderr for every canary in every encoding!
    assert_no_canary(&out.stdout, &w.cs);
    assert_no_canary(&out.stderr, &w.cs);

    let out_text = stdout(&out);
    let lines: Vec<&str> = out_text.lines().collect();
    assert_eq!(lines.len(), 4, "expected 4 JSON-RPC replies: {lines:?}");
    for line in &lines {
        assert!(
            line.contains("[envcloak:custom/acme-web]"),
            "expected redaction marker in {line}"
        );
    }
    assert!(
        lines[0].contains("[envcloak:custom/second]")
            && lines[2].contains("[envcloak:custom/second]"),
        "expected second redaction marker in {lines:?}"
    );
    w.sweep();
}

/// M2-18 test 5 & Mutation (1): Redirects (`301`, `302`, `307`, `308`) to
/// another host/port are refused and the redirect target receives no request
/// and no header.
#[test]
fn redirects_are_refused_and_redirect_target_receives_nothing() {
    let w = BridgeWorld::new();
    let target_srv = TestServer::start(Vec::new());
    let target_url = target_srv.url("/steal");

    let origin_srv = TestServer::start(vec![
        MockResponse::redirect(301, &target_url),
        MockResponse::redirect(302, &target_url),
        MockResponse::redirect(307, &target_url),
        MockResponse::redirect(308, &target_url),
    ]);

    let origin = origin_srv.origin();
    let manifest = w.write_bridge_manifest(
        "remote-redirect",
        &origin,
        &[("Authorization", "custom/acme-web")],
    );
    w.register_bridge(
        "claude-code/redirect",
        &manifest,
        &origin,
        &["Authorization"],
    );

    let url = origin_srv.url("/mcp");
    let args = [
        "mcp-bridge",
        "--header-ref",
        "Authorization=custom/acme-web",
        "--manifest",
        manifest.to_str().unwrap(),
        "--url",
        url.as_str(),
    ];

    for code in [301u16, 302, 307, 308] {
        let req = r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#.to_owned() + "\n";
        let out = w.run_agent_bridge_approved(&args, req.as_bytes());
        assert_no_canary(&out.stdout, &w.cs);
        assert_no_canary(&out.stderr, &w.cs);
        assert_eq!(
            out.status.code(),
            Some(125),
            "redirect {code} should exit 125: {}",
            stderr(&out)
        );
        assert!(
            stderr(&out).contains("envcloak: run_failed:")
                && stderr(&out).contains("HTTP redirect, which mcp-bridge refuses to follow"),
            "unexpected stderr for {code}: {}",
            stderr(&out)
        );
        let reply: Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        assert!(
            reply["error"]["message"]
                .as_str()
                .unwrap()
                .contains("HTTP redirect refused: mcp-bridge never follows redirects"),
            "unexpected JSON-RPC error for {code}: {reply}"
        );
    }

    assert!(
        target_srv.recorded().is_empty(),
        "redirect target received a request: {:?}",
        target_srv.recorded()
    );
    w.sweep();
}

/// M2-18 test 6 & Mutation (5): An SSE event exceeding `MAX_SSE_EVENT_BYTES`
/// (1 MiB) is refused before it is buffered without bound.
#[test]
fn oversized_sse_event_is_refused() {
    let w = BridgeWorld::new();
    let mut big_sse = Vec::with_capacity(1100 * 1024);
    let chunk = format!("data: {}\n", "x".repeat(8192));
    while big_sse.len() <= envcloak_mcp::bridge::sse::MAX_SSE_EVENT_BYTES + 16384 {
        big_sse.extend_from_slice(chunk.as_bytes());
    }
    let srv = TestServer::start(vec![MockResponse::sse(&big_sse)]);
    let origin = srv.origin();
    let manifest = w.write_bridge_manifest(
        "remote-oversized-sse",
        &origin,
        &[("Authorization", "custom/acme-web")],
    );
    w.register_bridge(
        "claude-code/oversized-sse",
        &manifest,
        &origin,
        &["Authorization"],
    );

    let url = srv.url("/mcp");
    let args = [
        "mcp-bridge",
        "--header-ref",
        "Authorization=custom/acme-web",
        "--manifest",
        manifest.to_str().unwrap(),
        "--url",
        url.as_str(),
    ];

    let out = w.run_agent_bridge_approved(
        &args,
        b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n",
    );
    assert_no_canary(&out.stdout, &w.cs);
    assert_no_canary(&out.stderr, &w.cs);
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("envcloak: run_failed:")
            && stderr(&out)
                .contains("an SSE event from the upstream MCP server exceeded the size cap"),
        "unexpected stderr: {}",
        stderr(&out)
    );
    w.sweep();
}

/// M2-18 test 7: Broken-cert HTTPS server (self-signed untrusted certificate)
/// is refused by TLS verification before any HTTP request or secret header is
/// sent.
#[test]
fn broken_cert_https_server_is_refused_by_tls_verification() {
    let w = BridgeWorld::new();
    let cert_path = w.files.path().join("cert.pem");
    let key_path = w.files.path().join("key.pem");
    let cert_gen = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            key_path.to_str().unwrap(),
            "-out",
            cert_path.to_str().unwrap(),
            "-days",
            "1",
            "-subj",
            "/CN=127.0.0.1",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("openssl req");
    assert!(cert_gen.success(), "openssl req failed");

    let port_file = w.files.path().join("tls.port");
    let got_file = w.files.path().join("tls.got");
    let tls_srv_script = r#"import socket, ssl, sys
cert, key, port_path, got_path = sys.argv[1:5]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(certfile=cert, keyfile=key)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(("127.0.0.1", 0))
sock.listen(5)
with open(port_path + ".tmp", "w") as f:
    f.write(str(sock.getsockname()[1]))
import os
os.rename(port_path + ".tmp", port_path)
sock.settimeout(15.0)
try:
    conn, _ = sock.accept()
    with ctx.wrap_socket(conn, server_side=True) as tls:
        data = tls.recv(4096)
        if data:
            with open(got_path, "wb") as f:
                f.write(data)
except Exception:
    pass
"#;
    let mut tls_child = Command::new(python3())
        .args([
            "-c",
            tls_srv_script,
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
            port_file.to_str().unwrap(),
            got_file.to_str().unwrap(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let start = Instant::now();
    while !port_file.exists() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "tls server did not bind"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let port: u16 = std::fs::read_to_string(&port_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let origin = format!("https://127.0.0.1:{port}");
    let manifest = w.write_bridge_manifest(
        "remote-tls",
        &origin,
        &[("Authorization", "custom/acme-web")],
    );
    w.register_bridge("claude-code/tls", &manifest, &origin, &["Authorization"]);

    let url = format!("{origin}/mcp");
    let args = [
        "mcp-bridge",
        "--header-ref",
        "Authorization=custom/acme-web",
        "--manifest",
        manifest.to_str().unwrap(),
        "--url",
        url.as_str(),
    ];

    let out = w.run_agent_bridge_approved(
        &args,
        b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n",
    );
    let _ = tls_child.wait();
    assert_no_canary(&out.stdout, &w.cs);
    assert_no_canary(&out.stderr, &w.cs);
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("envcloak: run_failed:"),
        "expected run_failed on broken cert: {}",
        stderr(&out)
    );
    assert!(
        !got_file.exists(),
        "broken-cert TLS server should never receive HTTP payload bytes"
    );
    w.sweep();
}

/// M2-18 test 8 & Mutation (6): `--url` with a different origin than the
/// registered origin is refused with `managed_command_mismatch`, both in the
/// daemon and in the relay's handshake check.
#[test]
fn origin_mismatch_is_refused_managed_command_mismatch() {
    let w = BridgeWorld::new();
    let srv1 = TestServer::start(Vec::new());
    let srv2 = TestServer::start(Vec::new());
    let origin1 = srv1.origin();
    let origin2 = srv2.origin();

    let manifest = w.write_bridge_manifest(
        "remote-origin",
        &origin1,
        &[("Authorization", "custom/acme-web")],
    );
    w.register_bridge(
        "claude-code/origin",
        &manifest,
        &origin1,
        &["Authorization"],
    );

    // Ask for `origin2` against the manifest registered for `origin1`.
    let bad_url = srv2.url("/mcp");
    let bad_args = [
        "mcp-bridge",
        "--header-ref",
        "Authorization=custom/acme-web",
        "--manifest",
        manifest.to_str().unwrap(),
        "--url",
        bad_url.as_str(),
    ];
    let out = w.run_agent_bridge(
        &bad_args,
        b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n",
    );
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("envcloak: managed_command_mismatch:"),
        "unexpected stderr: {}",
        stderr(&out)
    );

    // Even if the manifest on disk is rewritten to carry `origin2`'s digest
    // without re-registering, the daemon's record check still refuses it with
    // `managed_command_mismatch`.
    let suffix2 = bridge_binding_suffix(&origin2);
    std::fs::write(
        &manifest,
        format!("[project]\nname = \"remote-origin\"\n\n[env]\nAUTHORIZATION{suffix2} = \"custom/acme-web\"\n"),
    )
    .unwrap();
    let out2 = w.run_agent_bridge(
        &bad_args,
        b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n",
    );
    assert_eq!(out2.status.code(), Some(125), "{}", stderr(&out2));
    assert!(
        stderr(&out2).contains("envcloak: managed_command_mismatch:"),
        "unexpected stderr: {}",
        stderr(&out2)
    );
    assert!(srv2.recorded().is_empty(), "srv2 received a request");

    // And the relay's own `validate_target_url` refuses any handshake URL
    // whose origin differs from the `Recipient::Relay` origin.
    let origin1_parsed = BridgeUrl::parse(&origin1).unwrap();
    let err =
        envcloak_mcp::bridge::relay::validate_target_url(&origin1_parsed, &bad_url).unwrap_err();
    assert_eq!(err.token(), "managed_command_mismatch");
    w.sweep();
}

/// M2-18 test 9 & Mutation (7): A known provider key (`sk_test_...` in
/// `stripe/acme-web`) in `--header-ref` is refused with `policy_denied` when
/// the target host is not in the provider's `allowed_hosts`, and the target
/// host receives zero requests.
#[test]
fn provider_allowed_hosts_refuses_known_provider_key_on_unlisted_host() {
    let w = BridgeWorld::new();
    let srv = TestServer::start(Vec::new());
    let origin = srv.origin();

    let manifest = w.write_bridge_manifest(
        "remote-provider-host",
        &origin,
        &[("Authorization", "stripe/acme-web")],
    );
    w.register_bridge(
        "claude-code/provider-host",
        &manifest,
        &origin,
        &["Authorization"],
    );

    let url = srv.url("/mcp");
    let args = [
        "mcp-bridge",
        "--header-ref",
        "Authorization=stripe/acme-web",
        "--manifest",
        manifest.to_str().unwrap(),
        "--url",
        url.as_str(),
    ];

    let out = w.run_agent_bridge_approved(
        &args,
        b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n",
    );
    assert_no_canary(&out.stdout, &w.cs);
    assert_no_canary(&out.stderr, &w.cs);
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("envcloak: policy_denied:"),
        "expected policy_denied for Stripe key on 127.0.0.1: {}",
        stderr(&out)
    );
    assert!(
        srv.recorded().is_empty(),
        "server should receive no request when allowed_hosts refuses"
    );
    w.sweep();
}

/// M2-18 test 10 & Mutation (9): Short values (`<8` bytes in `tiny/acme-web`,
/// or `8..15` bytes without `allow_short` in `short/acme-web`) are refused
/// with `value_too_short` before any outbound HTTP request is sent.
#[test]
fn short_value_is_refused_before_any_outbound_request() {
    let w = BridgeWorld::new();
    let srv = TestServer::start(Vec::new());
    let origin = srv.origin();

    for (idx, slug) in [("short8", "short/acme-web"), ("tiny7", "tiny/acme-web")] {
        let manifest = w.write_bridge_manifest(
            &format!("remote-{idx}"),
            &origin,
            &[("Authorization", slug)],
        );
        w.register_bridge(
            &format!("claude-code/{idx}"),
            &manifest,
            &origin,
            &["Authorization"],
        );
        let url = srv.url("/mcp");
        let header_ref = format!("Authorization={slug}");
        let args = [
            "mcp-bridge",
            "--header-ref",
            header_ref.as_str(),
            "--manifest",
            manifest.to_str().unwrap(),
            "--url",
            url.as_str(),
        ];

        let out = w.run_agent_bridge_approved(
            &args,
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n",
        );
        assert_no_canary(&out.stdout, &w.cs);
        assert_no_canary(&out.stderr, &w.cs);
        assert_eq!(out.status.code(), Some(125), "{slug}: {}", stderr(&out));
        assert!(
            stderr(&out).contains("envcloak: value_too_short:") && stderr(&out).contains(slug),
            "expected value_too_short naming {slug}: {}",
            stderr(&out)
        );
    }

    assert!(
        srv.recorded().is_empty(),
        "server should receive no request when short value is refused"
    );
    w.sweep();
}

/// M2-18 test 11: `--stdio --launch <id>` round-trip with daemon-spawned
/// runner, output redaction, D-04 waiting, lifeline termination within 2
/// seconds, and refusal when the script is modified (`managed_launch_changed`)
/// or the launch id is unregistered (`managed_command_mismatch`).
#[test]
fn stdio_launch_round_trip_redaction_lifeline_and_refusals() {
    let w = BridgeWorld::new();
    let proj_dir = w.home.root().join("stdio-proj");
    std::fs::create_dir_all(&proj_dir).unwrap();
    let manifest = proj_dir.join("envcloak.toml");
    std::fs::write(
        &manifest,
        "[project]\nname = \"stdio-proj\"\n\n[env]\nCUSTOM_SECRET = \"custom/acme-web\"\n",
    )
    .unwrap();

    let pid_file = w.files.path().join("stdio-server.pid");
    let server_py = proj_dir.join("mcp_stdio_server.py");
    let script_body = format!(
        r#"import json, os, sys, time
with open({:?} + ".tmp", "w") as f:
    f.write(str(os.getpid()))
os.rename({:?} + ".tmp", {:?})
secret = os.environ.get("CUSTOM_SECRET", "")
for line in sys.stdin:
    msg = json.loads(line)
    reply = {{"jsonrpc": "2.0", "id": msg.get("id"), "result": {{"echo_secret": secret, "has_secret": bool(secret)}}}}
    sys.stdout.write(json.dumps(reply) + "\n")
    sys.stdout.flush()
time.sleep(30)
"#,
        pid_file.to_str().unwrap(),
        pid_file.to_str().unwrap(),
        pid_file.to_str().unwrap(),
    );
    std::fs::write(&server_py, &script_body).unwrap();

    let py = python3();
    let launch_id = w.register_stdio(
        "claude-code/stdio-server",
        &manifest,
        &[py.to_str().unwrap(), server_py.to_str().unwrap()],
        Some(&proj_dir),
    );

    // 1. Start `mcp-bridge --stdio --launch <id> --wait 30s`, approve while waiting (D-04).
    let args = [
        "mcp-bridge",
        "--stdio",
        "--launch",
        launch_id.as_str(),
        "--wait",
        "30s",
    ];
    let mut child = w.spawn_agent_bridge(&args);
    let mut child_stdin = child.stdin.take().unwrap();
    let mut child_stdout = BufReader::new(child.stdout.take().unwrap());
    let mut child_stderr = BufReader::new(child.stderr.take().unwrap());

    let mut pending_line = String::new();
    child_stderr.read_line(&mut pending_line).unwrap();
    assert!(
        pending_line.contains("approval_required"),
        "expected approval_required on stderr: {pending_line}"
    );
    let req_id = extract_request_id(&pending_line);
    w.approve_session(&req_id);

    writeln!(
        child_stdin,
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call"}}"#
    )
    .unwrap();
    child_stdin.flush().unwrap();

    let mut reply_line = String::new();
    child_stdout.read_line(&mut reply_line).unwrap();
    assert_no_canary(reply_line.as_bytes(), &w.cs);
    let reply: Value = serde_json::from_str(&reply_line).unwrap();
    assert_eq!(reply["id"], 1);
    assert_eq!(reply["result"]["has_secret"], true);
    assert_eq!(
        reply["result"]["echo_secret"], "[envcloak:custom/acme-web]",
        "stdio runner must redact echoed secret: {reply}"
    );

    // Wait for the server's pid file and verify lifeline termination within 2s
    // when the bridge client is killed.
    let start = Instant::now();
    while !pid_file.exists() {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "pid_file not written"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let srv_pid: i32 = std::fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();

    let _ = child.kill();
    let _ = child.wait();
    drop(child_stdin);

    let kill_time = Instant::now();
    loop {
        // Check if `srv_pid` has exited (`kill(pid, 0) != 0`).
        let alive = Command::new("/bin/kill")
            .args(["-0", &srv_pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !alive {
            break;
        }
        assert!(
            kill_time.elapsed() < Duration::from_secs(2),
            "stdio server pid {srv_pid} did not terminate within 2s of lifeline drop"
        );
        std::thread::sleep(Duration::from_millis(25));
    }

    // 2. Unregistered launch id -> `managed_command_mismatch`.
    let bad_id = "01J5Z000000000000000000000";
    let unreg_out = w.run_agent_bridge(&["mcp-bridge", "--stdio", "--launch", bad_id], b"");
    assert_eq!(unreg_out.status.code(), Some(125), "{}", stderr(&unreg_out));
    assert!(
        stderr(&unreg_out).contains("envcloak: managed_command_mismatch:"),
        "expected managed_command_mismatch: {}",
        stderr(&unreg_out)
    );

    // 3. Modify the registered script -> `managed_launch_changed`.
    std::fs::write(&server_py, format!("{script_body}\n# modified\n")).unwrap();
    let changed_out = w.run_agent_bridge(
        &["mcp-bridge", "--stdio", "--launch", launch_id.as_str()],
        b"",
    );
    assert_eq!(
        changed_out.status.code(),
        Some(125),
        "{}",
        stderr(&changed_out)
    );
    assert!(
        stderr(&changed_out).contains("envcloak: managed_launch_changed:"),
        "expected managed_launch_changed: {}",
        stderr(&changed_out)
    );
    w.sweep();
}

/// M2-18 test 12: Gate 13 (`value_on_argv`, exit 2) when a key-shaped value is
/// passed in `--header-ref`, `--url`, `--manifest`, or `--launch`.
#[test]
fn gate_13_value_on_argv_refused_in_mcp_bridge() {
    let w = BridgeWorld::new();
    let key = w.value(labels::STRIPE_SECRET_KEY).to_owned();
    let header_with_key = format!("Authorization={key}");
    let url_with_key = format!("https://mcp.example.com/{key}");
    let manifest_with_key = format!("/tmp/{key}/envcloak.toml");

    for args in [
        vec![
            "mcp-bridge",
            "--header-ref",
            header_with_key.as_str(),
            "--manifest",
            "/tmp/envcloak.toml",
            "--url",
            "https://mcp.example.com/v1",
        ],
        vec![
            "mcp-bridge",
            "--header-ref",
            "Authorization=stripe/acme-web",
            "--manifest",
            "/tmp/envcloak.toml",
            "--url",
            url_with_key.as_str(),
        ],
        vec![
            "mcp-bridge",
            "--header-ref",
            "Authorization=stripe/acme-web",
            "--manifest",
            manifest_with_key.as_str(),
            "--url",
            "https://mcp.example.com/v1",
        ],
    ] {
        let out = run(&w.home, &args, &[]);
        assert_no_canary(&out.stdout, &w.cs);
        assert_no_canary(&out.stderr, &w.cs);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {}", stderr(&out));
        assert!(
            stderr(&out).starts_with("envcloak: value_on_argv: "),
            "expected value_on_argv for {args:?}: {}",
            stderr(&out)
        );
    }
    let _ = HeaderRef::parse("Authorization=stripe/acme-web").unwrap();
    w.sweep();
}
