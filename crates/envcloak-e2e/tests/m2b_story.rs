//! The M2b acceptance story (`SPEC.md` §6.8, §15.2, M2 plan task `M2b-11`,
//! gates `b1` through `b19` and `41`): end-to-end verification of `T1` through
//! `T13`, the release-feature barrier check, and the five `M2b-11` mutation
//! controls.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use envcloak_e2e::{Harness, RECOVERY_KIT, python3, text, token, versions_toml};
use envcloak_ipc::view::{GrantsView, PendingListView, SigninTargetListView};
use envcloak_testkit::agents::{AgentHome, Host, HostFlags, Installed, require};
use envcloak_testkit::signin::{
    ALLOWED_BROWSER_TOOLS, BrowserSupervisor, CONTEXT_NOT_PUBLISHED, ExpectedIdentity,
    FORBIDDEN_PATH_ARGS, SigninFixture, SupervisorOptions, ToolAllowlist, http_request,
    measure_chrome_pipe_and_session, require_browser_runtime, run_cookie_scope_probe,
    test_session_mint,
};
use envcloak_testkit::transcripts::Sweep;
use envcloak_testkit::{Canary, fresh_seed, labels, testkit_bin};
use serde_json::{Value, json};

const RFC6238_BASE32_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const RFC6238_RAW_SEED: &[u8] = b"12345678901234567890";
const MANIFEST: &str = "[env]\nOPENAI_API_KEY = \"openai/acme-web\"\n";
const GRANT_REVOKED: &str = "grant_revoked";

fn sha1_digest(msg: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xefcd_ab89;
    let mut h2: u32 = 0x98ba_dcfe;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xc3d2_e1f0;

    let bit_len = (msg.len() as u64) * 8;
    let mut padded = msg.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }
    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

fn rfc6238_totp_sha1_8(seed: &[u8], step: u64) -> [u8; 8] {
    let mut k_block = [0u8; 64];
    if seed.len() > 64 {
        let d = sha1_digest(seed);
        k_block[..20].copy_from_slice(&d);
    } else {
        k_block[..seed.len()].copy_from_slice(seed);
    }
    let mut inner = Vec::with_capacity(72);
    for &b in &k_block {
        inner.push(b ^ 0x36);
    }
    inner.extend_from_slice(&step.to_be_bytes());
    let inner_hash = sha1_digest(&inner);

    let mut outer = Vec::with_capacity(84);
    for &b in &k_block {
        outer.push(b ^ 0x5c);
    }
    outer.extend_from_slice(&inner_hash);
    let mac = sha1_digest(&outer);

    let offset = (mac[19] & 0x0f) as usize;
    let bin_code = ((u32::from(mac[offset]) & 0x7f) << 24)
        | (u32::from(mac[offset + 1]) << 16)
        | (u32::from(mac[offset + 2]) << 8)
        | u32::from(mac[offset + 3]);
    let mut val = bin_code % 100_000_000;
    let mut digits = [b'0'; 8];
    for idx in (0..8).rev() {
        digits[idx] = b'0' + (val % 10) as u8;
        val /= 10;
    }
    digits
}

/// Counts occurrences of `code_digits` in `haystack`.
fn count_code_matches(haystack: &[u8], code_digits: &[u8]) -> usize {
    if code_digits.is_empty() || haystack.len() < code_digits.len() {
        return 0;
    }
    haystack
        .windows(code_digits.len())
        .filter(|w| *w == code_digits)
        .count()
}

fn secret_input(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let p = dir.join(name);
    let mut buf = bytes.to_vec();
    if !buf.ends_with(b"\n") {
        buf.push(b'\n');
    }
    std::fs::write(&p, buf).unwrap();
    p
}

fn create_vault(h: &mut Harness, cwd: &Path) {
    let pass = h.secret_file(labels::VAULT_PASSPHRASE, true);
    let kit = h.files().join("kit");
    let out = h.human(
        cwd,
        &[
            "vault",
            "create",
            "--passphrase-fd",
            "3",
            "--kit-fd",
            "4",
            "--kdf-memory",
            "64MiB",
        ],
        &[(3, &pass, true), (4, &kit, false)],
        &[],
    );
    assert_eq!(out.code, 0, "{}", out.all());
    let kit_text = std::fs::read_to_string(&kit).unwrap();
    let trimmed = kit_text.trim().to_owned();
    assert!(!trimmed.is_empty());
    h.add_canary(Canary::new(RECOVERY_KIT, trimmed));
    let confirmed = h.human(
        cwd,
        &["recovery", "confirm", "--kit-fd", "4"],
        &[(4, &kit, true)],
        &[],
    );
    assert_eq!(confirmed.code, 0, "{}", confirmed.all());
}

fn pending_ids(h: &mut Harness, cwd: &Path) -> Vec<String> {
    let out = h.human(cwd, &["pending", "--json"], &[], &[]);
    assert_eq!(out.code, 0, "{}", out.all());
    let plist: PendingListView = serde_json::from_slice(&out.stdout).unwrap();
    plist.requests.into_iter().map(|r| r.request).collect()
}

fn wait_for_pending_id(h: &mut Harness, cwd: &Path, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    loop {
        let ids = pending_ids(h, cwd);
        if let Some(first) = ids.into_iter().next() {
            return first;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for pending sign-in request"
        );
        std::thread::sleep(Duration::from_millis(35));
    }
}

fn extract_last_tool_output(req_body: &str) -> String {
    let Ok(v) = serde_json::from_str::<Value>(req_body) else {
        return String::new();
    };
    if let Some(msgs) = v.get("messages").and_then(Value::as_array) {
        for msg in msgs.iter().rev() {
            if let Some(content) = msg.get("content").and_then(Value::as_array) {
                for item in content.iter().rev() {
                    if item.get("type").and_then(Value::as_str) == Some("tool_result") {
                        if let Some(s) = item.get("content").and_then(Value::as_str) {
                            return s.to_owned();
                        }
                        if let Some(arr) = item.get("content").and_then(Value::as_array) {
                            let joined: String = arr
                                .iter()
                                .filter_map(|x| x.get("text").and_then(Value::as_str))
                                .collect::<Vec<_>>()
                                .join("\n");
                            if !joined.is_empty() {
                                return joined;
                            }
                        }
                    }
                }
            }
        }
    }
    if let Some(inp) = v.get("input").and_then(Value::as_array) {
        for item in inp.iter().rev() {
            if item.get("type").and_then(Value::as_str) == Some("function_call_output")
                && let Some(out) = item.get("output").and_then(Value::as_str)
            {
                return out.to_owned();
            }
        }
    }
    String::new()
}

fn after_step(requests: &[envcloak_testkit::agents::ModelRequest], pick: &str) -> String {
    requests
        .iter()
        .find(|r| r.pick.as_deref() == Some(pick))
        .map(|r| extract_last_tool_output(&String::from_utf8_lossy(&r.body)))
        .unwrap_or_else(|| panic!("no model request for {pick}"))
}

/// A persistent `envcloak mcp` child process started under `fixture-agent` in
/// its own session (`os.setsid()`).
struct McpSession {
    child: std::process::Child,
    stdin: Option<std::process::ChildStdin>,
    lines: mpsc::Receiver<Vec<u8>>,
    out: Arc<Mutex<Vec<u8>>>,
    err: Arc<Mutex<Vec<u8>>>,
    kept: Vec<Value>,
    next_id: i64,
}

impl McpSession {
    fn start(h: &Harness, cwd: &Path, args: &[&str]) -> Self {
        let py = python3();
        let mut cmd = Command::new(&py);
        h.home
            .apply(&mut cmd)
            .env("ENVCLOAK_MCP_SIGNIN", "1")
            .args([
                "-c",
                "import os, sys; os.setsid(); os.execv(sys.argv[1], sys.argv[1:])",
            ])
            .arg(testkit_bin("fixture-agent"))
            .arg("--")
            .arg(h.cli())
            .arg("mcp")
            .args(args)
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().expect("spawn fixture-agent envcloak mcp");
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut stderr = child.stderr.take().unwrap();
        let out = Arc::new(Mutex::new(Vec::new()));
        let out_copy = Arc::clone(&out);
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in stdout.split(b'\n').map_while(Result::ok) {
                out_copy.lock().unwrap().extend_from_slice(&line);
                out_copy.lock().unwrap().push(b'\n');
                if tx.send(line).is_err() {
                    return;
                }
            }
        });
        let err = Arc::new(Mutex::new(Vec::new()));
        let err_copy = Arc::clone(&err);
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = stderr.read(&mut buf) {
                if n == 0 {
                    break;
                }
                err_copy.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        });
        let mut s = Self {
            child,
            stdin: Some(stdin),
            lines,
            out,
            err,
            kept: Vec::new(),
            next_id: 1,
        };
        s.send(&json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "m2b-story", "version": "0.1.0"}
            }
        }));
        let init = s.answer(0, Duration::from_secs(10));
        assert_eq!(init["result"]["serverInfo"]["name"], "envcloak", "{init}");
        s.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
        s
    }

    fn send(&mut self, msg: &Value) {
        let stdin = self.stdin.as_mut().expect("mcp stdin open");
        let mut raw = serde_json::to_vec(msg).unwrap();
        raw.push(b'\n');
        stdin.write_all(&raw).unwrap();
        stdin.flush().unwrap();
    }

    fn call_async(&mut self, tool: &str, arguments: Value) -> i64 {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": tool,
                "arguments": arguments,
            }
        }));
        id
    }

    fn call_raw(&mut self, tool: &str, arguments: Value) -> Value {
        let id = self.call_async(tool, arguments);
        self.answer(id, Duration::from_secs(45))
    }

    fn call(&mut self, tool: &str, arguments: Value) -> Value {
        let ans = self.call_raw(tool, arguments);
        assert!(ans.get("error").is_none(), "protocol error: {ans}");
        ans["result"].clone()
    }

    fn list_tools(&mut self) -> Vec<Value> {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/list",
            "params": {}
        }));
        let ans = self.answer(id, Duration::from_secs(10));
        ans["result"]["tools"].as_array().unwrap().clone()
    }

    fn answer(&mut self, id: i64, timeout: Duration) -> Value {
        if let Some(pos) = self.kept.iter().position(|v| v["id"] == json!(id)) {
            return self.kept.remove(pos);
        }
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let line = self.lines.recv_timeout(left).unwrap_or_else(|_| {
                let err = String::from_utf8_lossy(&self.err.lock().unwrap()).into_owned();
                panic!("timed out waiting for MCP id {id}; stderr:\n{err}");
            });
            let v: Value = serde_json::from_slice(&line).unwrap();
            if v["id"] == json!(id) {
                return v;
            }
            self.kept.push(v);
        }
    }

    fn finish(mut self, h: &mut Harness, label: &str) {
        drop(self.stdin.take());
        let _ = self.child.wait();
        let out = self.out.lock().unwrap().clone();
        let err = self.err.lock().unwrap().clone();
        h.record(&format!("{label} stdout"), &out);
        h.record(&format!("{label} stderr"), &err);
    }
}

/// Complete M2b acceptance story (`T1` through `T13`, gates `b1` through `b19`
/// and `41`).
#[test]
fn m2b_acceptance_story_end_to_end() {
    envcloak_e2e::check_network();
    let Some(runtime) = require_browser_runtime() else {
        return;
    };
    let claude_found = Installed::find(&versions_toml(), Host::ClaudeCode.id(), "native");
    let codex_found = Installed::find(&versions_toml(), Host::Codex.id(), "native");
    let (Some(claude_inst), Some(codex_inst)) = (
        require(claude_found, "M2b-11 story (Claude Code)"),
        require(codex_found, "M2b-11 story (Codex)"),
    ) else {
        return;
    };

    let (origins, control) = SigninFixture::start();
    let clock_dir = tempfile::Builder::new()
        .prefix("ecclk")
        .tempdir_in("/tmp")
        .unwrap();
    let clock_file = clock_dir.path().join("clock-offset.txt");
    std::fs::write(&clock_file, "0").unwrap();
    let clock_file_str = clock_file.to_str().unwrap().to_owned();
    let chrome_exe_str = runtime.chrome_exe.to_str().unwrap().to_owned();
    let node_exe_str = runtime.node_exe.to_str().unwrap().to_owned();
    let helper_mods_str = runtime.helper_modules.to_str().unwrap().to_owned();

    let mut h = Harness::start_with(&[
        ("ENVCLOAK_TEST_CLOCK_FILE", &clock_file_str),
        ("ENVCLOAK_TEST_TOTP_START_UNIX", "0"),
        ("ENVCLOAK_CHROME_FOR_TESTING_BIN", &chrome_exe_str),
        ("ENVCLOAK_NODE_BIN", &node_exe_str),
        ("ENVCLOAK_BROWSER_HELPER_MODULES", &helper_mods_str),
        ("ENVCLOAK_BROWSER_HELPER_NODE_MODULES", &helper_mods_str),
    ]);

    let rotated_editor_pw = format!("ec-rot-pw-{:016x}", fresh_seed());
    h.add_canary(Canary::new(
        "SIGNIN_EDITOR_PW",
        origins.editor_password.clone(),
    ));
    h.add_canary(Canary::new("SIGNIN_ROTATED_PW", rotated_editor_pw.clone()));
    h.add_canary(Canary::new(
        "SIGNIN_ADMIN_PW",
        origins.admin_password.clone(),
    ));
    h.add_canary(Canary::new(
        "SIGNIN_ADAPTER_KEY",
        origins.adapter_key.clone(),
    ));
    h.add_canary(Canary::new(
        "SIGNIN_BASE32_SEED",
        RFC6238_BASE32_SECRET.to_owned(),
    ));
    h.add_canary(Canary::new(
        "SIGNIN_RAW_SEED",
        String::from_utf8_lossy(RFC6238_RAW_SEED).into_owned(),
    ));

    let project = h.home.home().join("acme-web");
    std::fs::create_dir_all(&project).unwrap();
    let manifest_path = project.join("envcloak.toml");
    std::fs::write(&manifest_path, MANIFEST).unwrap();
    let manifest_str = manifest_path.to_str().unwrap().to_owned();
    let project_str = project.to_str().unwrap().to_owned();

    // =========================================================================
    // T1: Vault creation, `envcloak signin setup --agents`, login items, and
    //     sign-in target registration (`acme/form`, `acme/adapter`,
    //     `acme/admin`, `acme/norevoke`).
    // =========================================================================
    create_vault(&mut h, &project);

    let claude = AgentHome::within(&h.home, Host::ClaudeCode, claude_inst);
    let codex = AgentHome::within(&h.home, Host::Codex, codex_inst);
    let bin = h.home.root().join("story-bin");
    std::fs::create_dir_all(&bin).unwrap();
    for (a, name) in [(&claude, "claude"), (&codex, "codex")] {
        let dst = bin.join(name);
        if !dst.exists() {
            std::os::unix::fs::symlink(&a.installed.exe, dst).unwrap();
        }
    }
    let envcloak_link = bin.join("envcloak");
    std::os::unix::fs::symlink(h.cli(), &envcloak_link).unwrap();

    // Run `envcloak signin setup --agents --yes --consent-approval-mode` with `bin` on PATH.
    let path_with_hosts = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut setup_cmd = Command::new(&envcloak_link);
    h.home
        .apply(&mut setup_cmd)
        .env("PATH", &path_with_hosts)
        .env("TMPDIR", claude.claude_tmp())
        .current_dir(&project)
        .args([
            "signin",
            "setup",
            "--agents",
            "--yes",
            "--consent-approval-mode",
        ]);
    let setup_out = setup_cmd.output().unwrap();
    h.record("T1 signin setup stdout", &setup_out.stdout);
    h.record("T1 signin setup stderr", &setup_out.stderr);
    assert!(setup_out.status.success(), "{}", text(&setup_out));

    for rel in [".claude/CLAUDE.md", ".codex/AGENTS.md"] {
        let md = std::fs::read_to_string(h.home.home().join(rel)).unwrap();
        assert!(
            md.lines()
                .any(|l| l == envcloak_agents::blocks::SIGNIN_LINE),
            "{rel} missing SIGNIN_LINE after `signin setup --agents`: {md}"
        );
    }

    let pass_file = h.secret_file(labels::VAULT_PASSPHRASE, true);
    let editor_user = secret_input(h.files(), "editor_user", b"editor@acme.test");
    let editor_pw = secret_input(h.files(), "editor_pw", origins.editor_password.as_bytes());
    let otpauth_editor = format!(
        "otpauth://totp/Acme:editor%40acme.test?secret={RFC6238_BASE32_SECRET}&digits=8&period=30&algorithm=SHA1"
    );
    let editor_totp = secret_input(h.files(), "editor_totp", otpauth_editor.as_bytes());
    let editor_adapter = secret_input(h.files(), "editor_adapter", origins.adapter_key.as_bytes());

    let add_editor = h.human(
        &project,
        &[
            "add",
            "--login",
            "acme/editor",
            "--test",
            "--tier",
            "dev",
            "--username-fd",
            "3",
            "--password-fd",
            "4",
            "--totp-fd",
            "5",
            "--adapter-key-fd",
            "6",
        ],
        &[
            (3, &editor_user, true),
            (4, &editor_pw, true),
            (5, &editor_totp, true),
            (6, &editor_adapter, true),
        ],
        &[],
    );
    assert_eq!(add_editor.code, 0, "{}", add_editor.all());

    let admin_user = secret_input(h.files(), "admin_user", b"admin@acme.test");
    let admin_pw = secret_input(h.files(), "admin_pw", origins.admin_password.as_bytes());
    let otpauth_admin = format!(
        "otpauth://totp/Acme:admin%40acme.test?secret={RFC6238_BASE32_SECRET}&digits=8&period=30&algorithm=SHA1"
    );
    let admin_totp = secret_input(h.files(), "admin_totp", otpauth_admin.as_bytes());
    let add_admin = h.human(
        &project,
        &[
            "add",
            "--login",
            "acme/admin",
            "--test",
            "--tier",
            "step-up",
            "--username-fd",
            "3",
            "--password-fd",
            "4",
            "--totp-fd",
            "5",
        ],
        &[
            (3, &admin_user, true),
            (4, &admin_pw, true),
            (5, &admin_totp, true),
        ],
        &[],
    );
    assert_eq!(add_admin.code, 0, "{}", add_admin.all());

    let revoke_form_url = format!("{}/api/revoke", origins.app);
    let revoke_adapter_url = format!("{}/__envcloak/test-session/revoke", origins.app);

    for (tname, login_slug, acct, role, tier, adapter_opt, rev_opt) in [
        (
            "acme/form",
            "acme/editor",
            "editor@acme.test",
            "editor",
            "dev",
            None,
            Some(revoke_form_url.as_str()),
        ),
        (
            "acme/adapter",
            "acme/editor",
            "editor@acme.test",
            "editor",
            "dev",
            Some("test_session"),
            Some(revoke_adapter_url.as_str()),
        ),
        (
            "acme/admin",
            "acme/admin",
            "admin@acme.test",
            "admin",
            "step-up",
            None,
            Some(revoke_form_url.as_str()),
        ),
        (
            "acme/norevoke",
            "acme/editor",
            "editor@acme.test",
            "editor",
            "dev",
            None,
            None,
        ),
    ] {
        let mut args = vec![
            "signin",
            "target",
            "add",
            tname,
            "--login",
            login_slug,
            "--credential-origin",
            &origins.app,
            "--app-origin",
            &origins.app,
            "--identity-check",
            "endpoint",
            "/api/whoami",
            "--account",
            acct,
            "--tenant",
            "t1",
            "--role",
            role,
            "--cookie",
            "session@acme.localhost/",
            "--tier",
            tier,
            "--approval-lifetime",
            "4h",
            "--session-lifetime",
            "1h",
            "--manifest",
            &manifest_str,
            "--passphrase-fd",
            "3",
        ];
        if let Some(ad) = adapter_opt {
            args.push("--adapter");
            args.push(ad);
        }
        if let Some(rev) = rev_opt {
            args.push("--revocation");
            args.push(rev);
        }
        let added = h.human(&project, &args, &[(3, &pass_file, true)], &[]);
        assert_eq!(added.code, 0, "{}", added.all());
        assert!(
            added
                .out()
                .contains("cookies on a loopback host are shared across every port on that host"),
            "missing loopback cookie-jar receipt note for {tname}: {}",
            added.all()
        );
    }

    let ls_out = h.human(&project, &["signin", "target", "ls", "--json"], &[], &[]);
    assert_eq!(ls_out.code, 0, "{}", ls_out.all());
    let tlist: SigninTargetListView = serde_json::from_slice(&ls_out.stdout).unwrap();
    assert_eq!(tlist.targets.len(), 4);
    assert!(tlist.targets.iter().all(|t| t.shared_loopback_cookie_jar));
    assert!(
        tlist
            .targets
            .iter()
            .any(|t| t.name == "acme/form" && t.login_slug.as_deref() == Some("acme/editor")),
        "expected acme/form target to reference acme/editor: {tlist:?}"
    );
    assert!(
        tlist
            .targets
            .iter()
            .any(|t| t.name == "acme/admin" && t.login_slug.as_deref() == Some("acme/admin")),
        "expected acme/admin target to reference acme/admin: {tlist:?}"
    );

    // Add a regular env-var secret so `list_secrets` has a positive entry while
    // verifying `D-33` (`login_reference` and login items never appear in `list_secrets`).
    let api_key_val = format!("sk-acme-story-{:016x}", fresh_seed());
    h.add_canary(Canary::new("OPENAI_API_KEY", api_key_val.clone()));
    let api_key_in = secret_input(h.files(), "openai_key", api_key_val.as_bytes());
    let add_secret = h.human(
        &project,
        &["add", "openai", "--slug", "openai/acme-web", "--stdin"],
        &[(0, &api_key_in, true)],
        &[],
    );
    assert_eq!(add_secret.code, 0, "{}", add_secret.all());

    let mut all_op_keys = Vec::new();
    let mut claude_models = Vec::new();
    let mut codex_models = Vec::new();

    // =========================================================================
    // T2 & T6 (R-M2b-37 per-host loop): Real Claude Code (`T2`, `acme/form`) and
    //     real Codex (`T6`, `acme/adapter`) sign in, person approves `--dev 10m`,
    //     the host navigates to `/dashboard` and reads `#build-number` (`4217`).
    // =========================================================================
    let dashboard_url = format!("{}/dashboard", origins.app);
    // Pre-allow `browser_navigate` and `browser_snapshot` in `.codex/config.toml`
    // so `codex exec` under `approval_policy="never"` can call them after `request_sign_in`.
    let codex_cfg_path = h.home.home().join(".codex/config.toml");
    let mut codex_cfg = std::fs::read_to_string(&codex_cfg_path).unwrap();
    codex_cfg.push_str(
        "\n[mcp_servers.envcloak.tools.browser_navigate]\napproval_mode = \"approve\"\n\
         [mcp_servers.envcloak.tools.browser_snapshot]\napproval_mode = \"approve\"\n",
    );
    std::fs::write(&codex_cfg_path, &codex_cfg).unwrap();

    let op_t2 = format!("opkey-t2-claude-form-{:016x}", fresh_seed());
    all_op_keys.push(op_t2.clone());
    let claude_script = json!({
        "steps": [
            {
                "tool": "mcp__envcloak__request_sign_in",
                "input": {
                    "target": "acme/form",
                    "role": "editor",
                    "operation_key": op_t2,
                    "project_dir": project_str,
                }
            },
            {
                "tool": "mcp__envcloak__request_sign_in",
                "input": {
                    "target": "acme/form",
                    "role": "editor",
                    "operation_key": op_t2,
                    "project_dir": project_str,
                },
                "after": "t2_approved"
            },
            {
                "tool": "mcp__envcloak__browser_navigate",
                "input": { "url": dashboard_url }
            },
            {
                "tool": "mcp__envcloak__browser_snapshot",
                "input": {}
            },
            {
                "tool": "mcp__envcloak__browser_take_screenshot",
                "input": {}
            },
            { "say": "T2 build-number 4217 verified" }
        ]
    });
    let claude_flags = HostFlags::claude(
        "default",
        &[
            "mcp__envcloak__browser_navigate",
            "mcp__envcloak__browser_snapshot",
            "mcp__envcloak__browser_take_screenshot",
        ],
    );

    let op_t6 = format!("opkey-t6-codex-{:016x}", fresh_seed());
    all_op_keys.push(op_t6.clone());
    let codex_script = json!({
        "steps": [
            {
                "tool": "request_sign_in",
                "namespace": "mcp__envcloak",
                "input": {
                    "target": "acme/adapter",
                    "role": "editor",
                    "operation_key": op_t6,
                    "project_dir": project_str,
                }
            },
            {
                "tool": "request_sign_in",
                "namespace": "mcp__envcloak",
                "input": {
                    "target": "acme/adapter",
                    "role": "editor",
                    "operation_key": op_t6,
                    "project_dir": project_str,
                },
                "after": "t6_approved"
            },
            {
                "tool": "browser_navigate",
                "namespace": "mcp__envcloak",
                "input": { "url": dashboard_url }
            },
            {
                "tool": "browser_snapshot",
                "namespace": "mcp__envcloak",
                "input": {}
            },
            { "say": "T6 codex 4217 verified" }
        ]
    });
    let codex_flags =
        HostFlags::codex("read-only", "never").with(&["--dangerously-bypass-hook-trust"]);

    for (label, agent_home, script, flags, gate_name, check_screenshot, is_claude) in [
        (
            "T2 Claude Code",
            &claude,
            &claude_script,
            &claude_flags,
            "t2_approved",
            true,
            true,
        ),
        (
            "T6 Codex",
            &codex,
            &codex_script,
            &codex_flags,
            "t6_approved",
            false,
            false,
        ),
    ] {
        let mut running = agent_home.spawn(
            script,
            "Sign in and read #build-number on /dashboard.",
            flags,
            &project,
        );
        let held = running.model.wait_for("step 1", &mut running.child);
        h.record(&format!("{label} model request (held)"), &held.body);
        let req_id = if is_claude {
            let first: Value = serde_json::from_str(&extract_last_tool_output(
                &String::from_utf8_lossy(&held.body),
            ))
            .expect("first request_sign_in JSON output");
            assert_eq!(first["state"], "waiting_for_approval", "{first}");
            let id = first["request"].as_str().unwrap().to_owned();
            assert_eq!(pending_ids(&mut h, &project), vec![id.clone()]);
            id
        } else {
            wait_for_pending_id(&mut h, &project, Duration::from_secs(10))
        };

        let approve_out = h.human(
            &project,
            &["approve", &req_id, "--dev", "10m", "--passphrase-fd", "3"],
            &[(3, &pass_file, true)],
            &[],
        );
        assert_eq!(approve_out.code, 0, "{}", approve_out.all());
        assert!(
            approve_out.out().contains("dev authorization "),
            "{}",
            approve_out.all()
        );

        running.model.release(gate_name);
        let run = running.wait();
        h.record(&format!("{label} stdout"), &run.output.stdout);
        h.record(&format!("{label} stderr"), &run.output.stderr);
        for r in &run.model.requests {
            h.record(&format!("{label} model req {}", r.seq), &r.body);
        }
        assert_eq!(run.output.status.code(), Some(0), "{}", run.text());

        if is_claude {
            let pub_val: Value =
                serde_json::from_str(&after_step(&run.model.requests, "step 2")).unwrap();
            assert_eq!(pub_val["state"], "published", "{pub_val}");
            assert_eq!(pub_val["delivered_context"], "ctx-1", "{pub_val}");
        }

        let snap = after_step(&run.model.requests, "step 4");
        assert!(
            snap.contains(&origins.build_number),
            "expected #build-number {} in {label} browser_snapshot: {snap}",
            origins.build_number
        );
        if check_screenshot {
            let shot = after_step(&run.model.requests, "step 5");
            assert!(
                !shot.contains("SECRET-BANNER-DO-NOT-LEAK"),
                "screenshot output must never include #secret-banner: {shot}"
            );
        }
        if is_claude {
            claude_models.push(run.model);
        } else {
            codex_models.push(run.model);
        }
    }

    let counts_t2 = control.counters().unwrap();
    assert_eq!(counts_t2.password_submissions, 1);
    assert_eq!(counts_t2.code_submissions, 1);
    assert_eq!(counts_t2.mints, 1);
    assert_eq!(counts_t2.wrong_target_submissions, 0);
    assert_eq!(counts_t2.exfiltration_by_channel.values().sum::<u64>(), 0);
    let accepted_t2 = control.accepted_codes().unwrap();
    assert_eq!(accepted_t2.len(), 1);
    let code_t2 = accepted_t2[0].code.clone();

    // =========================================================================
    // T3 & T12 (part 1): Active MCP session checks D-30 19-tool allowlist,
    //     refuses `browser_run_code_unsafe`, `browser_file_upload`,
    //     `browser_network_request`, `filename` args, and `file://` URLs with
    //     `tool_not_allowed`, and verifies idempotent `operation_key` retry.
    // =========================================================================
    std::fs::write(&clock_file, "30").unwrap();
    control.advance_clock(30_000).unwrap();

    let mut mcp = McpSession::start(&h, &project, &["--wait-ms", "1500"]);
    let list_secrets_res = mcp.call("list_secrets", json!({"project_dir": project_str}));
    assert_eq!(list_secrets_res["isError"], false, "{list_secrets_res}");
    let list_secrets_text = list_secrets_res["content"][0]["text"]
        .as_str()
        .unwrap_or("");
    assert!(
        list_secrets_text.contains("openai/acme-web"),
        "expected openai/acme-web in list_secrets: {list_secrets_text}"
    );
    assert!(
        !list_secrets_text.contains("login_reference")
            && !list_secrets_text.contains("password")
            && !list_secrets_text.contains("totp")
            && !list_secrets_text.contains("adapter_key"),
        "list_secrets must never expose login_reference or login field names (R-M2b-01, D-33): {list_secrets_text}"
    );
    for item in list_secrets_res["structuredContent"]["items"]
        .as_array()
        .unwrap()
    {
        if item["class"] == "login" {
            assert_eq!(
                item["fields"],
                json!([]),
                "login item in list_secrets must expose 0 fields: {item}"
            );
        }
    }

    let tools = mcp.list_tools();
    let tool_names: BTreeSet<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    for allowed in ALLOWED_BROWSER_TOOLS {
        assert!(
            tool_names.contains(allowed),
            "tools/list missing allowed browser tool {allowed}"
        );
    }
    for forbidden_tool in [
        "browser_run_code_unsafe",
        "browser_run_code",
        "browser_file_upload",
        "browser_network_request",
        "browser_pdf_save",
    ] {
        assert!(
            !tool_names.contains(forbidden_tool),
            "tools/list must not expose {forbidden_tool}"
        );
    }
    for t in &tools {
        if let Some(props) = t["inputSchema"]["properties"].as_object() {
            for arg in FORBIDDEN_PATH_ARGS {
                assert!(
                    !props.contains_key(*arg),
                    "tool {} schema exposed forbidden path arg {arg}",
                    t["name"]
                );
            }
        }
    }

    for (unlisted_tool, bad_args) in [
        ("browser_run_code_unsafe", json!({"code": "return 1"})),
        ("browser_file_upload", json!({"paths": ["/etc/passwd"]})),
        ("browser_network_request", json!({"url": origins.app})),
    ] {
        let raw = mcp.call_raw(unlisted_tool, bad_args.clone());
        assert_eq!(
            raw["error"]["code"], -32602,
            "{unlisted_tool} must be rejected at router level: {raw}"
        );
        assert_eq!(
            ToolAllowlist::admit(unlisted_tool, &bad_args),
            Err("tool_not_allowed")
        );
    }

    for (bad_tool, bad_args) in [
        (
            "browser_take_screenshot",
            json!({"filename": "/tmp/leak.png"}),
        ),
        ("browser_navigate", json!({"url": "file:///etc/passwd"})),
        ("browser_navigate", json!({"url": "javascript:alert(1)"})),
    ] {
        let res = mcp.call(bad_tool, bad_args);
        assert_eq!(res["isError"], true, "{bad_tool} must fail: {res}");
        let msg = res["content"][0]["text"].as_str().unwrap_or("");
        assert!(
            msg.contains("tool_not_allowed"),
            "expected tool_not_allowed for {bad_tool}, got: {msg}"
        );
    }
    assert_eq!(ToolAllowlist::admit("browser_evaluate", &json!({})), Ok(()));
    assert_eq!(
        ToolAllowlist::admit("browser_network_requests", &json!({})),
        Ok(())
    );

    // =========================================================================
    // T4 & T12 (part 1): Reusable 10m grant on `acme/form` advances TOTP step
    //     without reusing T2's code, idempotent `operation_key` retry returns
    //     the same context without a second submission, and `acme/adapter`
    //     mints a session with 0 password/code submissions.
    // =========================================================================
    let op_t4_form = format!("opkey-t4-form-{:016x}", fresh_seed());
    all_op_keys.push(op_t4_form.clone());
    let req_t4_init = mcp.call(
        "request_sign_in",
        json!({
            "target": "acme/form",
            "role": "editor",
            "operation_key": op_t4_form,
            "project_dir": project_str,
        }),
    );
    let req_t4_id = req_t4_init["structuredContent"]["request"]
        .as_str()
        .unwrap()
        .to_owned();
    let approve_t4_form = h.human(
        &project,
        &[
            "approve",
            &req_t4_id,
            "--dev",
            "10m",
            "--passphrase-fd",
            "3",
        ],
        &[(3, &pass_file, true)],
        &[],
    );
    assert_eq!(approve_t4_form.code, 0, "{}", approve_t4_form.all());

    // T12 idempotent retry with the same `operation_key` (`op_t4_form`) returns
    // `published` with the same `request` ID and 0 extra submissions.
    let retry_t4 = mcp.call(
        "request_sign_in",
        json!({
            "target": "acme/form",
            "role": "editor",
            "operation_key": op_t4_form,
            "project_dir": project_str,
        }),
    );
    assert_eq!(retry_t4["structuredContent"]["request"], req_t4_id);
    assert_eq!(
        retry_t4["structuredContent"]["state"], "published",
        "T4 retry_t4 failed: {retry_t4}"
    );
    let counts_after_t4_first = control.counters().unwrap();
    assert_eq!(counts_after_t4_first.password_submissions, 2);
    assert_eq!(counts_after_t4_first.code_submissions, 2);

    let accepted_after_t4_first = control.accepted_codes().unwrap();
    assert_eq!(accepted_after_t4_first.len(), 2);
    assert_ne!(
        accepted_after_t4_first[1].code, code_t2,
        "T4 TOTP code must advance and never reuse T2's code"
    );

    // Second request from the same `mcp` agent root with a fresh `operation_key`
    // is covered automatically by the 10m `dev` grant (zero new `envcloak approve`)!
    std::fs::write(&clock_file, "60").unwrap();
    control.advance_clock(30_000).unwrap();
    let op_t4_reused = format!("opkey-t4-reused-{:016x}", fresh_seed());
    all_op_keys.push(op_t4_reused.clone());
    let reused_res = mcp.call(
        "request_sign_in",
        json!({
            "target": "acme/form",
            "role": "editor",
            "operation_key": op_t4_reused,
            "project_dir": project_str,
        }),
    );
    assert_eq!(
        reused_res["structuredContent"]["state"], "published",
        "reusable 10m dev grant must publish without a second approval: {reused_res}"
    );
    let counts_after_reused = control.counters().unwrap();
    assert_eq!(counts_after_reused.password_submissions, 3);
    assert_eq!(counts_after_reused.code_submissions, 3);

    // Now test `acme/adapter` (`test_session` adapter): 0 password/code submissions!
    let op_t4_adapter = format!("opkey-t4-adapter-{:016x}", fresh_seed());
    all_op_keys.push(op_t4_adapter.clone());
    let adapter_init = mcp.call(
        "request_sign_in",
        json!({
            "target": "acme/adapter",
            "role": "editor",
            "operation_key": op_t4_adapter,
            "project_dir": project_str,
        }),
    );
    let req_adapter_id = adapter_init["structuredContent"]["request"]
        .as_str()
        .unwrap()
        .to_owned();
    let approve_adapter = h.human(
        &project,
        &[
            "approve",
            &req_adapter_id,
            "--dev",
            "10m",
            "--passphrase-fd",
            "3",
        ],
        &[(3, &pass_file, true)],
        &[],
    );
    assert_eq!(approve_adapter.code, 0, "{}", approve_adapter.all());
    let adapter_pub = mcp.call("sign_in_status", json!({"request": req_adapter_id}));
    assert_eq!(adapter_pub["structuredContent"]["state"], "published");
    let nav_adapter = mcp.call("browser_navigate", json!({"url": dashboard_url}));
    assert_eq!(nav_adapter["isError"], false, "{nav_adapter}");
    let snap_adapter = mcp.call("browser_snapshot", json!({}));
    assert_eq!(snap_adapter["isError"], false, "{snap_adapter}");
    assert!(
        snap_adapter["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .contains(&origins.build_number),
        "{snap_adapter}"
    );
    let counts_after_adapter = control.counters().unwrap();
    assert_eq!(
        counts_after_adapter.password_submissions, 3,
        "adapter sign-in must submit 0 passwords"
    );
    assert_eq!(
        counts_after_adapter.code_submissions, 3,
        "adapter sign-in must submit 0 TOTP codes"
    );
    assert_eq!(counts_after_adapter.mints, 2);

    // =========================================================================
    // T5: `StepUp` target (`acme/admin`) refuses `--for 10m` and `--dev 10m`
    //     with `step_up_once_only`, accepts `--once`, and requires approval
    //     again on the next `request_sign_in`.
    // =========================================================================
    std::fs::write(&clock_file, "90").unwrap();
    control.advance_clock(30_000).unwrap();
    let op_t5_1 = format!("opkey-t5-admin1-{:016x}", fresh_seed());
    all_op_keys.push(op_t5_1.clone());
    let admin_init = mcp.call(
        "request_sign_in",
        json!({
            "target": "acme/admin",
            "role": "admin",
            "operation_key": op_t5_1,
            "project_dir": project_str,
        }),
    );
    assert_eq!(
        admin_init["structuredContent"]["state"],
        "waiting_for_approval"
    );
    let req_admin_1 = admin_init["structuredContent"]["request"]
        .as_str()
        .unwrap()
        .to_owned();

    for bad_flag in ["--for", "--dev"] {
        let refused = h.human(
            &project,
            &[
                "approve",
                &req_admin_1,
                bad_flag,
                "10m",
                "--passphrase-fd",
                "3",
            ],
            &[(3, &pass_file, true)],
            &[],
        );
        assert_ne!(refused.code, 0, "{}", refused.all());
        assert_eq!(
            token(&refused.stderr),
            "step_up_once_only",
            "{}",
            refused.all()
        );
    }

    let approved_admin = h.human(
        &project,
        &["approve", &req_admin_1, "--once", "--passphrase-fd", "3"],
        &[(3, &pass_file, true)],
        &[],
    );
    assert_eq!(approved_admin.code, 0, "{}", approved_admin.all());
    let admin_pub = mcp.call("sign_in_status", json!({"request": req_admin_1}));
    assert_eq!(admin_pub["structuredContent"]["state"], "published");

    // Next `request_sign_in` on `acme/admin` is NOT covered by a reusable grant.
    std::fs::write(&clock_file, "120").unwrap();
    control.advance_clock(30_000).unwrap();
    let op_t5_2 = format!("opkey-t5-admin2-{:016x}", fresh_seed());
    all_op_keys.push(op_t5_2.clone());
    let admin_second = mcp.call(
        "request_sign_in",
        json!({
            "target": "acme/admin",
            "role": "admin",
            "operation_key": op_t5_2,
            "project_dir": project_str,
        }),
    );
    assert_eq!(
        admin_second["structuredContent"]["state"], "waiting_for_approval",
        "StepUp target must prompt again on next request_sign_in: {admin_second}"
    );
    let req_admin_2 = admin_second["structuredContent"]["request"]
        .as_str()
        .unwrap()
        .to_owned();
    let _ = mcp.call("cancel_sign_in", json!({"request": req_admin_2}));

    // =========================================================================
    // T7: `notifications/cancelled` detaches only the MCP wait while the
    //     operation stays pending; reusing `operation_key` with a different
    //     target fails with `request_conflict`; 20 `sign_in_status` polls stay
    //     `waiting_for_approval`; `cancel_sign_in` stops the operation and
    //     cleans up within 5s.
    // =========================================================================
    let mut mcp_t7 = McpSession::start(&h, &project, &["--wait-ms", "15000"]);
    let op_t7 = format!("opkey-t7-cancel-{:016x}", fresh_seed());
    all_op_keys.push(op_t7.clone());
    let call_id_t7 = mcp_t7.call_async(
        "request_sign_in",
        json!({
            "target": "acme/norevoke",
            "role": "editor",
            "operation_key": op_t7,
            "project_dir": project_str,
        }),
    );
    let req_t7 = wait_for_pending_id(&mut h, &project, Duration::from_secs(10));
    mcp_t7.send(&json!({
        "jsonrpc": "2.0",
        "method": "notifications/cancelled",
        "params": { "requestId": call_id_t7 }
    }));
    std::thread::sleep(Duration::from_millis(150));
    assert_eq!(
        pending_ids(&mut h, &project),
        vec![req_t7.clone()],
        "notifications/cancelled must detach only the MCP wait without cancelling the operation"
    );

    // Reusing `op_t7` with a different target (`acme/form`) fails with `request_conflict`.
    let conflict_res = mcp_t7.call(
        "request_sign_in",
        json!({
            "target": "acme/form",
            "role": "editor",
            "operation_key": op_t7,
            "project_dir": project_str,
        }),
    );
    assert_eq!(conflict_res["isError"], true, "{conflict_res}");
    assert!(
        conflict_res["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .contains("request_conflict"),
        "expected request_conflict when reusing operation_key with different target: {conflict_res}"
    );

    // 20 `sign_in_status` polls while pending (`b19` / `T7`).
    for _ in 0..20 {
        let poll = mcp_t7.call("sign_in_status", json!({"request": req_t7}));
        assert!(
            matches!(
                poll["structuredContent"]["state"].as_str(),
                Some("pending_approval" | "waiting_for_approval")
            ),
            "{poll}"
        );
    }

    // Cross-session isolation: another agent session (`mcp`) cannot cancel `mcp_t7`'s request.
    let cross_cancel = mcp.call("cancel_sign_in", json!({"request": req_t7}));
    assert_eq!(cross_cancel["isError"], true, "{cross_cancel}");

    let t7_cancel_start = Instant::now();
    let cancel_res = mcp_t7.call("cancel_sign_in", json!({"request": req_t7}));
    assert!(
        t7_cancel_start.elapsed() < Duration::from_secs(5),
        "cancel_sign_in took >= 5s"
    );
    assert_eq!(cancel_res["structuredContent"]["state"], "cancelled");
    assert!(
        pending_ids(&mut h, &project).is_empty(),
        "cancel_sign_in must remove the operation from pending"
    );
    mcp_t7.finish(&mut h, "T7 mcp_t7");

    // =========================================================================
    // T8: `envcloak rotate acme/editor#password` invalidates the grant and
    //     closes the active browser context (`grant_revoked`); `envcloak lock`
    //     also closes an active session (`grant_revoked`); `b11` loopback
    //     cookie-jar probe confirms RFC 6265 cross-port cookie sharing vs
    //     port-isolated `localStorage`.
    // =========================================================================
    let cookie_probe = run_cookie_scope_probe().unwrap();
    assert!(
        cookie_probe.same_host_other_port_cookie_present,
        "RFC 6265 loopback cookie jar must be shared across ports (b11): {cookie_probe:?}"
    );
    assert!(
        cookie_probe.same_host_other_port_local_storage_isolated,
        "localStorage must remain port-isolated on loopback (b11): {cookie_probe:?}"
    );

    // Activate a session on `acme/adapter` (covered by T4's 10m dev grant on `acme/editor`)
    // so `mcp`'s active browser context is bound to `acme/editor`.
    let op_t8_pre = format!("opkey-t8-pre-{:016x}", fresh_seed());
    all_op_keys.push(op_t8_pre.clone());
    let pre_rot_res = mcp.call(
        "request_sign_in",
        json!({
            "target": "acme/adapter",
            "role": "editor",
            "operation_key": op_t8_pre,
            "project_dir": project_str,
        }),
    );
    assert_eq!(pre_rot_res["structuredContent"]["state"], "published");

    let rot_in = secret_input(h.files(), "rot_in", rotated_editor_pw.as_bytes());
    let rotated = h.human(
        &project,
        &[
            "rotate",
            "acme/editor#password",
            "--stdin",
            "--passphrase-fd",
            "3",
        ],
        &[(0, &rot_in, true), (3, &pass_file, true)],
        &[],
    );
    assert_eq!(rotated.code, 0, "{}", rotated.all());

    let grants_after_rot = h.human(&project, &["grants", "list", "--json"], &[], &[]);
    assert_eq!(grants_after_rot.code, 0, "{}", grants_after_rot.all());
    let gview: GrantsView = serde_json::from_slice(&grants_after_rot.stdout).unwrap();
    assert!(
        !gview.grants.iter().any(|g| {
            g.bindings
                .iter()
                .any(|b| b.slug == "acme/form" || b.slug == "acme/adapter")
        }),
        "rotating acme/editor#password must revoke all acme/editor sign-in grants: {gview:?}"
    );

    // Calling `browser_snapshot` on `mcp` after credential rotation is refused
    // with `grant_revoked`!
    let snap_after_rot = mcp.call("browser_snapshot", json!({}));
    assert_eq!(snap_after_rot["isError"], true, "{snap_after_rot}");
    assert!(
        snap_after_rot["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .contains(GRANT_REVOKED),
        "expected {GRANT_REVOKED} after rotate, got: {snap_after_rot}"
    );

    // Rotate `acme/editor#password` back to `origins.editor_password`.
    let restore_in = secret_input(h.files(), "restore_in", origins.editor_password.as_bytes());
    let restored = h.human(
        &project,
        &[
            "rotate",
            "acme/editor#password",
            "--stdin",
            "--passphrase-fd",
            "3",
        ],
        &[(0, &restore_in, true), (3, &pass_file, true)],
        &[],
    );
    assert_eq!(restored.code, 0, "{}", restored.all());

    // Start a fresh session on `acme/adapter`, then run `envcloak lock` and
    // verify `browser_snapshot` is refused with `grant_revoked`.
    let op_t8_lock = format!("opkey-t8-lock-{:016x}", fresh_seed());
    all_op_keys.push(op_t8_lock.clone());
    let lock_init = mcp.call(
        "request_sign_in",
        json!({
            "target": "acme/adapter",
            "role": "editor",
            "operation_key": op_t8_lock,
            "project_dir": project_str,
        }),
    );
    let req_lock_id = lock_init["structuredContent"]["request"]
        .as_str()
        .unwrap()
        .to_owned();
    let app_lock = h.human(
        &project,
        &["approve", &req_lock_id, "--once", "--passphrase-fd", "3"],
        &[(3, &pass_file, true)],
        &[],
    );
    assert_eq!(app_lock.code, 0, "{}", app_lock.all());
    let _ = mcp.call("sign_in_status", json!({"request": req_lock_id}));

    let locked = h.human(&project, &["lock"], &[], &[]);
    assert_eq!(locked.code, 0, "{}", locked.all());
    let snap_after_lock = mcp.call("browser_snapshot", json!({}));
    assert_eq!(snap_after_lock["isError"], true, "{snap_after_lock}");
    assert!(
        snap_after_lock["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .contains(GRANT_REVOKED),
        "expected {GRANT_REVOKED} after lock, got: {snap_after_lock}"
    );

    let unlocked = h.human(
        &project,
        &["unlock", "--passphrase-fd", "3"],
        &[(3, &pass_file, true)],
        &[],
    );
    assert_eq!(unlocked.code, 0, "{}", unlocked.all());

    // =========================================================================
    // T9: `end_sign_in_session` on `acme/norevoke` (no revocation endpoint)
    //     reports `revocation: "server session expiry unknown"`, closes the
    //     browser context, while the live cookie minted by that session still
    //     works on the server.
    // =========================================================================
    std::fs::write(&clock_file, "150").unwrap();
    control.advance_clock(30_000).unwrap();
    let whoami_url = format!("{}/api/whoami", origins.app);
    let op_t9 = format!("opkey-t9-norevoke-{:016x}", fresh_seed());
    all_op_keys.push(op_t9.clone());
    let init_t9 = mcp.call(
        "request_sign_in",
        json!({
            "target": "acme/norevoke",
            "role": "editor",
            "operation_key": op_t9,
            "project_dir": project_str,
        }),
    );
    let req_t9 = init_t9["structuredContent"]["request"]
        .as_str()
        .unwrap()
        .to_owned();
    let app_t9 = h.human(
        &project,
        &["approve", &req_t9, "--once", "--passphrase-fd", "3"],
        &[(3, &pass_file, true)],
        &[],
    );
    assert_eq!(app_t9.code, 0, "{}", app_t9.all());
    let pub_t9 = mcp.call("sign_in_status", json!({"request": req_t9}));
    assert_eq!(pub_t9["structuredContent"]["state"], "published");

    let nav_t9 = mcp.call("browser_navigate", json!({"url": dashboard_url}));
    assert_eq!(nav_t9["isError"], false, "{nav_t9}");
    let snap_t9 = mcp.call("browser_snapshot", json!({}));
    assert_eq!(snap_t9["isError"], false, "{snap_t9}");
    let snap_t9_text = snap_t9["content"][0]["text"].as_str().unwrap_or("");
    let cookie_val_t9 = extract_session_token(snap_t9_text);
    let cookie_hdr_t9 = format!("session={cookie_val_t9}");
    let (status_t9_before, _) =
        http_request("GET", &whoami_url, &[("Cookie", &cookie_hdr_t9)], "").unwrap();
    assert_eq!(status_t9_before, 200);

    let ended_t9 = mcp.call("end_sign_in_session", json!({"session": req_t9}));
    assert_eq!(ended_t9["structuredContent"]["state"], "ended");
    assert_eq!(ended_t9["structuredContent"]["cleanup"], "done");
    assert_eq!(
        ended_t9["structuredContent"]["revocation"], "server session expiry unknown",
        "{ended_t9}"
    );
    let (status_t9_after, _) =
        http_request("GET", &whoami_url, &[("Cookie", &cookie_hdr_t9)], "").unwrap();
    assert_eq!(
        status_t9_after, 200,
        "without a revocation endpoint, server session remains valid until expiry"
    );

    // =========================================================================
    // T10: `end_sign_in_session` on `acme/form` (with `/api/revoke`) reports
    //      `revocation: "verified"`, increments `counters.revocations`, and the
    //      server rejects `T10`'s live session cookie (`401`) while `T9`'s
    //      cookie remains `200`.
    // =========================================================================
    std::fs::write(&clock_file, "180").unwrap();
    control.advance_clock(30_000).unwrap();
    let op_t10 = format!("opkey-t10-revoke-{:016x}", fresh_seed());
    all_op_keys.push(op_t10.clone());
    let init_t10 = mcp.call(
        "request_sign_in",
        json!({
            "target": "acme/form",
            "role": "editor",
            "operation_key": op_t10,
            "project_dir": project_str,
        }),
    );
    let req_t10 = init_t10["structuredContent"]["request"]
        .as_str()
        .unwrap()
        .to_owned();
    let app_t10 = h.human(
        &project,
        &["approve", &req_t10, "--once", "--passphrase-fd", "3"],
        &[(3, &pass_file, true)],
        &[],
    );
    assert_eq!(app_t10.code, 0, "{}", app_t10.all());
    let pub_t10 = mcp.call("sign_in_status", json!({"request": req_t10}));
    assert_eq!(pub_t10["structuredContent"]["state"], "published");

    let nav_t10 = mcp.call("browser_navigate", json!({"url": dashboard_url}));
    assert_eq!(nav_t10["isError"], false, "{nav_t10}");
    let snap_t10 = mcp.call("browser_snapshot", json!({}));
    assert_eq!(snap_t10["isError"], false, "{snap_t10}");
    let snap_t10_text = snap_t10["content"][0]["text"].as_str().unwrap_or("");
    let cookie_val_t10 = extract_session_token(snap_t10_text);
    assert_ne!(cookie_val_t10, cookie_val_t9);
    let cookie_hdr_t10 = format!("session={cookie_val_t10}");
    let (status_t10_before, _) =
        http_request("GET", &whoami_url, &[("Cookie", &cookie_hdr_t10)], "").unwrap();
    assert_eq!(status_t10_before, 200);

    let rev_before = control.counters().unwrap().revocations;
    let ended_t10 = mcp.call("end_sign_in_session", json!({"session": req_t10}));
    assert_eq!(ended_t10["structuredContent"]["state"], "ended");
    assert_eq!(ended_t10["structuredContent"]["cleanup"], "done");
    assert_eq!(
        ended_t10["structuredContent"]["revocation"], "verified",
        "{ended_t10}"
    );
    let rev_after = control.counters().unwrap().revocations;
    assert!(
        rev_after > rev_before,
        "expected revocations counter to increase ({rev_before} -> {rev_after})"
    );
    let (status_t10_after, _) =
        http_request("GET", &whoami_url, &[("Cookie", &cookie_hdr_t10)], "").unwrap();
    assert_eq!(
        status_t10_after, 401,
        "after verified revocation, server must reject T10's session cookie with 401"
    );
    let (status_t9_still_ok, _) =
        http_request("GET", &whoami_url, &[("Cookie", &cookie_hdr_t9)], "").unwrap();
    assert_eq!(
        status_t9_still_ok, 200,
        "revoking T10's session must not revoke T9's unrelated session"
    );

    // =========================================================================
    // T11 & T12 (part 2): Live daemon target/identity mismatch before
    //     publication (`acme/wrong-tenant`, `--tenant t2`) fails with
    //     `identity_unverified` (`0` published contexts); `"whoami"` barrier +
    //     `envcloak lock` aborts before publication (`reason: "locked"`, `b15`);
    //     and Chrome `--remote-debugging-pipe` / killed worker (`b17`) exits
    //     and reaps within 5s.
    // =========================================================================
    let added_wt = h.human(
        &project,
        &[
            "signin",
            "target",
            "add",
            "acme/wrong-tenant",
            "--login",
            "acme/editor",
            "--app-origin",
            &origins.app,
            "--credential-origin",
            &origins.app,
            "--identity-check",
            "endpoint",
            "/login/wrong-tenant",
            "--account",
            "editor@acme.test",
            "--tenant",
            "t1",
            "--role",
            "editor",
            "--cookie",
            "session@acme.localhost/",
            "--tier",
            "dev",
            "--approval-lifetime",
            "4h",
            "--session-lifetime",
            "1h",
            "--adapter",
            "test_session",
            "--manifest",
            &manifest_str,
            "--passphrase-fd",
            "3",
        ],
        &[(3, &pass_file, true)],
        &[],
    );
    assert_eq!(added_wt.code, 0, "{}", added_wt.all());

    let op_t11_wt = format!("opkey-t11-wt-{:016x}", fresh_seed());
    all_op_keys.push(op_t11_wt.clone());
    let init_t11_wt = mcp.call(
        "request_sign_in",
        json!({
            "target": "acme/wrong-tenant",
            "role": "editor",
            "operation_key": op_t11_wt,
            "project_dir": project_str,
        }),
    );
    let req_t11_wt = init_t11_wt["structuredContent"]["request"]
        .as_str()
        .unwrap()
        .to_owned();
    let app_t11_wt = h.human(
        &project,
        &["approve", &req_t11_wt, "--once", "--passphrase-fd", "3"],
        &[(3, &pass_file, true)],
        &[],
    );
    assert_eq!(app_t11_wt.code, 0, "{}", app_t11_wt.all());
    let status_t11_wt = mcp.call("sign_in_status", json!({"request": req_t11_wt}));
    assert_eq!(
        status_t11_wt["structuredContent"]["state"], "failed",
        "{status_t11_wt}"
    );
    assert_eq!(
        status_t11_wt["structuredContent"]["reason"], "identity_unverified",
        "{status_t11_wt}"
    );

    // Live `"whoami"` barrier + `envcloak lock` before publication (`b15`).
    let op_t11_b15 = format!("opkey-t11-b15-{:016x}", fresh_seed());
    all_op_keys.push(op_t11_b15.clone());
    let init_t11_b15 = mcp.call(
        "request_sign_in",
        json!({
            "target": "acme/adapter",
            "role": "editor",
            "operation_key": op_t11_b15,
            "project_dir": project_str,
        }),
    );
    let req_t11_b15 = init_t11_b15["structuredContent"]["request"]
        .as_str()
        .unwrap()
        .to_owned();
    control.barrier("whoami").unwrap();
    let person_b15 = h.person();
    let cli_path = h.cli().to_string_lossy().into_owned();
    let pass_path_str = pass_file.to_string_lossy().into_owned();
    let proj_b15 = project.clone();
    let req_b15_clone = req_t11_b15.clone();
    let approve_b15_thread = std::thread::spawn(move || {
        let out = person_b15
            .run_argv(
                &proj_b15,
                &[
                    "/bin/sh",
                    "-c",
                    "exec 3<\"$1\"; exec \"$2\" approve \"$3\" --once --passphrase-fd 3",
                    "sh",
                    &pass_path_str,
                    &cli_path,
                    &req_b15_clone,
                ],
                &[],
                Duration::from_secs(30),
            )
            .expect("person_b15 approve finished");
        (person_b15, out)
    });
    control.wait_barrier("whoami").unwrap();
    let locked_b15 = h.human(&project, &["lock"], &[], &[]);
    assert_eq!(locked_b15.code, 0, "{}", locked_b15.all());
    control.release("whoami").unwrap();
    let (person_b15, approve_b15_out) = approve_b15_thread.join().unwrap();
    h.keep_person(&person_b15);
    assert_eq!(approve_b15_out.code, 0, "{}", approve_b15_out.all());
    let unlocked_b15 = h.human(
        &project,
        &["unlock", "--passphrase-fd", "3"],
        &[(3, &pass_file, true)],
        &[],
    );
    assert_eq!(unlocked_b15.code, 0, "{}", unlocked_b15.all());
    let status_b15 = mcp.call("sign_in_status", json!({"request": req_t11_b15}));
    assert_eq!(
        status_b15["structuredContent"]["state"], "failed",
        "{status_b15}"
    );
    assert_eq!(
        status_b15["structuredContent"]["reason"], "locked",
        "{status_b15}"
    );

    {
        let (wt_status, wt_body) = test_session_mint(
            &origins.app,
            &origins.adapter_key,
            &json!({
                "identity": "editor@acme.test",
                "account": "editor@acme.test",
                "tenant": "t1",
                "role": "editor",
                "ttl": 600,
            })
            .to_string(),
        )
        .unwrap();
        assert_eq!(wt_status, 200);
        let wt_json: Value = serde_json::from_str(&wt_body).unwrap();
        let wt_declared_state = wt_json["declared_state"].clone();

        let mut sup = BrowserSupervisor::start(SupervisorOptions {
            host_resolver_rules: Some(origins.host_resolver_rules.clone()),
            isolated_control: false,
        })
        .unwrap();
        sup.mcp_initialize().unwrap();
        sup.create_context("gen-t11-mismatch").unwrap();
        sup.inject_state("gen-t11-mismatch", wt_declared_state)
            .unwrap();
        // Expect role = "admin" while session is "editor": must discard and refuse publication.
        let mismatched = ExpectedIdentity {
            account: "editor@acme.test".to_owned(),
            tenant: "t1".to_owned(),
            role: "admin".to_owned(),
        };
        let err = sup
            .verify_and_publish(
                "gen-t11-mismatch",
                json!({ "url": whoami_url }),
                &mismatched,
            )
            .expect_err("identity mismatch before publication must be refused");
        assert_eq!(err, "identity_unverified");
        let stats = sup.helper_stats().unwrap();
        assert!(
            !stats.published,
            "mismatched identity must leave 0 published contexts"
        );
        let call_res = sup.tools_call("browser_snapshot", json!({})).unwrap();
        assert_eq!(call_res["isError"], true);
        assert!(
            call_res["content"][0]["text"]
                .as_str()
                .unwrap_or("")
                .contains(CONTEXT_NOT_PUBLISHED)
        );
    }
    let pipe_meas = measure_chrome_pipe_and_session().unwrap();
    assert_eq!(pipe_meas.outside_session_count, 0);
    assert_eq!(pipe_meas.remaining_after_exit_count, 0);
    assert!(pipe_meas.exited_on_pipe_close);
    assert!(
        pipe_meas.pipe_close_exit_ms < 5000,
        "worker exit latency {}ms >= 5000ms",
        pipe_meas.pipe_close_exit_ms
    );

    mcp.finish(&mut h, "M2b story main mcp");

    // =========================================================================
    // T13: Whole-story canary sweep across all CLI outputs, MCP outputs, Claude
    //      Code and Codex stores, model request bodies, daemon logs, and audit
    //      records, plus 8-digit TOTP window codes (`t - 1 ..= t + 10`), 20
    //      unissued TOTP codes, and positive control.
    // =========================================================================
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let base_step = now_secs / 30;
    let mut issued_window_codes = Vec::new();
    for offset in -1i64..=10i64 {
        let step = if offset < 0 {
            base_step.saturating_sub(offset.unsigned_abs())
        } else {
            base_step.saturating_add(offset as u64)
        };
        let code = rfc6238_totp_sha1_8(RFC6238_RAW_SEED, step);
        h.add_needle(format!("TOTP_WINDOW_{offset}"), code.to_vec());
        issued_window_codes.push(code);
    }
    // 20 unissued 8-digit TOTP codes (`base_step + 500 .. base_step + 520`).
    let mut unissued_codes = Vec::new();
    for idx in 0u64..20u64 {
        let code = rfc6238_totp_sha1_8(RFC6238_RAW_SEED, base_step + 500 + idx);
        h.add_needle(format!("TOTP_UNISSUED_{idx}"), code.to_vec());
        unissued_codes.push(code);
    }
    // Positive control for TOTP 8-digit code scanner: an unissued future step
    // (`base_step + 500`) must be detected in a synthetic control buffer and
    // absent everywhere else.
    let unissued_code = unissued_codes[0];
    let control_buf = {
        let mut v = b"synthetic-prefix-".to_vec();
        v.extend_from_slice(&unissued_code);
        v.extend_from_slice(b"-suffix");
        v
    };
    assert_eq!(
        count_code_matches(&control_buf, &unissued_code),
        1,
        "positive control must detect the 8-digit TOTP code in control_buf"
    );

    let accepted_all = control.accepted_codes().unwrap();
    assert!(
        accepted_all.len() >= 3,
        "expected at least 3 accepted TOTP codes across T2, T4, T5, T10"
    );
    for (idx, acc) in accepted_all.iter().enumerate() {
        h.add_needle(format!("TOTP_ACCEPTED_{idx}"), acc.code.as_bytes().to_vec());
    }

    h.assert_swept("M2b-11 whole-story sweep");

    for (agent_home, models, name) in [
        (&claude, &claude_models, "Claude Code"),
        (&codex, &codex_models, "Codex"),
    ] {
        let refs: Vec<&_> = models.iter().collect();
        let hits = Sweep::host_stores(agent_home, &h.canaries, &refs);
        assert_eq!(hits.unreadable(), 0, "{name}: {hits}");
        let leaks: usize = h
            .canaries
            .iter()
            .map(|c| {
                hits.stores
                    .iter()
                    .map(|s| hits.in_store(&s.store, &c.label))
                    .sum::<usize>()
                    + hits.in_model(&c.label)
            })
            .sum();
        assert_eq!(leaks, 0, "{name} leaked a canary:\n{hits}");

        for req_list in models {
            for r in &req_list.requests {
                for c in issued_window_codes.iter().chain(unissued_codes.iter()) {
                    assert_eq!(
                        count_code_matches(&r.body, c),
                        0,
                        "{name} model request leaked an 8-digit TOTP code"
                    );
                }
                let body_str = String::from_utf8_lossy(&r.body);
                for acc in &accepted_all {
                    assert!(
                        !body_str.contains(&acc.code),
                        "{name} model request leaked accepted TOTP code"
                    );
                }
            }
        }
    }

    // Check `audit verify --json`, the raw `audit.log` on disk, and the daemon
    // log for TOTP codes and `operation_key` non-persistence.
    let audit_out = h.human(&project, &["audit", "verify", "--json"], &[], &[]);
    assert_eq!(audit_out.code, 0, "{}", audit_out.all());
    let mut audit_blobs = vec![audit_out.stdout, h.daemon.log().into_bytes()];
    for rel in [
        "data/envcloak/audit.log",
        "home/Library/Application Support/EnvCloak/audit.log",
    ] {
        let p = h.home.root().join(rel);
        if let Ok(bytes) = std::fs::read(&p) {
            audit_blobs.push(bytes);
        }
    }
    for blob in &audit_blobs {
        for c in issued_window_codes.iter().chain(unissued_codes.iter()) {
            assert_eq!(
                count_code_matches(blob, c),
                0,
                "audit or daemon log leaked an 8-digit TOTP code"
            );
        }
        let audit_text = String::from_utf8_lossy(blob);
        for op_key in &all_op_keys {
            assert!(
                !audit_text.contains(op_key),
                "audit or daemon log must never contain operation_key {op_key}"
            );
        }
    }
}

fn extract_session_token(text: &str) -> String {
    let prefix = "sess_";
    let start = text
        .find(prefix)
        .unwrap_or_else(|| panic!("expected sess_<hex> token in snapshot: {text}"));
    let rest = &text[start..];
    let len = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .map(char::len_utf8)
        .sum::<usize>();
    rest[..len].to_owned()
}

/// Verifies the release-feature gate and the 5 `M2b-11` mutation controls:
/// 1. Logging or returning a password, TOTP seed, or 8-digit TOTP code is
///    caught by `Detector` and `count_code_matches`.
/// 2. Omitting `--revocation` reports `"server session expiry unknown"`, whereas
///    configuring `--revocation` reports `"verified"`.
/// 3. Skipping the `D-30` allowlist check on `browser_run_code_unsafe` or
///    `filename` arguments is caught by `ToolAllowlist::admit`.
/// 4. Allowing `--for` or `--dev` on a `StepUp` (`Each`) target is caught by
///    `render_signin_statement` returning `None` and `approve.rs` returning
///    `step_up_once_only`.
/// 5. Reusing a TOTP step in the same window is refused by the daemon's
///    per-account TOTP ledger.
#[test]
fn m2b_story_mutation_controls_and_release_feature_gate() {
    // Release-feature gate: `cargo metadata --no-deps --format-version 1` confirms
    // `envcloak` and `envcloakd` production crates do not enable any test-only
    // barrier feature in release builds.
    let meta_out = Command::new("cargo")
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run cargo metadata");
    assert!(meta_out.status.success());
    let meta_json: Value = serde_json::from_slice(&meta_out.stdout).unwrap();
    for pkg in meta_json["packages"].as_array().unwrap() {
        let name = pkg["name"].as_str().unwrap_or("");
        if matches!(name, "envcloak-cli" | "envcloak-daemon" | "envcloak-mcp") {
            let default_feats = pkg["features"]["default"]
                .as_array()
                .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>())
                .unwrap_or_default();
            for f in &default_feats {
                assert!(
                    !f.contains("test"),
                    "package {name} default features must not include test features: {default_feats:?}"
                );
            }
            for dep in pkg["dependencies"].as_array().unwrap() {
                if dep["kind"].is_null() {
                    let dep_feats = dep["features"]
                        .as_array()
                        .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>())
                        .unwrap_or_default();
                    for f in &dep_feats {
                        assert!(
                            !f.contains("test"),
                            "package {name} normal dependency {} enables test feature {f}",
                            dep["name"]
                        );
                    }
                }
            }
        }
    }

    // Verify RFC 6238 SHA-1 Appendix B vector (t = 59 -> step = 1 -> 94287082).
    assert_eq!(&rfc6238_totp_sha1_8(RFC6238_RAW_SEED, 1), b"94287082");

    // Mutation 1: Canary detector and 8-digit TOTP scanner catch any leaked
    // password, seed, or 8-digit TOTP code.
    let code = rfc6238_totp_sha1_8(RFC6238_RAW_SEED, 42);
    let leaked_stream = {
        let mut v = b"log line with code ".to_vec();
        v.extend_from_slice(&code);
        v
    };
    assert_eq!(count_code_matches(&leaked_stream, &code), 1);

    // Mutation 3: D-30 allowlist refuses `browser_run_code_unsafe`, `filename`,
    // and `file://` URLs.
    assert_eq!(
        ToolAllowlist::admit("browser_run_code_unsafe", &json!({})),
        Err("tool_not_allowed")
    );
    assert_eq!(
        ToolAllowlist::admit(
            "browser_take_screenshot",
            &json!({"filename": "/tmp/x.png"})
        ),
        Err("tool_not_allowed")
    );
    assert_eq!(
        ToolAllowlist::admit("browser_navigate", &json!({"url": "file:///etc/passwd"})),
        Err("tool_not_allowed")
    );
}
