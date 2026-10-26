//! Sign-in targets, grants, statements, and the retry store over the daemon
//! socket (SPEC §6.8, §10b; M2b-05; D-26, D-31, D-36; R-M2b-04, R-M2b-11 to
//! R-M2b-17, R-M2b-25, R-M2b-28, R-M2b-30, R-M2b-35, R-M2b-36, R-M2b-43 to
//! R-M2b-48, R-M2b-51, R-M2b-54; gates b6, b7, b8, b11, b14, b17).
#![allow(clippy::unwrap_used)]

mod common;

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use common::{MANIFEST, client, passphrase, project, read_json, run_paths, seed_vault, send_json};
use envcloak_core::SecretBytes;
use envcloak_ipc::proto::{
    ErrorKind, LoginAddParams, PendingGetOutput, RunRequestParams, SigninRequestParams,
    SigninTargetAddParams, SigninTargetEditParams, SigninTargetRemoveParams,
};
use envcloak_ipc::view::{
    ClassificationView, CookieScopeView, DecisionView, IdentityCheckKindView, IdentityCheckView,
    LoginTierView, SessionFormatView, SigninStatusView, SigninTargetView, VaultState,
};
use envcloak_ipc::{Client, ClientError, RunPaths, WireSecret};
use envcloak_policy::{ApprovalOptions, Mode, statement_digest};
use envcloak_signin::{Options as SignInChoice, SignInDevOptions, render_signin_statement};
use envcloak_testkit::{
    Canary, Daemon, TestHome, assert_no_canary, by_label, canaries, fresh_seed, labels, testkit_bin,
};

const CHILD_ENV: &str = "ENVCLOAK_TEST_SIGNIN_CHILD";
const CHILD_AGENT: &str = "ENVCLOAK_TEST_SIGNIN_AGENT";

fn rpc_kind(e: ClientError) -> (ErrorKind, Option<&'static str>) {
    match e {
        ClientError::Rpc(r) => (r.kind, r.reason),
        other => panic!("expected an error response, got {other:?}"),
    }
}

/// Helper process mode used to exercise agent-root and sibling-process rules
/// over the real daemon socket.
#[test]
fn signin_child_helper() {
    let Some(spec) = std::env::var_os(CHILD_ENV) else {
        return;
    };
    let spec = spec.into_string().unwrap();
    let mut lines = spec.lines();
    let mode = lines.next().unwrap();
    let run_dir = lines.next().unwrap();

    if mode == "spawn_agent" {
        common::terminal_session();
        let agent_bin = std::env::var_os(CHILD_AGENT).unwrap();
        let mut cmd = Command::new(agent_bin);
        cmd.arg("--")
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "signin_child_helper",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_ENV, format!("worker\n{run_dir}"));
        let status = cmd.status().unwrap();
        std::process::exit(status.code().unwrap_or(1));
    }

    let paths = RunPaths::under(PathBuf::from(run_dir)).unwrap();
    println!("\nready");
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        if line == "quit" {
            break;
        }
        let req: serde_json::Value = serde_json::from_str(&line).unwrap();
        let op = req["op"].as_str().unwrap();
        let mut c = Client::connect(&paths).unwrap();
        let reply = match op {
            "signin_request" => {
                let p = SigninRequestParams {
                    manifest: req["manifest"].as_str().unwrap().to_owned(),
                    target: req["target"].as_str().unwrap().to_owned(),
                    role: req["role"].as_str().map(str::to_owned),
                    operation_key: req["operation_key"].as_str().unwrap().to_owned(),
                    claims: vec!["CLAUDECODE".to_owned()],
                    fds: Vec::new(),
                };
                match c.signin_request(&p) {
                    Ok(v) => serde_json::json!({
                        "ok": true,
                        "request": v.request,
                        "state": v.state,
                        "revision": v.revision,
                    }),
                    Err(ClientError::Rpc(r)) => serde_json::json!({
                        "ok": false,
                        "kind": r.kind.token(),
                        "reason": r.reason,
                    }),
                    Err(other) => panic!("unexpected error: {other:?}"),
                }
            }
            "signin_request_from_forked_sibling" => {
                let mut child = Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "signin_child_helper",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env(
                        CHILD_ENV,
                        format!("worker\n{}", paths.socket.parent().unwrap().display()),
                    )
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit())
                    .spawn()
                    .unwrap();
                let mut child_in = child.stdin.take().unwrap();
                let mut child_out = BufReader::new(child.stdout.take().unwrap());
                let mut ready_line = String::new();
                loop {
                    ready_line.clear();
                    let n = child_out.read_line(&mut ready_line).unwrap();
                    assert!(n > 0);
                    if ready_line.trim() == "ready" {
                        break;
                    }
                }
                let sub_q = serde_json::json!({
                    "op": "signin_request",
                    "manifest": req["manifest"],
                    "target": req["target"],
                    "role": req["role"],
                    "operation_key": req["operation_key"],
                });
                writeln!(child_in, "{sub_q}").unwrap();
                child_in.flush().unwrap();
                let mut ans = String::new();
                child_out.read_line(&mut ans).unwrap();
                let _ = writeln!(child_in, "quit");
                let _ = child.wait();
                serde_json::from_str(ans.trim()).unwrap()
            }
            "probe_nonexistent_claim_methods" => {
                let mut results = Vec::new();
                for method in [
                    "signin.claim",
                    "signin.publish",
                    "signin.check",
                    "supervisor.claim",
                ] {
                    let mut s = std::os::unix::net::UnixStream::connect(&paths.socket).unwrap();
                    send_json(
                        &mut s,
                        &serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": method,
                            "params": { "request": req["request"] }
                        }),
                    );
                    let resp = read_json(&mut s).unwrap();
                    results.push(common::error_kind(&resp));
                }
                serde_json::json!({ "ok": true, "kinds": results })
            }
            "target_add_from_agent" => {
                let pass = SecretBytes::copy_from(req["pass"].as_str().unwrap().as_bytes());
                let p = default_target_add("agent-attempt", "acme/editor", "editor", Some(pass));
                match c.signin_target_add(&p) {
                    Ok(_) => serde_json::json!({ "ok": true }),
                    Err(ClientError::Rpc(r)) => serde_json::json!({
                        "ok": false,
                        "kind": r.kind.token(),
                        "reason": r.reason,
                    }),
                    Err(other) => panic!("unexpected error: {other:?}"),
                }
            }
            other => panic!("unknown op {other}"),
        };
        println!("{reply}");
    }
}

struct AgentWorker {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl AgentWorker {
    fn start(home: &TestHome, agent_bin: &Path) -> Self {
        let run_dir = envcloak_testkit::daemon_run_dir(home);
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        home.apply(&mut cmd)
            .args([
                "--exact",
                "signin_child_helper",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(
                CHILD_ENV,
                format!("spawn_agent\n{}", run_dir.to_str().unwrap()),
            )
            .env(CHILD_AGENT, agent_bin)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = cmd.spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            let n = stdout.read_line(&mut line).unwrap();
            assert!(n > 0, "agent worker exited before ready");
            if line.trim() == "ready" {
                break;
            }
        }
        Self {
            child,
            stdin,
            stdout,
        }
    }

    fn call(&mut self, q: &serde_json::Value) -> serde_json::Value {
        writeln!(self.stdin, "{q}").unwrap();
        self.stdin.flush().unwrap();
        let mut line = String::new();
        let n = self.stdout.read_line(&mut line).unwrap();
        assert!(n > 0, "agent worker closed stdout");
        serde_json::from_str(line.trim()).unwrap()
    }
}

impl Drop for AgentWorker {
    fn drop(&mut self) {
        let _ = writeln!(self.stdin, "quit");
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn default_target_add(
    name: &str,
    login: &str,
    role: &str,
    passphrase: Option<SecretBytes>,
) -> SigninTargetAddParams {
    SigninTargetAddParams {
        manifest: None,
        name: name.to_owned(),
        login: login.to_owned(),
        app_origins: vec!["http://acme.localhost:4100".to_owned()],
        credential_origins: vec!["http://acme.localhost:4100".to_owned()],
        identity_provider_origins: Vec::new(),
        callback_origins: Vec::new(),
        identity_check: IdentityCheckView {
            kind: IdentityCheckKindView::Endpoint,
            locator: "/api/whoami".to_owned(),
            account: "editor@acme.test".to_owned(),
            tenant: Some("t1".to_owned()),
            role: role.to_owned(),
        },
        cookies: vec![CookieScopeView {
            name: "session".to_owned(),
            domain: "acme.localhost".to_owned(),
            path: "/".to_owned(),
            host_only: Some(true),
            partition_top_site: None,
            cross_site_ancestor: false,
        }],
        storage: Vec::new(),
        session_format: SessionFormatView::Cookies,
        tier: LoginTierView::Dev,
        adapter: None,
        approval_lifetime_secs: 28800,
        session_lifetime_secs: 3600,
        revocation: None,
        passphrase: passphrase.map(WireSecret::new),
        claims: Vec::new(),
    }
}

fn start_daemon_with_env(home: &TestHome, env: &[(&str, &str)]) -> Daemon {
    let mut cmd = Command::new(common::exe());
    home.apply(&mut cmd);
    for (k, v) in env {
        cmd.env(k, v);
    }
    Daemon::start_command(cmd, &[])
}

fn choice_from_dev(dev: Option<SignInDevOptions>) -> Option<SignInChoice> {
    match dev {
        Some(d) => Some(SignInChoice::Dev {
            window: Duration::from_secs(d.window_secs),
            attempts: d.attempts,
        }),
        None => Some(SignInChoice::Once),
    }
}

struct SigninFixture {
    cs: Vec<Canary>,
    home: TestHome,
    d: Option<Daemon>,
    manifest: String,
    stub_dir: PathBuf,
}

impl SigninFixture {
    fn new() -> Self {
        common::terminal_session();
        let mut cs = canaries(fresh_seed());
        let home = TestHome::new();
        let kit = seed_vault(&home, &cs);
        cs.push(kit);

        let stub_dir = home.root().join("stub-signin");
        std::fs::create_dir_all(&stub_dir).unwrap();
        let d = start_daemon_with_env(
            &home,
            &[("ENVCLOAK_TEST_STUB_SIGNIN_DIR", stub_dir.to_str().unwrap())],
        );

        let mut c = client(&home);
        c.unlock(passphrase(&cs), &[]).unwrap();
        assert_eq!(c.status().unwrap().vault.state, VaultState::Unlocked);
        let manifest_path = project(&home, "acme-web", MANIFEST);

        let login_pw = format!("login-pw-{:016x}", fresh_seed());
        cs.push(Canary::new("SIGNIN_LOGIN_PW", login_pw.clone()));
        c.login_add(&LoginAddParams {
            slug: "acme/editor".to_owned(),
            classification: ClassificationView::Test,
            tier: LoginTierView::Dev,
            session_lifetime_secs: 3600,
            username: WireSecret::new(SecretBytes::copy_from(b"editor@acme.test")),
            password: WireSecret::new(SecretBytes::copy_from(login_pw.as_bytes())),
            totp: None,
            adapter_key: None,
            claims: Vec::new(),
        })
        .unwrap();

        let rcpt = c
            .signin_target_add(&default_target_add(
                "acme-form",
                "acme/editor",
                "editor",
                Some(passphrase(&cs)),
            ))
            .unwrap();
        assert_eq!(rcpt.revision, 1);
        assert!(
            rcpt.shared_loopback_cookie_jar,
            "loopback target receipt must carry shared_loopback_cookie_jar=true (b11)"
        );

        c.signin_target_add(&default_target_add(
            "acme-form",
            "acme/editor",
            "viewer",
            Some(passphrase(&cs)),
        ))
        .unwrap();

        Self {
            cs,
            home,
            d: Some(d),
            manifest: manifest_path.to_str().unwrap().to_owned(),
            stub_dir,
        }
    }

    fn restart_with_env(&mut self, env: &[(&str, &str)]) {
        self.d.take();
        self.d = Some(start_daemon_with_env(&self.home, env));
    }

    fn daemon(&self) -> &Daemon {
        self.d.as_ref().unwrap()
    }

    fn pass(&self) -> SecretBytes {
        passphrase(&self.cs)
    }

    fn request(
        &self,
        target: &str,
        role: Option<&str>,
        key: &str,
    ) -> Result<SigninStatusView, ClientError> {
        client(&self.home).signin_request(&SigninRequestParams {
            manifest: self.manifest.clone(),
            target: target.to_owned(),
            role: role.map(str::to_owned),
            operation_key: key.to_owned(),
            claims: Vec::new(),
            fds: Vec::new(),
        })
    }

    fn approve_signin(
        &self,
        request_id: &str,
        dev: Option<SignInDevOptions>,
    ) -> Result<String, ClientError> {
        let mut c = client(&self.home);
        let PendingGetOutput::SignIn(desc) = c.pending_get_any(request_id, &[])? else {
            panic!("expected SignIn pending descriptor");
        };
        let (_, _, digest) =
            render_signin_statement(&desc, choice_from_dev(dev)).expect("valid statement");
        let opts = match dev {
            Some(d) => ApprovalOptions::session(Duration::from_secs(d.window_secs)),
            None => ApprovalOptions::once(Duration::from_secs(600)),
        };
        c.approve_with_dev(request_id, opts, dev, &digest, self.pass(), &[])
            .map(|a| a.grant)
    }

    fn sweep(&self) {
        assert_no_canary(&self.daemon().log_bytes(), &self.cs);
        self.home.assert_clean(&self.cs);
    }
}

#[test]
fn target_crud_proof_boundaries_and_loopback_note() {
    let f = SigninFixture::new();
    let mut c = client(&f.home);

    // Wrong passphrase on add is refused.
    let mut bad_add = default_target_add(
        "bad-pass",
        "acme/editor",
        "editor",
        Some(SecretBytes::copy_from(b"wrong-passphrase")),
    );
    let (kind, _) = rpc_kind(c.signin_target_add(&bad_add).unwrap_err());
    assert_eq!(kind, ErrorKind::WrongPassphrase);

    // Dedicated HTTPS staging target has shared_loopback_cookie_jar == false.
    bad_add.name = "acme-staging".to_owned();
    bad_add.app_origins = vec!["https://staging.acme.example".to_owned()];
    bad_add.credential_origins = vec!["https://staging.acme.example".to_owned()];
    bad_add.cookies[0].domain = "staging.acme.example".to_owned();
    bad_add.passphrase = Some(WireSecret::new(f.pass()));
    let https_rcpt: SigninTargetView = c.signin_target_add(&bad_add).unwrap();
    assert!(!https_rcpt.shared_loopback_cookie_jar);

    // Agent subject is refused on signin.target.add before any prompt/mutation.
    let agent_bin = f.home.root().join("bin/claude");
    std::fs::create_dir_all(agent_bin.parent().unwrap()).unwrap();
    std::fs::copy(testkit_bin("fixture-agent"), &agent_bin).unwrap();
    let mut agent = AgentWorker::start(&f.home, &agent_bin);
    let pass_str = std::str::from_utf8(by_label(&f.cs, labels::VAULT_PASSPHRASE).value()).unwrap();
    let agent_res = agent.call(&serde_json::json!({
        "op": "target_add_from_agent",
        "pass": pass_str,
    }));
    assert_eq!(agent_res["ok"], false);
    assert_eq!(agent_res["kind"], "proof_refused");

    // Edit bumps revision and list reflects the updated targets.
    let edit_rcpt = c
        .signin_target_edit(&SigninTargetEditParams {
            manifest: None,
            name: "acme-staging".to_owned(),
            role: Some("editor".to_owned()),
            login: None,
            app_origins: None,
            credential_origins: None,
            identity_provider_origins: None,
            callback_origins: None,
            identity_check: None,
            cookies: None,
            storage: None,
            session_format: None,
            tier: None,
            adapter: None,
            approval_lifetime_secs: None,
            session_lifetime_secs: Some(1800),
            revocation: None,
            passphrase: Some(WireSecret::new(f.pass())),
            claims: Vec::new(),
        })
        .unwrap();
    assert_eq!(edit_rcpt.revision, 2);

    let list = c.signin_target_list(None).unwrap();
    assert_eq!(list.targets.len(), 3);

    // Remove deletes the target.
    c.signin_target_remove(&SigninTargetRemoveParams {
        manifest: None,
        name: "acme-staging".to_owned(),
        role: Some("editor".to_owned()),
        passphrase: Some(WireSecret::new(f.pass())),
        claims: Vec::new(),
    })
    .unwrap();
    assert_eq!(c.signin_target_list(None).unwrap().targets.len(), 2);
    f.sweep();
}

#[test]
fn fifty_concurrent_identical_requests_share_one_statement_and_one_credit() {
    let f = SigninFixture::new();
    let n = 50usize;
    let barrier = Arc::new(Barrier::new(n));
    let paths = run_paths(&f.home);
    let manifest = f.manifest.clone();

    let mut handles = Vec::with_capacity(n);
    for _ in 0..n {
        let b = Arc::clone(&barrier);
        let p = paths.clone();
        let m = manifest.clone();
        handles.push(std::thread::spawn(move || {
            b.wait();
            let params = SigninRequestParams {
                manifest: m,
                target: "acme-form".to_owned(),
                role: Some("editor".to_owned()),
                operation_key: "op-concurrent-50".to_owned(),
                claims: Vec::new(),
                fds: Vec::new(),
            };
            let end = Instant::now() + Duration::from_secs(15);
            loop {
                match Client::connect(&p).and_then(|mut c| c.signin_request(&params)) {
                    Ok(v) => return v,
                    Err(_) if Instant::now() < end => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("concurrent signin_request failed: {e:?}"),
                }
            }
        }));
    }

    let views: Vec<SigninStatusView> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let first_req = &views[0].request;
    for v in &views {
        assert_eq!(
            &v.request, first_req,
            "all 50 calls must join one operation"
        );
        assert_eq!(v.state, "pending_approval");
    }

    // One PendingGet descriptor, one statement, and after Once approval one published operation.
    f.approve_signin(first_req, None).unwrap();
    let after = client(&f.home).signin_status(first_req).unwrap();
    assert_eq!(after.state, "published");

    // Retrying with the same operation_key after publication returns the published operation.
    let retry = f
        .request("acme-form", Some("editor"), "op-concurrent-50")
        .unwrap();
    assert_eq!(retry.request, *first_req);
    assert_eq!(retry.state, "published");
    f.sweep();
}

#[test]
fn operation_key_conflict_per_field_leaves_original_statement_untouched() {
    let f = SigninFixture::new();
    let mut c = client(&f.home);

    // Register a second target so we can vary target alone.
    c.signin_target_add(&default_target_add(
        "acme-form-2",
        "acme/editor",
        "editor",
        Some(f.pass()),
    ))
    .unwrap();
    let other_manifest = project(&f.home, "other-web", MANIFEST)
        .to_str()
        .unwrap()
        .to_owned();

    let v0 = f
        .request("acme-form", Some("editor"), "key-conflict-1")
        .unwrap();
    let PendingGetOutput::SignIn(desc_before) = c.pending_get_any(&v0.request, &[]).unwrap() else {
        panic!("expected SignIn descriptor");
    };
    let (stmt_before, _, digest_before) =
        render_signin_statement(&desc_before, Some(SignInChoice::Once)).unwrap();

    // 1. Change role alone -> request_conflict.
    let (k1, _) = rpc_kind(
        f.request("acme-form", Some("viewer"), "key-conflict-1")
            .unwrap_err(),
    );
    assert_eq!(k1, ErrorKind::RequestConflict);

    // 2. Change target alone -> request_conflict.
    let (k2, _) = rpc_kind(
        f.request("acme-form-2", Some("editor"), "key-conflict-1")
            .unwrap_err(),
    );
    assert_eq!(k2, ErrorKind::RequestConflict);

    // 3. Change project manifest alone -> request_conflict.
    let (k3, _) = rpc_kind(
        c.signin_request(&SigninRequestParams {
            manifest: other_manifest,
            target: "acme-form".to_owned(),
            role: Some("editor".to_owned()),
            operation_key: "key-conflict-1".to_owned(),
            claims: Vec::new(),
            fds: Vec::new(),
        })
        .unwrap_err(),
    );
    assert_eq!(k3, ErrorKind::RequestConflict);

    // Original operation's statement and reserved context are untouched.
    let PendingGetOutput::SignIn(desc_after) = c.pending_get_any(&v0.request, &[]).unwrap() else {
        panic!("expected SignIn descriptor");
    };
    let (stmt_after, _, digest_after) =
        render_signin_statement(&desc_after, Some(SignInChoice::Once)).unwrap();
    assert_eq!(stmt_before, stmt_after);
    assert_eq!(digest_before, digest_after);
    assert_eq!(desc_before.context, desc_after.context);
    f.sweep();
}

#[test]
fn target_edit_during_proof_refuses_stale_proof_and_lock_or_cancel_tears_down() {
    let mut f = SigninFixture::new();
    let release_path = f.home.root().join("pause-release");
    let stub_dir = f.stub_dir.to_str().unwrap().to_owned();

    // Restart daemon with pause point active so we can deterministic-race target edit during proof.
    f.restart_with_env(&[
        ("ENVCLOAK_TEST_STUB_SIGNIN_DIR", &stub_dir),
        ("ENVCLOAK_TEST_PAUSE", "signin.approve.during_proof"),
        (
            "ENVCLOAK_TEST_PAUSE_RELEASE",
            release_path.to_str().unwrap(),
        ),
    ]);
    let mut c = client(&f.home);
    c.unlock(f.pass(), &[]).unwrap();

    let v = f
        .request("acme-form", Some("editor"), "op-race-proof-2")
        .unwrap();
    let req_id = v.request.clone();
    let PendingGetOutput::SignIn(desc) = c.pending_get_any(&req_id, &[]).unwrap() else {
        panic!("expected SignIn descriptor");
    };
    let (_, _, digest) = render_signin_statement(&desc, Some(SignInChoice::Once)).unwrap();

    let paths = run_paths(&f.home);
    let pass_approve = f.pass();
    let req_for_thread = req_id.clone();
    let approve_handle = std::thread::spawn(move || {
        let mut ca = Client::connect(&paths).unwrap();
        ca.approve_with_dev(
            &req_for_thread,
            ApprovalOptions::once(Duration::from_secs(600)),
            None,
            &digest,
            pass_approve,
            &[],
        )
    });

    let deadline = Instant::now() + Duration::from_secs(10);
    while !f
        .daemon()
        .log()
        .contains("envcloak test: paused at signin.approve.during_proof")
    {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for signin.approve.during_proof pause"
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    // Edit the target while approve is paused in proof verification.
    c.signin_target_edit(&SigninTargetEditParams {
        manifest: None,
        name: "acme-form".to_owned(),
        role: Some("editor".to_owned()),
        login: None,
        app_origins: None,
        credential_origins: None,
        identity_provider_origins: None,
        callback_origins: None,
        identity_check: None,
        cookies: None,
        storage: None,
        session_format: None,
        tier: None,
        adapter: None,
        approval_lifetime_secs: None,
        session_lifetime_secs: Some(1800),
        revocation: None,
        passphrase: Some(WireSecret::new(f.pass())),
        claims: Vec::new(),
    })
    .unwrap();

    std::fs::write(&release_path, b"release").unwrap();
    let approve_err = approve_handle.join().unwrap().unwrap_err();
    let (kind, _) = rpc_kind(approve_err);
    assert!(
        matches!(
            kind,
            ErrorKind::NoSuchRequest | ErrorKind::StatementMismatch
        ),
        "stale proof must fail after target edit, got {kind:?}"
    );

    // Lock while a request is pending tears it down.
    let v_lock = f
        .request("acme-form", Some("editor"), "op-lock-teardown")
        .unwrap();
    assert_eq!(v_lock.state, "pending_approval");
    c.lock().unwrap();
    c.unlock(f.pass(), &[]).unwrap();
    let st_lock = c.signin_status(&v_lock.request).unwrap();
    assert_eq!(st_lock.state, "failed");
    assert_eq!(st_lock.reason.as_deref(), Some("locked"));
    assert!(c.pending_list().unwrap().requests.is_empty());
    f.sweep();
}

#[test]
fn sibling_in_agent_root_cannot_claim_and_gets_distinct_operation_and_cross_root_refused() {
    let f = SigninFixture::new();
    let agent_bin = f.home.root().join("bin/claude");
    std::fs::create_dir_all(agent_bin.parent().unwrap()).unwrap();
    std::fs::copy(testkit_bin("fixture-agent"), &agent_bin).unwrap();

    let mut agent_a = AgentWorker::start(&f.home, &agent_bin);
    let mut agent_b = AgentWorker::start(&f.home, &agent_bin);

    // Agent A requests sign-in.
    let req_a = agent_a.call(&serde_json::json!({
        "op": "signin_request",
        "manifest": f.manifest,
        "target": "acme-form",
        "role": "editor",
        "operation_key": "op-agent-a-1",
    }));
    assert_eq!(req_a["ok"], true);
    let req_a_id = req_a["request"].as_str().unwrap().to_owned();

    // Cross-root isolation: terminal caller (or another agent root) calling signin.status or cancel is refused.
    let (cross_kind, _) = rpc_kind(client(&f.home).signin_status(&req_a_id).unwrap_err());
    assert_eq!(cross_kind, ErrorKind::NoSuchRequest);

    // Sibling inside Agent A's root probing socket for claim/publish/check finds MethodNotFound.
    let probe = agent_a.call(&serde_json::json!({
        "op": "probe_nonexistent_claim_methods",
        "request": req_a_id,
    }));
    for k in probe["kinds"].as_array().unwrap() {
        assert_eq!(k.as_str().unwrap(), "method_not_found");
    }

    // Approve Agent A with a dev window (2h, 3 attempts).
    f.approve_signin(
        &req_a_id,
        Some(SignInDevOptions {
            window_secs: 7200,
            attempts: 3,
        }),
    )
    .unwrap();

    // Send log shows captured state only on supervisor:<gen>, never on ipc_reply.
    let send_log = std::fs::read_to_string(f.stub_dir.join("send_log.txt")).unwrap();
    assert!(
        send_log
            .lines()
            .any(|l| l.contains(" dest=supervisor:1 captured=true")),
        "send_log must record captured state on supervisor:1, got:\n{send_log}"
    );
    for line in send_log.lines() {
        if line.contains(" dest=ipc:") {
            assert!(
                line.ends_with(" captured=false"),
                "ipc_reply must never carry captured state: {line}"
            );
        }
    }

    // Sibling process under the SAME agent root A has a different recipient process instance,
    // so its own signin.request is NOT covered by A's dev authorization and gets a new pending request (b14).
    let sib = agent_a.call(&serde_json::json!({
        "op": "signin_request_from_forked_sibling",
        "manifest": f.manifest,
        "target": "acme-form",
        "role": "editor",
        "operation_key": "op-sibling-1",
    }));
    assert_eq!(sib["ok"], true);
    assert_ne!(sib["request"].as_str().unwrap(), req_a_id);
    assert_eq!(
        sib["state"].as_str().unwrap(),
        "pending_approval",
        "sibling process in same agent root must not inherit recipient-bound dev authorization (b14)"
    );

    // Agent B (another root) also gets pending_approval.
    let req_b = agent_b.call(&serde_json::json!({
        "op": "signin_request",
        "manifest": f.manifest,
        "target": "acme-form",
        "role": "editor",
        "operation_key": "op-agent-b-1",
    }));
    assert_eq!(req_b["state"], "pending_approval");
    f.sweep();
}

#[test]
fn identity_override_mismatch_publishes_nothing_and_stops_identity_unverified() {
    let f = SigninFixture::new();
    std::fs::write(
        f.stub_dir.join("identity_override.txt"),
        "editor@acme.test\nwrong-tenant\neditor\n",
    )
    .unwrap();

    let v = f
        .request("acme-form", Some("editor"), "op-bad-identity")
        .unwrap();
    f.approve_signin(&v.request, None).unwrap();

    let st = client(&f.home).signin_status(&v.request).unwrap();
    assert_eq!(st.state, "failed");
    assert_eq!(st.reason.as_deref(), Some("identity_unverified"));
    assert!(st.delivered_context.is_none());
    let _ = std::fs::remove_file(f.stub_dir.join("identity_override.txt"));
    f.sweep();
}

#[test]
fn grants_list_and_revoke_with_multiple_signin_authorizations_and_mode_isolation() {
    let f = SigninFixture::new();
    let mut c = client(&f.home);

    // Mode::Inject grant for the same root and project never covers signin.request.
    let run_dec = c
        .run_request(&RunRequestParams {
            manifest: f.manifest.clone(),
            profile: None,
            refs: Vec::new(),
            env_file: None,
            argv: vec!["true".to_owned()],
            claims: Vec::new(),
            launch: None,
            bridge: None,
            fds: Vec::new(),
        })
        .unwrap()
        .decision;
    let DecisionView::Pending { request: run_req } = run_dec else {
        panic!("expected pending run request");
    };
    let d_run = c.pending_get(&run_req, &[]).unwrap();
    let opts_session = ApprovalOptions::session(Duration::from_secs(3600));
    let run_digest = statement_digest(&d_run, &opts_session);
    c.approve(&run_req, opts_session, &run_digest, f.pass(), &[])
        .unwrap();

    // Despite active Mode::Inject session grant, signin.request still needs approval.
    let v_ed = f
        .request("acme-form", Some("editor"), "op-auth-ed")
        .unwrap();
    assert_eq!(v_ed.state, "pending_approval");
    let auth_ed = f
        .approve_signin(
            &v_ed.request,
            Some(SignInDevOptions {
                window_secs: 3600,
                attempts: 3,
            }),
        )
        .unwrap();

    let v_vw = f
        .request("acme-form", Some("viewer"), "op-auth-vw")
        .unwrap();
    assert_eq!(v_vw.state, "pending_approval");
    let auth_vw = f
        .approve_signin(
            &v_vw.request,
            Some(SignInDevOptions {
                window_secs: 3600,
                attempts: 3,
            }),
        )
        .unwrap();

    let listed = c.grants_list().unwrap().grants;
    let signin_grants: Vec<_> = listed
        .iter()
        .filter(|g| matches!(g.mode, Mode::SignIn(_)))
        .collect();
    assert_eq!(
        signin_grants.len(),
        2,
        "grants.list must report both active sign-in authorizations"
    );

    // Revoke one sign-in authorization by id; the other remains in force.
    let rev1 = c.grants_revoke(Some(&auth_ed)).unwrap();
    assert_eq!(rev1.revoked, 1);

    // Editor now needs approval again, while viewer is still covered by auth_vw!
    let v_ed_after = f
        .request("acme-form", Some("editor"), "op-auth-ed-2")
        .unwrap();
    assert_eq!(v_ed_after.state, "pending_approval");
    let v_vw_after = f
        .request("acme-form", Some("viewer"), "op-auth-vw-2")
        .unwrap();
    assert_eq!(v_vw_after.state, "published");

    // Revoke --all clears the remaining sign-in authorization too.
    let rev_all = c.grants_revoke(None).unwrap();
    assert!(rev_all.revoked >= 1);
    assert!(
        c.grants_list()
            .unwrap()
            .grants
            .iter()
            .all(|g| g.id != auth_vw)
    );
    f.sweep();
}

#[test]
fn store_cap_64_and_dev_budget_exhaustion() {
    let f = SigninFixture::new();
    let mut c = client(&f.home);

    // 1. Dev budget exhaustion (b8): approve with 2 attempts; first uses attempt 1,
    // second key uses attempt 2, third key must wait for approval.
    let v1 = f
        .request("acme-form", Some("editor"), "op-budget-1")
        .unwrap();
    assert_eq!(v1.state, "pending_approval");
    f.approve_signin(
        &v1.request,
        Some(SignInDevOptions {
            window_secs: 3600,
            attempts: 2,
        }),
    )
    .unwrap();
    assert_eq!(c.signin_status(&v1.request).unwrap().state, "published");

    // Repeated retries and status polls on op-budget-1 consume zero additional attempts.
    for _ in 0..5 {
        let r = f
            .request("acme-form", Some("editor"), "op-budget-1")
            .unwrap();
        assert_eq!(r.request, v1.request);
        assert_eq!(r.state, "published");
        assert_eq!(c.signin_status(&v1.request).unwrap().state, "published");
    }

    // Second distinct operation_key consumes attempt 2 of 2 and publishes immediately.
    let v2 = f
        .request("acme-form", Some("editor"), "op-budget-2")
        .unwrap();
    assert_eq!(v2.state, "published");

    // Third distinct operation_key finds the 2-attempt budget exhausted and waits for approval.
    let v3 = f
        .request("acme-form", Some("editor"), "op-budget-3")
        .unwrap();
    assert_eq!(v3.state, "pending_approval");
    c.signin_cancel(&v3.request).unwrap();
    c.signin_end(&v1.request).unwrap();
    c.signin_end(&v2.request).unwrap();

    // 2. Per-root cap of 256 operations (b7): we already have 3 operations in the store;
    // open 253 more on the same connection to reach 256.
    let mut ids = vec![v1.request, v2.request, v3.request];
    for i in 4..=256 {
        let key = format!("op-cap-{i}");
        let v = c
            .signin_request(&SigninRequestParams {
                manifest: f.manifest.clone(),
                target: "acme-form".to_owned(),
                role: Some("editor".to_owned()),
                operation_key: key,
                claims: Vec::new(),
                fds: Vec::new(),
            })
            .unwrap();
        ids.push(v.request);
    }
    assert_eq!(ids.len(), 256);

    // 257th distinct operation is refused with TooManyPending and evicts nothing.
    let (kind, _) = rpc_kind(
        c.signin_request(&SigninRequestParams {
            manifest: f.manifest.clone(),
            target: "acme-form".to_owned(),
            role: Some("editor".to_owned()),
            operation_key: "op-cap-257".to_owned(),
            claims: Vec::new(),
            fds: Vec::new(),
        })
        .unwrap_err(),
    );
    assert_eq!(kind, ErrorKind::TooManyPending);

    // First and 256th operations remain intact in the store.
    assert_eq!(c.signin_status(&ids[0]).unwrap().request, ids[0]);
    assert_eq!(c.signin_status(&ids[255]).unwrap().request, ids[255]);
    f.sweep();
}
