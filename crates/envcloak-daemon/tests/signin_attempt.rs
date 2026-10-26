//! Integration tests for sign-in attempt supervision in the daemon (`SPEC.md`
//! §6.8, M2 plan D-25, D-31, D-34, D-36, F-73, F-74, CR-3, L-08; gates `b3`,
//! `b12`, `b14`, `b15`, `b16`, `b17`; task `M2b-09`).
#![allow(clippy::unwrap_used)]

mod common;

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use common::{MANIFEST, client, data_dir, passphrase, project, run_paths, seed_vault};
use envcloak_browser::{TEARDOWN_CONFIRMATION_FILE, WORKER_DIAGNOSTIC_FILE, WorkerSessionFormat};
use envcloak_core::SecretBytes;
use envcloak_ipc::proto::{
    LoginAddParams, PendingGetOutput, SigninRequestParams, SigninTargetAddParams,
};
use envcloak_ipc::view::{
    ClassificationView, CookieScopeView, IdentityCheckKindView, IdentityCheckView, LoginTierView,
    SessionFormatView, SigninStatusView, VaultState,
};
use envcloak_ipc::{Client, ClientError, RunPaths, WireSecret};
use envcloak_policy::ApprovalOptions;
use envcloak_signin::totp::{
    Algorithm as TotpAlgorithm, Period as TotpPeriod, TotpParams, code as generate_totp_code,
    count_code_matches, step_at,
};
use envcloak_signin::{Options as SignInChoice, SignInDevOptions, render_signin_statement};
use envcloak_sys::{proc_info, process_running};
use envcloak_testkit::signin::{
    Control, INSTALL_BROWSER_RUNTIME, Origins, REQUIRE_BROWSER_RUNTIME_VAR,
    SigninFixture as WebSigninFixture, VerifiedBrowserRuntime, browser_versions_path,
    resolve_browser_runtime,
};
use envcloak_testkit::{
    Canary, Daemon, TestHome, assert_no_canary, canaries, fresh_seed, testkit_bin,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const CHILD_ENV: &str = "ENVCLOAK_TEST_ATTEMPT_CHILD";
const CHILD_AGENT: &str = "ENVCLOAK_TEST_ATTEMPT_AGENT";
const RFC6238_BASE32_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const RFC6238_RAW_SEED: &[u8] = b"12345678901234567890";

fn envcloak_bin() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    exe.parent().unwrap().parent().unwrap().join("envcloak")
}

fn kill_pid(pid: u32) {
    let _ = Command::new("kill")
        .args(["-KILL", &pid.to_string()])
        .status();
}

fn kill_pgrp(pgrp: u32) {
    let _ = Command::new("kill")
        .args(["-KILL", &format!("-{pgrp}")])
        .status();
}

fn browser_runtime_or_skip() -> Option<VerifiedBrowserRuntime> {
    match resolve_browser_runtime(&browser_versions_path()) {
        Ok(rt) => Some(rt),
        Err(reason) => {
            if std::env::var_os(REQUIRE_BROWSER_RUNTIME_VAR).is_some() {
                panic!(
                    "browser runtime missing or unverified ({REQUIRE_BROWSER_RUNTIME_VAR} is set): {reason}; run `{INSTALL_BROWSER_RUNTIME}`"
                );
            }
            eprintln!("skipping browser test (run `{INSTALL_BROWSER_RUNTIME}`): {reason}");
            None
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReadySnapshot {
    request: String,
    attempt_id: String,
    attempt_dir: PathBuf,
    driver_pid: u32,
    reaper_pid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoneSnapshot {
    request: String,
    attempt_id: String,
    outcome: String,
    reason: Option<String>,
    cleanup_confirmed: bool,
    held_state_count: usize,
}

fn is_pid_alive(pid: u32) -> bool {
    let Ok(pid_i32) = i32::try_from(pid) else {
        return false;
    };
    let Ok(info) = proc_info(pid_i32) else {
        return false;
    };
    process_running(pid_i32, info.start_time)
}

fn wait_for_pid_exit(pid: u32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !is_pid_alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    !is_pid_alive(pid)
}

fn wait_for_json_file<T: for<'de> Deserialize<'de>>(path: &Path, timeout: Duration) -> T {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(bytes) = std::fs::read(path)
            && let Ok(val) = serde_json::from_slice::<T>(&bytes)
        {
            return val;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("timed out waiting for JSON file {}", path.display());
}

fn wait_for_worker_diagnostic(attempt_dir: &Path, timeout: Duration) -> (u32, u32) {
    let meta_path = attempt_dir.join(WORKER_DIAGNOSTIC_FILE);
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(bytes) = std::fs::read(&meta_path)
            && let Ok(val) = serde_json::from_slice::<Value>(&bytes)
            && let (Some(pid), Some(sid)) = (
                val.get("pid").and_then(Value::as_u64),
                val.get("sid").and_then(Value::as_u64),
            )
            && pid > 0
        {
            return (pid as u32, sid as u32);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!(
        "timed out waiting for {} in {}",
        WORKER_DIAGNOSTIC_FILE,
        attempt_dir.display()
    );
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

#[allow(clippy::too_many_arguments)]
fn build_worker_spec_json(
    runtime: &VerifiedBrowserRuntime,
    origins: &Origins,
    account: &str,
    tenant: Option<&str>,
    role: &str,
    login_url: &str,
    status_dir: &Path,
    totp_fixed_unix: Option<u64>,
    totp_no_sleep: bool,
) -> Value {
    json!({
        "bootstrap": {
            "app_origins": [origins.app],
            "credential_origins": [origins.app],
            "identity_provider_origins": [],
            "callback_origins": [],
            "identity_check_kind": "endpoint",
            "identity_check_locator": "/api/whoami",
            "expected_account": account,
            "expected_tenant": tenant,
            "expected_role": role,
            "cookies": [{
                "name": "session",
                "domain": "acme.localhost",
                "host_only": true,
                "path": "/",
                "partition_site": null,
                "partition_cross_site_ancestor": false
            }],
            "storage": [],
            "session_format": WorkerSessionFormat::Cookies,
            "flow": {
                "BrowserLogin": {
                    "login_url": login_url,
                    "username_selector": null,
                    "password_selector": null,
                    "code_selector": null,
                    "submit_selector": null
                }
            }
        },
        "chrome_exe": runtime.chrome_exe,
        "chrome_sha256": runtime.pins.chrome_sha256,
        "host_resolver_rules": origins.host_resolver_rules,
        "test_ca_spki_sha256": null,
        "extra_chrome_args": [],
        "status_dir": status_dir,
        "totp_fixed_unix": totp_fixed_unix,
        "totp_no_sleep": totp_no_sleep
    })
}

fn target_add_for_origins(
    name: &str,
    login: &str,
    account: &str,
    role: &str,
    origins: &Origins,
    passphrase: SecretBytes,
) -> SigninTargetAddParams {
    SigninTargetAddParams {
        manifest: None,
        name: name.to_owned(),
        login: login.to_owned(),
        app_origins: vec![origins.app.clone()],
        credential_origins: vec![origins.app.clone()],
        identity_provider_origins: Vec::new(),
        callback_origins: Vec::new(),
        identity_check: IdentityCheckView {
            kind: IdentityCheckKindView::Endpoint,
            locator: "/api/whoami".to_owned(),
            account: account.to_owned(),
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
        passphrase: Some(WireSecret::new(passphrase)),
        claims: Vec::new(),
    }
}

/// Helper process mode used to test requester-root exit during an active attempt.
#[test]
fn attempt_child_helper() {
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
                "attempt_child_helper",
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
        let req: Value = serde_json::from_str(&line).unwrap();
        let mut c = Client::connect(&paths).unwrap();
        let p = SigninRequestParams {
            manifest: req["manifest"].as_str().unwrap().to_owned(),
            target: req["target"].as_str().unwrap().to_owned(),
            role: req["role"].as_str().map(str::to_owned),
            operation_key: req["operation_key"].as_str().unwrap().to_owned(),
            claims: vec!["CLAUDECODE".to_owned()],
            fds: Vec::new(),
        };
        let v = c.signin_request(&p).unwrap();
        let reply = json!({
            "request": v.request,
            "state": v.state,
        });
        println!("{reply}");
    }
}

struct AgentRequester {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl AgentRequester {
    fn start(home: &TestHome) -> Self {
        let agent_bin = home.root().join("bin/claude");
        std::fs::create_dir_all(agent_bin.parent().unwrap()).unwrap();
        std::fs::copy(testkit_bin("fixture-agent"), &agent_bin).unwrap();

        let run_dir = envcloak_testkit::daemon_run_dir(home);
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        home.apply(&mut cmd)
            .args([
                "--exact",
                "attempt_child_helper",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(
                CHILD_ENV,
                format!("spawn_agent\n{}", run_dir.to_str().unwrap()),
            )
            .env(CHILD_AGENT, &agent_bin)
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
            assert!(n > 0, "agent requester exited before ready");
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

    fn request(&mut self, manifest: &str, target: &str, role: &str, key: &str) -> String {
        let q = json!({
            "manifest": manifest,
            "target": target,
            "role": role,
            "operation_key": key,
        });
        writeln!(self.stdin, "{q}").unwrap();
        self.stdin.flush().unwrap();
        let mut line = String::new();
        let n = self.stdout.read_line(&mut line).unwrap();
        assert!(n > 0);
        let v: Value = serde_json::from_str(line.trim()).unwrap();
        v["request"].as_str().unwrap().to_owned()
    }

    fn exit_root(mut self) {
        let _ = writeln!(self.stdin, "quit");
        let _ = self.stdin.flush();
        drop(self.stdin);
        let _ = self.child.wait();
    }
}

struct AttemptTestHarness {
    cs: Vec<Canary>,
    home: TestHome,
    d: Option<Daemon>,
    manifest: String,
    spec_dir: PathBuf,
    status_dir: PathBuf,
    clock_file: PathBuf,
    sleep_file: PathBuf,
    runtime: VerifiedBrowserRuntime,
    origins: Origins,
    control: Control,
}

impl AttemptTestHarness {
    fn new(runtime: VerifiedBrowserRuntime, extra_env: &[(&str, &str)]) -> Self {
        common::terminal_session();
        let (origins, control) = WebSigninFixture::start();
        let mut cs = canaries(fresh_seed());
        let home = TestHome::new();
        let kit = seed_vault(&home, &cs);
        cs.push(kit);
        cs.push(Canary::new(
            "SIGNIN_EDITOR_PW",
            origins.editor_password.clone(),
        ));

        let spec_dir = home.root().join("worker-specs");
        let status_dir = home.root().join("worker-status");
        let clock_file = home.root().join("clock-offset.txt");
        let sleep_file = home.root().join("sleep-trigger.txt");
        std::fs::create_dir_all(&spec_dir).unwrap();
        std::fs::create_dir_all(&status_dir).unwrap();
        std::fs::write(&clock_file, "0").unwrap();

        let login_url = format!("{}/login", origins.app);
        let default_spec = build_worker_spec_json(
            &runtime,
            &origins,
            "editor@acme.test",
            Some("t1"),
            "editor",
            &login_url,
            &status_dir,
            None,
            false,
        );
        std::fs::write(
            spec_dir.join("default.json"),
            serde_json::to_vec(&default_spec).unwrap(),
        )
        .unwrap();

        let mut env_pairs = vec![
            (
                "ENVCLOAK_TEST_SIGNIN_WORKER_SPEC",
                spec_dir.to_str().unwrap(),
            ),
            ("ENVCLOAK_TEST_CLOCK_FILE", clock_file.to_str().unwrap()),
            (
                "ENVCLOAK_TEST_SLEEP_TRIGGER_FILE",
                sleep_file.to_str().unwrap(),
            ),
            ("ENVCLOAK_TEST_TOTP_START_UNIX", "0"),
        ];
        for (k, v) in extra_env {
            env_pairs.push((*k, *v));
        }

        let d = start_daemon_with_env(&home, &env_pairs);

        let mut c = client(&home);
        c.unlock(passphrase(&cs), &[]).unwrap();
        assert_eq!(c.status().unwrap().vault.state, VaultState::Unlocked);
        let manifest_path = project(&home, "acme-web", MANIFEST);

        let otpauth_8 = format!(
            "otpauth://totp/Acme:editor@acme.test?secret={RFC6238_BASE32_SECRET}&digits=8&period=30&algorithm=SHA1"
        );
        c.login_add(&LoginAddParams {
            slug: "acme/editor".to_owned(),
            classification: ClassificationView::Test,
            tier: LoginTierView::Dev,
            session_lifetime_secs: 3600,
            username: WireSecret::new(SecretBytes::copy_from(b"editor@acme.test")),
            password: WireSecret::new(SecretBytes::copy_from(origins.editor_password.as_bytes())),
            totp: Some(WireSecret::new(SecretBytes::copy_from(
                otpauth_8.as_bytes(),
            ))),
            adapter_key: Some(WireSecret::new(SecretBytes::copy_from(
                origins.adapter_key.as_bytes(),
            ))),
            claims: Vec::new(),
        })
        .unwrap();

        c.signin_target_add(&target_add_for_origins(
            "acme-form",
            "acme/editor",
            "editor@acme.test",
            "editor",
            &origins,
            passphrase(&cs),
        ))
        .unwrap();

        Self {
            cs,
            home,
            d: Some(d),
            manifest: manifest_path.to_str().unwrap().to_owned(),
            spec_dir,
            status_dir,
            clock_file,
            sleep_file,
            runtime,
            origins,
            control,
        }
    }

    fn pass(&self) -> SecretBytes {
        passphrase(&self.cs)
    }

    fn daemon(&self) -> &Daemon {
        self.d.as_ref().unwrap()
    }

    fn clear_status_files(&self) {
        let _ = std::fs::remove_file(self.status_dir.join("ready.json"));
        let _ = std::fs::remove_file(self.status_dir.join("done.json"));
    }

    fn wait_barrier(&self, name: &str) {
        if let Err(e) = self.control.wait_barrier(name) {
            let ready = std::fs::read_to_string(self.status_dir.join("ready.json")).ok();
            let done = std::fs::read_to_string(self.status_dir.join("done.json")).ok();
            let log = String::from_utf8_lossy(&self.daemon().log_bytes()).into_owned();
            panic!(
                "wait_barrier({name}) failed: {e}\nready.json={ready:?}\ndone.json={done:?}\ndaemon_log:\n{log}"
            );
        }
    }

    fn request(&self, target: &str, role: Option<&str>, key: &str) -> SigninStatusView {
        client(&self.home)
            .signin_request(&SigninRequestParams {
                manifest: self.manifest.clone(),
                target: target.to_owned(),
                role: role.map(str::to_owned),
                operation_key: key.to_owned(),
                claims: Vec::new(),
                fds: Vec::new(),
            })
            .unwrap()
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

    fn spawn_approve(
        &self,
        request_id: &str,
        dev: Option<SignInDevOptions>,
    ) -> std::thread::JoinHandle<Result<String, ClientError>> {
        let mut c = client(&self.home);
        let PendingGetOutput::SignIn(desc) = c.pending_get_any(request_id, &[]).unwrap() else {
            panic!("expected SignIn pending descriptor");
        };
        let (_, _, digest) =
            render_signin_statement(&desc, choice_from_dev(dev)).expect("valid statement");
        let opts = match dev {
            Some(d) => ApprovalOptions::session(Duration::from_secs(d.window_secs)),
            None => ApprovalOptions::once(Duration::from_secs(600)),
        };
        let paths = run_paths(&self.home);
        let pass = self.pass();
        let req_owned = request_id.to_owned();
        std::thread::spawn(move || {
            let mut ca = Client::connect(&paths).unwrap();
            ca.approve_with_dev(&req_owned, opts, dev, &digest, pass, &[])
                .map(|a| a.grant)
        })
    }

    fn sweep(&self) {
        if let Some(d) = &self.d {
            assert_no_canary(&d.log_bytes(), &self.cs);
        }
        self.home.assert_clean(&self.cs);
    }
}

#[test]
fn direct_invocation_of_signin_driver_and_reaper_exits_125_with_not_started_by_daemon() {
    for flag in ["--signin-driver", "--signin-reaper"] {
        let out = Command::new(common::exe())
            .arg(flag)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("spawn envcloakd");
        assert_eq!(
            out.status.code(),
            Some(125),
            "envcloakd {flag} must exit 125 when not started by daemon"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("not_started_by_daemon"),
            "stderr for {flag} must contain not_started_by_daemon, got: {stderr:?}"
        );
    }
}

#[test]
fn intent_audit_failure_starts_no_driver_and_submits_zero_credentials_b14() {
    let Some(runtime) = browser_runtime_or_skip() else {
        return;
    };
    let h = AttemptTestHarness::new(runtime, &[("ENVCLOAK_TEST_FAIL", "signin.intent_audit")]);
    h.control.reset_counters().unwrap();
    h.clear_status_files();

    let v = h.request("acme-form", Some("editor"), "op-intent-fail-1");
    assert_eq!(v.state, "pending_approval");
    h.approve_signin(&v.request, None).unwrap();

    let st = client(&h.home).signin_status(&v.request).unwrap();
    assert_eq!(st.state, "failed");
    assert_eq!(st.reason.as_deref(), Some("audit_failed"));
    assert!(
        !h.status_dir.join("ready.json").exists(),
        "no driver or reaper may start when signin_intent audit fails (b14)"
    );

    let done: DoneSnapshot =
        wait_for_json_file(&h.status_dir.join("done.json"), Duration::from_secs(5));
    assert_eq!(done.outcome, "failed");
    assert_eq!(done.reason.as_deref(), Some("audit_failed"));
    assert_eq!(done.held_state_count, 0);

    let snap = h.control.counters().unwrap();
    assert_eq!(snap.password_submissions, 0);
    assert_eq!(snap.code_submissions, 0);
    assert_eq!(snap.mints, 0);
    h.sweep();
}

#[test]
fn driver_sigkill_with_daemon_running_tears_down_worker_and_profile_within_5s_b12_f73() {
    let Some(runtime) = browser_runtime_or_skip() else {
        return;
    };
    let h = AttemptTestHarness::new(runtime, &[]);
    h.control.reset_counters().unwrap();
    h.clear_status_files();
    h.control.barrier("password_submit").unwrap();

    let v = h.request("acme-form", Some("editor"), "op-driver-sigkill-1");
    let approve_join = h.spawn_approve(&v.request, None);

    h.control.wait_barrier("password_submit").unwrap();
    let ready: ReadySnapshot =
        wait_for_json_file(&h.status_dir.join("ready.json"), Duration::from_secs(5));
    let (chrome_pid, _chrome_sid) =
        wait_for_worker_diagnostic(&ready.attempt_dir, Duration::from_secs(5));
    assert!(is_pid_alive(ready.driver_pid));
    assert!(is_pid_alive(ready.reaper_pid));
    assert!(is_pid_alive(chrome_pid));
    assert!(ready.attempt_dir.join("profile").exists());

    // Kill the driver with SIGKILL while the daemon is running.
    kill_pid(ready.driver_pid);
    let _ = h.control.release("password_submit");

    let kill_start = Instant::now();
    approve_join.join().unwrap().unwrap();
    let done: DoneSnapshot =
        wait_for_json_file(&h.status_dir.join("done.json"), Duration::from_secs(5));
    assert!(
        wait_for_pid_exit(chrome_pid, Duration::from_secs(5)),
        "worker Chrome must exit within 5s after driver SIGKILL"
    );
    assert!(
        wait_for_pid_exit(ready.reaper_pid, Duration::from_secs(5)),
        "reaper must exit within 5s after driver SIGKILL"
    );
    assert!(
        kill_start.elapsed() < Duration::from_secs(5),
        "teardown after driver SIGKILL must complete within 5s"
    );

    assert_eq!(done.outcome, "failed");
    assert_eq!(done.reason.as_deref(), Some("worker_lost"));
    assert!(done.cleanup_confirmed);
    assert_eq!(done.held_state_count, 0);
    assert!(
        !ready.attempt_dir.exists(),
        "confirmed attempt directory and profile/ must be removed"
    );

    let st = client(&h.home).signin_status(&v.request).unwrap();
    assert_eq!(st.state, "failed");
    assert_eq!(st.reason.as_deref(), Some("worker_lost"));
    assert_eq!(st.cleanup, "done");
    assert_eq!(client(&h.home).status().unwrap().cleanup_unconfirmed, 0);

    // No restart occurred: exactly 1 password submission was made before kill.
    let snap = h.control.counters().unwrap();
    assert_eq!(snap.password_submissions, 1);
    h.sweep();
}

#[test]
fn daemon_sigkill_during_attempt_triggers_reaper_lifeline_teardown_and_clean_sweep_b12_f73() {
    let Some(runtime) = browser_runtime_or_skip() else {
        return;
    };
    let mut h =
        AttemptTestHarness::new(runtime, &[("ENVCLOAK_TEST_BOOT_ID", "boot-daemon-kill-1")]);
    h.control.reset_counters().unwrap();
    h.clear_status_files();
    h.control.barrier("password_submit").unwrap();

    let v = h.request("acme-form", Some("editor"), "op-daemon-sigkill-1");
    let _approve_join = h.spawn_approve(&v.request, None);

    h.control.wait_barrier("password_submit").unwrap();
    let ready: ReadySnapshot =
        wait_for_json_file(&h.status_dir.join("ready.json"), Duration::from_secs(5));
    let (chrome_pid, _chrome_sid) =
        wait_for_worker_diagnostic(&ready.attempt_dir, Duration::from_secs(5));
    assert!(is_pid_alive(chrome_pid));
    assert!(ready.attempt_dir.join("profile").exists());

    // Kill the daemon abruptly with SIGKILL while the attempt is running.
    let mut d = h.d.take().unwrap();
    d.signal("-KILL");
    let _ = d.wait_exit(Duration::from_secs(5));
    let _ = h.control.release("password_submit");

    // Within 5s, the reaper observes lifeline EOF, kills worker Chrome, removes profile/,
    // writes teardown.confirmed, releases reaper.lock, and exits.
    assert!(
        wait_for_pid_exit(chrome_pid, Duration::from_secs(5)),
        "reaper must kill worker Chrome within 5s of daemon SIGKILL"
    );
    assert!(
        wait_for_pid_exit(ready.reaper_pid, Duration::from_secs(5)),
        "reaper must exit within 5s of daemon SIGKILL"
    );
    let _ = wait_for_pid_exit(ready.driver_pid, Duration::from_secs(5));
    if is_pid_alive(ready.driver_pid) {
        kill_pid(ready.driver_pid);
    }

    assert!(
        !ready.attempt_dir.join("profile").exists(),
        "reaper must remove profile/ on lifeline EOF"
    );
    assert!(
        ready.attempt_dir.join(TEARDOWN_CONFIRMATION_FILE).exists(),
        "reaper must write teardown.confirmed on lifeline EOF"
    );

    // Start a fresh daemon in the same TestHome: startup sweep verifies teardown.confirmed,
    // removes the attempt directory, and reports cleanup_unconfirmed == 0.
    let spec_str = h.spec_dir.to_str().unwrap().to_owned();
    h.d = Some(start_daemon_with_env(
        &h.home,
        &[
            ("ENVCLOAK_TEST_SIGNIN_WORKER_SPEC", &spec_str),
            ("ENVCLOAK_TEST_BOOT_ID", "boot-daemon-kill-1"),
            ("ENVCLOAK_TEST_TOTP_START_UNIX", "0"),
        ],
    ));
    let mut c = client(&h.home);
    c.unlock(h.pass(), &[]).unwrap();
    assert_eq!(c.status().unwrap().cleanup_unconfirmed, 0);
    assert!(
        !ready.attempt_dir.exists(),
        "startup sweep must remove confirmed attempt directory"
    );
    assert!(
        h.daemon().log().contains(&format!(
            "signin cleanup confirmed attempt={}",
            ready.attempt_id
        )),
        "daemon log must record confirmed signin cleanup from startup sweep"
    );
    h.sweep();
}

#[test]
fn reaper_sigkill_then_daemon_restart_and_boot_id_transition_cr3() {
    let Some(runtime) = browser_runtime_or_skip() else {
        return;
    };
    let mut h = AttemptTestHarness::new(runtime, &[("ENVCLOAK_TEST_BOOT_ID", "boot-cr3-1")]);
    h.control.reset_counters().unwrap();
    h.clear_status_files();
    h.control.barrier("password_submit").unwrap();

    let v = h.request("acme-form", Some("editor"), "op-reaper-sigkill-1");
    let _approve_join = h.spawn_approve(&v.request, None);

    h.control.wait_barrier("password_submit").unwrap();
    let ready: ReadySnapshot =
        wait_for_json_file(&h.status_dir.join("ready.json"), Duration::from_secs(5));
    let (chrome_pid, chrome_sid) =
        wait_for_worker_diagnostic(&ready.attempt_dir, Duration::from_secs(5));
    assert!(is_pid_alive(ready.reaper_pid));
    assert!(ready.attempt_dir.join("profile").exists());

    // 1. SIGKILL the reaper FIRST, then SIGKILL the daemon so reaper.lock is free
    // and no teardown.confirmed file exists on disk (CR-3).
    kill_pid(ready.reaper_pid);
    assert!(wait_for_pid_exit(ready.reaper_pid, Duration::from_secs(5)));
    let mut d = h.d.take().unwrap();
    d.signal("-KILL");
    let _ = d.wait_exit(Duration::from_secs(5));
    let _ = h.control.release("password_submit");

    // Reap orphan driver / Chrome in the test harness so no process leaks on the host,
    // while leaving attempt_dir/profile and worker.json untouched without teardown.confirmed.
    kill_pgrp(chrome_sid);
    kill_pid(chrome_pid);
    kill_pid(ready.driver_pid);
    let _ = wait_for_pid_exit(chrome_pid, Duration::from_secs(5));
    let _ = wait_for_pid_exit(ready.driver_pid, Duration::from_secs(5));

    assert!(ready.attempt_dir.join("profile").exists());
    assert!(!ready.attempt_dir.join(TEARDOWN_CONFIRMATION_FILE).exists());

    // 2. Restart daemon with the SAME boot id (`boot-cr3-1`):
    // Startup sweep sees a free lock without teardown.confirmed, removes profile/,
    // retains the tombstone, audits signin_cleanup outcome=unconfirmed, and reports
    // cleanup_unconfirmed == 1 (CR-3: free lock alone is never treated as confirmed!).
    let spec_str = h.spec_dir.to_str().unwrap().to_owned();
    h.d = Some(start_daemon_with_env(
        &h.home,
        &[
            ("ENVCLOAK_TEST_SIGNIN_WORKER_SPEC", &spec_str),
            ("ENVCLOAK_TEST_BOOT_ID", "boot-cr3-1"),
            ("ENVCLOAK_TEST_TOTP_START_UNIX", "0"),
        ],
    ));
    let mut c = client(&h.home);
    c.unlock(h.pass(), &[]).unwrap();
    assert_eq!(c.status().unwrap().cleanup_unconfirmed, 1);
    assert!(
        !ready.attempt_dir.join("profile").exists(),
        "startup sweep must remove profile/ from unconfirmed attempt dir"
    );
    assert!(
        ready.attempt_dir.exists(),
        "startup sweep must retain unconfirmed tombstone in the same boot"
    );
    assert!(
        h.daemon().log().contains(&format!(
            "signin cleanup unconfirmed attempt={} reason=reaper_teardown_unconfirmed",
            ready.attempt_id
        )),
        "daemon log must audit signin_cleanup outcome=unconfirmed"
    );

    // Verify `envcloak status` CLI surfaces `cleanup_unconfirmed`.
    let mut cli_cmd = Command::new(envcloak_bin());
    h.home.apply(&mut cli_cmd);
    let cli_out = cli_cmd.arg("status").output().unwrap();
    assert!(cli_out.status.success());
    let cli_stdout = String::from_utf8_lossy(&cli_out.stdout);
    assert!(
        cli_stdout.contains("cleanup_unconfirmed"),
        "envcloak status CLI output must surface cleanup_unconfirmed, got: {cli_stdout:?}"
    );

    // 3. Second daemon start in the SAME boot (`boot-cr3-1`) still reports cleanup_unconfirmed == 1.
    h.d.take();
    h.d = Some(start_daemon_with_env(
        &h.home,
        &[
            ("ENVCLOAK_TEST_SIGNIN_WORKER_SPEC", &spec_str),
            ("ENVCLOAK_TEST_BOOT_ID", "boot-cr3-1"),
            ("ENVCLOAK_TEST_TOTP_START_UNIX", "0"),
        ],
    ));
    assert_eq!(client(&h.home).status().unwrap().cleanup_unconfirmed, 1);
    assert!(ready.attempt_dir.exists());

    // 4. Start daemon with a CHANGED boot id (`boot-cr3-2`):
    // Startup sweep clears the tombstone, resets cleanup_unconfirmed to 0, and
    // audits signin_cleanup outcome=ended_by_reboot.
    h.d.take();
    h.d = Some(start_daemon_with_env(
        &h.home,
        &[
            ("ENVCLOAK_TEST_SIGNIN_WORKER_SPEC", &spec_str),
            ("ENVCLOAK_TEST_BOOT_ID", "boot-cr3-2"),
            ("ENVCLOAK_TEST_TOTP_START_UNIX", "0"),
        ],
    ));
    let mut c2 = client(&h.home);
    c2.unlock(h.pass(), &[]).unwrap();
    assert_eq!(c2.status().unwrap().cleanup_unconfirmed, 0);
    assert!(
        !ready.attempt_dir.exists(),
        "startup sweep after reboot must remove the tombstone directory"
    );
    assert!(
        h.daemon().log().contains(&format!(
            "signin cleanup ended_by_reboot attempt={}",
            ready.attempt_id
        )),
        "daemon log must audit signin_cleanup outcome=ended_by_reboot"
    );
    h.sweep();
}

#[test]
fn reaper_exit_0_without_teardown_record_is_reported_cleanup_unconfirmed_cr3() {
    let Some(runtime) = browser_runtime_or_skip() else {
        return;
    };
    let h = AttemptTestHarness::new(
        runtime,
        &[("ENVCLOAK_TEST_FAIL", "signin.reaper.exit_0_without_record")],
    );
    h.control.reset_counters().unwrap();
    h.clear_status_files();

    let v = h.request("acme-form", Some("editor"), "op-reaper-no-record-1");
    h.approve_signin(&v.request, None).unwrap();

    let done: DoneSnapshot =
        wait_for_json_file(&h.status_dir.join("done.json"), Duration::from_secs(5));
    assert_eq!(done.outcome, "failed");
    assert!(!done.cleanup_confirmed);
    assert_eq!(done.reason.as_deref(), Some("cleanup_unconfirmed"));
    assert_eq!(done.held_state_count, 0);

    let st = client(&h.home).signin_status(&v.request).unwrap();
    assert_eq!(st.state, "failed");
    assert_eq!(st.cleanup, "cleanup_unconfirmed");
    assert_eq!(st.reason.as_deref(), Some("cleanup_unconfirmed"));
    assert!(st.delivered_context.is_none());
    assert_eq!(client(&h.home).status().unwrap().cleanup_unconfirmed, 1);
    assert!(
        h.daemon().log().contains(&format!(
            "signin cleanup unconfirmed attempt={} reason=reaper_teardown_unconfirmed",
            done.attempt_id
        )),
        "daemon must audit signin_cleanup outcome=unconfirmed when reaper exits 0 without teardown.confirmed"
    );
    h.sweep();
}

#[test]
fn sixty_four_tombstones_refuse_sixty_fifth_attempt_with_cleanup_unconfirmed() {
    let Some(runtime) = browser_runtime_or_skip() else {
        return;
    };
    let h = AttemptTestHarness::new(runtime, &[("ENVCLOAK_TEST_BOOT_ID", "boot-cap-64")]);
    h.control.reset_counters().unwrap();
    h.clear_status_files();

    let attempts_root = data_dir(&h.home).join("signin").join("attempts");
    std::fs::create_dir_all(&attempts_root).unwrap();
    for i in 0..64 {
        let dir = attempts_root.join(format!("tomb-{i:02}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("attempt.meta.json"),
            r#"{"started_wall_secs":1700000000,"boot_id":"boot-cap-64"}"#,
        )
        .unwrap();
    }

    assert_eq!(client(&h.home).status().unwrap().cleanup_unconfirmed, 64);

    let v = h.request("acme-form", Some("editor"), "op-65th-attempt");
    h.approve_signin(&v.request, None).unwrap();

    let st = client(&h.home).signin_status(&v.request).unwrap();
    assert_eq!(st.state, "failed");
    assert_eq!(st.cleanup, "cleanup_unconfirmed");
    assert_eq!(st.reason.as_deref(), Some("cleanup_unconfirmed"));
    assert!(st.delivered_context.is_none());

    let snap = h.control.counters().unwrap();
    assert_eq!(
        snap.password_submissions, 0,
        "65th attempt must be refused before launching Chrome or submitting credentials"
    );
    h.sweep();
}

#[test]
fn barriers_cancel_lock_sleep_root_exit_timeout_and_revision_change_tear_down_with_zero_held_state_b12_b17()
 {
    let Some(runtime) = browser_runtime_or_skip() else {
        return;
    };
    let h = AttemptTestHarness::new(runtime, &[]);

    // (a) Cancel while parked at password_submit barrier.
    {
        std::fs::write(&h.clock_file, "0").unwrap();
        h.control.reset_counters().unwrap();
        h.clear_status_files();
        h.control.barrier("password_submit").unwrap();

        let v = h.request("acme-form", Some("editor"), "op-barrier-cancel");
        let approve_join = h.spawn_approve(&v.request, None);
        h.wait_barrier("password_submit");
        let ready: ReadySnapshot =
            wait_for_json_file(&h.status_dir.join("ready.json"), Duration::from_secs(5));
        let (chrome_pid, _) =
            wait_for_worker_diagnostic(&ready.attempt_dir, Duration::from_secs(5));

        client(&h.home).signin_cancel(&v.request).unwrap();
        let _ = h.control.release("password_submit");
        approve_join.join().unwrap().unwrap();

        let done: DoneSnapshot =
            wait_for_json_file(&h.status_dir.join("done.json"), Duration::from_secs(5));
        assert!(wait_for_pid_exit(chrome_pid, Duration::from_secs(5)));
        assert_eq!(done.outcome, "failed");
        assert_eq!(done.reason.as_deref(), Some("cancelled"));
        assert!(done.cleanup_confirmed);
        assert_eq!(done.held_state_count, 0);
        assert!(!ready.attempt_dir.exists());

        let st = client(&h.home).signin_status(&v.request).unwrap();
        assert_eq!(st.state, "cancelled");
        assert_eq!(st.reason.as_deref(), Some("cancelled"));
        assert!(st.delivered_context.is_none());
    }

    // (b) Vault lock while parked at password_submit barrier.
    {
        std::fs::write(&h.clock_file, "30").unwrap();
        h.control.reset_counters().unwrap();
        h.clear_status_files();
        h.control.barrier("password_submit").unwrap();

        let v = h.request("acme-form", Some("editor"), "op-barrier-lock");
        let approve_join = h.spawn_approve(&v.request, None);
        h.wait_barrier("password_submit");
        let ready: ReadySnapshot =
            wait_for_json_file(&h.status_dir.join("ready.json"), Duration::from_secs(5));
        let (chrome_pid, _) =
            wait_for_worker_diagnostic(&ready.attempt_dir, Duration::from_secs(5));

        client(&h.home).lock().unwrap();
        let _ = h.control.release("password_submit");
        approve_join.join().unwrap().unwrap();

        let done: DoneSnapshot =
            wait_for_json_file(&h.status_dir.join("done.json"), Duration::from_secs(5));
        assert!(wait_for_pid_exit(chrome_pid, Duration::from_secs(5)));
        assert_eq!(done.outcome, "failed");
        assert_eq!(done.reason.as_deref(), Some("locked"));
        assert!(done.cleanup_confirmed);
        assert_eq!(done.held_state_count, 0);
        assert!(!ready.attempt_dir.exists());

        let mut c = client(&h.home);
        c.unlock(h.pass(), &[]).unwrap();
        let st = c.signin_status(&v.request).unwrap();
        assert_eq!(st.state, "failed");
        assert_eq!(st.reason.as_deref(), Some("locked"));
        assert!(st.delivered_context.is_none());
    }

    // (c) Machine sleep while parked at password_submit barrier.
    {
        std::fs::write(&h.clock_file, "60").unwrap();
        h.control.reset_counters().unwrap();
        h.clear_status_files();
        h.control.barrier("password_submit").unwrap();

        let v = h.request("acme-form", Some("editor"), "op-barrier-sleep");
        let approve_join = h.spawn_approve(&v.request, None);
        h.wait_barrier("password_submit");
        let ready: ReadySnapshot =
            wait_for_json_file(&h.status_dir.join("ready.json"), Duration::from_secs(5));
        let (chrome_pid, _) =
            wait_for_worker_diagnostic(&ready.attempt_dir, Duration::from_secs(5));

        std::fs::write(&h.sleep_file, "1").unwrap();
        let _ = client(&h.home).status();
        let _ = h.control.release("password_submit");
        approve_join.join().unwrap().unwrap();

        let done: DoneSnapshot =
            wait_for_json_file(&h.status_dir.join("done.json"), Duration::from_secs(5));
        assert!(wait_for_pid_exit(chrome_pid, Duration::from_secs(5)));
        assert_eq!(done.outcome, "failed");
        assert_eq!(done.reason.as_deref(), Some("locked"));
        assert!(done.cleanup_confirmed);
        assert_eq!(done.held_state_count, 0);
        assert!(!ready.attempt_dir.exists());

        let mut c = client(&h.home);
        c.unlock(h.pass(), &[]).unwrap();
        let st = c.signin_status(&v.request).unwrap();
        assert_eq!(st.state, "failed");
        assert_eq!(st.reason.as_deref(), Some("locked"));
        assert!(st.delivered_context.is_none());
    }

    // (d) Requester root exit while parked at password_submit barrier.
    {
        std::fs::write(&h.clock_file, "90").unwrap();
        h.control.reset_counters().unwrap();
        h.clear_status_files();
        h.control.barrier("password_submit").unwrap();

        let mut agent = AgentRequester::start(&h.home);
        let req_id = agent.request(&h.manifest, "acme-form", "editor", "op-barrier-root-exit");
        let approve_join = h.spawn_approve(&req_id, None);
        h.wait_barrier("password_submit");
        let ready: ReadySnapshot =
            wait_for_json_file(&h.status_dir.join("ready.json"), Duration::from_secs(5));
        let (chrome_pid, _) =
            wait_for_worker_diagnostic(&ready.attempt_dir, Duration::from_secs(5));

        agent.exit_root();
        // Trigger a reconcile tick on the daemon so OperationStore observes the dead root.
        let _ = client(&h.home).grants_list();
        let _ = h.control.release("password_submit");
        approve_join.join().unwrap().unwrap();

        let done: DoneSnapshot =
            wait_for_json_file(&h.status_dir.join("done.json"), Duration::from_secs(5));
        assert!(wait_for_pid_exit(chrome_pid, Duration::from_secs(5)));
        assert_eq!(done.outcome, "failed");
        assert_eq!(done.reason.as_deref(), Some("root_exited"));
        assert!(done.cleanup_confirmed);
        assert_eq!(done.held_state_count, 0);
        assert!(!ready.attempt_dir.exists());
    }

    // (e) Per-attempt timeout while parked at password_submit barrier.
    {
        std::fs::write(&h.clock_file, "120").unwrap();
        h.control.reset_counters().unwrap();
        h.clear_status_files();
        h.control.barrier("password_submit").unwrap();

        let v = h.request("acme-form", Some("editor"), "op-barrier-timeout");
        let approve_join = h.spawn_approve(&v.request, None);
        h.wait_barrier("password_submit");
        let ready: ReadySnapshot =
            wait_for_json_file(&h.status_dir.join("ready.json"), Duration::from_secs(5));
        let (chrome_pid, _) =
            wait_for_worker_diagnostic(&ready.attempt_dir, Duration::from_secs(5));

        // Advance daemon clock by 305s (past DEFAULT_ATTEMPT_TIMEOUT = 300s) and poll status.
        std::fs::write(&h.clock_file, "425").unwrap();
        let st = client(&h.home).signin_status(&v.request).unwrap();
        assert_eq!(st.state, "failed");
        assert_eq!(st.reason.as_deref(), Some("attempt_timed_out"));
        let _ = h.control.release("password_submit");
        approve_join.join().unwrap().unwrap();

        let done: DoneSnapshot =
            wait_for_json_file(&h.status_dir.join("done.json"), Duration::from_secs(5));
        assert!(wait_for_pid_exit(chrome_pid, Duration::from_secs(5)));
        assert_eq!(done.outcome, "failed");
        assert_eq!(done.reason.as_deref(), Some("attempt_timed_out"));
        assert!(done.cleanup_confirmed);
        assert_eq!(done.held_state_count, 0);
        assert!(!ready.attempt_dir.exists());
    }

    // (f) Login revision change (items.rotate on acme/editor) while parked at password_submit barrier.
    {
        std::fs::write(&h.clock_file, "450").unwrap();
        h.control.reset_counters().unwrap();
        h.clear_status_files();
        h.control.barrier("password_submit").unwrap();

        let v = h.request("acme-form", Some("editor"), "op-barrier-revision");
        let approve_join = h.spawn_approve(&v.request, None);
        h.wait_barrier("password_submit");
        let ready: ReadySnapshot =
            wait_for_json_file(&h.status_dir.join("ready.json"), Duration::from_secs(5));
        let (chrome_pid, _) =
            wait_for_worker_diagnostic(&ready.attempt_dir, Duration::from_secs(5));

        // Rotate acme/editor's password to bump its authorization revision while the attempt is live.
        let mut c = client(&h.home);
        let tgt = c
            .items_target("acme/editor", Some("password"), &[])
            .unwrap();
        c.items_rotate(
            &tgt,
            SecretBytes::copy_from(h.origins.editor_password.as_bytes()),
            h.pass(),
            &[],
        )
        .unwrap();

        let _ = h.control.release("password_submit");
        approve_join.join().unwrap().unwrap();

        let done: DoneSnapshot =
            wait_for_json_file(&h.status_dir.join("done.json"), Duration::from_secs(5));
        assert!(wait_for_pid_exit(chrome_pid, Duration::from_secs(5)));
        assert_eq!(done.outcome, "failed");
        assert_eq!(done.reason.as_deref(), Some("revision_changed"));
        assert!(done.cleanup_confirmed);
        assert_eq!(done.held_state_count, 0);
        assert!(!ready.attempt_dir.exists());

        let st = c.signin_status(&v.request).unwrap();
        assert_eq!(st.state, "failed");
        assert_eq!(st.reason.as_deref(), Some("revision_changed"));
        assert!(st.delivered_context.is_none());
    }

    h.sweep();
}

#[test]
fn per_account_serialization_totp_no_reuse_post_restart_refusal_and_6digit_containment_b3_b14_b15()
{
    let Some(runtime) = browser_runtime_or_skip() else {
        return;
    };

    // 1. Post-restart TOTP step refusal (b15):
    // Start a daemon whose ENVCLOAK_TEST_TOTP_START_UNIX is 1000s (step 33) and
    // configure the worker spec with totp_fixed_unix = Some(1000) and totp_no_sleep = true.
    // Both step 33 (startup step) and step 32 (predecessor step) must be refused before
    // any TOTP code is submitted to the fixture.
    {
        let h = AttemptTestHarness::new(
            runtime.clone(),
            &[("ENVCLOAK_TEST_TOTP_START_UNIX", "1000")],
        );
        let login_url = format!("{}/login", h.origins.app);
        for fixed_ts in [1000u64, 970u64] {
            h.control.reset_counters().unwrap();
            h.clear_status_files();
            let spec = build_worker_spec_json(
                &h.runtime,
                &h.origins,
                "editor@acme.test",
                Some("t1"),
                "editor",
                &login_url,
                &h.status_dir,
                Some(fixed_ts),
                true,
            );
            std::fs::write(
                h.spec_dir.join("default.json"),
                serde_json::to_vec(&spec).unwrap(),
            )
            .unwrap();

            let v = h.request(
                "acme-form",
                Some("editor"),
                &format!("op-post-restart-{fixed_ts}"),
            );
            h.approve_signin(&v.request, None).unwrap();

            let st = client(&h.home).signin_status(&v.request).unwrap();
            assert_eq!(st.state, "failed");
            assert_eq!(
                st.reason.as_deref(),
                Some("code_rejected"),
                "post-restart step at ts={fixed_ts} must be refused by TotpState (b15)"
            );
            let snap = h.control.counters().unwrap();
            assert_eq!(
                snap.code_submissions, 0,
                "zero TOTP codes may be submitted in the startup step or its predecessor (b15)"
            );
        }
        h.sweep();
    }

    // 2. Per-account attempt serialization, TOTP step non-reuse across two concurrent
    // attempts for the same account (`b14`, `b15`), and 6-digit TOTP code containment (`b3`).
    let mut h = AttemptTestHarness::new(runtime, &[]);
    h.control.reset_counters().unwrap();
    h.clear_status_files();

    // Register a second target (`acme-form-2`) bound to the same login item (`acme/editor`).
    client(&h.home)
        .signin_target_add(&target_add_for_origins(
            "acme-form-2",
            "acme/editor",
            "editor@acme.test",
            "editor",
            &h.origins,
            h.pass(),
        ))
        .unwrap();

    let v1 = h.request("acme-form", Some("editor"), "op-serial-1");
    let v2 = h.request("acme-form-2", Some("editor"), "op-serial-2");

    // Launch both approvals concurrently on two threads: the second must serialize behind
    // the first on `AttemptGuard` and wait for the next 30s TOTP step rather than reusing
    // the first attempt's step (`b14`, `b15`).
    let barrier = Arc::new(Barrier::new(2));
    let b1 = Arc::clone(&barrier);
    let b2 = Arc::clone(&barrier);
    let paths1 = run_paths(&h.home);
    let paths2 = run_paths(&h.home);
    let pass1 = h.pass();
    let pass2 = h.pass();
    let req1 = v1.request.clone();
    let req2 = v2.request.clone();

    let PendingGetOutput::SignIn(desc1) = client(&h.home).pending_get_any(&req1, &[]).unwrap()
    else {
        panic!("expected SignIn descriptor 1");
    };
    let (_, _, dig1) = render_signin_statement(&desc1, Some(SignInChoice::Once)).unwrap();

    let PendingGetOutput::SignIn(desc2) = client(&h.home).pending_get_any(&req2, &[]).unwrap()
    else {
        panic!("expected SignIn descriptor 2");
    };
    let (_, _, dig2) = render_signin_statement(&desc2, Some(SignInChoice::Once)).unwrap();

    let t1 = std::thread::spawn(move || {
        b1.wait();
        let mut c = Client::connect(&paths1).unwrap();
        c.approve_with_dev(
            &req1,
            ApprovalOptions::once(Duration::from_secs(600)),
            None,
            &dig1,
            pass1,
            &[],
        )
        .unwrap();
    });
    let t2 = std::thread::spawn(move || {
        b2.wait();
        let mut c = Client::connect(&paths2).unwrap();
        c.approve_with_dev(
            &req2,
            ApprovalOptions::once(Duration::from_secs(600)),
            None,
            &dig2,
            pass2,
            &[],
        )
        .unwrap();
    });

    t1.join().unwrap();
    t2.join().unwrap();

    let st1 = client(&h.home).signin_status(&v1.request).unwrap();
    let st2 = client(&h.home).signin_status(&v2.request).unwrap();
    assert_eq!(st1.state, "published");
    assert_eq!(st2.state, "published");

    let codes = h.control.accepted_codes().unwrap();
    assert_eq!(
        codes.len(),
        2,
        "both serialized attempts must succeed with accepted TOTP codes"
    );
    assert_ne!(
        codes[0].step, codes[1].step,
        "two attempts for the same account must never reuse the same TOTP step (b15)"
    );
    assert_ne!(
        codes[0].code, codes[1].code,
        "two attempts for the same account must never submit the same TOTP code"
    );

    // 3. 6-digit TOTP code containment (`b3`):
    // Enroll a login item with a 6-digit TOTP seed (`acme/six`), run a supervised
    // attempt, and verify `count_code_matches(&bytes, &code) == 0` across all IPC
    // responses, daemon logs, and files under TestHome.
    let otpauth_6 = format!(
        "otpauth://totp/Acme:editor@acme.test?secret={RFC6238_BASE32_SECRET}&digits=6&period=30&algorithm=SHA1"
    );
    let mut c = client(&h.home);
    c.login_add(&LoginAddParams {
        slug: "acme/six".to_owned(),
        classification: ClassificationView::Test,
        tier: LoginTierView::Dev,
        session_lifetime_secs: 3600,
        username: WireSecret::new(SecretBytes::copy_from(b"editor@acme.test")),
        password: WireSecret::new(SecretBytes::copy_from(h.origins.editor_password.as_bytes())),
        totp: Some(WireSecret::new(SecretBytes::copy_from(
            otpauth_6.as_bytes(),
        ))),
        adapter_key: None,
        claims: Vec::new(),
    })
    .unwrap();
    c.signin_target_add(&target_add_for_origins(
        "acme-six-target",
        "acme/six",
        "editor@acme.test",
        "editor",
        &h.origins,
        h.pass(),
    ))
    .unwrap();

    let now_before = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let v_six = h.request("acme-six-target", Some("editor"), "op-six-digit-b3");
    h.approve_signin(&v_six.request, None).unwrap();
    let st_six = client(&h.home).signin_status(&v_six.request).unwrap();
    let st_six_bytes = serde_json::to_vec(&st_six).unwrap();

    let period_30 = TotpPeriod::new(30).unwrap();
    let params_6 = TotpParams::new(TotpAlgorithm::Sha1, 6, 30).unwrap();
    let base_step = step_at(now_before, period_30);
    let candidate_codes: Vec<_> = (base_step.saturating_sub(1)..=base_step + 2)
        .map(|s| generate_totp_code(&SecretBytes::copy_from(RFC6238_RAW_SEED), params_6, s))
        .collect();

    // Add the 8-digit accepted codes to the canary list as well.
    for ac in &codes {
        h.cs.push(Canary::new("SIGNIN_TOTP_8", ac.code.clone()));
    }

    let daemon_log = h.daemon().log_bytes();
    for code in &candidate_codes {
        assert_eq!(
            count_code_matches(&st_six_bytes, code),
            0,
            "6-digit TOTP code must never appear in IPC status response (b3)"
        );
        assert_eq!(
            count_code_matches(&daemon_log, code),
            0,
            "6-digit TOTP code must never appear in daemon log (b3)"
        );
    }

    h.sweep();
}
