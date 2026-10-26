//! CLI integration tests for `envcloak signin target add|edit|rm|ls`,
//! `envcloak pending`, `envcloak approve <id> [--once | --dev <dur> [--attempts <n>]]`,
//! `envcloak deny <id>`, and `envcloak grants list|revoke` on sign-in
//! requests and authorizations (M2b-05; SPEC §6.8, §10b; gates b7, b8, b11,
//! b14, b17).
#![allow(clippy::unwrap_used)]

mod common;

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use common::{
    MANIFEST, outside_dir, project, run, run_on_terminal, secret_file, seed_vault, start_daemon,
    stderr, stdout,
};
use envcloak_core::SecretBytes;
use envcloak_ipc::proto::SigninRequestParams;
use envcloak_ipc::view::{GrantsView, PendingListView, SigninTargetListView, SigninTargetView};
use envcloak_ipc::{Client, RunPaths};
use envcloak_signin::totp::{self, Algorithm, Code, Period, TotpParams, count_code_matches};
use envcloak_testkit::{
    Canary, Daemon, TestHome, assert_no_canary, by_label, canaries, daemon_run_dir, fresh_seed,
    labels,
};

const CHILD_ROLE_ENV: &str = "ENVCLOAK_CLI_SIGNIN_CHILD_ROLE";

#[test]
fn signin_cli_child_helper() {
    let Ok(role) = std::env::var(CHILD_ROLE_ENV) else {
        return;
    };
    if role != "requester" {
        panic!("unknown child role: {role}");
    }
    let run_dir = PathBuf::from(std::env::var_os("ENVCLOAK_TEST_RUN_DIR").unwrap());
    let manifest = std::env::var("ENVCLOAK_TEST_MANIFEST").unwrap();
    let run_paths = RunPaths::under(run_dir).unwrap();
    let mut client = Client::connect(&run_paths).unwrap();
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    writeln!(stdout, "\nREADY").unwrap();
    stdout.flush().unwrap();
    for line in BufReader::new(stdin.lock()).lines() {
        let line = line.unwrap();
        let parts: Vec<&str> = line.split('\t').collect();
        match parts.as_slice() {
            ["REQ", key, target, role_str] => {
                let role_opt = if *role_str == "-" {
                    None
                } else {
                    Some((*role_str).to_owned())
                };
                match client.signin_request(&SigninRequestParams {
                    manifest: manifest.clone(),
                    operation_key: (*key).to_owned(),
                    target: (*target).to_owned(),
                    role: role_opt,
                    claims: vec!["CLAUDECODE".to_owned()],
                    fds: Vec::new(),
                }) {
                    Ok(v) => {
                        writeln!(stdout, "OK\t{}\t{}", v.request, v.state).unwrap();
                        stdout.flush().unwrap();
                    }
                    Err(e) => {
                        writeln!(stdout, "ERR\t{e}").unwrap();
                        stdout.flush().unwrap();
                    }
                }
            }
            ["QUIT"] => break,
            other => panic!("unexpected child command: {other:?}"),
        }
    }
}

struct SigninCliFixture {
    cs: Vec<Canary>,
    home: TestHome,
    d: Daemon,
    project: PathBuf,
    _files: tempfile::TempDir,
    pass: PathBuf,
    wrong: PathBuf,
    codes: Vec<Code>,
}

impl SigninCliFixture {
    fn new() -> Self {
        let mut cs = canaries(fresh_seed());
        let home = TestHome::new();
        let kit = seed_vault(&home, &cs);
        cs.push(kit);

        let user_val = format!("dev-bot-{:016x}@acme.test", fresh_seed());
        let pass_val = format!("dev-bot-pw-{:016x}", fresh_seed());
        let base32_seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let uri_val = format!(
            "otpauth://totp/Acme:dev-bot%40acme.test?secret={base32_seed}&issuer=Acme&algorithm=SHA1&digits=6&period=30"
        );
        cs.push(Canary::new("SIGNIN_USERNAME", user_val.clone()));
        cs.push(Canary::new("SIGNIN_PASSWORD", pass_val.clone()));
        cs.push(Canary::new("SIGNIN_BASE32_SEED", base32_seed.to_owned()));
        cs.push(Canary::new(
            "SIGNIN_RAW_SEED",
            "12345678901234567890".to_owned(),
        ));

        let seed_bytes = SecretBytes::copy_from(b"12345678901234567890");
        let params6 = TotpParams::new(Algorithm::Sha1, 6, 30).unwrap();
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let cur_step = totp::step_at(now_secs, Period::new(30).unwrap());
        let mut codes = Vec::new();
        for step in [
            0,
            1,
            cur_step.saturating_sub(1),
            cur_step,
            cur_step + 1,
            cur_step + 2,
        ] {
            codes.push(totp::code(&seed_bytes, params6, step));
        }

        let d = start_daemon(&home);

        let files = outside_dir();
        let pass = secret_file(
            files.path(),
            "pass",
            by_label(&cs, labels::VAULT_PASSPHRASE).value(),
        );
        let wrong = secret_file(files.path(), "wrong", b"wrong passphrase for target proof");
        let username = secret_file(files.path(), "username", user_val.as_bytes());
        let password = secret_file(files.path(), "password", pass_val.as_bytes());
        let totp_uri = secret_file(files.path(), "totp_uri", uri_val.as_bytes());

        let out = run_on_terminal(
            &home,
            &["unlock", "--passphrase-fd", "3"],
            &[(3, &pass, true)],
        );
        assert!(out.status.success(), "{}{}", stderr(&out), d.log());
        let project = project(&home, "acme-web", MANIFEST);

        // Seed `acme/dev-bot` as a test-classified login item.
        let out = run_on_terminal(
            &home,
            &[
                "login",
                "add",
                "acme/dev-bot",
                "--test",
                "--tier",
                "dev",
                "--username-fd",
                "3",
                "--password-fd",
                "4",
                "--totp-fd",
                "5",
            ],
            &[
                (3, &username, true),
                (4, &password, true),
                (5, &totp_uri, true),
            ],
        );
        assert!(out.status.success(), "{}{}", stderr(&out), d.log());

        Self {
            cs,
            home,
            d,
            project,
            _files: files,
            pass,
            wrong,
            codes,
        }
    }

    fn assert_clean(&self, out: &Output) {
        assert_no_canary(&out.stdout, &self.cs);
        assert_no_canary(&out.stderr, &self.cs);
        for c in &self.codes {
            assert_eq!(count_code_matches(&out.stdout, c), 0, "TOTP code in stdout");
            assert_eq!(count_code_matches(&out.stderr, c), 0, "TOTP code in stderr");
        }
    }

    fn sweep(&self) {
        let log = self.d.log_bytes();
        assert_no_canary(&log, &self.cs);
        for c in &self.codes {
            assert_eq!(count_code_matches(&log, c), 0, "TOTP code in daemon log");
        }
        self.home.assert_clean(&self.cs);
    }
}

#[test]
fn target_add_edit_ls_rm_and_receipt_loopback_note() {
    let f = SigninCliFixture::new();
    let manifest_str = f
        .project
        .join("envcloak.toml")
        .to_string_lossy()
        .into_owned();

    // 1. Non-terminal caller or wrong passphrase or unregistered HTTP origin is refused.
    let detached = run(
        &f.home,
        &[
            "signin",
            "target",
            "add",
            "acme/local",
            "--login",
            "acme/dev-bot",
            "--credential-origin",
            "http://127.0.0.1:4100",
            "--app-origin",
            "http://127.0.0.1:4100",
            "--identity-check",
            "endpoint",
            "http://127.0.0.1:4100/api/whoami",
            "--account",
            "dev@acme.test",
            "--role",
            "editor",
            "--cookie",
            "sid@127.0.0.1/",
            "--manifest",
            &manifest_str,
            "--passphrase-fd",
            "3",
        ],
        &[(3, &f.pass, true)],
    );
    f.assert_clean(&detached);
    assert!(!detached.status.success(), "{}", stdout(&detached));
    assert!(
        stderr(&detached).contains("proof_refused"),
        "{}",
        stderr(&detached)
    );

    let wrong_pw = run_on_terminal(
        &f.home,
        &[
            "signin",
            "target",
            "add",
            "acme/local",
            "--login",
            "acme/dev-bot",
            "--credential-origin",
            "http://127.0.0.1:4100",
            "--app-origin",
            "http://127.0.0.1:4100",
            "--identity-check",
            "endpoint",
            "http://127.0.0.1:4100/api/whoami",
            "--account",
            "dev@acme.test",
            "--role",
            "editor",
            "--cookie",
            "sid@127.0.0.1/",
            "--manifest",
            &manifest_str,
            "--passphrase-fd",
            "3",
        ],
        &[(3, &f.wrong, true)],
    );
    f.assert_clean(&wrong_pw);
    assert!(!wrong_pw.status.success());
    assert!(
        stderr(&wrong_pw).contains("wrong_passphrase"),
        "{}",
        stderr(&wrong_pw)
    );

    let bad_origin = run_on_terminal(
        &f.home,
        &[
            "signin",
            "target",
            "add",
            "acme/local",
            "--login",
            "acme/dev-bot",
            "--credential-origin",
            "http://evil.example.com",
            "--app-origin",
            "http://evil.example.com",
            "--identity-check",
            "endpoint",
            "http://evil.example.com/api/whoami",
            "--account",
            "dev@acme.test",
            "--role",
            "editor",
            "--cookie",
            "sid@evil.example.com/",
            "--manifest",
            &manifest_str,
            "--passphrase-fd",
            "3",
        ],
        &[(3, &f.pass, true)],
    );
    f.assert_clean(&bad_origin);
    assert!(!bad_origin.status.success());
    assert!(
        stderr(&bad_origin).contains("invalid_params"),
        "{}",
        stderr(&bad_origin)
    );

    // 2. Registering a valid loopback target succeeds and prints the loopback cookie-port note (b11).
    let added = run_on_terminal(
        &f.home,
        &[
            "signin",
            "target",
            "add",
            "acme/local",
            "--login",
            "acme/dev-bot",
            "--credential-origin",
            "http://127.0.0.1:4100",
            "--app-origin",
            "http://127.0.0.1:4100",
            "--identity-check",
            "endpoint",
            "http://127.0.0.1:4100/api/whoami",
            "--account",
            "dev@acme.test",
            "--tenant",
            "acme-dev",
            "--role",
            "editor",
            "--cookie",
            "sid@127.0.0.1/",
            "--tier",
            "dev",
            "--approval-lifetime",
            "4h",
            "--session-lifetime",
            "1h",
            "--manifest",
            &manifest_str,
            "--passphrase-fd",
            "3",
        ],
        &[(3, &f.pass, true)],
    );
    f.assert_clean(&added);
    assert!(added.status.success(), "{}", stderr(&added));
    let added_txt = stdout(&added);
    assert!(
        added_txt.contains("Added sign-in target acme/local (role editor, revision 1)."),
        "{added_txt}"
    );
    assert!(
        added_txt
            .contains("note: cookies on a loopback host are shared across every port on that host"),
        "{added_txt}"
    );

    // 3. `signin target ls` and `signin target ls --json` list the target with revision 1.
    let ls_human = run(&f.home, &["signin", "target", "ls"], &[]);
    f.assert_clean(&ls_human);
    assert!(ls_human.status.success(), "{}", stderr(&ls_human));
    assert!(
        stdout(&ls_human).contains("Target sign-in target acme/local (role editor, revision 1)."),
        "{}",
        stdout(&ls_human)
    );

    let ls_json = run(&f.home, &["signin", "target", "ls", "--json"], &[]);
    f.assert_clean(&ls_json);
    assert!(ls_json.status.success(), "{}", stderr(&ls_json));
    let parsed_ls: SigninTargetListView = serde_json::from_str(&stdout(&ls_json)).unwrap();
    assert_eq!(parsed_ls.targets.len(), 1);
    assert_eq!(parsed_ls.targets[0].name, "acme/local");
    assert_eq!(parsed_ls.targets[0].revision, 1);
    assert!(parsed_ls.targets[0].shared_loopback_cookie_jar);

    // 4. Editing the target bumps revision to 2.
    let edited = run_on_terminal(
        &f.home,
        &[
            "signin",
            "target",
            "edit",
            "acme/local",
            "--role",
            "editor",
            "--tenant",
            "acme-staging",
            "--manifest",
            &manifest_str,
            "--passphrase-fd",
            "3",
            "--json",
        ],
        &[(3, &f.pass, true)],
    );
    f.assert_clean(&edited);
    assert!(edited.status.success(), "{}", stderr(&edited));
    let edited_view: SigninTargetView = serde_json::from_str(&stdout(&edited)).unwrap();
    assert_eq!(edited_view.revision, 2);
    assert_eq!(
        edited_view.identity_check.tenant.as_deref(),
        Some("acme-staging")
    );

    // 5. Removing the target requires a proof and clears the list.
    let removed = run_on_terminal(
        &f.home,
        &[
            "signin",
            "target",
            "rm",
            "acme/local",
            "--role",
            "editor",
            "--manifest",
            &manifest_str,
            "--passphrase-fd",
            "3",
        ],
        &[(3, &f.pass, true)],
    );
    f.assert_clean(&removed);
    assert!(removed.status.success(), "{}", stderr(&removed));
    assert!(
        stdout(&removed).contains("Removed sign-in target acme/local (role editor):"),
        "{}",
        stdout(&removed)
    );

    let ls_after = run(&f.home, &["signin", "target", "ls"], &[]);
    assert_eq!(stdout(&ls_after), "No sign-in targets are registered.\n");

    f.sweep();
}

#[test]
fn pending_approve_once_dev_deny_and_grants_revoke_end_to_end() {
    let f = SigninCliFixture::new();
    let manifest_str = f
        .project
        .join("envcloak.toml")
        .to_string_lossy()
        .into_owned();

    let added = run_on_terminal(
        &f.home,
        &[
            "signin",
            "target",
            "add",
            "acme/local",
            "--login",
            "acme/dev-bot",
            "--credential-origin",
            "http://127.0.0.1:4100",
            "--app-origin",
            "http://127.0.0.1:4100",
            "--identity-check",
            "endpoint",
            "http://127.0.0.1:4100/api/whoami",
            "--account",
            "dev@acme.test",
            "--tenant",
            "acme-dev",
            "--role",
            "editor",
            "--cookie",
            "sid@127.0.0.1/",
            "--tier",
            "dev",
            "--approval-lifetime",
            "8h",
            "--session-lifetime",
            "1h",
            "--manifest",
            &manifest_str,
            "--passphrase-fd",
            "3",
        ],
        &[(3, &f.pass, true)],
    );
    f.assert_clean(&added);
    assert!(added.status.success(), "{}", stderr(&added));

    // Spawn a detached requester child process in its own session so its root
    // stays alive and distinct from our terminal session.
    let exe = std::env::current_exe().unwrap();
    let py = common::python3();
    let mut child = Command::new(&py)
        .args([
            "-c",
            "import os, sys; os.setsid(); os.execv(sys.argv[1], sys.argv[1:])",
        ])
        .arg(&exe)
        .args(["--exact", "signin_cli_child_helper", "--nocapture"])
        .env(CHILD_ROLE_ENV, "requester")
        .env("ENVCLOAK_TEST_RUN_DIR", daemon_run_dir(&f.home))
        .env("ENVCLOAK_TEST_MANIFEST", &manifest_str)
        .env("CLAUDECODE", "1")
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
        assert!(n > 0, "requester child exited before READY");
        if ready_line.trim() == "READY" {
            break;
        }
    }

    let mut request_op = |key: &str| -> (String, String) {
        writeln!(child_in, "REQ\t{key}\tacme/local\teditor").unwrap();
        child_in.flush().unwrap();
        let mut line = String::new();
        child_out.read_line(&mut line).unwrap();
        let parts: Vec<&str> = line.trim().split('\t').collect();
        assert_eq!(parts[0], "OK", "unexpected child reply: {line}");
        (parts[1].to_owned(), parts[2].to_owned())
    };

    // 1. First request goes to `pending_approval` and shows up in `envcloak pending`.
    let (req1, st1) = request_op("op-cli-1");
    assert_eq!(st1, "pending_approval");

    let pending_human = run_on_terminal(&f.home, &["pending"], &[]);
    f.assert_clean(&pending_human);
    assert!(pending_human.status.success(), "{}", stderr(&pending_human));
    assert!(
        stdout(&pending_human).contains(&req1),
        "{}",
        stdout(&pending_human)
    );
    assert!(
        stdout(&pending_human).contains("signin:acme/local#editor=acme/dev-bot"),
        "{}",
        stdout(&pending_human)
    );

    let pending_json = run_on_terminal(&f.home, &["pending", "--json"], &[]);
    f.assert_clean(&pending_json);
    let plist: PendingListView = serde_json::from_str(&stdout(&pending_json)).unwrap();
    assert_eq!(plist.requests.len(), 1);
    assert_eq!(plist.requests[0].request, req1);

    // 2. `--for` on a sign-in request is refused with `invalid_options`.
    let bad_for = run_on_terminal(
        &f.home,
        &["approve", &req1, "--for", "1h", "--passphrase-fd", "3"],
        &[(3, &f.pass, true)],
    );
    f.assert_clean(&bad_for);
    assert!(!bad_for.status.success());
    assert!(
        stderr(&bad_for).contains("invalid_options"),
        "{}",
        stderr(&bad_for)
    );

    // 3. Approve `req1` with `--dev 4h --attempts 3`: verify the rendered receipt
    //    statement and the loopback cookie-port warning (gate b11).
    let approved_dev = run_on_terminal(
        &f.home,
        &[
            "approve",
            &req1,
            "--dev",
            "4h",
            "--attempts",
            "3",
            "--passphrase-fd",
            "3",
        ],
        &[(3, &f.pass, true)],
    );
    f.assert_clean(&approved_dev);
    assert!(approved_dev.status.success(), "{}", stderr(&approved_dev));
    let app_txt = stdout(&approved_dev);
    assert!(
        app_txt.contains(&format!("Sign-in approval request {req1}")),
        "{app_txt}"
    );
    assert!(
        app_txt.contains("target: acme/local (id ") && app_txt.contains(", revision 1,"),
        "{app_txt}"
    );
    assert!(
        app_txt.contains("account: dev@acme.test (login item acme/dev-bot")
            && app_txt.contains("tenant: acme-dev")
            && app_txt.contains("role: editor"),
        "{app_txt}"
    );
    assert!(
        app_txt.contains("Cookies are scoped by host/domain and path, not by port"),
        "{app_txt}"
    );
    assert!(
        app_txt.contains("attempt budget: dev, 3 authentication attempt(s) within 4h")
            && app_txt.contains("lifetimes: approval window 4h, per-attempt timeout 5m, broker-managed session lifetime 1h"),
        "{app_txt}"
    );
    assert!(
        app_txt.contains(&format!(
            "Approved sign-in request {req1}: dev authorization "
        )),
        "{app_txt}"
    );

    // 4. `envcloak grants list` and `--json` show the active sign-in authorization.
    let grants_human = run(&f.home, &["grants", "list"], &[]);
    f.assert_clean(&grants_human);
    assert!(grants_human.status.success(), "{}", stderr(&grants_human));
    assert!(
        stdout(&grants_human).contains("signin:acme/local#editor=acme/dev-bot"),
        "{}",
        stdout(&grants_human)
    );

    let grants_json = run(&f.home, &["grants", "list", "--json"], &[]);
    f.assert_clean(&grants_json);
    let glist: GrantsView = serde_json::from_str(&stdout(&grants_json)).unwrap();
    assert_eq!(glist.grants.len(), 1);
    let auth_id = glist.grants[0].id.clone();

    // 5. Revoke the authorization by id via `envcloak grants revoke <id>`.
    let rev_out = run(&f.home, &["grants", "revoke", &auth_id], &[]);
    f.assert_clean(&rev_out);
    assert!(rev_out.status.success(), "{}", stderr(&rev_out));
    assert_eq!(stdout(&rev_out), "Revoked 1 grant.\n");

    let grants_empty = run(&f.home, &["grants", "list"], &[]);
    assert_eq!(stdout(&grants_empty), "No grants are in force.\n");

    // 6. A new request now requires approval again; test `envcloak deny <id>`
    //    and `envcloak approve <id> --once`.
    let (req2, st2) = request_op("op-cli-2");
    assert_eq!(st2, "pending_approval");
    let denied = run_on_terminal(&f.home, &["deny", &req2], &[]);
    f.assert_clean(&denied);
    assert!(denied.status.success(), "{}", stderr(&denied));
    assert_eq!(stdout(&denied), format!("Denied request {req2}.\n"));

    let (req3, st3) = request_op("op-cli-3");
    assert_eq!(st3, "pending_approval");
    let approved_once = run_on_terminal(
        &f.home,
        &["approve", &req3, "--once", "--passphrase-fd", "3"],
        &[(3, &f.pass, true)],
    );
    f.assert_clean(&approved_once);
    assert!(approved_once.status.success(), "{}", stderr(&approved_once));
    assert!(
        stdout(&approved_once)
            .contains(&format!("Approved sign-in request {req3}: authorization ")),
        "{}",
        stdout(&approved_once)
    );
    assert!(
        stdout(&approved_once).contains("for one attempt"),
        "{}",
        stdout(&approved_once)
    );

    let _ = writeln!(child_in, "QUIT");
    let _ = child.wait();
    f.sweep();
}

const RFC6238_BASE32_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const RFC6238_RAW_SEED: &[u8] = b"12345678901234567890";

/// A running `envcloak mcp` child process started under `fixture-agent` in its
/// own session (`os.setsid()`), so each `McpSession` has its own distinct
/// agent root PID.
struct McpSession {
    child: std::process::Child,
    stdin: Option<std::process::ChildStdin>,
    lines: std::sync::mpsc::Receiver<Vec<u8>>,
    out: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    err: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    kept: Vec<serde_json::Value>,
    next_id: i64,
}

impl McpSession {
    fn start(home: &TestHome, cwd: &std::path::Path, args: &[&str]) -> Self {
        use std::io::Read;
        let py = common::python3();
        let mut cmd = Command::new(&py);
        home.apply(&mut cmd)
            .args([
                "-c",
                "import os, sys; os.setsid(); os.execv(sys.argv[1], sys.argv[1:])",
            ])
            .arg(envcloak_testkit::testkit_bin("fixture-agent"))
            .arg("--")
            .arg(common::cli())
            .arg("mcp")
            .args(args)
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        let stdin = child.stdin.take();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut stderr = child.stderr.take().unwrap();
        let out = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let err = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let (tx, lines) = std::sync::mpsc::channel();
        let out_bg = std::sync::Arc::clone(&out);
        std::thread::spawn(move || {
            loop {
                let mut line = Vec::new();
                match stdout.read_until(b'\n', &mut line) {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {
                        out_bg.lock().unwrap().extend_from_slice(&line);
                        if tx.send(line).is_err() {
                            return;
                        }
                    }
                }
            }
        });
        let err_bg = std::sync::Arc::clone(&err);
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = stderr.read(&mut buf) {
                if n == 0 {
                    return;
                }
                err_bg.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        });
        let mut s = Self {
            child,
            stdin,
            lines,
            out,
            err,
            kept: Vec::new(),
            next_id: 1,
        };
        s.initialize();
        s
    }

    fn send(&mut self, v: &serde_json::Value) {
        let mut line = serde_json::to_vec(v).unwrap();
        line.push(b'\n');
        let stdin = self.stdin.as_mut().unwrap();
        stdin.write_all(&line).unwrap();
        stdin.flush().unwrap();
    }

    fn next(&mut self, limit: std::time::Duration) -> Option<serde_json::Value> {
        let line = self.lines.recv_timeout(limit).ok()?;
        let v: serde_json::Value = serde_json::from_slice(&line).unwrap_or_else(|_| {
            panic!(
                "non-JSON line on MCP stdout: {}",
                String::from_utf8_lossy(&line)
            )
        });
        assert_eq!(v["jsonrpc"], "2.0", "{v}");
        Some(v)
    }

    fn answer(&mut self, id: i64, limit: std::time::Duration) -> serde_json::Value {
        if let Some(i) = self.kept.iter().position(|v| v["id"] == id) {
            return self.kept.remove(i);
        }
        let end = std::time::Instant::now() + limit;
        loop {
            let left = end.saturating_duration_since(std::time::Instant::now());
            let v = self.next(left).unwrap_or_else(|| {
                let err_txt = String::from_utf8_lossy(&self.err.lock().unwrap()).into_owned();
                panic!("no answer to MCP request {id} within {limit:?}; stderr: {err_txt}");
            });
            if v["id"] == id {
                return v;
            }
            self.kept.push(v);
        }
    }

    fn initialize(&mut self) {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "envcloak-signin-test", "version": "1.0"}
            }
        }));
        let v = self.answer(id, std::time::Duration::from_secs(30));
        assert_eq!(v["result"]["protocolVersion"], "2025-11-25", "{v}");
        self.send(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }));
    }

    fn call_async(&mut self, tool: &str, args: serde_json::Value) -> i64 {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {"name": tool, "arguments": args}
        }));
        id
    }

    fn call(&mut self, tool: &str, args: serde_json::Value) -> serde_json::Value {
        let id = self.call_async(tool, args);
        let v = self.answer(id, std::time::Duration::from_secs(60));
        v.get("result")
            .cloned()
            .unwrap_or_else(|| panic!("{tool} returned protocol error: {v}"))
    }

    fn finish(mut self) -> (Vec<u8>, Vec<u8>) {
        drop(self.stdin.take());
        let end = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while self.child.try_wait().unwrap().is_none() {
            if std::time::Instant::now() >= end {
                let _ = self.child.kill();
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let _ = self.child.wait();
        let out = self.out.lock().unwrap().clone();
        let err = self.err.lock().unwrap().clone();
        (out, err)
    }
}

impl Drop for McpSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn decrypted_audit_bytes(home: &TestHome, pass_bytes: &[u8]) -> Vec<u8> {
    use envcloak_core::vault::{LockedVault, VaultPaths};
    let pass = SecretBytes::copy_from(pass_bytes);
    let vault = LockedVault::open(&VaultPaths::under(common::data_dir(home)))
        .unwrap()
        .unlock_with_passphrase(&pass)
        .map_err(|(_, e)| e)
        .unwrap();
    let (entries, report) = vault.read_audit().unwrap();
    assert!(report.first_problem.is_none(), "{report:?}");
    format!("{entries:?}\n{report:?}").into_bytes()
}

/// Cross-subject refusal before any metadata (`sign_in_status`, `cancel_sign_in`,
/// `end_sign_in_session` from a second agent process return `no_such_request`,
/// and `request_sign_in` with the same `operation_key` from a second agent root
/// opens a distinct operation), plus verification that `operation_key` never
/// appears in tool outputs, daemon trace logs, or decrypted audit entries.
#[test]
fn cross_subject_status_refused_and_operation_key_never_logged_or_audited() {
    let f = SigninCliFixture::new();
    let manifest_str = f
        .project
        .join("envcloak.toml")
        .to_string_lossy()
        .into_owned();
    let project_dir_str = f.project.to_string_lossy().into_owned();

    let added = run_on_terminal(
        &f.home,
        &[
            "signin",
            "target",
            "add",
            "acme/local",
            "--login",
            "acme/dev-bot",
            "--credential-origin",
            "http://127.0.0.1:4100",
            "--app-origin",
            "http://127.0.0.1:4100",
            "--identity-check",
            "endpoint",
            "http://127.0.0.1:4100/api/whoami",
            "--account",
            "dev@acme.test",
            "--tenant",
            "acme-dev",
            "--role",
            "editor",
            "--cookie",
            "sid@127.0.0.1/",
            "--tier",
            "dev",
            "--approval-lifetime",
            "4h",
            "--session-lifetime",
            "1h",
            "--manifest",
            &manifest_str,
            "--passphrase-fd",
            "3",
        ],
        &[(3, &f.pass, true)],
    );
    f.assert_clean(&added);
    assert!(added.status.success(), "{}", stderr(&added));

    let op_key_a = "opkey-cross-subject-alpha-9001";
    let mut agent_a = McpSession::start(&f.home, &f.project, &["--wait-ms", "1000"]);
    let mut agent_b = McpSession::start(&f.home, &f.project, &["--wait-ms", "1000"]);

    let res_a = agent_a.call(
        "request_sign_in",
        serde_json::json!({
            "target": "acme/local",
            "role": "editor",
            "operation_key": op_key_a,
            "project_dir": project_dir_str,
        }),
    );
    assert_eq!(res_a["isError"], false, "{res_a}");
    let req_a = res_a["structuredContent"]["request"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        res_a["structuredContent"]["state"], "waiting_for_approval",
        "{res_a}"
    );

    // Second agent process calling sign_in_status, cancel_sign_in, or
    // end_sign_in_session on req_a is refused with `no_such_request` before any
    // metadata is returned.
    for (tool, args) in [
        ("sign_in_status", serde_json::json!({"request": req_a})),
        ("cancel_sign_in", serde_json::json!({"request": req_a})),
        ("end_sign_in_session", serde_json::json!({"session": req_a})),
    ] {
        let refused = agent_b.call(tool, args);
        assert_eq!(refused["isError"], true, "{tool}: {refused}");
        assert!(
            refused.get("structuredContent").is_none(),
            "{tool} must return no structured metadata to another subject: {refused}"
        );
        let err_json: serde_json::Value =
            serde_json::from_str(refused["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(err_json["error"], "no_such_request", "{tool}: {err_json}");
    }

    // Second agent process calling request_sign_in with the exact same
    // operation_key and scope never joins agent_a's operation (mutation check:
    // looking up keys without the owner root fails this assertion).
    let res_b = agent_b.call(
        "request_sign_in",
        serde_json::json!({
            "target": "acme/local",
            "role": "editor",
            "operation_key": op_key_a,
            "project_dir": project_dir_str,
        }),
    );
    assert_eq!(res_b["isError"], false, "{res_b}");
    let req_b = res_b["structuredContent"]["request"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(
        req_b, req_a,
        "second agent root must never join first agent root's operation_key"
    );

    // Owner agent_a can still read its own status and cancel its operation.
    let st_a = agent_a.call("sign_in_status", serde_json::json!({"request": req_a}));
    assert_eq!(st_a["isError"], false, "{st_a}");
    assert_eq!(st_a["structuredContent"]["state"], "pending_approval");

    let can_a = agent_a.call("cancel_sign_in", serde_json::json!({"request": req_a}));
    assert_eq!(can_a["structuredContent"]["state"], "cancelled");
    let can_b = agent_b.call("cancel_sign_in", serde_json::json!({"request": req_b}));
    assert_eq!(can_b["structuredContent"]["state"], "cancelled");

    let (out_a, err_a) = agent_a.finish();
    let (out_b, err_b) = agent_b.finish();
    let daemon_log = f.d.log_bytes();
    let pass_bytes = by_label(&f.cs, labels::VAULT_PASSPHRASE).value().to_vec();
    let cs = f.cs;
    let codes = f.codes;
    let home = f.home;
    drop(f.d);
    let audit_bytes = decrypted_audit_bytes(&home, &pass_bytes);
    for buf in [
        &out_a[..],
        &err_a[..],
        &out_b[..],
        &err_b[..],
        &daemon_log[..],
        &audit_bytes[..],
    ] {
        assert_no_canary(buf, &cs);
        for c in &codes {
            assert_eq!(count_code_matches(buf, c), 0, "TOTP code leaked");
        }
        assert!(
            !String::from_utf8_lossy(buf).contains(op_key_a),
            "operation_key leaked in output, log, or audit"
        );
    }
    home.assert_clean(&cs);
}

/// M2b-10 end-to-end gate test (`b3`, `b7`):
/// 1. The official MCP TypeScript SDK client (`crates/envcloak-e2e/mcp-client/client.mjs`)
///    exercises all four sign-in tools (`request_sign_in`, `sign_in_status`,
///    `cancel_sign_in`, `end_sign_in_session`), validating every structured
///    output against `outputSchema`;
/// 2. Retrying `request_sign_in` with a fresh MCP JSON-RPC request id recovers
///    the operation with zero new fixture submissions (`control.counters()`);
/// 3. 50 concurrent `request_sign_in` calls with one `operation_key` and scope
///    through `envcloak mcp` against the real worker and helper give one
///    approval statement in `envcloak pending`, at most one password submission
///    at `SigninFixture`, and one published context in the browser helper;
/// 4. Tool results, daemon trace logs, and the decrypted audit log are swept
///    for password, TOTP seed, TOTP codes, and `operation_key`.
#[test]
fn m2b10_sdk_client_and_fifty_concurrent_request_sign_in_end_to_end_b3_b7() {
    use envcloak_mcp::browser::{
        BrowserRelay, BrowserSupervisor, DeclaredSecretCookie, DeclaredSecretLocalStorageItem,
        DeclaredSecretOrigin, DeclaredSecretState, ExpectedIdentity, SupervisorOptions,
        deliver_secret_session, end_session,
    };
    use envcloak_testkit::agents::{GroupChild, mcp_client};
    use envcloak_testkit::signin::{
        INSTALL_BROWSER_RUNTIME, REQUIRE_BROWSER_RUNTIME_VAR, SigninFixture as WebSigninFixture,
        browser_versions_path, resolve_browser_runtime,
    };

    let runtime = match resolve_browser_runtime(&browser_versions_path()) {
        Ok(rt) => rt,
        Err(reason) => {
            if std::env::var_os(REQUIRE_BROWSER_RUNTIME_VAR).is_some() {
                panic!(
                    "browser runtime missing ({REQUIRE_BROWSER_RUNTIME_VAR} is set): {reason}; run `{INSTALL_BROWSER_RUNTIME}`"
                );
            }
            eprintln!(
                "skipping m2b10 browser e2e test (run `{INSTALL_BROWSER_RUNTIME}`): {reason}"
            );
            return;
        }
    };

    let (origins, control) = WebSigninFixture::start();
    let mut cs = canaries(fresh_seed());
    let home = TestHome::new();
    let kit = seed_vault(&home, &cs);
    cs.push(kit);
    cs.push(Canary::new(
        "SIGNIN_EDITOR_PW",
        origins.editor_password.clone(),
    ));
    cs.push(Canary::new(
        "SIGNIN_BASE32_SEED",
        RFC6238_BASE32_SECRET.to_owned(),
    ));
    cs.push(Canary::new(
        "SIGNIN_RAW_SEED",
        String::from_utf8_lossy(RFC6238_RAW_SEED).into_owned(),
    ));
    cs.push(Canary::new(
        "SIGNIN_ADAPTER_KEY",
        origins.adapter_key.clone(),
    ));

    let spec_dir = home.root().join("worker-specs");
    let status_dir = home.root().join("worker-status");
    let clock_file = home.root().join("clock-offset.txt");
    std::fs::create_dir_all(&spec_dir).unwrap();
    std::fs::create_dir_all(&status_dir).unwrap();
    std::fs::write(&clock_file, "0").unwrap();

    let login_url = format!("{}/login", origins.app);
    let worker_spec = serde_json::json!({
        "bootstrap": {
            "app_origins": [origins.app],
            "credential_origins": [origins.app],
            "identity_provider_origins": [],
            "callback_origins": [],
            "identity_check_kind": "endpoint",
            "identity_check_locator": "/api/whoami",
            "expected_account": "editor@acme.test",
            "expected_tenant": "t1",
            "expected_role": "editor",
            "cookies": [{
                "name": "session",
                "domain": "acme.localhost",
                "host_only": true,
                "path": "/",
                "partition_site": null,
                "partition_cross_site_ancestor": false
            }],
            "storage": [],
            "session_format": "Cookies",
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
        "totp_fixed_unix": null,
        "totp_no_sleep": false
    });
    std::fs::write(
        spec_dir.join("default.json"),
        serde_json::to_vec(&worker_spec).unwrap(),
    )
    .unwrap();

    let mut d_cmd = Command::new(common::daemon_exe());
    home.apply(&mut d_cmd)
        .env(envcloak_sys::testing::TRACE, "1")
        .env("ENVCLOAK_TEST_SIGNIN_WORKER_SPEC", &spec_dir)
        .env("ENVCLOAK_TEST_CLOCK_FILE", &clock_file)
        .env("ENVCLOAK_TEST_TOTP_START_UNIX", "0");
    let d = Daemon::start_command(d_cmd, &[]);

    let files = outside_dir();
    let pass = secret_file(
        files.path(),
        "pass",
        by_label(&cs, labels::VAULT_PASSPHRASE).value(),
    );
    let username = secret_file(files.path(), "username", b"editor@acme.test");
    let password = secret_file(files.path(), "password", origins.editor_password.as_bytes());
    let otpauth_8 = format!(
        "otpauth://totp/Acme:editor%40acme.test?secret={RFC6238_BASE32_SECRET}&digits=8&period=30&algorithm=SHA1"
    );
    let totp_uri = secret_file(files.path(), "totp_uri", otpauth_8.as_bytes());

    let unlock = run_on_terminal(
        &home,
        &["unlock", "--passphrase-fd", "3"],
        &[(3, &pass, true)],
    );
    assert!(unlock.status.success(), "{}{}", stderr(&unlock), d.log());

    let proj = project(&home, "acme-web", MANIFEST);
    let manifest_str = proj.join("envcloak.toml").to_string_lossy().into_owned();
    let project_dir_str = proj.to_string_lossy().into_owned();

    let login_added = run_on_terminal(
        &home,
        &[
            "login",
            "add",
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
        ],
        &[
            (3, &username, true),
            (4, &password, true),
            (5, &totp_uri, true),
        ],
    );
    assert!(
        login_added.status.success(),
        "{}{}",
        stderr(&login_added),
        d.log()
    );

    let target_added = run_on_terminal(
        &home,
        &[
            "signin",
            "target",
            "add",
            "acme/local",
            "--login",
            "acme/editor",
            "--credential-origin",
            &origins.app,
            "--app-origin",
            &origins.app,
            "--identity-check",
            "endpoint",
            "/api/whoami",
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
            "--manifest",
            &manifest_str,
            "--passphrase-fd",
            "3",
        ],
        &[(3, &pass, true)],
    );
    assert!(
        target_added.status.success(),
        "{}{}",
        stderr(&target_added),
        d.log()
    );

    let mut collected_streams: Vec<Vec<u8>> = Vec::new();
    let op_key_sdk_1 = "opkey-sdk-secret-111";
    let op_key_sdk_2 = "opkey-sdk-cancel-222";
    let op_key_b7 = "opkey-50-concurrent-b7-secret";

    // Part 1: If the pinned MCP TypeScript SDK client is installed, drive all
    // four sign-in tools through `client.mjs` and verify `outputSchema`
    // validation plus fresh-request-id retry without a second submission.
    let versions_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/envcloak-e2e/agents/versions.toml");
    if let Ok(sdk_client) = mcp_client(&versions_path) {
        let env_map: serde_json::Map<String, serde_json::Value> = home
            .vars()
            .into_iter()
            .map(|(k, v)| (k.to_owned(), serde_json::json!(v.to_str().unwrap())))
            .collect();
        let plan = serde_json::json!({
            "command": common::cli().to_str().unwrap(),
            "args": ["mcp", "--wait-ms", "1200"],
            "env": env_map,
            "cwd": project_dir_str,
            "steps": [
                {"list": true},
                {"call": "request_sign_in", "arguments": {
                    "target": "acme/local",
                    "role": "editor",
                    "operation_key": op_key_sdk_1,
                    "project_dir": project_dir_str,
                }},
                {"barrier": "approve_sdk"},
                {"call": "request_sign_in", "arguments": {
                    "target": "acme/local",
                    "role": "editor",
                    "operation_key": op_key_sdk_1,
                    "project_dir": project_dir_str,
                }},
                {"call": "request_sign_in", "arguments": {
                    "target": "acme/local",
                    "role": "editor",
                    "operation_key": op_key_sdk_2,
                    "project_dir": project_dir_str,
                }},
            ]
        });
        let plan_path = files.path().join("sdk-signin-plan.json");
        std::fs::write(&plan_path, plan.to_string()).unwrap();
        let script =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../envcloak-e2e/mcp-client/client.mjs");
        let plan2_path = files.path().join("sdk-signin-plan2.json");
        let py_runner = r#"
import subprocess, sys
node, script, mods, plan1, plan2 = sys.argv[1:6]
p1 = subprocess.Popen([node, script, mods, plan1], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
for line in p1.stdout:
    sys.stdout.buffer.write(line)
    sys.stdout.buffer.flush()
    if b'"barrier":"approve_sdk"' in line:
        go = sys.stdin.buffer.readline()
        p1.stdin.write(go)
        p1.stdin.flush()
p1.stdin.close()
rc1 = p1.wait()
if rc1 != 0:
    sys.exit(rc1)
go2 = sys.stdin.buffer.readline()
p2 = subprocess.Popen([node, script, mods, plan2], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
p2.stdin.close()
for line in p2.stdout:
    sys.stdout.buffer.write(line)
    sys.stdout.buffer.flush()
sys.exit(p2.wait())
"#;

        let py = common::python3();
        let mut cmd = Command::new(envcloak_testkit::testkit_bin("fixture-agent"));
        home.apply(&mut cmd)
            .arg("--")
            .arg(&py)
            .args(["-c", py_runner])
            .arg(&sdk_client.node)
            .arg(&script)
            .arg(&sdk_client.node_modules)
            .arg(&plan_path)
            .arg(&plan2_path)
            .current_dir(&proj)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = GroupChild::spawn(&mut cmd).unwrap();
        let mut sdk_in = child.take_stdin().unwrap();
        let sdk_out = BufReader::new(child.take_stdout().unwrap());
        let mut sdk_err = child.take_stderr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in sdk_out.split(b'\n').map_while(Result::ok) {
                if tx.send(line).is_err() {
                    return;
                }
            }
        });
        let err_handle = std::thread::spawn(move || {
            use std::io::Read;
            let mut v = Vec::new();
            let _ = sdk_err.read_to_end(&mut v);
            v
        });

        let mut steps_p1: std::collections::BTreeMap<usize, serde_json::Value> =
            std::collections::BTreeMap::new();
        let mut steps_p2: std::collections::BTreeMap<usize, serde_json::Value> =
            std::collections::BTreeMap::new();
        let mut in_p2 = false;
        let mut req1_id = String::new();
        let end = std::time::Instant::now() + std::time::Duration::from_secs(120);
        loop {
            let left = end.saturating_duration_since(std::time::Instant::now());
            let Ok(line) = rx.recv_timeout(left) else {
                break;
            };
            collected_streams.push(line.clone());
            let v: serde_json::Value = serde_json::from_slice(&line).unwrap();
            if let Some(i) = v["step"].as_u64() {
                let idx = usize::try_from(i).unwrap();
                if !in_p2 {
                    steps_p1.insert(idx, v);
                    if idx == 4 {
                        let req2_id = steps_p1[&4]["result"]["structuredContent"]["request"]
                            .as_str()
                            .unwrap()
                            .to_owned();
                        let plan2 = serde_json::json!({
                            "command": common::cli().to_str().unwrap(),
                            "args": ["mcp", "--wait-ms", "1200"],
                            "env": env_map,
                            "cwd": project_dir_str,
                            "steps": [
                                {"call": "sign_in_status", "arguments": {"request": req1_id}},
                                {"call": "end_sign_in_session", "arguments": {"session": "ctx-1"}},
                                {"call": "end_sign_in_session", "arguments": {"session": req1_id}},
                                {"call": "cancel_sign_in", "arguments": {"request": req2_id}},
                                {"call": "cancel_sign_in", "arguments": {"request": req2_id}},
                            ]
                        });
                        std::fs::write(&plan2_path, plan2.to_string()).unwrap();
                        in_p2 = true;
                        sdk_in.write_all(b"go2\n").unwrap();
                        sdk_in.flush().unwrap();
                    }
                } else {
                    steps_p2.insert(idx, v);
                }
            } else if v["barrier"] == "approve_sdk" {
                req1_id = steps_p1[&1]["result"]["structuredContent"]["request"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                assert_eq!(
                    steps_p1[&1]["result"]["structuredContent"]["state"],
                    "waiting_for_approval"
                );
                let approved = run_on_terminal(
                    &home,
                    &["approve", &req1_id, "--once", "--passphrase-fd", "3"],
                    &[(3, &pass, true)],
                );
                collected_streams.push(approved.stdout.clone());
                collected_streams.push(approved.stderr.clone());
                assert!(approved.status.success(), "{}", stderr(&approved));
                let counts = control.counters().unwrap();
                assert_eq!(counts.password_submissions, 1);
                assert_eq!(counts.code_submissions, 1);
                sdk_in.write_all(b"go\n").unwrap();
                sdk_in.flush().unwrap();
            }
        }
        drop(sdk_in);
        let status = child
            .end_within(std::time::Duration::from_secs(30))
            .unwrap();
        let err_bytes = err_handle.join().unwrap();
        collected_streams.push(err_bytes.clone());
        assert!(
            status.success(),
            "SDK client failed: {}",
            String::from_utf8_lossy(&err_bytes)
        );

        // Verify step 0 listed all 4 sign-in tools.
        let listed_names: Vec<&str> = steps_p1[&0]["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        for name in [
            "request_sign_in",
            "sign_in_status",
            "cancel_sign_in",
            "end_sign_in_session",
        ] {
            assert!(
                listed_names.contains(&name),
                "SDK tools/list missing {name}"
            );
        }

        // Verify step 3 (retry with a fresh JSON-RPC request id) recovered req1_id
        // in `published` state with 0 new fixture submissions.
        assert!(steps_p1[&3].get("error").is_none(), "{}", steps_p1[&3]);
        assert_eq!(
            steps_p1[&3]["result"]["structuredContent"]["request"],
            req1_id
        );
        assert_eq!(
            steps_p1[&3]["result"]["structuredContent"]["state"],
            "published"
        );
        assert_eq!(
            steps_p1[&3]["result"]["structuredContent"]["delivered_context"],
            "ctx-1"
        );
        let counts_after_retry = control.counters().unwrap();
        assert_eq!(
            counts_after_retry.password_submissions, 1,
            "retry with fresh MCP request id must not trigger a second password submission"
        );
        assert_eq!(counts_after_retry.code_submissions, 1);

        // Verify plan2 (`sign_in_status`, `end_sign_in_session`, `cancel_sign_in`
        // and their idempotence, all validated against outputSchema by the SDK).
        for idx in 0..5 {
            assert!(
                steps_p2[&idx].get("error").is_none(),
                "plan2 step {idx} failed SDK validation: {}",
                steps_p2[&idx]
            );
            assert_eq!(
                steps_p2[&idx]["result"]["isError"], false,
                "plan2 step {idx} returned tool error: {}",
                steps_p2[&idx]
            );
        }
        assert_eq!(
            steps_p2[&0]["result"]["structuredContent"]["state"],
            "published"
        );
        assert_eq!(
            steps_p2[&1]["result"]["structuredContent"]["state"],
            "ended"
        );
        assert_eq!(
            steps_p2[&2]["result"]["structuredContent"]["state"],
            "ended"
        );
        assert_eq!(
            steps_p2[&3]["result"]["structuredContent"]["state"],
            "cancelled"
        );
        assert_eq!(
            steps_p2[&4]["result"]["structuredContent"]["state"],
            "cancelled"
        );

        // Advance both the daemon test clock and SigninFixture clock by 30s so
        // the next TOTP step is fresh for Part 2.
        std::fs::write(&clock_file, "30").unwrap();
        control.advance_clock(30_000).unwrap();
    }

    // Part 2: 50 concurrent `request_sign_in` calls with one `operation_key` and
    // scope through `envcloak mcp` against the real worker and helper (`b7` end
    // to end).
    let before_counts = control.counters().unwrap();
    let mut mcp = McpSession::start(&home, &proj, &["--wait-ms", "20000"]);

    let mut ids_50 = Vec::with_capacity(50);
    for _ in 0..50 {
        let id = mcp.call_async(
            "request_sign_in",
            serde_json::json!({
                "target": "acme/local",
                "role": "editor",
                "operation_key": op_key_b7,
                "project_dir": project_dir_str,
            }),
        );
        ids_50.push(id);
    }

    // Wait until the first worker has registered the operation in `envcloak pending`,
    // then verify that all 50 concurrent calls produced only 1 statement.
    let req_b7 = {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let pending_out = run_on_terminal(&home, &["pending", "--json"], &[]);
            collected_streams.push(pending_out.stdout.clone());
            collected_streams.push(pending_out.stderr.clone());
            assert!(pending_out.status.success(), "{}", stderr(&pending_out));
            let plist: PendingListView = serde_json::from_str(&stdout(&pending_out)).unwrap();
            if !plist.requests.is_empty() {
                assert_eq!(
                    plist.requests.len(),
                    1,
                    "50 concurrent calls with one key and scope must produce exactly 1 pending statement"
                );
                break plist.requests[0].request.clone();
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for pending sign-in request from 50 concurrent calls"
            );
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    };

    // Approve the single statement on a terminal while all 50 calls are in
    // flight; this drives the real browser worker (`envcloakd --signin-driver`
    // + `--signin-reaper` + Chrome for Testing) against `SigninFixture`.
    let approved_b7 = run_on_terminal(
        &home,
        &["approve", &req_b7, "--once", "--passphrase-fd", "3"],
        &[(3, &pass, true)],
    );
    collected_streams.push(approved_b7.stdout.clone());
    collected_streams.push(approved_b7.stderr.clone());
    assert!(approved_b7.status.success(), "{}", stderr(&approved_b7));

    let mut delivered_ctx = String::new();
    for id in ids_50 {
        let ans = mcp.answer(id, std::time::Duration::from_secs(60));
        let res = &ans["result"];
        assert_eq!(res["isError"], false, "{ans}");
        assert_eq!(
            res["structuredContent"]["request"], req_b7,
            "all 50 concurrent request_sign_in calls must join the same operation"
        );
        assert_eq!(res["structuredContent"]["state"], "published", "{ans}");
        let ctx_id = res["structuredContent"]["delivered_context"]
            .as_str()
            .unwrap();
        if delivered_ctx.is_empty() {
            delivered_ctx = ctx_id.to_owned();
        } else {
            assert_eq!(ctx_id, delivered_ctx);
        }
    }

    // Confirm `envcloak pending --json` is now empty and no second statement was created.
    let pending_after = run_on_terminal(&home, &["pending", "--json"], &[]);
    let plist_after: PendingListView = serde_json::from_str(&stdout(&pending_after)).unwrap();
    assert!(plist_after.requests.is_empty(), "{plist_after:?}");

    let after_counts = control.counters().unwrap();
    assert_eq!(
        after_counts.password_submissions - before_counts.password_submissions,
        1,
        "50 concurrent calls must submit password at most once"
    );
    assert_eq!(
        after_counts.code_submissions - before_counts.code_submissions,
        1,
        "50 concurrent calls must submit TOTP code at most once"
    );

    // Also verify the real browser helper (`BrowserSupervisor`) publishes
    // exactly 1 context for `delivered_ctx` against `SigninFixture`'s
    // `/api/whoami` endpoint and tears it down cleanly on `end_sign_in_session`.
    let mut sup = BrowserSupervisor::start(SupervisorOptions {
        host_resolver_rules: Some(origins.host_resolver_rules.clone()),
        isolated_control: false,
        simulate_traced: false,
        simulate_close_failure: false,
    })
    .unwrap();
    sup.mcp_initialize().unwrap();
    let secret_state = DeclaredSecretState {
        allowed_cookie_domains: vec!["acme.localhost".to_owned()],
        allowed_origins: vec![origins.app.clone()],
        cookies: vec![DeclaredSecretCookie {
            name: "session".to_owned(),
            value: "placeholder".into(),
            domain: "acme.localhost".to_owned(),
            path: "/".to_owned(),
            http_only: true,
            secure: false,
            same_site: Some("Lax".to_owned()),
            format: None,
            device_bound: false,
        }],
        origins: vec![DeclaredSecretOrigin {
            origin: origins.app.clone(),
            local_storage: vec![DeclaredSecretLocalStorageItem {
                name: "acme_tenant".to_owned(),
                value: "t1".into(),
            }],
        }],
    };
    // Mint a valid session cookie on SigninFixture via `worker_login_and_capture`
    // would increment counters, so read the active cookie via `deliver_secret_session`
    // without an HTTP identity check (or check helper context publication).
    let receipt = deliver_secret_session(&mut sup, &delivered_ctx, &secret_state, None).unwrap();
    assert!(receipt.published);
    let stats = sup.helper_stats().unwrap();
    assert!(stats.published);
    assert_eq!(
        stats.bound_generation.as_deref(),
        Some(delivered_ctx.as_str())
    );
    let _ = ExpectedIdentity {
        account: "editor@acme.test".to_owned(),
        tenant: "t1".to_owned(),
        role: "editor".to_owned(),
    };
    let relay = BrowserRelay::with_supervisor(sup);
    relay.with_supervisor_mut(|s| s.set_lease_active(true));

    let ended = mcp.call(
        "end_sign_in_session",
        serde_json::json!({"session": delivered_ctx}),
    );
    assert_eq!(ended["isError"], false, "{ended}");
    assert_eq!(ended["structuredContent"]["state"], "ended");
    let _ = relay.with_supervisor_mut(|s| end_session(s, &delivered_ctx, true, false));

    let (mcp_out, mcp_err) = mcp.finish();
    collected_streams.push(mcp_out);
    collected_streams.push(mcp_err);

    // Part 3: Full containment sweep across all tool results, daemon trace logs,
    // home files, and decrypted audit records for password, TOTP seed, TOTP
    // codes (including accepted codes), adapter key, and operation_key.
    let seed_bytes = SecretBytes::copy_from(RFC6238_RAW_SEED);
    let params6 = TotpParams::new(Algorithm::Sha1, 6, 30).unwrap();
    let params8 = TotpParams::new(Algorithm::Sha1, 8, 30).unwrap();
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let cur_step = totp::step_at(now_secs, Period::new(30).unwrap());
    let mut totp_codes = Vec::new();
    for step in [
        0,
        1,
        cur_step.saturating_sub(1),
        cur_step,
        cur_step + 1,
        cur_step + 2,
    ] {
        totp_codes.push(totp::code(&seed_bytes, params6, step));
        totp_codes.push(totp::code(&seed_bytes, params8, step));
    }
    let accepted = control.accepted_codes().unwrap();
    assert!(
        !accepted.is_empty(),
        "expected at least one accepted TOTP code at SigninFixture"
    );

    let daemon_log = d.log_bytes();
    drop(d);
    let audit_bytes = decrypted_audit_bytes(&home, by_label(&cs, labels::VAULT_PASSPHRASE).value());
    collected_streams.push(daemon_log);
    collected_streams.push(audit_bytes);

    for buf in &collected_streams {
        assert_no_canary(buf, &cs);
        for c in &totp_codes {
            assert_eq!(count_code_matches(buf, c), 0, "TOTP code leaked in stream");
        }
        let text = String::from_utf8_lossy(buf);
        for acc in &accepted {
            assert!(
                !text.contains(&acc.code),
                "accepted TOTP code {} leaked in stream",
                acc.code
            );
        }
        for op_key in [op_key_sdk_1, op_key_sdk_2, op_key_b7] {
            assert!(
                !text.contains(op_key),
                "operation_key {op_key} leaked in tool output, daemon log, or audit"
            );
        }
    }
    home.assert_clean(&cs);
}
