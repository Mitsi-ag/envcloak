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
