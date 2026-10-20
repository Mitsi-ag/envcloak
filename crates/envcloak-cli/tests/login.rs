//! Login items, `envcloak login add`, `envcloak show`, login-field
//! rotation (`envcloak rotate <slug>#username|#password|#totp|#adapter_key`),
//! typed-field isolation, and bounded-output 6-digit TOTP code search
//! (M2b-03; SPEC §6.8, §10b; R-M2b-05, R-M2b-06, R-M2b-12, R-M2b-17,
//! R-M2b-24, R-M2b-36, R-M2b-40, R-M2b-52, R-M2b-55; gates b3, b15, b18).
#![allow(clippy::unwrap_used)]

mod common;

use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::time::Duration;

use common::{
    MANIFEST, cli, cli_command, data_dir, drive, finish_within, on_terminal_command,
    on_terminal_program, outside_dir, project, run, run_on_terminal, secret_file, seed_vault,
    start_daemon, stderr, stdout,
};
use envcloak_core::SecretBytes;
use envcloak_core::audit::AuditKind;
use envcloak_core::crypto::ItemClass;
use envcloak_core::vault::{Classification, LockedVault, LoginTier, Slug, VaultPaths};
use envcloak_ipc::proto::{
    CandidateForm, ExposedItem, MarkExposedParams, ScanCandidate, ScanMatchParams, ScanPurpose,
    ScanSource,
};
use envcloak_ipc::view::ExposureSourceView;
use envcloak_ipc::{Client, RunPaths, WireSecret};
use envcloak_signin::totp::{self, Algorithm, Code, Period, TotpParams, count_code_matches};
use envcloak_testkit::{
    Canary, Daemon, TestHome, assert_no_canary, by_label, canaries, daemon_run_dir, fresh_seed,
    labels, testkit_bin,
};

struct LoginFixture {
    cs: Vec<Canary>,
    home: TestHome,
    d: Daemon,
    project: PathBuf,
    files: tempfile::TempDir,
    pass: PathBuf,
    wrong: PathBuf,
    username: PathBuf,
    password: PathBuf,
    totp_uri: PathBuf,
    adapter_key: PathBuf,
    codes: Vec<Code>,
}

impl LoginFixture {
    fn new() -> Self {
        let mut cs = canaries(fresh_seed());
        let home = TestHome::new();
        let kit = seed_vault(&home, &cs);
        cs.push(kit);

        let user_val = format!("alice-login-{:016x}@example.test", fresh_seed());
        let pass_val = format!("correct-login-pw-{:016x}", fresh_seed());
        // RFC 6238 20-byte ASCII seed in base32: GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
        let base32_seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let uri_val = format!(
            "otpauth://totp/Acme:alice%40example.test?secret={base32_seed}&issuer=Acme&algorithm=SHA1&digits=6&period=30"
        );
        let adapter_val = format!("adapter-secret-{:016x}", fresh_seed());

        cs.push(Canary::new("LOGIN_USERNAME", user_val.clone()));
        cs.push(Canary::new("LOGIN_PASSWORD", pass_val.clone()));
        cs.push(Canary::new("LOGIN_BASE32_SEED", base32_seed.to_owned()));
        cs.push(Canary::new(
            "LOGIN_RAW_SEED",
            "12345678901234567890".to_owned(),
        ));
        cs.push(Canary::new("LOGIN_ADAPTER_KEY", adapter_val.clone()));

        let seed_bytes = SecretBytes::copy_from(b"12345678901234567890");
        let params6 = TotpParams::new(Algorithm::Sha1, 6, 30).unwrap();
        let params8 = TotpParams::new(Algorithm::Sha1, 8, 30).unwrap();
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
            codes.push(totp::code(&seed_bytes, params8, step));
        }

        let d = start_daemon(&home);
        let files = outside_dir();
        let pass = secret_file(
            files.path(),
            "pass",
            by_label(&cs, labels::VAULT_PASSPHRASE).value(),
        );
        let wrong = secret_file(files.path(), "wrong", b"wrong passphrase for rotation test");
        let username = secret_file(files.path(), "username", user_val.as_bytes());
        let password = secret_file(files.path(), "password", pass_val.as_bytes());
        let totp_uri = secret_file(files.path(), "totp_uri", uri_val.as_bytes());
        let adapter_key = secret_file(files.path(), "adapter_key", adapter_val.as_bytes());

        let out = run_on_terminal(
            &home,
            &["unlock", "--passphrase-fd", "3"],
            &[(3, &pass, true)],
        );
        assert!(out.status.success(), "{}{}", stderr(&out), d.log());
        let project = project(&home, "acme-web", MANIFEST);

        Self {
            cs,
            home,
            d,
            project,
            files,
            pass,
            wrong,
            username,
            password,
            totp_uri,
            adapter_key,
            codes,
        }
    }

    fn assert_no_codes(&self, haystack: &[u8], context: &str) {
        for c in &self.codes {
            assert_eq!(
                count_code_matches(haystack, c),
                0,
                "6/8-digit TOTP code found in {context}"
            );
        }
    }

    fn assert_clean_output(&self, out: &Output) {
        assert_no_canary(&out.stdout, &self.cs);
        assert_no_canary(&out.stderr, &self.cs);
        self.assert_no_codes(&out.stdout, "stdout");
        self.assert_no_codes(&out.stderr, "stderr");
    }

    fn sweep(&self) {
        let log = self.d.log_bytes();
        assert_no_canary(&log, &self.cs);
        self.assert_no_codes(&log, "daemon log");
        self.home.assert_clean(&self.cs);
    }
}

fn quoted(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[test]
fn login_add_show_ls_and_bounded_6_digit_code_search() {
    let f = LoginFixture::new();

    // Positive control for R-M2b-40 / gate b3: planting a 6-digit code in a
    // bounded output buffer is caught by `count_code_matches`, while longer
    // digit runs containing the same 6 digits are ignored.
    // RFC 6238 SHA-1 step 1 (T=59s) 6-digit code for "12345678901234567890" is 287082.
    let step1_code6 = &f.codes[2];
    let planted = b"error: code=287082 failed\n";
    assert_eq!(count_code_matches(planted, step1_code6), 1);
    let embedded = b"timestamp 92870820 ok\n";
    assert_eq!(count_code_matches(embedded, step1_code6), 0);

    // 1. Credential flags on argv and key-shaped slugs on argv are refused.
    for bad_args in [
        &["login", "add", "acme/editor", "--username", "alice"][..],
        &["login", "add", "acme/editor", "--password", "secret"],
        &[
            "login",
            "add",
            "acme/editor",
            "--totp",
            "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ",
        ],
        &["login", "add", "acme/editor", "--adapter-key", "secret"],
    ] {
        let out = run(&f.home, bad_args, &[]);
        f.assert_clean_output(&out);
        assert_eq!(out.status.code(), Some(2), "{bad_args:?}: {}", stderr(&out));
    }
    let key_slug = by_label(&f.cs, labels::OPENAI_API_KEY).as_str();
    let out = run(&f.home, &["login", "add", key_slug], &[]);
    f.assert_clean_output(&out);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).starts_with("envcloak: value_on_argv:"),
        "{}",
        stderr(&out)
    );

    // 2. Claimed environment (agent marker) refuses `login add` before reading descriptors.
    let mut cmd = on_terminal_command(
        &f.home,
        &[
            "login",
            "add",
            "acme/editor",
            "--username-fd",
            "3",
            "--password-fd",
            "4",
        ],
        &[(3, &f.username, true), (4, &f.password, true)],
    );
    cmd.env("ENVCLOAK_FIXTURE_AGENT", "1");
    let out = finish_within(cmd, Duration::from_secs(60));
    f.assert_clean_output(&out);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).starts_with("envcloak: proof_refused:"),
        "{}",
        stderr(&out)
    );

    // 3. `--live` with `--tier dev` is refused (`invalid_item` / `live_dev`).
    let out = run(
        &f.home,
        &[
            "login",
            "add",
            "acme/editor",
            "--live",
            "--tier",
            "dev",
            "--username-fd",
            "3",
            "--password-fd",
            "4",
        ],
        &[(3, &f.username, true), (4, &f.password, true)],
    );
    f.assert_clean_output(&out);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out)
            .starts_with("envcloak: invalid_item: live login items cannot use the dev tier"),
        "{}",
        stderr(&out)
    );

    // 4. Invalid `otpauth://` URI is refused without echoing any part of the URI.
    let bad_uri = secret_file(
        f.files.path(),
        "bad_uri",
        format!(
            "otpauth://hotp/Acme?secret={}&counter=1",
            by_label(&f.cs, "LOGIN_BASE32_SEED").as_str()
        )
        .as_bytes(),
    );
    let out = run(
        &f.home,
        &[
            "login",
            "add",
            "acme/editor",
            "--username-fd",
            "3",
            "--password-fd",
            "4",
            "--totp-fd",
            "5",
        ],
        &[
            (3, &f.username, true),
            (4, &f.password, true),
            (5, &bad_uri, true),
        ],
    );
    f.assert_clean_output(&out);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("not a valid otpauth://totp/ enrollment URI"),
        "{}",
        stderr(&out)
    );

    // 5. Enroll `acme/editor` with username, password, TOTP URI, and adapter key on descriptors.
    let out = run(
        &f.home,
        &[
            "login",
            "add",
            "acme/editor",
            "--test",
            "--tier",
            "dev",
            "--session-lifetime",
            "2h",
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
            (3, &f.username, true),
            (4, &f.password, true),
            (5, &f.totp_uri, true),
            (6, &f.adapter_key, true),
        ],
    );
    f.assert_clean_output(&out);
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    assert_eq!(
        stdout(&out),
        "Added login acme/editor.\n  kind: test key\n  tier: dev\n  session lifetime: 7200s\n  authorization revision: 1\n  fields: adapter_key, password, totp, username\n"
    );

    // 6. Enroll a second login via `/dev/tty` prompts (`drive`) with `--json`.
    let (tty_out, tty_code) = drive(
        &f.home,
        &[
            cli().to_str().unwrap(),
            "login",
            "add",
            "acme/billing",
            "--live",
            "--tier",
            "never-agent",
            "--json",
        ],
        &[
            (
                "Username (typing is hidden): ",
                &format!("{}\r", by_label(&f.cs, "LOGIN_USERNAME").as_str()),
            ),
            (
                "Password (typing is hidden): ",
                &format!("{}\r", by_label(&f.cs, "LOGIN_PASSWORD").as_str()),
            ),
            (
                "TOTP otpauth:// URI (optional, press Enter to skip): ",
                "\r",
            ),
        ],
    );
    assert_eq!(tty_code, 0, "{}{}", stdout(&tty_out), stderr(&tty_out));
    f.assert_clean_output(&tty_out);

    // 7. `envcloak show` and `envcloak ls --long` return metadata only.
    let show = run(&f.home, &["show", "acme/editor"], &[]);
    f.assert_clean_output(&show);
    assert!(show.status.success(), "{}", stderr(&show));
    let show_txt = stdout(&show);
    assert!(show_txt.starts_with("acme/editor\n"), "{show_txt}");
    assert!(show_txt.contains("  class: login\n"), "{show_txt}");
    assert!(show_txt.contains("  kind: test key\n"), "{show_txt}");
    assert!(show_txt.contains("  tier: dev\n"), "{show_txt}");
    assert!(
        show_txt.contains("  session lifetime: 7200s\n"),
        "{show_txt}"
    );
    assert!(
        show_txt.contains("  authorization revision: 1\n"),
        "{show_txt}"
    );
    assert!(show_txt.contains("    adapter_key: set "), "{show_txt}");
    assert!(show_txt.contains("    password: set "), "{show_txt}");
    assert!(show_txt.contains("    totp: set "), "{show_txt}");
    assert!(show_txt.contains("    username: set "), "{show_txt}");

    let show_json = run(&f.home, &["show", "acme/editor", "--json"], &[]);
    f.assert_clean_output(&show_json);
    assert!(show_json.status.success(), "{}", stderr(&show_json));
    let v: serde_json::Value = serde_json::from_slice(&show_json.stdout).unwrap();
    assert_eq!(v["slug"], "acme/editor");
    assert_eq!(v["class"], "login");
    assert_eq!(v["classification"], "test");
    assert_eq!(v["login"]["tier"], "dev");
    assert_eq!(v["login"]["session_lifetime_secs"], 7200);
    assert_eq!(v["login"]["authorization_revision"], 1);
    let field_names: Vec<&str> = v["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        field_names,
        vec!["adapter_key", "password", "totp", "username"]
    );

    let ls_long = run(&f.home, &["ls", "--long"], &[]);
    f.assert_clean_output(&ls_long);
    assert!(ls_long.status.success(), "{}", stderr(&ls_long));
    assert!(
        stdout(&ls_long).contains("acme/editor")
            && stdout(&ls_long).contains("adapter_key,password,totp,username"),
        "{}",
        stdout(&ls_long)
    );

    // 8. `envcloak audit verify` succeeds after `login add`.
    let audit = run(&f.home, &["audit", "verify"], &[]);
    f.assert_clean_output(&audit);
    assert!(audit.status.success(), "{}", stderr(&audit));
    f.sweep();
}

#[test]
fn login_rotate_requires_terminal_proof_and_bumps_revision() {
    let mut f = LoginFixture::new();

    // Enroll `acme/editor` first.
    let out = run(
        &f.home,
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
            "--adapter-key-fd",
            "6",
        ],
        &[
            (3, &f.username, true),
            (4, &f.password, true),
            (5, &f.totp_uri, true),
            (6, &f.adapter_key, true),
        ],
    );
    f.assert_clean_output(&out);
    assert!(out.status.success(), "{}", stderr(&out));

    let new_pw_str = format!("rotated-login-pw-{:016x}", fresh_seed());
    f.cs.push(Canary::new("ROTATED_PASSWORD", new_pw_str.clone()));
    let new_pw = secret_file(f.files.path(), "new_pw", new_pw_str.as_bytes());

    let new_user_str = format!("bob-rotated-{:016x}@example.test", fresh_seed());
    f.cs.push(Canary::new("ROTATED_USERNAME", new_user_str.clone()));
    let new_user = secret_file(f.files.path(), "new_user", new_user_str.as_bytes());

    let new_adapter_str = format!("rotated-adapter-{:016x}", fresh_seed());
    f.cs.push(Canary::new("ROTATED_ADAPTER", new_adapter_str.clone()));
    let new_adapter = secret_file(f.files.path(), "new_adapter", new_adapter_str.as_bytes());

    // 32-byte SHA256 seed in base32
    let new_base32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
    f.cs.push(Canary::new("ROTATED_BASE32_SEED", new_base32.to_owned()));
    let new_uri_str = format!(
        "otpauth://totp/Acme:bob%40example.test?secret={new_base32}&issuer=Acme&algorithm=SHA256&digits=8&period=30"
    );
    let new_uri = secret_file(f.files.path(), "new_uri", new_uri_str.as_bytes());

    // 1. Rotating a login item without naming a `#field` is refused with `ambiguous_field`.
    let out = run_on_terminal(
        &f.home,
        &["rotate", "acme/editor", "--stdin", "--passphrase-fd", "3"],
        &[(0, &new_pw, true), (3, &f.pass, true)],
    );
    f.assert_clean_output(&out);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).starts_with("envcloak: ambiguous_field:"),
        "{}",
        stderr(&out)
    );

    // 2. Rotating an unknown field `#api_key` on a login item is refused with `no_such_item` (`unknown_field`).
    let out = run_on_terminal(
        &f.home,
        &[
            "rotate",
            "acme/editor#api_key",
            "--stdin",
            "--passphrase-fd",
            "3",
        ],
        &[(0, &new_pw, true), (3, &f.pass, true)],
    );
    f.assert_clean_output(&out);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("the item has no field of that name"),
        "{}",
        stderr(&out)
    );

    // 3. Rotating from a detached session (no controlling terminal) is refused (`proof_refused`).
    let out = run(
        &f.home,
        &[
            "rotate",
            "acme/editor#password",
            "--stdin",
            "--passphrase-fd",
            "3",
        ],
        &[(0, &new_pw, true), (3, &f.pass, true)],
    );
    f.assert_clean_output(&out);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).starts_with("envcloak: proof_refused:"),
        "{}",
        stderr(&out)
    );

    // 4. Rotating from a claimed environment (`ENVCLOAK_FIXTURE_AGENT=1`) is refused.
    let mut cmd = on_terminal_command(
        &f.home,
        &[
            "rotate",
            "acme/editor#password",
            "--stdin",
            "--passphrase-fd",
            "3",
        ],
        &[(0, &new_pw, true), (3, &f.pass, true)],
    );
    cmd.env("ENVCLOAK_FIXTURE_AGENT", "1");
    let out = finish_within(cmd, Duration::from_secs(60));
    f.assert_clean_output(&out);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).starts_with("envcloak: proof_refused:"),
        "{}",
        stderr(&out)
    );

    // 5. Rotating from an agent process (`fixture-agent`) on a terminal is refused (`proof_refused`).
    let fixture_agent = testkit_bin("fixture-agent");
    let out = finish_within(
        on_terminal_program(
            &f.home,
            &[
                fixture_agent.as_path(),
                Path::new("--"),
                cli(),
                Path::new("rotate"),
                Path::new("acme/editor#password"),
                Path::new("--stdin"),
                Path::new("--passphrase-fd"),
                Path::new("3"),
            ],
            &[(0, &new_pw, true), (3, &f.pass, true)],
        ),
        Duration::from_secs(60),
    );
    f.assert_clean_output(&out);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).starts_with("envcloak: proof_refused:"),
        "{}",
        stderr(&out)
    );

    // 6. Rotating from a terminal that shares a session/terminal with a live pending
    // agent request is refused (T9-3 / F-70 boundary).
    {
        let dir = f.home.root().join("overlap");
        std::fs::create_dir_all(&dir).unwrap();
        let at = |name: &str| quoted(dir.join(name).to_str().unwrap());
        let cli_q = quoted(cli().to_str().unwrap());
        let agent_q = quoted(fixture_agent.to_str().unwrap());
        let script = format!(
            "set -u\n\
             mkfifo {fifo}\n\
             {agent} -- /bin/sh <{fifo} >/dev/null 2>&1 &\n\
             exec 4>{fifo}\n\
             echo \"cd {project}; {cli} run -- /bin/sh -c true 2>{run_err}; echo \\$? >{run_code}\" >&4\n\
             n=0; while [ ! -s {run_code} ] && [ $n -lt 200 ]; do sleep 0.05; n=$((n+1)); done\n\
             exec 0<{new_pw} 3<{pass}\n\
             {cli} rotate acme/editor#password --stdin --passphrase-fd 3 >{rot_out} 2>{rot_err}\n\
             echo $? >{rot_code}\n\
             exec 4>&-\n\
             wait\n",
            fifo = at("fifo"),
            agent = agent_q,
            project = quoted(f.project.to_str().unwrap()),
            cli = cli_q,
            run_err = at("run.err"),
            run_code = at("run.code"),
            new_pw = quoted(new_pw.to_str().unwrap()),
            pass = quoted(f.pass.to_str().unwrap()),
            rot_out = at("rot.out"),
            rot_err = at("rot.err"),
            rot_code = at("rot.code"),
        );
        let mut cmd = on_terminal_program(
            &f.home,
            &[Path::new("/bin/sh"), Path::new("-c"), Path::new(&script)],
            &[],
        );
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        let _ = finish_within(cmd, Duration::from_secs(60));
        let rot_err = std::fs::read_to_string(dir.join("rot.err")).unwrap();
        let rot_code = std::fs::read_to_string(dir.join("rot.code")).unwrap();
        assert_eq!(rot_code.trim(), "1", "{rot_err}");
        assert!(rot_err.starts_with("envcloak: proof_refused:"), "{rot_err}");
        // Deny the pending request so the rest of the test has no live pending request.
        let run_err = std::fs::read_to_string(dir.join("run.err")).unwrap();
        if let Some(id) = run_err
            .lines()
            .find_map(|l| l.split("request=").nth(1))
            .and_then(|s| s.split_whitespace().next())
        {
            let _ = run(&f.home, &["deny", id], &[]);
        }
    }

    // 7. Wrong passphrase is refused (`wrong_passphrase`), audited, and leaves revision at 1.
    let out = run_on_terminal(
        &f.home,
        &[
            "rotate",
            "acme/editor#password",
            "--stdin",
            "--passphrase-fd",
            "3",
        ],
        &[(0, &new_pw, true), (3, &f.wrong, true)],
    );
    f.assert_clean_output(&out);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("envcloak: wrong_passphrase:"),
        "{}",
        stderr(&out)
    );

    // 8. Invalid `#totp` URI on rotation is refused before touching the vault.
    let bad_uri = secret_file(f.files.path(), "bad_rot_uri", b"not-an-otpauth-uri");
    let out = run_on_terminal(
        &f.home,
        &[
            "rotate",
            "acme/editor#totp",
            "--stdin",
            "--passphrase-fd",
            "3",
        ],
        &[(0, &bad_uri, true), (3, &f.pass, true)],
    );
    f.assert_clean_output(&out);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("the TOTP URI is not a valid otpauth://totp/... URI"),
        "{}",
        stderr(&out)
    );

    // Revision is still 1 after all refused attempts.
    let show_json = run(&f.home, &["show", "acme/editor", "--json"], &[]);
    let v: serde_json::Value = serde_json::from_slice(&show_json.stdout).unwrap();
    assert_eq!(v["login"]["authorization_revision"], 1);

    // 9. Rotate `#password`, `#username`, `#totp`, and `#adapter_key` from a terminal with proof.
    for (field, file, expected_rev) in [
        ("password", &new_pw, 2u64),
        ("username", &new_user, 3u64),
        ("totp", &new_uri, 4u64),
        ("adapter_key", &new_adapter, 5u64),
    ] {
        let target = format!("acme/editor#{field}");
        let out = run_on_terminal(
            &f.home,
            &["rotate", &target, "--stdin", "--passphrase-fd", "3"],
            &[(0, file, true), (3, &f.pass, true)],
        );
        f.assert_clean_output(&out);
        assert!(
            out.status.success(),
            "rotate {target}: {}{}",
            stdout(&out),
            stderr(&out)
        );
        assert!(
            stdout(&out).contains(&format!("Rotated acme/editor#{field}")),
            "{}",
            stdout(&out)
        );

        let show_json = run(&f.home, &["show", "acme/editor", "--json"], &[]);
        f.assert_clean_output(&show_json);
        let v: serde_json::Value = serde_json::from_slice(&show_json.stdout).unwrap();
        assert_eq!(
            v["login"]["authorization_revision"], expected_rev,
            "after rotating {field}"
        );
    }

    // 10. Verify audit log chain is valid.
    let audit = run(&f.home, &["audit", "verify"], &[]);
    f.assert_clean_output(&audit);
    assert!(audit.status.success(), "{}", stderr(&audit));

    // 11. Stop the daemon, unlock the vault directly, and verify the audit records,
    // rotated metadata, and authorization revision.
    f.d.signal("-TERM");
    assert!(f.d.wait_exit(Duration::from_secs(30)).is_some());
    let pass_bytes = SecretBytes::copy_from(by_label(&f.cs, labels::VAULT_PASSPHRASE).value());
    let v = LockedVault::open(&VaultPaths::under(data_dir(&f.home)))
        .unwrap()
        .unlock_with_passphrase(&pass_bytes)
        .map_err(|(_, e)| e)
        .unwrap();
    let (entries, _) = v.read_audit().unwrap();
    let kinds: Vec<AuditKind> = entries.iter().map(|e| e.record.kind).collect();
    assert!(kinds.contains(&AuditKind::LoginAdd), "{kinds:?}");
    let proof_failed_count = entries
        .iter()
        .filter(|e| {
            e.record.kind == AuditKind::LoginReplace
                && e.record.decision.outcome == "failed"
                && e.record.decision.reason.as_deref() == Some("wrong_passphrase")
        })
        .count();
    assert_eq!(proof_failed_count, 1, "{entries:?}");
    let replaced_count = entries
        .iter()
        .filter(|e| {
            e.record.kind == AuditKind::LoginReplace && e.record.decision.outcome == "replaced"
        })
        .count();
    assert_eq!(replaced_count, 4, "{entries:?}");

    let meta = v.find(&Slug::new("acme/editor").unwrap()).unwrap();
    assert_eq!(meta.class, ItemClass::Login);
    assert_eq!(meta.details.classification, Classification::Test);
    assert_eq!(meta.login.unwrap().tier, LoginTier::Dev);
    assert_eq!(v.login_revision(meta.id), Some(5));
    assert!(meta.updated_at >= meta.created_at);
    assert_eq!(meta.fields.len(), 4);
    drop(v);
    f.sweep();
}

#[test]
fn typed_field_isolation_across_check_scan_and_mark_exposed() {
    let f = LoginFixture::new();

    // Enroll `acme/editor` through `envcloak login add`.
    let out = run(
        &f.home,
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
            "--adapter-key-fd",
            "6",
        ],
        &[
            (3, &f.username, true),
            (4, &f.password, true),
            (5, &f.totp_uri, true),
            (6, &f.adapter_key, true),
        ],
    );
    f.assert_clean_output(&out);
    assert!(out.status.success(), "{}", stderr(&out));

    // 1. `envcloak check` on a manifest binding a login field fails and reports `login`.
    let bad_proj = project(
        &f.home,
        "bad-login-proj",
        "[project]\nname = \"bad\"\n\n[env]\nEDITOR_PW = \"acme/editor#password\"\n",
    );
    let mut cmd = cli_command(&f.home, &["check"], &[]);
    cmd.current_dir(&bad_proj);
    let check_out = finish_within(cmd, Duration::from_secs(60));
    f.assert_clean_output(&check_out);
    assert_eq!(check_out.status.code(), Some(1), "{}", stdout(&check_out));
    assert!(
        stdout(&check_out)
            .contains("a login's field is never bound to a variable: only a sign-in opens it"),
        "{}",
        stdout(&check_out)
    );

    // 2. `scan.match` and `items.mark_exposed` ignore login items and never match login values.
    let run_paths = RunPaths::under(daemon_run_dir(&f.home)).unwrap();
    let mut client = Client::connect(&run_paths).unwrap();
    let pw_bytes = SecretBytes::copy_from(by_label(&f.cs, "LOGIN_PASSWORD").value());
    let openai_bytes = SecretBytes::copy_from(by_label(&f.cs, labels::OPENAI_API_KEY).value());
    let matches = client
        .scan_match(&ScanMatchParams {
            candidates: vec![
                ScanCandidate {
                    id: 1,
                    value: WireSecret::from(pw_bytes),
                    form: CandidateForm::Raw,
                },
                ScanCandidate {
                    id: 2,
                    value: WireSecret::from(openai_bytes),
                    form: CandidateForm::Raw,
                },
            ],
            source_kind: ScanSource::EnvFile,
            purpose: ScanPurpose::Doctor,
            claims: Vec::new(),
        })
        .unwrap();
    assert_eq!(matches.matches.len(), 1);
    assert_eq!(matches.matches[0].id, 2);
    assert_eq!(matches.matches[0].slug, "openai/acme-web");

    let editor_show = client.items_show("acme/editor").unwrap();
    let marked = client
        .items_mark_exposed(&MarkExposedParams {
            items: vec![ExposedItem {
                item: editor_show.id.clone(),
                sources: vec![ExposureSourceView::EnvFile],
                count: 1,
            }],
            claims: Vec::new(),
        })
        .unwrap();
    assert_eq!(marked.marked, 0);
    assert_eq!(marked.missing, 1);
    let after = client.items_show("acme/editor").unwrap();
    assert!(after.exposed.is_none());

    f.sweep();
}
