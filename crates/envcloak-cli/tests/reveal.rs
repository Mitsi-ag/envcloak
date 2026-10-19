//! Gates 34, 23, 33 and 19: terminal reveal (M2-21).
#![allow(clippy::unwrap_used)]

mod common;

use std::os::unix::fs::PermissionsExt;

use envcloak_testkit::{TestHome, assert_no_canary, canaries, fresh_seed};

/// Observe connection attempts independently of the client. A real
/// `status` attempt is the positive control, even with no valid daemon.
#[test]
fn reveal_without_a_terminal_never_contacts_the_daemon() {
    let home = TestHome::new();
    let dir = envcloak_testkit::daemon_run_dir(&home);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let listener =
        std::os::unix::net::UnixListener::bind(envcloak_testkit::daemon_socket(&home)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let (snapshots, commands) =
        std::sync::mpsc::channel::<Option<std::sync::mpsc::Sender<usize>>>();
    let observer = std::thread::spawn(move || {
        let mut count = 0;
        loop {
            let command = commands.recv_timeout(std::time::Duration::from_millis(10));
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        count += 1;
                        drop(stream);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => panic!("connection observer failed: {e}"),
                }
            }
            match command {
                Ok(Some(reply)) => reply.send(count).unwrap(),
                Ok(None) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
    });
    let snapshot = || {
        let (reply, count) = std::sync::mpsc::channel();
        snapshots.send(Some(reply)).unwrap();
        count
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap()
    };
    let out = common::run(&home, &["reveal", "example/item"], &[]);
    // Snapshot commands drain completed connections before replying. The
    // assertion therefore does not depend on the observer thread's scheduling.
    let reveal_connections = snapshot();
    let control = common::run(&home, &["status"], &[]);
    let control_connections = snapshot();
    snapshots.send(None).unwrap();
    observer.join().unwrap();
    assert_eq!(reveal_connections, 0);
    assert_eq!(control_connections, 1);
    assert!(!control.status.success());
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    let token = if cfg!(target_os = "macos") {
        "app_required"
    } else {
        "no_terminal"
    };
    assert!(common::stderr(&out).starts_with(&format!("envcloak: {token}:")));
    if cfg!(target_os = "macos") {
        assert_eq!(out.status.code(), Some(125));
    }
}

#[test]
fn reveal_arguments_never_echo_hostile_input() {
    let home = TestHome::new();
    let cs = canaries(fresh_seed());
    let long = "x".repeat(100_000);
    for target in ["", "a#", "a#b#c", "a\u{1b}[31m", "a\u{202e}", long.as_str()]
        .into_iter()
        .chain(cs.iter().map(|c| c.as_str()))
    {
        let out = common::run(&home, &["reveal", target], &[]);
        assert!(!out.status.success());
        assert!(out.stdout.is_empty());
        assert_no_canary(&out.stderr, &cs);
        assert!(out.stderr.len() < 1024);
    }
    use std::os::unix::ffi::OsStrExt;
    let mut bad = common::cli_command(&home, &["reveal"], &[]);
    bad.arg(std::ffi::OsStr::from_bytes(b"\xff\xfe"));
    let out = common::finish_within(bad, std::time::Duration::from_secs(30));
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    for extra in ["--stdout", "--json", "--passphrase-fd", "--stdin"] {
        let out = common::run(&home, &["reveal", "example/item", extra], &[]);
        assert!(!out.status.success());
        assert!(out.stdout.is_empty());
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use envcloak_testkit::{Canary, Daemon, by_label, labels, testkit_bin};
    use std::process::{Command, Stdio};
    use std::time::Duration;

    struct Fixture {
        home: TestHome,
        cs: Vec<Canary>,
        d: Daemon,
        files: tempfile::TempDir,
    }
    impl Fixture {
        fn new() -> Self {
            Self::with_value(None)
        }
        fn with_value(value: Option<String>) -> Self {
            Self::configured(value, false)
        }
        fn configured(value: Option<String>, pause: bool) -> Self {
            let home = TestHome::new();
            let mut cs = canaries(fresh_seed());
            if let Some(value) = value {
                let index = cs
                    .iter()
                    .position(|c| c.label == labels::OPENAI_API_KEY)
                    .unwrap();
                cs[index] = Canary::new(labels::OPENAI_API_KEY, value);
            }
            cs.push(common::seed_vault(&home, &cs));
            let dir = common::data_dir(&home).join("agents.d");
            std::fs::create_dir(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            let path = dir.join("test.toml");
            std::fs::write(&path, "[[agent]]\nid = \"extension-agent\"\nname = \"Extension agent\"\nexecutables = [\"extension-agent\"]\nmarkers = [\"EXTENSION_AGENT\"]\n").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let files = common::outside_dir();
            let mut daemon = Command::new(common::daemon_exe());
            home.apply(&mut daemon);
            if pause {
                daemon
                    .env(envcloak_sys::testing::PAUSE_SITE, "reveal.proof.verifying")
                    .env(
                        envcloak_sys::testing::PAUSE_RELEASE,
                        files.path().join("release"),
                    );
            }
            let d = Daemon::start_command(daemon, &[]);
            let pass = common::secret_file(
                files.path(),
                "pass",
                by_label(&cs, labels::VAULT_PASSPHRASE).value(),
            );
            let out = common::run_on_terminal(
                &home,
                &["unlock", "--passphrase-fd", "3"],
                &[(3, &pass, true)],
            );
            assert!(out.status.success(), "fixture unlock failed");
            Self { home, cs, d, files }
        }
        fn human(
            &self,
            prefix: &[&str],
            env: &[(&str, &str)],
            extra: serde_json::Value,
        ) -> serde_json::Value {
            let hex = |b: &[u8]| b.iter().map(|b| format!("{b:02x}")).collect::<String>();
            let mut spec = serde_json::json!({
                "value": hex(by_label(&self.cs, labels::OPENAI_API_KEY).value()),
                "proof": hex(by_label(&self.cs, labels::VAULT_PASSPHRASE).value()),
            });
            spec.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            if extra["wrong_proof"] == true {
                spec["proof"] = hex(b"deliberately wrong proof").into();
            }
            let during_proof = extra.get("ancestor_name").is_some();
            let reached = self.files.path().join("reached");
            if during_proof {
                spec["proof_reached"] = serde_json::json!(reached);
                spec["proof_release"] = serde_json::json!(self.files.path().join("release"));
            }
            let path = self.files.path().join("terminal.json");
            std::fs::write(&path, serde_json::to_vec(&spec).unwrap()).unwrap();
            let mut cmd = Command::new(common::python3());
            self.home
                .apply(&mut cmd)
                .envs(env.iter().copied())
                .arg(
                    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("tests/fixtures/reveal_terminal.py"),
                )
                .arg(&path)
                .args(prefix)
                .arg(common::cli())
                .args(["reveal", common::SLUGS[0]])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let out = std::thread::scope(|scope| {
                if during_proof {
                    scope.spawn(|| {
                        let log = self.d.log_when(Duration::from_secs(20), |s| {
                            s.contains("envcloak test: paused at reveal.proof.verifying")
                        });
                        assert!(log.contains("envcloak test: paused at reveal.proof.verifying"));
                        std::fs::write(&reached, b"reached").unwrap();
                    });
                }
                common::finish_within(cmd, Duration::from_secs(60))
            });
            assert!(
                out.status.success(),
                "PTY observer failed: {}",
                common::stderr(&out)
            );
            let observed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
            assert_eq!(observed["control_hits"], 1);
            for counter in [
                "stdout_bytes",
                "stdout_leak_hits",
                "stderr_leak_hits",
                "proof_leak_hits",
            ] {
                assert_eq!(observed[counter], 0, "{counter}");
            }
            assert_eq!(observed["stdout_hits"], 0);
            assert_eq!(observed["stderr_hits"], 0);
            assert_eq!(observed["proof_hits"], 0);
            assert_eq!(observed["restored"], true);
            assert_no_canary(&self.d.log_bytes(), &self.cs);
            self.home.assert_clean(&self.cs);
            observed
        }
    }

    #[test]
    fn gate34_reveal_only_on_tty_after_proof_and_until_enter() {
        let f = Fixture::new();
        let o = f.human(&[], &[], serde_json::json!({}));
        assert_eq!(o["code"], 0);
        assert_eq!(o["tty_hits"], 1);
        for flag in ["warning", "prompt", "ack", "waited", "echo_off"] {
            assert_eq!(o[flag], true, "{flag}");
        }
        let offsets =
            ["warning_at", "prompt_at", "value_at", "ack_at"].map(|key| o[key].as_i64().unwrap());
        assert!(offsets[0] >= 0);
        assert!(offsets.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn gate34_hostile_values_never_reach_the_terminal() {
        for controls in [
            "\u{1b}]52;c;Zml4dHVyZQ==\u{7}\u{1b}[2J\u{1b}[6n".to_owned(),
            (1u8..=31).map(char::from).collect(),
            (127u8..=159).map(char::from).collect(),
        ] {
            let cs = canaries(fresh_seed());
            let value = format!(
                "prefix{}{}suffix",
                by_label(&cs, labels::OPENAI_API_KEY).as_str(),
                controls
            );
            let f = Fixture::with_value(Some(value));
            let o = f.human(&[], &[], serde_json::json!({}));
            assert!(o["control_terminal_controls"].as_u64().unwrap() > 0);
            assert_eq!(o["tty_controls"], 0);
            assert_eq!(o["tty_hits"], 0);
            assert_eq!(o["invalid_value"], true);
            assert_eq!(o["ack"], false);
            assert_ne!(o["code"], 0);
        }
        let f = Fixture::with_value(Some("printable é 日本語 😀".into()));
        let o = f.human(&[], &[], serde_json::json!({}));
        assert_eq!(o["code"], 0);
        assert_eq!(o["tty_hits"], 1);
        assert_eq!(o["tty_controls"], 0);
    }

    #[test]
    fn gate23_builtin_asserted_and_extension_agents_never_see_a_prompt() {
        let f = Fixture::new();
        let builtin = testkit_bin("fixture-agent");
        let extension = f.files.path().join("extension-agent");
        std::fs::copy(&builtin, &extension).unwrap();
        for path in [&builtin, &extension] {
            let o = f.human(&[path.to_str().unwrap(), "--"], &[], serde_json::json!({}));
            assert_eq!(o["refused"], true);
            assert_eq!(o["prompt"], false);
            assert_eq!(o["tty_hits"], 0);
        }
        for marker in ["CLAUDECODE", "EXTENSION_AGENT"] {
            let o = f.human(&[], &[(marker, "1")], serde_json::json!({}));
            assert_eq!(o["refused"], true);
            assert_eq!(o["prompt"], false);
            assert_eq!(o["tty_hits"], 0);
        }
    }

    #[test]
    fn gate23_requesters_terminal_refused_for_builtin_and_extension() {
        let f = Fixture::new();
        let project = common::project(&f.home, "reveal", common::MANIFEST);
        let builtin = testkit_bin("fixture-agent");
        let extension = f.files.path().join("extension-agent");
        std::fs::copy(&builtin, &extension).unwrap();
        for (agent, through) in [
            (&builtin, None),
            (&extension, Some(testkit_bin("ec-probe"))),
        ] {
            let o = f.human(
                &[],
                &[],
                serde_json::json!({
                    "sibling": agent,
                    "through": through,
                    "manifest": project.join("envcloak.toml"),
                }),
            );
            assert_eq!(o["refused"], true);
            assert_eq!(o["prompt"], false);
            assert_eq!(o["tty_hits"], 0);
            assert!(f.d.log().contains("requester_terminal"));
        }
        // A separate terminal still works, with the same pending history.
        let o = f.human(&[], &[], serde_json::json!({}));
        assert_eq!(o["code"], 0);
        assert_eq!(o["tty_hits"], 1);
    }

    #[test]
    fn gate23_reveal_refuses_requester_before_proof_verification() {
        let f = Fixture::new();
        let project = common::project(&f.home, "late-reveal", common::MANIFEST);
        let o = f.human(
            &[],
            &[],
            serde_json::json!({
                "sibling": testkit_bin("fixture-agent"),
                "manifest": project.join("envcloak.toml"),
                "late": true,
                "wrong_proof": true,
            }),
        );
        assert_eq!(o["prompt"], true, "the preflight must have succeeded");
        assert_eq!(o["refused"], true);
        assert_eq!(o["tty_hits"], 0);
        assert_ne!(o["code"], 0);
        assert!(
            f.d.log()
                .contains("method=items.reveal reason=requester_terminal")
        );
    }

    #[test]
    fn gate23_reveal_revalidates_ancestry_during_proof() {
        for name in ["fixture-agent", "extension-agent"] {
            let f = Fixture::configured(None, true);
            let o = f.human(&[], &[], serde_json::json!({"ancestor_name": name}));
            assert_eq!(o["proof_barrier"], true);
            assert_eq!(o["ancestor_changed"], true);
            assert_eq!(o["prompt"], true);
            assert_eq!(o["refused"], true);
            assert_eq!(o["tty_hits"], 0);
            assert_eq!(o["ack"], false);
            assert_ne!(o["code"], 0);
            assert!(f.d.log().contains("method=items.reveal reason=agent"));
            let control = f.human(&[], &[], serde_json::json!({}));
            assert_eq!(control["code"], 0);
            assert_eq!(control["tty_hits"], 1);
        }
    }

    #[test]
    fn gate33_audit_failure_never_reaches_the_terminal() {
        let f = Fixture::new();
        let audit = common::data_dir(&f.home).join("audit");
        std::fs::remove_dir_all(&audit).unwrap();
        std::fs::write(audit, b"blocked").unwrap();
        let o = f.human(&[], &[], serde_json::json!({}));
        assert_eq!(o["audit_failed"], true);
        assert_eq!(o["tty_hits"], 0);
        assert_ne!(o["code"], 0);
    }

    #[test]
    fn reveal_interruptions_restore_the_terminal() {
        let f = Fixture::new();
        for phase in ["proof", "ack"] {
            let o = f.human(&[], &[], serde_json::json!({"interrupt": phase}));
            assert_eq!(o["interrupted"], true);
            assert_eq!(o["code"], -15);
            assert_eq!(o["tty_hits"], if phase == "proof" { 0 } else { 1 });
        }
    }

    #[test]
    fn gate19_traced_reveal_refuses_before_contact() {
        let home = TestHome::new();
        let mut cmd = Command::new(common::cli());
        home.apply(&mut cmd)
            .args(["reveal", "example/item"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = envcloak_sys::testing::spawn_traced(&mut cmd).unwrap();
        let out = child.wait_with_output().unwrap();
        assert_eq!(out.status.code(), Some(125));
        assert!(common::stderr(&out).starts_with("envcloak: traced:"));
        assert!(out.stdout.is_empty());
        let control = common::run(&home, &["reveal", "example/item"], &[]);
        assert!(common::stderr(&control).starts_with("envcloak: no_terminal:"));
    }
}

#[test]
fn gate34_mcp_neither_lists_nor_dispatches_reveal() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let home = TestHome::new();
    let mut cmd = Command::new(common::cli());
    home.apply(&mut cmd)
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    let mut input = child.stdin.take().unwrap();
    for message in [
        serde_json::json!({"jsonrpc":"2.0", "id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}),
        serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
        serde_json::json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"reveal","arguments":{"slug":"example/item"}}}),
    ] {
        writeln!(input, "{message}").unwrap();
    }
    drop(input);
    let out = child.wait_with_output().unwrap();
    let responses: Vec<serde_json::Value> = out
        .stdout
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_slice(l).unwrap())
        .collect();
    let listed = responses.iter().find(|r| r["id"] == 2).unwrap();
    let tools = listed["result"]["tools"].as_array().unwrap();
    assert!(tools.iter().any(|t| t["name"] == "run_with_secrets"));
    assert!(
        !tools
            .iter()
            .any(|t| t["name"].as_str().unwrap().contains("reveal"))
    );
    let called = responses.iter().find(|r| r["id"] == 3).unwrap();
    assert_eq!(called["error"]["code"], -32602);
    assert_eq!(
        called["error"]["message"],
        "unknown tool: tools/list shows the tools"
    );
    assert!(called.get("result").is_none());
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::path::Path;
    use std::process::Command;
    use std::time::{Duration, Instant};

    use envcloak_core::SecretBytes;
    use envcloak_core::crypto::{
        P256_PUBLIC_KEY_LEN, SeEnrolledUnder, SeEphemeralKey, SeUnlockerRecord, UnlockerId,
        derive_p256_keypair, se_reseal_aad, seal_secret_to_x25519, secret_sha256,
        sign_p256_prehash,
    };
    use envcloak_core::vault::{LockedVault, VaultPaths};
    use envcloak_ipc::app::{AppPasteParams, AppRevealBeginParams, AppRevealParams};
    use envcloak_ipc::{Client, RunPaths};
    use envcloak_policy::{SubjectKind, reveal_statement_digest};
    use envcloak_sys::pasteboard::{
        TEST_PASTEBOARD_ENV, TEST_PASTEBOARD_WRITE_BETWEEN_ENV, TestPasteboard,
    };
    use envcloak_testkit::{Canary, Daemon, by_label, daemon_run_dir, labels, testkit_bin};

    const TEST_TEAM_ID: &str = "AB12CD34EF";
    const TEST_SIGNING_ID: &str = "ai.envcloak.app";

    fn this_process_app_id() -> String {
        format!("{}:{TEST_TEAM_ID}:{TEST_SIGNING_ID}", std::process::id())
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn decode_hex<const N: usize>(s: &str) -> [u8; N] {
        assert_eq!(s.len(), 2 * N, "unexpected hex length: {}", s.len());
        let mut out = [0u8; N];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    fn decode_hex_vec(s: &str) -> Vec<u8> {
        assert_eq!(s.len() % 2, 0);
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn sample_se_keypairs(
        seed_byte: u8,
    ) -> (
        [u8; 32],
        [u8; P256_PUBLIC_KEY_LEN],
        [u8; 32],
        [u8; P256_PUBLIC_KEY_LEN],
    ) {
        let (unlock_sk, unlock_pub) = derive_p256_keypair(&[seed_byte; 32]);
        let (approve_sk, approve_pub) = derive_p256_keypair(&[seed_byte.wrapping_add(1); 32]);
        (unlock_sk, unlock_pub, approve_sk, approve_pub)
    }

    fn stripe_key(kind: &str) -> String {
        let seed = fresh_seed();
        let tail: String = (0..32u32)
            .map(|i| {
                let n =
                    u8::try_from((seed.rotate_left(7 * i) ^ (u64::from(i) * 0x9e37)) % 36).unwrap();
                char::from(if n < 10 { b'0' + n } else { b'a' + n - 10 })
            })
            .collect();
        format!("{}_{kind}_{tail}", concat!("s", "k"))
    }

    fn connect_client(home: &TestHome) -> Client {
        let paths = RunPaths::under(daemon_run_dir(home)).unwrap();
        Client::connect(&paths).unwrap()
    }

    fn start_daemon_with_app(
        home: &TestHome,
        app_id: Option<&str>,
        clock_file: Option<&Path>,
    ) -> Daemon {
        let mut cmd = Command::new(common::daemon_exe());
        home.apply(&mut cmd);
        if let Some(id) = app_id {
            cmd.env(envcloak_sys::testing::APP_IDENTITY, id);
        }
        if let Some(cf) = clock_file {
            cmd.env(envcloak_sys::testing::CLOCK_FILE, cf);
        }
        Daemon::start_command(cmd, &[])
    }

    fn agent_command(home: &TestHome, args: &[&str]) -> Command {
        let agent = testkit_bin("fixture-agent");
        let mut argv: Vec<&Path> = vec![agent.as_path(), Path::new("--"), common::cli()];
        argv.extend(args.iter().map(Path::new));
        common::on_terminal_program(home, &argv, &[])
    }

    #[test]
    fn m3_19_add_ask_answered_prints_only_slug_creates_no_grant_and_declined_expired() {
        let mut cs = canaries(fresh_seed());
        let home = TestHome::new();
        cs.push(common::seed_vault(&home, &cs));
        let clock_file = home.root().join("clock-offset");
        std::fs::write(&clock_file, "0").unwrap();

        let app_id = this_process_app_id();
        let mut d = start_daemon_with_app(&home, Some(&app_id), Some(&clock_file));
        let files = common::outside_dir();
        let pass = common::secret_file(
            files.path(),
            "pass",
            by_label(&cs, labels::VAULT_PASSPHRASE).value(),
        );
        let unlocked = common::run_on_terminal(
            &home,
            &["unlock", "--passphrase-fd", "3"],
            &[(3, &pass, true)],
        );
        assert!(unlocked.status.success(), "{}", common::stderr(&unlocked));

        let pasted_key = stripe_key("test");
        cs.push(Canary::new("PASTED_STRIPE_ASK", pasted_key.clone()));
        let pasted_secret = SecretBytes::copy_from(pasted_key.as_bytes());

        // 1. Answered path: `fixture-agent` runs `envcloak add stripe ... --ask --wait 30s`;
        //    the app responder sees the agent's evidence in `app.asks.list` and
        //    answers via `app.paste.begin` -> `app.paste.inspect` -> `app.paste`.
        let ask_cmd = agent_command(
            &home,
            &[
                "add",
                "stripe",
                "--account",
                "billing",
                "--env",
                "STRIPE_SECRET_KEY",
                "--note",
                "Need Stripe test key",
                "--ask",
                "--wait",
                "30s",
            ],
        );
        let out_added = std::thread::scope(|scope| {
            scope.spawn(|| {
                let deadline = Instant::now() + Duration::from_secs(15);
                let ask = loop {
                    let listed = connect_client(&home).app_asks_list(&[]).unwrap();
                    if let Some(a) = listed.asks.into_iter().next() {
                        break a;
                    }
                    assert!(Instant::now() < deadline, "timed out waiting for ask");
                    std::thread::sleep(Duration::from_millis(50));
                };
                assert_eq!(ask.requester.kind, SubjectKind::Agent);
                assert_eq!(
                    ask.requester.label.as_deref(),
                    Some("EnvCloak test fixture agent")
                );
                assert_eq!(ask.provider.as_deref(), Some("stripe"));
                assert_eq!(ask.account.as_deref(), Some("billing"));
                assert_eq!(ask.env_hint.as_deref(), Some("STRIPE_SECRET_KEY"));
                assert_eq!(ask.note.as_deref(), Some("Need Stripe test key"));

                let mut c = connect_client(&home);
                let stage = c.app_paste_begin(&[]).unwrap();
                let sealed = seal_secret_to_x25519(
                    &decode_hex(&stage.daemon_eph_pub),
                    stage.stage.as_bytes(),
                    &pasted_secret,
                )
                .unwrap();
                c.app_paste_inspect(&stage.stage, &hex_encode(&sealed), &[])
                    .unwrap();
                let res = c
                    .app_paste(&AppPasteParams {
                        stage: stage.stage,
                        slug: Some("stripe/billing-ask".to_owned()),
                        provider: Some("stripe".to_owned()),
                        field: None,
                        account: Some("billing".to_owned()),
                        env_hint: Some("STRIPE_SECRET_KEY".to_owned()),
                        allow_short: false,
                        ask: Some(ask.ask),
                        claims: Vec::new(),
                    })
                    .unwrap();
                assert_eq!(res.item.slug, "stripe/billing-ask");
                assert!(
                    c.grants_list().unwrap().grants.is_empty(),
                    "add --ask must never create a grant while requester is alive"
                );
            });
            common::finish_within(ask_cmd, Duration::from_secs(30))
        });

        assert_eq!(
            out_added.status.code(),
            Some(0),
            "stderr: {}",
            common::stderr(&out_added)
        );
        // Mutation Check 1: stdout is exclusively `<slug>\n` (no length, prefix,
        // classification or value).
        assert_eq!(
            common::stdout(&out_added),
            "stripe/billing-ask\n",
            "add --ask must print only the new slug"
        );
        assert!(
            out_added.stderr.is_empty(),
            "unexpected stderr: {}",
            common::stderr(&out_added)
        );
        assert_no_canary(&out_added.stdout, &cs);
        assert_no_canary(&out_added.stderr, &cs);

        // Mutation Check 2: answering `add --ask` creates NO grant for the
        // asking agent (or any other caller), and a subsequent `envcloak run`
        // by the agent for that item still requires approval.
        assert!(
            connect_client(&home)
                .grants_list()
                .unwrap()
                .grants
                .is_empty(),
            "add --ask must never create a grant"
        );
        let proj = common::project(
            &home,
            "ask-proj",
            "[project]\nname = \"ask-proj\"\n\n[env]\nSTRIPE_SECRET_KEY = \"stripe/billing-ask\"\n",
        );
        let manifest_path = proj.join("envcloak.toml");
        let run_after_ask = common::finish_within(
            agent_command(
                &home,
                &[
                    "run",
                    "--manifest",
                    manifest_path.to_str().unwrap(),
                    "--",
                    "/usr/bin/true",
                ],
            ),
            Duration::from_secs(30),
        );
        assert_eq!(run_after_ask.status.code(), Some(125));
        assert!(
            common::stderr(&run_after_ask).starts_with("envcloak: approval_required:"),
            "unexpected stderr: {}",
            common::stderr(&run_after_ask)
        );

        // 2. Declined path: `app.asks.decline` -> exits 125 with `declined`.
        let dec_cmd = agent_command(&home, &["add", "openai", "--ask", "--wait", "30s"]);
        let out_declined = std::thread::scope(|scope| {
            scope.spawn(|| {
                let deadline = Instant::now() + Duration::from_secs(15);
                let ask = loop {
                    let listed = connect_client(&home).app_asks_list(&[]).unwrap();
                    if let Some(a) = listed.asks.into_iter().next() {
                        break a;
                    }
                    assert!(Instant::now() < deadline, "timed out waiting for ask");
                    std::thread::sleep(Duration::from_millis(50));
                };
                connect_client(&home)
                    .app_asks_decline(&ask.ask, &[])
                    .unwrap();
            });
            common::finish_within(dec_cmd, Duration::from_secs(30))
        });
        assert_eq!(out_declined.status.code(), Some(125));
        assert!(out_declined.stdout.is_empty());
        assert!(
            common::stderr(&out_declined).starts_with("envcloak: declined:"),
            "stderr: {}",
            common::stderr(&out_declined)
        );

        // 3. Expired path: advance clock past 600s -> exits 125 with `expired`.
        let exp_cmd = agent_command(&home, &["add", "openai", "--ask", "--wait", "30s"]);
        let out_expired = std::thread::scope(|scope| {
            scope.spawn(|| {
                let deadline = Instant::now() + Duration::from_secs(15);
                loop {
                    let listed = connect_client(&home).app_asks_list(&[]).unwrap();
                    if !listed.asks.is_empty() {
                        break;
                    }
                    assert!(Instant::now() < deadline, "timed out waiting for ask");
                    std::thread::sleep(Duration::from_millis(50));
                }
                std::fs::write(&clock_file, "650").unwrap();
            });
            common::finish_within(exp_cmd, Duration::from_secs(30))
        });
        assert_eq!(out_expired.status.code(), Some(125));
        assert!(out_expired.stdout.is_empty());
        assert!(
            common::stderr(&out_expired).starts_with("envcloak: expired:"),
            "stderr: {}",
            common::stderr(&out_expired)
        );

        // 4. Vault locked while polling -> re-issues `items.ask` and reports
        //    `vault_locked` instead of `expired`.
        let lock_cmd = agent_command(&home, &["add", "openai", "--ask", "--wait", "30s"]);
        let out_locked = std::thread::scope(|scope| {
            scope.spawn(|| {
                let deadline = Instant::now() + Duration::from_secs(15);
                loop {
                    let listed = connect_client(&home).app_asks_list(&[]).unwrap();
                    if !listed.asks.is_empty() {
                        break;
                    }
                    assert!(Instant::now() < deadline, "timed out waiting for ask");
                    std::thread::sleep(Duration::from_millis(50));
                }
                connect_client(&home).lock().unwrap();
            });
            common::finish_within(lock_cmd, Duration::from_secs(30))
        });
        assert_eq!(out_locked.status.code(), Some(1));
        assert!(out_locked.stdout.is_empty());
        assert!(
            common::stderr(&out_locked).starts_with("envcloak: vault_locked:"),
            "stderr: {}",
            common::stderr(&out_locked)
        );

        d.signal("-TERM");
        assert!(d.wait_exit(Duration::from_secs(30)).is_some());
        assert_no_canary(&d.log_bytes(), &cs);
        home.assert_clean(&cs);
    }

    #[test]
    fn m3_19_add_from_clipboard_reads_warns_clears_and_preserves_concurrent_change() {
        let mut cs = canaries(fresh_seed());
        let home = TestHome::new();
        cs.push(common::seed_vault(&home, &cs));
        let mut d = common::start_daemon(&home);
        let files = common::outside_dir();
        let pass = common::secret_file(
            files.path(),
            "pass",
            by_label(&cs, labels::VAULT_PASSPHRASE).value(),
        );
        let unlocked = common::run_on_terminal(
            &home,
            &["unlock", "--passphrase-fd", "3"],
            &[(3, &pass, true)],
        );
        assert!(unlocked.status.success(), "{}", common::stderr(&unlocked));

        let pb = TestPasteboard::new();

        // 1. Normal `--from-clipboard`: reads value, prints warning on stderr,
        //    adds item to vault, and clears pasteboard because `changeCount`
        //    still matches.
        let clip_key_1 = stripe_key("test");
        cs.push(Canary::new("CLIP_STRIPE_1", clip_key_1.clone()));
        pb.set_string(&clip_key_1);

        let mut cmd1 = common::cli_command(
            &home,
            &[
                "add",
                "stripe",
                "--slug",
                "stripe/from-clip-1",
                "--from-clipboard",
            ],
            &[],
        );
        cmd1.env(TEST_PASTEBOARD_ENV, pb.name());
        let out1 = common::finish_within(cmd1, Duration::from_secs(30));
        assert_eq!(
            out1.status.code(),
            Some(0),
            "stderr: {}",
            common::stderr(&out1)
        );
        assert!(common::stdout(&out1).contains("Added stripe/from-clip-1."));
        let err1 = common::stderr(&out1);
        assert!(
            err1.contains(
                "warning: cleared from the clipboard; clipboard history tools may already hold the value"
            ),
            "stderr missing clipboard warning: {err1}"
        );
        assert_eq!(
            pb.read_string(),
            None,
            "pasteboard must be cleared after read"
        );
        assert_no_canary(&out1.stdout, &cs);
        assert_no_canary(&out1.stderr, &cs);

        // 2. Mutation Check 3: concurrent pasteboard write between read and
        //    clear -> item is added, but pasteboard is NOT cleared because
        //    `changeCount` changed since the read.
        let clip_key_2 = stripe_key("test");
        cs.push(Canary::new("CLIP_STRIPE_2", clip_key_2.clone()));
        pb.set_string(&clip_key_2);

        let mut cmd2 = common::cli_command(
            &home,
            &[
                "add",
                "stripe",
                "--slug",
                "stripe/from-clip-2",
                "--from-clipboard",
            ],
            &[],
        );
        cmd2.env(TEST_PASTEBOARD_ENV, pb.name())
            .env(TEST_PASTEBOARD_WRITE_BETWEEN_ENV, "concurrent-user-copy");
        let out2 = common::finish_within(cmd2, Duration::from_secs(30));
        assert_eq!(
            out2.status.code(),
            Some(0),
            "stderr: {}",
            common::stderr(&out2)
        );
        assert!(common::stdout(&out2).contains("Added stripe/from-clip-2."));
        let err2 = common::stderr(&out2);
        assert!(
            err2.contains(
                "warning: the clipboard changed before it could be cleared; clipboard history tools may already hold the value"
            ),
            "stderr missing concurrent change warning: {err2}"
        );
        assert_eq!(
            pb.read_string().as_deref(),
            Some("concurrent-user-copy"),
            "pasteboard must NOT be cleared when changeCount changed after read"
        );
        pb.set_string("");
        assert_no_canary(&out2.stdout, &cs);
        assert_no_canary(&out2.stderr, &cs);

        // Stop daemon and verify both clipboard items are stored in the vault
        // with their exact values.
        d.signal("-TERM");
        assert!(d.wait_exit(Duration::from_secs(30)).is_some());
        let v = LockedVault::open(&VaultPaths::under(common::data_dir(&home)))
            .unwrap()
            .unlock_with_passphrase(&SecretBytes::copy_from(
                by_label(&cs, labels::VAULT_PASSPHRASE).value(),
            ))
            .map_err(|(_, e)| e)
            .unwrap();
        for (slug, expected) in [
            ("stripe/from-clip-1", clip_key_1.as_bytes()),
            ("stripe/from-clip-2", clip_key_2.as_bytes()),
        ] {
            let meta = v.items().iter().find(|i| i.slug.as_str() == slug).unwrap();
            let fid = meta.fields[0].id;
            let actual = v.read_value(fid).unwrap();
            let expected_sec = SecretBytes::copy_from(expected);
            assert_eq!(secret_sha256(&actual), secret_sha256(&expected_sec));
        }
        drop(v);
        assert_no_canary(&d.log_bytes(), &cs);
        home.assert_clean(&cs);
    }

    #[test]
    fn m3_j5_macos_reveal_refuses_agent_and_opens_in_app_for_human() {
        let mut cs = canaries(fresh_seed());
        let home = TestHome::new();
        cs.push(common::seed_vault(&home, &cs));

        // Enroll a Secure Enclave unlocker in the vault before starting the daemon.
        let (_, unlock_pub, approve_sk, approve_pub) = sample_se_keypairs(0x91);
        {
            let mut v = LockedVault::open(&VaultPaths::under(common::data_dir(&home)))
                .unwrap()
                .unlock_with_passphrase(&SecretBytes::copy_from(
                    by_label(&cs, labels::VAULT_PASSPHRASE).value(),
                ))
                .map_err(|(_, e)| e)
                .unwrap();
            v.enroll_se_unlocker(SeUnlockerRecord {
                unlocker_id: UnlockerId::generate(),
                unlock_pub,
                approve_pub,
                label: "Touch ID".to_owned(),
                created_secs: 1_700_000_000,
                enrolled_under: SeEnrolledUnder {
                    team_id: TEST_TEAM_ID.to_owned(),
                    signing_id: TEST_SIGNING_ID.to_owned(),
                },
            })
            .unwrap();
        }

        let clock_file = home.root().join("clock-offset");
        std::fs::write(&clock_file, "0").unwrap();
        let app_id = this_process_app_id();
        let mut d = start_daemon_with_app(&home, Some(&app_id), Some(&clock_file));
        let files = common::outside_dir();
        let pass = common::secret_file(
            files.path(),
            "pass",
            by_label(&cs, labels::VAULT_PASSPHRASE).value(),
        );
        let unlocked = common::run_on_terminal(
            &home,
            &["unlock", "--passphrase-fd", "3"],
            &[(3, &pass, true)],
        );
        assert!(unlocked.status.success(), "{}", common::stderr(&unlocked));

        // 1. Mutation Check 4: `fixture-agent` running `envcloak reveal` on a
        //    terminal is refused with `proof_refused` before anything is filed
        //    (`status().app_requests == 0`).
        let agent_out = common::finish_within(
            agent_command(&home, &["reveal", common::SLUGS[0]]),
            Duration::from_secs(30),
        );
        assert_eq!(agent_out.status.code(), Some(125));
        assert!(agent_out.stdout.is_empty());
        assert!(
            common::stderr(&agent_out).starts_with("envcloak: proof_refused:"),
            "stderr: {}",
            common::stderr(&agent_out)
        );
        assert_eq!(
            connect_client(&home).status().unwrap().app_requests,
            0,
            "agent reveal must not file a pending app request"
        );
        assert_no_canary(&agent_out.stdout, &cs);
        assert_no_canary(&agent_out.stderr, &cs);

        // 2. Human on a terminal runs `envcloak reveal openai/acme-web`: opens a
        //    pending reveal request with the human's evidence; the app responder
        //    calls `app.reveal.begin` + `app.reveal`; CLI prints
        //    `"Shown in EnvCloak\n"` and never prints the secret value.
        let human_shown_cmd =
            common::on_terminal_command(&home, &["reveal", common::SLUGS[0]], &[]);
        let out_shown = std::thread::scope(|scope| {
            scope.spawn(|| {
                let deadline = Instant::now() + Duration::from_secs(15);
                loop {
                    if connect_client(&home).status().unwrap().app_requests > 0 {
                        break;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "timed out waiting for reveal.request"
                    );
                    std::thread::sleep(Duration::from_millis(50));
                }
                let mut c = connect_client(&home);
                let desc = c
                    .app_reveal_begin(&AppRevealBeginParams {
                        request: None,
                        slug: None,
                        field: None,
                        claims: Vec::new(),
                    })
                    .unwrap();
                assert_eq!(desc.slug, common::SLUGS[0]);
                let req_ev = desc
                    .requester
                    .as_ref()
                    .expect("client reveal must record requester evidence");
                assert_eq!(req_ev.kind, SubjectKind::Terminal);
                assert!(req_ev.label.is_none());

                let digest = reveal_statement_digest(&desc);
                let sig = sign_p256_prehash(&approve_sk, &digest).unwrap();
                let app_eph = SeEphemeralKey::generate().unwrap();
                let revealed = c
                    .app_reveal(&AppRevealParams {
                        request: desc.request.clone(),
                        digest: hex_encode(&digest),
                        signature: hex_encode(&sig),
                        app_eph_pub: hex_encode(app_eph.public_key()),
                        claims: Vec::new(),
                    })
                    .unwrap();
                let nonce_bytes: [u8; 32] = decode_hex(&desc.nonce);
                let aad = se_reseal_aad(&desc.request, &nonce_bytes);
                let opened = app_eph
                    .open_secret(&aad, &decode_hex_vec(&revealed.sealed_value))
                    .unwrap();
                let expected =
                    SecretBytes::copy_from(by_label(&cs, labels::OPENAI_API_KEY).value());
                assert_eq!(secret_sha256(&opened), secret_sha256(&expected));
            });
            common::finish_within(human_shown_cmd, Duration::from_secs(30))
        });
        assert_eq!(
            out_shown.status.code(),
            Some(0),
            "stderr: {}",
            common::stderr(&out_shown)
        );
        assert_eq!(common::stdout(&out_shown), "Shown in EnvCloak\n");
        assert!(out_shown.stderr.is_empty());
        assert_no_canary(&out_shown.stdout, &cs);
        assert_no_canary(&out_shown.stderr, &cs);

        // 3. Human reveal declined in the app (`deny`) -> exits 125 with `declined`.
        let human_dec_cmd = common::on_terminal_command(&home, &["reveal", common::SLUGS[0]], &[]);
        let out_dec = std::thread::scope(|scope| {
            scope.spawn(|| {
                let deadline = Instant::now() + Duration::from_secs(15);
                loop {
                    if connect_client(&home).status().unwrap().app_requests > 0 {
                        break;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "timed out waiting for reveal.request"
                    );
                    std::thread::sleep(Duration::from_millis(50));
                }
                let mut c = connect_client(&home);
                let desc = c
                    .app_reveal_begin(&AppRevealBeginParams {
                        request: None,
                        slug: None,
                        field: None,
                        claims: Vec::new(),
                    })
                    .unwrap();
                c.deny(&desc.request).unwrap();
            });
            common::finish_within(human_dec_cmd, Duration::from_secs(30))
        });
        assert_eq!(out_dec.status.code(), Some(125));
        assert!(out_dec.stdout.is_empty());
        assert!(
            common::stderr(&out_dec).starts_with("envcloak: declined:"),
            "stderr: {}",
            common::stderr(&out_dec)
        );

        // 4. Human reveal expired -> exits 125 with `expired`.
        let human_exp_cmd = common::on_terminal_command(&home, &["reveal", common::SLUGS[0]], &[]);
        let out_exp = std::thread::scope(|scope| {
            scope.spawn(|| {
                let deadline = Instant::now() + Duration::from_secs(15);
                loop {
                    if connect_client(&home).status().unwrap().app_requests > 0 {
                        break;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "timed out waiting for reveal.request"
                    );
                    std::thread::sleep(Duration::from_millis(50));
                }
                std::fs::write(&clock_file, "650").unwrap();
            });
            common::finish_within(human_exp_cmd, Duration::from_secs(30))
        });
        assert_eq!(out_exp.status.code(), Some(125));
        assert!(out_exp.stdout.is_empty());
        assert!(
            common::stderr(&out_exp).starts_with("envcloak: expired:"),
            "stderr: {}",
            common::stderr(&out_exp)
        );

        // 5. Vault locked while polling -> re-issues `reveal.request` and exits
        //    125 with `vault_locked` instead of `expired`.
        let human_lock_cmd = common::on_terminal_command(&home, &["reveal", common::SLUGS[0]], &[]);
        let out_lock = std::thread::scope(|scope| {
            scope.spawn(|| {
                let deadline = Instant::now() + Duration::from_secs(15);
                loop {
                    if connect_client(&home).status().unwrap().app_requests > 0 {
                        break;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "timed out waiting for reveal.request"
                    );
                    std::thread::sleep(Duration::from_millis(50));
                }
                connect_client(&home).lock().unwrap();
            });
            common::finish_within(human_lock_cmd, Duration::from_secs(30))
        });
        assert_eq!(out_lock.status.code(), Some(125));
        assert!(out_lock.stdout.is_empty());
        assert!(
            common::stderr(&out_lock).starts_with("envcloak: vault_locked:"),
            "stderr: {}",
            common::stderr(&out_lock)
        );

        d.signal("-TERM");
        assert!(d.wait_exit(Duration::from_secs(30)).is_some());
        assert_no_canary(&d.log_bytes(), &cs);
        home.assert_clean(&cs);
    }
}
