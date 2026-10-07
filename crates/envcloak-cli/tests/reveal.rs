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
