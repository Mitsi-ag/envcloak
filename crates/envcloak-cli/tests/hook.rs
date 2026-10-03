//! `envcloak hook` on the built binary (M2 plan M2-08; gate 34, the hook
//! denial, advisory): what Claude Code and Codex get back, read as each
//! host reads it, from the payloads the pinned hosts sent (M2-04's
//! captures in crates/envcloak-e2e/tests/fixtures/hook-payloads/), changed
//! only where a test puts a prompt or a command.
//!
//! - Allowed: no output, exit 0. Stopped: the host's JSON on standard
//!   output, the `[envcloak:<reason>]` message on standard error, exit 2.
//!   Another host's payload, or not JSON: exit 1, a value-free diagnostic.
//!   A usage error: exit 1, never 2.
//! - A prompt holding any key-shaped canary is stopped, and nothing the
//!   handler writes holds it, in any encoding; the home holds none after.
//! - A 100 MiB payload, or one that never ends, is stopped (`unchecked`)
//!   within the 2-second deadline.
//! - `SessionStart` adds the names the project's manifest binds when the
//!   daemon answers, never a value, and is silent when it is down.
#![allow(clippy::unwrap_used)]

mod common;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use common::{
    MANIFEST, cli, outside_dir, project, run_on_terminal, secret_file, seed_vault,
    start_daemon, stderr, stdout,
};
use envcloak_testkit::{TestHome, assert_no_canary, by_label, canaries, fresh_seed, labels};
use serde_json::{Value, json};

fn captured(host: &str, event: &str) -> Value {
    let dir = match host {
        "claude-code" => "claude-code-2.1.280",
        _ => "codex-0.159.2",
    };
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../envcloak-e2e/tests/fixtures/hook-payloads")
        .join(dir)
        .join(format!("{event}.json"));
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

fn with_command(host: &str, command: &str) -> Vec<u8> {
    let mut p = captured(host, "PreToolUse");
    p["tool_input"]["command"] = Value::from(command);
    serde_json::to_vec(&p).unwrap()
}

fn with_prompt(host: &str, prompt: &str) -> Vec<u8> {
    let mut p = captured(host, "UserPromptSubmit");
    p["prompt"] = Value::from(prompt);
    serde_json::to_vec(&p).unwrap()
}

/// A `SessionStart` payload of `host`'s shape for a session in `cwd`.
fn session_start(host: &str, cwd: &Path) -> Vec<u8> {
    let mut p = json!({
        "session_id": "s",
        "cwd": cwd.to_str().unwrap(),
        "hook_event_name": "SessionStart",
        "source": "startup",
        "transcript_path": "/dev/null",
    });
    if host == "codex" {
        p["model"] = Value::from("ec-scripted");
    }
    serde_json::to_vec(&p).unwrap()
}

/// `envcloak hook <args>` in `home`, fed `payload`; the writer ignores a
/// closed pipe, as a host does once the hook has answered.
fn hook(home: &TestHome, args: &[&str], payload: Vec<u8>) -> (Output, Duration) {
    let mut cmd = Command::new(cli());
    home.apply(&mut cmd)
        .arg("hook")
        .args(args)
        .current_dir(home.home())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let start = Instant::now();
    let mut child = cmd.spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&payload);
    });
    let out = wait(child, Duration::from_secs(30));
    let took = start.elapsed();
    writer.join().unwrap();
    (out, took)
}

fn wait(child: std::process::Child, limit: Duration) -> Output {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    rx.recv_timeout(limit)
        .expect("the hook did not exit")
        .unwrap()
}

fn args(host: &str, event: &str) -> [String; 4] {
    [
        "--host".to_owned(),
        host.to_owned(),
        "--event".to_owned(),
        event.to_owned(),
    ]
}

fn run(home: &TestHome, host: &str, event: &str, payload: Vec<u8>) -> Output {
    let a = args(host, event);
    let a: Vec<&str> = a.iter().map(String::as_str).collect();
    hook(home, &a, payload).0
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap()
}

/// What the host reads from a denial: its JSON, with the reason marker in
/// the field it shows, and the same message on standard error.
fn assert_denied(o: &Output, host: &str, event: &str, marker: &str) {
    assert_eq!(code(o), 2, "{}{}", stdout(o), stderr(o));
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    let shown = if event == "UserPromptSubmit" {
        assert_eq!(v["decision"], "block", "{v}");
        if host == "claude-code" {
            assert_eq!(v["hookSpecificOutput"]["suppressOriginalPrompt"], true, "{v}");
        }
        v["reason"].as_str().unwrap().to_owned()
    } else {
        let h = &v["hookSpecificOutput"];
        assert_eq!(h["hookEventName"], "PreToolUse", "{v}");
        assert_eq!(h["permissionDecision"], "deny", "{v}");
        h["permissionDecisionReason"].as_str().unwrap().to_owned()
    };
    assert!(shown.starts_with(marker), "{shown}");
    assert!(stderr(o).starts_with(marker), "{}", stderr(o));
}

#[test]
fn each_host_gets_its_own_answer() {
    let home = TestHome::new();
    for host in ["claude-code", "codex"] {
        for event in ["UserPromptSubmit", "PreToolUse"] {
            // As captured: a benign prompt, `echo hook-check`.
            let o = run(&home, host, event, serde_json::to_vec(&captured(host, event)).unwrap());
            assert_eq!(code(&o), 0, "{host} {event}: {}", stderr(&o));
            assert!(o.stdout.is_empty() && o.stderr.is_empty(), "{host} {event}");
        }
        for (command, marker) in [
            ("printenv", "[envcloak:env_dump]"),
            ("cat .env", "[envcloak:env_file]"),
            ("command env", "[envcloak:env_dump]"),
            ("envcloak approve REQUEST", "[envcloak:approve]"),
            ("envcloak reveal openai/acme-web", "[envcloak:reveal]"),
            ("cat${IFS}.env", "[envcloak:ambiguous]"),
        ] {
            let o = run(&home, host, "PreToolUse", with_command(host, command));
            assert_denied(&o, host, "PreToolUse", marker);
        }
        // The other host's payload, or no JSON: no decision, exit 1.
        let other = if host == "codex" { "claude-code" } else { "codex" };
        for payload in [
            with_command(other, "printenv"),
            b"not json".to_vec(),
            b"[]".to_vec(),
            Vec::new(),
        ] {
            let o = run(&home, host, "PreToolUse", payload);
            assert_eq!(code(&o), 1, "{host}: {}", stderr(&o));
            assert!(o.stdout.is_empty());
            assert!(
                stderr(&o).starts_with("envcloak: hook_payload: "),
                "{}",
                stderr(&o)
            );
        }
        // A Claude Code tool name from Codex is not one Codex sends.
        if host == "claude-code" {
            let mut p = captured(host, "PreToolUse");
            p["tool_name"] = json!("Read");
            p["tool_input"] = json!({"file_path": "/w/.env.production"});
            let o = run(&home, host, "PreToolUse", serde_json::to_vec(&p).unwrap());
            assert_denied(&o, host, "PreToolUse", "[envcloak:env_file]");
        }
    }
}

#[test]
fn usage_errors_exit_1_never_2() {
    let home = TestHome::new();
    for a in [
        &[][..],
        &["--host", "cursor", "--event", "PreToolUse"],
        &["--host", "codex", "--event", "Stop"],
        &["--host", "codex"],
        &["--host", "codex", "--event", "PreToolUse", "--json"],
    ] {
        let (o, _) = hook(&home, a, with_command("codex", "printenv"));
        assert_eq!(code(&o), 1, "{a:?}");
        assert!(o.stdout.is_empty(), "{a:?}");
        assert!(stderr(&o).starts_with("envcloak: usage: "), "{}", stderr(&o));
    }
}

/// Mutation checked: `cmd/hook.rs` writing the payload it read after the
/// block message on standard error (the match echoed in the block
/// reason): the sweep finds the canary ("canary leak: OPENAI_API_KEY as
/// raw") and this fails.
#[test]
fn a_key_in_a_prompt_is_stopped_and_never_echoed() {
    let home = TestHome::new();
    let mut cs = canaries(fresh_seed());
    // The URL canary's password holds a `/`, a quote and a space, which a
    // URL must escape: written as a URL holds it (the raw form is in
    // docs/INSTALLERS.md's list of what the prompt check misses).
    let url = by_label(&cs, labels::DATABASE_URL).as_str();
    let (user, rest) = url.split_at(url.find(':').unwrap() + 3);
    let (user_and_password, host_part) = rest.split_at(rest.rfind('@').unwrap());
    let (name, password) = user_and_password.split_once(':').unwrap();
    let escaped: String = password
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    cs.push(envcloak_testkit::Canary::new(
        "DATABASE_URL_ESCAPED",
        format!("{user}{name}:{escaped}{host_part}"),
    ));
    for host in ["claude-code", "codex"] {
        for label in [
            labels::OPENAI_API_KEY,
            labels::OPENAI_API_KEY_ROTATED,
            labels::STRIPE_SECRET_KEY,
            labels::GITHUB_TOKEN,
            "DATABASE_URL_ESCAPED",
        ] {
            let v = by_label(&cs, label).as_str();
            for prompt in [
                v.to_owned(),
                format!("please use {v} for the deploy"),
                format!("key=\"{v}\""),
            ] {
                let o = run(&home, host, "UserPromptSubmit", with_prompt(host, &prompt));
                assert_eq!(code(&o), 2, "{host}: {label} was let through");
                assert_denied(&o, host, "UserPromptSubmit", "[envcloak:key_in_prompt]");
                assert_no_canary(&o.stdout, &cs);
                assert_no_canary(&o.stderr, &cs);
            }
        }
        // The same canary in a command: stopped for the file it reads,
        // never echoed.
        let v = by_label(&cs, labels::OPENAI_API_KEY).as_str();
        let o = run(
            &home,
            host,
            "PreToolUse",
            with_command(host, &format!("grep {v} .env")),
        );
        assert_denied(&o, host, "PreToolUse", "[envcloak:env_file]");
        assert_no_canary(&o.stdout, &cs);
        assert_no_canary(&o.stderr, &cs);
    }
    home.assert_clean(&cs);
}

#[test]
fn a_payload_too_large_or_too_slow_is_stopped_within_the_deadline() {
    let home = TestHome::new();
    for host in ["claude-code", "codex"] {
        let mut big = with_command(host, "echo ok");
        big.resize(100 * 1024 * 1024, b' ');
        let a = args(host, "PreToolUse");
        let a: Vec<&str> = a.iter().map(String::as_str).collect();
        let (o, took) = hook(&home, &a, big);
        assert_denied(&o, host, "PreToolUse", "[envcloak:unchecked]");
        assert!(took < Duration::from_millis(2500), "{took:?}");

        // A payload that never ends: the host's pipe stays open.
        let mut cmd = Command::new(cli());
        home.apply(&mut cmd)
            .arg("hook")
            .args(&a)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let start = Instant::now();
        let mut child = cmd.spawn().unwrap();
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(b"{\"hook_event_name\": ").unwrap();
        let o = wait(child, Duration::from_secs(10));
        let took = start.elapsed();
        drop(stdin);
        assert_denied(&o, host, "PreToolUse", "[envcloak:unchecked]");
        assert!(took < Duration::from_millis(2500), "{took:?}");
        assert!(took >= Duration::from_millis(1900), "{took:?}");

        // SessionStart decides nothing: silent.
        let a = args(host, "SessionStart");
        let a: Vec<&str> = a.iter().map(String::as_str).collect();
        let mut big = session_start(host, &home.home());
        big.resize(4 * 1024 * 1024, b' ');
        let (o, _) = hook(&home, &a, big);
        assert_eq!(code(&o), 0);
        assert!(o.stdout.is_empty() && o.stderr.is_empty());
    }
}

fn context_names(o: &Output) -> String {
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["hookEventName"], "SessionStart");
    v["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn session_start_names_the_bound_variables_and_is_silent_without_a_daemon() {
    let cs = canaries(fresh_seed());
    let home = TestHome::new();
    let kit = seed_vault(&home, &cs);
    let mut cs = cs;
    cs.push(kit);
    let dir: PathBuf = project(&home, "acme-web", MANIFEST);
    let nested = dir.join("src");
    std::fs::create_dir_all(&nested).unwrap();
    for host in ["claude-code", "codex"] {
        let (o, took) = {
            let a = args(host, "SessionStart");
            let a: Vec<&str> = a.iter().map(String::as_str).collect();
            hook(&home, &a, session_start(host, &dir))
        };
        assert_eq!(code(&o), 0, "{}", stderr(&o));
        assert!(o.stdout.is_empty(), "no daemon: {}", stdout(&o));
        assert!(took < Duration::from_millis(2500), "{took:?}");
    }
    let d = start_daemon(&home);
    let files = outside_dir();
    let pass = secret_file(
        files.path(),
        "pass",
        by_label(&cs, labels::VAULT_PASSPHRASE).value(),
    );
    let out = run_on_terminal(
        &home,
        &["unlock", "--passphrase-fd", "3"],
        &[(3, &pass, true)],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    for host in ["claude-code", "codex"] {
        for cwd in [&dir, &nested] {
            let o = run(&home, host, "SessionStart", session_start(host, cwd));
            assert_eq!(code(&o), 0, "{}", stderr(&o));
            let text = context_names(&o);
            assert!(text.contains("binds OPENAI_API_KEY, SHORT_TOKEN, STRIPE_SECRET_KEY."), "{text}");
            assert!(text.contains("envcloak run -- <command>"), "{text}");
            assert_no_canary(&o.stdout, &cs);
            assert_no_canary(&o.stderr, &cs);
        }
        // No manifest: nothing.
        let o = run(&home, host, "SessionStart", session_start(host, &home.home()));
        assert_eq!(code(&o), 0);
        assert!(o.stdout.is_empty());
    }
    assert_no_canary(&d.log_bytes(), &cs);
    drop(d);
    home.assert_clean(&cs);
}
