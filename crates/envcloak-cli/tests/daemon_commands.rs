//! The CLI's daemon commands (SPEC §4.1, §4.2, §5 "Unlock flow", story
//! S1): `vault create`, `unlock`, `lock`, `status` and `daemon install`,
//! against a real `envcloakd` in an isolated home. Passphrases and the
//! Recovery Kit travel on descriptors here (`--passphrase-fd`,
//! `--kit-fd`); `tests/tty.rs` covers the terminal. Every output and the
//! home are swept for them.
#![allow(clippy::unwrap_used)]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use common::{
    cli, cli_command, daemon_exe, finish_within, outside_dir, run, run_on_terminal, secret_file,
    start_daemon, stderr, stdout,
};
use envcloak_core::vault::{LockedVault, VaultPaths};
use envcloak_core::{RecoveryKit, SecretBytes};
use envcloak_ipc::proto::{self, IncomingRequest};
use envcloak_ipc::{Client, Frame, RunPaths};
use envcloak_testkit::{
    Canary, TEST_PATH, TestHome, assert_no_canary, by_label, canaries, daemon_run_dir, fresh_seed,
    labels,
};

fn assert_clean_output(o: &std::process::Output, cs: &[Canary]) {
    assert_no_canary(&o.stdout, cs);
    assert_no_canary(&o.stderr, cs);
}

/// The data directory of `home`, as the daemon resolves it.
fn data_dir(home: &TestHome) -> PathBuf {
    if cfg!(target_os = "macos") {
        home.home().join("Library/Application Support/EnvCloak")
    } else {
        home.root().join("data/envcloak")
    }
}

/// SPEC §4.1: clients never start a daemon found on `PATH`. A fake
/// `envcloakd` first on `PATH` records any start; every command that needs
/// the daemon says how to start one, and the fake never runs.
#[test]
fn the_cli_never_starts_envcloakd_from_path() {
    let home = TestHome::new();
    let files = outside_dir();
    let bin = home.root().join("fakebin");
    std::fs::create_dir(&bin).unwrap();
    let marker = home.root().join("envcloakd-started");
    let fake = bin.join("envcloakd");
    std::fs::write(
        &fake,
        format!("#!/bin/sh\necho started > '{}'\n", marker.display()),
    )
    .unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!("{}:{TEST_PATH}", bin.display());
    let pass = secret_file(files.path(), "pass", b"correct horse battery staple words");
    let kit = files.path().join("kit");

    let commands: [(&[&str], Vec<common::Fd<'_>>); 5] = [
        (&["status"], vec![]),
        (&["lock"], vec![]),
        (&["unlock", "--passphrase-fd", "3"], vec![(3, &pass, true)]),
        (
            &["vault", "create", "--passphrase-fd", "3", "--kit-fd", "4"],
            vec![(3, &pass, true), (4, &kit, false)],
        ),
        (&["run", "--", "true"], vec![]),
    ];
    for (args, fds) in commands {
        let mut cmd = cli_command(&home, args, &fds);
        cmd.env("PATH", &path);
        let out = finish_within(cmd, Duration::from_secs(60));
        let err = stderr(&out);
        assert!(!out.status.success(), "{args:?}");
        assert!(err.contains("daemon_unavailable"), "{args:?}: {err}");
        assert!(err.contains("envcloak daemon install"), "{args:?}: {err}");
        assert!(!marker.exists(), "{args:?} started the envcloakd on PATH");
    }
    // Nothing was written for the kit either.
    assert_eq!(std::fs::read(&kit).unwrap(), b"");
    // Control: the fake records a start when it runs.
    assert!(Command::new(&fake).status().unwrap().success());
    assert!(marker.exists());
}

#[test]
fn status_says_what_this_build_cannot_verify() {
    let home = TestHome::new();
    let d = start_daemon(&home);
    let out = run(&home, &["status"], &[]);
    let s = stdout(&out);
    assert!(out.status.success(), "{s}{}", stderr(&out));
    assert!(
        s.contains(&format!("daemon: running (pid {}", d.pid())),
        "{s}"
    );
    assert!(s.contains("daemon identity: unverified"), "{s}");
    assert!(s.contains("vault: none yet"), "{s}");
    assert!(s.contains("idle lock: after 8h 0m idle"), "{s}");
    if cfg!(target_os = "macos") {
        // Cargo builds are unsigned: both processes say so.
        assert!(
            s.contains("daemon hardening: unhardened (not signed with the hardened runtime)"),
            "{s}"
        );
        assert!(
            s.contains("cli hardening: unhardened (not signed with the hardened runtime)"),
            "{s}"
        );
    } else {
        assert!(s.contains("daemon hardening: hardened"), "{s}");
        assert!(s.contains("cli hardening: hardened"), "{s}");
    }

    let out = run(&home, &["status", "--json"], &[]);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["daemon"]["state"], "running");
    assert_eq!(v["daemon"]["identity"], "unverified");
    assert_eq!(v["daemon"]["hardened"], cfg!(target_os = "linux"));
    assert_eq!(v["cli"]["hardened"], cfg!(target_os = "linux"));
    assert_eq!(v["vault"]["state"], "absent");
    assert_eq!(v["lock"]["idle_limit_secs"], 8 * 3600);
}

#[test]
fn status_without_a_daemon_says_how_to_start_one() {
    let home = TestHome::new();
    let out = run(&home, &["status"], &[]);
    assert_eq!(out.status.code(), Some(1));
    let s = stdout(&out);
    assert!(s.contains("daemon: not running"), "{s}");
    assert!(s.contains("envcloak daemon install"), "{s}");
    assert!(stderr(&out).starts_with("envcloak: daemon_unavailable:"));
    let out = run(&home, &["status", "--json"], &[]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["daemon"]["state"], "not running");
}

/// A program running as the user can answer in the daemon's place (its
/// code identity is unverified in M1). Whatever it puts in `status`'s
/// strings, `envcloak status` prints no control character of its: the
/// version and the reason come out as fixed placeholders.
#[test]
fn status_prints_no_control_sequence_a_stand_in_daemon_sends() {
    let home = TestHome::new();
    let paths = RunPaths::under(daemon_run_dir(&home)).unwrap();
    paths.prepare_dir().unwrap();
    let listener = UnixListener::bind(&paths.socket).unwrap();
    let body = serde_json::json!({
        "daemon": {
            "version": "\u{1b}]0;owned\u{7}\u{1b}[2J9.9",
            "pid": 4242,
            "hardening": {"core_dumps_off": true, "non_dumpable": true, "hardened_runtime": null},
            "runtime_dir_fallback": false
        },
        "vault": {
            "state": "unavailable", "integrity": null, "read_only": false,
            "unavailable": "\u{1b}[31mdamaged\r\u{8}", "busy": false, "failed_unlocks": 0
        },
        "lock": {"last_reason": null, "idle_limit_secs": 28800, "idle_remaining_secs": null},
        "approvals": {"grants": 0, "pending": 0, "proof_failures": 0, "proof_wait_secs": 0},
        "audit": {"open": false, "head_seq": null, "unanchored": 0, "queued": 0, "dropped": 0}
    });
    let server = std::thread::spawn(move || {
        for _ in 0..2 {
            let (mut s, _) = listener.accept().unwrap();
            let f = Frame::read_from(&mut s).unwrap();
            let req = IncomingRequest::parse(&f).unwrap();
            proto::result_frame(req.id, &body)
                .unwrap()
                .write_to(&mut s)
                .unwrap();
        }
    });
    let human = run(&home, &["status"], &[]);
    let json = run(&home, &["status", "--json"], &[]);
    server.join().unwrap();
    for out in [&human, &json] {
        assert!(out.status.success(), "{}", stderr(out));
        for b in out.stdout.iter().chain(&out.stderr) {
            assert!(
                *b == b'\n' || !b.is_ascii_control(),
                "a control byte {b:#04x} reached the terminal: {:?}",
                stdout(out)
            );
        }
    }
    let said = stdout(&human);
    assert!(said.contains("version unrecognized"), "{said}");
    assert!(said.contains("vault: unavailable (unknown)"), "{said}");
    let v: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(v["daemon"]["version"], "unrecognized");
    assert_eq!(v["vault"]["unavailable"], "unknown");
}

/// Story S1 and the lock cycle: `vault create --passphrase-fd 3 --kit-fd 4
/// --kdf-memory 64MiB` creates and unlocks the vault and writes the kit
/// only to descriptor 4; lock and unlock follow. The kit really unlocks the
/// vault, and neither it nor the passphrase appears in any output, the
/// daemon's log or the home.
#[test]
fn vault_create_lock_and_unlock_through_descriptors() {
    let cs = canaries(fresh_seed());
    let pass = by_label(&cs, labels::VAULT_PASSPHRASE).value();
    let home = TestHome::new();
    let mut d = start_daemon(&home);
    let files = outside_dir();
    let pass_file = secret_file(files.path(), "pass", pass);
    let kit_file = files.path().join("kit");

    let out = run(
        &home,
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
        &[(3, &pass_file, true), (4, &kit_file, false)],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("Vault created and unlocked."));
    let kit_text = std::fs::read_to_string(&kit_file).unwrap();
    let kit_text = kit_text.trim_end().to_owned();
    let kit = RecoveryKit::parse(&SecretBytes::copy_from(kit_text.as_bytes())).unwrap();
    let mut all = cs.clone();
    all.push(Canary::new("RECOVERY_KIT", kit_text));
    assert_clean_output(&out, &all);

    let mut outputs = vec![out];
    let status = run(&home, &["status"], &[]);
    assert!(stdout(&status).contains("vault: unlocked (integrity ok)"));
    assert!(
        stdout(&status).contains("locks in 7h"),
        "{}",
        stdout(&status)
    );
    let lock = run(&home, &["lock"], &[]);
    assert_eq!(stdout(&lock), "Vault locked.\n");
    let again = run(&home, &["lock"], &[]);
    assert_eq!(stdout(&again), "The vault was not unlocked.\n");
    let status = run(&home, &["status"], &[]);
    assert!(stdout(&status).contains("vault: locked"));
    assert!(stdout(&status).contains("last locked by: request"));

    let wrong = secret_file(files.path(), "wrong", b"a wrong passphrase, but long");
    let bad = run_on_terminal(
        &home,
        &["unlock", "--passphrase-fd", "3"],
        &[(3, &wrong, true)],
    );
    assert_eq!(bad.status.code(), Some(1));
    assert!(
        stderr(&bad).starts_with("envcloak: wrong_passphrase:"),
        "{}",
        stderr(&bad)
    );
    let good = run_on_terminal(
        &home,
        &["unlock", "--passphrase-fd", "3"],
        &[(3, &pass_file, true)],
    );
    assert_eq!(stdout(&good), "Vault unlocked.\n", "{}", stderr(&good));
    let already = run_on_terminal(
        &home,
        &["unlock", "--passphrase-fd", "3"],
        &[(3, &pass_file, true)],
    );
    assert_eq!(stdout(&already), "The vault is already unlocked.\n");
    let status = run(&home, &["status"], &[]);
    assert!(stdout(&status).contains("failed unlocks: 1"));
    outputs.extend([status, lock, again, bad, good, already]);
    for o in &outputs {
        assert_clean_output(o, &all);
    }

    // The kit written to descriptor 4 is this vault's.
    d.signal("-TERM");
    assert!(d.wait_exit(Duration::from_secs(20)).unwrap().success());
    let v = LockedVault::open(&VaultPaths::under(data_dir(&home)))
        .unwrap()
        .unlock_with_kit(&kit)
        .map_err(|(_, e)| e)
        .unwrap();
    drop(v);
    assert_no_canary(&d.log_bytes(), &all);
    home.assert_clean(&all);
}

#[test]
fn vault_create_refuses_before_anything_is_created() {
    let cs = canaries(fresh_seed());
    let pass = by_label(&cs, labels::VAULT_PASSPHRASE).value();
    let home = TestHome::new();
    let _d = start_daemon(&home);
    let files = outside_dir();
    let pass_file = secret_file(files.path(), "pass", pass);
    let weak = secret_file(files.path(), "weak", b"short");
    let kit_file = files.path().join("kit");

    // The kit never goes to stdin, stdout or stderr.
    for fd in ["0", "1", "2"] {
        let out = run(
            &home,
            &["vault", "create", "--passphrase-fd", "3", "--kit-fd", fd],
            &[(3, &pass_file, true)],
        );
        assert_eq!(out.status.code(), Some(1), "{fd}");
        assert!(
            stderr(&out).starts_with("envcloak: kit_fd:"),
            "{}",
            stderr(&out)
        );
        assert_clean_output(&out, &cs);
    }
    // Usage errors, never echoing the arguments.
    for args in [
        &["vault", "create", "--passphrase-fd", "3", "--kit-fd", "3"][..],
        &["vault", "create", "--kdf-memory", "32MiB"],
        &["vault", "create", "--passphrase-fd"],
        &["vault", "create", pass_file.to_str().unwrap()],
        &["vault", "destroy"],
    ] {
        let out = run(&home, args, &[]);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(!stderr(&out).contains(pass_file.to_str().unwrap()));
    }
    // A weak passphrase is refused here, before the kit is written.
    let out = run(
        &home,
        &["vault", "create", "--passphrase-fd", "3", "--kit-fd", "4"],
        &[(3, &weak, true), (4, &kit_file, false)],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).starts_with("envcloak: passphrase_rejected:"));
    assert_eq!(std::fs::read(&kit_file).unwrap(), b"");
    // No terminal, and no descriptor for the passphrase or the kit.
    for (args, fds) in [
        (&["vault", "create"][..], vec![]),
        (
            &["vault", "create", "--passphrase-fd", "3"],
            vec![(3, pass_file.as_path(), true)],
        ),
    ] {
        let out = run(&home, args, &fds);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert!(
            stderr(&out).starts_with("envcloak: no_terminal:"),
            "{}",
            stderr(&out)
        );
    }
    let status = run(&home, &["status"], &[]);
    assert!(stdout(&status).contains("vault: none yet"));

    // With a vault, a second create is refused before anything is asked.
    let out = run(
        &home,
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
        &[(3, &pass_file, true), (4, &kit_file, false)],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let second_kit = files.path().join("kit2");
    let out = run(
        &home,
        &["vault", "create", "--passphrase-fd", "3", "--kit-fd", "4"],
        &[(3, &pass_file, true), (4, &second_kit, false)],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).starts_with("envcloak: vault_exists:"));
    assert_eq!(std::fs::read(&second_kit).unwrap(), b"");
}

/// Starts `vault create --passphrase-fd 3 --kit-fd 4 --kdf-memory 256MiB`
/// and waits until the daemon is running Argon2id for it.
fn create_in_background(home: &TestHome, pass_file: &Path, kit_file: &Path) -> Child {
    let mut cmd = cli_command(
        home,
        &[
            "vault",
            "create",
            "--passphrase-fd",
            "3",
            "--kit-fd",
            "4",
            "--kdf-memory",
            "256MiB",
        ],
        &[(3, pass_file, true), (4, kit_file, false)],
    );
    let mut child = cmd.spawn().unwrap();
    let paths = RunPaths::under(daemon_run_dir(home)).unwrap();
    let end = Instant::now() + Duration::from_secs(30);
    loop {
        let busy = Client::connect(&paths).and_then(|mut c| c.status());
        if matches!(busy, Ok(ref s) if s.vault.busy) {
            return child;
        }
        if Instant::now() > end || child.try_wait().unwrap().is_some() {
            let _ = child.kill();
            let out = child.wait_with_output().unwrap();
            panic!("vault create never reached the daemon: {}", stderr(&out));
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// Waits up to a minute for `child` and collects its output.
fn wait_output(child: Child) -> std::process::Output {
    let end = Instant::now() + Duration::from_secs(60);
    let mut child = child;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > end {
            let _ = child.kill();
            panic!("vault create did not finish");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    child.wait_with_output().unwrap()
}

/// `envcloak lock` while `vault create` runs Argon2id: the vault is created
/// and then locked. The CLI says so, exits 0 and tells the user to keep
/// the kit, which really unlocks the vault; it never calls the kit void.
#[test]
fn a_lock_during_vault_create_keeps_the_vault_and_the_kit() {
    let cs = canaries(fresh_seed());
    let pass = by_label(&cs, labels::VAULT_PASSPHRASE).value();
    let home = TestHome::new();
    let mut d = start_daemon(&home);
    let files = outside_dir();
    let pass_file = secret_file(files.path(), "pass", pass);
    let kit_file = files.path().join("kit");

    let creating = create_in_background(&home, &pass_file, &kit_file);
    let lock = run(&home, &["lock"], &[]);
    assert_eq!(stdout(&lock), "The vault was not unlocked.\n");
    let out = wait_output(creating);
    let (said, err) = (stdout(&out), stderr(&out));
    assert!(out.status.success(), "{said}{err}");
    assert!(said.contains("Vault created, then locked"), "{said}");
    assert!(said.contains("keep it"), "{said}");
    assert!(!format!("{said}{err}").contains("void"), "{said}{err}");
    let status = stdout(&run(&home, &["status"], &[]));
    assert!(status.contains("vault: locked"), "{status}");
    assert!(status.contains("last locked by: request"), "{status}");

    let kit_text = std::fs::read_to_string(&kit_file).unwrap();
    let kit_text = kit_text.trim_end().to_owned();
    let kit = RecoveryKit::parse(&SecretBytes::copy_from(kit_text.as_bytes())).unwrap();
    let mut all = cs.clone();
    all.push(Canary::new("RECOVERY_KIT", kit_text));
    assert_clean_output(&out, &all);
    let good = run_on_terminal(
        &home,
        &["unlock", "--passphrase-fd", "3"],
        &[(3, &pass_file, true)],
    );
    assert_eq!(stdout(&good), "Vault unlocked.\n", "{}", stderr(&good));
    d.signal("-TERM");
    assert!(d.wait_exit(Duration::from_secs(20)).unwrap().success());
    let v = LockedVault::open(&VaultPaths::under(data_dir(&home)))
        .unwrap()
        .unlock_with_kit(&kit)
        .map_err(|(_, e)| e)
        .unwrap();
    drop(v);
    assert_no_canary(&d.log_bytes(), &all);
    home.assert_clean(&all);
}

/// The daemon stops while `vault create` runs Argon2id, so the answer
/// never comes. Whether the vault exists is unknown to the CLI, so it
/// says to keep the kit rather than calling it void.
#[test]
fn a_daemon_that_stops_during_vault_create_leaves_the_kit_kept() {
    let cs = canaries(fresh_seed());
    let pass = by_label(&cs, labels::VAULT_PASSPHRASE).value();
    let home = TestHome::new();
    let mut d = start_daemon(&home);
    let files = outside_dir();
    let pass_file = secret_file(files.path(), "pass", pass);
    let kit_file = files.path().join("kit");

    let creating = create_in_background(&home, &pass_file, &kit_file);
    d.signal("-TERM");
    assert!(d.wait_exit(Duration::from_secs(20)).unwrap().success());
    let out = wait_output(creating);
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.starts_with("envcloak: daemon_unavailable:"), "{err}");
    assert!(err.contains("keep the Recovery Kit"), "{err}");
    assert!(!err.contains("void"), "{err}");
    let kit_text = std::fs::read_to_string(&kit_file).unwrap();
    assert!(!kit_text.trim().is_empty());
    let mut all = cs.clone();
    all.push(Canary::new("RECOVERY_KIT", kit_text.trim_end().to_owned()));
    assert_clean_output(&out, &all);
    assert_no_canary(&d.log_bytes(), &all);
}

// ------------------------------------------------------- daemon install

/// `packaging/<file>`, which the CLI compiles in.
fn template(name: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../packaging")
        .join(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// What `daemon install` must write for `daemon` in `home`: the packaging
/// template, filled in by this test.
fn expected_definition(home: &TestHome, daemon: &str) -> (PathBuf, String) {
    if cfg!(target_os = "macos") {
        let h = home.home();
        let log = h.join("Library/Logs/EnvCloak/envcloakd.log");
        let env = format!(
            "    <key>HOME</key>\n    <string>{}</string>\n",
            xml(h.to_str().unwrap())
        );
        let text = template("launchd/ai.envcloak.envcloakd.plist")
            .replace("@LABEL@", "ai.envcloak.envcloakd")
            .replace("@ENVCLOAKD@", &xml(daemon))
            .replace("@LOG@", &xml(log.to_str().unwrap()))
            .replace("@ENVIRONMENT@", &env);
        (
            h.join("Library/LaunchAgents/ai.envcloak.envcloakd.plist"),
            text,
        )
    } else {
        let r = home.root();
        let mut env = String::new();
        for (k, v) in [
            ("HOME", r.join("home")),
            ("XDG_CONFIG_HOME", r.join("config")),
            ("XDG_DATA_HOME", r.join("data")),
            ("XDG_STATE_HOME", r.join("state")),
            ("XDG_RUNTIME_DIR", r.join("run")),
        ] {
            env.push_str(&format!("Environment=\"{k}={}\"\n", v.display()));
        }
        let quoted = format!("\"{}\"", daemon.replace('%', "%%").replace('$', "$$"));
        let text = template("systemd/envcloakd.service")
            .replace("@ENVCLOAKD@", &quoted)
            .replace("@ENVIRONMENT@", &env);
        (
            r.join("config/systemd/user/ai.envcloak.envcloakd.service"),
            text,
        )
    }
}

/// `daemon install --no-start` writes the packaging template, filled in
/// with the absolute path of the `envcloakd` beside this `envcloak` (never
/// one on `PATH`) and the home's directories, mode 0644.
#[test]
fn daemon_install_writes_the_packaging_template_with_absolute_paths() {
    let home = TestHome::new();
    let out = run(&home, &["daemon", "install", "--no-start"], &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    let daemon = daemon_exe();
    let (path, want) = expected_definition(&home, daemon.to_str().unwrap());
    let got = std::fs::read_to_string(&path).unwrap();
    assert_eq!(got, want);
    assert!(stdout(&out).contains(path.to_str().unwrap()));
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o644);
    assert!(!got.contains('@'), "every placeholder is filled");

    // --daemon with characters each format must escape.
    let odd = home.root().join("tmp/Env Cloak & $HOME%x");
    std::fs::create_dir_all(&odd).unwrap();
    let copy = odd.join("envcloakd");
    std::fs::copy(&daemon, &copy).unwrap();
    let out = run(
        &home,
        &[
            "daemon",
            "install",
            "--no-start",
            "--daemon",
            copy.to_str().unwrap(),
        ],
        &[],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let (path, want) = expected_definition(&home, copy.to_str().unwrap());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), want);
}

#[test]
fn daemon_install_refuses_a_daemon_it_cannot_pin() {
    let home = TestHome::new();
    let dir = home.root().join("tmp");
    let cases: [(&[&str], &str); 4] = [
        (
            &["daemon", "install", "--no-start", "--daemon", "envcloakd"],
            "daemon_path",
        ),
        (
            &[
                "daemon",
                "install",
                "--no-start",
                "--daemon",
                "/nonexistent/envcloakd",
            ],
            "daemon_not_found",
        ),
        (
            &[
                "daemon",
                "install",
                "--no-start",
                "--daemon",
                dir.to_str().unwrap(),
            ],
            "daemon_not_found",
        ),
        (
            &["daemon", "install", "--no-start", "--daemon", "/etc/hosts"],
            "daemon_not_found",
        ),
    ];
    for (args, token) in cases {
        let out = run(&home, args, &[]);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert!(
            stderr(&out).starts_with(&format!("envcloak: {token}:")),
            "{args:?}: {}",
            stderr(&out)
        );
    }
    // No definition was written.
    assert!(!home.home().join("Library/LaunchAgents").exists());
    assert!(!home.root().join("config/systemd").exists());
    for args in [
        &["daemon", "install", "--label", "com.example.x"][..],
        &["daemon", "install", "--bogus"],
        &["daemon"],
    ] {
        assert_eq!(run(&home, args, &[]).status.code(), Some(2), "{args:?}");
    }
}

/// The CLI compiles in the packaging files: the source constants equal
/// them byte for byte, for both platforms, and this platform's is in the
/// binary.
#[test]
fn the_compiled_in_templates_are_the_packaging_files() {
    let plist = template("launchd/ai.envcloak.envcloakd.plist");
    for p in ["@LABEL@", "@ENVCLOAKD@", "@ENVIRONMENT@", "@LOG@"] {
        assert!(plist.contains(p), "{p}");
    }
    assert!(plist.contains("<string>--foreground</string>"));
    let unit = template("systemd/envcloakd.service");
    for p in ["@ENVCLOAKD@", "@ENVIRONMENT@"] {
        assert!(unit.contains(p), "{p}");
    }
    assert!(unit.contains("ExecStart=@ENVCLOAKD@ --foreground\n"));

    let src =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/cmd/daemon.rs"))
            .unwrap();
    let between = |start: &str, end: &str| {
        let i = src.find(start).unwrap() + start.len();
        let j = src[i..].find(end).unwrap();
        src[i..i + j].to_owned()
    };
    assert_eq!(
        between("pub const LAUNCHD_TEMPLATE: &str = r#\"", "\"#;"),
        plist,
        "LAUNCHD_TEMPLATE differs from packaging/launchd"
    );
    assert_eq!(
        between("pub const SYSTEMD_TEMPLATE: &str = \"", "\";\n"),
        unit,
        "SYSTEMD_TEMPLATE differs from packaging/systemd"
    );
    let bin = std::fs::read(cli()).unwrap();
    let here = if cfg!(target_os = "macos") {
        &plist
    } else {
        &unit
    };
    assert!(
        bin.windows(here.len()).any(|w| w == here.as_bytes()),
        "the CLI binary does not carry this platform's template"
    );
}
