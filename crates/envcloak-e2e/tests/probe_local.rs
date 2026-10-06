//! Gate 38 on the person's own machine, and gate 23 for the probe's
//! approvals (M2 plan task M2-28): `envcloak agents status --probe`, run by
//! the person in an isolated test home where their own daemon runs with
//! their own vault, against a stand-in Claude Code (`ec-fake-host`, copied
//! as `claude` onto the person's `PATH` with its mode beside it).
//!
//! - The probe runs in a probe home of its own under `/tmp`, beside the
//!   person's running daemon: no "second instance" refusal, no connection
//!   to the person's daemon (its connections are counted in its test
//!   trace, with a positive control), the person's vault byte for byte the
//!   same, and nothing in the person's home read or written but the switch
//!   files and the result cache (the rest is a tree of mode-0000 files,
//!   and no error comes from them). Its requests are approved from the
//!   person's terminal with every proof rule kept, so the output probe
//!   passes; its report on standard output is one JSON document.
//! - On macOS, with `HOME` as long as a real one (`/Users/` and 20
//!   characters), the probe's socket still fits `sun_path`.
//! - Run by an agent (directly, or through a terminal `script` makes for
//!   it, F-70's launcher case), no approval is given and the output probe
//!   reads `skipped (probe_needs_terminal)`; a host that requests and
//!   approves from its own session and terminal is refused (T9-3).
//! - Each hook-disabling switch in the person's real files gives its token.
//! - A host version outside the qualification table is `not_qualified`,
//!   never `failed` or `passed`, and nothing is started for it.
//! - The probe home is gone after a run, and after `kill -9` of the runner
//!   the next run removes what it left.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use envcloak_e2e::{Harness, Human, finish_within, quoted, text, write_script};
use envcloak_testkit::{TEST_PATH, labels, testkit_bin};
use serde_json::{Value, json};
use sha2::Digest as _;

/// One person's machine: their home, daemon and vault, and a stand-in
/// Claude Code on their `PATH`.
struct Machine {
    h: Harness,
    /// The directory `claude` is in.
    bin: PathBuf,
    /// Where the person runs the probe.
    cwd: PathBuf,
}

/// The stand-in, as `claude` in a directory of its own with `mode` beside
/// it (its home is a probe home, which holds no mode of its own).
fn host_dir(root: &Path, mode: &Value) -> PathBuf {
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::copy(testkit_bin("ec-fake-host"), bin.join("claude")).unwrap();
    std::fs::set_permissions(bin.join("claude"), std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(bin.join("ec-fake-host.json"), mode.to_string()).unwrap();
    bin
}

/// A person with a vault, their daemon tracing its connections, and the
/// stand-in set to `mode`.
fn machine(mode: &Value) -> Machine {
    let trace: &[(&str, &str)] = &[("ENVCLOAK_TEST_TRACE", "1")];
    let mut h = Harness::start_with(trace);
    let home = h.home.home();
    let pass = h.secret_file(labels::VAULT_PASSPHRASE, true);
    let kit = h.files().join("kit");
    let created = h.human(
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
        &[(3, &pass, true), (4, &kit, false)],
        &[],
    );
    assert_eq!(created.code, 0, "{}", created.all());
    let kit_text = std::fs::read_to_string(&kit).unwrap();
    h.add_canary(envcloak_testkit::Canary::new(
        envcloak_e2e::RECOVERY_KIT,
        kit_text.trim_end().to_owned(),
    ));
    let bin = host_dir(h.files(), mode);
    let cwd = home.join("work");
    std::fs::create_dir_all(&cwd).unwrap();
    Machine { h, bin, cwd }
}

impl Machine {
    fn path(&self) -> String {
        format!("PATH={}:{TEST_PATH}", self.bin.display())
    }

    /// `envcloak agents status --probe --agent claude-code [extra]` on the
    /// person's own terminal, with `env` (`NAME=value`) besides `PATH`.
    fn probe_on_terminal(&mut self, env: &[String], extra: &[&str]) -> Human {
        let path = self.path();
        let cli = self.h.cli();
        let mut argv = vec!["/usr/bin/env", path.as_str()];
        argv.extend(env.iter().map(String::as_str));
        argv.extend([
            cli.to_str().unwrap(),
            "agents",
            "status",
            "--probe",
            "--agent",
            "claude-code",
        ]);
        argv.extend_from_slice(extra);
        let cwd = self.cwd.clone();
        self.h.human_argv(&cwd, &argv, &[], &[])
    }

    /// The same, with `--json`, by a process with no terminal (CI's runner,
    /// as a script runs it): parsed, and the exit code.
    fn probe_without_terminal(&mut self, env: &[(&str, &str)]) -> (Value, i32) {
        let mut cmd = Command::new(self.h.cli());
        cmd.env_clear()
            .envs(self.h.home.vars())
            .env("PATH", format!("{}:{TEST_PATH}", self.bin.display()))
            .envs(env.iter().copied())
            .args([
                "agents",
                "status",
                "--probe",
                "--agent",
                "claude-code",
                "--json",
            ])
            .current_dir(&self.cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // A session of its own, without a terminal.
        envcloak_sys::new_session_on_spawn(&mut cmd, None).unwrap();
        let out = finish_within(cmd, Duration::from_secs(600));
        self.h.assert_clean("the probe's output", &out.stdout);
        self.h.assert_clean("the probe's errors", &out.stderr);
        let v = serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|e| panic!("not one JSON document ({e}):\n{}", text(&out)));
        (v, out.status.code().unwrap_or(-1))
    }

    /// The person's daemon's connections so far, from its test trace.
    fn connections(&self) -> usize {
        String::from_utf8_lossy(&self.h.daemon.log_bytes())
            .lines()
            .filter(|l| l.starts_with("envcloakd: test: connection opened"))
            .count()
    }
}

/// `--json`'s one report, or the test fails: one JSON document and
/// nothing else on standard output.
fn one_document(human: &Human) -> Value {
    serde_json::from_slice(&human.stdout)
        .unwrap_or_else(|e| panic!("not one JSON document ({e}):\n{}", human.all()))
}

fn probe_of(v: &Value) -> &Value {
    let probes = v["probes"].as_array().unwrap();
    assert_eq!(probes.len(), 1, "{v:#}");
    &probes[0]
}

fn surface<'v>(p: &'v Value, name: &str) -> &'v Value {
    p["surfaces"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["surface"] == name)
        .unwrap_or_else(|| panic!("no {name}: {p:#}"))
}

/// The reason tokens of `surface` in `agents status`'s row for Claude Code.
fn row_reasons(v: &Value, name: &str) -> Vec<String> {
    let row = v["agents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["agent"] == "claude-code")
        .unwrap_or_else(|| panic!("no row: {v:#}"));
    let s = row["surfaces"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["surface"] == name)
        .unwrap();
    s["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap().to_owned())
        .collect()
}

/// The probe homes in `/tmp` now (`ecp` and six letters or digits).
fn probe_homes() -> Vec<PathBuf> {
    let tmp = std::fs::canonicalize("/tmp").unwrap();
    let mut out: Vec<PathBuf> = std::fs::read_dir(&tmp)
        .unwrap()
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(envcloak_agents::probe::home::probe_home_name)
        })
        .map(|e| e.path())
        .filter(|p| p.join(envcloak_agents::probe::home::MARKER).exists())
        .collect();
    out.sort();
    out
}

/// Every file under `dir`, by its path, with its bytes' SHA-256.
fn digests(dir: &Path) -> BTreeMap<PathBuf, String> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            let m = std::fs::symlink_metadata(&p).unwrap();
            if m.is_dir() {
                stack.push(p);
            } else if m.is_file() {
                let d = std::fs::read(&p)
                    .map(|b| {
                        sha2::Sha256::digest(&b)
                            .iter()
                            .map(|x| format!("{x:02x}"))
                            .collect::<String>()
                    })
                    .unwrap_or_else(|_| format!("unreadable {:o}", m.permissions().mode()));
                out.insert(p, d);
            }
        }
    }
    out
}

/// A tree of mode-0000 files in the person's home, standing for what the
/// probe has no business reading: any read of one fails.
fn sentinel_tree(home: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for (dir, name) in [
        ("", ".envcloak-probe-sentinel"),
        (".ssh", "id_sentinel"),
        ("Documents", "notes"),
        (".config/gh", "hosts.yml"),
        (".codex", "auth.json"),
    ] {
        let d = home.join(dir);
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join(name);
        std::fs::write(&f, b"sentinel\n").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o000)).unwrap();
        files.push(f);
    }
    files
}

fn restore(files: &[PathBuf]) {
    for f in files {
        std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

/// The output probe passed, through approvals given from the person's
/// terminal; every other surface the stand-in serves passed.
fn assert_probed_and_approved(p: &Value) {
    assert_eq!(p["qualified"], true, "{p:#}");
    assert_eq!(p["needs_terminal"], false, "{p:#}");
    assert!(p["approvals"].as_u64().unwrap() >= 1, "{p:#}");
    assert_eq!(p["home_removed"], true, "{p:#}");
    for s in [
        "prompt_to_model",
        "transcript",
        "file_read",
        "shell",
        "output",
    ] {
        assert_eq!(surface(p, s)["probe"], "passed", "{s}: {p:#}");
    }
}

/// The probe beside the person's own running daemon. Mutations checked:
/// the probe's environment given the person's `XDG_RUNTIME_DIR` (on Linux
/// the probe daemon is then the person's socket: refused, and nothing is
/// probed); `agents install`'s report in the probe home left on this
/// process's standard output (not one JSON document); the host started in
/// this process's session, on its terminal (`HostSession` without its new
/// session): the probe's own approvals are then refused (T9-3) and the
/// output probe does not pass.
#[test]
fn the_probe_runs_beside_the_persons_daemon_and_touches_nothing_of_theirs() {
    let mut m = machine(&json!({}));
    let data = m.h.data_dir();
    let vault_before = digests(&data);
    assert!(!vault_before.is_empty(), "the person has a vault");
    let home = m.h.home.home();
    let sentinels = sentinel_tree(&home);
    let home_before = digests(&home);
    let homes_before = probe_homes();
    let opened_before = m.connections();

    let human = m.probe_on_terminal(&[], &["--json"]);
    let home_after_run = digests(&home);
    restore(&sentinels);
    assert_eq!(human.code, 0, "{}", human.all());
    assert!(human.stderr.is_empty(), "no error at all: {}", human.all());
    let v = one_document(&human);
    let p = probe_of(&v);
    assert_probed_and_approved(p);
    assert_eq!(p["kept"], true, "{p:#}");

    // The person's daemon saw no connection; then one command of theirs
    // is counted (positive control).
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(
        m.connections(),
        opened_before,
        "the probe connected to the person's daemon"
    );
    let listed = m.h.human(&home, &["pending", "--json"], &[], &[]);
    assert_eq!(listed.code, 0, "{}", listed.all());
    let end = Instant::now() + Duration::from_secs(30);
    while m.connections() == opened_before && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        m.connections() > opened_before,
        "the trace counts connections"
    );

    // The vault and everything in the home, the mode-0000 sentinels
    // included, as they were; the only new file is the result cache.
    let cache = data.join("agents").join("coverage.json");
    let mut vault_after = digests(&data);
    assert!(vault_after.remove(&cache).is_some(), "the result is kept");
    assert_eq!(vault_after, vault_before, "the person's vault changed");
    let mut home_after = home_after_run;
    home_after.remove(&cache);
    let sentinels_after: Vec<_> = sentinels.iter().map(|f| home_after.get(f)).collect();
    // Root, as in CI's user namespace, reads a file of mode 0000: there the
    // digests alone say they are as they were.
    if envcloak_sys::effective_uid() != 0 {
        assert!(
            sentinels_after
                .iter()
                .all(|d| d.is_some_and(|d| d.starts_with("unreadable")))
        );
    }
    assert_eq!(home_after, home_before, "the person's home changed");

    // No probe home is left.
    assert_eq!(probe_homes(), homes_before);
    m.h.assert_swept("after the probe");
}

/// On macOS, with `HOME` as long as `/Users/` and a 20-character name, the
/// probe runs and its socket fits `sun_path` (the probe home is under
/// `/tmp`). Mutation checked: the probe home made under EnvCloak's data
/// directory (`<data>/probe/`): its socket path is then about 120 bytes,
/// the probe home is refused with `probe_socket_too_long`, and nothing is
/// probed.
#[test]
fn a_home_as_long_as_a_real_one_leaves_the_socket_room() {
    if !cfg!(target_os = "macos") {
        return;
    }
    let mut m = machine(&json!({}));
    // `/Users/` and 20 characters: 27 bytes, made under `/tmp`.
    let dir = tempfile::Builder::new()
        .prefix("ecr")
        .tempdir_in("/tmp")
        .unwrap();
    let canon = std::fs::canonicalize(dir.path()).unwrap();
    let pad = 27usize.saturating_sub(canon.as_os_str().len() + 1);
    let long = canon.join("u".repeat(pad.max(1)));
    std::fs::create_dir(&long).unwrap();
    assert!(long.as_os_str().len() >= 27, "{}", long.display());
    let cwd = long.join("work");
    std::fs::create_dir(&cwd).unwrap();
    m.cwd = cwd;
    let human = m.probe_on_terminal(&[format!("HOME={}", long.display())], &["--json"]);
    assert_eq!(human.code, 0, "{}", human.all());
    let v = one_document(&human);
    assert_probed_and_approved(probe_of(&v));
    m.h.assert_swept("after the probe");
}

/// Run by an agent, the probe asks for no approval and makes no grant: the
/// output probe reads `skipped (probe_needs_terminal)`, and so through a
/// terminal `script` makes for the agent (F-70's launcher case). Mutation
/// checked: `ProbeDaemon::may_approve` answering yes whatever the daemon
/// says: the approver then asks, the daemon refuses, and the output probe
/// reads `failed`.
#[test]
fn run_by_an_agent_the_probe_gives_no_approval() {
    let mut m = machine(&json!({}));
    let cli = m.h.cli();
    let cwd = m.cwd.clone();
    let path = m.path();
    let direct = format!(
        "{path} {} agents status --probe --agent claude-code --json",
        quoted(cli.to_str().unwrap())
    );
    let script = if cfg!(target_os = "macos") {
        format!("/usr/bin/script -q /dev/null /usr/bin/env {direct}")
    } else {
        format!(
            "/usr/bin/script -qec {} /dev/null",
            quoted(&format!("/usr/bin/env {direct}"))
        )
    };
    for (case, line) in [
        ("directly", format!("/usr/bin/env {direct}")),
        ("through script", script),
    ] {
        let out = m.h.agent_line(&cwd, &line);
        assert_eq!(out.status.code(), Some(0), "{case}: {}", text(&out));
        // `script` copies its terminal's output, with carriage returns.
        let stdout = String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n");
        // and macOS's echoes the end of its input as `^D` first.
        let json_text = stdout.find('{').map_or("", |i| &stdout[i..]);
        let v: Value = serde_json::from_str(json_text)
            .unwrap_or_else(|e| panic!("{case}: not JSON ({e}): {}", text(&out)));
        let p = probe_of(&v);
        assert_eq!(p["needs_terminal"], true, "{case}: {p:#}");
        assert_eq!(p["approvals"], 0, "{case}: {p:#}");
        let output = surface(p, "output");
        assert_eq!(output["probe"], "skipped", "{case}: {p:#}");
        assert_eq!(
            output["why"],
            json!(["probe_needs_terminal"]),
            "{case}: {p:#}"
        );
        assert_eq!(p["server"]["probe"], "skipped", "{case}: {p:#}");
        assert!(
            row_reasons(&v, "output").contains(&"probe_needs_terminal".to_owned()),
            "{case}"
        );
    }
    m.h.assert_swept("after the agent's probes");
}

/// A host that makes a request and approves it from its own session and
/// terminal, as `HostSession` starts it, is refused (T9-3), and the
/// command is not run; the same request approved from the person's
/// terminal is granted (the control). Mutation checked: the host started
/// with the session and terminal of the approver (`HostSession` without its
/// new session, `the_probe_runs_beside...` above).
#[test]
fn an_approval_from_the_hosts_own_terminal_is_refused() {
    let mut m = machine(&json!({}));
    let root = m.h.home.root().to_path_buf();
    let project = root.join("t93");
    std::fs::create_dir_all(&project).unwrap();
    // One item, added by the person, bound by the project.
    let value_file = m.h.secret_file(labels::OPENAI_API_KEY, false);
    let cli_path = m.h.cli();
    let added = m.h.program(
        &cli_path,
        &["add", "--slug", "t93/key", "--env", "T93_KEY", "--stdin"],
        Some(&value_file),
    );
    assert_eq!(added.status.code(), Some(0), "{}", text(&added));
    std::fs::write(
        project.join("envcloak.toml"),
        "[project]\nname = \"t93\"\n\n[env]\nT93_KEY = \"t93/key\"\n",
    )
    .unwrap();
    let pass = m.h.secret_file(labels::VAULT_PASSPHRASE, false);
    let ran = root.join("t93-ran");
    let refused = root.join("t93-approve");
    let code = root.join("t93-code");
    let cli = quoted(m.h.cli().to_str().unwrap());
    // In one session on one terminal: the request, then its approval.
    // The request's id, as the person's listing gives it: the host's own
    // listing shows it no request it may not approve.
    let id_file = root.join("t93-id");
    let body = format!(
        "#!/bin/sh\n{cli} run --wait 2m -- /usr/bin/touch {ran} &\n\
         while [ ! -f {id} ]; do sleep 0.1; done\n\
         {cli} approve \"$(cat {id})\" --once --live T93_KEY --passphrase-fd 3 3<{pass} >/dev/null 2>{refused}\n\
         echo $? >{code}.tmp; mv {code}.tmp {code}\nwait\n",
        id = quoted(id_file.to_str().unwrap()),
        code = quoted(code.to_str().unwrap()),
        ran = quoted(ran.to_str().unwrap()),
        pass = quoted(pass.to_str().unwrap()),
        refused = quoted(refused.to_str().unwrap()),
    );
    let script = root.join("t93.sh");
    write_script(&script, &body);
    let mut cmd = Command::new(&script);
    cmd.env_clear()
        .envs(m.h.home.vars())
        .current_dir(&project)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let session = envcloak_agents::probe::HostSession::spawn(cmd).unwrap();
    let mut child = session.child;
    let end = Instant::now() + Duration::from_secs(120);
    let id = loop {
        let listed = m.h.human(&project, &["pending", "--json"], &[], &[]);
        let v = one_document(&listed);
        if let Some(id) = v["requests"][0]["request"].as_str() {
            break id.to_owned();
        }
        assert!(Instant::now() < end, "the host's request did not come");
        std::thread::sleep(Duration::from_millis(200));
    };
    std::fs::write(&id_file, &id).unwrap();
    // The control: once the host's own approval was refused, the person
    // approves the same request from their terminal.
    let approve_code = loop {
        if let Ok(c) = std::fs::read_to_string(&code) {
            break c.trim().parse::<i32>().unwrap();
        }
        assert!(Instant::now() < end, "the host's approval did not finish");
        std::thread::sleep(Duration::from_millis(100));
    };
    let said = std::fs::read_to_string(&refused).unwrap_or_default();
    m.h.assert_clean("the host's approval", said.as_bytes());
    assert_ne!(approve_code, 0, "the host approved its own request: {said}");
    assert!(said.contains("proof_refused"), "{said}");
    assert!(!ran.exists(), "the host's own approval ran the command");
    let pass_r = m.h.secret_file(labels::VAULT_PASSPHRASE, true);
    let approved = m.h.human(
        &project,
        &[
            "approve",
            &id,
            "--once",
            "--live",
            "T93_KEY",
            "--passphrase-fd",
            "3",
        ],
        &[(3, &pass_r, true)],
        &[],
    );
    assert_eq!(approved.code, 0, "{}", approved.all());
    let end = Instant::now() + Duration::from_secs(60);
    while child.try_wait().unwrap().is_none() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    drop(session.terminal);
    assert!(ran.exists(), "the person's approval ran the command");
    m.h.assert_swept("after the approvals");
}

/// Each hook-disabling switch in the person's own files gives its token in
/// the report the probe ends with (read-only; the managed files are
/// system paths, covered by M2-09's degrader tests with the path given).
/// Mutation checked: `--probe` reading the person's configuration without
/// their environment (`CLAUDE_CONFIG_DIR` dropped): its case fails.
#[test]
fn each_switch_in_the_persons_files_gives_its_token() {
    let mut m = machine(&json!({}));
    let home = m.h.home.home();
    let cwd = m.cwd.clone();
    let off = json!({"disableAllHooks": true}).to_string();
    let cases: [(&str, PathBuf, &str); 3] = [
        (
            "switched_off_user",
            home.join(".claude/settings.json"),
            &off,
        ),
        (
            "switched_off_project",
            cwd.join(".claude/settings.json"),
            &off,
        ),
        (
            "switched_off_local",
            cwd.join(".claude/settings.local.json"),
            &off,
        ),
    ];
    for (token, file, body) in &cases {
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, body).unwrap();
        let (v, code) = m.probe_without_terminal(&[]);
        assert_eq!(code, 0, "{token}: {v:#}");
        assert!(
            row_reasons(&v, "prompt_to_model").contains(&(*token).to_owned()),
            "{token}: {v:#}"
        );
        std::fs::remove_file(file).unwrap();
    }
    let moved = m.h.home.root().join("claude-config");
    std::fs::create_dir_all(&moved).unwrap();
    let (v, _) = m.probe_without_terminal(&[("CLAUDE_CONFIG_DIR", moved.to_str().unwrap())]);
    assert!(
        row_reasons(&v, "prompt_to_model").contains(&"config_dir_moved".to_owned()),
        "{v:#}"
    );
    // With none, none of these tokens.
    let (v, _) = m.probe_without_terminal(&[]);
    let reasons = row_reasons(&v, "prompt_to_model");
    for t in [
        "switched_off_user",
        "switched_off_project",
        "switched_off_local",
        "config_dir_moved",
    ] {
        assert!(!reasons.contains(&t.to_owned()), "{t}: {v:#}");
    }
    m.h.assert_swept("after the switches");
}

/// A host version outside the qualification table is not probed: every
/// outcome `not_qualified`, never `failed` or `passed`, the message names
/// the versions CI results exist for, the run exits 0, and no probe home is
/// made. Mutation checked: `not_qualified` reported as `failed`.
#[test]
fn a_version_outside_the_table_is_not_qualified() {
    let mut m = machine(&json!({"version": "2.1.999"}));
    let before = probe_homes();
    let human = m.probe_on_terminal(&[], &[]);
    assert_eq!(human.code, 0, "{}", human.all());
    assert!(
        human.out().contains(
            "probe not qualified for Claude Code v2.1.999; CI results for v2.1.280 are in \
             docs/INSTALLERS.md"
        ),
        "{}",
        human.all()
    );
    let (v, code) = m.probe_without_terminal(&[]);
    assert_eq!(code, 0);
    let p = probe_of(&v);
    assert_eq!(p["qualified"], false, "{p:#}");
    assert_eq!(p["probed"], false, "{p:#}");
    assert_eq!(p["runs"], 0, "{p:#}");
    for s in p["surfaces"].as_array().unwrap() {
        assert_eq!(s["probe"], "not_qualified", "{p:#}");
    }
    assert_eq!(p["server"]["probe"], "not_qualified", "{p:#}");
    assert_eq!(probe_homes(), before, "nothing is made for it");
    m.h.assert_swept("after the probe");
}

/// The runner killed with SIGKILL mid-probe leaves its probe home; its
/// daemon, whose terminal the runner held, hangs up and ends; the next run
/// removes the home. Mutation checked: the sweep at the start of a run
/// taken out: the home is left.
#[test]
fn the_probe_home_is_cleaned_after_kill_9() {
    let mut m = machine(&json!({}));
    let before = probe_homes();
    let mut cmd = Command::new(m.h.cli());
    cmd.env_clear()
        .envs(m.h.home.vars())
        .env("PATH", format!("{}:{TEST_PATH}", m.bin.display()))
        .args([
            "agents",
            "status",
            "--probe",
            "--agent",
            "claude-code",
            "--json",
        ])
        .current_dir(&m.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    envcloak_sys::new_session_on_spawn(&mut cmd, None).unwrap();
    let mut child = cmd.spawn().unwrap();
    let end = Instant::now() + Duration::from_secs(120);
    let left = loop {
        let new: Vec<PathBuf> = probe_homes()
            .into_iter()
            .filter(|p| !before.contains(p))
            .collect();
        // Once the probe home has its daemon's socket, the run is going.
        if let Some(p) = new.into_iter().find(|p| has_socket(p)) {
            break p;
        }
        assert!(Instant::now() < end, "no probe home appeared");
        std::thread::sleep(Duration::from_millis(50));
    };
    // This test's own unreaped child.
    child.kill().unwrap();
    let _ = child.wait();
    assert!(left.exists());
    let (v, code) = m.probe_without_terminal(&[]);
    assert_eq!(code, 0, "{v:#}");
    assert!(v["swept"]["removed"].as_u64().unwrap() >= 1, "{v:#}");
    assert!(!left.exists(), "the killed run's probe home is left");
    m.h.assert_swept("after the sweep");
}

/// Whether a probe home holds a socket yet (its daemon listens).
fn has_socket(root: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt as _;
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let Ok(t) = e.file_type() else { continue };
            if t.is_socket() {
                return true;
            }
            if t.is_dir() {
                stack.push(e.path());
            }
        }
    }
    false
}
