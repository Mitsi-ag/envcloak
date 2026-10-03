//! `envcloak agents install` and `uninstall` on the real, pinned hosts (M2
//! plan M2-08; gate 38's installer half, gate 34's hook denial,
//! advisory), on configurations the hosts' own CLIs wrote (L-02):
//!
//! - `claude mcp add-json` and `codex mcp add` register another server
//!   (Codex's with a literal in its `env`), and the person keeps
//!   instructions and settings of their own (a literal in Claude Code's
//!   `env` block, between two places install edits; Codex's
//!   `network_access = false`); the files are then older than 2 minutes,
//!   as a person's are. Neither literal ever reaches EnvCloak's state,
//!   `<data>/agents/`, swept after install and after uninstall (lesson
//!   L-12).
//! - Install, then uninstall at once: every file byte for byte as it was,
//!   what install created gone, and each host's own `mcp list` still
//!   listing the other server (and, while installed, EnvCloak's). The
//!   rules file loads in the pinned Codex (`codex execpolicy check`), and
//!   forbids what it says.
//! - Installed, the hosts load it: on the scripted model, Claude Code's
//!   and Codex's `PreToolUse` hooks stop a command that prints the
//!   environment, with EnvCloak's marker in what the host sends its model
//!   next, while the control command runs; a prompt holding a key-shaped
//!   token never reaches the model, while a plain one does. Codex runs
//!   with `--dangerously-bypass-hook-trust`, standing for the person's
//!   trust in `/hooks` (untrusted hooks do not run: M2-04 measured it).
//! - K-01: on Linux, with or without consent, no socket allowance or
//!   broader network setting is written for either host; on macOS, with
//!   consent, a command in Codex's `workspace-write` sandbox reaches
//!   EnvCloak's socket and nothing else (a loopback TCP listener, directly
//!   and through Codex's proxy, and another Unix socket all refused).

use std::path::{Path, PathBuf};
use std::time::Duration;

use envcloak_e2e::{Harness, age, quoted, text, versions_toml, write_script};
use envcloak_testkit::agents::{AgentHome, Host, HostFlags, HostRun, Installed, require};
use envcloak_testkit::{Canary, TEST_PATH, daemon_socket, fresh_seed, labels, sweep_dir};
use serde_json::{Value, json};

use super::skeleton::last_tool_output;

/// The person's vault, created on a terminal of their own; the daemon
/// keeps it unlocked.
fn vault(h: &mut Harness) {
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
    h.add_canary(Canary::new(
        envcloak_e2e::RECOVERY_KIT,
        kit_text.trim_end().to_owned(),
    ));
}

/// A directory holding `claude` and `codex`, each starting the pinned
/// build: what the installer finds on the person's `PATH`.
fn host_bin(h: &Harness, hosts: &[&AgentHome]) -> PathBuf {
    let bin = h.home.root().join("host-bin");
    std::fs::create_dir_all(&bin).unwrap();
    for a in hosts {
        let name = match a.host {
            Host::ClaudeCode => "claude",
            Host::Codex => "codex",
        };
        write_script(
            &bin.join(name),
            &format!(
                "#!/bin/sh\nexec {} \"$@\"\n",
                quoted(a.installed.exe.to_str().unwrap())
            ),
        );
    }
    bin
}

/// `envcloak agents <args> --json`, by the person, with the hosts on
/// `PATH` and Claude Code's temporary directory where the harness keeps
/// it: the report and the exit code.
fn agents(h: &mut Harness, bin: &Path, claude_tmp: &Path, args: &[&str]) -> (Value, i32) {
    let path = format!("PATH={}:{TEST_PATH}", bin.display());
    let tmp = format!("CLAUDE_CODE_TMPDIR={}", claude_tmp.display());
    let cli = h.cli();
    let mut argv = vec![
        "/usr/bin/env",
        path.as_str(),
        tmp.as_str(),
        cli.to_str().unwrap(),
        "agents",
    ];
    argv.extend_from_slice(args);
    argv.push("--json");
    let home = h.home.home();
    let out = h.human_argv(&home, &argv, &[], &[]);
    let v = serde_json::from_slice(&out.stdout).unwrap_or_else(|_| panic!("{}", out.all()));
    (v, out.code)
}

/// The notes a report has for `host`.
fn notes(v: &Value, host: &str) -> Vec<String> {
    v["hosts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|x| x["host"] == host)
        .flat_map(|x| x["notes"].as_array().unwrap().iter())
        .map(|n| n["name"].as_str().unwrap().to_owned())
        .collect()
}

/// The request the script answered with `pick`, as the host sent it.
fn request(run: &HostRun, pick: &str) -> String {
    run.model
        .requests
        .iter()
        .find(|r| r.pick.as_deref() == Some(pick))
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .unwrap_or_else(|| panic!("no request for {pick}: {run:?}"))
}

/// The person's own files, and what each host's CLI wrote: the files an
/// install changes, as bytes.
const FILES: [&str; 5] = [
    ".claude/CLAUDE.md",
    ".claude/settings.json",
    ".claude.json",
    ".codex/AGENTS.md",
    ".codex/config.toml",
];
const CREATED: [&str; 2] = [".codex/hooks.json", ".codex/rules/envcloak.rules"];

/// See the module documentation.
///
/// Mutations checked: a rules example that its rule does not match (the
/// `head -n 5 .env` the first version had): the pinned Codex refuses to
/// load the file ("expected every example to match at least one rule")
/// and the execpolicy check fails. The hook's denial for `Bash` answered
/// with no decision (`hook::decide` returning `NoDecision` for
/// `PreToolUse`): `printenv` runs, no marker reaches the model, and this
/// fails. Names read in their own case (`names_dotenv` without its
/// lower-casing): Claude Code's Read of `.ENV.staging` returns the file and
/// this fails. The unchanged-text journal (`hunks::hunks` keeping the
/// whole span between the first and last change, with its old text):
/// the sweep of `<data>/agents/` finds the settings.json literal and this
/// fails.
#[test]
fn the_installer_on_the_hosts_own_configs() {
    let claude_found = Installed::find(&versions_toml(), Host::ClaudeCode.id(), "native");
    let codex_found = Installed::find(&versions_toml(), Host::Codex.id(), "native");
    let (Some(ci), Some(xi)) = (
        require(claude_found, "M2-08 install (Claude Code)"),
        require(codex_found, "M2-08 install (Codex)"),
    ) else {
        return;
    };
    let mut h = Harness::start();
    vault(&mut h);
    let claude = AgentHome::within(&h.home, Host::ClaudeCode, ci);
    let codex = AgentHome::within(&h.home, Host::Codex, xi);
    let home = h.home.home();
    let bin = host_bin(&h, &[&claude, &codex]);
    let tmp = claude.claude_tmp();

    // Literals the person wrote into the configs: never in EnvCloak's
    // state (not the harness's canaries, which the configs would hold).
    let seed = || format!("{:016x}{:016x}", fresh_seed(), fresh_seed());
    let lits = [
        Canary::new("SETTINGS_ENV_LITERAL", format!("ecst{}", seed())),
        Canary::new("CODEX_ENV_LITERAL", format!("eccx{}", seed())),
    ];
    let state = h.data_dir().join("agents");
    let swept = |when: &str| {
        let hits = sweep_dir(&state, &lits);
        assert!(
            hits.is_empty(),
            "{when}: {} hit(s) in <data>/agents",
            hits.len()
        );
    };

    // What the hosts' CLIs write, and the person's own files.
    let other = json!({"command": "/usr/bin/true", "args": ["serve"]});
    let added = claude.host_cli(&[
        "mcp",
        "add-json",
        "--scope",
        "user",
        "other",
        &other.to_string(),
    ]);
    assert!(added.status.success(), "{}", text(&added));
    let env = format!("TOKEN={}", lits[1].as_str());
    let added = codex.host_cli(&[
        "mcp",
        "add",
        "other",
        "--env",
        &env,
        "--",
        "/usr/bin/true",
        "serve",
    ]);
    assert!(added.status.success(), "{}", text(&added));
    // A setting of the person's near the top of config.toml: with consent
    // on macOS, install edits it and the end of the file.
    let toml_path = home.join(".codex/config.toml");
    let theirs = std::fs::read_to_string(&toml_path).unwrap();
    assert!(theirs.contains(lits[1].as_str()), "codex mcp add --env");
    std::fs::write(
        &toml_path,
        format!("[sandbox_workspace_write]\nnetwork_access = false\n\n{theirs}"),
    )
    .unwrap();
    std::fs::create_dir_all(home.join(".claude")).unwrap();
    std::fs::write(home.join(".claude/CLAUDE.md"), "# Mine\n\nUse tabs.\n").unwrap();
    std::fs::write(
        home.join(".claude/settings.json"),
        format!(
            "{{\n  \"permissions\": {{\n    \"allow\": [\"Bash(npm test)\"]\n  }},\n  \
             \"env\": {{\n    \"API_TOKEN\": \"{}\"\n  }},\n  \"model\": \"sonnet\"\n}}\n",
            lits[0].as_str()
        ),
    )
    .unwrap();
    std::fs::write(home.join(".codex/AGENTS.md"), "# Codex notes\n").unwrap();
    for f in FILES {
        age(&home.join(f), Duration::from_secs(600));
    }
    let before: Vec<Vec<u8>> = FILES
        .iter()
        .map(|f| std::fs::read(home.join(f)).unwrap())
        .collect();
    let lists = |want_envcloak: bool| {
        for a in [&claude, &codex] {
            let out = a.host_cli(&["mcp", "list"]);
            let said = text(&out);
            assert!(out.status.success(), "{said}");
            assert!(
                said.contains("other"),
                "{:?} lost the other server: {said}",
                a.host
            );
            assert_eq!(
                said.contains("envcloak"),
                want_envcloak,
                "{:?}: {said}",
                a.host
            );
        }
    };
    lists(false);

    // Install, with consent; the hosts list both servers; uninstall at
    // once.
    let (v, code) = agents(
        &mut h,
        &bin,
        &tmp,
        &["install", "--yes", "--consent-sandbox-sockets"],
    );
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["complete"], true, "{v}");
    swept("after install");
    for host in ["claude-code", "codex"] {
        assert!(
            v["hosts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|x| x["host"] == host && x["found"] == "installed"),
            "{host}: {v}"
        );
    }
    lists(true);
    let settings: Value =
        serde_json::from_slice(&std::fs::read(home.join(".claude/settings.json")).unwrap())
            .unwrap();
    let toml = std::fs::read_to_string(home.join(".codex/config.toml")).unwrap();
    assert!(!toml.contains("domains"), "{toml}");
    assert!(!toml.contains("approval"), "{toml}");
    assert_eq!(
        toml.contains("network_access = true"),
        cfg!(target_os = "macos"),
        "{toml}"
    );
    if cfg!(target_os = "linux") {
        // K-01, with consent given: nothing for the socket, nothing broader.
        assert!(settings["sandbox"].get("network").is_none(), "{settings}");
        for word in ["network_proxy", "unix_sockets"] {
            assert!(!toml.contains(word), "{word}: {toml}");
        }
        for host in ["claude-code", "codex"] {
            assert!(
                notes(&v, host).contains(&"sandbox_blocks_socket".to_owned()),
                "{host}: {v}"
            );
        }
    }
    // The rules load in the pinned Codex and forbid what they say.
    let rules = home.join(".codex/rules/envcloak.rules");
    for (cmd, forbidden) in [
        (&["printenv"][..], true),
        (&["cat", ".env"], true),
        (&["envcloak", "approve", "REQUEST"], true),
        (&["cat", ".env.example"], false),
        (&["envcloak", "run", "--", "npm", "test"], false),
    ] {
        let mut a = vec!["execpolicy", "check", "--rules", rules.to_str().unwrap()];
        a.extend_from_slice(cmd);
        let out = codex.host_cli(&a);
        let said = text(&out);
        assert!(out.status.success(), "{cmd:?}: {said}");
        assert_eq!(
            said.contains("\"decision\":\"forbidden\""),
            forbidden,
            "{cmd:?}: {said}"
        );
    }
    let (u, code) = agents(&mut h, &bin, &tmp, &["uninstall", "--yes"]);
    assert_eq!(code, 0, "{u}");
    swept("after uninstall");
    for (f, b) in FILES.iter().zip(&before) {
        assert!(
            &std::fs::read(home.join(f)).unwrap() == b,
            "{f} is not as it was"
        );
    }
    for f in CREATED {
        assert!(!home.join(f).exists(), "{f}");
    }
    lists(false);

    // Installed again, the hosts load it.
    let (v, code) = agents(&mut h, &bin, &tmp, &["install", "--yes"]);
    assert_eq!(code, 0, "{v}");
    let script = |cmd: &str| {
        json!({"steps": [
            {"shell": cmd},
            {"shell": "echo ecctl-hook-control"},
            {"say": "done"},
        ]})
    };
    let pasted = Canary::new(
        "PASTED_TOKEN",
        format!("ecpk{:016x}{:016x}", fresh_seed(), fresh_seed()),
    );
    for (a, flags, command) in [
        (&claude, HostFlags::claude("default", &["Bash"]), "printenv"),
        (
            &codex,
            HostFlags::codex("read-only", "never").with(&["--dangerously-bypass-hook-trust"]),
            // Not `printenv`, which EnvCloak's rules forbid before any
            // hook runs: the hook's own denial is what this shows.
            "env",
        ),
    ] {
        let run = a.run(&script(command), "Check the environment.", &flags, &home);
        h.record(&format!("{:?} stdout", a.host), &run.output.stdout);
        h.record(&format!("{:?} stderr", a.host), &run.output.stderr);
        for r in &run.model.requests {
            h.record(&format!("{:?} request {}", a.host, r.seq), &r.body);
        }
        assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
        let denied = request(&run, "step 1");
        // The output is not shown: had the command run, it would hold
        // the environment.
        assert!(
            denied.contains("[envcloak:env_dump]"),
            "{:?}: no marker after {command} ({} bytes of tool output)",
            a.host,
            last_tool_output(&denied).len()
        );
        assert!(
            !last_tool_output(&denied).contains("PATH="),
            "{:?}: {command} ran",
            a.host
        );
        let control = last_tool_output(&request(&run, "step 2"));
        assert!(
            control.contains("ecctl-hook-control"),
            "{:?}: {control}",
            a.host
        );
        println!(
            "measurement: {:?} {} after agents install: {command} denied by EnvCloak's hook, the \
             control ran",
            a.host, a.installed.pin.version
        );

        // A prompt holding a key-shaped token never reaches the model.
        let prompt = format!("Deploy with {}", pasted.as_str());
        let blocked = a.run(
            &json!({"steps": [{"say": "not blocked"}]}),
            &prompt,
            &flags,
            &home,
        );
        assert!(
            blocked.model.model_calls().is_empty(),
            "{:?}: a prompt holding a key reached the model",
            a.host
        );
        for r in &blocked.model.requests {
            assert!(
                !String::from_utf8_lossy(&r.body).contains(pasted.as_str()),
                "{:?}",
                a.host
            );
        }
        // What the host printed is its own (Codex's `exec` prints the
        // prompt it was given); whether it shows EnvCloak's reason is
        // recorded.
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&blocked.output.stdout),
            String::from_utf8_lossy(&blocked.output.stderr)
        );
        println!(
            "measurement: {:?} {} after agents install: a pasted key-shaped prompt blocked \
             (exit {:?}), the model never called; EnvCloak's reason shown: {}; the host printed \
             the prompt: {}",
            a.host,
            a.installed.pin.version,
            blocked.output.status.code(),
            said.contains("[envcloak:key_in_prompt]"),
            said.contains(pasted.as_str())
        );
    }

    // Claude Code's own file tool reaches the hook as well: a Read of an
    // env file of another profile, in another case, and on Linux of a
    // process's environment. (Grep, ToolSearch and the deferred Monitor
    // were measured unavailable in the pinned version's non-interactive
    // session, "No such tool available", so their decisions are tested on
    // the captured payload's shape: tests/hook_bypass.rs.)
    let staging = home.join(".ENV.staging");
    std::fs::write(&staging, "STAGING_PROBE=1\n").unwrap();
    let mut steps =
        vec![json!({"tool": "Read", "input": {"file_path": staging.to_str().unwrap()}})];
    if cfg!(target_os = "linux") {
        steps.push(json!({"tool": "Read", "input": {"file_path": "/proc/self/environ"}}));
    }
    steps.push(json!({"shell": "echo ecctl-hook-control"}));
    steps.push(json!({"say": "done"}));
    let run = claude.run(
        &json!({ "steps": steps }),
        "Read the env file.",
        &HostFlags::claude("default", &["Bash"]),
        &home,
    );
    h.record("claude read stdout", &run.output.stdout);
    h.record("claude read stderr", &run.output.stderr);
    let read = last_tool_output(&request(&run, "step 1"));
    assert!(
        read.contains("[envcloak:env_file]"),
        "Read of .ENV.staging: {read}"
    );
    assert!(!read.contains("STAGING_PROBE"), "the file was read");
    let mut next = 2;
    if cfg!(target_os = "linux") {
        let environ = last_tool_output(&request(&run, "step 2"));
        assert!(
            environ.contains("[envcloak:env_dump]"),
            "Read of /proc/self/environ: {environ}"
        );
        assert!(!environ.contains("PATH="), "the environment was read");
        next = 3;
    }
    let control = last_tool_output(&request(&run, &format!("step {next}")));
    assert!(control.contains("ecctl-hook-control"), "{control}");
    println!(
        "measurement: Claude Code {} after agents install: Read of .ENV.staging denied by \
         EnvCloak's hook{}, the control ran",
        claude.installed.pin.version,
        if cfg!(target_os = "linux") {
            ", and of /proc/self/environ"
        } else {
            ""
        }
    );
    std::fs::remove_file(&staging).unwrap();

    // Uninstall after the hosts ran: Claude Code rewrote ~/.claude.json
    // and the harness set its model keys in config.toml since, which
    // EnvCloak takes for the host's own writes: two minutes on, only
    // EnvCloak's entries come out.
    for f in [
        ".codex/config.toml",
        ".claude.json",
        ".claude/settings.json",
    ] {
        age(&home.join(f), Duration::from_secs(180));
    }
    let (u, code) = agents(&mut h, &bin, &tmp, &["uninstall", "--yes"]);
    assert_eq!(code, 0, "{u}");
    lists(false);
    for f in [
        ".claude/settings.json",
        ".codex/config.toml",
        ".claude/CLAUDE.md",
    ] {
        let t = std::fs::read_to_string(home.join(f)).unwrap();
        assert!(!t.contains("envcloak"), "{f}: {t}");
    }
    for f in CREATED {
        assert!(!home.join(f).exists(), "{f}");
    }
    swept("at the end");
    claude.check_isolated();
    h.assert_swept("M2-08 install");
}

/// K-01 on macOS, as the installer writes it: with consent, a command in
/// Codex's `workspace-write` sandbox reaches EnvCloak's socket and nothing
/// else. On Linux there is no such setting (the test above shows none is
/// written).
///
/// Mutations checked: the socket allowance written without consent's
/// `unix_sockets` rule (only `network_access` and the proxy enabled):
/// `envcloak status` no longer reaches the daemon and this fails. A
/// `domains` allow rule for `127.0.0.1` added to the proxy settings in
/// `hosts::codex::config_settings`: the request through Codex's proxy
/// reaches the loopback listener and this fails (the Codex review: the
/// probe checked raw sockets only).
#[test]
fn codex_reaches_the_socket_and_nothing_else_after_install() {
    if !cfg!(target_os = "macos") {
        eprintln!(
            "codex_reaches_the_socket_and_nothing_else_after_install: macOS only (K-01: no \
             allowance on Linux)"
        );
        return;
    }
    let found = Installed::find(&versions_toml(), Host::Codex.id(), "native");
    let Some(xi) = require(found, "M2-08 Codex socket allowance") else {
        return;
    };
    let mut h = Harness::start();
    vault(&mut h);
    let codex = AgentHome::within(&h.home, Host::Codex, xi);
    let bin = host_bin(&h, &[&codex]);
    let tmp = h.home.root().join("claude-tmp");
    let (v, code) = agents(
        &mut h,
        &bin,
        &tmp,
        &[
            "install",
            "--agent",
            "codex",
            "--consent-sandbox-sockets",
            "--yes",
        ],
    );
    assert_eq!(code, 0, "{v}");
    let home = h.home.home();
    let toml = std::fs::read_to_string(home.join(".codex/config.toml")).unwrap();
    let socket = daemon_socket(&h.home);
    assert!(
        toml.contains(&format!("\"{}\" = \"allow\"", socket.display())),
        "{toml}"
    );
    // Something else to reach: a loopback TCP listener and another Unix
    // socket.
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = tcp.local_addr().unwrap().port();
    let other = h.home.root().join("other.sock");
    let _unix = std::os::unix::net::UnixListener::bind(&other).unwrap();
    let probe = h.home.root().join("egress.py");
    std::fs::write(&probe, EGRESS).unwrap();
    let cli = h.cli();
    let command = format!(
        "{} status 2>&1 | head -n 1; python3 {} raw {port} {}",
        quoted(cli.to_str().unwrap()),
        quoted(probe.to_str().unwrap()),
        quoted(other.to_str().unwrap())
    );
    // Through the proxy, in a call of its own: Codex fails the whole call
    // when its proxy blocks a request (docs/AGENTS.md, K-01's table).
    let proxied = format!(
        "python3 {} proxied {port} {}",
        quoted(probe.to_str().unwrap()),
        quoted(other.to_str().unwrap())
    );
    let script = json!({"steps": [{"shell": command}, {"shell": proxied}, {"say": "done"}]});
    let run = codex.run(
        &script,
        "Check the daemon.",
        &HostFlags::codex("workspace-write", "never").with(&["--dangerously-bypass-hook-trust"]),
        &home,
    );
    h.record("codex stdout", &run.output.stdout);
    h.record("codex stderr", &run.output.stderr);
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    let out = last_tool_output(&request(&run, "step 1"));
    println!(
        "measurement: Codex {} workspace-write after agents install --consent-sandbox-sockets: \
         {}",
        codex.installed.pin.version,
        out.split_whitespace().collect::<Vec<_>>().join(" ")
    );
    assert!(out.contains("daemon: running"), "the socket: {out}");
    for key in ["TCP", "UNIX"] {
        assert!(
            out.contains(&format!("{key}NO")),
            "{key} was reached from the sandbox: {out}"
        );
        assert!(!out.contains(&format!("{key}OK")), "{key}: {out}");
    }
    let through = last_tool_output(&request(&run, "step 2"));
    println!(
        "measurement: Codex {} workspace-write, a request through its proxy to a loopback \
         listener: {}",
        codex.installed.pin.version,
        through.split_whitespace().collect::<Vec<_>>().join(" ")
    );
    assert!(
        !through.contains("PROXIEDOK")
            && (through.contains("PROXIEDNO") || through.contains("was blocked")),
        "through the proxy: {through}"
    );
    // Nothing reached the listener, directly or through the proxy: the
    // independent check (the listener never answers, so a request the
    // proxy lets through ends in the probe's own timeout).
    tcp.set_nonblocking(true).unwrap();
    assert!(
        matches!(tcp.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
        "a connection reached the loopback listener"
    );
    h.assert_swept("M2-08 Codex socket allowance");
}

/// What a sandboxed command tries besides EnvCloak's socket: a loopback
/// TCP listener, directly and through the proxy Codex points the command
/// at, and another Unix socket. Each prints `<KEY>OK` or `<KEY>NO <why>`
/// (the keys built at run time, so the command's text never holds them);
/// with no proxy in the command's environment, `PROXIEDNO no_proxy`.
const EGRESS: &str = r#"import errno, os, socket, sys, urllib.request
mode, port, other = sys.argv[1], int(sys.argv[2]), sys.argv[3]
def raw(key, family, addr):
    s = None
    try:
        s = socket.socket(family)
        s.settimeout(5)
        s.connect(addr)
        print(key + "OK")
    except OSError as e:
        print(key + "NO", errno.errorcode.get(e.errno, "timeout"))
    finally:
        if s is not None:
            s.close()
if mode == "raw":
    raw("TCP", socket.AF_INET, ("127.0.0.1", port))
    raw("UNIX", socket.AF_UNIX, other)
    sys.exit(0)
proxy = next((os.environ[k] for k in ("http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY") if os.environ.get(k)), None)
if proxy is None:
    print("PROXIED" + "NO", "no_proxy")
else:
    if "://" not in proxy:
        proxy = "http://" + proxy
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy}))
    try:
        opener.open("http://127.0.0.1:%d/" % port, timeout=5)
        print("PROXIED" + "OK")
    except Exception as e:
        print("PROXIED" + "NO", type(e).__name__)
"#;
