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

/// `envcloak agents <args> --json` in `cwd` (a project's directory), as
/// [`agents`] runs it.
fn agents_in(
    h: &mut Harness,
    bin: &Path,
    claude_tmp: &Path,
    cwd: &Path,
    args: &[&str],
) -> (Value, i32) {
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
    let out = h.human_argv(cwd, &argv, &[], &[]);
    let v = serde_json::from_slice(&out.stdout).unwrap_or_else(|_| panic!("{}", out.all()));
    (v, out.code)
}

/// Whether the report has `host`'s change of a file refused for `reason`.
fn refused_as(v: &Value, host: &str, reason: &str) -> bool {
    v["hosts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|x| x["host"] == host)
        .flat_map(|x| x["changes"].as_array().unwrap().iter())
        .any(|c| c["outcome"] == "refused" && c["reason"] == reason)
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
/// lower-casing): on macOS, Claude Code's Read of `.ENV.staging` is stopped
/// by its own deny rule instead, with no EnvCloak marker, and this fails. The unchanged-text journal (`hunks::hunks` keeping the
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

    // A command whose file the reader cannot resolve (fail closed: the
    // orchestrator's finding) is not let through: Claude Code puts it to
    // the person (`permissionDecision: "ask"`), which `-p` cannot answer,
    // so it does not run; Codex runs a call its hook asks about (Codex's
    // cycle178 measurement), so there the hook denies it. Either way the
    // file's text never reaches the model, and the control after it runs.
    let probe = format!("ecunres{:016x}", fresh_seed());
    std::fs::write(home.join("plain.txt"), format!("{probe}\n")).unwrap();
    for (a, flags) in [
        (&claude, HostFlags::claude("default", &["Bash"])),
        (
            &codex,
            HostFlags::codex("read-only", "never").with(&["--dangerously-bypass-hook-trust"]),
        ),
    ] {
        let run = a.run(
            &script("f=plain.txt; cat \"$f\""),
            "Show the file.",
            &flags,
            &home,
        );
        h.record(
            &format!("{:?} unresolved stdout", a.host),
            &run.output.stdout,
        );
        h.record(
            &format!("{:?} unresolved stderr", a.host),
            &run.output.stderr,
        );
        assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
        let after = request(&run, "step 1");
        assert!(
            !after.contains(&probe),
            "{:?}: the unresolved read ran and its output reached the model",
            a.host
        );
        let control = last_tool_output(&request(&run, "step 2"));
        assert!(
            control.contains("ecctl-hook-control"),
            "{:?}: {control}",
            a.host
        );
        println!(
            "measurement: {:?} {}: an unresolved read did not run; EnvCloak's marker \
             [envcloak:unresolved] in the next request: {}",
            a.host,
            a.installed.pin.version,
            after.contains("[envcloak:unresolved]")
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
    // Neither file is read. On macOS EnvCloak's hook is what refuses the
    // env file (measured: the hook runs before Claude Code's own deny
    // rule, which stops it when the hook does not); on Linux, CI measured
    // Claude Code refusing a file in that directory before any hook runs,
    // so there the refusal's source is recorded, not asserted.
    // What refused, named from a fixed list: no tool output is printed
    // (it could hold fixture data; Codex's cycle 321 review).
    let shown = |out: &str| -> String {
        [
            ("[envcloak:env_file]", "EnvCloak's hook (env_file)"),
            ("[envcloak:env_dump]", "EnvCloak's hook (env_dump)"),
            (
                "denied by your permission settings",
                "Claude Code's permission settings",
            ),
            (
                "would block or produce infinite output",
                "Claude Code's device-file check",
            ),
        ]
        .iter()
        .find(|(needle, _)| out.contains(needle))
        .map_or_else(
            || format!("an answer of {} bytes from no known source", out.len()),
            |(_, source)| (*source).to_owned(),
        )
    };
    let read = last_tool_output(&request(&run, "step 1"));
    assert!(!read.contains("STAGING_PROBE"), "the file was read");
    let by_hook = read.contains("[envcloak:env_file]");
    if cfg!(target_os = "macos") {
        assert!(by_hook, "Read of .ENV.staging: {}", shown(&read));
    }
    let mut next = 2;
    let mut environ_by_hook = None;
    if cfg!(target_os = "linux") {
        let environ = last_tool_output(&request(&run, "step 2"));
        assert!(!environ.contains("PATH="), "the environment was read");
        environ_by_hook = Some(environ.contains("[envcloak:env_dump]"));
        println!(
            "measurement: Claude Code {} after agents install, Read of /proc/self/environ: {}",
            claude.installed.pin.version,
            shown(&environ)
        );
        next = 3;
    }
    let control = last_tool_output(&request(&run, &format!("step {next}")));
    assert!(
        control.contains("ecctl-hook-control"),
        "the control's output ({} bytes) is not its echo",
        control.len()
    );
    println!(
        "measurement: Claude Code {} after agents install: Read of .ENV.staging refused \
         (EnvCloak's marker: {by_hook}; {}), of /proc/self/environ: {environ_by_hook:?}, the \
         control ran",
        claude.installed.pin.version,
        shown(&read)
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

/// Codex review: in a fresh home the registration created
/// `~/.claude.json`, and uninstall took EnvCloak's entry out and left the
/// file. In a home with no `.claude.json`, install creates it with
/// EnvCloak's entry alone (through its own writer); uninstall right after
/// removes it, and the files install created go too. Installed again, the
/// pinned Claude Code (L-02) lists EnvCloak's server from the file and
/// writes its own state into it (measured with 2.1.280: `claude mcp list`
/// rewrites a file without its start-up fields); the file is then Claude
/// Code's as much as EnvCloak's, and uninstall, once the 2 minutes since
/// Claude Code's write are over, takes out EnvCloak's entry only: Claude
/// Code still reads the file, and no longer lists the server.
///
/// Mutation checked: the file's creation not recorded (`FileRecord`'s
/// `created` always `false` in `Writer::try_change`): uninstall leaves an
/// empty `.claude.json` and this fails.
#[test]
fn a_fresh_claude_home_comes_back_without_a_claude_json() {
    let claude_found = Installed::find(&versions_toml(), Host::ClaudeCode.id(), "native");
    let Some(ci) = require(claude_found, "M2-08 fresh home (Claude Code)") else {
        return;
    };
    let mut h = Harness::start();
    vault(&mut h);
    let claude = AgentHome::within(&h.home, Host::ClaudeCode, ci);
    let home = h.home.home();
    let bin = host_bin(&h, &[&claude]);
    let tmp = claude.claude_tmp();
    assert!(!home.join(".claude.json").exists(), "not a fresh home");
    let (v, code) = agents(
        &mut h,
        &bin,
        &tmp,
        &["install", "--agent", "claude-code", "--yes"],
    );
    assert_eq!(code, 0, "{v}");
    assert!(home.join(".claude.json").exists(), "{v}");
    let (u, code) = agents(
        &mut h,
        &bin,
        &tmp,
        &["uninstall", "--agent", "claude-code", "--yes"],
    );
    assert_eq!(code, 0, "{u}");
    for f in [".claude.json", ".claude/settings.json", ".claude/CLAUDE.md"] {
        assert!(!home.join(f).exists(), "{f} is still there: {u}");
    }
    // Again, and Claude Code reads the file and writes its own state in.
    let (v, code) = agents(
        &mut h,
        &bin,
        &tmp,
        &["install", "--agent", "claude-code", "--yes"],
    );
    assert_eq!(code, 0, "{v}");
    let out = claude.host_cli(&["mcp", "list"]);
    let said = text(&out);
    assert!(out.status.success() && said.contains("envcloak"), "{said}");
    age(&home.join(".claude.json"), Duration::from_secs(600));
    let (u, code) = agents(
        &mut h,
        &bin,
        &tmp,
        &["uninstall", "--agent", "claude-code", "--yes"],
    );
    assert_eq!(code, 0, "{u}");
    let left: Value =
        serde_json::from_slice(&std::fs::read(home.join(".claude.json")).unwrap_or_default())
            .unwrap_or(Value::Null);
    assert!(left.is_object(), "{u}");
    assert!(
        left.get("mcpServers")
            .and_then(|m| m.get("envcloak"))
            .is_none(),
        "{left}"
    );
    let out = claude.host_cli(&["mcp", "list"]);
    let said = text(&out);
    assert!(out.status.success() && !said.contains("envcloak"), "{said}");
    claude.check_isolated();
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

/// Codex review, round 6 (high), on the pinned Codex (L-02): Codex merges
/// a trusted project's `.codex/config.toml` into the user's settings, so a
/// proxy domain rule there, which on its own turns nothing on, is switched
/// on by the socket allowance's `network_access` and proxy. Measured
/// first: with the allowance as round 5 wrote it (by hand here), a request
/// from Codex's `workspace-write` sandbox in that project goes through
/// Codex's proxy to a loopback listener (the control: the rule widens the
/// allowance on this host). Then `agents install --consent-sandbox-sockets`
/// writes the server and no allowance, reports the step refused
/// (`network_settings_present`) and exits 1, and from the same project the
/// request reaches nothing (directly or through the proxy).
///
/// Mutation checked: `codex_layers::other_layers_fit` answering `Ok`: the
/// installer writes the allowance, the request reaches the listener after
/// install, and this fails.
#[test]
fn codex_inherited_network_rules_keep_the_socket_allowance_out() {
    if !cfg!(target_os = "macos") {
        eprintln!(
            "codex_inherited_network_rules_keep_the_socket_allowance_out: macOS only (K-01: no \
             allowance on Linux)"
        );
        return;
    }
    let found = Installed::find(&versions_toml(), Host::Codex.id(), "native");
    let Some(xi) = require(found, "M2-08 Codex inherited network rules") else {
        return;
    };
    let mut h = Harness::start();
    vault(&mut h);
    let mut codex = AgentHome::within(&h.home, Host::Codex, xi);
    let bin = host_bin(&h, &[&codex]);
    let tmp = h.home.root().join("claude-tmp");
    let home = h.home.home();
    let proj = home.join("work/proj");
    std::fs::create_dir_all(proj.join(".git")).unwrap();
    std::fs::create_dir_all(proj.join(".codex")).unwrap();
    std::fs::write(
        proj.join(".codex/config.toml"),
        "[features.network_proxy.domains]\n\"127.0.0.1\" = \"allow\"\n",
    )
    .unwrap();
    let proj = std::fs::canonicalize(&proj).unwrap();
    let trust = format!(
        "[projects.\"{}\"]\ntrust_level = \"trusted\"\n",
        proj.display()
    );
    let socket = daemon_socket(&h.home);
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = tcp.local_addr().unwrap().port();
    let other = h.home.root().join("other.sock");
    let _unix = std::os::unix::net::UnixListener::bind(&other).unwrap();
    let probe = h.home.root().join("egress.py");
    std::fs::write(&probe, EGRESS).unwrap();
    let proxied = format!(
        "python3 {} proxied {port} {}",
        quoted(probe.to_str().unwrap()),
        quoted(other.to_str().unwrap())
    );
    let flags =
        HostFlags::codex("workspace-write", "never").with(&["--dangerously-bypass-hook-trust"]);
    let drained = |tcp: &std::net::TcpListener| {
        tcp.set_nonblocking(true).unwrap();
        let mut n = 0;
        while tcp.accept().is_ok() {
            n += 1;
        }
        n
    };

    // The control: the allowance as round 5 wrote it, by hand.
    codex.codex_config(&format!(
        "{trust}\n[sandbox_workspace_write]\nnetwork_access = true\n\n\
         [features.network_proxy]\nenabled = true\n\n\
         [features.network_proxy.unix_sockets]\n\"{}\" = \"allow\"\n",
        socket.display()
    ));
    let script = json!({"steps": [{"shell": proxied}, {"say": "done"}]});
    let run = codex.run(&script, "Check.", &flags, &proj);
    h.record("codex stdout (control)", &run.output.stdout);
    h.record("codex stderr (control)", &run.output.stderr);
    let through = last_tool_output(&request(&run, "step 1"));
    // The listener never answers: a request the proxy lets through
    // reaches it (a connection to accept) and ends in the probe's timeout.
    let reached = drained(&tcp);
    println!(
        "measurement: Codex {} workspace-write in a trusted project whose settings allow \
         127.0.0.1, with the round-5 allowance: connections reaching the loopback listener {}; \
         {}",
        codex.installed.pin.version,
        reached,
        through.split_whitespace().collect::<Vec<_>>().join(" ")
    );
    assert!(
        reached > 0 && !through.contains("was blocked"),
        "the control: the project's rule did not widen the allowance here: {through}"
    );

    // EnvCloak's install, with consent.
    codex.codex_config(&trust);
    age(&home.join(".codex/config.toml"), Duration::from_secs(600));
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
    let toml = std::fs::read_to_string(home.join(".codex/config.toml")).unwrap();
    let run = codex.run(&script, "Check.", &flags, &proj);
    h.record("codex stdout", &run.output.stdout);
    h.record("codex stderr", &run.output.stderr);
    let through = last_tool_output(&request(&run, "step 1"));
    let reached = drained(&tcp);
    println!(
        "measurement: Codex {} workspace-write in that project after agents install \
         --consent-sandbox-sockets: connections reaching the loopback listener {}; {}",
        codex.installed.pin.version,
        reached,
        through.split_whitespace().collect::<Vec<_>>().join(" ")
    );
    assert_eq!(
        reached, 0,
        "the loopback listener was reached after install"
    );
    assert!(!through.contains("PROXIEDOK"), "{through}");
    assert!(!toml.contains("network_access"), "{toml}");
    assert!(toml.contains("[mcp_servers.envcloak]"), "{toml}");
    assert_eq!(code, 1, "{v}");
    assert!(refused_as(&v, "codex", "network_settings_present"), "{v}");
    h.assert_swept("M2-08 Codex inherited network rules");
}

/// `git <args>` in `dir` with a cleared environment and no user or system
/// configuration, within a bound; it must succeed.
fn git(dir: &Path, args: &[&str]) {
    let mut cmd = std::process::Command::new("git");
    cmd.args([
        "-c",
        "user.name=EnvCloak test",
        "-c",
        "user.email=test@example.invalid",
        "-c",
        "init.defaultBranch=main",
        "-c",
        "core.hooksPath=/dev/null",
    ])
    .args(args)
    .current_dir(dir)
    .env_clear()
    .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
    .env("HOME", dir)
    .env("GIT_CONFIG_NOSYSTEM", "1")
    .env("LC_ALL", "C")
    .stdin(std::process::Stdio::null())
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped());
    let out = envcloak_testkit::agents::finish_capped(cmd, Duration::from_secs(60), 1 << 20);
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The verifier's round-7 layout: a trusted project in Codex's directory
/// holding a folder link to a folder whose `.codex` holds the rule, and
/// `allow_symlinked_codex_home = true` in the user's `config.toml`.
const OPTED_OUT: &str = "a folder link in Codex's directory, opted out";
/// The same, the folder behind the link holding no network setting.
const OPTED_OUT_NO_RULE: &str = "a folder link in Codex's directory, opted out, no rule";

/// The layouts of [`codex_linked_layers_keep_the_socket_allowance_out`]:
/// in `work` (or Codex's directory), a trusted project with a proxy
/// domain rule for `127.0.0.1` where Codex reads it; the project, the
/// session's folder, and the flags naming it.
fn linked_layout(
    name: &str,
    work: &Path,
    codex_home: &Path,
    rule: &str,
) -> (PathBuf, PathBuf, Vec<String>) {
    match name {
        OPTED_OUT | OPTED_OUT_NO_RULE => {
            let p = codex_home.join("proj");
            std::fs::create_dir_all(p.join(".git")).unwrap();
            std::fs::create_dir_all(work.join("elsewhere/.codex")).unwrap();
            let body = if name == OPTED_OUT {
                rule
            } else {
                "model_verbosity = \"low\"\n"
            };
            std::fs::write(work.join("elsewhere/.codex/config.toml"), body).unwrap();
            std::os::unix::fs::symlink(work.join("elsewhere"), p.join("link")).unwrap();
            let through = p.join("link").to_str().unwrap().to_owned();
            (p.clone(), p, vec!["-C".to_owned(), through])
        }
        "a .codex link to a folder" => {
            let p = work.join("linked");
            std::fs::create_dir_all(p.join(".git")).unwrap();
            std::fs::create_dir_all(work.join("held")).unwrap();
            std::fs::write(work.join("held/config.toml"), rule).unwrap();
            std::os::unix::fs::symlink(work.join("held"), p.join(".codex")).unwrap();
            (p.clone(), p, Vec::new())
        }
        "a linked worktree" => {
            let main = work.join("main");
            std::fs::create_dir_all(&main).unwrap();
            git(&main, &["init", "-q"]);
            git(&main, &["commit", "-q", "--allow-empty", "-m", "start"]);
            let tree = work.join("trees/wt");
            git(&main, &["worktree", "add", "-q", tree.to_str().unwrap()]);
            std::fs::create_dir_all(tree.join(".codex")).unwrap();
            std::fs::write(tree.join(".codex/config.toml"), rule).unwrap();
            (main, tree, Vec::new())
        }
        _ => {
            let p = work.join("named");
            std::fs::create_dir_all(p.join(".git")).unwrap();
            std::fs::create_dir_all(work.join("elsewhere/.codex")).unwrap();
            std::fs::write(work.join("elsewhere/.codex/config.toml"), rule).unwrap();
            std::os::unix::fs::symlink(work.join("elsewhere"), p.join("link")).unwrap();
            let through = p.join("link").to_str().unwrap().to_owned();
            (p.clone(), p, vec!["-C".to_owned(), through])
        }
    }
}

/// The verifier's round-6 and round-7 findings (Codex F-128) and their
/// class, on the pinned Codex (L-02): layers of a trusted project that
/// Codex reads and the check did not look at. Four layouts, each with a
/// proxy domain rule for `127.0.0.1` where Codex reads it:
///
/// - the project's `.codex` is a link to a folder holding the rule;
/// - a linked git worktree of the project (made by git, outside it) holds
///   the rule in its own `.codex/config.toml`, and the session runs there
///   (Codex trusts it through its main checkout);
/// - a folder link inside the project leads to a folder whose `.codex`
///   holds the rule, and the session is named through the link (`codex
///   exec -C <project>/link`);
/// - the same inside Codex's own directory, with `allow_symlinked_codex_home
///   = true` in the user's `config.toml`: the opt-out Codex's refusal of a
///   symlinked writable root names, which lets a writable root at or
///   beneath Codex's directory be named through links (and a control with
///   no rule behind the link).
///
/// Measured first, for each, with the allowance as round 5 wrote it (by
/// hand): from the first two, a request from Codex's `workspace-write`
/// sandbox goes through Codex's proxy to a loopback listener (Codex reads
/// that layer, and its rule widens the allowance); then `agents install
/// --consent-sandbox-sockets` writes the server and no allowance, reports
/// the step refused (`network_settings_present`) and exits 1, and the same
/// request reaches nothing. The third is measured with EnvCloak's own
/// allowance: the check does not follow folder links, so install writes
/// it (exit 0); the session named through the link, with the allowance
/// and the rule behind the link both there, runs no command at all (Codex
/// refuses a writable root named through a symlink: "symlinked writable
/// roots are not supported"), and one in the project itself reaches
/// nothing through the proxy (the rule behind the link is not read
/// there). The fourth is measured after its install, then by hand (a
/// session named through a link may make Codex record that name as a
/// trusted project, which the check then reads, hiding whether it read
/// the opt-out): install withholds the allowance
/// (`network_settings_present`, exit 1) and the listener is not reached;
/// then, with the round-5 allowance by hand, the session named through the
/// link runs its command and the rule behind the link widens the
/// allowance to the listener. Its control, the opt-out and no rule:
/// install writes the allowance (exit 0), and the session through the
/// link runs its command and reaches nothing through the proxy.
///
/// Mutations checked, each against real Codex: `.codex` looked at without
/// following a symlink (`symlink_metadata` in `codex_layers::dot_codex`):
/// the first layout's allowance is written and the listener reached after
/// install; `linked_worktrees` not called: the second's; folder links
/// followed in every walk (as the round-7 draft did): the third layout's
/// install withholds the allowance, which no session there could use, and
/// exits 1; the opt-out not read (`symlinked_home_allowed` answering
/// `false`): the fourth layout's allowance is written and the listener
/// reached after install.
#[test]
fn codex_linked_layers_keep_the_socket_allowance_out() {
    if !cfg!(target_os = "macos") {
        eprintln!(
            "codex_linked_layers_keep_the_socket_allowance_out: macOS only (K-01: no allowance \
             on Linux)"
        );
        return;
    }
    let found = Installed::find(&versions_toml(), Host::Codex.id(), "native");
    let Some(xi) = require(found, "M2-08 Codex linked layers") else {
        return;
    };
    let rule = "[features.network_proxy.domains]\n\"127.0.0.1\" = \"allow\"\n";
    let refused_root = "symlinked writable roots are not supported";
    for name in [
        "a .codex link to a folder",
        "a linked worktree",
        "a folder link named by -C",
        OPTED_OUT,
        OPTED_OUT_NO_RULE,
    ] {
        let through_link = name == "a folder link named by -C";
        let opted_out = name == OPTED_OUT || name == OPTED_OUT_NO_RULE;
        let mut h = Harness::start();
        vault(&mut h);
        let mut codex = AgentHome::within(&h.home, Host::Codex, xi.clone());
        let bin = host_bin(&h, &[&codex]);
        let tmp = h.home.root().join("claude-tmp");
        let home = h.home.home();
        let work = home.join("work");
        std::fs::create_dir_all(&work).unwrap();
        let work = std::fs::canonicalize(&work).unwrap();
        let codex_home = std::fs::canonicalize(home.join(".codex")).unwrap();
        let (project, cwd, extra) = linked_layout(name, &work, &codex_home, rule);
        let extra: Vec<&str> = extra.iter().map(String::as_str).collect();
        let base =
            HostFlags::codex("workspace-write", "never").with(&["--dangerously-bypass-hook-trust"]);
        let flags = base.clone().with(&extra);
        let trust = format!(
            "{}[projects.\"{}\"]\ntrust_level = \"trusted\"\n",
            if opted_out {
                "allow_symlinked_codex_home = true\n"
            } else {
                ""
            },
            project.display()
        );
        let socket = daemon_socket(&h.home);
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = tcp.local_addr().unwrap().port();
        tcp.set_nonblocking(true).unwrap();
        let other = h.home.root().join("other.sock");
        let _unix = std::os::unix::net::UnixListener::bind(&other).unwrap();
        let probe = h.home.root().join("egress.py");
        std::fs::write(&probe, EGRESS).unwrap();
        let proxied = format!(
            "python3 {} proxied {port} {}",
            quoted(probe.to_str().unwrap()),
            quoted(other.to_str().unwrap())
        );
        let script = json!({"steps": [{"shell": proxied}, {"say": "done"}]});
        let drained = |tcp: &std::net::TcpListener| {
            let mut n = 0;
            while tcp.accept().is_ok() {
                n += 1;
            }
            n
        };
        let measure = |h: &mut Harness,
                       codex: &AgentHome,
                       when: &str,
                       flags: &HostFlags|
         -> (usize, String) {
            let run = codex.run(&script, "Check.", flags, &cwd);
            h.record(&format!("codex stdout ({when})"), &run.output.stdout);
            h.record(&format!("codex stderr ({when})"), &run.output.stderr);
            let said = last_tool_output(&request(&run, "step 1"));
            let reached = drained(&tcp);
            println!(
                "measurement: Codex {} workspace-write, {name}, {when}: connections reaching the \
                 loopback listener {}; {}",
                codex.installed.pin.version,
                reached,
                said.split_whitespace().collect::<Vec<_>>().join(" ")
            );
            (reached, said)
        };

        // The control: the round-5 allowance, by hand. (A session named
        // through a link is measured with EnvCloak's own allowance first:
        // Codex may record that name as a trusted project of its own,
        // which the check would then read; the opted-out layout's control
        // comes after its install.)
        let round5 = format!(
            "{trust}\n[sandbox_workspace_write]\nnetwork_access = true\n\n\
             [features.network_proxy]\nenabled = true\n\n\
             [features.network_proxy.unix_sockets]\n\"{}\" = \"allow\"\n",
            socket.display()
        );
        if !through_link && !opted_out {
            codex.codex_config(&round5);
            let (reached, said) = measure(&mut h, &codex, "with the round-5 allowance", &flags);
            assert!(
                reached > 0 && !said.contains("was blocked"),
                "the control ({name}): the layer did not widen the allowance here: {said}"
            );
        }

        // EnvCloak's install, with consent.
        codex.codex_config(&trust);
        age(&home.join(".codex/config.toml"), Duration::from_secs(600));
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
        let toml = std::fs::read_to_string(home.join(".codex/config.toml")).unwrap();
        assert!(toml.contains("[mcp_servers.envcloak]"), "{name}: {toml}");
        let (reached, said) = measure(&mut h, &codex, "after agents install", &flags);
        assert_eq!(
            reached, 0,
            "{name}: the loopback listener was reached after install"
        );
        assert!(!said.contains("PROXIEDOK"), "{name}: {said}");
        if through_link {
            assert_eq!(code, 0, "{name}: {v}");
            assert!(toml.contains("network_access = true"), "{name}: {toml}");
            // The allowance and the rule behind the link are both there:
            // the command does not run.
            assert!(said.contains(refused_root), "{name}: {said}");
            // The project itself, as Codex names it: the rule behind the
            // link is not read, and the proxy blocks the listener (Codex
            // fails the whole call when its proxy blocks a request).
            let (reached, said) = measure(&mut h, &codex, "after install, in the project", &base);
            assert_eq!(reached, 0, "{name}: the listener was reached");
            assert!(
                said.contains("PROXIEDNO") || said.contains("was blocked"),
                "{name}: {said}"
            );
        } else if name == OPTED_OUT_NO_RULE {
            // The control: nothing behind the link widens the allowance,
            // which is written, and the command runs and reaches nothing.
            assert_eq!(code, 0, "{name}: {v}");
            assert!(toml.contains("network_access = true"), "{name}: {toml}");
            assert!(!said.contains(refused_root), "{name}: {said}");
            assert!(
                said.contains("PROXIEDNO") || said.contains("was blocked"),
                "{name}: {said}"
            );
        } else {
            assert!(!toml.contains("network_access"), "{name}: {toml}");
            assert_eq!(code, 1, "{name}: {v}");
            assert!(
                refused_as(&v, "codex", "network_settings_present"),
                "{name}: {v}"
            );
        }
        if name == OPTED_OUT {
            // The control, after the install: with the allowance by hand,
            // the session named through the link reads the rule behind it.
            codex.codex_config(&round5);
            let (reached, said) = measure(&mut h, &codex, "with the round-5 allowance", &flags);
            assert!(
                reached > 0 && !said.contains("was blocked"),
                "the control ({name}): the layer did not widen the allowance here: {said}"
            );
        }
        h.assert_swept("M2-08 Codex linked layers");
    }
}

/// Codex review, round 6, on the pinned Codex (L-02): which instruction
/// file a session reads, and how much of it. Measured first, and the
/// installer then judged by it:
///
/// - a trusted project's `project_doc_fallback_filenames` replaces the
///   user's: with both lists' files there, Codex sends the project's
///   file's text to the model and not the user's; `agents install
///   --project` puts the block into the project's file, and the next
///   session's request holds the block;
/// - `project_root_markers` decides the project root: with `.hg` as the
///   marker, Codex sends the root's file before the working directory's;
///   once the root's file fills the 32 KiB budget, the working
///   directory's file is not sent at all, and `agents install --project`
///   there refuses the block (`instruction_budget`) instead of writing
///   where it is never read.
///
/// Mutations checked: the fallback lists joined (as before round 6): the
/// block goes into the user's file, which Codex does not read, and this
/// fails. `.git` as the only marker: the block is written into the
/// working directory's file past the budget, and this fails.
#[test]
fn codex_reads_the_project_block_where_install_put_it() {
    let found = Installed::find(&versions_toml(), Host::Codex.id(), "native");
    let Some(xi) = require(found, "M2-08 Codex merged instruction settings") else {
        return;
    };
    let mut h = Harness::start();
    vault(&mut h);
    let mut codex = AgentHome::within(&h.home, Host::Codex, xi);
    let bin = host_bin(&h, &[&codex]);
    let tmp = h.home.root().join("claude-tmp");
    let home = h.home.home();
    let tag = format!("{:x}", fresh_seed());
    let word = |what: &str| format!("ec{what}file{tag}");
    let say = json!({"steps": [{"say": "done"}]});
    let flags = HostFlags::codex("read-only", "never");

    let proj = home.join("work/merged");
    std::fs::create_dir_all(proj.join(".git")).unwrap();
    std::fs::create_dir_all(proj.join(".codex")).unwrap();
    std::fs::write(
        proj.join(".codex/config.toml"),
        "project_doc_fallback_filenames = [\"CLAUDE.md\"]\n",
    )
    .unwrap();
    std::fs::write(proj.join("GEMINI.md"), format!("# {}\n", word("user"))).unwrap();
    std::fs::write(proj.join("CLAUDE.md"), format!("# {}\n", word("project"))).unwrap();
    let proj = std::fs::canonicalize(&proj).unwrap();
    codex.codex_config(&format!(
        "project_doc_fallback_filenames = [\"GEMINI.md\"]\n\n[projects.\"{}\"]\ntrust_level = \
         \"trusted\"\n",
        proj.display()
    ));
    let run = codex.run(&say, "Hello.", &flags, &proj);
    let sent = request(&run, "step 0");
    println!(
        "measurement: Codex {} with a user list [GEMINI.md] and a project list [CLAUDE.md], \
         both there: project file sent {}, user file sent {}",
        codex.installed.pin.version,
        sent.contains(&word("project")),
        sent.contains(&word("user"))
    );
    assert!(
        sent.contains(&word("project")) && !sent.contains(&word("user")),
        "the measurement: Codex read another file than the project's list names"
    );
    let (v, code) = agents_in(
        &mut h,
        &bin,
        &tmp,
        &proj,
        &["install", "--project", "--agent", "codex", "--yes"],
    );
    assert_eq!(code, 0, "{v}");
    let block = envcloak_agents::blocks::block();
    let project = std::fs::read_to_string(proj.join("CLAUDE.md")).unwrap();
    assert!(project.ends_with(&block), "{v}");
    assert_eq!(
        std::fs::read_to_string(proj.join("GEMINI.md")).unwrap(),
        format!("# {}\n", word("user"))
    );
    let run = codex.run(&say, "Hello.", &flags, &proj);
    let sent = request(&run, "step 0");
    // A line of the block, as JSON carries it.
    let line = block
        .lines()
        .find(|l| l.contains("envcloak run --"))
        .unwrap()
        .to_owned();
    let encoded = serde_json::to_string(&line).unwrap();
    assert!(
        sent.contains(encoded.trim_matches('"')),
        "the block did not reach Codex's model"
    );

    // Markers: `.hg` puts the root above the working directory.
    let hg = home.join("work/hg");
    let sub = hg.join("s");
    std::fs::create_dir_all(hg.join(".hg")).unwrap();
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(hg.join("AGENTS.md"), format!("# {}\n", word("root"))).unwrap();
    std::fs::write(sub.join("AGENTS.md"), format!("# {}\n", word("sub"))).unwrap();
    let hg = std::fs::canonicalize(&hg).unwrap();
    let sub = std::fs::canonicalize(&sub).unwrap();
    codex.codex_config(&format!(
        "project_root_markers = [\".hg\"]\n\n[projects.\"{}\"]\ntrust_level = \"trusted\"\n",
        hg.display()
    ));
    let run = codex.run(&say, "Hello.", &flags, &sub);
    let sent = request(&run, "step 0");
    println!(
        "measurement: Codex {} with project_root_markers [.hg], in a folder below the root: \
         root file sent {}, the folder's sent {}",
        codex.installed.pin.version,
        sent.contains(&word("root")),
        sent.contains(&word("sub"))
    );
    assert!(sent.contains(&word("root")) && sent.contains(&word("sub")));
    // The root's file now fills the budget.
    std::fs::write(
        hg.join("AGENTS.md"),
        format!("# {}\n{}\n", word("root"), "y".repeat(33 * 1024)),
    )
    .unwrap();
    let run = codex.run(&say, "Hello.", &flags, &sub);
    let sent = request(&run, "step 0");
    println!(
        "measurement: Codex {} once the root's file is past 32 KiB: the folder's file sent {}",
        codex.installed.pin.version,
        sent.contains(&word("sub"))
    );
    assert!(
        !sent.contains(&word("sub")),
        "the measurement: Codex read past its budget"
    );
    let (v, code) = agents_in(
        &mut h,
        &bin,
        &tmp,
        &sub,
        &["install", "--project", "--agent", "codex", "--yes"],
    );
    assert_eq!(code, 1, "{v}");
    let change = &v["project"]["changes"][0];
    assert_eq!(change["reason"], "instruction_budget", "{v}");
    assert_eq!(
        std::fs::read_to_string(sub.join("AGENTS.md")).unwrap(),
        format!("# {}\n", word("sub"))
    );
    h.assert_swept("M2-08 Codex merged instruction settings");
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

/// The verifier's finding: the Claude Code matcher was said to name every
/// tool of the pinned version that runs a command or reads a file, while
/// the pinned version had more (Artifact's `file_path`, Workflow's
/// `scriptPath`, ReadMcpResourceDirTool, NotebookEdit). The pinned
/// package's own `sdk-tools.d.ts` is the oracle: every tool whose input
/// names a command, a local path or a URI is in EnvCloak's matcher, or is
/// one that reads nothing it would send on (listed here, with why). A new
/// pin with another such tool fails this until it is classified.
///
/// Mutation checked: `Artifact` taken out of `TOOL_MATCHER`: this fails.
#[test]
fn every_tool_of_the_pinned_claude_code_that_reads_a_file_is_hooked() {
    let found = Installed::find(&versions_toml(), Host::ClaudeCode.id(), "npm");
    let Some(ci) = require(found, "M2-08 matcher (Claude Code sdk-tools.d.ts)") else {
        return;
    };
    let d = ci
        .dir
        .join("node_modules/@anthropic-ai/claude-code/sdk-tools.d.ts");
    let text = std::fs::read_to_string(&d).unwrap();
    // Each `export interface <Name>Input {`, and its fields.
    let mut tools: Vec<(String, Vec<String>)> = Vec::new();
    let mut current: Option<(String, Vec<String>)> = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("export interface ") {
            if let Some(name) = rest.strip_suffix("Input {") {
                current = Some((name.to_owned(), Vec::new()));
                continue;
            }
        }
        if line == "}" {
            tools.extend(current.take());
            continue;
        }
        if let (Some((_, fields)), Some(field)) = (
            current.as_mut(),
            line.strip_prefix("  ")
                .filter(|l| !l.starts_with(' '))
                .and_then(|l| l.split_once(':'))
                .map(|(f, _)| f),
        ) {
            let field = field.trim_end_matches('?').trim_matches('"');
            if !field.is_empty() && !field.starts_with('/') && !field.starts_with('*') {
                fields.push(field.to_owned());
            }
        }
    }
    let tool = |iface: &str| match iface {
        "FileEdit" => "Edit".to_owned(),
        "FileRead" => "Read".to_owned(),
        "FileWrite" => "Write".to_owned(),
        "ReadMcpResourceDir" => "ReadMcpResourceDirTool".to_owned(),
        "ReadMcpResource" => "ReadMcpResourceTool".to_owned(),
        other => other.to_owned(),
    };
    const READS: [&str; 8] = [
        "command",
        "file_path",
        "file_paths",
        "notebook_path",
        "path",
        "local_path",
        "scriptPath",
        "uri",
    ];
    // Tools with such a field that read nothing they would send on.
    const NOT_READS: [(&str, &str); 2] = [
        ("Write", "it writes a file and reads none"),
        ("EnterWorktree", "its path is a worktree to switch into"),
    ];
    let hooked: Vec<&str> = envcloak_agents::hosts::claude::TOOL_MATCHER
        .split('|')
        .collect();
    let mut seen = Vec::new();
    for (iface, fields) in &tools {
        if !fields.iter().any(|f| READS.contains(&f.as_str())) {
            continue;
        }
        let t = tool(iface);
        seen.push(t.clone());
        assert!(
            hooked.contains(&t.as_str()) || NOT_READS.iter().any(|(n, _)| *n == t),
            "{t} ({iface}Input: {fields:?}) reads a file, runs a command or names a URI, \
             and is not in the matcher {hooked:?}"
        );
    }
    // The positive control: the parse found the tools it must.
    for t in [
        "Bash",
        "Read",
        "Edit",
        "Artifact",
        "Workflow",
        "ReadMcpResourceDirTool",
    ] {
        assert!(
            seen.iter().any(|s| s == t),
            "{t} not found in {d:?}: {seen:?}"
        );
    }
}
