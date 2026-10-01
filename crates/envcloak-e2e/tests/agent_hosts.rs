//! The pinned agent hosts against the scripted model (M2 plan task M2-04,
//! D-13, R-M2-66, R-M2-78, R-M2-88): the stub answers scripted turns to
//! Claude Code and Codex; a canary a scripted turn prints with plain
//! `printf` is found in the tool result the host sent its model and in
//! that host's transcript (the positive control); a run with no canary
//! leaves none anywhere (the negative control). A command that prints a
//! canary names it in two pieces, so only what it printed can hold it
//! whole.
//!
//! Each host runs in an isolated home with a cleared environment, its
//! flags pinned per run (D-13), and `HTTPS_PROXY` pointed at the model,
//! which refuses and records every tunnel. A host that is not installed
//! (scripts/install-agent-hosts.py) skips its test with a line on
//! standard error, unless ENVCLOAK_TEST_REQUIRE_AGENT_HOSTS is set, as in
//! CI's agent jobs.
//!
//! Lines starting `measurement:` are what docs/AGENTS.md's host behaviour
//! table and docs/ACCEPTANCE.md record; CI prints them on both systems.
#![allow(clippy::unwrap_used)]

use std::path::Path;

use envcloak_agents::probe::model::{QUALIFIED, SERVER};
use envcloak_e2e::{bin_dir, versions_toml};
use envcloak_testkit::agents::{AgentHome, Host, HostFlags, HostRun, Installed, pins, require};
use envcloak_testkit::transcripts::{OTHER, Sweep};
use envcloak_testkit::{Canary, by_label, canaries, fresh_seed, labels};
use serde_json::json;

fn host(h: Host, variant: &str, test: &str) -> Option<AgentHome> {
    let found = Installed::find(&versions_toml(), h.id(), variant);
    require(found, test).map(|i| AgentHome::start(h, i))
}

/// The flags every run here pins (D-13): Claude Code `-p` in the default
/// permission mode with Bash allowed; Codex `exec` in its workspace-write
/// sandbox with approval policy `never`. Never a bypass mode.
fn flags(h: Host) -> HostFlags {
    match h {
        Host::ClaudeCode => HostFlags::claude("default", &["Bash"]),
        Host::Codex => HostFlags::codex("workspace-write", "never"),
    }
}

/// The store a host keeps its transcripts in.
fn transcript_store(h: Host) -> &'static str {
    match h {
        Host::ClaudeCode => "claude/projects",
        Host::Codex => "codex/sessions",
    }
}

fn os() -> &'static str {
    std::env::consts::OS
}

fn measure(a: &AgentHome, what: &str, value: impl std::fmt::Display) {
    println!(
        "measurement: {what} host={} version={} os={}: {value}",
        a.installed.pin.id,
        a.installed.pin.version,
        os()
    );
}

/// A command that prints each of `values` on a line of its own, each
/// named in two pieces: the command's own text never holds one whole, so
/// a whole one anywhere is what the command printed.
fn print_split(values: &[&str]) -> String {
    values
        .iter()
        .map(|v| {
            let mid = v.len() / 2;
            let (a, b) = v.split_at(
                v.char_indices()
                    .map(|(i, _)| i)
                    .find(|&i| i >= mid)
                    .unwrap_or(mid),
            );
            format!(
                "printf '%s%s\\n' {} {}",
                envcloak_e2e::quoted(a),
                envcloak_e2e::quoted(b)
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Linux: whether this process runs in a user namespace (CI's
/// `unshare -rn`) or outside one; empty elsewhere. Sandbox rows say which.
fn namespace() -> &'static str {
    if !cfg!(target_os = "linux") {
        return "";
    }
    match std::fs::read_to_string("/proc/self/uid_map") {
        Ok(map) if map.split_whitespace().collect::<Vec<_>>() == ["0", "0", "4294967295"] => {
            " (outside a user namespace)"
        }
        Ok(_) => " (in a user namespace)",
        Err(_) => " (user namespace unknown)",
    }
}

/// The body of the request the script answered with `pick`.
fn body_of(run: &HostRun, pick: &str) -> String {
    let r = run
        .model
        .requests
        .iter()
        .find(|r| r.pick.as_deref() == Some(pick))
        .unwrap_or_else(|| panic!("no request for {pick}: {:?}", run.model.requests));
    String::from_utf8_lossy(&r.body).into_owned()
}

#[test]
fn the_qualified_table_is_the_pinned_tier_1_hosts() {
    let mut pinned: Vec<(String, String)> = pins(&versions_toml())
        .into_iter()
        .filter(|p| p.tier == 1)
        .map(|p| (p.id, p.version))
        .collect();
    pinned.sort();
    pinned.dedup();
    let mut qualified: Vec<(String, String)> = QUALIFIED
        .iter()
        .map(|q| (q.host.to_owned(), q.version.to_owned()))
        .collect();
    qualified.sort();
    assert_eq!(pinned, qualified);
}

#[test]
fn the_scripted_model_is_never_linked_into_envcloak_or_envcloakd() {
    let contains = |p: &Path| {
        let bytes = std::fs::read(p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
        bytes.windows(SERVER.len()).any(|w| w == SERVER.as_bytes())
    };
    let bins = bin_dir();
    for name in ["envcloak", "envcloakd"] {
        assert!(
            !contains(&bins.join(name)),
            "{name} holds the scripted model"
        );
    }
    // The positive control: the model's own program holds it.
    let model = envcloak_testkit::agents::probe_model_exe();
    assert!(contains(&model), "the sentinel is not where it must be");
}

fn scripted_turns(h: Host, variant: &str) {
    let Some(a) = host(h, variant, "scripted_turns") else {
        return;
    };
    let marker = format!("ecturn-{:016x}", fresh_seed());
    let script = json!({"steps": [
        {"say": "running the step", "shell": print_split(&[&marker])},
        {"say": "done"},
    ]});
    let run = a.run(&script, "Run the scripted step.", &flags(h), &a.home_dir());
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    assert!(
        String::from_utf8_lossy(&run.output.stdout).contains("done"),
        "{}",
        run.text()
    );
    assert!(run.model.clean(), "{:?}", run.model.outcome);
    let picks: Vec<&str> = run
        .model
        .model_calls()
        .iter()
        .filter_map(|r| r.pick.as_deref())
        .collect();
    assert_eq!(picks, ["step 0", "step 1"], "{:?}", run.model.requests);
    // The host ran the command and sent its output back.
    assert!(
        last_tool_output(&body_of(&run, "step 1")).contains(&marker),
        "{}",
        run.text()
    );
    let mut endpoints = run.model.model_endpoints();
    endpoints.dedup();
    measure(&a, "model endpoints", endpoints.join(", "));
    let mut tunnels: Vec<&str> = run.model.connects();
    tunnels.sort_unstable();
    tunnels.dedup();
    measure(&a, "tunnels refused", tunnels.join(", "));
    measure(&a, "seconds", run.elapsed.as_secs_f32());
}

#[test]
fn claude_code_is_served_scripted_turns() {
    scripted_turns(Host::ClaudeCode, "native");
}

#[test]
fn claude_code_from_npm_is_served_scripted_turns() {
    scripted_turns(Host::ClaudeCode, "npm");
}

#[test]
fn codex_is_served_scripted_turns() {
    scripted_turns(Host::Codex, "native");
}

/// Claude Code from npm with install scripts off: `node cli-wrapper.cjs`
/// is the entry, and the native binary its child (F-37's
/// interpreter-launched layout, which M2-10 classifies on an asserted
/// basis). Served like the native build, and the shell tool's ancestry,
/// nearest first up to the test, is recorded: the command's shell, the
/// native binary, Node.
#[test]
fn claude_code_through_node_is_served_scripted_turns_and_its_layout_recorded() {
    scripted_turns(Host::ClaudeCode, "npm-wrapper");
    let Some(a) = host(Host::ClaudeCode, "npm-wrapper", "npm_wrapper_layout") else {
        return;
    };
    let probe = format!(
        "p=$$; printf '%s%s' 'ANC' 'ESTRY['; while [ \"$p\" != {test} ] && [ \"$p\" -gt 1 ]; do \
         printf '%s,' \"$(basename \"$(ps -o comm= -p \"$p\")\")\"; \
         p=$(ps -o ppid= -p \"$p\" | tr -d ' '); done; printf '%s%s' ']' 'END'",
        test = std::process::id()
    );
    let script = json!({"steps": [{"shell": probe}, {"say": "done"}]});
    let run = a.run(
        &script,
        "Show the ancestry.",
        &flags(Host::ClaudeCode),
        &a.home_dir(),
    );
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    let text = last_tool_output(&body_of(&run, "step 1"));
    let start = text.rfind("ANCESTRY[").map(|i| i + 9).unwrap_or(0);
    let end = text[start..].find("]END").map_or(start, |i| start + i);
    let chain: Vec<&str> = text[start..end]
        .split(',')
        .filter(|s| !s.is_empty())
        .collect();
    measure(&a, "shell tool ancestry, nearest first", chain.join(" <- "));
    let node = chain.iter().position(|n| *n == "node");
    let native = chain.iter().position(|n| *n == "claude");
    assert!(
        matches!((native, node), (Some(c), Some(n)) if c < n),
        "the native binary is not a child of node: {chain:?}"
    );
}

/// A canary printed by a scripted turn with plain `echo` must be found in
/// the host's transcript store and in the model's request bodies: the
/// sweep's positive control (L-01, SI-18). Raw counts per store are
/// printed for docs/ACCEPTANCE.md.
fn positive_control(h: Host) {
    let Some(a) = host(h, "native", "positive_control") else {
        return;
    };
    let control = Canary::new(
        "POSITIVE_CONTROL",
        format!("ecctl-{:016x}{:016x}", fresh_seed(), fresh_seed()),
    );
    // A key-shaped one too, printed the same way: whether a host keeps a
    // key it saw printed, raw.
    let cs = canaries(fresh_seed());
    let key = by_label(&cs, labels::OPENAI_API_KEY).clone();
    let script = json!({"steps": [
        {"shell": print_split(&[control.as_str(), key.as_str()])},
        {"say": "done"},
    ]});
    let run = a.run(&script, "Print the two lines.", &flags(h), &a.home_dir());
    assert_eq!(run.output.status.code(), Some(0), "exit code");
    assert!(run.model.clean(), "{:?}", run.model.outcome);
    // The command named it in two pieces: whole, it is what the command
    // printed, and the tool result the host sent holds it.
    assert!(
        last_tool_output(&body_of(&run, "step 1")).contains(control.as_str()),
        "the printed control is not in the tool result the host sent its model"
    );
    let all = [control.clone(), key.clone()];
    let hits = Sweep::host_stores(&a, &all, &[&run.model]);
    print!(
        "measurement: store hits host={} os={}:\n{hits}",
        a.installed.pin.id,
        os()
    );
    let store = transcript_store(h);
    assert!(
        hits.in_store_as(store, "POSITIVE_CONTROL", "raw") >= 1,
        "the positive control is not in {store}:\n{hits}"
    );
    assert!(
        hits.in_model("POSITIVE_CONTROL") >= 1,
        "the positive control is not in the model's request bodies:\n{hits}"
    );
    measure(
        &a,
        "printed key kept raw in the transcript",
        hits.in_store_as(store, &key.label, "raw"),
    );
    // Every hit outside the listed stores is reported, never dropped: a
    // new store shows up here first.
    measure(
        &a,
        "control hits outside the listed stores",
        hits.in_store(OTHER, "POSITIVE_CONTROL"),
    );
}

#[test]
fn claude_code_keeps_what_a_scripted_turn_prints() {
    positive_control(Host::ClaudeCode);
}

#[test]
fn codex_keeps_what_a_scripted_turn_prints() {
    positive_control(Host::Codex);
}

/// Claude Code 2.1.280 writes what a Bash command prints, while it runs,
/// to `claude-<uid>/<project>/<session>/tasks/<id>.output` in its per-user
/// temporary directory, outside `HOME`, and deletes the file when the
/// command ends (verifier, medium: in no store list, so the sweep never
/// looked there; a host killed mid-command leaves it). A control the
/// command prints is found there while the command waits on a barrier
/// file, and the directory is the one `CLAUDE_CODE_TMPDIR` names in the
/// home: nothing is kept in `/tmp/claude-<uid>/` (checked after the run).
#[test]
fn claude_code_keeps_a_running_command_s_output_in_its_temporary_store() {
    let Some(a) = host(Host::ClaudeCode, "native", "claude_code_temporary_store") else {
        return;
    };
    let control = Canary::new(
        "POSITIVE_CONTROL",
        format!("ecrun-{:016x}{:016x}", fresh_seed(), fresh_seed()),
    );
    let release = a.root().join("release");
    let shell = format!(
        "{}; while [ ! -e {} ]; do sleep 0.1; done; echo released",
        print_split(&[control.as_str()]),
        envcloak_e2e::quoted(release.to_str().unwrap())
    );
    let script = json!({"steps": [{"shell": shell}, {"say": "done"}]});
    let running = a.spawn(
        &script,
        "Run the step.",
        &flags(Host::ClaudeCode),
        &a.home_dir(),
    );
    let cs = [control.clone()];
    let end = std::time::Instant::now() + std::time::Duration::from_secs(120);
    let while_running = loop {
        let hits = Sweep::host_stores(&a, &cs, &[]);
        if hits.in_store("claude/tmp", &control.label) > 0 {
            break hits;
        }
        assert!(
            std::time::Instant::now() < end,
            "the running command's output never reached claude/tmp:\n{hits}"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    std::fs::write(&release, b"").unwrap();
    let run = running.wait();
    a.check_pinned();
    a.check_isolated();
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    let after = Sweep::host_stores(&a, &cs, &[&run.model]);
    measure(
        &a,
        "a running Bash command's printed output in claude/tmp",
        format!(
            "while it runs: {} hit(s); after it ended: {}",
            while_running.in_store("claude/tmp", &control.label),
            after.in_store("claude/tmp", &control.label)
        ),
    );
}

/// A run that never sees a canary leaves none anywhere: not in the host's
/// stores, not in the rest of the home, not in what it sent its model.
fn negative_control(h: Host) {
    let Some(a) = host(h, "native", "negative_control") else {
        return;
    };
    let cs = canaries(fresh_seed());
    let script = json!({"steps": [
        {"shell": "echo nothing secret here"},
        {"say": "done"},
    ]});
    let run = a.run(&script, "Print a line.", &flags(h), &a.home_dir());
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    let hits = Sweep::host_stores(&a, &cs, &[&run.model]);
    assert_eq!(hits.total(), 0, "{hits}");
    let home = a.test_home().unwrap();
    assert!(home.sweep(&cs).is_empty(), "the home holds a canary");
}

#[test]
fn claude_code_negative_control_is_clean() {
    negative_control(Host::ClaudeCode);
}

#[test]
fn codex_negative_control_is_clean() {
    negative_control(Host::Codex);
}

/// Every file a host wrote in its home, by path relative to `HOME`
/// (names only), for the store list in docs/ACCEPTANCE.md.
fn files_written(a: &AgentHome) -> Vec<String> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                walk(&p, base, out);
            } else {
                out.push(p.strip_prefix(base).unwrap_or(&p).display().to_string());
            }
        }
    }
    let mut out = Vec::new();
    let home = a.home_dir();
    walk(&home, &home, &mut out);
    out.sort();
    out
}

fn stores_written(h: Host) {
    let Some(a) = host(h, "native", "stores_written") else {
        return;
    };
    let script = json!({"steps": [{"shell": "echo stores"}, {"say": "done"}]});
    let run = a.run(&script, "Print a line.", &flags(h), &a.home_dir());
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    // Collapse ids so the list reads as shapes.
    // The skills Codex unpacks at every start are its own files, not a
    // store of what it saw.
    let shapes: Vec<String> = files_written(&a)
        .into_iter()
        .filter(|f| !f.starts_with(".codex/skills/.system/") && !f.starts_with(".codex/tmp/arg0/"))
        .map(|f| {
            f.split('/')
                .map(|part| {
                    if part.chars().filter(char::is_ascii_hexdigit).count() >= 8 {
                        "<id>".to_owned()
                    } else {
                        part.to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join("/")
        })
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    measure(&a, "files written", shapes.join(", "));
}

#[test]
fn claude_code_stores() {
    stores_written(Host::ClaudeCode);
}

#[test]
fn codex_stores() {
    stores_written(Host::Codex);
}

// ---------------------------------------------------------------------
// Measurements for docs/AGENTS.md "Host behaviour" (M2-04): each prints
// `measurement:` lines and asserts only what it must for the next tasks.
// ---------------------------------------------------------------------

/// What the host sent back for a call: the body of the request the
/// script answered with `pick` (the turn after the call).
fn after_call(run: &HostRun, pick: &str) -> String {
    body_of(run, pick)
}

/// The value printed after `key` (`KEY<value>`), up to a space, a quote
/// or a backslash, in `text`; the last such.
fn printed(text: &str, key: &str) -> Option<String> {
    let at = text.rfind(key)? + key.len();
    let value: String = text[at..]
        .chars()
        .take_while(|c| !matches!(c, ' ' | '"' | '\\' | '\n'))
        .collect();
    Some(value)
}

/// What a command run by the shell tool has for a terminal: whether each
/// standard stream is one (`[ -t fd ]`), whether it has a controlling
/// terminal (it can open `/dev/tty`, which only a process with one can),
/// and that terminal's name as `ps` gives it. Not `tty`, which reports on
/// standard input alone (verifier, medium: a command whose input is
/// redirected has a controlling terminal `tty` cannot see). The keys are
/// built at run time, so the command's own text never matches them.
const TTY_PROBE: &str = "for fd in 0 1 2; do if [ -t $fd ]; then t=T; else t=N; fi; \
     printf '%s%s%s ' FD $fd $t; done; \
     if (: </dev/tty) 2>/dev/null; then t=Y; else t=N; fi; printf '%s%s ' CTTY $t; \
     t=$(ps -o tty= -p $$ 2>/dev/null | tr -d ' '); printf '%s%s ' TTYNAME \"${t:-none}\"";

/// [`TTY_PROBE`]'s answer in `output`, as `stdin=.. stdout=.. stderr=..
/// controlling-terminal=.. (name)`; `None` when a part of it is missing.
fn tty_shown(output: &str) -> Option<String> {
    let get = |k: &str| printed(output, k).filter(|v| !v.is_empty());
    Some(format!(
        "stdin={} stdout={} stderr={} controlling-terminal={} ({})",
        get("FD0")?,
        get("FD1")?,
        get("FD2")?,
        get("CTTY")?,
        get("TTYNAME")?
    ))
}

/// The probe itself, with no host: under a pseudo-terminal of its own with
/// standard input from `/dev/null`, it reports a controlling terminal and
/// a standard input that is not a terminal; in a new session with no
/// terminal, no controlling terminal. A probe that read the controlling
/// terminal from standard input (`tty`) fails the first.
#[test]
fn the_terminal_probe_reads_the_controlling_terminal_not_standard_input() {
    let driver = "import os, pty, sys\n\
        probe = sys.argv[2]\n\
        if sys.argv[1] == 'pty':\n\
        \x20   pid, fd = pty.fork()\n\
        \x20   if pid == 0:\n\
        \x20       null = os.open('/dev/null', os.O_RDONLY)\n\
        \x20       os.dup2(null, 0)\n\
        \x20       os.execv('/bin/sh', ['/bin/sh', '-c', probe])\n\
        \x20   out = b''\n\
        \x20   while True:\n\
        \x20       try:\n\
        \x20           c = os.read(fd, 4096)\n\
        \x20       except OSError:\n\
        \x20           break\n\
        \x20       if not c:\n\
        \x20           break\n\
        \x20       out += c\n\
        \x20   os.waitpid(pid, 0)\n\
        \x20   sys.stdout.write(out.decode())\n\
        else:\n\
        \x20   os.setsid()\n\
        \x20   os.execv('/bin/sh', ['/bin/sh', '-c', probe])\n";
    let run = |mode: &str| {
        let out = std::process::Command::new(envcloak_e2e::python3())
            .args(["-c", driver, mode, TTY_PROBE])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        tty_shown(&text).unwrap_or_else(|| panic!("the probe printed {text:?}"))
    };
    let in_terminal = run("pty");
    assert!(
        in_terminal.starts_with("stdin=N stdout=T stderr=T controlling-terminal=Y"),
        "{in_terminal}"
    );
    let detached = run("setsid");
    assert!(
        detached.starts_with("stdin=N stdout=N stderr=N controlling-terminal=N"),
        "{detached}"
    );
}

/// Whether the shell tool's standard streams are terminals and whether it
/// has a controlling terminal ([`TTY_PROBE`]), as the harness runs a host
/// here: `-p` or `exec`, standard input from `/dev/null`, in a session of
/// its own with no terminal (M2-17 and M2-19 depend on it; the interactive
/// case is in [`claude_code_interactive_trust_and_paste`]).
fn tty_in_the_shell_tool(h: Host) {
    let Some(a) = host(h, "native", "tty_in_the_shell_tool") else {
        return;
    };
    let script = json!({"steps": [{"shell": TTY_PROBE}, {"say": "done"}]});
    let run = a.run(&script, "Check the terminal.", &flags(h), &a.home_dir());
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    let output = last_tool_output(&after_call(&run, "step 1"));
    let shown = tty_shown(&output).unwrap_or_else(|| panic!("the probe printed {output:?}"));
    measure(
        &a,
        "shell tool terminal, no terminal for the host (T=tty, N=not)",
        shown,
    );
}

#[test]
fn claude_code_shell_tool_terminal() {
    tty_in_the_shell_tool(Host::ClaudeCode);
}

#[test]
fn codex_shell_tool_terminal() {
    tty_in_the_shell_tool(Host::Codex);
}

/// The names (never the values) of the variables the shell tool's
/// commands get: the host's markers, and whether the model credential
/// the host was given reaches them.
fn environment_in_the_shell_tool(h: Host) {
    let Some(a) = host(h, "native", "environment_in_the_shell_tool") else {
        return;
    };
    // Quoted: an unquoted `[` is a pattern to zsh, Codex's and macOS's
    // shell. The keys are built at run time, so the command never matches.
    let probe = "printf '%s%s' 'NAM' 'ES['; env | cut -d= -f1 | sort | tr '\\n' ' '; \
                 printf '%s%s' ']' 'END'";
    let script = json!({"steps": [{"shell": probe}, {"say": "done"}]});
    let run = a.run(
        &script,
        "List the variable names.",
        &flags(h),
        &a.home_dir(),
    );
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    let text = after_call(&run, "step 1");
    let start = text.rfind("NAMES[").map(|i| i + 6).unwrap_or(0);
    let end = text[start..]
        .find("]END")
        .map(|i| start + i)
        .unwrap_or(start);
    let names: Vec<&str> = text[start..end].split_whitespace().collect();
    assert!(!names.is_empty(), "no names printed");
    let markers: Vec<&str> = names
        .iter()
        .copied()
        .filter(|n| {
            ["CLAUDE", "CODEX", "AGENT", "SANDBOX", "PROXY", "ENTRYPOINT"]
                .iter()
                .any(|m| n.contains(m))
        })
        .collect();
    measure(&a, "shell tool marker variables", markers.join(" "));
    let credential = match h {
        Host::ClaudeCode => "ANTHROPIC_API_KEY",
        Host::Codex => "EC_MODEL_TOKEN",
    };
    measure(
        &a,
        &format!("shell tool gets the model credential ({credential})"),
        names.contains(&credential),
    );
}

#[test]
fn claude_code_shell_tool_environment() {
    environment_in_the_shell_tool(Host::ClaudeCode);
}

#[test]
fn codex_shell_tool_environment() {
    environment_in_the_shell_tool(Host::Codex);
}

fn fixture_mcp() -> std::path::PathBuf {
    envcloak_testkit::testkit_bin("ec-mcp-fixture")
}

/// The milliseconds between the model's answer to `call` (the tool call)
/// and the host's next request (`next`): how long the host waited.
fn waited(run: &HostRun, call: &str, next: &str) -> u64 {
    let at = |p: &str| {
        run.model
            .requests
            .iter()
            .find(|r| r.pick.as_deref() == Some(p))
            .map(|r| r.at_ms)
            .unwrap_or_else(|| panic!("no request for {p}"))
    };
    at(next).saturating_sub(at(call))
}

/// Claude Code and an MCP server it starts (registered with its own CLI,
/// `claude mcp add-json`, as the installer will): the server's ancestry
/// and environment names, and the tool-call cutoff under `-p` without and
/// with a per-server `timeout` of 60 s (Map C §8 item 1, K-08, SI-17),
/// which sets M2-06's `--wait-ms` default: calls of 30 s and 70 s, so the
/// cutoff is seen where it falls inside 70 s, and otherwise 70 s is the
/// lower bound recorded.
#[test]
fn claude_code_mcp_server_and_tool_cutoff() {
    let Some(a) = host(Host::ClaudeCode, "native", "claude_code_mcp") else {
        return;
    };
    let server = fixture_mcp();
    let register = |timeout: Option<u64>| {
        let _ = a.host_cli(&["mcp", "remove", "--scope", "user", "fixture"]);
        let mut entry = json!({"command": server.to_str().unwrap(), "args": []});
        if let Some(t) = timeout {
            entry["timeout"] = json!(t);
        }
        let out = a.host_cli(&[
            "mcp",
            "add-json",
            "--scope",
            "user",
            "fixture",
            &entry.to_string(),
        ]);
        assert!(
            out.status.success(),
            "claude mcp add-json: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    let tools = HostFlags::claude("default", &["mcp__fixture__whoami", "mcp__fixture__wait"]);

    register(None);
    let whoami = json!({"steps": [{"tool": "mcp__fixture__whoami", "input": {}}, {"say": "done"}]});
    // A call made before Claude Code has connected the new server gets an
    // error instead of an answer: tried up to three times, and what the
    // earlier tries got is recorded with the answer.
    let mut earlier = Vec::new();
    let text = loop {
        let run = a.run(&whoami, "Who is the server?", &tools, &a.home_dir());
        assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
        let text = after_call(&run, "step 1");
        if text.contains("ancestry=") {
            break text;
        }
        // The fixture's answers hold names only; an error is the host's.
        let got: String = last_tool_output(&text).chars().take(160).collect();
        earlier.push(got);
        assert!(
            earlier.len() < 3,
            "the whoami call was never answered: {earlier:?}"
        );
    };
    let at = text.rfind("ancestry=").unwrap_or(0) + 9;
    let ancestry = text[at..]
        .split(['"', '\\'])
        .next()
        .unwrap_or("")
        .to_owned();
    measure(&a, "MCP server ancestry", &ancestry);
    if !earlier.is_empty() {
        measure(
            &a,
            "MCP call before the answer, tries",
            format!("{earlier:?}"),
        );
    }
    let env = printed(&text, "env=").unwrap_or_default();
    let markers: Vec<&str> = env
        .split(',')
        .filter(|n| {
            ["CLAUDE", "AGENT", "ENTRYPOINT", "ANTHROPIC"]
                .iter()
                .any(|m| n.contains(m))
        })
        .collect();
    measure(&a, "MCP server marker variables", markers.join(" "));

    for timeout in [None, Some(60_000)] {
        register(timeout);
        for call_ms in [30_000u64, 70_000] {
            let wait = json!({"steps": [
                {"tool": "mcp__fixture__wait", "input": {"ms": call_ms}},
                {"say": "done"},
            ]});
            let run = a.run(&wait, "Wait.", &tools, &a.home_dir());
            assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
            let after = after_call(&run, "step 1");
            let answered = after.contains(&format!("waited {call_ms}"));
            let ms = waited(&run, "step 0", "step 1");
            let setting = match timeout {
                None => "no per-server timeout".to_owned(),
                Some(t) => format!("per-server timeout {t} ms"),
            };
            measure(
                &a,
                &format!("MCP tool call of {} s under -p, {setting}", call_ms / 1000),
                format!(
                    "{} after {:.1} s",
                    if answered { "answered" } else { "cut off" },
                    ms as f64 / 1000.0
                ),
            );
            if timeout.is_some() && call_ms < 60_000 {
                assert!(answered, "a per-server timeout of 60 s cut off a 30 s call");
            }
        }
    }
}

/// Codex and an MCP server registered with its own CLI (`codex mcp add
/// fixture -- <command>`, which writes `[mcp_servers.fixture]` with the
/// command), plus the two keys that CLI cannot set, as the person's
/// settings (M2-08's installer writes the same): how its tools are
/// offered (a `mcp__fixture` namespace in 0.159.2), whether a call runs
/// under `exec` with approval policy `never` for each per-server
/// `default_tools_approval_mode` (SI-17; the meaning of `auto`), the
/// server's ancestry, and the cutoff `tool_timeout_sec` sets.
#[test]
fn codex_mcp_server_approval_modes_and_tool_cutoff() {
    let Some(mut a) = host(Host::Codex, "native", "codex_mcp") else {
        return;
    };
    let server = fixture_mcp();
    let added = a.host_cli(&["mcp", "add", "fixture", "--", server.to_str().unwrap()]);
    assert!(
        added.status.success(),
        "codex mcp add: {}",
        String::from_utf8_lossy(&added.stderr)
    );
    // What the CLI wrote (a path is the same string in TOML and JSON).
    let written = std::fs::read_to_string(a.codex_home().join("config.toml")).unwrap();
    assert!(
        written.contains("[mcp_servers.fixture]")
            && written.contains(&format!("command = {}", json!(server.to_str().unwrap()))),
        "{written}"
    );
    let config = |mode: Option<&str>, timeout: u64| {
        let mut t = format!("[mcp_servers.fixture]\ntool_timeout_sec = {timeout}\n");
        if let Some(m) = mode {
            t.push_str(&format!("default_tools_approval_mode = \"{m}\"\n"));
        }
        t
    };
    let whoami = json!({"steps": [
        {"tool": "whoami", "namespace": "mcp__fixture", "input": {}},
        {"say": "done"},
    ]});
    let mut ran_with = Vec::new();
    for mode in [None, Some("auto"), Some("prompt"), Some("approve")] {
        a.codex_config(&config(mode, 60));
        let run = a.run(
            &whoami,
            "Who is the server?",
            &flags(Host::Codex),
            &a.home_dir(),
        );
        assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
        if mode.is_none() {
            let offered = run
                .model
                .model_calls()
                .first()
                .and_then(|r| r.json())
                .map(|b| {
                    b["tools"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter(|t| t["name"] == "mcp__fixture")
                        .map(|t| format!("{} {}", t["type"], t["name"]))
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            measure(&a, "MCP tools offered as", offered);
        }
        let text = after_call(&run, "step 1");
        let ran = text.contains("ancestry=");
        measure(
            &a,
            &format!(
                "MCP call under exec, approval never, default_tools_approval_mode {}",
                mode.unwrap_or("unset")
            ),
            if ran { "ran" } else { "refused" },
        );
        if ran {
            ran_with.push(mode);
            let at = text.rfind("ancestry=").unwrap_or(0) + 9;
            let ancestry = text[at..].split(['"', '\\']).next().unwrap_or("");
            measure(&a, "MCP server ancestry", ancestry);
        }
    }
    assert!(
        ran_with.contains(&Some("approve")),
        "no approval mode let the call run"
    );
    // The cutoff: a 15 s call under tool_timeout_sec = 5.
    a.codex_config(&config(Some("approve"), 5));
    let wait = json!({"steps": [
        {"tool": "wait", "namespace": "mcp__fixture", "input": {"ms": 15000}},
        {"say": "done"},
    ]});
    let run = a.run(&wait, "Wait.", &flags(Host::Codex), &a.home_dir());
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    let answered = after_call(&run, "step 1").contains("waited 15000");
    measure(
        &a,
        "MCP tool call of 15 s, tool_timeout_sec = 5",
        format!(
            "{} after {:.1} s",
            if answered { "answered" } else { "cut off" },
            waited(&run, "step 0", "step 1") as f64 / 1000.0
        ),
    );
}

/// A hook command that saves every payload it gets under `dir`, named by
/// its event, and blocks a prompt holding `BLOCK-ME-NOW` (exit 2, the
/// documented block for both hosts) and sleeps 10 s on one holding
/// `SLOW-HOOK`.
fn hook_command(dir: &Path) -> std::path::PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    let path = dir.join("hook.sh");
    envcloak_e2e::write_script(
        &path,
        &format!(
            "#!/bin/sh\nevent=\"$1\"\nf='{}'/\"$event\".$$.json\ncat > \"$f\"\n\
             case \"$event\" in UserPromptSubmit)\n\
             if grep -q SLOW-HOOK \"$f\"; then sleep 10; fi\n\
             if grep -q BLOCK-ME-NOW \"$f\"; then echo 'blocked by the fixture hook' >&2; exit 2; fi;;\n\
             esac\nexit 0\n",
            dir.display()
        ),
    );
    path
}

/// The payloads the hook saved for `event`, newest last.
fn payloads(dir: &Path, event: &str) -> Vec<serde_json::Value> {
    let mut found: Vec<(std::time::SystemTime, serde_json::Value)> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(&format!("{event}."))
        })
        .filter_map(|e| {
            let at = e.metadata().ok()?.modified().ok()?;
            let v = serde_json::from_slice(&std::fs::read(e.path()).ok()?).ok()?;
            Some((at, v))
        })
        .collect();
    found.sort_by_key(|(at, _)| *at);
    found.into_iter().map(|(_, v)| v).collect()
}

/// A payload with what differs from run to run (ids, paths, times)
/// replaced by fixed placeholders, keeping every key and value type, so
/// it can be compared with the fixture M2-08's parsers test against.
fn normalized(v: &serde_json::Value, home: &Path) -> serde_json::Value {
    use serde_json::Value;
    let home = home.to_string_lossy().into_owned();
    let private = format!("/private{home}");
    match v {
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, v)| {
                    let v = match (k.as_str(), v) {
                        (
                            "session_id" | "turn_id" | "tool_use_id" | "agent_id",
                            Value::String(_),
                        ) => {
                            json!("<id>")
                        }
                        _ => normalized(v, Path::new(&home)),
                    };
                    (k.clone(), v)
                })
                .collect(),
        ),
        Value::Array(a) => {
            Value::Array(a.iter().map(|x| normalized(x, Path::new(&home))).collect())
        }
        Value::String(s) => {
            // Claude Code names a project's transcript directory after its
            // path, with `/` and `.` as `-`.
            let encoded = |p: &str| p.replace(['/', '.'], "-");
            let s = s
                .replace(&private, "<home>")
                .replace(&home, "<home>")
                .replace(&encoded(&private), "<home-as-directory-name>")
                .replace(&encoded(&home), "<home-as-directory-name>");
            // Session files are named by id, and Codex's sit under dated
            // directories.
            let s = s
                .split('/')
                .map(|part| {
                    if part.chars().filter(char::is_ascii_hexdigit).count() >= 16 {
                        "<id>".to_owned()
                    } else if !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()) {
                        "<n>".to_owned()
                    } else {
                        part.to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join("/");
            Value::String(s)
        }
        other => other.clone(),
    }
}

/// Compares `got` with the fixture `name` of `host` (written instead when
/// ENVCLOAK_TEST_WRITE_FIXTURES is set, by a maintainer pinning a new
/// version): the real payloads, with synthetic content, that M2-08's hook
/// parsers test against.
fn payload_fixture(a: &AgentHome, name: &str, got: &serde_json::Value) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/hook-payloads")
        .join(format!(
            "{}-{}",
            a.installed.pin.id, a.installed.pin.version
        ));
    let path = dir.join(format!("{name}.json"));
    let text = format!("{}\n", serde_json::to_string_pretty(got).unwrap());
    if std::env::var_os("ENVCLOAK_TEST_WRITE_FIXTURES").is_some() {
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, &text).unwrap();
        return;
    }
    let want = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    assert_eq!(text, want, "{} drifted from {}", name, path.display());
}

/// Claude Code's hooks under `-p`: the real `UserPromptSubmit` and
/// `PreToolUse` payloads (fixtures for M2-08), and whether a prompt a hook
/// blocks still reaches `history.jsonl` or the transcript (K-14, R-M2-85),
/// and the model.
#[test]
fn claude_code_hooks_and_blocked_prompt_persistence() {
    let Some(a) = host(Host::ClaudeCode, "native", "claude_code_hooks") else {
        return;
    };
    let dir = a.root().join("hook-payloads");
    let hook = hook_command(&dir);
    let command = |event: &str| format!("{} {event}", hook.display());
    // The person's settings: two hooks in the user settings file.
    let settings = json!({"hooks": {
        "UserPromptSubmit": [{"hooks": [{"type": "command", "command": command("UserPromptSubmit")}]}],
        "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": command("PreToolUse")}]}],
    }});
    std::fs::create_dir_all(a.home_dir().join(".claude")).unwrap();
    std::fs::write(
        a.home_dir().join(".claude/settings.json"),
        serde_json::to_string_pretty(&settings).unwrap(),
    )
    .unwrap();
    let script = json!({"steps": [{"shell": "echo hook-check"}, {"say": "done"}]});
    let run = a.run(
        &script,
        "List the files here.",
        &flags(Host::ClaudeCode),
        &a.home_dir(),
    );
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    for event in ["UserPromptSubmit", "PreToolUse"] {
        let got = payloads(&dir, event);
        assert!(!got.is_empty(), "no {event} payload");
        payload_fixture(&a, event, &normalized(&got[got.len() - 1], &a.home_dir()));
    }

    let control = Canary::new(
        "BLOCKED_PROMPT",
        format!("ecblk-{:016x}{:016x}", fresh_seed(), fresh_seed()),
    );
    let blocked = format!("BLOCK-ME-NOW {}", control.as_str());
    let script = json!({"steps": [{"say": "the prompt was not blocked"}]});
    let run = a.run(&script, &blocked, &flags(Host::ClaudeCode), &a.home_dir());
    let hits = Sweep::host_stores(&a, std::slice::from_ref(&control), &[&run.model]);
    print!(
        "measurement: blocked prompt hits host=claude-code os={}:\n{hits}",
        os()
    );
    measure(
        &a,
        "blocked prompt: exit code",
        format!("{:?}", run.output.status.code()),
    );
    measure(
        &a,
        "blocked prompt: model requests",
        run.model.model_calls().len(),
    );
    measure(
        &a,
        "blocked prompt: in history.jsonl",
        hits.in_store("claude/history.jsonl", &control.label),
    );
    measure(
        &a,
        "blocked prompt: in transcripts",
        hits.in_store("claude/projects", &control.label),
    );
    assert_eq!(
        hits.in_model(&control.label),
        0,
        "a blocked prompt reached the model"
    );
}

/// Codex's hooks under `exec`: whether they run untrusted, the real
/// payloads (fixtures for M2-08), a blocked prompt's persistence and
/// whether it reaches the model, and what a hook that outlives its
/// `timeout` does (Map C §8 item 3).
#[test]
fn codex_hooks_trust_blocked_prompt_and_timeout() {
    let Some(mut a) = host(Host::Codex, "native", "codex_hooks") else {
        return;
    };
    let dir = a.root().join("hook-payloads");
    let hook = hook_command(&dir);
    let hooks = |timeout: u64| {
        format!(
            "[[hooks.UserPromptSubmit]]\nhooks = [{{ type = \"command\", command = {}, timeout = {timeout} }}]\n\
             [[hooks.PreToolUse]]\nhooks = [{{ type = \"command\", command = {}, timeout = {timeout} }}]\n",
            json!(format!("{} UserPromptSubmit", hook.display())),
            json!(format!("{} PreToolUse", hook.display())),
        )
    };
    a.codex_config(&hooks(30));
    let script = json!({"steps": [{"shell": "echo hook-check"}, {"say": "done"}]});
    // Untrusted, as a fresh install leaves them.
    let run = a.run(
        &script,
        "List the files here.",
        &flags(Host::Codex),
        &a.home_dir(),
    );
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    measure(
        &a,
        "hooks run without trust (no bypass)",
        !payloads(&dir, "UserPromptSubmit").is_empty(),
    );
    // Trust bypassed, in this probe home only (D-13).
    let trusted = flags(Host::Codex).with(&["--dangerously-bypass-hook-trust"]);
    let run = a.run(&script, "List the files here.", &trusted, &a.home_dir());
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    for event in ["UserPromptSubmit", "PreToolUse"] {
        let got = payloads(&dir, event);
        assert!(!got.is_empty(), "no {event} payload");
        payload_fixture(&a, event, &normalized(&got[got.len() - 1], &a.home_dir()));
    }

    let control = Canary::new(
        "BLOCKED_PROMPT",
        format!("ecblk-{:016x}{:016x}", fresh_seed(), fresh_seed()),
    );
    let blocked = format!("BLOCK-ME-NOW {}", control.as_str());
    let script = json!({"steps": [{"say": "the prompt was not blocked"}]});
    let run = a.run(&script, &blocked, &trusted, &a.home_dir());
    let hits = Sweep::host_stores(&a, std::slice::from_ref(&control), &[&run.model]);
    print!(
        "measurement: blocked prompt hits host=codex os={}:\n{hits}",
        os()
    );
    measure(
        &a,
        "blocked prompt: exit code",
        format!("{:?}", run.output.status.code()),
    );
    measure(
        &a,
        "blocked prompt: model requests",
        run.model.model_calls().len(),
    );
    measure(
        &a,
        "blocked prompt: in history.jsonl",
        hits.in_store("codex/history.jsonl", &control.label),
    );
    measure(
        &a,
        "blocked prompt: in sessions",
        hits.in_store("codex/sessions", &control.label),
    );
    measure(
        &a,
        "blocked prompt: in SQLite stores",
        hits.in_store("codex/sqlite", &control.label),
    );
    assert_eq!(
        hits.in_model(&control.label),
        0,
        "a blocked prompt reached the model"
    );

    // A hook slower than its timeout: does the prompt go on (fail open)?
    a.codex_config(&hooks(2));
    let slow = format!("SLOW-HOOK BLOCK-ME-NOW {}", control.as_str());
    let script = json!({"steps": [{"say": "the prompt went on"}]});
    let run = a.run(&script, &slow, &trusted, &a.home_dir());
    measure(
        &a,
        "hook past its 2 s timeout, prompt it would block",
        format!(
            "{} (exit {:?}, {:.1} s)",
            if run.model.model_calls().is_empty() {
                "blocked"
            } else {
                "went on (fails open)"
            },
            run.output.status.code(),
            run.elapsed.as_secs_f32()
        ),
    );
}

/// Whether Claude Code expands an `@` mention under `-p` (M2-09's `@.env`
/// probe depends on it).
#[test]
fn claude_code_at_mentions_under_print() {
    let Some(a) = host(Host::ClaudeCode, "native", "claude_code_at_mentions") else {
        return;
    };
    let marker = format!("ecreadme-{:016x}", fresh_seed());
    std::fs::write(a.home_dir().join("README.md"), format!("{marker}\n")).unwrap();
    let script = json!({"steps": [{"say": "done"}]});
    let run = a.run(
        &script,
        "Summarize @README.md",
        &flags(Host::ClaudeCode),
        &a.home_dir(),
    );
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    let first = after_call(&run, "step 0");
    measure(&a, "@ mention expanded under -p", first.contains(&marker));
}

/// `envcloakd --foreground` in `a`'s home, by absolute path.
fn daemon_in(a: &AgentHome) -> envcloak_testkit::Daemon {
    let home = a.test_home().unwrap();
    let mut cmd = std::process::Command::new(bin_dir().join("envcloakd"));
    home.apply(&mut cmd);
    envcloak_testkit::Daemon::start_command(cmd, &[])
}

/// What `envcloak status` printed inside the host's shell tool, and the
/// uid the command ran as there, with keys built at run time so the
/// command's text never matches.
fn status_probe() -> String {
    format!(
        "printf '%s%s%s%s' 'UI' 'D[' \"$(id -u)\" ']'; \
         printf '%s%s' 'REA' 'CH['; {} status 2>&1 | tr '\\n' ' ' | cut -c1-600; printf '%s%s' ']' 'END'",
        envcloak_e2e::quoted(bin_dir().join("envcloak").to_str().unwrap())
    )
}

/// The text of the last tool result in a request body (Anthropic
/// Messages or OpenAI Responses), on one line.
fn last_tool_output(body: &str) -> String {
    last_tool_text(body)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// The text of the last tool result in a request body, as the host sent
/// it (parts joined by line breaks).
fn last_tool_text(body: &str) -> String {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        return String::new();
    };
    let mut out = String::new();
    // A string, a list of text parts, or anything else whole, as JSON.
    let text = |c: &serde_json::Value| match c {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(parts) => parts
            .iter()
            .filter_map(|p| p["text"].as_str())
            .collect::<Vec<_>>()
            .join("\n"),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    };
    for m in v["messages"].as_array().into_iter().flatten() {
        for c in m["content"].as_array().into_iter().flatten() {
            if c["type"] == "tool_result" {
                out = text(&c["content"]);
            }
        }
    }
    for item in v["input"].as_array().into_iter().flatten() {
        if item["type"] == "function_call_output" {
            out = text(&item["output"]);
        }
    }
    out
}

/// Whether the status probe reached the daemon, and if not, why: the
/// failure token and its fixed message, the uid inside the sandbox and
/// the test's own; when the probe printed nothing, the start of what the
/// command printed instead.
fn reach(text: &str) -> String {
    let inside: String = text
        .rfind("UID[")
        .map(|i| {
            text[i + 4..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect()
        })
        .unwrap_or_else(|| "?".to_owned());
    let Some(start) = text.rfind("REACH[").map(|i| i + 6) else {
        let said: String = last_tool_output(text).chars().take(300).collect();
        return format!("no output (the command did not run: {said:?})");
    };
    let end = text[start..]
        .find("]END")
        .map(|i| start + i)
        .unwrap_or(start);
    let line = &text[start..end];
    if line.starts_with("daemon: running") {
        "reaches the daemon".to_owned()
    } else if line.is_empty() {
        "no output".to_owned()
    } else {
        // `daemon: not running` or `not verified`, and the failure token
        // with its fixed message.
        let first = line.split("cli hardening").next().unwrap_or(line).trim();
        let why: String = line
            .split("envcloak: ")
            .nth(1)
            // `cut` ends the line, which the request body escapes.
            .map_or("?", |r| r.trim().trim_end_matches("\\n").trim_end())
            .chars()
            .take(200)
            .collect();
        format!(
            "does not ({first}; {why}; uid {inside} inside, {} outside)",
            own_uid()
        )
    }
}

/// The test's own uid, from `id -u`.
fn own_uid() -> String {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_else(|_| "?".to_owned())
}

/// Whether `envcloak status` reaches the daemon from Claude Code's Bash
/// sandbox (K-01): off; on with no socket allowance; on with
/// `allowUnixSockets` naming EnvCloak's socket (macOS) or
/// `allowAllUnixSockets` (Linux). `failIfUnavailable` makes a sandbox
/// that cannot start (Linux without bubblewrap) show as such.
#[test]
fn claude_code_sandbox_reaches_the_socket() {
    let Some(a) = host(Host::ClaudeCode, "native", "claude_code_sandbox") else {
        return;
    };
    let _daemon = daemon_in(&a);
    let socket = envcloak_testkit::daemon_socket(a.test_home().unwrap());
    let base = json!({"enabled": true, "failIfUnavailable": true,
                      "autoAllowBashIfSandboxed": true, "allowUnsandboxedCommands": false});
    // macOS resolves /tmp to /private/tmp before the sandbox compares a
    // path: the socket as the daemon names it, and resolved.
    let resolved = std::fs::canonicalize(&socket).unwrap();
    let mut given = base.clone();
    given["network"] = json!({"allowUnixSockets": [socket.to_str().unwrap()]});
    let mut allowed = base.clone();
    if cfg!(target_os = "macos") {
        allowed["network"] = json!({"allowUnixSockets": [resolved.to_str().unwrap()]});
    } else {
        allowed["network"] = json!({"allowAllUnixSockets": true});
    }
    let script = json!({"steps": [{"shell": status_probe()}, {"say": "done"}]});
    let mut cases = vec![
        ("sandbox off", None),
        ("sandbox on, no socket allowance", Some(base)),
    ];
    if cfg!(target_os = "macos") {
        cases.push((
            "sandbox on, allowUnixSockets [the socket's path as given]",
            Some(given),
        ));
        cases.push((
            "sandbox on, allowUnixSockets [the socket's resolved path]",
            Some(allowed),
        ));
    } else {
        cases.push(("sandbox on, allowAllUnixSockets", Some(allowed)));
    }
    for (name, sandbox) in cases {
        let settings = match sandbox {
            Some(s) => json!({"sandbox": s}),
            None => json!({}),
        };
        std::fs::create_dir_all(a.home_dir().join(".claude")).unwrap();
        std::fs::write(
            a.home_dir().join(".claude/settings.json"),
            settings.to_string(),
        )
        .unwrap();
        let run = a.run(
            &script,
            "Check the daemon.",
            &flags(Host::ClaudeCode),
            &a.home_dir(),
        );
        let result = if run.output.status.code() == Some(0) {
            reach(&after_call(&run, "step 1"))
        } else {
            format!("the host did not run (exit {:?})", run.output.status.code())
        };
        measure(
            &a,
            &format!("envcloak status, {name}{}", namespace()),
            result,
        );
    }
}

/// What a sandboxed command tries besides EnvCloak's socket, as a Python
/// program (keys built at run time, so the command's text never matches
/// them). `raw`: a loopback TCP listener, another Unix socket and a raw
/// connection to a non-loopback address (TEST-NET-1, which nothing
/// answers: a sandbox that let it out shows `timeout`). `https` and
/// `http`: a request through whatever proxy the command's environment
/// names (Codex's own, under its network proxy), each in a command of its
/// own, since Codex fails a whole command whose request its proxy blocks.
/// Each prints `<KEY>OK` or `<KEY>NO <why>`, one word; `PXY` lists the
/// command's proxy variables with the host and port each names.
const EGRESS: &str = r#"import errno, os, re, socket, sys, urllib.error, urllib.request
mode, port, other = sys.argv[1], int(sys.argv[2]), sys.argv[3]
def say(key, verdict, why=""):
    print(key + "%s" % verdict, re.sub(r"[^A-Za-z0-9._-]", "_", str(why))[:80])
def raw(key, family, addr):
    # A socket the sandbox will not even let be made counts as refused.
    s = None
    try:
        s = socket.socket(family)
        s.settimeout(5)
        s.connect(addr)
        say(key, "OK")
    except socket.timeout:
        say(key, "NO", "timeout")
    except OSError as e:
        say(key, "NO", errno.errorcode.get(e.errno, e.errno))
    finally:
        if s is not None:
            s.close()
if mode == "raw":
    raw("TCP", socket.AF_INET, ("127.0.0.1", port))
    raw("UNIX", socket.AF_UNIX, other)
    raw("EXT", socket.AF_INET, ("192.0.2.1", 443))
    proxies = sorted("%s=%s" % (k, re.sub(r"^[a-z0-9]+://", "", v)) for k, v in os.environ.items() if "proxy" in k.lower())
    print("PXY", re.sub(r"[^A-Za-z0-9._:=,-]", "_", ",".join(proxies) or "none")[:400])
for key, url in (("PRXS", "https://example.com/"), ("PRXH", "http://example.com/")):
    if mode != url.split(":")[0]:
        continue
    try:
        # Within the 10 s Codex waits before it returns a command's
        # output so far.
        r = urllib.request.urlopen(url, timeout=5)
        say(key, "OK", r.status)
    except urllib.error.HTTPError as e:
        say(key, "NO", "http-%d" % e.code)
    except Exception as e:
        t = re.search(r"Tunnel connection failed: (\d+)", str(e))
        say(key, "NO", "tunnel-" + t.group(1) if t else type(getattr(e, "reason", e)).__name__ + "-" + str(getattr(e, "reason", e))[:60])
"#;

/// Whether `envcloak status` reaches the daemon from Codex's sandbox
/// (K-01) in `read-only` (the `exec` default) and `workspace-write`, each
/// with no network setting and with the bounded setting (network access,
/// the network proxy on, no domain rule and one `unix_sockets` allow rule
/// for EnvCloak's socket), and `workspace-write` with network access
/// alone; and what else a command can reach there ([`EGRESS`]). Under the
/// bounded setting in `workspace-write` (what M2-08 would write) nothing
/// else may be reachable: on macOS a raw connection anywhere is refused by
/// the sandbox itself (`EPERM`), and on both systems both proxied
/// requests are refused by Codex itself (its proxy's "Network access to
/// ... was blocked", naming its rule, a 403 from it, or `EPERM` for the
/// socket), never by a network that is not there, and never reach the
/// scripted model's proxy.
#[test]
fn codex_sandbox_reaches_the_socket_and_nothing_else() {
    let Some(mut a) = host(Host::Codex, "native", "codex_sandbox") else {
        return;
    };
    let _daemon = daemon_in(&a);
    let socket = envcloak_testkit::daemon_socket(a.test_home().unwrap());
    // Something else to reach: a loopback TCP listener and a Unix socket.
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = tcp.local_addr().unwrap().port();
    let other = a.root().join("other.sock");
    let _unix = std::os::unix::net::UnixListener::bind(&other).unwrap();
    let probe = a.root().join("egress.py");
    std::fs::write(&probe, EGRESS).unwrap();
    let egress = |mode: &str| {
        format!(
            "python3 {} {mode} {port} {}",
            envcloak_e2e::quoted(probe.to_str().unwrap()),
            envcloak_e2e::quoted(other.to_str().unwrap())
        )
    };
    let bounded = format!(
        "[sandbox_workspace_write]\nnetwork_access = true\n\
         [features.network_proxy]\nenabled = true\n\
         [features.network_proxy.unix_sockets]\n{} = \"allow\"\n",
        json!(socket.to_str().unwrap())
    );
    for (name, sandbox, config) in [
        ("read-only", "read-only", String::new()),
        (
            "read-only, network_access, proxy with one unix_sockets rule",
            "read-only",
            bounded.clone(),
        ),
        ("workspace-write", "workspace-write", String::new()),
        (
            "workspace-write, network_access",
            "workspace-write",
            "[sandbox_workspace_write]\nnetwork_access = true\n".to_owned(),
        ),
        (
            "workspace-write, network_access, proxy with one unix_sockets rule",
            "workspace-write",
            bounded.clone(),
        ),
    ] {
        a.codex_config(&config);
        let script = json!({"steps": [
            {"shell": format!("{}; {}", status_probe(), egress("raw"))},
            // With the probe's exit status, as `RC<n>`, built at run time.
            {"shell": format!("{}; printf '%s%s\\n' 'R' \"C$?\"", egress("https"))},
            {"shell": format!("{}; printf '%s%s\\n' 'R' \"C$?\"", egress("http"))},
            {"say": "done"},
        ]});
        let run = a.run(
            &script,
            "Check the daemon.",
            &HostFlags::codex(sandbox, "never"),
            &a.home_dir(),
        );
        assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
        let text = after_call(&run, "step 1");
        let label = format!("{name}{}", namespace());
        measure(&a, &format!("envcloak status, {label}"), reach(&text));
        // Each proxied request's result is in the next turn's request.
        let proxied = [
            ("PRXS", after_call(&run, "step 2")),
            ("PRXH", after_call(&run, "step 3")),
        ];
        let seen = |key: &str| {
            // The raw probe's keys are in the request after its command;
            // each proxied one's in the request after its own, read from
            // that command's tool result.
            let (body, out) = match proxied.iter().find(|(k, _)| *k == key) {
                Some((_, body)) => (body.as_str(), last_tool_output(body)),
                None => (text.as_str(), text.clone()),
            };
            if let Some(e) = printed(&out, &format!("{key}OK ")) {
                format!("reached ({e})")
            } else if let Some(e) = printed(&out, &format!("{key}NO ")) {
                format!("refused ({e})")
            } else if let Some(why) = out
                .split_once("was blocked: ")
                .filter(|(before, _)| before.contains("Network access to"))
                .map(|(_, why)| why)
            {
                // Codex failed the whole command: its proxy blocked the
                // request, and says by which rule (macOS: the domain is
                // not on the allowlist; Linux CI, whose namespaces resolve
                // no name: local or private addresses).
                let why: String = why
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '/'))
                    .collect();
                format!("refused (codex-proxy: {})", why.trim())
            } else {
                // What the command's tool result said instead (Python's own
                // error, or the host's words), and the types of the last
                // items the request ends with, for the record: no value.
                let said: String = out
                    .chars()
                    .filter(|c| c.is_ascii_graphic() || *c == ' ')
                    .take(300)
                    .collect();
                let types = serde_json::from_str::<serde_json::Value>(body)
                    .ok()
                    .and_then(|v| v["input"].as_array().cloned())
                    .map(|items| {
                        items
                            .iter()
                            .rev()
                            .take(4)
                            .map(|i| i["type"].as_str().unwrap_or("?").to_owned())
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .unwrap_or_default();
                let rc = printed(&out, "RC").unwrap_or_else(|| "?".to_owned());
                format!("not tried (tool result {said:?}; exit {rc}; last items {types})")
            }
        };
        let proxies = printed(&text, "PXY ").unwrap_or_else(|| "?".to_owned());
        measure(
            &a,
            &format!("other egress, {label}"),
            format!(
                "loopback TCP {}, another Unix socket {}, a non-loopback address {}, \
                 HTTPS through the command's proxy {}, HTTP {}; the command's proxy \
                 variables {proxies}, the scripted model at {}",
                seen("TCP"),
                seen("UNIX"),
                seen("EXT"),
                seen("PRXS"),
                seen("PRXH"),
                run.model_url.trim_start_matches("http://")
            ),
        );
        if sandbox == "workspace-write" && name.contains("unix_sockets") {
            for key in ["TCP", "UNIX", "EXT", "PRXS", "PRXH"] {
                assert!(
                    seen(key).starts_with("refused"),
                    "the bounded setting lets a command reach {key}: {}",
                    seen(key)
                );
            }
            if cfg!(target_os = "macos") {
                assert!(
                    matches!(seen("EXT").as_str(), "refused (EPERM)" | "refused (EACCES)"),
                    "a non-loopback connection was not refused by the sandbox: {}",
                    seen("EXT")
                );
            }
            // Refused by Codex itself: its proxy, by its rules (no domain
            // is allowed), or its sandbox, which will not let the socket
            // be made (EPERM); never by a network that is missing (CI's
            // Linux namespace has none, so ECONNREFUSED, ENETUNREACH or a
            // timeout prove nothing there).
            for key in ["PRXS", "PRXH"] {
                let got = seen(key);
                assert!(
                    matches!(got.as_str(), "refused (tunnel-403)" | "refused (http-403)")
                        || got.starts_with("refused (codex-proxy: ")
                        || got.starts_with("refused (PermissionError"),
                    "{key} was not refused by Codex: {got}"
                );
            }
            // Every request that reached the scripted model was read: a
            // proxy request in any form is recorded (an HTTP/1.0 tunnel, a
            // request to forward), so the check below can fail.
            assert_eq!(
                run.model.outcome["malformed"].as_u64(),
                Some(0),
                "{:?}",
                run.model.outcome
            );
            assert!(
                !run.model
                    .connects()
                    .iter()
                    .any(|c| c.starts_with("example.com")),
                "a sandboxed command reached the scripted model's proxy"
            );
        }
    }
}

/// Drives a program on a pseudo-terminal of its own (40 rows, 120
/// columns), as a person in a terminal window. argv[1] is a JSON spec:
/// `argv`, `env`, `cwd`, `limit` and `steps`, each one of
/// - `["wait", text, n]`: until the screen has shown `text` `n` times;
/// - `["wait_raw", bytes, n]`: until the program has written `bytes` `n`
///   times;
/// - `["idle", ms]`: until it has written nothing for `ms` milliseconds;
/// - `["send", text]`: types `text`.
///
/// It answers the queries a terminal answers. The program's exit code (or
/// 128 plus its signal) is printed last as `EXIT <n>`; `TIMEOUT <step>`
/// when a wait runs out, and `STILL RUNNING` when the program has not
/// exited `limit` seconds after the last step (it is killed in both
/// cases). The screen is never printed: it can hold what was pasted. On a
/// timeout it is written to `screen`, for diagnosis. The program leads a
/// session and a process group of its own, outside the driver's, so the
/// harness's group kill does not reach it: the driver ends that group
/// itself, whenever the program exits, is killed or outlives the driver's
/// limit, and on a `SIGTERM` to the driver (the harness's limit). The
/// group is killed while the program that leads it is still unreaped (its
/// exit is seen with `waitid(WNOWAIT)`), so its id cannot have been reused,
/// and then the program is reaped (D-34); what the program left running
/// in its group (a process that ignores the hangup when the terminal
/// closes) goes with it.
const PTY_DRIVER: &str = r#"import fcntl, json, os, pty, re, select, signal, struct, sys, termios, time
spec = json.load(open(sys.argv[1]))
pid, fd = pty.fork()
if pid == 0:
    os.chdir(spec["cwd"])
    os.execve(spec["argv"][0], spec["argv"], dict(spec["env"]))
# SIGTERM is blocked around every reap, so the handler only ever runs
# while the child is unreaped.
TERM = {signal.SIGTERM}
def end_group():
    # The child leads the group (pty.fork made it a session leader) and is
    # unreaped: the group's id is still its.
    try:
        os.killpg(pid, 9)
    except OSError:
        pass
def stop(*_):
    signal.pthread_sigmask(signal.SIG_BLOCK, TERM)
    end_group()
    os.waitpid(pid, 0)
    sys.exit(1)
signal.signal(signal.SIGTERM, stop)
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
shown = b""
def more(until):
    global shown
    r, _, _ = select.select([fd], [], [], max(0.0, until - time.time()))
    if not r:
        return True
    try:
        c = os.read(fd, 65536)
    except OSError:
        return False
    if not c:
        return False
    shown += c
    # Answer the queries a terminal answers: the version (XTVERSION), the
    # keyboard protocol, the device attributes, the cursor position.
    for q, a in ((b"\x1b[>0q", b"\x1bP>|xterm(388)\x1b\\"), (b"\x1b[?u", b"\x1b[?0u"),
                 (b"\x1b[c", b"\x1b[?1;2c"), (b"\x1b[6n", b"\x1b[1;1R")):
        for _ in range(c.count(q)):
            os.write(fd, a)
    return True
def screen():
    # What a person reads: escape sequences (cursor moves stand in for
    # spaces) as spaces, runs of white space as one.
    t = re.sub(rb"\x1b\[[0-9;?<>=]*[ -/]*[@-~]", b" ", shown)
    t = re.sub(rb"\x1b\][^\x07\x1b]*(\x07|\x1b\\)", b" ", t)
    return re.sub(rb"\s+", b" ", t)
alive = True
for i, step in enumerate(spec["steps"]):
    if step[0] == "send":
        os.write(fd, step[1].encode())
        continue
    if step[0] == "idle":
        # Until the program has written nothing for step[1] ms.
        end = time.time() + spec["limit"]
        while time.time() < end and alive:
            before = len(shown)
            quiet_until = time.time() + step[1] / 1000.0
            while time.time() < quiet_until and len(shown) == before and alive:
                alive = more(quiet_until)
            if len(shown) == before:
                break
        continue
    end = time.time() + spec["limit"]
    seen = (lambda: shown.count(step[1].encode())) if step[0] == "wait_raw" else (lambda: screen().count(step[1].encode()))
    while seen() < step[2]:
        if time.time() > end or not alive:
            if spec.get("screen"):
                open(spec["screen"], "wb").write(screen())
            print("TIMEOUT %d" % i)
            signal.pthread_sigmask(signal.SIG_BLOCK, TERM)
            end_group()
            os.waitpid(pid, 0)
            sys.exit(0)
        alive = more(min(end, time.time() + 0.5))
end = time.time() + spec["limit"]
while time.time() < end:
    signal.pthread_sigmask(signal.SIG_BLOCK, TERM)
    # Seen without reaping: the group is ended first.
    if os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None:
        end_group()
        _, status = os.waitpid(pid, 0)
        print("EXIT %d" % os.waitstatus_to_exitcode(status))
        sys.exit(0)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, TERM)
    more(min(end, time.time() + 0.2))
# Still running after the last step: killed with its group, its own
# unreaped child.
signal.pthread_sigmask(signal.SIG_BLOCK, TERM)
end_group()
os.waitpid(pid, 0)
print("STILL RUNNING")
"#;

/// Claude Code 2.1.280 draws the trust dialog before it takes keys, and
/// shows nothing when it starts to: keys sent at once go to a dialog that
/// is then replaced, and an Enter reads as "No, exit". The screen staying
/// unchanged for this long is when the dialog has been seen to take them.
const SETTLED_MS: u64 = 3000;

/// Runs Claude Code interactively in `a`'s home against `model`, with
/// `args` (its flags, pinned per run), driven by `steps`; the driver's
/// last line.
fn interactive_claude(
    a: &AgentHome,
    model: &envcloak_testkit::agents::Model,
    cwd: &Path,
    args: &[&str],
    limit: u64,
    steps: serde_json::Value,
) -> String {
    let env: Vec<(String, String)> = a
        .env_for(model, cwd)
        .into_iter()
        .map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                v.to_string_lossy().into_owned(),
            )
        })
        .map(|(k, v)| {
            if k == "TERM" {
                (k, "xterm-256color".to_owned())
            } else {
                (k, v)
            }
        })
        .collect();
    let mut argv = vec![a.installed.exe.to_str().unwrap()];
    argv.extend_from_slice(args);
    let spec = json!({
        "argv": argv,
        "env": env,
        "cwd": cwd.to_str().unwrap(),
        "limit": limit,
        // What the screen showed when a wait ran out, for diagnosis: a
        // file in the test's root, outside HOME, swept with the home.
        "screen": a.root().join("pty-screen.txt").to_str().unwrap(),
        "steps": steps,
    });
    let spec_path = a.root().join("pty-spec.json");
    std::fs::write(&spec_path, spec.to_string()).unwrap();
    let mut cmd = std::process::Command::new(envcloak_e2e::python3());
    cmd.arg("-c")
        .arg(PTY_DRIVER)
        .arg(&spec_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let out = envcloak_testkit::agents::finish_within(cmd, std::time::Duration::from_secs(600));
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .last()
        .unwrap_or("")
        .to_owned()
}

/// The pseudo-terminal driver ends what its program leaves behind (Codex
/// review, medium: the program leads a session of its own, the harness's
/// group kill does not reach it, and the driver reaped it at once and
/// never killed its group). The program starts a process that ignores the
/// hangup and holds a FIFO's write end open, then exits; once the driver
/// has returned, the FIFO reads to its end: nothing holds it any more.
#[test]
fn the_pty_driver_ends_what_its_program_leaves_running() {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let home = envcloak_testkit::TestHome::new();
    let fifo = home.root().join("held");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let mut reader = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&fifo)
        .unwrap();
    let program = home.root().join("leaves-one.sh");
    std::fs::write(
        &program,
        format!(
            "exec 3>{}\nprintf x >&3\n(trap '' HUP; exec sleep 600) &\nexit 0\n",
            envcloak_e2e::quoted(fifo.to_str().unwrap())
        ),
    )
    .unwrap();
    let spec = json!({
        "argv": ["/bin/sh", program.to_str().unwrap()],
        "env": [["PATH", "/usr/bin:/bin"]],
        "cwd": home.root().to_str().unwrap(),
        "limit": 30,
        "steps": [],
    });
    let spec_path = home.root().join("pty-spec.json");
    std::fs::write(&spec_path, spec.to_string()).unwrap();
    let mut cmd = std::process::Command::new(envcloak_e2e::python3());
    cmd.arg("-c")
        .arg(PTY_DRIVER)
        .arg(&spec_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let out = envcloak_testkit::agents::finish_within(cmd, std::time::Duration::from_secs(60));
    let last = String::from_utf8_lossy(&out.stdout)
        .lines()
        .last()
        .unwrap_or("")
        .to_owned();
    assert_eq!(last, "EXIT 0");
    let mut got = Vec::new();
    let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut chunk = [0u8; 16];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    std::time::Instant::now() < end,
                    "a process the program left running still holds the FIFO"
                );
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => panic!("read the FIFO: {e}"),
        }
    }
    assert_eq!(got, b"x", "the program never started what it leaves behind");
}

/// One interactive Claude Code session through a pseudo-terminal (D-13,
/// review row 25): whether a prompt can be submitted before the workspace
/// trust dialog is answered, and which stores a real paste reaches
/// (`paste-cache/`, `history.jsonl`, the transcript), for a short paste
/// and a long one. The person's settings: onboarding done and the
/// harness's key approved, in `~/.claude.json`, labelled so.
#[test]
fn claude_code_interactive_trust_and_paste() {
    let Some(a) = host(Host::ClaudeCode, "native", "claude_code_interactive") else {
        return;
    };
    let project = a.root().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let script = json!({"steps": [{"say": "reply received"}], "side": "ok"});
    let approve_key = |model: &envcloak_testkit::agents::Model| {
        // Settings the person made, so the session opens at the trust
        // dialog: onboarding done, the key in ANTHROPIC_API_KEY approved.
        let token = model.token();
        let cfg = json!({"hasCompletedOnboarding": true, "theme": "dark",
                         "customApiKeyResponses": {"approved": [&token[token.len() - 20..]], "rejected": []}});
        std::fs::write(a.home_dir().join(".claude.json"), cfg.to_string()).unwrap();
    };

    // Before the trust dialog is answered: type a prompt and Enter.
    let before = Canary::new("BEFORE_TRUST", format!("ecpre-{:016x}", fresh_seed()));
    let model = envcloak_testkit::agents::Model::start(&script);
    approve_key(&model);
    let end = interactive_claude(
        &a,
        &model,
        &project,
        &[],
        30,
        json!([
            ["wait", "trust this folder", 1],
            ["idle", SETTLED_MS],
            ["send", format!("{}\r", before.as_str())],
        ]),
    );
    let report = model.finish();
    let reached = report.requests.iter().any(|r| {
        r.body
            .windows(before.as_str().len())
            .any(|w| w == before.as_str().as_bytes())
    });
    measure(
        &a,
        "interactive: prompt typed before the trust dialog is answered",
        format!(
            "{} ({end})",
            if reached {
                "reached the model"
            } else {
                "never reached the model"
            }
        ),
    );

    // Trust accepted with the documented keys, then two pastes.
    let short = Canary::new(
        "PASTE_SHORT",
        format!("ecpaste-{:016x}{:016x}", fresh_seed(), fresh_seed()),
    );
    let long_value = format!("eclong-{:016x}{:016x}", fresh_seed(), fresh_seed());
    let long = Canary::new("PASTE_LONG", long_value.clone());
    let long_text: String = (0..40)
        .map(|i| {
            if i == 20 {
                format!("{long_value}\n")
            } else {
                format!("line {i} of a long paste\n")
            }
        })
        .collect();
    // A project of its own: the first session's is left as it ended.
    let project = a.root().join("project-2");
    std::fs::create_dir_all(&project).unwrap();
    let model = envcloak_testkit::agents::Model::start(&script);
    approve_key(&model);
    let end = interactive_claude(
        &a,
        &model,
        &project,
        &[],
        120,
        json!([
            ["wait", "trust this folder", 1],
            ["idle", SETTLED_MS],
            // Down to "Yes" and Enter, in one write.
            ["send", "\u{1b}[B\r"],
            ["wait", "for shortcuts", 1],
            // A bracketed paste and Enter, as a terminal sends them.
            [
                "send",
                format!("\u{1b}[200~{}\u{1b}[201~\r", short.as_str())
            ],
            ["wait", "reply received", 1],
            ["send", format!("\u{1b}[200~{long_text}\u{1b}[201~\r")],
            ["wait", "reply received", 2],
            ["send", "/exit\r"],
        ]),
    );
    let report = model.finish();
    assert!(end.starts_with("EXIT"), "the session did not end: {end}");
    let cs = [short.clone(), long.clone()];
    let hits = Sweep::host_stores(&a, &cs, &[&report]);
    print!(
        "measurement: interactive paste hits host=claude-code os={}:\n{hits}",
        os()
    );
    for c in &cs {
        let stores: Vec<String> = hits
            .stores
            .iter()
            .filter(|s| hits.in_store(&s.store, &c.label) > 0)
            .map(|s| s.store.clone())
            .collect();
        measure(
            &a,
            &format!(
                "interactive: a {} paste is kept in",
                if c.label == "PASTE_SHORT" {
                    "one-line"
                } else {
                    "40-line"
                }
            ),
            stores.join(", "),
        );
    }

    // The Bash tool in an interactive session, the host on a terminal of
    // its own (the flags pinned: default permission mode, Bash allowed):
    // what a command it runs has for a terminal (TTY_PROBE).
    let project = a.root().join("project-3");
    std::fs::create_dir_all(&project).unwrap();
    let script = json!({"steps": [{"shell": TTY_PROBE}, {"say": "probe done"}], "side": "ok"});
    let model = envcloak_testkit::agents::Model::start(&script);
    approve_key(&model);
    let end = interactive_claude(
        &a,
        &model,
        &project,
        &["--permission-mode", "default", "--allowedTools", "Bash"],
        120,
        json!([
            ["wait", "trust this folder", 1],
            ["idle", SETTLED_MS],
            ["send", "\u{1b}[B\r"],
            ["wait", "for shortcuts", 1],
            ["send", "Check the terminal.\r"],
            ["wait", "probe done", 1],
            ["send", "/exit\r"],
        ]),
    );
    let report = model.finish();
    a.check_pinned();
    a.check_isolated();
    assert!(end.starts_with("EXIT"), "the session did not end: {end}");
    let after = report
        .requests
        .iter()
        .find(|r| r.pick.as_deref() == Some("step 1"))
        .map(|r| last_tool_output(&String::from_utf8_lossy(&r.body)))
        .unwrap_or_else(|| panic!("no request after the probe: {:?}", report.requests));
    let shown = tty_shown(&after).unwrap_or_else(|| panic!("the probe printed {after:?}"));
    measure(
        &a,
        "interactive: shell tool terminal, the host on a terminal (T=tty, N=not)",
        shown,
    );
}

// ---------------------------------------------------------------------
// Tier 2 (M2-04's spike, Codex review: drivability was read from the
// documentation only). Each tier-2 host, with its documented base-URL
// setting pointed at the scripted model in an isolated home: which
// endpoints it calls; for the drivable ones, whether the scripted model's
// call to its shell tool starts a command, and what that command's
// ancestry is (the executable, interpreter and script layout M2-10
// classifies). Flags are pinned per host; no host runs in a bypass mode.
// ---------------------------------------------------------------------

/// What the probe command prints: a marker, then each ancestor up to four
/// levels, nearest first, as `ANC <comm> | <args, cut>`. The keys are
/// built at run time, so the command's own text never holds them whole.
const ANCESTRY_PROBE: &str = "printf '%s%s\\n' 'MARK' 'ER-ran'; p=$$; i=0; \
     while [ \"$p\" -gt 1 ] && [ $i -lt 4 ]; do \
     printf '%s %s | %s\\n' 'AN''C' \"$(ps -o comm= -p \"$p\")\" \"$(ps -o args= -p \"$p\" | cut -c1-400)\"; \
     p=$(ps -o ppid= -p \"$p\" | tr -d ' '); i=$((i+1)); done";

/// One tier-2 host run: the scripted model's report, the host's output
/// and the host as installed.
struct Tier2Run {
    report: envcloak_testkit::agents::ModelReport,
    output: std::process::Output,
}

/// Runs the tier-2 host `id`/`variant` in a fresh home against a scripted
/// model: the probe through its shell tool `shell` (the tool's name and
/// the rest of its input), or one plain reply when it has none. `setup`
/// writes the host's settings into the home and adds its arguments and
/// variables. Every proxy variable points at the model, which refuses and
/// records every tunnel.
fn tier_2(
    id: &str,
    variant: &str,
    shell: Option<(&str, serde_json::Value)>,
    setup: impl FnOnce(
        &envcloak_testkit::TestHome,
        &envcloak_testkit::agents::Model,
        &mut std::process::Command,
    ),
) -> Option<Tier2Run> {
    let found = Installed::find(&versions_toml(), id, variant);
    let installed = require(found, &format!("tier 2 ({id})"))?;
    let home = envcloak_testkit::TestHome::new();
    let project = home.root().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let script = match &shell {
        Some((tool, extra)) => {
            let mut input = extra.clone();
            input["command"] = json!(ANCESTRY_PROBE);
            json!({"steps": [{"tool": tool, "input": input}, {"say": "probe done"}], "side": "ok"})
        }
        None => json!({"steps": [{"say": "scripted reply"}], "side": "ok"}),
    };
    let model = envcloak_testkit::agents::Model::start(&script);
    let mut cmd = installed.command();
    cmd.env_clear().envs(home.vars());
    for k in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
        cmd.env(k, model.base_url());
    }
    for k in ["NO_PROXY", "no_proxy"] {
        cmd.env(k, "127.0.0.1,localhost");
    }
    setup(&home, &model, &mut cmd);
    cmd.current_dir(&project)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let output = envcloak_testkit::agents::finish_within(cmd, envcloak_testkit::agents::RUN_LIMIT);
    let report = model.finish();
    if let Err(why) = installed.verify() {
        panic!("the host changed during the run: {why}");
    }
    let label = format!("{id}/{variant} {}", installed.pin.version);
    let mut tunnels = report.connects();
    tunnels.sort_unstable();
    tunnels.dedup();
    println!(
        "measurement: tier 2 host={label} os={}: endpoints {}; tunnels refused {}; outcome {}",
        os(),
        report.model_endpoints().join(", "),
        tunnels.join(", "),
        report.outcome
    );
    Some(Tier2Run { report, output })
}

/// The probe's answer in the request after the shell call: the marker,
/// and the ancestry as `comm (args)` entries, nearest first, the shell
/// itself left out (its arguments are the probe).
fn tier_2_probe(run: &Tier2Run) -> (bool, Vec<String>) {
    let Some(r) = run
        .report
        .requests
        .iter()
        .find(|r| r.pick.as_deref() == Some("step 1"))
    else {
        return (false, Vec::new());
    };
    let text = last_tool_text(&String::from_utf8_lossy(&r.body));
    let ran = text.contains("MARKER-ran");
    let lines: Vec<&str> = text
        .lines()
        .filter_map(|l| l.trim().strip_prefix("ANC "))
        .collect();
    let base = |p: &str| p.rsplit('/').next().unwrap_or(p).to_owned();
    // The shell, by name; then its ancestors up to this test.
    let shell = lines
        .first()
        .map(|l| base(l.split_once(" | ").map_or(*l, |(c, _)| c)));
    let chain = shell
        .into_iter()
        .chain(lines.iter().skip(1).map(|l| {
            let (comm, args) = l.split_once(" | ").unwrap_or((l, ""));
            // The program and, when it is an interpreter, its script.
            let mut words = args.split_whitespace();
            let program = words.next().map(base).unwrap_or_default();
            let script = words
                .next()
                .filter(|w| w.ends_with(".js") || w.ends_with(".mjs") || w.ends_with(".cjs"))
                .map(base);
            match script {
                Some(script) => format!("{} ({program} {script})", base(comm)),
                None => format!("{} ({program})", base(comm)),
            }
        }))
        .take_while(|c| !c.starts_with("agent_hosts"))
        .collect();
    (ran, chain)
}

/// A drivable tier-2 host: it spoke Anthropic Messages to the scripted
/// model, its shell tool ran the probe, and the command's shell and its
/// nearest ancestors are `expected`, by name, in order (the shell first).
fn tier_2_drivable(id: &str, run: &Tier2Run, expected: &[&str]) {
    assert!(
        run.report
            .model_endpoints()
            .iter()
            .any(|e| e == "POST /v1/messages"),
        "{id} did not speak Anthropic Messages to the scripted model: {:?}",
        run.report.requests
    );
    let (ran, chain) = tier_2_probe(run);
    println!(
        "measurement: tier 2 host={id} os={}: shell tool ran the command: {ran}; its ancestry, \
         nearest first: {}",
        os(),
        chain.join(" <- ")
    );
    assert!(
        ran,
        "{id}'s shell tool did not run the command; stdout {:?}",
        String::from_utf8_lossy(&run.output.stdout)
    );
    for (i, want) in expected.iter().enumerate() {
        assert!(
            chain.get(i).is_some_and(|c| c.contains(want)),
            "{id}: ancestor {i} is not {want}: {chain:?}"
        );
    }
}

/// Qwen Code: `modelProviders.anthropic` in `~/.qwen/settings.json`, the
/// key by `envKey`; `-p`'s positional prompt in the default approval mode
/// with the shell tool allowed by name (headless runs deny it otherwise).
#[test]
fn tier_2_qwen_code_against_the_scripted_model() {
    let Some(run) = tier_2(
        "qwen-code",
        "npm",
        Some(("run_shell_command", json!({"description": "probe"}))),
        |home, model, cmd| {
            let dir = home.home().join(".qwen");
            std::fs::create_dir_all(&dir).unwrap();
            let settings = json!({
                "modelProviders": {"anthropic": [{"id": "ec-scripted", "name": "ec",
                    "envKey": "EC_MODEL_TOKEN", "baseUrl": model.base_url()}]},
                "model": {"name": "ec-scripted"},
                "security": {"auth": {"selectedType": "anthropic"}},
            });
            std::fs::write(dir.join("settings.json"), settings.to_string()).unwrap();
            cmd.env("EC_MODEL_TOKEN", model.token()).args([
                "Run the probe.",
                "--approval-mode",
                "default",
                "--allowed-tools",
                "run_shell_command",
            ]);
        },
    ) else {
        return;
    };
    tier_2_drivable("qwen-code", &run, &["sh", "node (node cli-entry.js)"]);
}

/// Kimi Code: an `anthropic` provider in `$KIMI_CODE_HOME/config.toml`
/// (`~/.kimi-code`), the key by `api_key_env`; `-p`.
#[test]
fn tier_2_kimi_code_against_the_scripted_model() {
    let Some(run) = tier_2(
        "kimi-code",
        "npm",
        Some(("Bash", json!({}))),
        |home, model, cmd| {
            let dir = home.home().join(".kimi-code");
            std::fs::create_dir_all(&dir).unwrap();
            let config = format!(
                "default_model = \"ec\"\n\n[providers.ec]\ntype = \"anthropic\"\n\
                 base_url = {}\napi_key_env = \"EC_MODEL_TOKEN\"\n\n[models.ec]\n\
                 provider = \"ec\"\nmodel = \"ec-scripted\"\nmax_context_size = 200000\n",
                json!(model.base_url())
            );
            std::fs::write(dir.join("config.toml"), config).unwrap();
            cmd.env("EC_MODEL_TOKEN", model.token())
                .env("KIMI_CODE_HOME", &dir)
                .args(["-p", "Run the probe."]);
        },
    ) else {
        return;
    };
    // Node, which names its process `kimi-code` (its arguments too).
    tier_2_drivable("kimi-code", &run, &["sh", "kimi-code"]);
}

/// OpenCode: a provider in `~/.config/opencode/opencode.json` on the
/// bundled `@ai-sdk/anthropic`, the key from the environment; `run`.
#[test]
fn tier_2_opencode_against_the_scripted_model() {
    let Some(run) = tier_2(
        "opencode",
        "native",
        Some(("bash", json!({"description": "probe"}))),
        |home, model, cmd| {
            let dir = home.root().join("config").join("opencode");
            std::fs::create_dir_all(&dir).unwrap();
            let config = json!({
                "provider": {"ec": {"npm": "@ai-sdk/anthropic", "name": "ec",
                    "options": {"baseURL": format!("{}/v1", model.base_url()),
                                "apiKey": "{env:EC_MODEL_TOKEN}"},
                    "models": {"ec-scripted": {"name": "ec-scripted"}}}},
                "model": "ec/ec-scripted",
                "autoupdate": false,
                "share": "disabled",
            });
            std::fs::write(dir.join("opencode.json"), config.to_string()).unwrap();
            cmd.env("EC_MODEL_TOKEN", model.token())
                .args(["run", "Run the probe."]);
        },
    ) else {
        return;
    };
    tier_2_drivable("opencode", &run, &["sh", "opencode (opencode)"]);
}

/// Copilot CLI: `COPILOT_PROVIDER_BASE_URL` with
/// `COPILOT_PROVIDER_TYPE=anthropic`, offline, updates off; `-p` with the
/// shell tool allowed (`--allow-tool=shell`, not every tool).
#[test]
fn tier_2_copilot_cli_against_the_scripted_model() {
    let Some(run) = tier_2(
        "copilot-cli",
        "npm",
        Some(("bash", json!({"description": "probe", "mode": "sync"}))),
        |_, model, cmd| {
            cmd.env("COPILOT_OFFLINE", "true")
                .env("COPILOT_AUTO_UPDATE", "false")
                .env("COPILOT_PROVIDER_BASE_URL", model.base_url())
                .env("COPILOT_PROVIDER_TYPE", "anthropic")
                .env("COPILOT_PROVIDER_API_KEY", model.token())
                .env("COPILOT_MODEL", "ec-scripted")
                .args(["-p", "Run the probe.", "--allow-tool=shell"]);
        },
    ) else {
        return;
    };
    // `node npm-loader.js` starts the platform package's binary (pinned
    // as `starts`), which runs the command. Matched by its program: on
    // Linux its process name is its main thread's (`MainThread`).
    tier_2_drivable(
        "copilot-cli",
        &run,
        &["sh", "(copilot)", "node (node npm-loader.js)"],
    );
}

/// Gemini CLI: `GOOGLE_GEMINI_BASE_URL` with a Gemini API key. It speaks
/// the Gemini API, not one of the scripted model's two protocols: not
/// drivable, measured.
#[test]
fn tier_2_gemini_cli_speaks_neither_protocol() {
    let Some(run) = tier_2("gemini-cli", "npm", None, |home, model, cmd| {
        let dir = home.home().join(".gemini");
        std::fs::create_dir_all(&dir).unwrap();
        let settings = json!({"security": {"auth": {"selectedType": "gemini-api-key"}},
                              "general": {"disableAutoUpdate": true}});
        std::fs::write(dir.join("settings.json"), settings.to_string()).unwrap();
        cmd.env("GOOGLE_GEMINI_BASE_URL", model.base_url())
            .env("GEMINI_API_KEY", model.token())
            .args(["-p", "Say hello.", "--skip-trust"]);
    }) else {
        return;
    };
    assert!(
        run.report.model_calls().is_empty(),
        "Gemini CLI spoke a protocol the scripted model serves: {:?}",
        run.report.requests
    );
    assert!(
        run.report
            .requests
            .iter()
            .any(|r| r.path.starts_with("/v1beta/models/")),
        "Gemini CLI did not reach the base URL: {:?}",
        run.report.requests
    );
}

/// Cursor CLI: no documented base-URL setting; with every proxy variable
/// at the scripted model, all it tries is a tunnel to its own servers.
/// Not drivable, measured.
#[test]
fn tier_2_cursor_cli_has_no_base_url() {
    let Some(run) = tier_2("cursor-cli", "native", None, |_, model, cmd| {
        cmd.env("CURSOR_API_KEY", model.token())
            .args(["-p", "Say hello."]);
    }) else {
        return;
    };
    assert!(
        run.report.model_endpoints().is_empty(),
        "Cursor CLI reached the scripted model itself: {:?}",
        run.report.requests
    );
}
