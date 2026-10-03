//! The agent catalog against the pinned hosts (M2 plan task M2-10;
//! gates 23 and 25; risk K-03). The catalog's patterns rest on these
//! layouts (integrations/agents.toml), so each is checked on the real
//! install M2-04's cache holds:
//!
//! - every tier-2 host, started on a pseudo-terminal of its own and left
//!   waiting for input, classifies as its catalog entry when its running
//!   processes are read as the daemon reads an ancestor (its executable,
//!   and its arguments where the catalog needs them), with the basis that
//!   decides whether it may root a grant above a caller's session; Cursor
//!   CLI in the layout its installer makes, which M2-04's cache does not;
//! - a command Codex starts with `tty: true` (on a pseudo-terminal of its
//!   own, in a session it leads) under `env -i` is an agent subject rooted
//!   at Codex: a grant for its terminal does not cover it, and its proofs
//!   are refused;
//! - for each tier-2 host M2-04 found drivable, a command its shell tool
//!   starts on a pseudo-terminal of its own (the shape of Gemini CLI's
//!   `node-pty`), under `env -i`, is an agent subject labeled with the
//!   host's entry, and its proofs are refused.
//!
//! The caller is `ec-probe`, which connects to a socket this test listens
//! on, as the CLI connects to the daemon, and stays until it is closed;
//! the test gathers its evidence there with the builtin catalog, as the
//! daemon does (`envcloak_policy::gather`). Lines starting `measurement:`
//! feed docs/AGENTS.md.

use std::os::fd::AsFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use envcloak_e2e::{python3, quoted, versions_toml};
use envcloak_policy::{
    AgentCatalog, AgentLabel, Claims, MatchBasis, ProofRefusal, SubjectEvidence, SubjectKind,
    gather,
};
use envcloak_testkit::agents::{AgentHome, GroupChild, Host, HostFlags, Installed, require};
use envcloak_testkit::{TestHome, testkit_bin};
use serde_json::json;

use super::{os, tier_2};

/// Runs argv[1:] as the leader of a new session on a new
/// pseudo-terminal (120 columns, 40 rows), reading and dropping what it
/// prints. Once it has printed something and then nothing for two
/// seconds (it drew its screen and waits for input), prints `QUIET` on
/// standard output, once. When this driver's standard input closes, kills
/// that session's process group while its leader is unreaped, then reaps
/// it.
const PTY_HOLD: &str = r#"import fcntl, os, pty, select, signal, struct, sys, termios, time
pid, fd = pty.fork()
if pid == 0:
    os.execv(sys.argv[1], sys.argv[1:])
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
seen, last, told = False, time.monotonic(), False
while True:
    r, _, _ = select.select([fd, 0], [], [], 0.2)
    if fd in r:
        try:
            data = os.read(fd, 65536)
        except OSError:
            data = b""
        if not data:
            break
        seen, last = True, time.monotonic()
    if 0 in r and not os.read(0, 4096):
        break
    if seen and not told and time.monotonic() - last >= 2:
        sys.stdout.write("QUIET\n")
        sys.stdout.flush()
        told = True
try:
    os.killpg(pid, signal.SIGKILL)
except OSError:
    pass
os.waitpid(pid, 0)
"#;

/// Runs argv[1:] as the leader of a new session on a new pseudo-terminal
/// until it ends, dropping what it prints, as `node-pty` and Codex's
/// `tty: true` start a command; exits with its status.
const PTY_ONCE: &str = r#"import os, pty, sys
pid, fd = pty.fork()
if pid == 0:
    os.execv(sys.argv[1], sys.argv[1:])
while True:
    try:
        data = os.read(fd, 65536)
    except OSError:
        break
    if not data:
        break
_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status) & 255)
"#;

/// A socket this test listens on, in a short temporary directory, and the
/// evidence of each caller that connects to it.
struct Listener {
    _home: TestHome,
    sock: PathBuf,
    l: UnixListener,
}

impl Listener {
    fn new() -> Self {
        let home = TestHome::new();
        let sock = home.root().join("e.sock");
        let l = UnixListener::bind(&sock).unwrap();
        l.set_nonblocking(true).unwrap();
        Listener {
            _home: home,
            sock,
            l,
        }
    }

    /// The evidence of the next caller, gathered while it is connected, or
    /// why there is none within `limit`. The connection is then closed,
    /// which lets the caller exit.
    fn next_within(&self, limit: Duration) -> Result<SubjectEvidence, String> {
        let end = Instant::now() + limit;
        let s: UnixStream = loop {
            match self.l.accept() {
                Ok((s, _)) => break s,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= end {
                        return Err(format!("no caller connected within {limit:?}"));
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => return Err(format!("accept: {e}")),
            }
        };
        s.set_nonblocking(false).map_err(|e| e.to_string())?;
        let peer = envcloak_sys::peer_identity(s.as_fd()).map_err(|e| e.to_string())?;
        gather(&peer, Claims::none(), &AgentCatalog::builtin()).map_err(|e| e.to_string())
    }
}

/// The script a host's shell tool runs (`sh ./ec-pty-probe.sh`, in the
/// directory the host works in, so the command names no path a host
/// would ask about): `ec-probe <socket>` under `env -i`, leading a session
/// of its own on a new pseudo-terminal.
fn probe_on_its_own_pty(sock: &Path) -> String {
    let probe = testkit_bin("ec-probe");
    let line = [
        "exec".to_owned(),
        quoted(&python3().to_string_lossy()),
        "-c".to_owned(),
        quoted(PTY_ONCE),
        "/usr/bin/env".to_owned(),
        "-i".to_owned(),
        quoted(&probe.to_string_lossy()),
        quoted(&sock.to_string_lossy()),
    ]
    .join(" ");
    format!("{line}\n")
}

/// The script's name, in the host's working directory.
const PTY_SCRIPT: &str = "ec-pty-probe.sh";

/// Checks the evidence of a command `id`'s host started on a
/// pseudo-terminal of its own: it leads its session there, with no marker,
/// and is an agent subject labeled `id` at the nearest agent, its basis
/// `basis`; a grant for its terminal (rooted at its session's leader, for
/// a terminal subject) does not cover it, and its proofs are refused.
/// Prints the measurement.
fn assert_pty_command_is_an_agent(e: &SubjectEvidence, host: &str, id: &str, basis: MatchBasis) {
    let (n, label) = e
        .nearest_agent()
        .unwrap_or_else(|| panic!("{host}: no agent in the command's ancestry: {e:?}"));
    println!(
        "measurement: catalog host={host} os={}: a command on its own pseudo-terminal: kind {:?}, \
         nearest agent {} ({:?}) at {n}, root at {}, terminal {}, proof refusal {:?}",
        os(),
        e.kind(),
        label.id,
        label.basis,
        e.root_index(),
        e.terminal(),
        e.proof_refusal().map(ProofRefusal::token)
    );
    assert!(e.terminal(), "{host}: no controlling terminal: {e:?}");
    let leader = e.session_leader().expect("its session's leader");
    assert!(leader.same(e.caller()), "{host}: {e:?}");
    assert!(e.claims().markers().is_empty());
    assert_eq!((label.id.as_str(), label.basis), (id, basis), "{host}");
    assert_eq!(e.kind(), SubjectKind::Agent, "{host}");
    assert!(!e.covered_by(leader, SubjectKind::Terminal), "{host}");
    assert!(!e.covered_by(&e.root(), SubjectKind::Terminal), "{host}");
    assert_eq!(e.proof_refusal(), Some(ProofRefusal::Agent), "{host}");
}

/// Gate 23 and 25 (risk K-03): Codex's `tty: true` starts a command on a
/// pseudo-terminal of its own. Under `env -i`, with no sandbox in the way
/// of the socket (`danger-full-access`; the classification, not the
/// sandbox, is measured here), the command is an agent subject rooted at
/// the pinned `codex` binary, above its session.
#[test]
fn a_codex_tty_true_command_is_an_agent() {
    let found = Installed::find(&versions_toml(), Host::Codex.id(), "native");
    let Some(installed) = require(found, "a_codex_tty_true_command_is_an_agent") else {
        return;
    };
    let a = AgentHome::start(Host::Codex, installed);
    let l = Listener::new();
    let probe = testkit_bin("ec-probe");
    let cmd = format!(
        "/usr/bin/env -i {} {}",
        quoted(&probe.to_string_lossy()),
        quoted(&l.sock.to_string_lossy())
    );
    let script = json!({"steps": [
        {"tool": "exec_command", "input": {"cmd": cmd, "tty": true, "yield_time_ms": 30000}},
        {"say": "done"}
    ]});
    let running = a.spawn(
        &script,
        "Run the probe.",
        &HostFlags::codex("danger-full-access", "never"),
        &a.home_dir(),
    );
    let e = l.next_within(Duration::from_secs(240));
    let run = running.wait();
    let e = e.unwrap_or_else(|why| panic!("{why}; the host said {}", run.text()));
    assert_pty_command_is_an_agent(&e, "codex", "codex", MatchBasis::Executable);
    // Rooted at the pinned binary itself, the host's own process.
    let root = e.root();
    let exe = root.exe.as_ref().expect("the root's executable");
    assert_eq!(exe.path.file_name().unwrap(), "codex", "{e:?}");
    assert!(e.root_index() > 0);
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    a.check_pinned();
}

/// One drivable tier-2 host's shell tool runs [`probe_on_its_own_pty`];
/// the command's evidence is gathered while the host runs.
fn drivable_pty_command(
    id: &str,
    variant: &str,
    tool: &str,
    input: serde_json::Value,
    setup: impl FnOnce(
        &envcloak_testkit::TestHome,
        &envcloak_testkit::agents::Model,
        &mut std::process::Command,
    ),
) -> Option<SubjectEvidence> {
    pinned(id, variant, id)?;
    let l = Listener::new();
    let mut input = input;
    input["command"] = json!(format!("sh ./{PTY_SCRIPT}"));
    let script = probe_on_its_own_pty(&l.sock);
    let setup = |home: &envcloak_testkit::TestHome,
                 model: &envcloak_testkit::agents::Model,
                 cmd: &mut std::process::Command| {
        std::fs::write(home.root().join("project").join(PTY_SCRIPT), &script).unwrap();
        setup(home, model, cmd);
    };
    let (tx, rx) = mpsc::channel();
    let run = std::thread::scope(|scope| {
        scope.spawn(|| {
            let _ = tx.send(l.next_within(Duration::from_secs(240)));
        });
        tier_2(id, variant, Some((tool, input)), setup)
    });
    let run = run?;
    let e = rx.recv().unwrap();
    Some(e.unwrap_or_else(|why| {
        panic!(
            "{id}: {why}; the host said {}",
            String::from_utf8_lossy(&run.output.stdout)
        )
    }))
}

/// Gates 23 and 25 for Qwen Code (drivable, M2-04): node runs its entry
/// script, so it is known by that script, and roots no grant above the
/// command's session.
#[test]
fn a_qwen_code_command_on_its_own_pty_is_an_agent() {
    let Some(e) = drivable_pty_command(
        "qwen-code",
        "npm",
        "run_shell_command",
        json!({"description": "probe"}),
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
            cmd.env("EC_MODEL_TOKEN", model.api_key()).args([
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
    assert_pty_command_is_an_agent(&e, "qwen-code", "qwen-code", MatchBasis::Asserted);
}

/// Gates 23 and 25 for Kimi Code (drivable): node renames its process to
/// `kimi-code`, which the `kimi` entry knows.
#[test]
fn a_kimi_code_command_on_its_own_pty_is_an_agent() {
    let Some(e) =
        drivable_pty_command("kimi-code", "npm", "Bash", json!({}), |home, model, cmd| {
            let dir = home.home().join(".kimi-code");
            std::fs::create_dir_all(&dir).unwrap();
            let config = format!(
                "default_model = \"ec\"\n\n[providers.ec]\ntype = \"anthropic\"\n\
                 base_url = {}\napi_key_env = \"EC_MODEL_TOKEN\"\n\n[models.ec]\n\
                 provider = \"ec\"\nmodel = \"ec-scripted\"\nmax_context_size = 200000\n",
                json!(model.base_url())
            );
            std::fs::write(dir.join("config.toml"), config).unwrap();
            cmd.env("EC_MODEL_TOKEN", model.api_key())
                .env("KIMI_CODE_HOME", &dir)
                .args(["-p", "Run the probe."]);
        })
    else {
        return;
    };
    assert_pty_command_is_an_agent(&e, "kimi-code", "kimi", MatchBasis::Asserted);
}

/// Gates 23 and 25 for OpenCode (drivable): its native binary, known by
/// its path, roots the grant above the command's session.
#[test]
fn an_opencode_command_on_its_own_pty_is_an_agent() {
    let Some(e) = drivable_pty_command(
        "opencode",
        "native",
        "bash",
        json!({"description": "probe"}),
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
            cmd.env("EC_MODEL_TOKEN", model.api_key())
                .args(["run", "Run the probe."]);
        },
    ) else {
        return;
    };
    assert_pty_command_is_an_agent(&e, "opencode", "opencode", MatchBasis::Executable);
    let root = e.root();
    let exe = root.exe.as_ref().expect("the root's executable");
    assert_eq!(exe.path.file_name().unwrap(), "opencode", "{e:?}");
}

/// Gates 23 and 25 for Copilot CLI (drivable): `node npm-loader.js`
/// starts the platform binary, which runs the command and is known by its
/// path.
#[test]
fn a_copilot_cli_command_on_its_own_pty_is_an_agent() {
    let Some(e) = drivable_pty_command(
        "copilot-cli",
        "npm",
        "bash",
        json!({"description": "probe", "mode": "sync"}),
        |_, model, cmd| {
            cmd.env("COPILOT_OFFLINE", "true")
                .env("COPILOT_AUTO_UPDATE", "false")
                .env("COPILOT_PROVIDER_BASE_URL", model.base_url())
                .env("COPILOT_PROVIDER_TYPE", "anthropic")
                .env("COPILOT_PROVIDER_API_KEY", model.api_key())
                .env("COPILOT_MODEL", "ec-scripted")
                .args(["-p", "Run the probe.", "--allow-tool=shell"]);
        },
    ) else {
        return;
    };
    assert_pty_command_is_an_agent(&e, "copilot-cli", "copilot-cli", MatchBasis::Executable);
    let root = e.root();
    let exe = root.exe.as_ref().expect("the root's executable");
    assert_eq!(exe.path.file_name().unwrap(), "copilot", "{e:?}");
}

/// What the daemon would make of process `pid` as an ancestor of a caller
/// of this uid: read as `gather` reads it (its executable, and its
/// arguments where the catalog needs them), then classified.
fn classify_running(cat: &AgentCatalog, pid: i32) -> Option<AgentLabel> {
    let mut p = envcloak_sys::proc_info(pid).ok()?;
    if p.uid != envcloak_sys::effective_uid() {
        return None;
    }
    if cat.needs_argv(&p) {
        p.argv = envcloak_sys::proc_argv(pid).ok();
    }
    cat.classify(&p)
}

/// Process `root` and its descendants, from `ps`.
fn tree(root: i32) -> Vec<i32> {
    let out = Command::new("ps")
        .args(["-A", "-o", "pid=,ppid="])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap();
    let pairs: Vec<(i32, i32)> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let mut w = l.split_whitespace();
            Some((w.next()?.parse().ok()?, w.next()?.parse().ok()?))
        })
        .collect();
    let mut found = vec![root];
    let mut i = 0;
    while i < found.len() {
        let parent = found[i];
        found.extend(
            pairs
                .iter()
                .filter(|(_, pp)| *pp == parent)
                .map(|(p, _)| *p),
        );
        i += 1;
    }
    found
}

/// The file name of the executable process `pid` runs.
fn exe_name(pid: i32) -> Option<String> {
    let p = envcloak_sys::proc_info(pid).ok()?;
    let exe = p.exe?;
    Some(exe.path.file_name()?.to_string_lossy().into_owned())
}

/// Starts `argv` on a pseudo-terminal of its own in `home`, with the
/// variables of `home` and nothing else from this process, waits (up to
/// 120 seconds) until it waits for input ([`PTY_HOLD`]'s `QUIET`), then
/// reads its processes as the daemon reads ancestors: those whose
/// executable's file name is a key of `want` must be there, each key at
/// least once, and each must classify as its value, an entry id and a
/// basis. Prints what it found, then ends the tree; panics when the host
/// never waited for input or a process did not classify so.
fn running_classifies(
    host: &str,
    home: &TestHome,
    argv: &[&std::ffi::OsStr],
    want: &[(&str, &str, MatchBasis)],
) {
    let cat = AgentCatalog::builtin();
    let mut cmd = Command::new(python3());
    cmd.arg("-c").arg(PTY_HOLD).args(argv);
    cmd.env_clear()
        .envs(home.vars())
        .env("DISABLE_AUTOUPDATER", "1")
        .current_dir(home.home())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // Nothing leaves loopback: a proxy that refuses every connection.
    for k in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
        cmd.env(k, "http://127.0.0.1:9");
    }
    let mut driver = GroupChild::spawn(&mut cmd).unwrap();
    let stdin = driver.take_stdin();
    let stdout = driver.take_stdout().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        use std::io::BufRead;
        for line in std::io::BufReader::new(stdout).lines() {
            if tx.send(line.unwrap_or_default()).is_err() {
                break;
            }
        }
    });
    let quiet = rx
        .recv_timeout(Duration::from_secs(120))
        .is_ok_and(|l| l == "QUIET");
    let driver_pid = i32::try_from(driver.id()).unwrap();
    let mut seen: Vec<String> = Vec::new();
    let mut good = quiet;
    let mut present = vec![false; want.len()];
    for pid in tree(driver_pid).into_iter().skip(1) {
        let Some(name) = exe_name(pid) else {
            continue;
        };
        let got = classify_running(&cat, pid);
        seen.push(format!(
            "{name}: {:?}",
            got.as_ref().map(|l| (l.id.as_str(), l.basis))
        ));
        if let Some(k) = want.iter().position(|(n, _, _)| *n == name) {
            present[k] = true;
            let (_, id, basis) = want[k];
            if got.as_ref().map(|l| (l.id.as_str(), l.basis)) != Some((id, basis)) {
                good = false;
            }
        }
    }
    let shown = seen.join("; ");
    println!(
        "measurement: catalog host={host} os={}: waiting for input: {quiet}; its running \
         processes read as ancestors: {shown}",
        os()
    );
    drop(stdin);
    let _ = driver.end_within(Duration::from_secs(30));
    assert!(quiet, "{host}: it never waited for input");
    assert!(
        good && present.iter().all(|p| *p),
        "{host}: its processes did not classify as {want:?} while it waited for input: {shown}"
    );
}

/// The pinned host `id`/`variant`, or `None` when it is not installed
/// (a skip, except in CI).
fn pinned(id: &str, variant: &str, test: &str) -> Option<Installed> {
    require(Installed::find(&versions_toml(), id, variant), test)
}

/// The pinned host's command line: its interpreter, if any, then its
/// entry.
fn argv_of(i: &Installed) -> Vec<PathBuf> {
    match &i.interpreter {
        Some((node, _)) => vec![node.clone(), i.exe.clone()],
        None => vec![i.exe.clone()],
    }
}

fn os_strs(v: &[PathBuf]) -> Vec<&std::ffi::OsStr> {
    v.iter().map(|p| p.as_os_str()).collect()
}

/// Gemini CLI (tier 2, not drivable): node runs its bundle, and relaunches
/// it in a child node with more memory; both are Gemini CLI by their
/// script.
#[test]
fn gemini_cli_running_is_its_entry() {
    let Some(i) = pinned("gemini-cli", "npm", "gemini_cli_running_is_its_entry") else {
        return;
    };
    let home = TestHome::new();
    let argv = argv_of(&i);
    running_classifies(
        "gemini-cli",
        &home,
        &os_strs(&argv),
        &[("node", "gemini-cli", MatchBasis::Asserted)],
    );
}

/// Copilot CLI: `node npm-loader.js`, by its script, and the platform
/// binary it starts, by its path.
#[test]
fn copilot_cli_running_is_its_entry() {
    let Some(i) = pinned("copilot-cli", "npm", "copilot_cli_running_is_its_entry") else {
        return;
    };
    let home = TestHome::new();
    let argv = argv_of(&i);
    running_classifies(
        "copilot-cli",
        &home,
        &os_strs(&argv),
        &[
            ("node", "copilot-cli", MatchBasis::Asserted),
            ("copilot", "copilot-cli", MatchBasis::Executable),
        ],
    );
}

/// OpenCode: the native binary, by its path.
#[test]
fn opencode_running_is_its_entry() {
    let Some(i) = pinned("opencode", "native", "opencode_running_is_its_entry") else {
        return;
    };
    let home = TestHome::new();
    let argv = argv_of(&i);
    running_classifies(
        "opencode",
        &home,
        &os_strs(&argv),
        &[("opencode", "opencode", MatchBasis::Executable)],
    );
}

/// Kimi Code: node, which renames its process and overwrites its own
/// arguments with `kimi-code`.
#[test]
fn kimi_code_running_is_its_entry() {
    let Some(i) = pinned("kimi-code", "npm", "kimi_code_running_is_its_entry") else {
        return;
    };
    let home = TestHome::new();
    let argv = argv_of(&i);
    running_classifies(
        "kimi-code",
        &home,
        &os_strs(&argv),
        &[("node", "kimi", MatchBasis::Asserted)],
    );
}

/// Qwen Code: node runs its entry script.
#[test]
fn qwen_code_running_is_its_entry() {
    let Some(i) = pinned("qwen-code", "npm", "qwen_code_running_is_its_entry") else {
        return;
    };
    let home = TestHome::new();
    let argv = argv_of(&i);
    running_classifies(
        "qwen-code",
        &home,
        &os_strs(&argv),
        &[("node", "qwen-code", MatchBasis::Asserted)],
    );
}

/// Cursor CLI, in the layout its installer makes (https://cursor.com/
/// install): `~/.local/share/cursor-agent/versions/<version>/` holding its
/// own node, its `cursor-agent` script and its index.js. M2-04's cache
/// keeps the package as downloaded, so the test lays the version out in
/// the home: the script and node copied (the kernel names a process after
/// the file it runs, not a link to it), the rest linked. The script runs
/// node on index.js, `argv[0]` set to the script's path; node is Cursor by
/// its path, and lies in the entry's install tree.
#[test]
fn cursor_cli_running_is_its_entry() {
    let Some(i) = pinned("cursor-cli", "native", "cursor_cli_running_is_its_entry") else {
        return;
    };
    let home = TestHome::new();
    let version = home
        .home()
        .join(".local/share/cursor-agent/versions")
        .join(&i.pin.version);
    std::fs::create_dir_all(&version).unwrap();
    for entry in std::fs::read_dir(&i.dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let to = version.join(&name);
        if name == "cursor-agent" || name == "node" {
            std::fs::copy(entry.path(), &to).unwrap();
        } else {
            std::os::unix::fs::symlink(entry.path(), &to).unwrap();
        }
    }
    let node = version.join("node");
    assert!(
        AgentCatalog::builtin().within_install_tree("cursor", &node, Some(&home.home())),
        "{node:?}"
    );
    let script = version.join("cursor-agent");
    running_classifies(
        "cursor-cli",
        &home,
        &[script.as_os_str()],
        &[("node", "cursor", MatchBasis::Executable)],
    );
}
