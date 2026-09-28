//! `envcloak run` end to end (SPEC §6.1; story S4 to S6): a covered run
//! starts the command with the values in its environment and its output
//! redacted, gate 9 through the CLI (a short value is refused, an allowed
//! one reported), gate 13 during a run (`ps` shows no value in the CLI's
//! argv or environment), gate 14 (the values are in the child's
//! environment only, a sibling reads it as SPEC §1.1 says, and nothing is
//! written to a file), and gate 33's release order (an audit failure
//! starts nothing).
//!
//! The requester is `fixture-agent`, which the builtin catalog knows,
//! running a shell that takes one command after another; the approver is
//! this test process's own `envcloak approve` on a terminal of its own
//! (see tests/approve.rs). Under a developer's Claude Code the approvals
//! are refused, as they must be; run the tests outside the agent's tree
//! then. Every output, the daemon's log and the home are swept for the
//! passphrase, the kit and the values.
#![allow(clippy::unwrap_used)]

mod common;

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

use common::{
    MANIFEST, cli, data_dir, outside_dir, project, python3, run_on_terminal, secret_file,
    seed_vault, start_daemon, stderr, stdout,
};
use envcloak_testkit::{
    Canary, Daemon, TestHome, assert_no_canary, by_label, canaries, fresh_seed, labels, testkit_bin,
};

/// A seeded vault, a daemon with it unlocked, the project, and the
/// passphrase on a file for `--passphrase-fd`.
struct Fixture {
    cs: Vec<Canary>,
    home: TestHome,
    d: Daemon,
    project: PathBuf,
    files: tempfile::TempDir,
    pass: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let cs = canaries(fresh_seed());
        let home = TestHome::new();
        let kit = seed_vault(&home, &cs);
        let mut cs = cs;
        cs.push(kit);
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
        assert!(out.status.success(), "{}{}", stderr(&out), d.log());
        let project = project(&home, "acme-web", MANIFEST);
        std::fs::write(project.join("emit.py"), EMIT).unwrap();
        Fixture {
            cs,
            home,
            d,
            project,
            files,
            pass,
        }
    }

    fn agent(&self) -> Agent {
        Agent::start(self)
    }

    /// `envcloak approve <id> --for 1h` from a terminal of its own.
    fn approve(&self, id: &str) {
        let out = run_on_terminal(
            &self.home,
            &["approve", id, "--for", "1h", "--passphrase-fd", "3"],
            &[(3, &self.pass, true)],
        );
        assert_no_canary(&out.stdout, &self.cs);
        assert_no_canary(&out.stderr, &self.cs);
        assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    }

    fn value(&self, label: &str) -> &[u8] {
        by_label(&self.cs, label).value()
    }

    fn sweep(&self) {
        assert_no_canary(&self.d.log_bytes(), &self.cs);
        self.home.assert_clean(&self.cs);
        let _ = &self.files;
    }
}

/// The command the runs start: for each variable named, the SHA-256 of
/// its value and the value itself, as JSON and as base64, on standard
/// output, and the value on standard error.
const EMIT: &str = r#"import base64, hashlib, json, os, sys
for name in sys.argv[1:]:
    v = os.environb[name.encode()]
    out = sys.stdout.buffer
    out.write(b"%s sha256=%s\n" % (name.encode(), hashlib.sha256(v).hexdigest().encode()))
    out.write(b"raw=" + v + b"\n")
    out.write(b"json=" + json.dumps(v.decode()).encode() + b"\n")
    out.write(b"b64=" + base64.b64encode(v) + b"\n")
    out.flush()
    sys.stderr.buffer.write(b"err=" + v + b"\n")
    sys.stderr.flush()
"#;

fn sha256_hex(v: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(v)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `s` as one shell word.
fn quoted(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// One command line sent to the agent's shell; its output lands in files.
struct Sent {
    out: PathBuf,
    err: PathBuf,
    code: PathBuf,
}

/// A running fixture agent with a shell as its command, taking one
/// command line after another; killed on drop. The agent is the root of
/// every grant for its commands.
struct Agent {
    child: Child,
    stdin: ChildStdin,
    dir: PathBuf,
    n: usize,
    cs: Vec<Canary>,
}

impl Agent {
    fn start(f: &Fixture) -> Agent {
        let dir = f.home.root().join("agent");
        std::fs::create_dir_all(&dir).unwrap();
        let mut cmd = Command::new(testkit_bin("fixture-agent"));
        f.home.apply(&mut cmd);
        let mut child = cmd
            .args(["--", "/bin/sh"])
            .current_dir(&f.project)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        Agent {
            child,
            stdin,
            dir,
            n: 0,
            cs: f.cs.clone(),
        }
    }

    /// Sends `command` to the agent's shell and returns at once.
    fn send(&mut self, command: &str) -> Sent {
        self.n += 1;
        let base = self.dir.join(self.n.to_string());
        let sent = Sent {
            out: base.with_extension("out"),
            err: base.with_extension("err"),
            code: base.with_extension("code"),
        };
        writeln!(
            self.stdin,
            "( {command} ) </dev/null >{} 2>{}; echo $? >{}",
            quoted(sent.out.to_str().unwrap()),
            quoted(sent.err.to_str().unwrap()),
            quoted(sent.code.to_str().unwrap())
        )
        .unwrap();
        self.stdin.flush().unwrap();
        sent
    }

    /// Waits for a command sent and returns its output, swept.
    fn wait(&self, sent: &Sent) -> Output {
        let end = Instant::now() + Duration::from_secs(120);
        let status = loop {
            if let Ok(s) = std::fs::read_to_string(&sent.code) {
                if let Ok(n) = s.trim().parse::<i32>() {
                    break ExitStatus::from_raw(n << 8);
                }
            }
            assert!(Instant::now() < end, "the agent's command did not finish");
            std::thread::sleep(Duration::from_millis(20));
        };
        let o = Output {
            status,
            stdout: std::fs::read(&sent.out).unwrap(),
            stderr: std::fs::read(&sent.err).unwrap(),
        };
        assert_no_canary(&o.stdout, &self.cs);
        assert_no_canary(&o.stderr, &self.cs);
        // The output files are in the swept home: remove them, so the
        // sweep is about what EnvCloak wrote.
        for p in [&sent.out, &sent.err, &sent.code] {
            let _ = std::fs::remove_file(p);
        }
        o
    }

    /// `envcloak run <args>` as the agent's command.
    fn run(&mut self, args: &[&str]) -> Output {
        let sent = self.send(&run_line(args));
        self.wait(&sent)
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn run_line(args: &[&str]) -> String {
    let mut line = format!("{} run", quoted(cli().to_str().unwrap()));
    for a in args {
        line.push(' ');
        line.push_str(&quoted(a));
    }
    line
}

/// The request id in `approval_required request=<id>`.
fn request_id(err: &str) -> String {
    let line = err
        .lines()
        .find(|l| l.contains("approval_required"))
        .unwrap_or_else(|| panic!("no approval_required in: {err}"));
    line.split("request=")
        .nth(1)
        .and_then(|s| s.split(':').next())
        .unwrap()
        .to_owned()
}

/// Story S4 to S6 through the CLI: the agent's run waits for an approval,
/// then starts the command with the values in its environment (their
/// digests match) and every form of them redacted on both streams; the
/// command's exit code passes through, and a missing command is 127.
/// Gate 9: `--profile short` binds a 10-byte value without `allow_short`
/// and is refused with 125 and `value_too_short`, starting nothing; an
/// item that allows short values runs, with the coverage report naming
/// it on standard error.
#[test]
fn a_covered_run_starts_the_command_with_the_values_redacted() {
    let f = Fixture::new();
    let mut agent = f.agent();
    let py = python3();
    let py = py.to_str().unwrap();
    let emit = ["--", py, "emit.py", "OPENAI_API_KEY", "STRIPE_SECRET_KEY"];

    let out = agent.run(&emit);
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    assert!(out.stdout.is_empty());
    f.approve(&request_id(&stderr(&out)));

    let out = agent.run(&emit);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let o = stdout(&out);
    for (name, label, slug) in [
        ("OPENAI_API_KEY", labels::OPENAI_API_KEY, "openai/acme-web"),
        (
            "STRIPE_SECRET_KEY",
            labels::STRIPE_SECRET_KEY,
            "stripe/acme-web",
        ),
    ] {
        let digest = sha256_hex(f.value(label));
        assert!(o.contains(&format!("{name} sha256={digest}\n")), "{o}");
        let marker = format!("[envcloak:{slug}]");
        for form in ["raw", "json", "b64"] {
            let want = if form == "json" {
                format!("{form}=\"{marker}\"\n")
            } else {
                format!("{form}={marker}\n")
            };
            assert!(o.contains(&want), "{form}: {o}");
        }
        assert!(stderr(&out).contains(&format!("err={marker}\n")));
    }

    // The command's code, and `env(1)`'s codes for one that cannot start.
    let out = agent.run(&["--", "/bin/sh", "-c", "exit 7"]);
    assert_eq!(out.status.code(), Some(7), "{}", stderr(&out));
    let out = agent.run(&["--", "./no-such-command"]);
    assert_eq!(out.status.code(), Some(127));
    assert_eq!(
        stderr(&out),
        "envcloak: command_not_found: the command was not found\n"
    );

    // Gate 9: a 10-byte value without allow_short.
    let mark = f.files.path().join("started");
    let touch = format!("touch {}", quoted(mark.to_str().unwrap()));
    let short = ["--profile", "short", "--", "/bin/sh", "-c", touch.as_str()];
    let out = agent.run(&short);
    f.approve(&request_id(&stderr(&out)));
    let out = agent.run(&short);
    assert_eq!(out.status.code(), Some(125));
    assert!(
        stderr(&out).starts_with("envcloak: value_too_short: short/acme-web: "),
        "{}",
        stderr(&out)
    );
    assert!(!mark.exists(), "the command started");

    // An item that allows short values: taken, and reported.
    let value = secret_file(f.files.path(), "short", f.value(labels::SHORT_TOKEN));
    let added = common::run(
        &f.home,
        &["add", "--slug", "short/allowed", "--allow-short", "--stdin"],
        &[(0, &value, true)],
    );
    assert!(added.status.success(), "{}", stderr(&added));
    let allowed = [
        "--ref",
        "SHORT_TOKEN=short/allowed",
        "--",
        py,
        "emit.py",
        "SHORT_TOKEN",
    ];
    let out = agent.run(&allowed);
    f.approve(&request_id(&stderr(&out)));
    let out = agent.run(&allowed);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let e = stderr(&out);
    assert!(
        e.starts_with("envcloak: coverage: short/allowed is 8 to 15 bytes (allowed short)"),
        "{e}"
    );
    assert!(
        e.contains("envcloak: coverage: short/allowed: inside a longer base64 stream"),
        "{e}"
    );
    let o = stdout(&out);
    assert!(o.contains("raw=[envcloak:short/allowed]\n"), "{o}");
    assert!(o.contains("b64=[envcloak:short/allowed]\n"), "{o}");
    assert!(o.contains(&format!(
        "SHORT_TOKEN sha256={}",
        sha256_hex(f.value(labels::SHORT_TOKEN))
    )));
    drop(agent);
    f.sweep();
}

/// What `ps` shows of `pid`: its command line, and its environment as
/// another process of the user reads it: on macOS what `ps -E` adds, on
/// Linux `/proc/<pid>/environ` (`None` when that is refused).
fn ps(pid: u32) -> (Vec<u8>, Option<Vec<u8>>) {
    let run_ps = |extra: &[&str]| -> Vec<u8> {
        let out = Command::new("/bin/ps")
            .args(extra)
            .args(["-ww", "-o", "command=", "-p", &pid.to_string()])
            .output()
            .unwrap();
        assert!(out.status.success(), "ps failed");
        assert!(!out.stdout.is_empty(), "ps showed nothing for {pid}");
        out.stdout
    };
    let argv = run_ps(&[]);
    let environ = if cfg!(target_os = "macos") {
        Some(run_ps(&["-E"]))
    } else {
        std::fs::read(format!("/proc/{pid}/environ")).ok()
    };
    (argv, environ)
}

/// Gates 13 and 14 while a run holds values: `ps` shows none in the
/// CLI's argv or environment (Linux: the CLI is non-dumpable, so its
/// environment cannot be read at all), and none in the child's argv. The
/// child's environment holds them, and a sibling process of the same user
/// reads it there, as SPEC §1.1 says it can on both systems; the result is
/// printed for the record. The command is `fixture-agent`, a binary of
/// this workspace, since macOS does not show a platform binary's
/// environment to `ps`. After the run no file holds a value, and the
/// temporary directory is empty.
#[test]
fn values_live_in_the_childs_environment_only() {
    let f = Fixture::new();
    let mut agent = f.agent();
    let ready = f.files.path().join("ready");
    let fifo = f.files.path().join("go");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let script = format!(
        "echo \"cli=$(ps -o ppid= -p $PPID | tr -d ' ') child=$PPID\" >{}.tmp; mv {0}.tmp {0}; \
         read line <{}; printf '%s\\n' \"$OPENAI_API_KEY\"",
        quoted(ready.to_str().unwrap()),
        quoted(fifo.to_str().unwrap())
    );
    let holder = testkit_bin("fixture-agent");
    let argv = [
        "--",
        holder.to_str().unwrap(),
        "--",
        "/bin/sh",
        "-c",
        &script,
    ];

    let out = agent.run(&argv);
    f.approve(&request_id(&stderr(&out)));
    let sent = agent.send(&run_line(&argv));
    let end = Instant::now() + Duration::from_secs(60);
    let pids = loop {
        if let Ok(s) = std::fs::read_to_string(&ready) {
            break s;
        }
        assert!(Instant::now() < end, "the command did not start");
        std::thread::sleep(Duration::from_millis(20));
    };
    let pid = |key: &str| -> u32 {
        pids.split_whitespace()
            .find_map(|w| w.strip_prefix(key))
            .unwrap()
            .parse()
            .unwrap()
    };
    let (cli_pid, child_pid) = (pid("cli="), pid("child="));

    // The CLI: its command line and environment hold no value.
    let (argv_shown, environ) = ps(cli_pid);
    assert_no_canary(&argv_shown, &f.cs);
    let text = String::from_utf8_lossy(&argv_shown);
    assert!(text.contains(" run -- "), "{text}");
    if let Some(e) = &environ {
        assert_no_canary(e, &f.cs);
        if cfg!(target_os = "macos") {
            assert!(
                String::from_utf8_lossy(e).contains("HOME="),
                "ps -E showed no environment"
            );
        }
    }
    if cfg!(target_os = "linux") {
        assert!(environ.is_none(), "the CLI's environment was readable");
    }

    // The child: its command line holds none; its environment holds them,
    // readable by this sibling process.
    let (argv_shown, environ) = ps(child_pid);
    assert_no_canary(&argv_shown, &f.cs);
    let child_env = environ.expect("the child's environment was refused");
    let openai = f.value(labels::OPENAI_API_KEY);
    let stripe = f.value(labels::STRIPE_SECRET_KEY);
    let has = |hay: &[u8], v: &[u8]| hay.windows(v.len()).any(|w| w == v);
    assert!(has(&child_env, openai) && has(&child_env, stripe));
    println!(
        "gate 14 ({}): a sibling process of the same user read the child's environment \
         (values present), and not the CLI's",
        std::env::consts::OS
    );

    std::fs::write(&fifo, b"go\n").unwrap();
    let out = agent.wait(&sent);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&out), "[envcloak:openai/acme-web]\n");
    // No temporary file, and no value in any file of the home.
    let tmp: Vec<_> = std::fs::read_dir(f.home.root().join("tmp"))
        .unwrap()
        .collect();
    assert!(tmp.is_empty(), "files were left in TMPDIR");
    drop(agent);
    f.sweep();
}

/// Gate 33's release order through the CLI: when the delivery's audit
/// entry cannot be written, the answer carries no value and the command
/// never starts; once the log can be written, the same grant runs it.
#[test]
fn an_audit_failure_starts_nothing() {
    let f = Fixture::new();
    let mut agent = f.agent();
    let mark = f.files.path().join("started");
    let touch = format!("touch {}", quoted(mark.to_str().unwrap()));
    let argv = ["--", "/bin/sh", "-c", touch.as_str()];
    let out = agent.run(&argv);
    f.approve(&request_id(&stderr(&out)));

    let audit = data_dir(&f.home).join("audit");
    std::fs::remove_dir_all(&audit).unwrap();
    std::fs::write(&audit, b"in the way").unwrap();
    let out = agent.run(&argv);
    assert_eq!(out.status.code(), Some(125));
    assert!(
        stderr(&out).starts_with("envcloak: approval_denied:"),
        "{}",
        stderr(&out)
    );
    assert!(!mark.exists(), "the command started without its entry");

    std::fs::remove_file(&audit).unwrap();
    std::fs::create_dir(&audit).unwrap();
    std::fs::set_permissions(&audit, std::fs::Permissions::from_mode(0o700)).unwrap();
    let out = agent.run(&argv);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(mark.exists());
    drop(agent);
    f.sweep();
}
