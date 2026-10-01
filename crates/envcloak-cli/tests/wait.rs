//! `envcloak run --wait`, `envcloak run --manifest` and `envcloak pending`
//! end to end (SPEC §6.1 steps 1 and 4, §10b; M2 plan D-04, D-05): an
//! agent's run waits for a person's approval without holding a connection,
//! the person finds the request with `envcloak pending` (never from the
//! agent's output) and approves it from a terminal of their own, and the
//! run goes on; a `y` typed into the waiting run's terminal approves
//! nothing; the wait ends at its deadline, on SIGINT and on a denial; five
//! waiters under one agent all run as each is approved; `envcloak pending`
//! lists nothing where no proof is taken; and `--manifest` names a project
//! as the search upward does, with the same refusals.
//!
//! The requester is `fixture-agent`, which the builtin catalog knows,
//! running a shell that takes one command after another (as in
//! tests/run.rs); the person is this test process's own command on a
//! terminal of its own (`common::run_on_terminal`). Under a developer's
//! Claude Code the approvals are refused, as they must be; run the tests
//! outside the agent's tree then. Every output, the daemon's log and the
//! home are swept for the passphrase, the kit and the values.
#![allow(clippy::unwrap_used)]

mod common;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::symlink;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

use common::{
    MANIFEST, cli, cli_command, daemon_exe, drive_from, finish_within, on_terminal_command,
    outside_dir, project, python3, run, run_on_terminal, secret_file, seed_vault, stderr, stdout,
};
use envcloak_testkit::{
    Canary, Daemon, TestHome, assert_no_canary, by_label, canaries, fresh_seed, labels, testkit_bin,
};

/// The command the covered runs start: for each variable named, the
/// SHA-256 of its value and the value itself, on standard output.
const EMIT: &str = r#"import hashlib, os, sys
for name in sys.argv[1:]:
    v = os.environb[name.encode()]
    sys.stdout.buffer.write(b"%s sha256=%s\n" % (name.encode(), hashlib.sha256(v).hexdigest().encode()))
    sys.stdout.buffer.write(b"raw=" + v + b"\n")
    sys.stdout.flush()
"#;

/// A seeded vault, a daemon with it unlocked (with a test build's trace,
/// and other test settings `env` names), the project, and the passphrase
/// on a file for `--passphrase-fd`.
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
        Self::with_env(&[])
    }

    fn with_env(env: &[(&str, &str)]) -> Self {
        let cs = canaries(fresh_seed());
        let home = TestHome::new();
        let kit = seed_vault(&home, &cs);
        let mut cs = cs;
        cs.push(kit);
        let mut cmd = Command::new(daemon_exe());
        home.apply(&mut cmd)
            .env(envcloak_sys::testing::TRACE, "1")
            .envs(env.iter().copied());
        let d = Daemon::start_command(cmd, &[]);
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

    /// `envcloak <args>` from this process on a terminal of its own, as a
    /// person runs it, with the passphrase file on descriptor 3; swept.
    fn person(&self, args: &[&str]) -> Output {
        let out = run_on_terminal(&self.home, args, &[(3, &self.pass, true)]);
        assert_no_canary(&out.stdout, &self.cs);
        assert_no_canary(&out.stderr, &self.cs);
        out
    }

    /// The requests `envcloak pending --json` lists to a person.
    fn listed(&self) -> Vec<String> {
        let out = self.person(&["pending", "--json"]);
        assert!(out.status.success(), "{}", stderr(&out));
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        v["requests"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["request"].as_str().unwrap().to_owned())
            .collect()
    }

    /// Waits up to a minute until `envcloak pending` lists `n` requests,
    /// and returns them.
    fn wait_listed(&self, n: usize) -> Vec<String> {
        let end = Instant::now() + Duration::from_secs(60);
        loop {
            let ids = self.listed();
            if ids.len() >= n {
                return ids;
            }
            assert!(Instant::now() < end, "{ids:?}\n{}", self.d.log());
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn approve(&self, id: &str, how: &[&str]) {
        let mut args = vec!["approve", id];
        args.extend_from_slice(how);
        args.extend_from_slice(&["--passphrase-fd", "3"]);
        let out = self.person(&args);
        assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    }

    fn agent(&self) -> Agent {
        Agent::start(self)
    }

    /// `pending.state` answers in the daemon's trace, for each pid.
    fn poll_answers(&self) -> Vec<(String, String)> {
        self.d
            .log()
            .lines()
            .filter_map(|l| l.strip_prefix("envcloakd: test: pending.state pid="))
            .map(|rest| {
                let pid = rest.split(' ').next().unwrap().to_owned();
                let answer = rest.rsplit("answer=").next().unwrap().to_owned();
                (pid, answer)
            })
            .collect()
    }

    fn sweep(&self) {
        assert_no_canary(&self.d.log_bytes(), &self.cs);
        self.home.assert_clean(&self.cs);
        let _ = &self.files;
    }
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

/// A running fixture agent with a shell as its command; killed on drop.
/// The agent is the root of every request its commands make.
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

    /// Sends `command` to the agent's shell, in the background (`&`):
    /// the shell takes the next line at once.
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
            "( ( {command} ) </dev/null >{} 2>{}; echo $? >{} ) &",
            quoted(sent.out.to_str().unwrap()),
            quoted(sent.err.to_str().unwrap()),
            quoted(sent.code.to_str().unwrap())
        )
        .unwrap();
        self.stdin.flush().unwrap();
        sent
    }

    /// Waits for a command sent and returns its output, swept; the files
    /// are removed, so the home's sweep is about what EnvCloak wrote.
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
        for p in [&sent.out, &sent.err, &sent.code] {
            let _ = std::fs::remove_file(p);
        }
        o
    }

    /// `envcloak <args>` as the agent's command, waited for.
    fn cli(&mut self, args: &[&str]) -> Output {
        let sent = self.send(&cli_line(args));
        self.wait(&sent)
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `envcloak <args>` as one shell line.
fn cli_line(args: &[&str]) -> String {
    let mut line = quoted(cli().to_str().unwrap());
    for a in args {
        line.push(' ');
        line.push_str(&quoted(a));
    }
    line
}

/// The `approval_required` lines of `err`, and the request each names.
fn required(err: &str) -> Vec<String> {
    err.lines()
        .filter(|l| l.starts_with("envcloak: approval_required: request="))
        .map(|l| {
            l.split("request=")
                .nth(1)
                .and_then(|s| s.split(':').next())
                .unwrap()
                .to_owned()
        })
        .collect()
}

fn sha256_hex(v: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(v)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Story S8's waiting half through the CLI: the agent's `run --wait`
/// prints the `approval_required` line once and waits; the person reads
/// the request id from `envcloak pending` on a terminal of their own (it
/// shows the agent, the project and the bindings) and approves it; the
/// run then starts the command with the values (their digests match) and
/// its output redacted, and exits 0.
#[test]
fn a_waiting_run_starts_once_a_person_approves() {
    let f = Fixture::new();
    let mut agent = f.agent();
    let py = python3();
    let sent = agent.send(&cli_line(&[
        "run",
        "--wait",
        "60s",
        "--",
        py.to_str().unwrap(),
        "emit.py",
        "OPENAI_API_KEY",
    ]));
    let ids = f.wait_listed(1);
    assert_eq!(ids.len(), 1, "{ids:?}");
    let text = f.person(&["pending"]);
    let shown = stdout(&text);
    assert!(shown.starts_with(&format!("{}\n", ids[0])), "{shown}");
    assert!(
        shown.contains("  from: agent EnvCloak test fixture agent\n"),
        "{shown}"
    );
    assert!(shown.contains("acme-web\n"), "{shown}");
    assert!(
        shown.contains("  bindings: openai/acme-web, stripe/acme-web\n"),
        "{shown}"
    );
    f.approve(&ids[0], &["--once"]);
    let out = agent.wait(&sent);
    let (o, e) = (stdout(&out), stderr(&out));
    assert_eq!(out.status.code(), Some(0), "{o}{e}");
    assert_eq!(required(&e), [ids[0].clone()], "{e}");
    assert!(e.contains("waiting up to 1m for it"), "{e}");
    let digest = sha256_hex(by_label(&f.cs, labels::OPENAI_API_KEY).value());
    assert!(
        o.contains(&format!("OPENAI_API_KEY sha256={digest}\n")),
        "{o}"
    );
    assert!(o.contains("raw=[envcloak:openai/acme-web]\n"), "{o}");
    assert!(f.listed().is_empty());
    drop(agent);
    f.sweep();
}

/// Gate 23 with `--wait`: a `y` typed into the waiting run's terminal (an
/// agent's, here) approves nothing and is read by nothing: the run waits
/// out its deadline and exits 125, its one `approval_required` line its
/// failure, and the request still waits for a person.
#[test]
fn a_y_typed_into_the_waiting_terminal_approves_nothing() {
    let f = Fixture::new();
    let fixture = testkit_bin("fixture-agent");
    let argv: Vec<&str> = vec![
        fixture.to_str().unwrap(),
        "--",
        cli().to_str().unwrap(),
        "run",
        "--wait",
        "3s",
        "--",
        "./emit",
    ];
    let (out, code) = drive_from(
        &f.home,
        &f.project,
        &argv,
        &[("waiting up to 3s for it", "y\r")],
    );
    let shown = stdout(&out);
    assert_eq!(code, 125, "{shown}");
    let ids = required(&shown);
    assert_eq!(ids.len(), 1, "{shown}");
    assert_eq!(f.listed(), ids);
    assert_eq!(
        stdout(&run(&f.home, &["grants", "list"], &[])),
        "No grants are in force.\n"
    );
    f.sweep();
}

/// D-04: no connection stays open between polls. A waiting run is
/// watched through the daemon's test trace, with the idle bound cut to 2
/// seconds: each poll is a connection of its own, opened and closed
/// before the next (so the daemon holds none of the waiter's between
/// polls), polls keep coming until the deadline, and the idle bound
/// never closes one. At the deadline the run exits 125 with its one
/// `approval_required` line, and the request still waits.
///
/// Mutation: hold the connection while waiting (poll on one connection
/// kept open): the waiter's connections are not opened and closed per
/// poll and this fails.
#[test]
fn a_waiting_run_holds_no_connection_between_polls() {
    let f = Fixture::with_env(&[(envcloak_sys::testing::IDLE_CONNECTION_MS, "2000")]);
    let mut cmd = cli_command(&f.home, &["run", "--wait", "8s", "--", "./emit"], &[]);
    cmd.current_dir(&f.project);
    let child = cmd.spawn().unwrap();
    let pid = child.id().to_string();
    let out = finish_within_child(child, Duration::from_secs(60));
    let e = stderr(&out);
    assert_eq!(out.status.code(), Some(125), "{e}");
    assert_eq!(required(&e).len(), 1, "{e}");
    assert_eq!(e.lines().count(), 1, "{e}");
    let log = f.d.log();
    let tag = format!("pid={pid}");
    let mine: Vec<&str> = log
        .lines()
        .filter(|l| l.starts_with("envcloakd: test: ") && l.split(' ').any(|w| w == tag))
        .collect();
    assert!(
        !mine.iter().any(|l| l.contains("idle connection closed")),
        "{log}"
    );
    // Every step on a connection of its own: the daemon check before the
    // request, the request, and each poll; when a poll is answered, it is
    // the waiter's only connection, and none is left open at the end.
    let opened = mine
        .iter()
        .filter(|l| l.contains("connection opened"))
        .count();
    let polls = mine.iter().filter(|l| l.contains("pending.state")).count();
    let mut open = 0i32;
    for l in &mine {
        if l.contains("connection opened") {
            open += 1;
        } else if l.contains("connection closed") {
            open -= 1;
        } else if l.contains("pending.state") {
            assert_eq!(open, 1, "{l}:\n{log}");
        }
    }
    assert_eq!(open, 0, "{log}");
    assert!(polls >= 9, "{polls} polls in 8 s:\n{log}");
    assert_eq!(opened, polls + 2, "{log}");
    assert_eq!(f.listed().len(), 1);
    f.sweep();
}

/// Spawned `child`'s output, waiting up to `limit`.
fn finish_within_child(mut child: Child, limit: Duration) -> Output {
    let mut out = child.stdout.take().unwrap();
    let mut err = child.stderr.take().unwrap();
    let reader = std::thread::spawn(move || {
        use std::io::Read;
        let mut o = Vec::new();
        let mut e = Vec::new();
        let _ = out.read_to_end(&mut o);
        let _ = err.read_to_end(&mut e);
        (o, e)
    });
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if start.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the process did not exit within {limit:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let (stdout, stderr) = reader.join().unwrap();
    Output {
        status,
        stdout,
        stderr,
    }
}

/// A daemon that takes each connection and never answers holds `run
/// --wait 1s` no longer than its limit, the deadline and 5 seconds for a
/// last answer: the run exits 125 with `daemon_unavailable`, saying the
/// daemon did not answer within the wait, and starts nothing.
///
/// Mutation: give each call of the wait the client's 300-second timeout
/// (`Fresh` connecting with `Client::connect`): the run is still waiting
/// at this test's 60-second bound and this fails.
#[test]
fn a_wait_on_a_silent_daemon_ends_by_its_limit() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let home = TestHome::new();
    let dir = envcloak_testkit::daemon_run_dir(&home);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = envcloak_testkit::daemon_socket(&home);
    let l = UnixListener::bind(&socket).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stopping = Arc::clone(&stop);
    // Takes every connection and holds it, unanswered, until told to stop.
    let server = std::thread::spawn(move || {
        let mut held = Vec::new();
        while let Ok((s, _)) = l.accept() {
            if stopping.load(Ordering::SeqCst) {
                break;
            }
            held.push(s);
        }
        held.len()
    });
    let files = outside_dir();
    let marker = files.path().join("started");
    let mut cmd = cli_command(
        &home,
        &[
            "run",
            "--wait",
            "1s",
            "--manifest",
            "/nowhere/envcloak.toml",
            "--",
            "touch",
            marker.to_str().unwrap(),
        ],
        &[],
    );
    let started = Instant::now();
    let out = finish_within_child(cmd.spawn().unwrap(), Duration::from_secs(60));
    let took = started.elapsed();
    stop.store(true, Ordering::SeqCst);
    drop(std::os::unix::net::UnixStream::connect(&socket));
    let held = server.join().unwrap();
    let e = stderr(&out);
    assert_eq!(out.status.code(), Some(125), "{e}");
    assert_eq!(
        e,
        "envcloak: daemon_unavailable: the daemon did not answer within the wait (1s, and 5s \
         for a last answer); nothing was started\n"
    );
    assert!(took < Duration::from_secs(20), "{took:?}");
    assert!(held >= 2, "{held}");
    assert!(!marker.exists(), "the command was started");
}

/// The daemon's runtime directory under `home`, made as the daemon makes
/// it (0700), and the socket path in it, for a peer standing in for the
/// daemon.
fn stand_in_socket(home: &TestHome) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let dir = envcloak_testkit::daemon_run_dir(home);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    envcloak_testkit::daemon_socket(home)
}

/// `envcloak run --wait 1s` of a project that does not exist, whose
/// command would create `marker`; its output, and how long it took (given
/// up at 90 seconds).
fn wait_one_second(home: &TestHome, marker: &std::path::Path) -> (Output, Duration) {
    let mut cmd = cli_command(
        home,
        &[
            "run",
            "--wait",
            "1s",
            "--manifest",
            "/nowhere/envcloak.toml",
            "--",
            "touch",
            marker.to_str().unwrap(),
        ],
        &[],
    );
    let started = Instant::now();
    let out = finish_within_child(cmd.spawn().unwrap(), Duration::from_secs(90));
    (out, started.elapsed())
}

/// The longest `run --wait 1s` may take: its deadline, 5 seconds for a
/// last answer, and slack for starting the process on a loaded machine.
const ONE_SECOND_WAIT_BOUND: Duration = Duration::from_secs(10);

/// A daemon that reads the request and then sends a well-formed answer a
/// byte at a time, header and body alike, a byte every 500 ms, holds `run
/// --wait 1s` no longer than its limit (the deadline and 5 seconds for a
/// last answer): each read of the run's call waits only for the time left
/// to that limit, not a whole timeout again for each byte. The run exits
/// 125 with `daemon_unavailable` and starts nothing.
///
/// Mutation: set the call's timeouts once at connect and read and write
/// blocking (`Client::call` on the stream itself): each byte arrives
/// within the timeout, the answer is read whole about 45 seconds in, and
/// this fails on the time taken.
#[test]
fn a_wait_on_a_daemon_sending_a_byte_at_a_time_ends_by_its_limit() {
    use std::os::unix::net::UnixListener;

    use envcloak_ipc::proto::{RunAnswer, result_frame};
    use envcloak_ipc::view::DecisionView;

    let home = TestHome::new();
    let l = UnixListener::bind(stand_in_socket(&home)).unwrap();
    let mut answer = Vec::new();
    result_frame(
        1,
        &RunAnswer::decided(DecisionView::Pending {
            request: "ABCDEFGH".to_owned(),
        }),
    )
    .unwrap()
    .write_to(&mut answer)
    .unwrap();
    assert!(answer.len() > 60, "{}", answer.len());
    std::thread::spawn(move || {
        while let Ok((mut s, _)) = l.accept() {
            let answer = answer.clone();
            std::thread::spawn(move || {
                if envcloak_ipc::Frame::read_from(&mut s).is_err() {
                    return;
                }
                for b in answer {
                    if s.write_all(&[b]).is_err() {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(500));
                }
            });
        }
    });
    let files = outside_dir();
    let marker = files.path().join("started");
    let (out, took) = wait_one_second(&home, &marker);
    let e = stderr(&out);
    assert_eq!(out.status.code(), Some(125), "{e}");
    assert_eq!(
        e,
        "envcloak: daemon_unavailable: the daemon did not answer within the wait (1s, and 5s \
         for a last answer); nothing was started\n"
    );
    assert!(took < ONE_SECOND_WAIT_BOUND, "{took:?}");
    assert!(!marker.exists(), "the command was started");
}

/// The wait ends on SIGINT, as any program does (a shell reports 130),
/// with nothing held open; and on a denial, which exits 125 with
/// `approval_denied` naming the request.
#[test]
fn a_waiting_run_ends_on_sigint_and_on_a_denial() {
    let f = Fixture::new();
    let mut cmd = cli_command(&f.home, &["run", "--wait", "60s", "--", "./emit"], &[]);
    cmd.current_dir(&f.project);
    let mut child = cmd.spawn().unwrap();
    // Waiting: its line is out.
    let mut err = BufReader::new(child.stderr.take().unwrap());
    let mut line = String::new();
    err.read_line(&mut line).unwrap();
    assert!(
        line.starts_with("envcloak: approval_required: request="),
        "{line}"
    );
    // SIGINT to this test's own child, which it has not reaped.
    let ok = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .unwrap()
        .success();
    assert!(ok);
    let end = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        assert!(Instant::now() < end, "SIGINT did not end the wait");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(status.signal(), Some(libc::SIGINT), "{status:?}");
    let mut rest = String::new();
    std::io::Read::read_to_string(&mut err, &mut rest).unwrap();
    assert_eq!(rest, "");

    // A denial, from any client (tightening needs no proof).
    let mut cmd = cli_command(&f.home, &["run", "--wait", "60s", "--", "./other"], &[]);
    cmd.current_dir(&f.project);
    let child = cmd.spawn().unwrap();
    let ids = f.wait_listed(2);
    let other = ids.iter().find(|i| !line.contains(i.as_str())).unwrap();
    let out = run(&f.home, &["deny", other], &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = finish_within_child(child, Duration::from_secs(30));
    let e = stderr(&out);
    assert_eq!(out.status.code(), Some(125), "{e}");
    assert!(
        e.lines().last().unwrap().starts_with(&format!(
            "envcloak: approval_denied: request={other} was denied"
        )),
        "{e}"
    );
    f.sweep();
}

/// `envcloak pending` lists nothing where no proof would be taken: to the
/// agent's command, to a command without a terminal, and to a person's
/// terminal whose shell carries an agent's marker; each prints the same
/// line as when nothing waits. The person's own terminal lists it.
///
/// Mutation: list pending requests to an agent subject (skip the proof
/// check in `pending.list`): the agent's `envcloak pending` lists the
/// request and this fails.
#[test]
fn pending_lists_nothing_where_no_proof_is_taken() {
    let f = Fixture::new();
    let mut agent = f.agent();
    let out = agent.cli(&["run", "--", "./emit"]);
    assert_eq!(out.status.code(), Some(125));
    let id = required(&stderr(&out)).pop().unwrap();
    let none = "No requests are waiting for approval that this terminal may approve.\n";
    let out = agent.cli(&["pending"]);
    assert_eq!(
        (out.status.code(), stdout(&out)),
        (Some(0), none.to_owned())
    );
    let out = agent.cli(&["pending", "--json"]);
    assert_eq!(stdout(&out), "{\"requests\":[]}\n");
    let out = run(&f.home, &["pending"], &[]);
    assert_eq!(
        (out.status.code(), stdout(&out)),
        (Some(0), none.to_owned())
    );
    let mut cmd = on_terminal_command(&f.home, &["pending"], &[]);
    cmd.env("CLAUDECODE", "1");
    let out = finish_within(cmd, Duration::from_secs(60));
    assert_eq!(stdout(&out), none);
    assert_eq!(f.listed(), [id]);
    // Usage errors echo nothing.
    let out = run(&f.home, &["pending", "--bogus"], &[]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(stderr(&out), "envcloak: usage: envcloak pending [--json]\n");
    drop(agent);
    f.sweep();
}

/// D-04's five waiters under one root, through the CLI: five `run --wait`
/// commands of one agent at once; three go pending and two are refused
/// `too_many_pending` and ask again; the person approves whatever
/// `envcloak pending` lists, once each, until all five have run. Every one
/// exits 0, no other way; every poll the daemon answered was `pending` or
/// `approved`, or `busy`, never another refusal.
#[test]
fn five_waiters_under_one_agent_all_run() {
    let f = Fixture::new();
    let mut agent = f.agent();
    let sent: Vec<Sent> = (1..=5)
        .map(|n| {
            agent.send(&cli_line(&[
                "run",
                "--wait",
                "120s",
                "--",
                "/bin/sh",
                "-c",
                "exit 0",
                &format!("job-{n}"),
            ]))
        })
        .collect();
    // Before anyone approves: three requests wait and two waiters were
    // told every place is taken.
    let end = Instant::now() + Duration::from_secs(60);
    loop {
        let told = sent
            .iter()
            .filter(|s| {
                std::fs::read_to_string(&s.err)
                    .is_ok_and(|e| e.contains("envcloak: too_many_pending: "))
            })
            .count();
        if told == 2 && f.listed().len() == 3 {
            break;
        }
        assert!(Instant::now() < end, "{told} told:\n{}", f.d.log());
        std::thread::sleep(Duration::from_millis(100));
    }
    let end = Instant::now() + Duration::from_secs(120);
    let mut approved = 0;
    while sent.iter().any(|s| !s.code.exists()) {
        assert!(Instant::now() < end, "{}", f.d.log());
        let ids = f.listed();
        assert!(ids.len() <= 3, "a root holds at most 3: {ids:?}");
        for id in ids {
            f.approve(&id, &["--once"]);
            approved += 1;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let outs: Vec<Output> = sent.iter().map(|s| agent.wait(s)).collect();
    let log = f.d.log();
    let ran = log.matches("audit: request decision=covered").count();
    let shown: Vec<(Option<i32>, String)> =
        outs.iter().map(|o| (o.status.code(), stderr(o))).collect();
    assert_eq!(ran, 5, "{shown:?}\n{log}");
    assert!(
        approved >= 5,
        "{approved}: {:?}\n{log}",
        outs.iter().map(stderr).collect::<Vec<_>>()
    );
    let mut crowded = 0;
    for out in &outs {
        let e = stderr(out);
        assert_eq!(out.status.code(), Some(0), "{e}");
        assert!(
            e.lines()
                .all(|l| l.starts_with("envcloak: approval_required: ")
                    || l.starts_with("envcloak: too_many_pending: ")),
            "{e}"
        );
        crowded += usize::from(e.contains("envcloak: too_many_pending: "));
    }
    assert!(crowded >= 2, "{crowded} waiters met the cap");
    let answers = f.poll_answers();
    assert!(!answers.is_empty());
    for (pid, a) in &answers {
        assert!(
            ["pending", "approved", "busy"].contains(&a.as_str()),
            "pid {pid}: {a}"
        );
    }
    drop(agent);
    f.sweep();
}

/// D-05's explicit manifest: `--manifest` names the project by its
/// absolute path, from any working directory, and the daemon opens it as
/// it opens one found upward: the same directory is the same project (a
/// grant approved for a run found upward covers a run that names it,
/// through a symlinked directory too). A relative path is a usage error,
/// echoing nothing; a symlinked manifest, a missing one and a file not
/// named `envcloak.toml` are refused as the daemon refuses them.
#[test]
fn manifest_names_the_project_explicitly() {
    let f = Fixture::new();
    let mut agent = f.agent();
    let out = agent.cli(&["run", "--", "/bin/sh", "-c", "exit 0"]);
    let id = required(&stderr(&out)).pop().unwrap();
    f.approve(&id, &["--for", "1h"]);

    let manifest = f.project.join("envcloak.toml");
    let linked_dir = f.home.root().join("link-to-acme");
    symlink(&f.project, &linked_dir).unwrap();
    for path in [manifest.clone(), linked_dir.join("envcloak.toml")] {
        let line = format!(
            "cd / && {}",
            cli_line(&[
                "run",
                "--manifest",
                path.to_str().unwrap(),
                "--",
                "/bin/sh",
                "-c",
                "exit 3",
            ])
        );
        let sent = agent.send(&line);
        let out = agent.wait(&sent);
        assert_eq!(out.status.code(), Some(3), "{path:?}: {}", stderr(&out));
    }

    // A symlinked manifest, a missing one, another file name.
    let elsewhere = f.home.root().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    symlink(&manifest, elsewhere.join("envcloak.toml")).unwrap();
    std::fs::write(elsewhere.join("other.toml"), MANIFEST).unwrap();
    for (path, why) in [
        (elsewhere.join("envcloak.toml"), "symlink"),
        (
            f.home.root().join("nowhere/envcloak.toml"),
            "no envcloak.toml there",
        ),
        (elsewhere.join("other.toml"), "not named envcloak.toml"),
    ] {
        let out = agent.cli(&["run", "--manifest", path.to_str().unwrap(), "--", "./emit"]);
        let e = stderr(&out);
        assert_eq!(out.status.code(), Some(125), "{e}");
        assert!(e.starts_with("envcloak: manifest_invalid: "), "{e}");
        assert!(e.contains(why), "{why}: {e}");
    }
    let canary = by_label(&f.cs, labels::OPENAI_API_KEY).as_str();
    for rel in ["acme-web/envcloak.toml", canary] {
        let out = agent.cli(&["run", "--manifest", rel, "--", "./emit"]);
        assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
        assert!(
            stderr(&out)
                .starts_with("envcloak: --manifest needs the absolute path of an envcloak.toml\n"),
            "{}",
            stderr(&out)
        );
    }
    drop(agent);
    f.sweep();
}
