//! Approvals with real agents and terminals (SPEC §6.1 step 4, §10a,
//! §10b; the story's S4 to S6 decisions): gate 23 (forged approvals), 24
//! (manifest self-authorization), 25's grant half (a grant for the
//! terminal does not cover the agent), 29's root exit, and 31 as the CLI
//! shows a statement.
//!
//! The agent is `fixture-agent` (envcloak-testkit), which the builtin
//! catalog knows, running a shell that takes one command after another,
//! as one agent session does; a grant is scoped to that process instance,
//! so a second agent would not be covered by the first one's grant. The
//! approver is this test process's own command (`envcloak approve`),
//! leading a session on a pseudo-terminal of its own as a person's
//! command in a terminal window does (`common::run_on_terminal`), with no
//! agent in its ancestry in CI. The daemon takes a proof only from such a
//! terminal subject: the same command without a terminal, as a service
//! manager's job or after `setsid`, is refused. Under a developer's
//! Claude Code every approval here is refused, as SPEC §10b says it must
//! be; run the tests outside the agent's tree then. Every output, the
//! daemon's log and the home are swept for the passphrase, the kit and
//! the values.
#![allow(clippy::unwrap_used)]

mod common;

use std::io::Write;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

use common::{
    MANIFEST, cli, cli_command, drive_from, finish_within, on_terminal_command, outside_dir,
    project, run, run_on_terminal, secret_file, seed_vault, start_daemon, stderr, stdout,
};
use envcloak_ipc::proto::RunRequestParams;
use envcloak_ipc::view::DecisionView;
use envcloak_ipc::{Client, RunPaths};
use envcloak_testkit::{
    Canary, Daemon, TestHome, assert_no_canary, by_label, canaries, daemon_run_dir, fresh_seed,
    labels, testkit_bin,
};

/// A seeded vault, a daemon with it unlocked through the CLI, the
/// project, and the passphrase on a file for `--passphrase-fd`.
struct Fixture {
    cs: Vec<Canary>,
    home: TestHome,
    d: Daemon,
    project: PathBuf,
    files: tempfile::TempDir,
    pass: PathBuf,
    wrong: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        Self::with_manifest(MANIFEST)
    }

    fn with_manifest(manifest: &str) -> Self {
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
        let wrong = secret_file(files.path(), "wrong", b"not the passphrase at all, no");
        let out = run_on_terminal(
            &home,
            &["unlock", "--passphrase-fd", "3"],
            &[(3, &pass, true)],
        );
        assert!(out.status.success(), "{}{}", stderr(&out), d.log());
        let project = project(&home, "acme-web", manifest);
        Fixture {
            cs,
            home,
            d,
            project,
            files,
            pass,
            wrong,
        }
    }

    /// One agent session in the project directory.
    fn agent(&self) -> Agent {
        Agent::start(self, &self.project)
    }

    /// `envcloak <args>` from this process on a terminal of its own, as a
    /// person gives a proof, with the passphrase file on descriptor 3.
    fn person(&self, args: &[&str], pass: &Path) -> Output {
        let out = run_on_terminal(&self.home, args, &[(3, pass, true)]);
        assert_no_canary(&out.stdout, &self.cs);
        assert_no_canary(&out.stderr, &self.cs);
        out
    }

    /// `envcloak approve <id> <args>` from this process with the right
    /// passphrase, expected to succeed. Returns what it printed.
    fn approve(&self, id: &str, args: &[&str]) -> String {
        let mut argv = vec!["approve", id];
        argv.extend_from_slice(args);
        argv.extend_from_slice(&["--passphrase-fd", "3"]);
        let out = self.person(&argv, &self.pass);
        let (o, e) = (stdout(&out), stderr(&out));
        assert!(out.status.success(), "{o}{e}");
        o
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

/// A running fixture agent with a shell as its command, taking one
/// command line after another, each with its own output files; killed
/// on drop. The agent is the root of every grant for its commands.
struct Agent {
    child: Child,
    stdin: ChildStdin,
    out_dir: PathBuf,
    n: usize,
    cs: Vec<Canary>,
}

impl Agent {
    fn start(f: &Fixture, cwd: &Path) -> Agent {
        // A directory of its own: two agents in one test must not share
        // output files.
        static AGENTS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = AGENTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let out_dir = f.home.root().join(format!("agent-{n}"));
        std::fs::create_dir_all(&out_dir).unwrap();
        let mut cmd = Command::new(testkit_bin("fixture-agent"));
        f.home.apply(&mut cmd);
        let mut child = cmd
            .args(["--", "/bin/sh"])
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        Agent {
            child,
            stdin,
            out_dir,
            n: 0,
            cs: f.cs.clone(),
        }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Runs `command` in the agent's shell and returns its output.
    fn sh(&mut self, command: &str) -> Output {
        self.n += 1;
        let base = self.out_dir.join(self.n.to_string());
        let (out, err, code) = (
            base.with_extension("out"),
            base.with_extension("err"),
            base.with_extension("code"),
        );
        // A subshell, so the redirections and the exit status cover the
        // whole command line.
        writeln!(
            self.stdin,
            "( {command} ) </dev/null >{} 2>{}; echo $? >{}",
            quoted(out.to_str().unwrap()),
            quoted(err.to_str().unwrap()),
            quoted(code.to_str().unwrap())
        )
        .unwrap();
        self.stdin.flush().unwrap();
        let end = Instant::now() + Duration::from_secs(60);
        let status = loop {
            if let Ok(s) = std::fs::read_to_string(&code) {
                if let Ok(n) = s.trim().parse::<i32>() {
                    break ExitStatus::from_raw(n << 8);
                }
            }
            assert!(Instant::now() < end, "the agent's command did not finish");
            std::thread::sleep(Duration::from_millis(20));
        };
        let o = Output {
            status,
            stdout: std::fs::read(&out).unwrap(),
            stderr: std::fs::read(&err).unwrap(),
        };
        assert_no_canary(&o.stdout, &self.cs);
        assert_no_canary(&o.stderr, &self.cs);
        o
    }

    /// `envcloak run <args>` as the agent's command.
    fn run(&mut self, args: &[&str]) -> Output {
        let mut line = format!("{} run", quoted(cli().to_str().unwrap()));
        for a in args {
            line.push(' ');
            line.push_str(&quoted(a));
        }
        self.sh(&line)
    }

    /// `envcloak <args>` with the passphrase file on descriptor 3. Returns
    /// the output and how many bytes of the file the command left unread.
    fn with_pass(&mut self, args: &[&str], pass: &Path) -> (Output, usize) {
        let rest = self.out_dir.join(format!("{}.rest", self.n + 1));
        let mut line = format!(
            "exec 3<{}; {}",
            quoted(pass.to_str().unwrap()),
            quoted(cli().to_str().unwrap())
        );
        for a in args {
            line.push(' ');
            line.push_str(&quoted(a));
        }
        // The descriptor's offset is shared with the command's, so what is
        // left to read after it is what it did not read. (`wc -c` alone
        // may give a regular file's size, whatever the offset.)
        line.push_str(&format!(
            " --passphrase-fd 3; s=$?; cat <&3 | wc -c >{}; exec 3<&-; exit $s",
            quoted(rest.to_str().unwrap())
        ));
        let out = self.sh(&line);
        let left = std::fs::read_to_string(&rest)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        (out, left)
    }

    /// Kills the agent process. Its shell lives on, orphaned, until the
    /// pipe closes on drop.
    fn kill(&mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The request id in `approval_required request=<id>`.
fn request_id(err: &str) -> String {
    let line = err
        .lines()
        .find(|l| l.contains("approval_required"))
        .unwrap_or_else(|| panic!("no approval_required in: {err}"));
    let id = line
        .split("request=")
        .nth(1)
        .and_then(|s| s.split(':').next())
        .unwrap_or_else(|| panic!("no request id in: {err}"));
    assert_eq!(id.len(), 8, "{line}");
    id.to_owned()
}

/// The grant id in `Approved request <id>: grant <grant>, ...`.
fn grant_id(shown: &str) -> String {
    let line = shown
        .lines()
        .find(|l| l.starts_with("Approved request"))
        .unwrap_or_else(|| panic!("no approval line in: {shown}"));
    let id = line
        .split("grant ")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .unwrap_or_else(|| panic!("no grant id in: {line}"));
    assert_eq!(id.len(), 26, "{line}");
    id.to_owned()
}

/// Story S4 to S6: the agent's request needs a person's approval, given
/// out of band with the passphrase; a wrong passphrase fails; the
/// statement shows the command line escaped (gate 31); after approval the
/// same request is covered and a different binding set is not (gate 28);
/// grants are listed and revoked without a proof (gate 29); a denial is
/// remembered (gate 32).
#[test]
fn an_agents_request_needs_a_persons_approval() {
    let f = Fixture::new();
    let mut agent = f.agent();

    // S4: exit 125, the request id, no value, nothing read from anywhere.
    let out = agent.run(&["--", "./emit", "--flag", "\x1b[31mred", "\u{202e}gnp.exe"]);
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(
        err.starts_with("envcloak: approval_required: request="),
        "{err}"
    );
    assert!(err.contains("in a terminal you control"), "{err}");
    let id = request_id(&err);
    assert!(out.stdout.is_empty());

    // S5: a wrong passphrase is refused and counted; the right one
    // creates the grant. The statement is shown escaped.
    let out = f.person(
        &["approve", &id, "--for", "1h", "--passphrase-fd", "3"],
        &f.wrong,
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).starts_with("envcloak: wrong_passphrase:"),
        "{}",
        stderr(&out)
    );
    let status = stdout(&run(&f.home, &["status"], &[]));
    assert!(status.contains("failed passphrase attempts: 1"), "{status}");
    assert!(
        status.contains("grants: 0 in force, 1 waiting for approval"),
        "{status}"
    );

    let shown = f.approve(&id, &["--for", "1h"]);
    assert!(shown.contains(&format!("Approval request {id}")), "{shown}");
    assert!(
        shown.contains("agent EnvCloak test fixture agent"),
        "{shown}"
    );
    assert!(
        shown.contains(&format!("rooted at pid {}", agent.pid())),
        "{shown}"
    );
    assert!(shown.contains("new project"), "{shown}");
    assert!(
        shown.contains("OPENAI_API_KEY = openai/acme-web#value"),
        "{shown}"
    );
    assert!(
        shown.contains("STRIPE_SECRET_KEY = stripe/acme-web#value"),
        "{shown}"
    );
    assert!(shown.contains("first use"), "{shown}");
    assert!(shown.contains("[0] ./emit"), "{shown}");
    assert!(shown.contains("[2] \\u{1b}[31mred"), "{shown}");
    assert!(shown.contains("[3] \\u{202e}gnp.exe"), "{shown}");
    assert!(
        !shown.contains('\u{1b}') && !shown.contains('\u{202e}'),
        "raw bytes: {shown:?}"
    );
    assert!(shown.contains("for 1h"), "{shown}");
    let grant = grant_id(&shown);
    // Approved: the request is gone.
    let out = f.person(&["approve", &id, "--passphrase-fd", "3"], &f.pass);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).starts_with("envcloak: no_such_request:"),
        "{}",
        stderr(&out)
    );

    // S6's decision: covered now, with any command line, under the same
    // agent.
    let out = agent.run(&["--", "./emit"]);
    let err = stderr(&out);
    assert!(
        err.contains(&format!(
            "grant {grant} covers this request (inject mode, output redacted)"
        )),
        "{err}"
    );
    assert_eq!(out.status.code(), Some(2));
    // A different binding set prompts for it.
    let out = agent.run(&["--profile", "short", "--", "./emit"]);
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    let short = request_id(&stderr(&out));
    assert_ne!(short, id);

    // The grant is listed, then revoked without a proof.
    let list = stdout(&run(&f.home, &["grants", "list"], &[]));
    assert!(list.contains(&grant), "{list}");
    assert!(list.contains("agent EnvCloak test fixture agent"), "{list}");
    assert!(
        list.contains("OPENAI_API_KEY=openai/acme-web, STRIPE_SECRET_KEY=stripe/acme-web"),
        "{list}"
    );
    assert!(list.contains("session, "), "{list}");
    let json = stdout(&run(&f.home, &["grants", "list", "--json"], &[]));
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["grants"][0]["id"], grant);
    assert_eq!(v["grants"][0]["kind"], "agent");
    let out = run(&f.home, &["grants", "revoke", &grant], &[]);
    assert_eq!(stdout(&out), "Revoked 1 grant.\n");
    let out = run(&f.home, &["grants", "revoke", &grant], &[]);
    assert_eq!(stdout(&out), "No grant was revoked.\n");
    assert_eq!(
        stdout(&run(&f.home, &["grants", "list"], &[])),
        "No grants are in force.\n"
    );
    let out = agent.run(&["--", "./emit"]);
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));

    // A denial is remembered: the same request is denied without a
    // prompt for 10 minutes.
    let out = run(&f.home, &["deny", &short], &[]);
    assert_eq!(stdout(&out), format!("Denied request {short}.\n"));
    let out = agent.run(&["--profile", "short", "--", "./emit"]);
    assert_eq!(out.status.code(), Some(125));
    assert!(
        stderr(&out).starts_with("envcloak: approval_denied:"),
        "{}",
        stderr(&out)
    );
    drop(agent);
    f.sweep();
}

/// Gate 23: proofs are refused from a caller with an agent in its
/// ancestry or agent markers in its environment (`approve` and `unlock`
/// alike), and the statement is only advisory: a `y` typed into the
/// requester's terminal approves nothing, and `envcloak run` reads
/// nothing from it. An agent's own `approve` stops before it shows the
/// statement or reads the passphrase: it consumes no input.
#[test]
fn forged_approvals_approve_nothing() {
    let f = Fixture::new();
    let mut agent = f.agent();
    let out = agent.run(&["--", "./emit"]);
    let id = request_id(&stderr(&out));
    let pass_len = std::fs::metadata(&f.pass).unwrap().len() as usize;

    // The agent runs `envcloak approve` itself, with the right passphrase:
    // refused before the statement is shown or the passphrase read.
    let (out, left) = agent.with_pass(&["approve", &id], &f.pass);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).starts_with("envcloak: proof_refused:"),
        "{}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("terminal you control"),
        "{}",
        stderr(&out)
    );
    assert!(out.stdout.is_empty(), "{}", stdout(&out));
    assert_eq!(left, pass_len, "the agent's approve read the passphrase");

    // A person's terminal whose shell carries an agent's marker: the
    // claim only tightens, and the command refuses before it reads.
    let mut cmd = on_terminal_command(
        &f.home,
        &["approve", &id, "--passphrase-fd", "3"],
        &[(3, &f.pass, true)],
    );
    cmd.env("CLAUDECODE", "1");
    let out = finish_within(cmd, Duration::from_secs(60));
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).starts_with("envcloak: proof_refused:"),
        "{}",
        stderr(&out)
    );
    assert!(out.stdout.is_empty(), "{}", stdout(&out));
    let status = stdout(&run(&f.home, &["status"], &[]));
    assert!(
        status.contains("grants: 0 in force, 1 waiting for approval"),
        "{status}"
    );

    // `unlock` is a proof too.
    assert!(run(&f.home, &["lock"], &[]).status.success());
    let (out, left) = agent.with_pass(&["unlock"], &f.pass);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).starts_with("envcloak: proof_refused:"),
        "{}",
        stderr(&out)
    );
    // The daemon refuses the agent's unlock: the CLI read the passphrase
    // and sent it, and the daemon never looked at it.
    assert_eq!(left, 0);
    let status = stdout(&run(&f.home, &["status"], &[]));
    assert!(status.contains("vault: locked"), "{status}");
    assert!(!status.contains("failed unlocks"), "{status}");
    let out = f.person(&["unlock", "--passphrase-fd", "3"], &f.pass);
    assert!(out.status.success(), "{}", stderr(&out));
    let log = f.d.log();
    assert!(
        log.contains("proof refused method=unlock reason=agent "),
        "{log}"
    );
    assert!(
        log.contains("proof refused method=pending.get reason=agent "),
        "{log}"
    );

    // The request went with the lock; a new one, on a terminal of the
    // agent's own: `y` typed there approves nothing, and the request
    // stays for a person.
    let fixture = testkit_bin("fixture-agent");
    let argv: Vec<&str> = vec![
        fixture.to_str().unwrap(),
        "--",
        cli().to_str().unwrap(),
        "run",
        "--",
        "./emit",
    ];
    let (out, code) = drive_from(&f.home, &f.project, &argv, &[("approval_required", "y\r")]);
    assert_eq!(code, 125, "{}", stdout(&out));
    let shown = stdout(&out);
    let id = request_id(&shown);
    assert_eq!(
        stdout(&run(&f.home, &["grants", "list"], &[])),
        "No grants are in force.\n"
    );
    let status = stdout(&run(&f.home, &["status"], &[]));
    assert!(
        status.contains("grants: 0 in force, 1 waiting for approval"),
        "{status}"
    );

    // The agent runs `envcloak approve` on that terminal: no statement
    // and no passphrase prompt appear there, so there is nothing for a
    // person to type into.
    let argv: Vec<&str> = vec![
        fixture.to_str().unwrap(),
        "--",
        cli().to_str().unwrap(),
        "approve",
        &id,
    ];
    let (out, code) = drive_from(&f.home, &f.project, &argv, &[]);
    let shown = stdout(&out);
    assert_eq!(code, 1, "{shown}");
    assert!(shown.contains("proof_refused"), "{shown}");
    assert!(!shown.contains("passphrase to approve"), "{shown}");
    assert!(!shown.contains("Approval request"), "{shown}");

    let shown = f.approve(&id, &["--once"]);
    assert!(shown.contains("for one request"), "{shown}");
    drop(agent);
    f.sweep();
}

/// Gate 23: a proof needs a terminal session. The same person's command
/// without a controlling terminal, as a program that left an agent's
/// tree runs it (forked out and `setsid`; a service manager's job below),
/// shows no statement, gives no grant and unlocks nothing: SPEC §10b
/// takes a proof only from a terminal subject. Its own request is still
/// decided, and needs a person.
#[test]
fn a_proof_needs_a_terminal_session() {
    let f = Fixture::new();
    // A request from a command without a terminal: an `unknown` subject,
    // pending like any other.
    let mut cmd = cli_command(&f.home, &["run", "--", "./emit"], &[]);
    cmd.current_dir(&f.project);
    let out = finish_within(cmd, Duration::from_secs(60));
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    let mine = request_id(&stderr(&out));
    let mut agent = f.agent();
    let out = agent.run(&["--", "./emit"]);
    let id = request_id(&stderr(&out));

    for request in [&id, &mine] {
        let out = run(
            &f.home,
            &["approve", request, "--passphrase-fd", "3"],
            &[(3, &f.pass, true)],
        );
        assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
        assert!(
            stderr(&out).starts_with("envcloak: proof_refused:"),
            "{}",
            stderr(&out)
        );
        assert!(out.stdout.is_empty(), "{}", stdout(&out));
    }
    assert_eq!(
        stdout(&run(&f.home, &["grants", "list"], &[])),
        "No grants are in force.\n"
    );
    assert!(run(&f.home, &["lock"], &[]).status.success());
    let out = run(
        &f.home,
        &["unlock", "--passphrase-fd", "3"],
        &[(3, &f.pass, true)],
    );
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).starts_with("envcloak: proof_refused:"),
        "{}",
        stderr(&out)
    );
    let status = stdout(&run(&f.home, &["status"], &[]));
    assert!(status.contains("vault: locked"), "{status}");
    assert!(!status.contains("failed"), "{status}");
    let log = f.d.log();
    for method in ["pending.get", "unlock"] {
        assert!(
            log.contains(&format!(
                "proof refused method={method} reason=no_terminal "
            )) || log.contains(&format!("proof refused method={method} reason=agent ")),
            "{log}"
        );
    }
    // The same command on a terminal of its own unlocks.
    let out = f.person(&["unlock", "--passphrase-fd", "3"], &f.pass);
    assert!(out.status.success(), "{}", stderr(&out));
    drop(agent);
    f.sweep();
}

/// Whether the service-manager cases may run: they submit a job to the
/// user's `launchd` or `systemd --user`. CI sets
/// `ENVCLOAK_TEST_SERVICE_MANAGER=1` on both systems and must run them.
fn service_manager_allowed() -> bool {
    if std::env::var_os("ENVCLOAK_TEST_SERVICE_MANAGER").is_none() {
        assert!(
            std::env::var_os("CI").is_none(),
            "CI must set ENVCLOAK_TEST_SERVICE_MANAGER=1 for the service-manager proofs"
        );
        eprintln!("skipped: set ENVCLOAK_TEST_SERVICE_MANAGER=1 to submit a test job");
        return false;
    }
    true
}

/// A job submitted to the user's service manager (`launchctl submit` on
/// macOS, `systemd-run --user` on Linux), removed on drop.
struct Job {
    name: String,
    #[cfg(target_os = "linux")]
    runtime: String,
}

impl Job {
    /// Submits `/bin/sh script` with `home`'s environment and nothing else.
    fn submit(home: &TestHome, script: &Path) -> Job {
        let name = format!(
            "envcloak-test-proof-{}-{}",
            std::process::id(),
            script.file_name().unwrap().to_str().unwrap()
        );
        let mut argv: Vec<std::ffi::OsString> = vec!["/usr/bin/env".into(), "-i".into()];
        for (k, v) in home.vars() {
            let mut kv = std::ffi::OsString::from(format!("{k}="));
            kv.push(v);
            argv.push(kv);
        }
        argv.extend(["/bin/sh".into(), script.as_os_str().to_owned()]);
        #[cfg(target_os = "macos")]
        {
            let label = format!("ai.envcloak.{name}");
            let ok = Command::new("launchctl")
                .args(["submit", "-l", &label, "--"])
                .args(&argv)
                .status()
                .unwrap()
                .success();
            assert!(ok, "launchctl submit failed");
            Job { name: label }
        }
        #[cfg(target_os = "linux")]
        {
            let runtime = std::env::var("ENVCLOAK_TEST_SERVICE_RUNTIME_DIR").expect(
                "ENVCLOAK_TEST_SERVICE_RUNTIME_DIR names the user manager's runtime directory",
            );
            let ok = Command::new("systemd-run")
                .args([
                    "--user",
                    "--quiet",
                    "--collect",
                    &format!("--unit={name}"),
                    "--",
                ])
                .args(&argv)
                .env("XDG_RUNTIME_DIR", &runtime)
                .env(
                    "DBUS_SESSION_BUS_ADDRESS",
                    format!("unix:path={runtime}/bus"),
                )
                .status()
                .unwrap()
                .success();
            assert!(ok, "systemd-run --user failed");
            Job { name, runtime }
        }
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        let _ = Command::new("launchctl")
            .args(["remove", &self.name])
            .status();
        #[cfg(target_os = "linux")]
        let _ = Command::new("systemctl")
            .args(["--user", "stop", &self.name])
            .env("XDG_RUNTIME_DIR", &self.runtime)
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}/bus", self.runtime),
            )
            .status();
    }
}

/// Runs `envcloak <args> --passphrase-fd 3` as a job of the user's service
/// manager, with the passphrase file on descriptor 3, as an agent that
/// escaped its tree through `launchctl submit` or `systemd-run --user`
/// would. Returns the output and how many bytes of the file it left
/// unread.
fn as_service_job(f: &Fixture, tag: &str, args: &[&str]) -> (Output, usize) {
    let dir = f.home.root().join(format!("job-{tag}"));
    std::fs::create_dir_all(&dir).unwrap();
    let (out, err, rest, code) = (
        dir.join("out"),
        dir.join("err"),
        dir.join("rest"),
        dir.join("code"),
    );
    let mut line = format!(
        "exec 3<{}\n{}",
        quoted(f.pass.to_str().unwrap()),
        quoted(cli().to_str().unwrap())
    );
    for a in args {
        line.push(' ');
        line.push_str(&quoted(a));
    }
    let q = |p: &Path| quoted(p.to_str().unwrap());
    line.push_str(&format!(
        " --passphrase-fd 3 </dev/null >{} 2>{}\ns=$?\ncat <&3 | wc -c >{}\necho $s >{}.part\nmv {}.part {}\n\
         exec /bin/sleep 300\n",
        q(&out),
        q(&err),
        q(&rest),
        q(&code),
        q(&code),
        q(&code)
    ));
    let script = dir.join(tag);
    std::fs::write(&script, line).unwrap();
    let job = Job::submit(&f.home, &script);
    let end = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Ok(s) = std::fs::read_to_string(&code) {
            break ExitStatus::from_raw(s.trim().parse::<i32>().unwrap() << 8);
        }
        assert!(
            Instant::now() < end,
            "the service manager's job did not finish"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    drop(job);
    let o = Output {
        status,
        stdout: std::fs::read(&out).unwrap(),
        stderr: std::fs::read(&err).unwrap(),
    };
    assert_no_canary(&o.stdout, &f.cs);
    assert_no_canary(&o.stderr, &f.cs);
    let left = std::fs::read_to_string(&rest)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    (o, left)
}

/// Gate 23 with a service manager: `envcloak approve` and `unlock` run as
/// a `launchctl submit` (macOS) or `systemd-run --user` (Linux) job, how
/// an agent leaves its tree for a process that is neither an agent's nor
/// an orphan, are refused: no statement, no passphrase read by `approve`,
/// no grant, no unlock.
#[test]
fn a_service_managers_job_gives_no_proof() {
    if !service_manager_allowed() {
        return;
    }
    let f = Fixture::new();
    let pass_len = std::fs::metadata(&f.pass).unwrap().len() as usize;
    let mut agent = f.agent();
    let out = agent.run(&["--", "./emit"]);
    let id = request_id(&stderr(&out));

    let (out, left) = as_service_job(&f, "approve", &["approve", &id, "--for", "1h"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).starts_with("envcloak: proof_refused:"),
        "{}",
        stderr(&out)
    );
    assert!(out.stdout.is_empty(), "{}", stdout(&out));
    assert_eq!(left, pass_len, "the job's approve read the passphrase");
    assert_eq!(
        stdout(&run(&f.home, &["grants", "list"], &[])),
        "No grants are in force.\n"
    );

    assert!(run(&f.home, &["lock"], &[]).status.success());
    let (out, _) = as_service_job(&f, "unlock", &["unlock"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).starts_with("envcloak: proof_refused:"),
        "{}",
        stderr(&out)
    );
    let status = stdout(&run(&f.home, &["status"], &[]));
    assert!(status.contains("vault: locked"), "{status}");
    let log = f.d.log();
    for method in ["pending.get", "unlock"] {
        assert!(
            log.contains(&format!(
                "proof refused method={method} reason=no_terminal "
            )),
            "{log}"
        );
    }
    drop(agent);
    f.sweep();
}

/// Gate 31: a command line with an argument that is not UTF-8 is refused
/// as a usage error before anything is sent. It is never shown, or
/// approved, as something else: replaced by an empty string, two distinct
/// commands and one with an empty argument would read the same.
#[test]
fn a_command_line_that_is_not_utf8_is_refused() {
    use std::os::unix::ffi::OsStrExt;

    let f = Fixture::new();
    for bad in [&b"\xff"[..], b"a\xc3", b"\xe2\x82", b"ok\xed\xa0\x80"] {
        let mut cmd = cli_command(&f.home, &["run", "--", "./emit"], &[]);
        cmd.current_dir(&f.project)
            .arg(std::ffi::OsStr::from_bytes(bad));
        let out = finish_within(cmd, Duration::from_secs(60));
        assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
        assert!(stderr(&out).contains("not valid UTF-8"), "{}", stderr(&out));
        assert!(
            !out.stderr.windows(bad.len()).any(|w| w == bad),
            "the argument was echoed"
        );
    }
    let status = stdout(&run(&f.home, &["status"], &[]));
    assert!(
        status.contains("grants: 0 in force, 0 waiting for approval"),
        "{status}"
    );
    // An empty argument is an argument, and the statement shows it.
    let mut cmd = cli_command(&f.home, &["run", "--", "./emit", ""], &[]);
    cmd.current_dir(&f.project);
    let out = finish_within(cmd, Duration::from_secs(60));
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    let id = request_id(&stderr(&out));
    let shown = f.approve(&id, &["--once"]);
    assert!(shown.contains("command (2 arguments):"), "{shown}");
    assert!(shown.contains("    [1] \n"), "{shown:?}");
    f.sweep();
}

/// Gate 24: a manifest that tries to loosen policy (`redact = false`,
/// `mode = "inject"`) changes nothing: the agent's request still needs an
/// approval, and its output stays redacted. `agents = "allow"` does not
/// even parse.
#[test]
fn a_loosening_manifest_still_needs_approval_and_redaction_stays_on() {
    let f = Fixture::with_manifest(&format!(
        "{MANIFEST}\n[policy]\nredact = false\nmode = \"inject\"\n"
    ));
    let mut agent = f.agent();
    let out = agent.run(&["--", "./emit"]);
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    let id = request_id(&stderr(&out));
    f.approve(&id, &[]);
    let out = agent.run(&["--", "./emit"]);
    assert!(
        stderr(&out).contains("(inject mode, output redacted)"),
        "{}\n{}",
        stderr(&out),
        f.d.log()
    );

    let loose = project(
        &f.home,
        "loose",
        &format!("{MANIFEST}\n[policy]\nagents = \"allow\"\n"),
    );
    let mut in_loose = Agent::start(&f, &loose);
    let out = in_loose.run(&["--", "./emit"]);
    assert_eq!(out.status.code(), Some(125));
    assert!(
        stderr(&out).starts_with("envcloak: manifest_invalid:"),
        "{}",
        stderr(&out)
    );
    assert!(stderr(&out).contains("loosen"), "{}", stderr(&out));
    drop((agent, in_loose));
    f.sweep();
}

/// Gate 25's grant half: a grant for this process's own tree (the
/// terminal, or whatever CI runs the tests in) does not cover the fixture
/// agent under it: the agent barrier.
#[test]
fn a_grant_for_the_terminal_does_not_cover_the_agent() {
    let f = Fixture::new();
    // This process asks, and approves its own request out of band.
    let paths = RunPaths::under(daemon_run_dir(&f.home)).unwrap();
    let mut c = Client::connect(&paths).unwrap();
    let params = RunRequestParams {
        manifest: f.project.join("envcloak.toml").to_str().unwrap().to_owned(),
        profile: None,
        refs: Vec::new(),
        argv: vec!["./emit".to_owned()],
        claims: Vec::new(),
    };
    let id = match c.run_request(&params).unwrap() {
        DecisionView::Pending { request } => request,
        other => panic!("{other:?}"),
    };
    f.approve(&id, &["--for", "1h"]);
    assert!(matches!(
        c.run_request(&params).unwrap(),
        DecisionView::Covered { .. }
    ));
    // The agent, a child of this process, is not covered.
    let mut agent = f.agent();
    let out = agent.run(&["--", "./emit"]);
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    assert!(
        stderr(&out).starts_with("envcloak: approval_required:"),
        "{}",
        stderr(&out)
    );
    drop(agent);
    f.sweep();
}

/// Gate 29: a grant ends when its root exits. The root is the fixture
/// agent; its command is approved, a second command under it is covered,
/// and once the agent is gone the grant is swept.
#[test]
fn a_grant_ends_when_its_root_exits() {
    let f = Fixture::new();
    let mut agent = f.agent();
    let out = agent.run(&["--", "true"]);
    let id = request_id(&stderr(&out));
    f.approve(&id, &["--for", "1h"]);
    let out = agent.run(&["--", "true"]);
    assert!(
        stderr(&out).contains("covers this request"),
        "{}",
        stderr(&out)
    );
    let list = stdout(&run(&f.home, &["grants", "list"], &[]));
    assert!(
        list.contains(&format!("rooted at pid {}", agent.pid())),
        "{list}"
    );

    // The root exits (its shell child lives on, orphaned): the tick sweeps
    // the grant within a few seconds.
    agent.kill();
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        let list = stdout(&run(&f.home, &["grants", "list"], &[]));
        if list == "No grants are in force.\n" {
            break;
        }
        assert!(Instant::now() < end, "the grant outlived its root: {list}");
        std::thread::sleep(Duration::from_millis(200));
    }
    drop(agent);
    f.sweep();
}
