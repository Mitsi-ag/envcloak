//! PTY mode's start (M2 task M2-17): `envcloak_exec::start_pty` puts the
//! values in the command's environment and nowhere else (gate 14 for the
//! PTY path), the PTY monitor it forks keeps the CLI's hardening (R-M2-79:
//! core dumps off; on Linux non-dumpable, so its environment cannot be
//! read even by the same user, while the command's, after `exec`, can),
//! the form a real terminal writes a value holding LF in is the CR LF form
//! the redactor adds (the kernel's `ONLCR` as the independent oracle,
//! D-19), failures before the start keep their exit codes, and a run
//! started with SIGCHLD ignored keeps its child its own to wait for.
//!
//! Gate 14 runs in a copy of this binary standing in for the CLI, so its
//! own standard output and standard error are captured and searched too,
//! and everything the terminal shows is read to its end (the reader joined
//! once the terminal ended), with a positive control for each: a second
//! canary the command prints late, after the test's first wait, and that
//! the stand-in prints on both of its outputs, must be found.
//!
//! No libtest harness (`harness = false`): the command is this binary,
//! started as `pty_spawn --child`, so `ps` shows its environment on macOS
//! (it does not show a platform binary's), and nothing else runs in the
//! process that forks the monitor.
#![allow(clippy::unwrap_used)]

use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use envcloak_core::SecretBytes;
use envcloak_exec::{ChildExit, ExecError, RunSpec, start_pty};
use envcloak_policy::EnvName;
use envcloak_redact::RedactorBuilder;
use envcloak_sys::pty::MonitorEvent;
use envcloak_testkit::{by_label, canaries, fresh_seed, labels};

#[global_allocator]
static ALLOCATOR: envcloak_sys::WipingAllocator = envcloak_sys::WipingAllocator;

const CHILD: &str = "--child";
const DEADLINE: Duration = Duration::from_secs(20);
/// The role a copy of this binary plays, when not the command.
const ROLE: &str = "ENVCLOAK_PTY_SPAWN_ROLE";
/// The canaries' seed, for the gate-14 stand-in.
const SEED: &str = "ENVCLOAK_PTY_SPAWN_SEED";
/// What the command prints after it read its line.
const LATE: &str = "ENVCLOAK_PTY_SPAWN_LATE";
/// How the M1-run stand-in has its children reaped.
const HOW: &str = "ENVCLOAK_PTY_SPAWN_HOW";

fn main() {
    if std::env::args().nth(1).as_deref() == Some(CHILD) {
        return child();
    }
    match std::env::var(ROLE).as_deref() {
        Ok("gate14") => return gate14_stand_in(),
        Ok("m1-run") => return m1_run_with_sigchld_ignored(),
        _ => {}
    }
    envcloak_sys::testing::libtest::run_cases(
        "pty_spawn",
        &[
            (
                "values_live_in_the_commands_environment_only",
                values_live_in_the_commands_environment_only,
            ),
            (
                "a_terminal_writes_a_value_holding_lf_in_the_form_the_redactor_adds",
                a_terminal_writes_a_value_holding_lf_in_the_form_the_redactor_adds,
            ),
            (
                "failures_before_the_start_keep_their_exit_codes",
                failures_before_the_start_keep_their_exit_codes,
            ),
            (
                "a_run_started_with_sigchld_ignored_still_waits_for_its_command",
                a_run_started_with_sigchld_ignored_still_waits_for_its_command,
            ),
        ],
    );
}

/// The command: reports its pid, waits for a line, then prints what
/// `ENVCLOAK_PTY_SPAWN_LATE` holds (if anything) and exits.
fn child() {
    let mut out = std::io::stdout().lock();
    writeln!(out, "READY {}", std::process::id()).unwrap();
    out.flush().unwrap();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).unwrap();
    if let Some(late) = std::env::var_os(LATE) {
        writeln!(out, "LATE {}", late.to_string_lossy()).unwrap();
        out.flush().unwrap();
    }
}

/// Everything the PTY's master side shows, read on a thread until the
/// terminal ends (EOF or EIO, once nothing holds the slave side).
struct Screen {
    seen: Arc<Mutex<Vec<u8>>>,
    more: mpsc::Receiver<()>,
    reader: Option<std::thread::JoinHandle<()>>,
    writer: std::fs::File,
}

impl Screen {
    fn new(master: OwnedFd) -> Self {
        let writer = std::fs::File::from(master.try_clone().unwrap());
        let mut reader = std::fs::File::from(master);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (tx, more) = mpsc::channel();
        let sink = Arc::clone(&seen);
        let reader = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf) {
                    Ok(n) if n > 0 => {
                        sink.lock().unwrap().extend_from_slice(&buf[..n]);
                        let _ = tx.send(());
                    }
                    // EOF, or EIO once every slave descriptor is closed.
                    _ => return,
                }
            }
        });
        Screen {
            seen,
            more,
            reader: Some(reader),
            writer,
        }
    }

    /// Waits until `done` holds for what was shown, up to [`DEADLINE`].
    fn wait_for(&self, done: impl Fn(&[u8]) -> bool) -> bool {
        let end = Instant::now() + DEADLINE;
        while !done(&self.seen.lock().unwrap()) {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            // A wake-up per chunk, or the reader's end.
            if let Err(mpsc::RecvTimeoutError::Disconnected) = self.more.recv_timeout(left) {
                return done(&self.seen.lock().unwrap());
            }
        }
        true
    }

    fn type_line(&mut self) {
        self.writer.write_all(b"\n").unwrap();
    }

    /// Reads to the terminal's end and returns everything it showed; fails
    /// the test when it has not ended by [`DEADLINE`] (the reader stops
    /// only at EOF or EIO, so a joined reader is a confirmed end).
    fn read_to_end(mut self) -> Vec<u8> {
        drop(self.writer);
        let end = Instant::now() + DEADLINE;
        loop {
            let left = end.saturating_duration_since(Instant::now());
            match self.more.recv_timeout(left) {
                Ok(()) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    panic!("the terminal did not end");
                }
            }
        }
        self.reader.take().unwrap().join().unwrap();
        self.seen.lock().unwrap().clone()
    }
}

fn holds(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// What `ps` shows of process `pid`: its command line, and its environment
/// (macOS `ps -E`; Linux `/proc/<pid>/environ`, `None` when refused).
fn ps(pid: u32) -> (Vec<u8>, Option<Vec<u8>>) {
    let run_ps = |extra: &[&str]| -> Vec<u8> {
        let out = Command::new("/bin/ps")
            .args(extra)
            .args(["-ww", "-o", "command=", "-p", &pid.to_string()])
            .output()
            .unwrap();
        assert!(out.status.success(), "ps failed");
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

/// Gate 14 for the PTY path, and R-M2-79 for the monitor, in a stand-in
/// for the CLI (see the module documentation). The command's environment
/// holds the value, readable by a process of the same user (SPEC §1.1);
/// its command line does not, nor the stand-in's environment, nor
/// anything the terminal showed, read to its end, nor the stand-in's own
/// standard output or standard error. Positive controls: the late canary
/// the command prints after the stand-in's first wait is found on the
/// terminal, and the stand-in's copies of it are found on both of its
/// outputs.
fn values_live_in_the_commands_environment_only() {
    let seed = fresh_seed();
    let cs = canaries(seed);
    let value = by_label(&cs, labels::OPENAI_API_KEY).value();
    let late = by_label(&cs, labels::STRIPE_SECRET_KEY).value();
    let out = Command::new(std::env::current_exe().unwrap())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env(ROLE, "gate14")
        .env(SEED, seed.to_string())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let report = String::from_utf8_lossy(&out.stdout);
    // What the stand-in said on failure, minus any line holding the value.
    let said: Vec<String> = String::from_utf8_lossy(&out.stderr)
        .lines()
        .filter(|l| !holds(l.as_bytes(), value))
        .map(str::to_owned)
        .collect();
    assert!(
        out.status.success() && report.contains("GATE14 DONE"),
        "the stand-in failed: {:?}\n{}",
        out.status,
        said.join("\n")
    );
    assert!(
        !holds(&out.stdout, value),
        "the value is on the stand-in's stdout"
    );
    assert!(
        !holds(&out.stderr, value),
        "the value is on the stand-in's stderr"
    );
    assert!(
        holds(&out.stdout, late) && holds(&out.stderr, late),
        "the positive control: the stand-in's own outputs were not searched"
    );
    for line in report.lines().filter(|l| l.starts_with("gate 14")) {
        println!("{line}");
    }
}

/// The CLI stand-in for gate 14 (stdout and stderr captured by the test).
fn gate14_stand_in() {
    let hardening = envcloak_sys::harden_process();
    assert!(hardening.core_dumps_off, "{hardening:?}");
    if cfg!(target_os = "linux") {
        assert!(hardening.non_dumpable, "{hardening:?}");
    }
    let seed: u64 = std::env::var(SEED).unwrap().parse().unwrap();
    let cs = canaries(seed);
    let value = by_label(&cs, labels::OPENAI_API_KEY).value();
    let late = by_label(&cs, labels::STRIPE_SECRET_KEY).value();
    let exe = std::env::current_exe().unwrap();
    let pty = start_pty(
        &[exe.into_os_string(), OsString::from(CHILD)],
        &[
            (
                EnvName::new("OPENAI_API_KEY").unwrap(),
                SecretBytes::copy_from(value),
            ),
            (EnvName::new(LATE).unwrap(), SecretBytes::copy_from(late)),
        ],
        None,
        None,
    )
    .unwrap();
    let mut monitor = pty.monitor;
    let mut screen = Screen::new(pty.master);
    let ready = format!("READY {}", monitor.command_id());
    assert!(
        screen.wait_for(|s| holds(s, ready.as_bytes())),
        "the command did not report"
    );

    let (argv, environ) = ps(monitor.command_id());
    assert!(!holds(&argv, value), "the value is in the command's argv");
    assert!(holds(&argv, CHILD.as_bytes()), "ps showed another process");
    let environ = environ.expect("the command's environment was refused");
    assert!(
        holds(&environ, value),
        "the value is not in the command's environment"
    );
    let own = std::env::vars_os().any(|(_, v)| holds(v.as_encoded_bytes(), value));
    assert!(!own, "the value is in the stand-in's environment");

    // The monitor: forked from this hardened process, never exec'd.
    let monitor_pid = monitor.monitor_id();
    if cfg!(target_os = "linux") {
        let refused = std::fs::read(format!("/proc/{monitor_pid}/environ")).unwrap_err();
        assert_eq!(
            refused.kind(),
            std::io::ErrorKind::PermissionDenied,
            "the monitor is dumpable"
        );
        let limits = std::fs::read_to_string(format!("/proc/{monitor_pid}/limits")).unwrap();
        let core = limits
            .lines()
            .find(|l| l.starts_with("Max core file size"))
            .unwrap();
        let fields: Vec<&str> = core.split_whitespace().collect();
        assert_eq!(&fields[4..6], ["0", "0"], "{core}");
    }

    screen.type_line();
    let event = monitor.next_event(Some(DEADLINE)).unwrap();
    assert!(
        matches!(event, Some(MonitorEvent::Exited(s)) if s.success()),
        "{event:?}"
    );
    monitor.finish().unwrap();
    let all = screen.read_to_end();
    assert!(!holds(&all, value), "the value reached the terminal");
    assert!(
        holds(&all, late),
        "the positive control: output printed after the first wait was not read"
    );
    let mut out = std::io::stdout().lock();
    out.write_all(b"LATE-CONTROL ").unwrap();
    out.write_all(late).unwrap();
    std::io::stderr().write_all(late).unwrap();
    writeln!(
        out,
        "\ngate 14 PTY ({}): a process of the same user read the command's environment (the \
         value present), not its argv, and{} the monitor's; the terminal read to its end \
         and the stand-in's outputs hold no value\nGATE14 DONE",
        std::env::consts::OS,
        if cfg!(target_os = "linux") {
            " not"
        } else {
            " (no check of)"
        }
    )
    .unwrap();
}

/// The command prints a multi-line value through its terminal; the master
/// shows it with every LF as CR LF (the kernel's line discipline, an
/// independent oracle), which is exactly the form `crlf_variants` adds:
/// redacted whole with it, passed through without it. (The shapes beyond
/// this one, LFs in a row and a CR LF already there among them, are in
/// `crates/envcloak-redact/tests/crlf_kernel.rs`.)
fn a_terminal_writes_a_value_holding_lf_in_the_form_the_redactor_adds() {
    let cs = canaries(fresh_seed());
    let key = by_label(&cs, labels::OPENAI_API_KEY).value();
    let stripe = by_label(&cs, labels::STRIPE_SECRET_KEY).value();
    let mut value = key.to_vec();
    value.push(b'\n');
    value.extend_from_slice(stripe);
    value.push(b'\n');
    let pty = start_pty(
        &[
            OsString::from("/bin/sh"),
            OsString::from("-c"),
            OsString::from("printf '%s' \"$PTY_VALUE\""),
        ],
        &[(
            EnvName::new("PTY_VALUE").unwrap(),
            SecretBytes::copy_from(&value),
        )],
        None,
        None,
    )
    .unwrap();
    let mut monitor = pty.monitor;
    let screen = Screen::new(pty.master);
    let event = monitor.next_event(Some(DEADLINE)).unwrap();
    assert!(
        matches!(event, Some(MonitorEvent::Exited(s)) if s.success()),
        "{event:?}"
    );
    monitor.finish().unwrap();
    let seen = screen.read_to_end();
    let mut expected = key.to_vec();
    expected.extend_from_slice(b"\r\n");
    expected.extend_from_slice(stripe);
    expected.extend_from_slice(b"\r\n");
    assert!(seen == expected, "the terminal's form is not CR LF");
    let with = RedactorBuilder::new()
        .crlf_variants(true)
        .secret("multi/line", &value)
        .build()
        .0;
    assert_eq!(with.redact(&seen), b"[envcloak:multi/line]");
    let without = RedactorBuilder::new()
        .secret("multi/line", &value)
        .build()
        .0;
    assert!(
        without.redact(&seen) == seen,
        "the positive control: without the variant the form passes through"
    );
}

/// No command, a NUL byte, a missing program and one that cannot run come
/// back as before anything ran, with `env(1)`'s codes.
fn failures_before_the_start_keep_their_exit_codes() {
    let dir = tempfile::tempdir().unwrap();
    let missing = start_pty(
        &[dir.path().join("missing").into_os_string()],
        &[],
        None,
        None,
    );
    assert!(matches!(missing, Err(ExecError::NotFound)), "{missing:?}");
    assert_eq!(missing.unwrap_err().exit_code(), 127);
    let not_exec = start_pty(&[dir.path().as_os_str().to_owned()], &[], None, None);
    assert!(
        matches!(not_exec, Err(ExecError::NotExecutable(_))),
        "{not_exec:?}"
    );
    assert_eq!(not_exec.unwrap_err().exit_code(), 126);
    let nul = start_pty(
        &[OsString::from("/usr/bin/true")],
        &[(EnvName::new("A").unwrap(), SecretBytes::copy_from(b"x\0y"))],
        None,
        None,
    );
    assert!(matches!(nul, Err(ExecError::NulByte)), "{nul:?}");
    assert!(matches!(
        start_pty(&[], &[], None, None),
        Err(ExecError::NoCommand)
    ));
}

/// Whether the kernel reaps this process's children on its own now: with
/// SIGCHLD ignored it reaps a probe child itself, and waiting for the
/// probe fails (`ECHILD`).
fn reaps_on_its_own() -> bool {
    let mut probe = Command::new("/bin/sh")
        .args(["-c", "exit 0"])
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    probe.wait().is_err()
}

/// The M1 runner, with its children reaped on their own (SIGCHLD ignored
/// from its start, or `SA_NOCLDWAIT` set in it, as `ENVCLOAK_PTY_SPAWN_HOW`
/// says): reports its setup and whether the kernel
/// does reap on its own, runs `exit 7` through `envcloak_exec::run` and
/// reports the outcome and the setup after.
fn m1_run_with_sigchld_ignored() {
    if std::env::var(HOW).as_deref() == Ok("NoWait") {
        envcloak_sys::testing::set_sigchld(envcloak_sys::testing::ChildReaping::NoWait).unwrap();
    }
    let at_start = (envcloak_sys::testing::sigchld_setup(), reaps_on_its_own());
    let devnull = || OwnedFd::from(std::fs::File::create("/dev/null").unwrap());
    let ran = envcloak_exec::run(RunSpec::new(
        vec![
            OsString::from("/bin/sh"),
            OsString::from("-c"),
            OsString::from("exit 7"),
        ],
        vec![],
        RedactorBuilder::new().build().0,
        devnull(),
        devnull(),
    ));
    println!(
        "SETUP-AT-START {:?}\nREAPS-AT-START {}\nRUN {}\nSETUP-AFTER {:?}\nREAPS-AFTER {}",
        at_start.0,
        at_start.1,
        match ran {
            Ok(ChildExit::Code(c)) => format!("code {c}"),
            Ok(other) => format!("{other:?}"),
            Err(e) => format!("error {}", e.token()),
        },
        envcloak_sys::testing::sigchld_setup(),
        reaps_on_its_own()
    );
}

/// A run started with SIGCHLD ignored or with `SA_NOCLDWAIT` would have
/// its command reaped by the kernel as it exits (where the kernel reaps on
/// its own: Linux for both, measured and printed), the pid it signals and
/// waits for free for reuse, and its wait would fail. `envcloak_exec::run`
/// (and `start_pty`, through `spawn_session`) give SIGCHLD its default
/// back before the fork: the command's exit code comes back. Skip that and
/// the setup is still there after, and the run fails where the kernel
/// reaps on its own.
fn a_run_started_with_sigchld_ignored_still_waits_for_its_command() {
    use envcloak_sys::testing::ChildReaping;
    for (how, setup) in [
        (ChildReaping::NoWait, "(false, true)"),
        (ChildReaping::Ignored, "(true, false)"),
    ] {
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env(ROLE, "m1-run")
            .stdin(Stdio::null());
        cmd.env(HOW, format!("{how:?}"));
        if how == ChildReaping::Ignored {
            envcloak_sys::testing::sigchld_ignored_on_spawn(&mut cmd);
        }
        let out = cmd.output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "{how:?}: {:?}\n{text}", out.status);
        assert!(
            text.contains(&format!("SETUP-AT-START {setup}")),
            "{how:?}: the stand-in did not start so (the setup failed):\n{text}"
        );
        assert!(text.contains("RUN code 7"), "{how:?}: {text}");
        assert!(
            text.contains("SETUP-AFTER (false, false)") && text.contains("REAPS-AFTER false"),
            "{how:?}: {text}"
        );
        println!(
            "pty_spawn ({}): SIGCHLD {how:?}: the kernel reaps children on its own: \
             {}; the run waited for its command",
            std::env::consts::OS,
            text.contains("REAPS-AT-START true")
        );
    }
}
