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
//! once the terminal ended), and the stand-in and the command run with a
//! home, a `TMPDIR` and a working directory of their own under a private
//! root, which is swept after the run (gate 14's "no temporary files"),
//! with a positive control for each: a second canary the command prints
//! late, after the test's first wait, that the stand-in prints on both of
//! its outputs and writes to a file under the root, must be found there.
//! An injected name replaces an inherited one and the last of two entries
//! for a name is the one the command gets (one entry, as `Command::env`
//! gives).
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
/// Where the gate-14 stand-in writes its positive control.
const CONTROL: &str = "ENVCLOAK_PTY_SPAWN_CONTROL";
/// The name the environment-order case injects, and the values it uses
/// (none of them a secret).
const ORDERED: &str = "ENVCLOAK_PTY_SPAWN_ORDERED";
/// The command's mode that prints its environment entries for a name.
const ENV_OF: &str = "--env-of";

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some(CHILD) => return child(),
        Some(ENV_OF) => return env_of(),
        _ => {}
    }
    match std::env::var(ROLE).as_deref() {
        Ok("gate14") => return gate14_stand_in(),
        Ok("m1-run") => return m1_run_with_sigchld_ignored(),
        Ok("env-order") => return env_order_stand_in(),
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
            (
                "an_injected_name_replaces_an_inherited_one_and_the_last_entry_wins",
                an_injected_name_replaces_an_inherited_one_and_the_last_entry_wins,
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

/// The command in its other mode: prints each entry of its own
/// environment (the raw `environ` list, duplicates kept) whose name is
/// `ENVCLOAK_PTY_SPAWN_ORDERED`, then `ENV-DONE`.
fn env_of() {
    let mut out = std::io::stdout().lock();
    for (name, value) in std::env::vars_os() {
        if name == ORDERED {
            writeln!(out, "ENV-ENTRY {}", value.to_string_lossy()).unwrap();
        }
    }
    writeln!(out, "ENV-DONE").unwrap();
    out.flush().unwrap();
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
    // The stand-in's and the command's own home, temporary directory and
    // working directory, under a short private root swept below.
    let root = tempfile::Builder::new()
        .prefix("ecg14")
        .tempdir_in("/tmp")
        .unwrap();
    let [home, tmp, cwd, control] = ["home", "tmp", "cwd", "control"].map(|d| {
        let p = root.path().join(d);
        std::fs::create_dir(&p).unwrap();
        p
    });
    let out = Command::new(std::env::current_exe().unwrap())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &home)
        .env("TMPDIR", &tmp)
        .env(ROLE, "gate14")
        .env(SEED, seed.to_string())
        .env(CONTROL, &control)
        .current_dir(&cwd)
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
    // No temporary file: the temporary directory is empty, and no file
    // under the root holds the value; the late canary the stand-in wrote
    // under it is found (the sweep can find what it looks for).
    let left: Vec<_> = std::fs::read_dir(&tmp).unwrap().collect();
    assert!(
        left.is_empty(),
        "files were left in TMPDIR: {} of them",
        left.len()
    );
    let (with_value, with_late) = sweep(root.path(), value, late);
    assert_eq!(
        with_value,
        Vec::<std::path::PathBuf>::new(),
        "files hold the value"
    );
    assert_eq!(
        with_late,
        vec![control.join("late")],
        "the positive control: the sweep did not find the late canary where it was written"
    );
    for line in report.lines().filter(|l| l.starts_with("gate 14")) {
        println!("{line}");
    }
    println!(
        "gate 14 PTY ({}): the private root swept: {} file(s) hold the value, {} the control",
        std::env::consts::OS,
        with_value.len(),
        with_late.len()
    );
}

/// Every regular file under `root` (symbolic links not followed) that
/// holds `value`, and every one that holds `control`, raw.
fn sweep(
    root: &std::path::Path,
    value: &[u8],
    control: &[u8],
) -> (Vec<std::path::PathBuf>, Vec<std::path::PathBuf>) {
    let (mut with_value, mut with_control) = (Vec::new(), Vec::new());
    let mut dirs = vec![root.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                dirs.push(entry.path());
            } else if kind.is_file() {
                let bytes = std::fs::read(entry.path()).unwrap();
                if holds(&bytes, value) {
                    with_value.push(entry.path());
                }
                if holds(&bytes, control) {
                    with_control.push(entry.path());
                }
            }
        }
    }
    (with_value, with_control)
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

    // The monitor: forked from this hardened process, never exec'd. Its
    // command line and (macOS) its environment are this process's, from
    // its own start: neither holds the value.
    let monitor_pid = monitor.monitor_id();
    let (monitor_argv, monitor_environ) = ps(monitor_pid);
    assert!(
        holds(&monitor_argv, b"pty_spawn"),
        "ps showed another process"
    );
    assert!(
        !holds(&monitor_argv, value),
        "the value is in the monitor's argv"
    );
    if cfg!(target_os = "macos") {
        let environ = monitor_environ.expect("the monitor's environment was refused");
        assert!(
            holds(&environ, ROLE.as_bytes()),
            "ps -E showed no environment"
        );
        assert!(
            !holds(&environ, value),
            "the value is in the monitor's environment"
        );
    }
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
    // The monitor wiped its copy of the strings prepared for the exec,
    // the value's `NAME=value` among them, once the command had executed:
    // built with the `testing` feature, it ends with
    // `PREPARED_KEPT_EXIT` when one of them was still there.
    let monitor_status = monitor.finish().unwrap();
    assert_ne!(
        monitor_status.code(),
        Some(envcloak_sys::testing::PREPARED_KEPT_EXIT),
        "the monitor kept its copy of the command's environment"
    );
    assert!(monitor_status.success(), "{monitor_status:?}");
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
    let control = std::path::PathBuf::from(std::env::var_os(CONTROL).unwrap());
    std::fs::write(control.join("late"), late).unwrap();
    writeln!(
        out,
        "\ngate 14 PTY ({}): a process of the same user read the command's environment (the \
         value present), not its argv, and not the monitor's {}; the terminal read to its end \
         and the stand-in's outputs hold no value\nGATE14 DONE",
        std::env::consts::OS,
        if cfg!(target_os = "linux") {
            "(non-dumpable)"
        } else {
            "(ps -E: the CLI's own)"
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
    assert!(
        with.redact(&seen) == b"[envcloak:multi/line]",
        "the terminal's form was not redacted whole (not printed: it holds the value)"
    );
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

/// The three ways a process can come to have its children reaped by the
/// kernel on their own, and the setup each reads back as (ignored,
/// `SA_NOCLDWAIT` set): `SA_NOCLDWAIT` set in the process; SIGCHLD ignored
/// by whatever started it, inherited across `exec`; and SIGCHLD ignored by
/// the process itself, which macOS reads back with `SA_NOCLDWAIT` set too
/// (XNU marks the process so when `sigaction` ignores SIGCHLD). On macOS
/// 26.4.1 the kernel was measured to reap on its own for the first and the
/// last, not the middle one; Linux reaps for all three.
const REAPING: [(&str, &str); 3] = [
    ("no-wait", "(false, true)"),
    ("ignored-inherited", "(true, false)"),
    (
        "ignored-here",
        if cfg!(target_os = "macos") {
            "(true, true)"
        } else {
            "(true, false)"
        },
    ),
];

/// Sets this stand-in's SIGCHLD up as `ENVCLOAK_PTY_SPAWN_HOW` says (the
/// inherited one was set by the test before the `exec`).
fn set_up_reaping() {
    use envcloak_sys::testing::{ChildReaping, set_sigchld};
    match std::env::var(HOW).as_deref() {
        Ok("no-wait") => set_sigchld(ChildReaping::NoWait).unwrap(),
        Ok("ignored-here") => set_sigchld(ChildReaping::Ignored).unwrap(),
        _ => {}
    }
}

/// The M1 runner, with its children reaped on their own as
/// `ENVCLOAK_PTY_SPAWN_HOW` says ([`REAPING`]): reports its setup and
/// whether the kernel does reap on its own, runs `exit 7` through
/// `envcloak_exec::run` and reports the outcome and the setup after.
fn m1_run_with_sigchld_ignored() {
    set_up_reaping();
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

/// A run started with its children reaped on their own (each of
/// [`REAPING`]) would have its command reaped by the kernel as it exits
/// where the kernel does (measured and printed), the pid it signals and
/// waits for free for reuse, and its wait would fail. `envcloak_exec::run`
/// (and `start_pty`, through `spawn_session`) give SIGCHLD its default
/// back before the fork: the command's exit code comes back. Skip that and
/// the setup is still there after, and the run fails where the kernel
/// reaps on its own (on macOS: `no-wait` and `ignored-here`).
fn a_run_started_with_sigchld_ignored_still_waits_for_its_command() {
    for (how, setup) in REAPING {
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env(ROLE, "m1-run")
            .env(HOW, how)
            .stdin(Stdio::null());
        if how == "ignored-inherited" {
            envcloak_sys::testing::sigchld_ignored_on_spawn(&mut cmd);
        }
        let out = cmd.output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "{how}: {:?}\n{text}", out.status);
        assert!(
            text.contains(&format!("SETUP-AT-START {setup}")),
            "{how}: the stand-in did not start so (the setup failed):\n{text}"
        );
        assert!(text.contains("RUN code 7"), "{how}: {text}");
        assert!(
            text.contains("SETUP-AFTER (false, false)") && text.contains("REAPS-AFTER false"),
            "{how}: {text}"
        );
        println!(
            "pty_spawn ({}): SIGCHLD {how}: the kernel reaps children on its own: {}; the run \
             waited for its command",
            std::env::consts::OS,
            text.contains("REAPS-AT-START true")
        );
    }
}

/// The stand-in for the environment's order: its own environment holds
/// `ENVCLOAK_PTY_SPAWN_ORDERED=stale-value`; it starts the command (`pty_spawn
/// --env-of`) with the same name injected twice, `first-value` then
/// `last-value`, and prints what the command's terminal showed, read to
/// its end.
fn env_order_stand_in() {
    let exe = std::env::current_exe().unwrap();
    let pty = start_pty(
        &[exe.into_os_string(), OsString::from(ENV_OF)],
        &[
            (
                EnvName::new(ORDERED).unwrap(),
                SecretBytes::copy_from(b"first-value"),
            ),
            (
                EnvName::new(ORDERED).unwrap(),
                SecretBytes::copy_from(b"last-value"),
            ),
        ],
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
    let all = screen.read_to_end();
    std::io::stdout().write_all(&all).unwrap();
}

/// An injected name replaces an inherited one, and of two entries for a
/// name the last is the one the command gets, as `Command::env` has it:
/// the command's environment holds exactly one entry for the name, the
/// last injected value (read inside the command from its own `environ`,
/// duplicates kept). Keep the inherited entry, or let the first injected
/// entry win, and the command sees two entries or the wrong one (whose
/// `getenv` would return the first, the stale value).
fn an_injected_name_replaces_an_inherited_one_and_the_last_entry_wins() {
    let out = Command::new(std::env::current_exe().unwrap())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env(ROLE, "env-order")
        .env(ORDERED, "stale-value")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{:?}\n{text}", out.status);
    assert!(
        text.contains("ENV-DONE"),
        "the command did not report:\n{text}"
    );
    let entries: Vec<&str> = text
        .lines()
        .filter_map(|l| l.trim_end().strip_prefix("ENV-ENTRY "))
        .collect();
    assert_eq!(
        entries,
        vec!["last-value"],
        "the command's entries for the name"
    );
}
