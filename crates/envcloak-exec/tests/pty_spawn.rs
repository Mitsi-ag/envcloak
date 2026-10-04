//! PTY mode's start (M2 task M2-17): `envcloak_exec::start_pty` puts the
//! values in the command's environment and nowhere else (gate 14 for the
//! PTY path), the PTY monitor it forks keeps the CLI's hardening (R-M2-79:
//! core dumps off; on Linux non-dumpable, so its environment cannot be
//! read even by the same user, while the command's, after `exec`, can),
//! the form a real terminal writes a value holding LF in is the CR LF form
//! the redactor adds (the kernel's `ONLCR` as the independent oracle,
//! D-19), and failures before the start keep their exit codes.
//!
//! No libtest harness (`harness = false`): the command is this binary,
//! started as `pty_spawn --child`, so `ps` shows its environment on macOS
//! (it does not show a platform binary's), and nothing else runs in the
//! process that forks the monitor.
#![allow(clippy::unwrap_used)]

use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::process::Command;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use envcloak_core::SecretBytes;
use envcloak_exec::{ExecError, start_pty};
use envcloak_policy::EnvName;
use envcloak_redact::RedactorBuilder;
use envcloak_sys::pty::MonitorEvent;
use envcloak_testkit::{by_label, canaries, fresh_seed, labels};

#[global_allocator]
static ALLOCATOR: envcloak_sys::WipingAllocator = envcloak_sys::WipingAllocator;

const CHILD: &str = "--child";
const DEADLINE: Duration = Duration::from_secs(20);

fn main() {
    if std::env::args().nth(1).as_deref() == Some(CHILD) {
        return child();
    }
    let cases: [(&str, fn()); 3] = [
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
    ];
    // Name filters: words that are not options, nor the value of a libtest
    // option that takes one (`--test-threads 6`).
    let mut filter = Vec::new();
    let mut words = std::env::args().skip(1);
    while let Some(a) = words.next() {
        if [
            "--test-threads",
            "--skip",
            "--color",
            "--format",
            "--logfile",
            "-Z",
        ]
        .contains(&a.as_str())
        {
            words.next();
        } else if !a.starts_with('-') {
            filter.push(a);
        }
    }
    let mut failed = Vec::new();
    let mut ran = 0usize;
    for (name, case) in cases {
        if !filter.is_empty() && !filter.iter().any(|f| name.contains(f.as_str())) {
            continue;
        }
        ran += 1;
        match std::panic::catch_unwind(case) {
            Ok(()) => println!("pty_spawn: {name} ... ok"),
            Err(_) => {
                println!("pty_spawn: {name} ... FAILED");
                failed.push(name);
            }
        }
    }
    println!("pty_spawn: {ran} case(s) run, {} failed", failed.len());
    if !failed.is_empty() {
        println!("pty_spawn: failed: {failed:?}");
        std::process::exit(101);
    }
}

/// The command: reports its pid, then waits for a line.
fn child() {
    let mut out = std::io::stdout().lock();
    writeln!(out, "READY {}", std::process::id()).unwrap();
    out.flush().unwrap();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).unwrap();
}

/// Everything the PTY's master side shows, read on a thread so each wait
/// is bounded; the thread ends when the terminal does (EOF or EIO).
struct Screen {
    seen: Vec<u8>,
    chunks: mpsc::Receiver<Vec<u8>>,
    writer: std::fs::File,
}

impl Screen {
    fn new(master: OwnedFd) -> Self {
        let writer = std::fs::File::from(master.try_clone().unwrap());
        let mut reader = std::fs::File::from(master);
        let (tx, chunks) = mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = reader.read(&mut buf) {
                if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                    return;
                }
            }
        });
        Screen {
            seen: Vec::new(),
            chunks,
            writer,
        }
    }

    /// Reads until `done` holds or the terminal ends, up to [`DEADLINE`].
    fn wait_for(&mut self, done: impl Fn(&[u8]) -> bool) -> bool {
        let end = Instant::now() + DEADLINE;
        while !done(&self.seen) {
            let left = end.saturating_duration_since(Instant::now());
            match self.chunks.recv_timeout(left) {
                Ok(chunk) => self.seen.extend_from_slice(&chunk),
                Err(_) => return false,
            }
        }
        true
    }

    fn type_line(&mut self) {
        self.writer.write_all(b"\n").unwrap();
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

/// Gate 14 for the PTY path, and R-M2-79 for the monitor. The command's
/// environment holds the value, readable by this sibling-of-sorts process
/// of the same user (SPEC §1.1), its command line does not, nor does this
/// process's own environment or anything the terminal showed. With this
/// process hardened as the CLI is, the monitor's core dumps are off and,
/// on Linux, its environment cannot be read at all; the command's can,
/// which is the positive control for that refusal.
fn values_live_in_the_commands_environment_only() {
    let hardening = envcloak_sys::harden_process();
    assert!(hardening.core_dumps_off, "{hardening:?}");
    if cfg!(target_os = "linux") {
        assert!(hardening.non_dumpable, "{hardening:?}");
    }
    let cs = canaries(fresh_seed());
    let value = by_label(&cs, labels::OPENAI_API_KEY).value();
    let exe = std::env::current_exe().unwrap();
    let pty = start_pty(
        &[exe.into_os_string(), OsString::from(CHILD)],
        &[(
            EnvName::new("OPENAI_API_KEY").unwrap(),
            SecretBytes::copy_from(value),
        )],
        None,
        None,
    )
    .unwrap();
    let mut monitor = pty.monitor;
    let mut screen = Screen::new(pty.master);
    let ready = format!("READY {}", monitor.command_id());
    assert!(
        screen.wait_for(|s| holds(s, ready.as_bytes())),
        "the command did not report: {}",
        String::from_utf8_lossy(&screen.seen)
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
    assert!(!own, "the value is in this process's environment");

    // The monitor: forked from this hardened process, never exec'd.
    let monitor_pid = monitor.monitor_id();
    if cfg!(target_os = "linux") {
        let refused = std::fs::read(format!("/proc/{monitor_pid}/environ")).unwrap_err();
        assert_eq!(
            refused.kind(),
            std::io::ErrorKind::PermissionDenied,
            "the monitor is dumpable: {refused}"
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
    assert!(
        !holds(&screen.seen, value),
        "the value reached the terminal"
    );
    println!(
        "gate 14 PTY ({}): a process of the same user read the command's environment (the \
         value present), not its argv, and{} the monitor's",
        std::env::consts::OS,
        if cfg!(target_os = "linux") {
            " not"
        } else {
            " (no check of)"
        }
    );
}

/// The command prints a multi-line value through its terminal; the master
/// shows it with every LF as CR LF (the kernel's line discipline, an
/// independent oracle), which is exactly the form `crlf_variants` adds:
/// redacted whole with it, passed through without it.
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
    let mut screen = Screen::new(pty.master);
    let event = monitor.next_event(Some(DEADLINE)).unwrap();
    assert!(
        matches!(event, Some(MonitorEvent::Exited(s)) if s.success()),
        "{event:?}"
    );
    monitor.finish().unwrap();
    // The terminal ends once nothing holds its slave side.
    screen.wait_for(|_| false);
    let mut expected = key.to_vec();
    expected.extend_from_slice(b"\r\n");
    expected.extend_from_slice(stripe);
    expected.extend_from_slice(b"\r\n");
    assert_eq!(screen.seen, expected, "the terminal's form");
    let with = RedactorBuilder::new()
        .crlf_variants(true)
        .secret("multi/line", &value)
        .build()
        .0;
    assert_eq!(with.redact(&screen.seen), b"[envcloak:multi/line]");
    let without = RedactorBuilder::new()
        .secret("multi/line", &value)
        .build()
        .0;
    assert_eq!(
        without.redact(&screen.seen),
        screen.seen,
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
