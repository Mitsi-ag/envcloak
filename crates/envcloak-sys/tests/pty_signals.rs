//! Forwarded signals reach the PTY's actual foreground job (M2 plan D-35,
//! task M2-17's spike (d); review CR-4), on a real pseudo-terminal.
//!
//! The command is a nested job-control shell (`/bin/sh -i` with `set -m`,
//! cleared environment) under the PTY monitor, and the shell runs a
//! counting fixture (a copy of this binary) as a job in its own foreground
//! process group. Both count every SIGINT, SIGQUIT, SIGTERM and SIGHUP
//! they receive, on separate counter files per process and per signal (the
//! shell through `trap`, the job through `SignalRelay`).
//!
//! 1. Each of the four goes through `pty::forward_signal`, the route
//!    `envcloak run --pty` takes: the job counts 1 and the shell 0.
//! 2. The measurement the route table rests on, kept as a test: for each
//!    signal, whether `TIOCSIG` on the master reaches the job, and where
//!    the kernel refuses it (Linux: `EINVAL` for SIGTERM and SIGHUP),
//!    whether the monitor's session-scoped delivery (`OwnedSession`, Linux)
//!    does; the measured route must be [`signal_route`]'s. Whether
//!    `TIOCSIG` flushes input typed and not yet read is recorded too
//!    (macOS: it does, `NOFLSH` being unset).
//! 3. A positive control for the shell's counters: each signal sent to
//!    the command's own group (the monitor's `Signal(n)`, the route a
//!    narrowed signal would take) reaches the shell, which counts it, and
//!    not the job.
//!
//! The final counts are exact: the job 2 for each signal, the shell 1.
//! Forwarding through the monitor's own child group (the shell's) would
//! leave the job at 0 in step 1.
//!
//! No libtest harness (`harness = false`): a copy of this binary is the
//! counting fixture, and nothing else runs in the process that forks the
//! monitor.
#![allow(unsafe_code, clippy::unwrap_used)]

mod pty_common;

use std::ffi::OsStr;
use std::io::BufRead;
use std::os::fd::{AsFd, AsRawFd};
use std::path::Path;

use envcloak_sys::pty::{
    MonitorCommand, MonitorEvent, SignalRoute, forward_signal, signal_foreground_job, signal_route,
    spawn_session,
};
use envcloak_sys::{Relayed, SignalRelay};
use pty_common::{
    DEADLINE, DIR, OwnPidOnly, ROLE, Screen, lines, my_role, own_allocations, put, run_cases,
    short_dir, wait_lines,
};

#[global_allocator]
static ALLOCATOR: OwnPidOnly = OwnPidOnly;

const SIGNALS: [(i32, &str); 4] = [
    (libc::SIGINT, "INT"),
    (libc::SIGQUIT, "QUIT"),
    (libc::SIGTERM, "TERM"),
    (libc::SIGHUP, "HUP"),
];

const PROMPT: &str = "EC-PROMPT> ";

fn main() {
    own_allocations();
    match my_role().as_deref() {
        Some("counter") => return counter(),
        Some(other) => panic!("unknown role {other}"),
        None => {}
    }
    run_cases(
        "pty_signals",
        &[(
            "forwarded_signals_reach_the_nested_shells_job_and_not_the_shell",
            forwarded_signals_reach_the_nested_shells_job_and_not_the_shell,
        )],
    );
}

/// The counting fixture: appends a line to `<dir>/job-<SIG>` for each of
/// the four signals it receives; prints `JOB-READY <pid> <pgid>`, then
/// `GOT [<line>]` for each line it reads, and exits on `done`.
fn counter() {
    let dir = std::path::PathBuf::from(std::env::var_os(DIR).unwrap());
    let relay = SignalRelay::install(&SIGNALS.map(|(s, _)| s)).unwrap();
    std::thread::spawn(move || {
        while let Ok(Some(caught)) = relay.next() {
            if let Relayed::Signal { number, .. } = caught {
                let name = SIGNALS.iter().find(|(s, _)| *s == number).unwrap().1;
                let mut f = std::fs::OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(dir.join(format!("job-{name}")))
                    .unwrap();
                std::io::Write::write_all(&mut f, b"x\n").unwrap();
            }
        }
    });
    // SAFETY: plain queries of this process's own state.
    let (pid, pgrp) = unsafe { (libc::getpid(), libc::getpgrp()) };
    let stdout = std::io::stdout();
    put(
        stdout.as_fd(),
        format!("JOB-READY {pid} {pgrp}\n").as_bytes(),
    );
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap();
        if line == "done" {
            std::process::exit(0);
        }
        put(stdout.as_fd(), format!("GOT [{line}]\n").as_bytes());
    }
}

fn counts(dir: &Path, who: &str) -> Vec<usize> {
    SIGNALS
        .iter()
        .map(|(_, name)| lines(&dir.join(format!("{who}-{name}"))))
        .collect()
}

fn forwarded_signals_reach_the_nested_shells_job_and_not_the_shell() {
    let dir = short_dir();
    let d = dir.path();
    let home = d.join("home");
    std::fs::create_dir(&home).unwrap();
    let pty = envcloak_sys::pty::open_pty(None, None).unwrap();
    let mut monitor = spawn_session(
        &[OsStr::new("/bin/sh"), OsStr::new("-i")],
        &[
            (OsStr::new("PATH"), OsStr::new("/usr/bin:/bin")),
            (OsStr::new("HOME"), home.as_os_str()),
            (OsStr::new("PS1"), OsStr::new(PROMPT)),
            (OsStr::new("TERM"), OsStr::new("dumb")),
            (OsStr::new("LC_ALL"), OsStr::new("C")),
        ],
        pty.slave,
    )
    .unwrap();
    let mut screen = Screen::new(pty.master);
    screen.expect(PROMPT, 1, "the nested shell's prompt");
    let traps: String = SIGNALS
        .iter()
        .map(|(_, name)| format!("trap 'echo x >> {}/shell-{name}' {name}; ", d.display()))
        .collect();
    screen.type_bytes(format!("{traps}set -m\n").as_bytes());
    screen.expect(PROMPT, 2, "the shell set its traps");
    let exe = std::env::current_exe().unwrap();
    screen.type_bytes(
        format!(
            "{ROLE}=counter {DIR}='{}' '{}'\n",
            d.display(),
            exe.display()
        )
        .as_bytes(),
    );
    screen.expect("JOB-READY", 1, "the job started");
    let ready = screen.text();
    let fields: Vec<i32> = ready[ready.find("JOB-READY").unwrap()..]
        .split_whitespace()
        .skip(1)
        .take(2)
        .map(|w| w.parse().unwrap())
        .collect();
    let (job, job_group) = (fields[0], fields[1]);
    assert_eq!(job, job_group, "the job leads its own group");
    assert_ne!(
        u32::try_from(job_group).unwrap(),
        monitor.command_id(),
        "the job's group is not the shell's"
    );
    let mut fg: libc::pid_t = 0;
    // SAFETY: TIOCGPGRP writes one pid_t; read here only to check the
    // setup, never to signal.
    unsafe { libc::ioctl(screen.master().as_raw_fd(), libc::TIOCGPGRP as _, &mut fg) };
    assert_eq!(fg, job_group, "the job is the terminal's foreground group");

    // 1. The route `envcloak run --pty` takes.
    for (i, (sig, name)) in SIGNALS.iter().enumerate() {
        let forwarded = forward_signal(&monitor, screen.master(), *sig).unwrap();
        assert_eq!(Some(forwarded.route), signal_route(*sig), "{name}");
        assert!(
            wait_lines(&d.join(format!("job-{name}")), 1, DEADLINE),
            "SIG{name} forwarded by {:?} did not reach the job; job {:?}, shell {:?}",
            forwarded.route,
            counts(d, "job"),
            counts(d, "shell")
        );
        let mut expected = vec![0; 4];
        for e in expected.iter_mut().take(i + 1) {
            *e = 1;
        }
        assert_eq!(counts(d, "job"), expected, "after SIG{name}");
    }

    // 2. The measurement behind the route table.
    let mut table = Vec::new();
    for (sig, name) in SIGNALS {
        let file = d.join(format!("job-{name}"));
        let before = lines(&file);
        let flush = (sig == libc::SIGINT).then(|| {
            // Typed, not yet a line: does TIOCSIG discard it?
            screen.type_bytes(b"pending");
        });
        let measured = match signal_foreground_job(screen.master(), sig) {
            Ok(()) => {
                assert!(
                    wait_lines(&file, before + 1, DEADLINE),
                    "TIOCSIG took SIG{name} but the job did not count it"
                );
                SignalRoute::Tiocsig
            }
            Err(e) => {
                assert_eq!(e.raw_os_error(), Some(libc::EINVAL), "SIG{name}: {e}");
                #[cfg(target_os = "linux")]
                {
                    let n = monitor
                        .session()
                        .unwrap()
                        .signal_foreground(screen.master(), sig)
                        .unwrap();
                    assert_eq!(n, 1, "SIG{name}: the job is one process");
                    assert!(
                        wait_lines(&file, before + 1, DEADLINE),
                        "the session delivery took SIG{name} but the job did not count it"
                    );
                    SignalRoute::Session
                }
                #[cfg(not(target_os = "linux"))]
                SignalRoute::CommandGroup
            }
        };
        let flushed = flush.map(|()| {
            screen.type_bytes(b"\n");
            screen.expect("GOT [", 1, "the job read the line");
            screen.count("GOT [pending]") == 0
        });
        table.push((name, measured, flushed));
        assert_eq!(
            Some(measured),
            signal_route(sig),
            "SIG{name} measured by the spike is not pty::signal_route's"
        );
    }
    let flushed = table.iter().find_map(|(_, _, f)| *f).unwrap();
    // macOS flushes the terminal's queues with TIOCSIG unless NOFLSH is
    // set; Linux's pty_signal does not.
    assert_eq!(flushed, cfg!(target_os = "macos"), "{table:?}");
    println!(
        "pty_signals ({}): measured routes {:?}; TIOCSIG flushed unread input: {flushed}",
        std::env::consts::OS,
        table
            .iter()
            .map(|(n, r, _)| format!("SIG{n} {r:?}"))
            .collect::<Vec<_>>()
    );

    // 3. The positive control: the command's own group is the shell's.
    // The job ends first. At its prompt the shell runs a pending trap once
    // it has read and run the next command (`:`), before its next prompt.
    // The monitor sends the signal on its own time after `send` returns,
    // so the command is typed again until the trap has run.
    let prompts = screen.count(PROMPT);
    screen.type_bytes(b"done\n");
    screen.expect(PROMPT, prompts + 1, "the job ended");
    for (sig, name) in SIGNALS {
        monitor.send(MonitorCommand::Signal(sig)).unwrap();
        let file = d.join(format!("shell-{name}"));
        let end = std::time::Instant::now() + DEADLINE;
        while lines(&file) == 0 {
            assert!(
                std::time::Instant::now() < end,
                "the shell did not count SIG{name} sent to its group; shell {:?}, job {:?}; \
                 the terminal showed:\n{}",
                counts(d, "shell"),
                counts(d, "job"),
                screen.text()
            );
            let prompts = screen.count(PROMPT);
            screen.type_bytes(b":\n");
            screen.expect(PROMPT, prompts + 1, "the shell ran a command");
        }
    }
    screen.type_bytes(b"exit\n");
    let event = screen.next_event(&mut monitor);
    assert!(
        matches!(event, Some(MonitorEvent::Exited(_))),
        "{event:?}\n{}",
        screen.text()
    );
    assert_eq!(
        counts(d, "job"),
        vec![2; 4],
        "the job: forwarded and measured"
    );
    assert_eq!(
        counts(d, "shell"),
        vec![1; 4],
        "the shell: the control only"
    );
    drop(screen);
    monitor.finish().unwrap();
}
