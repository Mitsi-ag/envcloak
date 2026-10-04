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
    MonitorCommand, MonitorEvent, RouteReason, SignalRoute, forward_signal, signal_foreground_job,
    signal_route, spawn_session,
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
        Some("family") => return family(),
        Some("member") => return member(),
        Some(other) => panic!("unknown role {other}"),
        None => {}
    }
    run_cases(
        "pty_signals",
        &[
            (
                "forwarded_signals_reach_the_nested_shells_job_and_not_the_shell",
                forwarded_signals_reach_the_nested_shells_job_and_not_the_shell,
            ),
            (
                "a_process_that_leaves_the_job_before_the_delivery_gets_nothing",
                a_process_that_leaves_the_job_before_the_delivery_gets_nothing,
            ),
            (
                "signals_to_a_stopped_command_wait_for_it_and_the_monitor_passes_them_on",
                signals_to_a_stopped_command_wait_for_it_and_the_monitor_passes_them_on,
            ),
            (
                "a_job_whose_group_leader_is_gone_is_narrowed_on_linux",
                a_job_whose_group_leader_is_gone_is_narrowed_on_linux,
            ),
        ],
    );
}

/// The kernel's release (`uname -r`) on Linux, for the measurement's
/// line; empty elsewhere.
fn kernel_release() -> String {
    if !cfg!(target_os = "linux") {
        return String::new();
    }
    // SAFETY: utsname is plain data; uname fills it in.
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: `u` is writable.
    if unsafe { libc::uname(&mut u) } != 0 {
        return String::new();
    }
    // SAFETY: uname wrote a NUL-terminated release into the array.
    let release = unsafe { std::ffi::CStr::from_ptr(u.release.as_ptr()) };
    format!(" {}", release.to_string_lossy())
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
        assert_eq!(forwarded.reason, RouteReason::Measured, "{name}");
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
    #[cfg(target_os = "linux")]
    assert!(
        group_signal_supported(),
        "this kernel ({}) cannot signal a process group through a pidfd \
         (PIDFD_SIGNAL_PROCESS_GROUP, Linux 6.9): SIGTERM and SIGHUP are narrowed to the \
         command's group on it, which this measurement does not cover",
        kernel_release()
    );
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
                    let job = monitor
                        .session()
                        .unwrap()
                        .foreground_job(screen.master())
                        .unwrap();
                    assert_eq!(
                        i32::try_from(job.group_id()).unwrap(),
                        job_group,
                        "SIG{name}: the bound job is the job"
                    );
                    job.signal(sig).unwrap();
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
        "pty_signals ({}{}): measured routes {:?}; TIOCSIG flushed unread input: {flushed}",
        std::env::consts::OS,
        kernel_release(),
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

/// What a member of the family does: `stay` in the leader's group, leave
/// the session with `setsid`, or move to a group of its own in the session
/// with `setpgid(0, 0)`.
const KIND: &str = "ENVCLOAK_PTY_KIND";
const KINDS: [&str; 3] = ["stay", "setsid", "setpgid"];

/// Counts each of the four signals into `<dir>/<who>-<SIG>` on a thread of
/// its own.
fn count_signals(dir: std::path::PathBuf, who: String) {
    let relay = SignalRelay::install(&SIGNALS.map(|(s, _)| s)).unwrap();
    std::thread::spawn(move || {
        while let Ok(Some(caught)) = relay.next() {
            if let Relayed::Signal { number, .. } = caught {
                let name = SIGNALS.iter().find(|(s, _)| *s == number).unwrap().1;
                let mut f = std::fs::OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(dir.join(format!("{who}-{name}")))
                    .unwrap();
                std::io::Write::write_all(&mut f, b"x\n").unwrap();
            }
        }
    });
}

/// Waits until `path` exists (a barrier the test or another fixture
/// sets), up to the deadline.
fn wait_for_file(path: &Path) -> bool {
    let end = std::time::Instant::now() + DEADLINE;
    while !path.exists() {
        if std::time::Instant::now() >= end {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    true
}

/// A self-raised SIGTERM, counted: each process's positive control that
/// its counters work.
fn raise_term() {
    // SAFETY: SIGTERM to this process itself, which counts it.
    unsafe { libc::kill(libc::getpid(), libc::SIGTERM) };
}

/// The family's leader, the command: leads the terminal's foreground
/// group, starts one member of each kind in it, counts its own signals,
/// and prints `FAMILY-READY` once every member counted its control. On
/// `done` typed it tells the members to end, waits for them, and exits.
fn family() {
    let dir = std::path::PathBuf::from(std::env::var_os(DIR).unwrap());
    count_signals(dir.clone(), "leader".to_owned());
    raise_term();
    let exe = std::env::current_exe().unwrap();
    let mut members: Vec<std::process::Child> = KINDS
        .iter()
        .map(|kind| {
            std::process::Command::new(&exe)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env(ROLE, "member")
                .env(DIR, &dir)
                .env(KIND, kind)
                .stdin(std::process::Stdio::null())
                .spawn()
                .unwrap()
        })
        .collect();
    for who in ["leader", "stay", "setsid", "setpgid"] {
        assert!(
            wait_lines(&dir.join(format!("{who}-TERM")), 1, DEADLINE),
            "{who} never counted its control"
        );
    }
    let stdout = std::io::stdout();
    put(stdout.as_fd(), b"FAMILY-READY\n");
    for line in std::io::stdin().lock().lines() {
        if line.unwrap() == "done" {
            break;
        }
    }
    std::fs::write(dir.join("done"), b"").unwrap();
    for m in &mut members {
        m.wait().unwrap();
    }
}

/// A member: counts its signals, raises its control, and when the test
/// says `leave` does what its kind says and reports it, then waits for
/// `done`.
fn member() {
    let dir = std::path::PathBuf::from(std::env::var_os(DIR).unwrap());
    let kind = std::env::var(KIND).unwrap();
    count_signals(dir.clone(), kind.clone());
    raise_term();
    assert!(wait_for_file(&dir.join("leave")), "{kind}: no leave");
    // SAFETY: setsid and setpgid change only this process's own session
    // or group.
    let rc = unsafe {
        match kind.as_str() {
            "setsid" => libc::setsid(),
            "setpgid" => libc::setpgid(0, 0),
            _ => 0,
        }
    };
    assert!(rc >= 0, "{kind}: {}", std::io::Error::last_os_error());
    std::fs::write(dir.join(format!("{kind}-left")), b"").unwrap();
    assert!(wait_for_file(&dir.join("done")), "{kind}: no done");
}

/// The job is the family: a leader and three members in its group (Codex's
/// review of PR #27: membership can change before a signal is delivered).
/// On Linux the job is bound first (`OwnedSession::foreground_job`); then
/// one member leaves the session with `setsid` and one moves to a group of
/// its own, and only then is the signal sent, through the bound job: the
/// leader and the member that stayed get it, the two that left nothing.
/// The same holds for each of the four signals through `forward_signal` on
/// both systems. Every process raised one SIGTERM at its start and counted
/// it, so the counters of the two that left can count (a positive
/// control). Bind each member with a pidfd of its own and signal them
/// after (the design before this one) and the two that left are signalled.
fn a_process_that_leaves_the_job_before_the_delivery_gets_nothing() {
    let dir = short_dir();
    let d = dir.path();
    let exe = std::env::current_exe().unwrap();
    let pty = envcloak_sys::pty::open_pty(None, None).unwrap();
    let mut monitor = spawn_session(
        &[exe.as_os_str()],
        &[
            (OsStr::new("PATH"), OsStr::new("/usr/bin:/bin")),
            (OsStr::new(ROLE), OsStr::new("family")),
            (OsStr::new(DIR), d.as_os_str()),
        ],
        pty.slave,
    )
    .unwrap();
    let mut screen = Screen::new(pty.master);
    screen.expect("FAMILY-READY", 1, "the family started");
    #[cfg(target_os = "linux")]
    let job = monitor
        .session()
        .unwrap()
        .foreground_job(screen.master())
        .unwrap();
    #[cfg(target_os = "linux")]
    assert_eq!(
        job.group_id(),
        monitor.command_id(),
        "the job is the family"
    );
    std::fs::write(d.join("leave"), b"").unwrap();
    for kind in ["setsid", "setpgid"] {
        assert!(wait_for_file(&d.join(format!("{kind}-left"))), "{kind}");
    }
    // Each delivery is waited for before the next: a signal sent while the
    // same one is still pending is merged with it.
    let both_count = |name: &str, n: usize| {
        for who in ["leader", "stay"] {
            assert!(
                wait_lines(&d.join(format!("{who}-{name}")), n, DEADLINE),
                "{who} SIG{name}: {:?}",
                counts(d, who)
            );
        }
    };
    // Each process's control, on Linux the bound job's, and one forwarded.
    let term = if cfg!(target_os = "linux") { 2 } else { 1 };
    #[cfg(target_os = "linux")]
    {
        job.signal(libc::SIGTERM).unwrap();
        both_count("TERM", term);
    }
    for (sig, name) in SIGNALS {
        let forwarded = forward_signal(&monitor, screen.master(), sig).unwrap();
        assert_eq!(Some(forwarded.route), signal_route(sig), "SIG{name}");
        assert_eq!(forwarded.reason, RouteReason::Measured, "SIG{name}");
        both_count(name, if sig == libc::SIGTERM { term + 1 } else { 1 });
    }
    for who in ["leader", "stay"] {
        assert_eq!(counts(d, who), vec![1, 1, term + 1, 1], "{who}");
    }
    // The ones that left: their own control only. Every delivery to the
    // job has been counted by the two that stayed by now.
    for who in ["setsid", "setpgid"] {
        assert_eq!(counts(d, who), vec![0, 0, 1, 0], "{who} got a signal");
    }
    screen.type_bytes(b"done\n");
    let event = screen.next_event(&mut monitor);
    assert!(
        matches!(event, Some(MonitorEvent::Exited(s)) if s.success()),
        "{event:?}\n{}",
        screen.text()
    );
    for who in ["setsid", "setpgid"] {
        assert_eq!(counts(d, who), vec![0, 0, 1, 0], "{who} got a signal");
    }
    monitor.finish().unwrap();
    println!(
        "pty_signals ({}{}): two members that left the job (setsid, setpgid) before the \
         delivery got nothing; the leader and the member that stayed got each signal",
        std::env::consts::OS,
        kernel_release()
    );
}

/// The command stops (the suspend character): the monitor holds the
/// terminal. Each of the four forwarded then goes to the command's own
/// group through the monitor (`CommandStopped`), and waits there: the
/// command counts each once after `Resume`. Stopped again, each of the
/// four is sent to the monitor itself, as a `TIOCSIG` racing the stop
/// would (by `TIOCSIG` where the kernel takes it; otherwise, Linux SIGTERM
/// and SIGHUP, to the monitor as this process's own unreaped child): the
/// monitor lives on, passes each on to the command, which counts each
/// again after `Resume`, and still reports the command's exit. Leave
/// SIGTERM at its default in the monitor and it dies; ignore the four
/// there (the monitor before) and the command's counts stay at one; skip
/// the check of the foreground in `forward_signal` and the first four are
/// sent to the monitor's group (macOS: the route is wrong; Linux: an
/// error).
fn signals_to_a_stopped_command_wait_for_it_and_the_monitor_passes_them_on() {
    let dir = short_dir();
    let d = dir.path();
    let exe = std::env::current_exe().unwrap();
    let pty = envcloak_sys::pty::open_pty(None, None).unwrap();
    let suspend = envcloak_sys::TerminalSettings::read(pty.slave.as_fd())
        .unwrap()
        .suspend_char()
        .unwrap();
    let mut monitor = spawn_session(
        &[exe.as_os_str()],
        &[
            (OsStr::new("PATH"), OsStr::new("/usr/bin:/bin")),
            (OsStr::new(ROLE), OsStr::new("counter")),
            (OsStr::new(DIR), d.as_os_str()),
        ],
        pty.slave,
    )
    .unwrap();
    let mut screen = Screen::new(pty.master);
    screen.expect("JOB-READY", 1, "the command started");
    let stop = |screen: &mut Screen, monitor: &mut envcloak_sys::pty::SessionMonitor| {
        screen.type_bytes(&[suspend]);
        assert_eq!(
            screen.next_event(monitor),
            Some(MonitorEvent::Stopped(libc::SIGTSTP)),
            "the suspend character did not stop the command"
        );
    };
    let resume = |screen: &mut Screen, monitor: &mut envcloak_sys::pty::SessionMonitor| {
        monitor.send(MonitorCommand::Resume).unwrap();
        assert_eq!(screen.next_event(monitor), Some(MonitorEvent::Continued));
    };
    let wait_counts = |n: usize| {
        for (_, name) in SIGNALS {
            assert!(
                wait_lines(&d.join(format!("job-{name}")), n, DEADLINE),
                "SIG{name}: the command counted {:?}",
                counts(d, "job")
            );
        }
        assert_eq!(counts(d, "job"), vec![n; 4]);
    };

    stop(&mut screen, &mut monitor);
    for (sig, name) in SIGNALS {
        let forwarded = forward_signal(&monitor, screen.master(), sig).unwrap();
        assert_eq!(
            (forwarded.route, forwarded.reason),
            (SignalRoute::CommandGroup, RouteReason::CommandStopped),
            "SIG{name} while the command is stopped"
        );
    }
    assert_eq!(
        counts(d, "job"),
        vec![0; 4],
        "a stopped command counts nothing"
    );
    resume(&mut screen, &mut monitor);
    wait_counts(1);

    stop(&mut screen, &mut monitor);
    let monitor_pid = i32::try_from(monitor.monitor_id()).unwrap();
    let mut how = Vec::new();
    for (sig, name) in SIGNALS {
        match signal_foreground_job(screen.master(), sig) {
            Ok(()) => how.push(format!("SIG{name} TIOCSIG")),
            Err(e) => {
                assert_eq!(e.raw_os_error(), Some(libc::EINVAL), "SIG{name}: {e}");
                // SAFETY: the monitor is this process's own, unreaped child
                // (the session monitor's handle holds it).
                assert_eq!(unsafe { libc::kill(monitor_pid, sig) }, 0);
                how.push(format!("SIG{name} to the monitor"));
            }
        }
        assert_eq!(
            monitor
                .next_event(Some(std::time::Duration::from_millis(100)))
                .unwrap(),
            None,
            "SIG{name}: the monitor reported something or ended"
        );
    }
    resume(&mut screen, &mut monitor);
    wait_counts(2);
    screen.type_bytes(b"done\n");
    let event = screen.next_event(&mut monitor);
    assert!(
        matches!(event, Some(MonitorEvent::Exited(s)) if s.success()),
        "the monitor no longer reports: {event:?}\n{}",
        screen.text()
    );
    assert_eq!(counts(d, "job"), vec![2; 4]);
    monitor.finish().unwrap();
    println!(
        "pty_signals ({}): with the command stopped, forwarded signals went to its group \
         through the monitor and waited; sent to the monitor ({}), each was passed on",
        std::env::consts::OS,
        how.join(", ")
    );
}

/// Whether this kernel signals a process group through a pidfd
/// (`PIDFD_SIGNAL_PROCESS_GROUP`, Linux 6.9): a signal 0 sent so through a
/// pidfd on this process is refused with `EINVAL` only where it cannot.
#[cfg(target_os = "linux")]
fn group_signal_supported() -> bool {
    // SAFETY: pidfd_open on this process itself; the descriptor is closed
    // below.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) };
    assert!(fd >= 0, "pidfd_open: {}", std::io::Error::last_os_error());
    let fd = libc::c_int::try_from(fd).unwrap();
    // SAFETY: signal 0 checks and sends nothing; flag 4 is
    // PIDFD_SIGNAL_PROCESS_GROUP.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd,
            0,
            std::ptr::null::<libc::siginfo_t>(),
            4u32,
        )
    };
    let refused = rc != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL);
    // SAFETY: closes the descriptor opened above.
    unsafe { libc::close(fd) };
    !refused
}

/// A job whose group leader is gone: a nested shell runs `true | counter`
/// (the counter reading the terminal), a pipeline whose group `true`
/// leads, and `true` exits at once and is
/// reaped by the shell, leaving the counter alone in a group no process
/// has the number of. On Linux nothing holds that group's identity to
/// signal it through (`OwnedSession` reports `NoLeader`), so SIGTERM and
/// SIGHUP are narrowed to the command's own group, the shell's: the shell
/// counts each, the job nothing, and `forward_signal` says `Narrowed`. On
/// macOS `TIOCSIG` reaches the job's group as it is. SIGINT reaches the
/// job through `TIOCSIG` on both, a control. Signal the group by its
/// number instead of narrowing and the job counts on Linux; report the
/// failure instead of narrowing and the forward is an error.
fn a_job_whose_group_leader_is_gone_is_narrowed_on_linux() {
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
            "true | {ROLE}=counter {DIR}='{}' '{}' < /dev/tty\n",
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
    assert_ne!(
        job, job_group,
        "the counter does not lead the pipeline's group"
    );
    // The group's leader, `true`, gone and reaped: no process has the
    // group's number (read from /proc; nothing is signalled by it).
    if cfg!(target_os = "linux") {
        let end = std::time::Instant::now() + DEADLINE;
        while Path::new(&format!("/proc/{job_group}")).exists() {
            assert!(
                std::time::Instant::now() < end,
                "the pipeline's leader was never reaped"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
    let mut seen = Vec::new();
    for (sig, name) in SIGNALS {
        let forwarded = forward_signal(&monitor, screen.master(), sig).unwrap();
        let narrowed = cfg!(target_os = "linux") && signal_route(sig) == Some(SignalRoute::Session);
        if narrowed {
            // The shell counts it once the job has ended (below).
            assert_eq!(
                (forwarded.route, forwarded.reason),
                (SignalRoute::CommandGroup, RouteReason::Narrowed),
                "SIG{name}"
            );
        } else {
            assert_eq!(
                (Some(forwarded.route), forwarded.reason),
                (signal_route(sig), RouteReason::Measured),
                "SIG{name}"
            );
            let mut fg: libc::pid_t = 0;
            // SAFETY: TIOCGPGRP writes one pid_t; read only for the message.
            unsafe { libc::ioctl(screen.master().as_raw_fd(), libc::TIOCGPGRP as _, &mut fg) };
            assert!(
                wait_lines(&d.join(format!("job-{name}")), 1, DEADLINE),
                "SIG{name} did not reach the job (job {job} group {job_group}, foreground {fg}): {}",
                screen.text()
            );
        }
        seen.push(format!(
            "SIG{name} {:?} {:?}",
            forwarded.route, forwarded.reason
        ));
    }
    screen.type_bytes(b"done\n");
    screen.expect(PROMPT, 3, "the job ended");
    // The shell runs a pending trap once it has read and run a command:
    // `:` is typed until the narrowed signals have been counted.
    if cfg!(target_os = "linux") {
        let end = std::time::Instant::now() + DEADLINE;
        while counts(d, "shell")[2..] != [1, 1] {
            assert!(
                std::time::Instant::now() < end,
                "the shell did not count the narrowed signals: {:?}",
                counts(d, "shell")
            );
            let prompts = screen.count(PROMPT);
            screen.type_bytes(b":\n");
            screen.expect(PROMPT, prompts + 1, "the shell ran a command");
        }
    }
    let (job_counts, shell_counts) = (counts(d, "job"), counts(d, "shell"));
    if cfg!(target_os = "linux") {
        assert_eq!(job_counts, vec![1, 1, 0, 0], "the job");
        assert_eq!(shell_counts, vec![0, 0, 1, 1], "the shell");
    } else {
        assert_eq!(job_counts, vec![1; 4], "the job");
        assert_eq!(shell_counts, vec![0; 4], "the shell");
    }
    screen.type_bytes(b"exit\n");
    let event = screen.next_event(&mut monitor);
    assert!(
        matches!(event, Some(MonitorEvent::Exited(_))),
        "{event:?}\n{}",
        screen.text()
    );
    drop(screen);
    monitor.finish().unwrap();
    println!(
        "pty_signals ({}{}): a job whose group leader was reaped: {}",
        std::env::consts::OS,
        kernel_release(),
        seen.join(", ")
    );
}
