//! The PTY suspension topology (M2 plan D-35, task M2-17's spike; review
//! F-76), on a real pseudo-terminal of the test's own:
//!
//! - (a) the counterexample, kept as a permanent test: a command that
//!   leads its own new session, with its parent outside it, receives the
//!   typed suspend character and does not stop (an orphaned process group
//!   ignores SIGTSTP), while SIGSTOP, SIGCONT and a typed interrupt behave
//!   normally. This is why the command never leads the session;
//! - (b) the monitor's topology, on both systems, with two cats: the
//!   suspend character stops cat and the monitor reports it, `Resume`
//!   gives the terminal back and continues it. GNU cat reads on; BSD cat
//!   may read on or exit with EINTR depending on when the stop arrived.
//!   Both BSD outcomes are accepted independently under each topology.
//!   A cat that reads again on `EINTR`
//!   (this binary's `cat` role, with the default dispositions, so the
//!   suspend character stops it) must make the round trip on each system.
//!   This runs under an allocator that aborts in any process but the
//!   test's own, so the monitor (and the command between `fork` and
//!   `exec`) is shown not to allocate;
//! - (c) the outer-shell gate in its minimal form, with the same two cats
//!   on both systems: a job-control shell (`/bin/sh -i`, `set -m`, cleared
//!   environment, no rc files) on a private outer PTY starts a driver
//!   that relays to cat under the monitor as `envcloak run --pty` will;
//!   the suspend character gives the shell its prompt back with `stty -g`
//!   as before, `jobs` shows the job stopped, `fg` resumes it, and then
//!   `/bin/cat` has a valid outcome, and the retrying cat
//!   round-trips a fresh line;
//! - the command's place: a terminal on 0, 1 and 2 and no other
//!   descriptor, its own process group as the terminal's foreground group,
//!   and the monitor, its parent, leading its session (`getsid(0)` equals
//!   `getppid()`), so its group is not orphaned; the monitor holds only the
//!   slave and the control channel, also when the CLI held a descriptor
//!   above a lowered limit (or, where it cannot show that, starts
//!   nothing); and the monitor's death is the end of the control channel
//!   for the CLI.
//!
//! The kill criterion of M2-17 is judged on these: on either system, a
//! missing stop or report, the outer prompt, `jobs`, `stty -g` or `fg`
//! failing, `/bin/cat` doing neither valid outcome, or the retrying
//! cat's round trip failing, fails (b) or (c). `/bin/cat`'s own ending on
//! macOS is an application's (BSD cat does not retry a read `EINTR`
//! interrupts), not the topology's. The order of `Resume` (the terminal
//! handed back before SIGCONT) is gated by the monitor's model test
//! (`a_resume_gives_the_terminal_back_before_sigcont_to_the_childs_group`
//! in `crates/envcloak-sys/src/pty_monitor.rs`), on both systems, every
//! time: with SIGCONT sent first, (b) and (c) failed on macOS in only 2 of
//! 5 runs of a review, and pass on Linux, where the monitor's `tcsetpgrp`
//! lands before cat reads again.
//!
//! No libtest harness (`harness = false`): a copy of this binary plays the
//! driver and the probe, and nothing else runs in the process that forks
//! the monitor.
#![allow(unsafe_code, clippy::unwrap_used)]

mod pty_common;

use std::ffi::OsStr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::process::ExitStatusExt;
use std::process::Stdio;
use std::time::Duration;

use envcloak_sys::pty::{MonitorCommand, MonitorEvent, SessionError, open_pty, spawn_session};
use envcloak_sys::{TerminalGuard, TerminalSettings, set_window_size, window_size};
use pty_common::{
    DEADLINE, OwnPidOnly, ROLE, SCENARIO, Screen, has_exited, my_role, own_allocations, put,
    run_cases, short_dir, wait_child, wait_child_within,
};

#[global_allocator]
static ALLOCATOR: OwnPidOnly = OwnPidOnly;

fn main() {
    own_allocations();
    match my_role().as_deref() {
        Some("driver") => return driver(),
        Some("probe") => return probe(),
        Some("cat") => return cat(),
        Some("fd-stand-in") => return fd_stand_in(),
        Some(other) => panic!("unknown role {other}"),
        None => {}
    }
    run_cases(
        "pty_topology",
        &[
            (
                "a_session_leading_child_does_not_stop_on_the_suspend_character",
                a_session_leading_child_does_not_stop_on_the_suspend_character,
            ),
            (
                "the_monitor_stops_cat_on_the_suspend_character_and_resumes_it",
                the_monitor_stops_cat_on_the_suspend_character_and_resumes_it,
            ),
            (
                "suspend_stops_the_command_and_the_channels_end_hangs_it_up",
                suspend_stops_the_command_and_the_channels_end_hangs_it_up,
            ),
            (
                "a_monitor_that_dies_ends_the_channel_for_the_cli",
                a_monitor_that_dies_ends_the_channel_for_the_cli,
            ),
            (
                "a_command_that_stops_itself_after_each_resume_is_never_reported_exited",
                a_command_that_stops_itself_after_each_resume_is_never_reported_exited,
            ),
            (
                "the_monitor_closes_a_descriptor_above_a_lowered_limit_or_refuses",
                the_monitor_closes_a_descriptor_above_a_lowered_limit_or_refuses,
            ),
            (
                "an_outer_job_control_shell_regains_its_terminal_and_fg_resumes",
                an_outer_job_control_shell_regains_its_terminal_and_fg_resumes,
            ),
            (
                "a_stopped_cat_has_a_valid_read_outcome_under_the_monitor_and_shell",
                a_stopped_cat_has_a_valid_read_outcome_under_the_monitor_and_shell,
            ),
            (
                "the_command_leads_the_foreground_group_of_a_session_its_parent_leads",
                the_command_leads_the_foreground_group_of_a_session_its_parent_leads,
            ),
        ],
    );
}

/// A private PTY straight from `openpty`, independent of the code under
/// test: master, slave, and the slave's settings, echo on or off (off, what
/// comes back is the command's, not the line discipline's echo).
fn raw_pty(echo: bool) -> (OwnedFd, OwnedFd, TerminalSettings) {
    let (mut m, mut s): (libc::c_int, libc::c_int) = (-1, -1);
    // SAFETY: `m` and `s` are writable; null name, termios and size leave
    // the defaults.
    let rc = unsafe {
        libc::openpty(
            &mut m,
            &mut s,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
    // SAFETY: openpty returned two open descriptors nothing else owns.
    let (master, slave) = unsafe { (OwnedFd::from_raw_fd(m), OwnedFd::from_raw_fd(s)) };
    for fd in [master.as_raw_fd(), slave.as_raw_fd()] {
        // SAFETY: F_SETFD on this process's own descriptor.
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    }
    let settings = TerminalSettings::read(slave.as_fd())
        .unwrap()
        .with_echo(echo);
    settings.apply(slave.as_fd()).unwrap();
    assert!(settings.signal_chars(), "ISIG is on by default");
    assert!(settings.suspend_char().is_some(), "VSUSP is set by default");
    (master, slave, settings)
}

fn reset_job_control_signals() {
    for sig in [
        libc::SIGTSTP,
        libc::SIGTTIN,
        libc::SIGTTOU,
        libc::SIGINT,
        libc::SIGQUIT,
        libc::SIGHUP,
        libc::SIGCONT,
    ] {
        // SAFETY: SIG_DFL with an empty mask; async-signal-safe.
        unsafe {
            let mut act: libc::sigaction = std::mem::zeroed();
            act.sa_sigaction = libc::SIG_DFL;
            libc::sigaction(sig, &act, std::ptr::null_mut());
        }
    }
}

/// Starts `program` as the leader of a new session whose controlling
/// terminal is `slave`, the way a terminal emulator starts a shell (and
/// the way the M2-17 design before D-35 started the command), with the
/// job-control signals at their defaults.
fn session_leader(mut cmd: std::process::Command, slave: &OwnedFd) -> std::process::Child {
    cmd.stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave.try_clone().unwrap()));
    // SAFETY: the closure calls only async-signal-safe functions and does
    // not allocate.
    unsafe {
        std::os::unix::process::CommandExt::pre_exec(&mut cmd, || {
            if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            reset_job_control_signals();
            Ok(())
        });
    }
    cmd.spawn().unwrap()
}

/// (a) The counterexample (F-76): `/bin/cat` leading its own session on a
/// private PTY, default dispositions, ISIG and VSUSP set. The typed
/// suspend character stops nothing (a line typed after it comes back, and
/// no stop is reported), while SIGSTOP to the same owned, unreaped child
/// stops it, SIGCONT gives it its input back, and a typed interrupt ends
/// it with SIGINT. The input relay and the wait-status observer work; job
/// control does not, in this topology.
fn a_session_leading_child_does_not_stop_on_the_suspend_character() {
    let (master, slave, settings) = raw_pty(false);
    let mut child = session_leader(std::process::Command::new("/bin/cat"), &slave);
    drop(slave);
    let pid = i32::try_from(child.id()).unwrap();
    let mut screen = Screen::new(master);
    screen.type_bytes(b"line-one\n");
    screen.expect("line-one\r\n", 1, "cat runs");
    screen.type_bytes(&[settings.suspend_char().unwrap()]);
    screen.type_bytes(b"line-two\n");
    screen.expect(
        "line-two\r\n",
        1,
        "cat kept reading after the suspend character",
    );
    assert_eq!(
        wait_child_within(pid, libc::WSTOPPED | libc::WNOWAIT, Duration::ZERO),
        None,
        "the suspend character stopped a session leader"
    );
    // SIGSTOP to the owned, unreaped child does stop it.
    // kill on this process's own unreaped child.
    assert_eq!(envcloak_sys::testing::kill_raw(pid, libc::SIGSTOP), 0);
    assert_eq!(
        wait_child(pid, libc::WSTOPPED),
        Some((libc::CLD_STOPPED, libc::SIGSTOP))
    );
    screen.type_bytes(b"line-three\n");
    // as above.
    assert_eq!(envcloak_sys::testing::kill_raw(pid, libc::SIGCONT), 0);
    screen.expect("line-three\r\n", 1, "SIGCONT gave cat its input back");
    screen.type_bytes(&[settings.interrupt_char().unwrap()]);
    let status = child.wait().unwrap();
    assert_eq!(status.signal(), Some(libc::SIGINT), "{status:?}");
    println!(
        "pty_topology ({}): a session-leading cat ignored the suspend character; SIGSTOP, \
         SIGCONT and the interrupt character worked",
        std::env::consts::OS
    );
}

/// What `/bin/cat`, stopped in a read of its terminal and continued, did
/// next, from what the terminal showed.
fn cat_outcome(screen: &str) -> &'static str {
    if screen.contains("Interrupted system call") {
        "the read failed with EINTR"
    } else if screen.matches("line-two").count() >= 2 {
        "cat read the next line"
    } else {
        "neither"
    }
}

/// How a cat of [`cats`] is named in a line the test prints.
fn cat_label(cat: &str) -> &str {
    if cat == "/bin/cat" {
        cat
    } else {
        "the EINTR-retrying cat"
    }
}

/// Each topology runs BSD/GNU cat and the retrying fixture. The boolean
/// requires a round trip; only BSD cat may instead exit with EINTR.
fn cats() -> Vec<(String, bool)> {
    vec![
        ("/bin/cat".to_owned(), !cfg!(target_os = "macos")),
        (std::env::current_exe().unwrap().display().to_string(), true),
    ]
}

/// The monitor must stop and resume both cats. GNU cat and the retrying
/// fixture must read on; BSD cat may instead exit 1 with EINTR. An early
/// exit still keeps its output until a late reader drains it. Every cycle
/// runs under OwnPidOnly to reject allocations between fork and exec.
fn the_monitor_stops_cat_on_the_suspend_character_and_resumes_it() {
    for (cat, reads_on) in cats() {
        monitor_cycle(&cat, reads_on);
    }
}

fn monitor_cycle(cat: &str, reads_on: bool) {
    let (master, slave, settings) = raw_pty(false);
    let mut monitor = spawn_session(
        &[OsStr::new(cat)],
        &[
            (OsStr::new("PATH"), OsStr::new("/usr/bin:/bin")),
            (OsStr::new(ROLE), OsStr::new("cat")),
        ],
        slave,
    )
    .unwrap();
    let mut screen = Screen::new(master);
    screen.type_bytes(b"line-one\n");
    screen.expect("line-one\r\n", 1, "cat runs under the monitor");
    screen.type_bytes(&[settings.suspend_char().unwrap()]);
    assert_eq!(
        monitor.next_event(Some(DEADLINE)).unwrap(),
        Some(MonitorEvent::Stopped(libc::SIGTSTP)),
        "the suspend character did not stop {cat}"
    );
    screen.type_bytes(b"line-two\n");
    monitor.send(MonitorCommand::Resume).unwrap();
    assert_eq!(
        monitor.next_event(Some(DEADLINE)).unwrap(),
        Some(MonitorEvent::Continued),
        "{cat}"
    );
    // BSD cat may already have exited with EINTR, or may read on. Keep
    // the delayed-reader check when it exited, without assuming another
    // cat's scheduling outcome predicts this one.
    let early = if reads_on {
        None
    } else {
        let late = std::time::Instant::now() + Duration::from_millis(1200);
        let event = monitor
            .next_event(Some(Duration::from_millis(1200)))
            .unwrap();
        let left = late.saturating_duration_since(std::time::Instant::now());
        assert_eq!(monitor.next_event(Some(left)).unwrap(), None, "{cat}");
        event
    };
    let reads_on = reads_on || early.is_none();
    if reads_on {
        screen.expect("line-two\r\n", 1, "Resume gave cat its input back");
        screen.type_bytes(b"line-three\n");
        screen.expect("line-three\r\n", 1, "cat still reads");
        screen.type_bytes(&[settings.eof_char().unwrap()]);
    } else {
        screen.expect(
            "Interrupted system call",
            1,
            "BSD cat's EINTR message, read late",
        );
    }
    let event = match early {
        Some(event) => Some(event),
        None => screen.next_event(&mut monitor),
    };
    let Some(MonitorEvent::Exited(status)) = event else {
        panic!("{cat} did not exit: {event:?} (a stop on SIGTTIN would show here)");
    };
    if reads_on {
        assert_eq!(status.code(), Some(0), "{cat}: {status:?}");
    } else {
        assert_eq!(status.code(), Some(1), "{cat}: {status:?}");
    }
    // The monitor ends with `PREPARED_KEPT_EXIT` (this binary has the
    // `testing` feature) when it kept a string prepared for the exec.
    let monitor_status = monitor.finish().unwrap();
    assert!(
        monitor_status.success(),
        "{cat}: the monitor ended {monitor_status:?}"
    );
    println!(
        "pty_topology ({}): {} under the monitor: stopped by the suspend character, \
         continued by Resume, {}",
        std::env::consts::OS,
        cat_label(cat),
        if reads_on {
            "read on and ended at EOF"
        } else {
            "then ended with EINTR as under a shell"
        }
    );
}

/// The monitor's other two commands on the real path: `Suspend` (the CLI
/// got SIGTSTP from another process) stops the command, which `Resume`
/// continues; and the end of the control channel while the command runs
/// (the CLI gone) hangs the command up, so the monitor reaps it and exits
/// on its own. `finish` returns only once that has happened.
fn suspend_stops_the_command_and_the_channels_end_hangs_it_up() {
    let (master, slave, _) = raw_pty(false);
    // A cat that reads on after a stop.
    let (cat, _) = cats().pop().unwrap();
    let mut monitor = spawn_session(
        &[OsStr::new(&cat)],
        &[
            (OsStr::new("PATH"), OsStr::new("/usr/bin:/bin")),
            (OsStr::new(ROLE), OsStr::new("cat")),
        ],
        slave,
    )
    .unwrap();
    let mut screen = Screen::new(master);
    screen.type_bytes(b"line-one\n");
    screen.expect("line-one\r\n", 1, "cat runs under the monitor");
    monitor.send(MonitorCommand::Suspend).unwrap();
    assert_eq!(
        monitor.next_event(Some(DEADLINE)).unwrap(),
        Some(MonitorEvent::Stopped(libc::SIGTSTP)),
        "Suspend did not stop cat"
    );
    monitor.send(MonitorCommand::Resume).unwrap();
    assert_eq!(
        monitor.next_event(Some(DEADLINE)).unwrap(),
        Some(MonitorEvent::Continued)
    );
    screen.type_bytes(b"line-two\n");
    screen.expect("line-two\r\n", 1, "cat reads again");
    // The CLI's end of the channel goes, the command still running.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(monitor.finish());
    });
    let finished = rx.recv_timeout(DEADLINE).expect("the monitor did not end");
    assert!(finished.unwrap().success());
    // Nothing holds the slave any more: the terminal ends.
    assert!(
        screen.wait_for_end(),
        "the terminal did not end: {}",
        screen.text()
    );
}

/// The monitor dies (SIGKILL, sent to it as this process's own unreaped
/// child): the CLI sees the end of the control channel within the
/// deadline (`UnexpectedEof`, what M2-19's `pty_monitor_lost` stands on),
/// a command sent after it fails, `finish` reaps the monitor and returns
/// how it died, and the kernel hangs the session up, so the command ends
/// and the terminal with it. Keep a copy of the monitor's end of the
/// channel in the CLI and the end never comes: the wait times out.
fn a_monitor_that_dies_ends_the_channel_for_the_cli() {
    let (master, slave, _) = raw_pty(false);
    let mut monitor = spawn_session(
        &[OsStr::new("/bin/cat")],
        &[(OsStr::new("PATH"), OsStr::new("/usr/bin:/bin"))],
        slave,
    )
    .unwrap();
    let mut screen = Screen::new(master);
    screen.type_bytes(b"line-one\n");
    screen.expect("line-one\r\n", 1, "cat runs under the monitor");
    let pid = i32::try_from(monitor.monitor_id()).unwrap();
    // the monitor is this process's own, unreaped child (the
    // session monitor's handle holds it).
    assert_eq!(envcloak_sys::testing::kill_raw(pid, libc::SIGKILL), 0);
    let lost = monitor.next_event(Some(DEADLINE));
    assert!(
        matches!(&lost, Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof),
        "the monitor's death was not seen as the channel's end: {lost:?}"
    );
    assert!(
        monitor.send(MonitorCommand::Resume).is_err(),
        "a command to a dead monitor was taken"
    );
    let status = monitor.finish().unwrap();
    assert_eq!(status.signal(), Some(libc::SIGKILL), "{status:?}");
    assert!(
        screen.wait_for_end(),
        "the hung-up session did not end the terminal: {}",
        screen.text()
    );
}

/// How many stops the self-stopping command makes, at most.
const STOP_CYCLES: usize = 20_000;
/// How long its stop and resume cycles run, at most.
const STOP_STRESS: Duration = Duration::from_secs(15);

/// A command that stops itself again at once after every `Resume`
/// (`kill -STOP $$` in a loop), so its stops race the monitor's two looks
/// at it, thousands of times. Each must come as `Stopped(SIGSTOP)` (with
/// `Continued` between), never as `Exited`: macOS's `waitid` returns a
/// stop to the monitor's exit observer when the command stopped after the
/// first look, and a monitor that counted it reported `Exited` with the
/// stop's signal, closed the slave, and then hung reaping a command that
/// was only stopped (the verifier's review of PR #27 found it within 206
/// to 2124 cycles, 4 runs of 4). Then `Signal(SIGKILL)` ends the command,
/// `Exited` says it was killed, and `finish` returns within the deadline.
fn a_command_that_stops_itself_after_each_resume_is_never_reported_exited() {
    let (master, slave, _) = raw_pty(false);
    let mut monitor = spawn_session(
        &[
            OsStr::new("/bin/sh"),
            OsStr::new("-c"),
            OsStr::new("while :; do kill -STOP $$; done"),
        ],
        &[(OsStr::new("PATH"), OsStr::new("/usr/bin:/bin"))],
        slave,
    )
    .unwrap();
    let start = std::time::Instant::now();
    let (mut stops, mut continues) = (0usize, 0usize);
    while stops < STOP_CYCLES && start.elapsed() < STOP_STRESS {
        match monitor.next_event(Some(DEADLINE)).unwrap() {
            Some(MonitorEvent::Stopped(sig)) => {
                assert_eq!(sig, libc::SIGSTOP, "after {stops} stops");
                stops += 1;
                monitor.send(MonitorCommand::Resume).unwrap();
            }
            Some(MonitorEvent::Continued) => continues += 1,
            other => panic!(
                "after {stops} stops and {continues} continues the monitor reported {other:?} \
                 for a command that only stops itself"
            ),
        }
    }
    assert!(stops >= 100, "only {stops} stops in {STOP_STRESS:?}");
    monitor.send(MonitorCommand::Signal(libc::SIGKILL)).unwrap();
    let status = loop {
        match monitor.next_event(Some(DEADLINE)).unwrap() {
            Some(MonitorEvent::Stopped(_) | MonitorEvent::Continued) => {}
            Some(MonitorEvent::Exited(status)) => break status,
            None => panic!("no exit after SIGKILL"),
        }
    };
    assert_eq!(status.signal(), Some(libc::SIGKILL), "{status:?}");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(monitor.finish());
    });
    let finished = rx.recv_timeout(DEADLINE).expect("finish did not return");
    assert!(finished.unwrap().success());
    drop(master);
    println!(
        "pty_topology ({}): a command stopping itself after each Resume: {stops} stops and \
         {continues} continues in {:?}, no exit until SIGKILL",
        std::env::consts::OS,
        start.elapsed()
    );
}

/// The descriptor the stand-in leaves open above its lowered limit.
const HIGH_FD: libc::c_int = 200;
/// The stand-in's lowered soft limit on descriptors.
const LOWERED_LIMIT: libc::rlim_t = 64;

/// The CLI stand-in for the descriptor cleanup: opens descriptor 200
/// without close-on-exec, lowers its soft `RLIMIT_NOFILE` to 64 (below
/// it), forces the monitor's second way of closing descriptors when
/// `ENVCLOAK_PTY_SCENARIO` is `fallback`, starts the probe under a monitor,
/// and reports what the monitor holds (`MONITOR-FDS`), or `REFUSED` with
/// the error when the monitor would not start the command.
fn fd_stand_in() {
    let out = std::io::stdout();
    let say = |s: String| put(out.as_fd(), s.as_bytes());
    let null = std::fs::File::open("/dev/null").unwrap();
    // SAFETY: F_DUPFD makes a new descriptor at 200 or above, without
    // close-on-exec, or fails without effect.
    let high = unsafe { libc::fcntl(null.as_raw_fd(), libc::F_DUPFD, HIGH_FD) };
    assert_eq!(high, HIGH_FD, "{}", std::io::Error::last_os_error());
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `lim` is writable; then the soft limit alone is lowered.
    unsafe {
        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim), 0);
        lim.rlim_cur = LOWERED_LIMIT;
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &lim), 0);
    }
    // SAFETY: F_GETFD only reads a descriptor's flags.
    let open_above = unsafe { libc::fcntl(HIGH_FD, libc::F_GETFD) } >= 0;
    say(format!("HIGH-FD-OPEN {open_above}\n"));
    if std::env::var(SCENARIO).as_deref() == Ok("fallback") {
        envcloak_sys::testing::force_descriptor_fallback();
    }
    let (master, slave, _) = raw_pty(false);
    let exe = std::env::current_exe().unwrap();
    match spawn_session(
        &[exe.as_os_str()],
        &[
            (OsStr::new("PATH"), OsStr::new("/usr/bin:/bin")),
            (OsStr::new(ROLE), OsStr::new("probe")),
        ],
        slave,
    ) {
        Ok(mut monitor) => {
            let mut screen = Screen::new(master);
            screen.expect("PROBE", 1, "the probe reports");
            let fds: Vec<i32> = descriptors_of(monitor.monitor_id())
                .into_iter()
                .map(|(n, _)| n)
                .collect();
            let probe = screen.text();
            say(format!(
                "MONITOR-FDS {fds:?}\nCOMMAND-CLEAN {}\n",
                probe.contains("fds=[0, 1, 2] ")
            ));
            screen.type_bytes(b"\n");
            let event = screen.next_event(&mut monitor);
            assert!(matches!(event, Some(MonitorEvent::Exited(_))), "{event:?}");
            monitor.finish().unwrap();
        }
        Err(SessionError::Setup(e)) => say(format!("REFUSED {e}\n")),
        Err(e) => panic!("{e}"),
    }
}

/// The monitor closes every descriptor it inherits but the slave and the
/// channel, also one opened before the CLI lowered its limit and now above
/// it (Codex's review of PR #27). The CLI stand-in holds descriptor 200,
/// not close-on-exec, under a soft limit of 64. The primary way (Linux
/// `close_range`, macOS `proc_pidinfo`) leaves the monitor 0 to 3 and the
/// command 0 to 2; with it passed over, Linux's `/proc/self/fd` listing
/// does the same, and macOS, which has no second listing, refuses to start
/// the command (`SetupFailed`) rather than start it with what it could not
/// close. Close up to the soft limit instead (the fallback before) and
/// descriptor 200 is left in the monitor, and on macOS the command starts.
fn the_monitor_closes_a_descriptor_above_a_lowered_limit_or_refuses() {
    let mut seen = Vec::new();
    for scenario in ["primary", "fallback"] {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .env_clear()
            .env("PATH", "/usr/bin:/usr/sbin:/bin")
            .env(ROLE, "fd-stand-in")
            .env(SCENARIO, scenario)
            .stdin(Stdio::null())
            .stderr(Stdio::inherit())
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(out.status.success(), "{scenario}: {:?}\n{text}", out.status);
        assert!(
            text.contains("HIGH-FD-OPEN true"),
            "{scenario}: the positive control: descriptor 200 was not open in the stand-in\n{text}"
        );
        if scenario == "fallback" && cfg!(target_os = "macos") {
            assert!(
                text.contains("REFUSED"),
                "{scenario}: the monitor started a command it could not show clean:\n{text}"
            );
        } else {
            assert!(
                text.contains("MONITOR-FDS [0, 1, 2, 3]"),
                "{scenario}: the monitor kept more than the slave and the channel:\n{text}"
            );
            assert!(
                text.contains("COMMAND-CLEAN true"),
                "{scenario}: the command started with more than the slave:\n{text}"
            );
        }
        seen.push(format!(
            "{scenario}: {}",
            text.lines().nth(1).unwrap_or_default()
        ));
    }
    println!(
        "pty_topology ({}): descriptor 200 above a soft limit of 64: {}",
        std::env::consts::OS,
        seen.join("; ")
    );
}

/// The suspend and EOF characters of `slave`, as the shell left them.
fn chars_of(slave: BorrowedFd<'_>) -> (u8, u8) {
    let s = TerminalSettings::read(slave).unwrap();
    (s.suspend_char().unwrap(), s.eof_char().unwrap())
}

const PROMPT: &str = "EC-PROMPT> ";

/// Types `line` at the outer shell's prompt and waits for the next prompt.
fn say(screen: &mut Screen, prompts: &mut usize, line: &str) {
    screen.type_bytes(line.as_bytes());
    *prompts += 1;
    screen.expect(PROMPT, *prompts, line);
}

/// The outer shell regains its terminal and fg resumes the job. Both cats
/// must stop, restore stty -g and appear stopped in jobs. The retrying cat
/// must round-trip a fresh line; only BSD cat may instead end with EINTR.
fn an_outer_job_control_shell_regains_its_terminal_and_fg_resumes() {
    for (cat, reads_on) in cats() {
        outer_shell_cycle(&cat, reads_on);
    }
}

fn outer_shell_cycle(cat: &str, mut reads_on: bool) {
    let (master, slave, _) = raw_pty(true);
    let dir = short_dir();
    let home = dir.path().join("home");
    std::fs::create_dir(&home).unwrap();
    let mut cmd = std::process::Command::new("/bin/sh");
    cmd.arg("-i")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &home)
        .env("PS1", PROMPT)
        .env("TERM", "dumb")
        .env("LC_ALL", "C");
    let mut shell = session_leader(cmd, &slave);
    let shell_pid = i32::try_from(shell.id()).unwrap();
    let mut screen = Screen::new(master);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut prompts = 1;
        screen.expect(PROMPT, prompts, "the outer shell's first prompt");
        say(&mut screen, &mut prompts, "set -m\n");
        let before = dir.path().join("before");
        let after = dir.path().join("after");
        say(
            &mut screen,
            &mut prompts,
            &format!("stty -g > {}\n", before.display()),
        );
        let (suspend, eof) = chars_of(slave.as_fd());
        let exe = std::env::current_exe().unwrap();
        let exe = exe.display();
        screen.type_bytes(format!("{ROLE}=driver '{exe}' '{cat}'\n").as_bytes());
        screen.expect("DRIVER-READY", 1, "the driver started cat");
        screen.type_bytes(b"line-one\n");
        screen.expect("line-one", 2, "a line round-trips through cat");
        screen.type_bytes(&[suspend]);
        prompts += 1;
        screen.expect(
            PROMPT,
            prompts,
            "the suspend character gave the outer shell its prompt back",
        );
        say(&mut screen, &mut prompts, "jobs\n");
        assert!(
            screen.count("Stopped") >= 1,
            "jobs did not list a stopped job:\n{}",
            screen.text()
        );
        say(
            &mut screen,
            &mut prompts,
            &format!("stty -g > {}\n", after.display()),
        );
        assert_eq!(
            std::fs::read(&before).unwrap(),
            std::fs::read(&after).unwrap(),
            "the outer terminal was not restored when the job stopped"
        );
        screen.type_bytes(b"fg\n");
        screen.expect("DRIVER-RESUMED", 1, "fg resumed the driver");
        if !reads_on {
            screen.wait_for_within(Duration::from_secs(1), |s| s.count("DRIVER-EXIT") > 0);
            reads_on = screen.count("DRIVER-EXIT 1") == 0;
        }
        if reads_on {
            screen.type_bytes(b"line-two\n");
            screen.expect("line-two", 2, "a fresh line round-trips after fg");
            screen.type_bytes(&[eof]);
        }
        prompts += 1;
        screen.expect(PROMPT, prompts, "cat and the driver ended");
        if reads_on {
            assert_eq!(screen.count("DRIVER-EXIT 0"), 1, "{}", screen.text());
        } else {
            assert_eq!(
                (
                    screen.count("Interrupted system call"),
                    screen.count("DRIVER-EXIT 1")
                ),
                (1, 1),
                "{}",
                screen.text()
            );
        }
        screen.type_bytes(b"exit 0\n");
        // Read on while the shell exits (a session's leader on macOS waits
        // for its terminal's output to drain as it exits), until it has or
        // the terminal ended with it.
        screen.wait_for(|_| has_exited(shell_pid));
        let exited = wait_child(shell_pid, libc::WEXITED | libc::WNOWAIT).is_some();
        assert!(exited, "the outer shell did not exit:\n{}", screen.text());
    }));
    // The master closed first: no exit waits on output nobody reads.
    drop(screen);
    if result.is_err() {
        // The shell is this process's own, unreaped child: end its session.
        let _ = shell.kill();
    }
    let status = shell.wait().unwrap();
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
    assert_eq!(status.code(), Some(0), "{status:?}");
    println!(
        "pty_topology ({}): {}: the outer shell regained its terminal on the suspend \
         character, and fg resumed it; {}",
        std::env::consts::OS,
        cat_label(cat),
        if reads_on {
            "a fresh line round-tripped"
        } else {
            "it then ended with EINTR, as under a shell"
        }
    );
}

/// The driver: what `envcloak run --pty -- <command>` does about the
/// outer terminal and the monitor, without the redaction; the command is
/// its arguments. Prints `DRIVER-READY` once the command runs,
/// `DRIVER-RESUMED` after a stop and `fg`, and `DRIVER-EXIT <code>` at the
/// end.
fn driver() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let out = |b: &[u8]| put(stdout.as_fd(), b);
    let guard = TerminalGuard::enter_raw(stdin.as_fd()).unwrap();
    let pty = open_pty(window_size(stdin.as_fd()).ok(), Some(guard.saved())).unwrap();
    let master = pty.master;
    let argv: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let argv: Vec<&OsStr> = argv.iter().map(|a| a.as_os_str()).collect();
    let mut monitor = spawn_session(
        &argv,
        &[
            (OsStr::new("PATH"), OsStr::new("/usr/bin:/bin")),
            (OsStr::new(ROLE), OsStr::new("cat")),
        ],
        pty.slave,
    )
    .unwrap();
    out(b"DRIVER-READY\r\n");
    let mut exited = None;
    let mut input_open = true;
    while exited.is_none() {
        let control = monitor.control().unwrap().as_raw_fd();
        let mut fds = [
            libc::pollfd {
                fd: if input_open {
                    stdin.as_fd().as_raw_fd()
                } else {
                    -1
                },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: master.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: control,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: three initialized pollfds.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), 3, -1) };
        if rc < 0 {
            continue;
        }
        let mut buf = [0u8; 1024];
        if fds[0].revents != 0 {
            // SAFETY: `buf` is writable.
            let n = unsafe { libc::read(fds[0].fd, buf.as_mut_ptr().cast(), buf.len()) };
            match usize::try_from(n) {
                Ok(0) | Err(_) => input_open = false,
                Ok(n) => put(master.as_fd(), &buf[..n]),
            }
        }
        if fds[1].revents != 0 {
            // SAFETY: `buf` is writable.
            let n = unsafe { libc::read(master.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if let Ok(n) = usize::try_from(n) {
                out(&buf[..n]);
            }
        }
        if fds[2].revents != 0 {
            match monitor.next_event(Some(Duration::ZERO)).unwrap() {
                Some(MonitorEvent::Stopped(_)) => {
                    guard.restore().unwrap();
                    stop_own_group();
                    // Continued (the person's `fg`): raw again, the size
                    // again, and only then the command.
                    guard.reenter_raw().unwrap();
                    if let Ok(size) = window_size(stdin.as_fd()) {
                        set_window_size(master.as_fd(), size).unwrap();
                    }
                    monitor.send(MonitorCommand::Resume).unwrap();
                    out(b"DRIVER-RESUMED\r\n");
                }
                Some(MonitorEvent::Exited(status)) => exited = Some(status),
                Some(MonitorEvent::Continued) | None => {}
            }
        }
    }
    // Drain what cat wrote before it exited.
    let mut screen = Screen::new(master);
    screen.wait_for_within(Duration::from_secs(2), |_| false);
    out(screen.seen());
    drop(guard);
    let code = exited.and_then(|s| s.code()).unwrap_or(125);
    monitor.finish().unwrap();
    out(format!("DRIVER-EXIT {code}\r\n").as_bytes());
    std::process::exit(code);
}

/// Stops this process's own group with SIGTSTP at its default action, as
/// the CLI does once the outer terminal is restored; returns once the
/// group is continued.
fn stop_own_group() {
    // SAFETY: SIG_DFL with an empty mask, then SIGTSTP to this process's
    // own group (its job in the outer shell).
    unsafe {
        let mut act: libc::sigaction = std::mem::zeroed();
        act.sa_sigaction = libc::SIG_DFL;
        libc::sigaction(libc::SIGTSTP, &act, std::ptr::null_mut());
    }
    envcloak_sys::testing::kill_raw(0, libc::SIGTSTP);
}

/// The probe: reports where it runs, as the kernel sees it from inside,
/// then waits for a line before it exits.
fn probe() {
    // SAFETY: plain queries of this process's own state.
    let (pid, ppid, pgrp, sid, fg) = unsafe {
        (
            libc::getpid(),
            libc::getppid(),
            libc::getpgrp(),
            libc::getsid(0),
            libc::tcgetpgrp(0),
        )
    };
    // SAFETY: isatty only queries a descriptor.
    let ttys: Vec<bool> = (0..3).map(|fd| unsafe { libc::isatty(fd) } == 1).collect();
    let dir = if cfg!(target_os = "linux") {
        "/proc/self/fd"
    } else {
        "/dev/fd"
    };
    let listed: Vec<i32> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .collect();
    // The listing's own descriptor is closed by now: keep those still
    // open.
    let fds: Vec<i32> = listed
        .into_iter()
        // SAFETY: F_GETFD only reads a descriptor's flags.
        .filter(|fd| unsafe { libc::fcntl(*fd, libc::F_GETFD) } >= 0)
        .collect();
    let line = format!(
        "PROBE ttys={ttys:?} leads_group={} foreground={} session_is_parent={} fds={fds:?} \
         sid={sid} ppid={ppid} pid={pid}\r\n",
        pgrp == pid,
        fg == pgrp,
        sid == ppid,
    );
    put(std::io::stdout().as_fd(), line.as_bytes());
    let mut byte = [0u8; 1];
    // SAFETY: `byte` is writable.
    unsafe { libc::read(0, byte.as_mut_ptr().cast(), 1) };
}

/// The descriptors process `pid` holds, with what each names, from
/// outside: `/proc/<pid>/fd` on Linux, `lsof` on macOS.
fn descriptors_of(pid: u32) -> Vec<(i32, String)> {
    let mut v = Vec::new();
    if cfg!(target_os = "linux") {
        for e in std::fs::read_dir(format!("/proc/{pid}/fd")).unwrap() {
            let e = e.unwrap();
            let Some(n) = e.file_name().to_str().and_then(|s| s.parse().ok()) else {
                continue;
            };
            let target = std::fs::read_link(e.path()).unwrap();
            v.push((n, target.to_string_lossy().into_owned()));
        }
    } else {
        let out = std::process::Command::new("/usr/sbin/lsof")
            .args(["-n", "-P", "-p", &pid.to_string(), "-F", "ftn"])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let mut fd: Option<i32> = None;
        let mut kind = String::new();
        for line in text.lines() {
            match line.split_at_checked(1) {
                Some(("f", n)) => {
                    fd = n.parse().ok();
                    kind.clear();
                }
                Some(("t", t)) => kind = t.to_owned(),
                Some(("n", name)) => {
                    if let Some(n) = fd.take() {
                        v.push((n, format!("{kind} {name}")));
                    }
                }
                _ => {}
            }
        }
    }
    v.sort();
    v
}

/// The command's place (D-35): a terminal on 0, 1 and 2, its own process
/// group, which is the slave's foreground group, and the monitor, its
/// parent, leading its session; descriptors 0 to 2 and nothing else. The
/// monitor holds the slave on 0 to 2 and the control channel on 3, and
/// nothing else.
fn the_command_leads_the_foreground_group_of_a_session_its_parent_leads() {
    let (master, slave, _) = raw_pty(false);
    let exe = std::env::current_exe().unwrap();
    let mut monitor = spawn_session(
        &[exe.as_os_str()],
        &[
            (OsStr::new("PATH"), OsStr::new("/usr/bin:/bin")),
            (OsStr::new(ROLE), OsStr::new("probe")),
        ],
        slave,
    )
    .unwrap();
    let mut screen = Screen::new(master);
    screen.expect("\r\n", 1, "the probe reports");
    let report = screen.text();
    for (fact, what) in [
        ("ttys=[true, true, true]", "a terminal on 0 to 2"),
        ("leads_group=true", "its own process group"),
        ("foreground=true", "the slave's foreground group"),
        ("session_is_parent=true", "its parent leads its session"),
        ("fds=[0, 1, 2]", "descriptors 0 to 2 and nothing else"),
    ] {
        assert!(report.contains(fact), "not {what}: {report}");
    }
    assert!(
        report.contains(&format!("sid={} ", monitor.monitor_id())),
        "the session is not the monitor's: {report}"
    );
    assert!(
        report.contains(&format!("pid={}\r", monitor.command_id())),
        "{report}"
    );
    // The monitor, from outside: the slave three times, the channel once.
    let fds = descriptors_of(monitor.monitor_id());
    let numbers: Vec<i32> = fds.iter().map(|(n, _)| *n).collect();
    assert_eq!(numbers, vec![0, 1, 2, 3], "{fds:?}");
    let a_terminal = |s: &str| s.contains("/dev/pts/") || s.contains("/dev/ttys");
    assert!(fds[..3].iter().all(|(_, s)| a_terminal(s)), "{fds:?}");
    assert!(fds[..3].iter().all(|(_, s)| *s == fds[0].1), "{fds:?}");
    assert!(
        fds[3].1.contains("socket") || fds[3].1.starts_with("unix"),
        "{fds:?}"
    );
    screen.type_bytes(b"\n");
    let event = screen.next_event(&mut monitor);
    assert!(
        matches!(event, Some(MonitorEvent::Exited(s)) if s.success()),
        "{event:?}"
    );
    monitor.finish().unwrap();
}

/// A `cat` that reads again when a read is interrupted (`EINTR`), as GNU
/// `cat` does.
fn cat() {
    let mut buf = [0u8; 4096];
    loop {
        // SAFETY: `buf` is writable for its length.
        let n = unsafe { libc::read(0, buf.as_mut_ptr().cast(), buf.len()) };
        match usize::try_from(n) {
            Ok(0) => std::process::exit(0),
            Ok(n) => put(std::io::stdout().as_fd(), &buf[..n]),
            Err(_) if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted => {
            }
            Err(_) => std::process::exit(1),
        }
    }
}

/// `/bin/cat`, stopped by the suspend character inside a read of its
/// terminal and continued with nothing typed, then given a line: whether
/// it reads the line or its read fails (`EINTR`). Returns the screen.
fn stopped_cat_under_a_shell() -> String {
    let (master, slave, _) = raw_pty(true);
    let mut cmd = std::process::Command::new("/bin/sh");
    cmd.arg("-i")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("PS1", PROMPT)
        .env("TERM", "dumb")
        .env("LC_ALL", "C");
    let mut shell = session_leader(cmd, &slave);
    let (suspend, _) = chars_of(slave.as_fd());
    let mut screen = Screen::new(master);
    let mut prompts = 1;
    screen.expect(PROMPT, prompts, "the shell's first prompt");
    say(&mut screen, &mut prompts, "set -m\n");
    screen.type_bytes(b"/bin/cat\n");
    screen.type_bytes(b"line-one\n");
    screen.expect("line-one", 2, "cat runs");
    screen.type_bytes(&[suspend]);
    prompts += 1;
    screen.expect(PROMPT, prompts, "the suspend character stopped cat");
    screen.type_bytes(b"fg\n");
    screen.expect("/bin/cat", 2, "fg");
    // Nothing typed until cat has had its chance to fail.
    screen.wait_for_within(Duration::from_millis(500), |s| s.count("Interrupted") > 0);
    screen.type_bytes(b"line-two\n");
    screen.wait_for_within(Duration::from_secs(2), |s| s.count("line-two") >= 2);
    let text = screen.text();
    drop(screen);
    let _ = shell.kill();
    let _ = shell.wait();
    text
}

/// The same with cat under the monitor: `Resume` with nothing typed.
fn stopped_cat_under_the_monitor() -> String {
    let (master, slave, settings) = raw_pty(true);
    let mut monitor = spawn_session(
        &[OsStr::new("/bin/cat")],
        &[(OsStr::new("PATH"), OsStr::new("/usr/bin:/bin"))],
        slave,
    )
    .unwrap();
    let mut screen = Screen::new(master);
    screen.type_bytes(b"line-one\n");
    screen.expect("line-one", 2, "cat runs under the monitor");
    screen.type_bytes(&[settings.suspend_char().unwrap()]);
    assert_eq!(
        monitor.next_event(Some(DEADLINE)).unwrap(),
        Some(MonitorEvent::Stopped(libc::SIGTSTP))
    );
    monitor.send(MonitorCommand::Resume).unwrap();
    assert_eq!(
        monitor.next_event(Some(DEADLINE)).unwrap(),
        Some(MonitorEvent::Continued)
    );
    screen.wait_for_within(Duration::from_millis(500), |s| s.count("Interrupted") > 0);
    screen.type_bytes(b"line-two\n");
    screen.wait_for_within(Duration::from_secs(2), |s| s.count("line-two") >= 2);
    drop(monitor);
    screen.text()
}

/// Observe both kernel topologies independently. BSD cat's EINTR depends
/// on the exact read/stop interleaving, so the outcomes need not match.
/// GNU cat must read on in both; neither path may hang or lose the stop.
fn a_stopped_cat_has_a_valid_read_outcome_under_the_monitor_and_shell() {
    let outcome = cat_outcome;
    let shell = stopped_cat_under_a_shell();
    let monitor = stopped_cat_under_the_monitor();
    let (a, b) = (outcome(&shell), outcome(&monitor));
    assert_ne!(a, "neither", "{shell}");
    assert_ne!(b, "neither", "{monitor}");
    if !cfg!(target_os = "macos") {
        assert_eq!(a, "cat read the next line", "{shell}");
        assert_eq!(b, "cat read the next line", "{monitor}");
    }
    println!(
        "pty_topology ({}): /bin/cat stopped in a read and continued with nothing typed: {a}, \
         under a job-control shell; {b} under the monitor",
        std::env::consts::OS
    );
}
