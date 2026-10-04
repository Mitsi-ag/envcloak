//! The outer terminal in PTY mode (M2 plan M2-17, lesson L-13) and what
//! the PTY carries: on a real pseudo-terminal of the test's own, a copy of
//! this binary takes it raw with `TerminalGuard` and leaves it in each
//! way `envcloak run --pty` can: a normal exit, an error, SIGTERM, SIGHUP,
//! a release-build abort from a panic (the panic hook restores; no
//! destructor runs), and SIGTSTP then SIGCONT (restored while stopped, raw
//! again after). Each time the settings read back equal to those before,
//! and input typed and not read is discarded (`TCSAFLUSH`). Then the
//! window size reaches the command, at the start and on a change, and the
//! command's exec failures come back as `env(1)` reports them.
//!
//! No libtest harness (`harness = false`): copies of this binary play the
//! guarded program and the probe, and nothing else runs in the process
//! that forks the monitor.
#![allow(unsafe_code, clippy::unwrap_used)]

mod pty_common;

use std::ffi::OsStr;
use std::io::{BufRead, Read};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::process::Stdio;
use std::time::Duration;

use envcloak_sys::pty::{MonitorEvent, SessionError, open_pty, spawn_session};
use envcloak_sys::{
    Relayed, SignalRelay, TerminalGuard, TerminalSettings, WindowSize, exit_by_signal,
    install_panic_hook, set_window_size, window_size,
};
use pty_common::{
    DEADLINE, OwnPidOnly, ROLE, SCENARIO, Screen, my_role, own_allocations, put, role, run_cases,
    short_dir, wait_child,
};

#[global_allocator]
static ALLOCATOR: OwnPidOnly = OwnPidOnly;

fn main() {
    own_allocations();
    match my_role().as_deref() {
        Some("guarded") => return guarded(),
        Some("size") => return size_probe(),
        Some(other) => panic!("unknown role {other}"),
        None => {}
    }
    run_cases(
        "pty",
        &[
            ("restored_after_a_normal_exit", restored_after_a_normal_exit),
            ("restored_after_an_error", restored_after_an_error),
            ("restored_after_sigterm", restored_after_sigterm),
            ("restored_after_sighup", restored_after_sighup),
            (
                "restored_after_a_release_abort_by_the_panic_hook",
                restored_after_a_release_abort_by_the_panic_hook,
            ),
            (
                "restored_while_stopped_and_raw_again_after_sigcont",
                restored_while_stopped_and_raw_again_after_sigcont,
            ),
            (
                "input_typed_and_not_read_is_discarded_on_restore",
                input_typed_and_not_read_is_discarded_on_restore,
            ),
            (
                "the_window_size_reaches_the_command_and_follows_a_change",
                the_window_size_reaches_the_command_and_follows_a_change,
            ),
            (
                "exec_failures_read_as_env_1_has_them",
                exec_failures_read_as_env_1_has_them,
            ),
        ],
    );
}

/// The guarded program, in the way out `ENVCLOAK_PTY_SCENARIO` names. It takes its
/// standard input raw, prints `RAW`, and then:
/// - `exit` and `error`: reads one byte, then returns normally or with an
///   error (the guard dropped on the way);
/// - `signal`: waits for SIGTERM or SIGHUP, drops the guard and ends by
///   the signal;
/// - `abort`: reads one byte, then panics inside an `extern "C"` function,
///   which cannot unwind, so the process aborts as a release build does,
///   after the panic hook and without the guard's drop;
/// - `stop`: on SIGTSTP restores the terminal and stops; on SIGCONT takes
///   raw mode again, prints `RAW-AGAIN`, reads one byte and exits;
/// - `unread`: waits for SIGUSR1 without reading, then exits normally.
fn guarded() {
    let scenario = std::env::var(SCENARIO).unwrap();
    if scenario == "abort" {
        // The abort leaves no core file behind (CI routes core files to a
        // directory gate 19 checks).
        envcloak_sys::disable_core_dumps().unwrap();
        install_panic_hook("pty-test");
    }
    let relay = match scenario.as_str() {
        "signal" => Some(SignalRelay::install(&[libc::SIGTERM, libc::SIGHUP]).unwrap()),
        "stop" => Some(SignalRelay::install(&[libc::SIGTSTP]).unwrap()),
        "unread" => Some(SignalRelay::install(&[libc::SIGUSR1]).unwrap()),
        _ => None,
    };
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let result = (|| -> std::io::Result<()> {
        let guard = TerminalGuard::enter_raw(stdin.as_fd())?;
        put(stdout.as_fd(), b"RAW\n");
        let read_one = || {
            let mut b = [0u8; 1];
            std::io::stdin().read_exact(&mut b)
        };
        match scenario.as_str() {
            "exit" => read_one()?,
            "error" => {
                read_one()?;
                return Err(std::io::Error::other("an error on the way out"));
            }
            "signal" => {
                let Some(Relayed::Signal { number, .. }) = relay.unwrap().next()? else {
                    panic!("no signal");
                };
                drop(guard);
                exit_by_signal(number);
            }
            "abort" => {
                read_one()?;
                boom();
            }
            "stop" => {
                let relay = relay.unwrap();
                let Some(Relayed::Signal { .. }) = relay.next()? else {
                    panic!("no SIGTSTP");
                };
                guard.restore()?;
                // The relay's drop gives SIGTSTP its default action back.
                drop(relay);
                // SAFETY: SIGTSTP to this process itself.
                unsafe { libc::kill(libc::getpid(), libc::SIGTSTP) };
                guard.reenter_raw()?;
                put(stdout.as_fd(), b"RAW-AGAIN\n");
                read_one()?;
            }
            "unread" => {
                relay.unwrap().next()?;
            }
            other => panic!("unknown scenario {other}"),
        }
        drop(guard);
        Ok(())
    })();
    if result.is_err() {
        std::process::exit(1);
    }
}

/// A panic that cannot unwind past this frame: the process aborts after
/// the panic hook, without running the destructors of the frames above.
extern "C" fn boom() {
    panic!("an injected panic");
}

/// A terminal of the test's own: master, slave, and the slave's settings
/// as they start (cooked).
fn outer() -> (OwnedFd, OwnedFd, TerminalSettings) {
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
    let before = TerminalSettings::read(slave.as_fd()).unwrap();
    assert!(!before.is_raw());
    (master, slave, before)
}

/// The guarded program in `scenario`, on the outer terminal `slave`, in a
/// process group of its own (so a stop stops only it); returns once it has
/// printed `RAW` and the terminal reads back raw.
fn start_guarded(
    scenario: &str,
    master: OwnedFd,
    slave: &OwnedFd,
) -> (std::process::Child, Screen) {
    use std::os::unix::process::CommandExt;
    let child = role("guarded")
        .env(SCENARIO, scenario)
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .unwrap();
    let mut screen = Screen::new(master);
    screen.expect("RAW\n", 1, scenario);
    assert!(
        TerminalSettings::read(slave.as_fd()).unwrap().is_raw(),
        "{scenario}: not raw"
    );
    (child, screen)
}

fn pending_input(slave: BorrowedFd<'_>) -> usize {
    let mut n: libc::c_int = 0;
    // SAFETY: FIONREAD writes one int.
    let rc = unsafe { libc::ioctl(slave.as_raw_fd(), libc::FIONREAD as _, &mut n) };
    assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
    usize::try_from(n).unwrap()
}

/// Waits for the guarded program to end, checks how, and that the
/// terminal's settings read back as they were before.
fn assert_restored(
    mut child: std::process::Child,
    slave: &OwnedFd,
    before: &TerminalSettings,
    how: impl Fn(std::process::ExitStatus) -> bool,
    what: &str,
) {
    let pid = i32::try_from(child.id()).unwrap();
    let ended = wait_child(pid, libc::WEXITED | libc::WNOWAIT);
    if ended.is_none() {
        let _ = child.kill();
    }
    let status = child.wait().unwrap();
    assert!(ended.is_some(), "{what}: the program did not end");
    assert!(how(status), "{what}: {status:?}");
    let after = TerminalSettings::read(slave.as_fd()).unwrap();
    assert!(
        after.same_as(before),
        "{what}: the terminal was left {after:?}, not {before:?}"
    );
}

fn restored_after_a_normal_exit() {
    let (master, slave, before) = outer();
    let (child, screen) = start_guarded("exit", master, &slave);
    screen.type_bytes(b"q");
    assert_restored(child, &slave, &before, |s| s.code() == Some(0), "exit");
}

fn restored_after_an_error() {
    let (master, slave, before) = outer();
    let (child, screen) = start_guarded("error", master, &slave);
    screen.type_bytes(b"q");
    assert_restored(child, &slave, &before, |s| s.code() == Some(1), "error");
}

fn restored_after_signal(sig: i32, what: &str) {
    let (master, slave, before) = outer();
    let (child, _screen) = start_guarded("signal", master, &slave);
    // SAFETY: kill on this process's own, unreaped child.
    assert_eq!(
        unsafe { libc::kill(i32::try_from(child.id()).unwrap(), sig) },
        0
    );
    assert_restored(child, &slave, &before, |s| s.signal() == Some(sig), what);
}

fn restored_after_sigterm() {
    restored_after_signal(libc::SIGTERM, "SIGTERM");
}

fn restored_after_sighup() {
    restored_after_signal(libc::SIGHUP, "SIGHUP");
}

/// A release build aborts on a panic: no destructor runs, so the guard's
/// drop does not restore. The panic hook does.
fn restored_after_a_release_abort_by_the_panic_hook() {
    let (master, slave, before) = outer();
    let (child, screen) = start_guarded("abort", master, &slave);
    screen.type_bytes(b"q");
    assert_restored(
        child,
        &slave,
        &before,
        |s| s.signal() == Some(libc::SIGABRT),
        "abort",
    );
}

/// SIGTSTP from another process: the terminal is restored before the
/// program stops (read while it is stopped), raw again after SIGCONT, and
/// restored at the exit.
fn restored_while_stopped_and_raw_again_after_sigcont() {
    let (master, slave, before) = outer();
    let (child, mut screen) = start_guarded("stop", master, &slave);
    let pid = i32::try_from(child.id()).unwrap();
    // SAFETY: kill on this process's own, unreaped child.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGTSTP) }, 0);
    assert_eq!(
        wait_child(pid, libc::WSTOPPED),
        Some((libc::CLD_STOPPED, libc::SIGTSTP)),
        "the program did not stop"
    );
    let stopped = TerminalSettings::read(slave.as_fd()).unwrap();
    assert!(
        stopped.same_as(&before),
        "stopped with the terminal {stopped:?}"
    );
    // SAFETY: as above.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGCONT) }, 0);
    screen.expect("RAW-AGAIN\n", 1, "continued");
    assert!(TerminalSettings::read(slave.as_fd()).unwrap().is_raw());
    screen.type_bytes(b"q");
    assert_restored(child, &slave, &before, |s| s.code() == Some(0), "stop");
}

/// Input typed while the terminal is raw and never read is discarded when
/// the settings come back (`TCSAFLUSH`): it would otherwise reach the next
/// program to read the terminal, usually the shell.
fn input_typed_and_not_read_is_discarded_on_restore() {
    let (master, slave, before) = outer();
    let (child, screen) = start_guarded("unread", master, &slave);
    screen.type_bytes(b"typed-and-not-read\n");
    let deadline = std::time::Instant::now() + DEADLINE;
    while pending_input(slave.as_fd()) == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "the input never arrived"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    // SAFETY: kill on this process's own, unreaped child.
    assert_eq!(
        unsafe { libc::kill(i32::try_from(child.id()).unwrap(), libc::SIGUSR1) },
        0
    );
    assert_restored(child, &slave, &before, |s| s.code() == Some(0), "unread");
    assert_eq!(
        pending_input(slave.as_fd()),
        0,
        "input typed while raw was left for the next reader"
    );
}

/// The size probe: prints `SIZE <rows> <cols>` at the start and after each
/// SIGWINCH, and exits on a line from its terminal.
fn size_probe() {
    let relay = SignalRelay::install(&[libc::SIGWINCH]).unwrap();
    let report = || {
        let s = window_size(std::io::stdin().as_fd()).unwrap();
        put(
            std::io::stdout().as_fd(),
            format!("SIZE {} {}\n", s.rows, s.cols).as_bytes(),
        );
    };
    report();
    std::thread::spawn(move || {
        let _ = std::io::stdin().lock().lines().next();
        std::process::exit(0);
    });
    while let Ok(Some(_)) = relay.next() {
        report();
    }
}

/// `open_pty` gives the slave the outer size, and `set_window_size` on the
/// master changes it, which the command sees with SIGWINCH.
fn the_window_size_reaches_the_command_and_follows_a_change() {
    let start = WindowSize {
        rows: 33,
        cols: 101,
        ..WindowSize::default()
    };
    let pty = open_pty(Some(start), None).unwrap();
    assert_eq!(window_size(pty.slave.as_fd()).unwrap(), start);
    let exe = std::env::current_exe().unwrap();
    let mut monitor = spawn_session(
        &[exe.as_os_str()],
        &[(OsStr::new(ROLE), OsStr::new("size"))],
        pty.slave,
    )
    .unwrap();
    let mut screen = Screen::new(pty.master);
    screen.expect("SIZE 33 101", 1, "the size at the start");
    let changed = WindowSize {
        rows: 48,
        cols: 160,
        ..WindowSize::default()
    };
    set_window_size(screen.master(), changed).unwrap();
    screen.expect("SIZE 48 160", 1, "the size after a change");
    screen.type_bytes(b"\n");
    let event = monitor.next_event(Some(DEADLINE)).unwrap();
    assert!(
        matches!(event, Some(MonitorEvent::Exited(s)) if s.success()),
        "{event:?}"
    );
    monitor.finish().unwrap();
}

fn exec_error(argv: &[&OsStr], env: &[(&OsStr, &OsStr)]) -> Option<i32> {
    let pty = open_pty(None, None).unwrap();
    match spawn_session(argv, env, pty.slave) {
        Err(SessionError::Exec(e)) => e.raw_os_error(),
        Err(SessionError::Setup(e)) => panic!("a setup error: {e}"),
        Ok(m) => {
            drop(m);
            None
        }
    }
}

/// A program that does not exist is `ENOENT` (127 for the CLI), one that
/// cannot be run `EACCES` (126), as `env(1)` has them; a name without a
/// `/` is looked up on the command's `PATH`, a NUL byte refused before
/// anything starts.
fn exec_failures_read_as_env_1_has_them() {
    let dir = short_dir();
    let plain = dir.path().join("plain");
    std::fs::write(&plain, b"#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o644)).unwrap();
    let path = (OsStr::new("PATH"), OsStr::new("/usr/bin:/bin"));
    assert_eq!(
        exec_error(&[dir.path().join("missing").as_os_str()], &[path]),
        Some(libc::ENOENT)
    );
    assert_eq!(
        exec_error(&[OsStr::new("envcloak-no-such-command-anywhere")], &[path]),
        Some(libc::ENOENT)
    );
    assert_eq!(
        exec_error(&[plain.as_os_str()], &[path]),
        Some(libc::EACCES)
    );
    assert_eq!(
        exec_error(&[dir.path().as_os_str()], &[path]),
        Some(libc::EACCES)
    );
    // On the PATH, a refused candidate before a missing one is EACCES.
    let in_path = (OsStr::new("PATH"), dir.path().as_os_str());
    assert_eq!(
        exec_error(&[OsStr::new("plain")], &[in_path]),
        Some(libc::EACCES)
    );
    // Found on the PATH: it runs.
    assert_eq!(exec_error(&[OsStr::new("true")], &[path]), None);
    let pty = open_pty(None, None).unwrap();
    let nul = std::ffi::OsString::from_vec(b"a\0b".to_vec());
    assert!(matches!(
        spawn_session(&[nul.as_os_str()], &[path], pty.slave),
        Err(SessionError::Setup(e)) if e.kind() == std::io::ErrorKind::InvalidInput
    ));
}
