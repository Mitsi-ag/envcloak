//! The outer terminal in PTY mode (M2 plan M2-17, lesson L-13) and what
//! the PTY carries: on a real pseudo-terminal of the test's own, a copy of
//! this binary takes it raw with `TerminalGuard` and leaves it in each
//! way `envcloak run --pty` can: a normal exit (through
//! `TerminalGuard::release`, which reports), an error, SIGTERM, SIGHUP, a
//! release-build abort from a panic (the panic hook restores; no
//! destructor runs), and SIGTSTP then SIGCONT (restored while stopped, raw
//! again after). Before each way out, input is typed and left unread; each
//! time the settings read back as before, both through the guard's own
//! type and through `stty -g` (an independent reader), and the unread
//! input is gone (`TCSAFLUSH`), on Linux as on macOS. Then: a new PTY
//! starts with the outer terminal's settings (a remapped or a disabled
//! suspend character) and size, both of its sides close-on-exec; the
//! window size reaches the command and follows a change, as `stty size`
//! inside the PTY reads it; the command's exec failures come back as
//! `env(1)` reports them; and a CLI that inherited SIGCHLD ignored still
//! owns its monitor until it reaps it.
//!
//! No libtest harness (`harness = false`): copies of this binary play the
//! guarded program and the probes, and nothing else runs in the process
//! that forks the monitor.
#![allow(unsafe_code, clippy::unwrap_used)]

mod pty_common;

use std::ffi::OsStr;
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
        Some("winch") => return winch_probe(),
        Some("sigchld-ignored") => return sigchld_ignored(),
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
                "the_settings_read_again_after_a_stop_are_what_comes_back",
                the_settings_read_again_after_a_stop_are_what_comes_back,
            ),
            (
                "input_typed_and_not_read_is_discarded_on_restore",
                input_typed_and_not_read_is_discarded_on_restore,
            ),
            (
                "raw_mode_is_refused_after_the_final_restore",
                raw_mode_is_refused_after_the_final_restore,
            ),
            (
                "a_new_pty_starts_with_the_outer_settings_and_size",
                a_new_pty_starts_with_the_outer_settings_and_size,
            ),
            (
                "the_window_size_reaches_the_command_and_follows_a_change",
                the_window_size_reaches_the_command_and_follows_a_change,
            ),
            (
                "the_last_output_before_the_exit_is_not_lost_at_the_close",
                the_last_output_before_the_exit_is_not_lost_at_the_close,
            ),
            (
                "exec_failures_read_as_env_1_has_them",
                exec_failures_read_as_env_1_has_them,
            ),
            (
                "a_cli_that_inherited_sigchld_ignored_still_owns_its_monitor",
                a_cli_that_inherited_sigchld_ignored_still_owns_its_monitor,
            ),
        ],
    );
}

/// The guarded program, in the way out `ENVCLOAK_PTY_SCENARIO` names. It
/// takes its standard input raw, prints `RAW`, never reads it, and waits
/// for the signal that starts its way out (so the test can leave input
/// unread first):
/// - `exit`: SIGUSR1, then `TerminalGuard::release`, which must report
///   success, and exit 0;
/// - `error`: SIGUSR1, then an error returned (the guard dropped on the
///   way), exit 1;
/// - `signal`: SIGTERM or SIGHUP; the guard dropped, then the end by that
///   signal;
/// - `abort`: SIGUSR1, then a panic inside an `extern "C"` function, which
///   cannot unwind, so the process aborts as a release build does, after
///   the panic hook and without the guard's drop;
/// - `stop`: SIGTSTP: restores the terminal and stops; on SIGCONT takes
///   raw mode again, prints `RAW-AGAIN`, waits for SIGUSR1 and exits 0;
/// - `refresh`: as `stop`, but on SIGCONT reads the terminal's settings
///   again (`TerminalGuard::refresh`) before raw mode, and on SIGTERM
///   panics inside an `extern "C"` function, so the process aborts after
///   the panic hook's restore, without the guard's drop;
/// - `final`: SIGUSR1, then the panic hook's restore
///   (`restore_outer_terminal`), then `TerminalGuard::reenter_raw`, which
///   must be refused; prints `REFUSED` and whether the terminal is raw
///   after it, and exits 0.
fn guarded() {
    let scenario = std::env::var(SCENARIO).unwrap();
    if scenario == "abort" || scenario == "refresh" {
        // The abort leaves no core file behind (CI routes core files to a
        // directory gate 19 checks).
        envcloak_sys::disable_core_dumps().unwrap();
        install_panic_hook("pty-test");
    }
    let first: &[i32] = match scenario.as_str() {
        "signal" => &[libc::SIGTERM, libc::SIGHUP],
        "stop" | "refresh" => &[libc::SIGTSTP],
        _ => &[libc::SIGUSR1],
    };
    let relay = SignalRelay::install(first).unwrap();
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let result = (|| -> std::io::Result<()> {
        let mut guard = TerminalGuard::enter_raw(stdin.as_fd())?;
        put(stdout.as_fd(), b"RAW\n");
        let Some(Relayed::Signal { number, .. }) = relay.next()? else {
            panic!("no signal");
        };
        match scenario.as_str() {
            "exit" => {
                guard.release()?;
                return Ok(());
            }
            "error" => return Err(std::io::Error::other("an error on the way out")),
            "signal" => {
                drop(guard);
                exit_by_signal(number);
            }
            "abort" => boom(),
            "final" => {
                assert!(envcloak_sys::restore_outer_terminal(), "nothing restored");
                let again = guard.reenter_raw();
                let raw = TerminalSettings::read(stdin.as_fd())?.is_raw();
                put(
                    stdout.as_fd(),
                    format!(
                        "{} RAW-AFTER={raw}\n",
                        match again {
                            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => "REFUSED",
                            Err(_) => "FAILED",
                            Ok(()) => "TAKEN",
                        }
                    )
                    .as_bytes(),
                );
            }
            "stop" | "refresh" => {
                guard.restore()?;
                // The relay's drop gives SIGTSTP its default action back.
                drop(relay);
                // SAFETY: SIGTSTP to this process itself.
                unsafe { libc::kill(libc::getpid(), libc::SIGTSTP) };
                if scenario == "refresh" {
                    guard.refresh()?;
                }
                guard.reenter_raw()?;
                let done = if scenario == "refresh" {
                    libc::SIGTERM
                } else {
                    libc::SIGUSR1
                };
                let relay = SignalRelay::install(&[done]).unwrap();
                put(stdout.as_fd(), b"RAW-AGAIN\n");
                relay.next()?;
                if scenario == "refresh" {
                    boom();
                }
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

/// What `stty -g` prints for the terminal `fd`: an independent reader of
/// its settings.
fn stty_g(fd: BorrowedFd<'_>) -> String {
    let out = std::process::Command::new("/bin/stty")
        .arg("-g")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::from(fd.try_clone_to_owned().unwrap()))
        .stderr(Stdio::inherit())
        .output()
        .unwrap();
    assert!(out.status.success(), "stty -g failed: {:?}", out.status);
    String::from_utf8(out.stdout).unwrap()
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

/// Types a line the guarded program never reads and waits until the
/// terminal holds it (a barrier, never a sleep).
fn leave_unread(screen: &Screen, slave: &OwnedFd) {
    screen.type_bytes(b"typed-and-not-read\n");
    let deadline = std::time::Instant::now() + DEADLINE;
    while pending_input(slave.as_fd()) == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "the input never arrived"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// The terminal is as it was before: the same settings read through the
/// guard's own type and through `stty -g`, and no input left unread.
fn assert_as_before(slave: &OwnedFd, before: &TerminalSettings, stty_before: &str, what: &str) {
    let after = TerminalSettings::read(slave.as_fd()).unwrap();
    assert!(
        after.same_as(before),
        "{what}: the terminal was left {after:?}, not {before:?}"
    );
    assert_eq!(stty_g(slave.as_fd()), stty_before, "{what}: stty -g");
    assert_eq!(
        pending_input(slave.as_fd()),
        0,
        "{what}: input typed while raw was left for the next reader"
    );
}

/// Waits for the guarded program to end, checks how, and that the
/// terminal is as it was before.
fn assert_restored(
    mut child: std::process::Child,
    slave: &OwnedFd,
    before: &TerminalSettings,
    stty_before: &str,
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
    assert_as_before(slave, before, stty_before, what);
}

/// The way out `scenario` takes once `sig` is sent, with input left unread
/// first.
fn restored_after(
    scenario: &str,
    sig: i32,
    how: impl Fn(std::process::ExitStatus) -> bool,
    what: &str,
) {
    let (master, slave, before) = outer();
    let stty_before = stty_g(slave.as_fd());
    let (child, screen) = start_guarded(scenario, master, &slave);
    leave_unread(&screen, &slave);
    // SAFETY: kill on this process's own, unreaped child.
    assert_eq!(
        unsafe { libc::kill(i32::try_from(child.id()).unwrap(), sig) },
        0
    );
    assert_restored(child, &slave, &before, &stty_before, how, what);
}

fn restored_after_a_normal_exit() {
    restored_after("exit", libc::SIGUSR1, |s| s.code() == Some(0), "exit");
}

fn restored_after_an_error() {
    restored_after("error", libc::SIGUSR1, |s| s.code() == Some(1), "error");
}

fn restored_after_sigterm() {
    restored_after(
        "signal",
        libc::SIGTERM,
        |s| s.signal() == Some(libc::SIGTERM),
        "SIGTERM",
    );
}

fn restored_after_sighup() {
    restored_after(
        "signal",
        libc::SIGHUP,
        |s| s.signal() == Some(libc::SIGHUP),
        "SIGHUP",
    );
}

/// A release build aborts on a panic: no destructor runs, so the guard's
/// drop does not restore. The panic hook does, with `TCSAFLUSH`.
fn restored_after_a_release_abort_by_the_panic_hook() {
    restored_after(
        "abort",
        libc::SIGUSR1,
        |s| s.signal() == Some(libc::SIGABRT),
        "abort",
    );
}

/// SIGTSTP from another process: the terminal is restored, unread input
/// discarded, before the program stops (read while it is stopped), raw
/// again after SIGCONT, and restored at the exit.
fn restored_while_stopped_and_raw_again_after_sigcont() {
    let (master, slave, before) = outer();
    let stty_before = stty_g(slave.as_fd());
    let (child, mut screen) = start_guarded("stop", master, &slave);
    let pid = i32::try_from(child.id()).unwrap();
    leave_unread(&screen, &slave);
    // SAFETY: kill on this process's own, unreaped child.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGTSTP) }, 0);
    assert_eq!(
        wait_child(pid, libc::WSTOPPED),
        Some((libc::CLD_STOPPED, libc::SIGTSTP)),
        "the program did not stop"
    );
    assert_as_before(&slave, &before, &stty_before, "stopped");
    // SAFETY: as above.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGCONT) }, 0);
    screen.expect("RAW-AGAIN\n", 1, "continued");
    assert!(TerminalSettings::read(slave.as_fd()).unwrap().is_raw());
    leave_unread(&screen, &slave);
    // SAFETY: as above.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGUSR1) }, 0);
    assert_restored(
        child,
        &slave,
        &before,
        &stty_before,
        |s| s.code() == Some(0),
        "stop",
    );
}

/// The settings read again after a stop (`TerminalGuard::refresh`; the
/// verifier's review of M2-19, L-09). Changed while the program was
/// stopped, as the person's `stty` would (the suspend character remapped,
/// echo off), they are what raw mode is taken from and what the panic
/// hook's final restore puts back, read by the test and by `stty -g`.
/// Left raw while it was stopped (as a shell that does not take a stopped
/// job's terminal back leaves it), they are not kept: the settings from
/// before come back, never raw ones.
///
/// Mutations checked: keep the settings read again in the guard but not in
/// the panic hook's registration (the abort puts the old ones back), and
/// keep raw settings (the abort leaves the terminal raw): each fails this.
fn the_settings_read_again_after_a_stop_are_what_comes_back() {
    for leave_raw in [false, true] {
        let what = if leave_raw {
            "left raw while stopped"
        } else {
            "changed while stopped"
        };
        let (master, slave, before) = outer();
        let stty_before = stty_g(slave.as_fd());
        // A refresh now requires a foreground owner. Give the guard an
        // actual controlling terminal under the monitor, with an owned
        // group for the stop and resume, rather than an unattached tty.
        let exe = std::env::current_exe().unwrap();
        let mut monitor = spawn_session(
            &[exe.as_os_str()],
            &[
                (OsStr::new("PATH"), OsStr::new("/usr/bin:/bin")),
                (OsStr::new(ROLE), OsStr::new("guarded")),
                (OsStr::new(SCENARIO), OsStr::new("refresh")),
            ],
            slave.try_clone().unwrap(),
        )
        .unwrap();
        let mut screen = Screen::new(master);
        screen.expect("RAW\n", 1, what);
        monitor
            .send(envcloak_sys::pty::MonitorCommand::Suspend)
            .unwrap();
        assert_eq!(
            monitor.next_event(Some(DEADLINE)).unwrap(),
            Some(MonitorEvent::Stopped(libc::SIGTSTP)),
            "{what}"
        );
        let changed = if leave_raw {
            before.raw()
        } else {
            before.with_suspend_char(Some(0x18)).with_echo(false)
        };
        changed.apply(slave.as_fd()).unwrap();
        let stty_changed = stty_g(slave.as_fd());
        monitor
            .send(envcloak_sys::pty::MonitorCommand::Resume)
            .unwrap();
        assert_eq!(
            monitor.next_event(Some(DEADLINE)).unwrap(),
            Some(MonitorEvent::Continued)
        );
        screen.expect("RAW-AGAIN\n", 1, what);
        assert!(
            TerminalSettings::read(slave.as_fd()).unwrap().is_raw(),
            "{what}"
        );
        monitor
            .send(envcloak_sys::pty::MonitorCommand::Signal(libc::SIGTERM))
            .unwrap();
        let (want, stty_want) = if leave_raw {
            (&before, &stty_before)
        } else {
            (&changed, &stty_changed)
        };
        let event = screen.next_event(&mut monitor);
        assert!(
            matches!(event, Some(MonitorEvent::Exited(s)) if s.signal() == Some(libc::SIGABRT)),
            "{what}: {event:?}"
        );
        assert_as_before(&slave, want, stty_want, what);
        monitor.finish().unwrap();
    }
}

/// Input typed while the terminal is raw and never read is discarded when
/// the settings come back (`TCSAFLUSH`): it would otherwise reach the next
/// program to read the terminal, usually the shell. (Every way out above
/// checks this too; this is the plan's named case, on the drop path.)
fn input_typed_and_not_read_is_discarded_on_restore() {
    restored_after("error", libc::SIGUSR1, |s| s.code() == Some(1), "unread");
}

/// The panic hook's restore is final for the guard (Codex's review of PR
/// #27): `reenter_raw` after it is refused and the terminal stays as it
/// was, read inside the program right after the refusal and by the test
/// after the exit (also through `stty -g`). Let `reenter_raw` switch
/// without the slot's check and the terminal is raw again after the
/// restore.
fn raw_mode_is_refused_after_the_final_restore() {
    let (master, slave, before) = outer();
    let stty_before = stty_g(slave.as_fd());
    let (child, mut screen) = start_guarded("final", master, &slave);
    // SAFETY: kill on this process's own, unreaped child.
    assert_eq!(
        unsafe { libc::kill(i32::try_from(child.id()).unwrap(), libc::SIGUSR1) },
        0
    );
    screen.expect("RAW-AFTER=", 1, "the program reports");
    assert!(
        screen.text().contains("REFUSED RAW-AFTER=false"),
        "{}",
        screen.text()
    );
    assert_restored(
        child,
        &slave,
        &before,
        &stty_before,
        |s| s.code() == Some(0),
        "final",
    );
}

fn cloexec(fd: BorrowedFd<'_>) -> bool {
    // SAFETY: F_GETFD only reads a descriptor's flags.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    assert!(flags >= 0, "{}", std::io::Error::last_os_error());
    flags & libc::FD_CLOEXEC != 0
}

/// `open_pty` gives the new slave the outer terminal's settings, so a
/// suspend character the person remapped, or disabled, carries over, and
/// its size; both sides are close-on-exec. Read back through the guard's
/// type and through `stty -g`, whose output must equal the outer
/// terminal's. Ignore the settings and the remapped character is lost.
fn a_new_pty_starts_with_the_outer_settings_and_size() {
    let (_outer_master, outer_slave, cooked) = outer();
    let size = WindowSize {
        rows: 41,
        cols: 97,
        ..WindowSize::default()
    };
    const CTRL_X: u8 = 0x18;
    for (what, settings) in [
        ("suspend remapped", cooked.with_suspend_char(Some(CTRL_X))),
        ("suspend disabled", cooked.with_suspend_char(None)),
        ("echo off", cooked.with_echo(false)),
    ] {
        settings.apply(outer_slave.as_fd()).unwrap();
        let outer_now = TerminalSettings::read(outer_slave.as_fd()).unwrap();
        assert!(outer_now.same_as(&settings), "{what}: the outer terminal");
        let pty = open_pty(Some(size), Some(&outer_now)).unwrap();
        let slave_now = TerminalSettings::read(pty.slave.as_fd()).unwrap();
        assert!(
            slave_now.same_as(&outer_now),
            "{what}: the new PTY has {slave_now:?}, the outer terminal {outer_now:?}"
        );
        assert_eq!(
            stty_g(pty.slave.as_fd()),
            stty_g(outer_slave.as_fd()),
            "{what}: stty -g"
        );
        assert_eq!(window_size(pty.slave.as_fd()).unwrap(), size, "{what}");
        assert!(cloexec(pty.master.as_fd()), "{what}: the master");
        assert!(cloexec(pty.slave.as_fd()), "{what}: the slave");
    }
    let remapped = open_pty(None, Some(&cooked.with_suspend_char(Some(CTRL_X)))).unwrap();
    assert_eq!(
        TerminalSettings::read(remapped.slave.as_fd())
            .unwrap()
            .suspend_char(),
        Some(CTRL_X)
    );
    let disabled = open_pty(None, Some(&cooked.with_suspend_char(None))).unwrap();
    assert_eq!(
        TerminalSettings::read(disabled.slave.as_fd())
            .unwrap()
            .suspend_char(),
        None
    );
}

/// The SIGWINCH probe: prints `WINCH-READY`, waits for SIGWINCH, prints
/// `WINCH` and exits.
fn winch_probe() {
    let relay = SignalRelay::install(&[libc::SIGWINCH]).unwrap();
    put(std::io::stdout().as_fd(), b"WINCH-READY\n");
    let caught = relay.next().unwrap();
    assert!(
        matches!(caught, Some(Relayed::Signal { number, .. }) if number == libc::SIGWINCH),
        "{caught:?}"
    );
    put(std::io::stdout().as_fd(), b"WINCH\n");
}

/// `open_pty` gives the slave the outer size, and `set_window_size` on the
/// master changes it, which the command's foreground group sees with
/// SIGWINCH. The sizes are read inside the PTY by `stty size`, not by the
/// code under test: the command is `sh -c 'stty size; <probe>; stty size'`.
fn the_window_size_reaches_the_command_and_follows_a_change() {
    let start = WindowSize {
        rows: 33,
        cols: 101,
        ..WindowSize::default()
    };
    let pty = open_pty(Some(start), None).unwrap();
    let exe = std::env::current_exe().unwrap();
    let mut monitor = spawn_session(
        &[
            OsStr::new("/bin/sh"),
            OsStr::new("-c"),
            OsStr::new("stty size; \"$WINCH_PROBE\"; stty size"),
        ],
        &[
            (OsStr::new("PATH"), OsStr::new("/usr/bin:/bin")),
            (OsStr::new("WINCH_PROBE"), exe.as_os_str()),
            (OsStr::new(ROLE), OsStr::new("winch")),
        ],
        pty.slave,
    )
    .unwrap();
    let mut screen = Screen::new(pty.master);
    screen.expect("33 101\r\n", 1, "stty size at the start");
    screen.expect("WINCH-READY", 1, "the probe runs");
    let changed = WindowSize {
        rows: 48,
        cols: 160,
        ..WindowSize::default()
    };
    set_window_size(screen.master(), changed).unwrap();
    screen.expect("WINCH\r\n", 1, "SIGWINCH after a change");
    screen.expect("48 160\r\n", 1, "stty size after a change");
    let event = screen.next_event(&mut monitor);
    assert!(
        matches!(event, Some(MonitorEvent::Exited(s)) if s.success()),
        "{event:?}\n{}",
        screen.text()
    );
    monitor.finish().unwrap();
}

/// What the command writes just before it exits still reaches the master
/// side when the CLI reads it late: nothing is read until a second after
/// the command could have exited; then the line is there, and the exit is
/// reported. (The case where macOS's close of the slave loses a late
/// line, and the monitor's wait for the read that prevents it, is (b) in
/// `pty_topology.rs`.) Flush the terminal's output at the exit and the
/// line is gone.
fn the_last_output_before_the_exit_is_not_lost_at_the_close() {
    let pty = open_pty(None, None).unwrap();
    let mut monitor = spawn_session(
        &[
            OsStr::new("/bin/sh"),
            OsStr::new("-c"),
            OsStr::new("printf 'last-words\\n'"),
        ],
        &[(OsStr::new("PATH"), OsStr::new("/usr/bin:/bin"))],
        pty.slave,
    )
    .unwrap();
    let mut screen = Screen::new(pty.master);
    // Nothing read for a second: the command has exited by then.
    let early = monitor.next_event(Some(Duration::from_secs(1))).unwrap();
    screen.wait_for(|s| s.count("last-words\r\n") == 1);
    assert_eq!(
        screen.count("last-words\r\n"),
        1,
        "the command's last line was lost: {:?}",
        screen.text()
    );
    let event = match early {
        Some(event) => Some(event),
        None => screen.next_event(&mut monitor),
    };
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

/// Whether the kernel reaps this process's children on its own now: a
/// probe child is waited for, which fails (`ECHILD`) when it was reaped
/// already.
fn reaps_on_its_own() -> bool {
    let mut probe = std::process::Command::new("/bin/sh")
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
/// (XNU marks the process so when `sigaction` ignores SIGCHLD).
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

/// The CLI stand-in started with its children reaped on their own as
/// `ENVCLOAK_PTY_SCENARIO` says ([`REAPING`]): reports its setup and
/// whether the kernel does reap on its own, runs a command that exits 7
/// under the monitor, and reports what `finish` returned (the monitor's
/// own status, which needs the monitor unreaped until then) and the setup
/// after.
fn sigchld_ignored() {
    use envcloak_sys::testing::{ChildReaping, set_sigchld};
    match std::env::var(SCENARIO).as_deref() {
        Ok("no-wait") => set_sigchld(ChildReaping::NoWait).unwrap(),
        Ok("ignored-here") => set_sigchld(ChildReaping::Ignored).unwrap(),
        _ => {}
    }
    let out = std::io::stdout();
    let said = |s: String| put(out.as_fd(), s.as_bytes());
    said(format!(
        "SETUP-AT-START {:?}\nREAPS-AT-START {}\n",
        envcloak_sys::testing::sigchld_setup(),
        reaps_on_its_own()
    ));
    let pty = open_pty(None, None).unwrap();
    let mut monitor = spawn_session(
        &[
            OsStr::new("/bin/sh"),
            OsStr::new("-c"),
            OsStr::new("exit 7"),
        ],
        &[(OsStr::new("PATH"), OsStr::new("/usr/bin:/bin"))],
        pty.slave,
    )
    .unwrap();
    let event = monitor.next_event(Some(DEADLINE)).unwrap();
    said(format!(
        "EXITED {:?}\n",
        match event {
            Some(MonitorEvent::Exited(s)) => s.code(),
            _ => None,
        }
    ));
    let finished = monitor.finish();
    said(format!(
        "FINISH {}\nSETUP-AFTER {:?}\nREAPS-AFTER {}\n",
        match &finished {
            Ok(s) => format!("ok {:?}", s.code()),
            Err(e) => format!("error {:?}", e.raw_os_error()),
        },
        envcloak_sys::testing::sigchld_setup(),
        reaps_on_its_own()
    ));
    drop(pty.master);
}

/// A CLI that has its children reaped by the kernel on their own (each of
/// [`REAPING`]) would have its monitor reaped the moment it exits where
/// the kernel does so (Linux for all three; on macOS 26.4.1 for
/// `SA_NOCLDWAIT` and for SIGCHLD ignored in the process, not for one
/// inherited across `exec`, measured and printed), its pid, the session's
/// id and the handle's signal target, free for reuse while the handle
/// still holds it. `spawn_session` gives SIGCHLD its default back, without
/// `SA_NOCLDWAIT`, before the fork, so the monitor stays unreaped until
/// `finish` reaps it, which returns its status. Skip that and the setup is
/// still there after (both systems) and `finish` fails with `ECHILD` where
/// the kernel reaped on its own.
fn a_cli_that_inherited_sigchld_ignored_still_owns_its_monitor() {
    for (how, setup) in REAPING {
        let mut cmd = role("sigchld-ignored");
        cmd.env(SCENARIO, how)
            .stdin(Stdio::null())
            .stderr(Stdio::inherit());
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
        assert!(text.contains("EXITED Some(7)"), "{how}: {text}");
        assert!(
            text.contains("FINISH ok Some(0)"),
            "{how}: the monitor was not this process's to reap:\n{text}"
        );
        assert!(
            text.contains("SETUP-AFTER (false, false)") && text.contains("REAPS-AFTER false"),
            "{how}: {text}"
        );
        let reaped = text.contains("REAPS-AT-START true");
        println!(
            "pty ({}): SIGCHLD {how}: the kernel reaps children on its own: {reaped}; \
             the monitor stayed this process's to reap",
            std::env::consts::OS
        );
    }
}
