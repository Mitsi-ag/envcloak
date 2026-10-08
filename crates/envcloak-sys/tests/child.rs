//! `wait_for_exit`, `signal_process` and `signal_group` against real
//! children: an exited child stays waitable (its pid is not reused before
//! it is reaped), a stopped child has not exited, and a signal reaches
//! one process or a whole group.
#![allow(unsafe_code, clippy::unwrap_used)]

use std::io::{BufRead, BufReader};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, Stdio};

use std::time::{Duration, Instant};

use envcloak_sys::{has_exited, proc_info, signal_group, signal_process, wait_for_exit};

#[test]
fn an_exited_child_stays_waitable_until_it_is_reaped() {
    let mut child = Command::new("/bin/sh")
        .args(["-c", "exit 7"])
        .spawn()
        .unwrap();
    let pid = i32::try_from(child.id()).unwrap();
    wait_for_exit(pid).unwrap();
    // Exited but not reaped: the pid is still this child's, and waiting
    // again returns at once.
    wait_for_exit(pid).unwrap();
    assert_eq!(child.wait().unwrap().code(), Some(7));
    // Reaped: no longer a child of this process.
    assert_eq!(
        wait_for_exit(pid).unwrap_err().raw_os_error(),
        Some(libc::ECHILD)
    );
}

/// The numeric wrappers themselves, which clippy.toml bans elsewhere
/// (D-34; this file is listed in security/signal-allowlist.txt).
#[test]
#[allow(clippy::disallowed_methods)]
fn a_signal_reaches_the_process_or_its_whole_group() {
    // A shell leading its own group, with a background sleeper in the
    // group; both report their pids, then wait.
    let mut leader = Command::new("/bin/sh")
        .args(["-c", "sleep 60 & echo $!; echo $$; wait"])
        .process_group(0)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(leader.stdout.take().unwrap()).lines();
    let sleeper: i32 = lines.next().unwrap().unwrap().parse().unwrap();
    let shell: i32 = lines.next().unwrap().unwrap().parse().unwrap();
    assert_eq!(shell, i32::try_from(leader.id()).unwrap());
    assert!(proc_info(sleeper).is_ok());

    // The whole group: the sleeper dies too, and the shell with it.
    signal_group(shell, libc::SIGTERM).unwrap();
    let status = leader.wait().unwrap();
    assert!(
        status.signal() == Some(libc::SIGTERM) || status.code() == Some(128 + libc::SIGTERM),
        "{status:?}"
    );
    let gone = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while signal_process(sleeper, 0).is_ok() {
        assert!(
            std::time::Instant::now() < gone,
            "the group's sleeper lived"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    // One process: only it.
    let mut one = Command::new("/bin/sleep").arg("60").spawn().unwrap();
    signal_process(i32::try_from(one.id()).unwrap(), libc::SIGKILL).unwrap();
    assert_eq!(one.wait().unwrap().signal(), Some(libc::SIGKILL));
}

/// Waits, consuming nothing, until this process's own child `pid` has a
/// stop to report (`WSTOPPED | WNOWAIT`), up to `limit`.
fn stop_unconsumed(pid: i32, limit: Duration) -> bool {
    let end = Instant::now() + limit;
    loop {
        // SAFETY: siginfo_t is plain data; waitid fills it in.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: `info` is writable; `pid` is this process's own child, and
        // WNOWAIT leaves its stop where it is.
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                libc::id_t::try_from(pid).unwrap(),
                &mut info,
                libc::WSTOPPED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        // SAFETY: waitid filled `info` in or left it zeroed.
        if rc == 0 && unsafe { info.si_pid() } == pid && info.si_code == libc::CLD_STOPPED {
            return true;
        }
        if Instant::now() >= end {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// A child that stopped itself, its stop consumed by no one, has not
/// exited: `has_exited` says so and `wait_for_exit` keeps waiting, and
/// neither consumes the stop. macOS's `waitid` returns that stop
/// (`CLD_STOPPED`) to a call asked for exits only (measured on macOS
/// 26.4); read as an exit, `envcloak run` took a stopped command for an
/// ended one and stopped passing signals on to it. Continued, it exits,
/// and both see that. Count any record as an exit and the first two
/// assertions fail on macOS.
#[test]
fn a_stopped_child_has_not_exited() {
    let mut child = Command::new("/bin/sh")
        .args(["-c", "kill -STOP $$; exit 7"])
        .spawn()
        .unwrap();
    let pid = i32::try_from(child.id()).unwrap();
    assert!(
        stop_unconsumed(pid, Duration::from_secs(10)),
        "it did not stop"
    );
    assert!(!has_exited(pid).unwrap(), "a stopped child read as exited");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || tx.send(wait_for_exit(pid)));
    assert!(
        rx.recv_timeout(Duration::from_millis(500)).is_err(),
        "wait_for_exit returned for a stopped child"
    );
    assert!(
        stop_unconsumed(pid, Duration::ZERO),
        "the stop was consumed"
    );
    assert_eq!(envcloak_sys::testing::kill_raw(pid, libc::SIGCONT), 0);
    rx.recv_timeout(Duration::from_secs(10))
        .expect("wait_for_exit did not see the exit")
        .unwrap();
    assert!(has_exited(pid).unwrap());
    assert_eq!(child.wait().unwrap().code(), Some(7));
}
