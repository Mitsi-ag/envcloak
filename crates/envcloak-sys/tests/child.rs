//! `wait_for_exit`, `signal_process` and `signal_group` against real
//! children: an exited child stays waitable (its pid is not reused before
//! it is reaped), and a signal reaches one process or a whole group.
#![allow(clippy::unwrap_used)]

use std::io::{BufRead, BufReader};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, Stdio};

use envcloak_sys::{proc_info, signal_group, signal_process, wait_for_exit};

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

#[test]
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
