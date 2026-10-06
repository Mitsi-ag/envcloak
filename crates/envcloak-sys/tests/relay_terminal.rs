//! `SignalRelay` against a real terminal (review R-10): the kernel, not a
//! test, says who sent each signal. A copy of this binary leads a new
//! session whose controlling terminal is a new pseudo-terminal, installs a
//! relay for SIGINT, and reports each signal it catches. This process,
//! outside that session, types Ctrl-C on the terminal, so the line
//! discipline sends SIGINT to the terminal's foreground process group:
//! that must read as the terminal's (`by_process: false`), on Linux
//! (`SI_KERNEL`) and on macOS (a live sender in another session) alike.
//! The copy then sends itself SIGINT by pid, which must read as sent by a
//! process. A handler that took every signal for a process's would pass
//! every other Linux test; this one fails it.
//!
//! No libtest harness (`harness = false`): the copy is this binary, and
//! the signals must reach a process that runs nothing else.
#![allow(unsafe_code, clippy::unwrap_used)]

use std::io::{BufRead, BufReader, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use envcloak_sys::{Relayed, SignalRelay};

const CHILD_ENV: &str = "ENVCLOAK_SYS_RELAY_TERMINAL_CHILD";

fn main() {
    if std::env::var_os(CHILD_ENV).is_some() {
        return child();
    }
    parent();
    println!("relay_terminal: a terminal's Ctrl-C and a kill by pid are told apart");
}

/// The copy: its standard input is the terminal's slave side. Prints
/// `ready`, then `caught <signal> <by_process>` for the terminal's SIGINT
/// and for its own.
fn child() {
    envcloak_sys::testing::setsid().unwrap();
    // SAFETY: fd 0 is the pseudo-terminal's slave side, and this process
    // leads a session without a controlling terminal; argument 0 steals
    // none.
    let rc = unsafe { libc::ioctl(0, libc::TIOCSCTTY as _, 0) };
    assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
    let relay = SignalRelay::install(&[libc::SIGINT]).unwrap();
    let report = |caught: Option<Relayed>| {
        let Some(Relayed::Signal { number, by_process }) = caught else {
            panic!("no signal: {caught:?}");
        };
        let mut out = std::io::stdout().lock();
        writeln!(out, "caught {number} {by_process}").unwrap();
        out.flush().unwrap();
    };
    {
        let mut out = std::io::stdout().lock();
        writeln!(out, "ready").unwrap();
        out.flush().unwrap();
    }
    report(relay.next().unwrap());
    let me = i32::try_from(std::process::id()).unwrap();
    assert_eq!(envcloak_sys::testing::kill_raw(me, libc::SIGINT), 0);
    report(relay.next().unwrap());
}

/// A new pseudo-terminal, its master and slave sides, with signal
/// characters on and Ctrl-C as the interrupt character.
fn pty() -> (OwnedFd, OwnedFd) {
    let (mut m, mut s): (libc::c_int, libc::c_int) = (-1, -1);
    // SAFETY: `m` and `s` are writable; a null name, termios and window
    // size are allowed and leave the defaults.
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
    // SAFETY: openpty returned two open descriptors that nothing else owns.
    let (master, slave) = unsafe { (OwnedFd::from_raw_fd(m), OwnedFd::from_raw_fd(s)) };
    // SAFETY: termios is plain data; tcgetattr fills it in.
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: `t` is a writable termios; the slave side is open.
    assert_eq!(unsafe { libc::tcgetattr(slave.as_raw_fd(), &mut t) }, 0);
    t.c_lflag |= libc::ISIG;
    t.c_cc[libc::VINTR] = 0x03;
    // SAFETY: `t` is an initialized termios; the slave side is open.
    assert_eq!(
        unsafe { libc::tcsetattr(slave.as_raw_fd(), libc::TCSANOW, &t) },
        0
    );
    (master, slave)
}

fn parent() {
    let (master, slave) = pty();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .env_clear()
        .env(CHILD_ENV, "1")
        .stdin(Stdio::from(slave))
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    // The copy's lines, read on a thread so each wait is bounded: a copy
    // that never reports is killed, and the test fails rather than waits.
    let (tx, lines) = mpsc::channel();
    let stdout = child.stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if tx.send(line.unwrap()).is_err() {
                return;
            }
        }
    });
    let mut next = || {
        lines
            .recv_timeout(Duration::from_secs(30))
            .unwrap_or_else(|_| {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the copy did not report in time");
            })
    };
    assert_eq!(next(), "ready");
    // Ctrl-C, typed on the terminal from outside its session.
    let mut typed = std::fs::File::from(master.try_clone().unwrap());
    typed.write_all(&[0x03]).unwrap();
    assert_eq!(
        next(),
        format!("caught {} false", libc::SIGINT),
        "the terminal's Ctrl-C read as sent by a process"
    );
    assert_eq!(
        next(),
        format!("caught {} true", libc::SIGINT),
        "a kill by pid read as the terminal's"
    );
    let status = child.wait().unwrap();
    assert!(status.success(), "{status:?}");
    drop(master);
}
