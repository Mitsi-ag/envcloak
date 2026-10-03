//! The OS interfaces the daemon and CLI stand on (SPEC §4.2, §5 "Lock"):
//! `flock`, the termination signals, the clock pair, descriptors named by
//! number, and secret input on a terminal.
#![allow(clippy::unwrap_used)]

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::time::Duration;

use envcloak_sys::{
    SecretInput, TerminationSignals, awake_time, cloexec_flag, inherited_fd, time_including_sleep,
    try_lock_exclusive,
};

/// Held by the test that starts children and by the lock test: a child
/// forked while the lock test holds its first open file keeps a copy of
/// that descriptor until it runs its program, so the lock would outlast
/// the test's own close (a CI failure of M2-RES1's pull request, on
/// Linux).
static FORKS: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn no_forks() -> std::sync::MutexGuard<'static, ()> {
    FORKS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[test]
fn a_second_open_of_a_locked_file_cannot_lock_it() {
    let _no_forks = no_forks();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("envcloakd.lock");
    let open = || {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap()
    };
    let first = open();
    assert!(try_lock_exclusive(&first).unwrap());
    // The same open file description may take it again.
    assert!(try_lock_exclusive(&first).unwrap());
    // Another one, even in this process, may not.
    let second = open();
    assert!(!try_lock_exclusive(&second).unwrap());
    drop(first);
    assert!(try_lock_exclusive(&second).unwrap());
}

#[test]
fn a_blocked_termination_signal_waits_for_sigwait() {
    // Blocks the set in this test's thread only; the signal is sent to this
    // thread, so no other thread can take it.
    let signals = TerminationSignals::block().unwrap();
    for sig in TerminationSignals::SIGNALS {
        envcloak_sys::testing::signal_this_thread(sig).unwrap();
        assert_eq!(signals.wait().unwrap(), sig);
    }
    assert!(format!("{signals:?}").contains("SIGTERM"));
}

/// A child started with `unblock_termination_on_spawn`, by a thread that
/// blocks the termination signals (as every thread of `envcloak mcp`
/// does), has none of them blocked: a shell that sends itself each one
/// ends by it. Started without it, the same shell goes on past its own
/// signal and says so: the positive control, that the mask is inherited
/// and the test can fail (Codex review of M2-06, high).
///
/// Mutation checked: `unblock_termination_on_spawn` adding nothing to the
/// command: each shell goes on past its signal and this fails.
#[test]
fn a_child_can_start_with_the_termination_signals_unblocked() {
    use std::os::unix::process::ExitStatusExt;
    let _forks = no_forks();
    // On a thread of its own, whose mask ends with it.
    std::thread::spawn(|| {
        let _blocked = TerminationSignals::block().unwrap();
        for (sig, name) in [
            (libc::SIGTERM, "TERM"),
            (libc::SIGINT, "INT"),
            (libc::SIGHUP, "HUP"),
        ] {
            let shell = |unblocked: bool| {
                let mut cmd = std::process::Command::new("/bin/sh");
                cmd.arg("-c")
                    .arg(format!("kill -{name} $$; echo went-on"))
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin");
                if unblocked {
                    envcloak_sys::unblock_termination_on_spawn(&mut cmd).unwrap();
                }
                cmd.output().unwrap()
            };
            let kept = shell(false);
            assert_eq!(
                (kept.status.code(), kept.stdout.as_slice()),
                (Some(0), &b"went-on\n"[..]),
                "{name}: the blocked mask was not inherited"
            );
            let freed = shell(true);
            assert_eq!(
                freed.status.signal(),
                Some(sig),
                "{name}: {:?}",
                freed.status
            );
            assert!(freed.stdout.is_empty(), "{name}");
        }
    })
    .join()
    .unwrap();
}

/// Reads time awake, time including sleep, then time awake again, 50
/// times, and keeps the reading whose two awake reads were closest: the
/// middle read then happened, in awake time, within that gap after the
/// first. Returns (awake, including sleep, gap).
fn pinned_reading() -> (Duration, Duration, Duration) {
    (0..50)
        .map(|_| {
            let a = awake_time().unwrap();
            let s = time_including_sleep().unwrap();
            let gap = awake_time().unwrap() - a;
            (a, s, gap)
        })
        .min_by_key(|r| r.2)
        .unwrap()
}

/// The clock pair shares an origin and a timebase: time including sleep is
/// time awake plus the time the machine has slept since boot. So it never
/// trails time awake, and while nothing sleeps the two advance by the same
/// amount, to within how closely each reading is pinned (plus 250 ns for
/// clock ticks). macOS pairs CLOCK_MONOTONIC_RAW with CLOCK_UPTIME_RAW,
/// both counts of the mach timebase; CLOCK_MONOTONIC, the calendar clock
/// less the boot time, has microsecond steps, ran behind CLOCK_UPTIME_RAW
/// on a CI runner, and drifted from it by 1 to 13 µs in 2 s on a Mac.
#[test]
fn the_clock_pair_shares_an_origin_and_a_timebase() {
    let (a0, s0, g0) = pinned_reading();
    assert!(
        s0 >= a0,
        "time including sleep {s0:?} trails time awake {a0:?}"
    );
    std::thread::sleep(Duration::from_secs(2));
    let (a1, s1, g1) = pinned_reading();
    let awake = a1 - a0;
    let total = s1 - s0;
    assert!(awake >= Duration::from_millis(1900), "{awake:?}");
    let slack = g0 + g1 + Duration::from_nanos(250);
    assert!(
        total.abs_diff(awake) <= slack,
        "awake {awake:?}, including sleep {total:?}, allowed {slack:?}"
    );
}

#[test]
fn an_inherited_descriptor_is_copied_with_cloexec() {
    let mut f = tempfile::tempfile().unwrap();
    f.write_all(b"from the descriptor").unwrap();
    f.rewind().unwrap();
    let copy = inherited_fd(f.as_raw_fd()).unwrap();
    assert_ne!(copy.as_raw_fd(), f.as_raw_fd());
    assert!(copy.as_raw_fd() > 2);
    assert!(cloexec_flag(copy.as_fd()).unwrap());
    let mut text = String::new();
    File::from(copy).read_to_string(&mut text).unwrap();
    assert_eq!(text, "from the descriptor");
    // The original is still open.
    assert!(cloexec_flag(f.as_fd()).unwrap());

    let err = inherited_fd(-1).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    // A number that is not open.
    let err = inherited_fd(100_000).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EBADF));
}

#[test]
fn secret_input_needs_a_terminal() {
    let f = tempfile::tempfile().unwrap();
    let err = SecretInput::begin(f.as_fd()).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::ENOTTY), "{err}");
}
