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

#[test]
fn a_second_open_of_a_locked_file_cannot_lock_it() {
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

#[test]
fn the_clock_pair_advances_together_while_awake() {
    let (a0, s0) = (awake_time().unwrap(), time_including_sleep().unwrap());
    std::thread::sleep(Duration::from_millis(200));
    let (a1, s1) = (awake_time().unwrap(), time_including_sleep().unwrap());
    let awake = a1 - a0;
    let total = s1 - s0;
    assert!(awake >= Duration::from_millis(150), "{awake:?}");
    assert!(total >= Duration::from_millis(150), "{total:?}");
    // Nothing slept here, so neither clock ran ahead by more than noise.
    // Only deltas compare: the two clocks need not share an origin.
    let gap = total.abs_diff(awake);
    assert!(gap < Duration::from_millis(100), "{awake:?} {total:?}");
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
