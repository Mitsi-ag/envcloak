//! Gates 34, 23, 33 and 19: terminal reveal (M2-21).
#![allow(clippy::unwrap_used)]

mod common;

use std::os::unix::fs::PermissionsExt;

use envcloak_testkit::{TestHome, assert_no_canary, canaries, fresh_seed};

/// Observe connection attempts independently of the client. A real
/// `status` attempt is the positive control, even with no valid daemon.
#[test]
fn reveal_without_a_terminal_never_contacts_the_daemon() {
    let home = TestHome::new();
    let dir = envcloak_testkit::daemon_run_dir(&home);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let listener = std::os::unix::net::UnixListener::bind(
        envcloak_testkit::daemon_socket(&home),
    ).unwrap();
    listener.set_nonblocking(true).unwrap();
    let out = common::run(&home, &["reveal", "example/item"], &[]);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    let token = if cfg!(target_os = "macos") { "app_required" } else { "no_terminal" };
    assert!(common::stderr(&out).starts_with(&format!("envcloak: {token}:")));
    if cfg!(target_os = "macos") {
        assert_eq!(out.status.code(), Some(125));
    }
    assert_eq!(listener.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    let control = common::run(&home, &["status"], &[]);
    assert!(!control.status.success());
    assert!(listener.accept().is_ok(), "the observer missed its connection control");
}

#[test]
fn reveal_arguments_never_echo_hostile_input() {
    let home = TestHome::new();
    let cs = canaries(fresh_seed());
    let long = "x".repeat(100_000);
    for target in ["", "a#", "a#b#c", "a\u{1b}[31m", "a\u{202e}", long.as_str()]
        .into_iter().chain(cs.iter().map(|c| c.as_str()))
    {
        let out = common::run(&home, &["reveal", target], &[]);
        assert!(!out.status.success());
        assert!(out.stdout.is_empty());
        assert_no_canary(&out.stderr, &cs);
        assert!(out.stderr.len() < 1024);
    }
    for extra in ["--stdout", "--json", "--passphrase-fd", "--stdin"] {
        let out = common::run(&home, &["reveal", "example/item", extra], &[]);
        assert!(!out.status.success());
        assert!(out.stdout.is_empty());
    }
}
