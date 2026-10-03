//! `envcloak run --status-fd N`'s own failures, before any daemon is
//! asked (M2 plan M2-RES1): a status descriptor that is not open, and a
//! sweep of the inherited descriptors that cannot list them, each start
//! nothing and say so, the second in its status record (Codex review of
//! M2-RES1: a sweep that could not list the descriptors guessed at their
//! numbers and reported success).
#![allow(clippy::unwrap_used)]

mod common;

use std::time::Duration;

use common::{cli_command, finish_within, outside_dir, python3, stderr};
use envcloak_client::run_status::RunStatus;
use envcloak_testkit::TestHome;

/// Marks that it ran by making the file argv[1] names.
const MARKS_IT_RAN: &str = "import sys\nopen(sys.argv[1], 'w').close()\n";

/// The run's own failures with a status descriptor: one that is not open
/// is a usage error (exit 2) before anything; a sweep whose listing of the
/// inherited descriptors fails (`/dev/fd` unreadable, made to fail in a
/// test build) refuses with `run_failed`, recorded `not_started`, exit 125.
/// Neither starts the command, whose mark stays absent. Control: with the
/// listing working and no daemon, the run gets past the sweep and records
/// `daemon_unavailable`.
///
/// Mutation checked: the sweep falling back to the numbers up to the soft
/// `RLIMIT_NOFILE` when the listing fails, as before: the run goes on to
/// ask for the daemon, the record says `daemon_unavailable` and this
/// fails.
#[test]
fn the_status_descriptors_own_failures_start_nothing() {
    let home = TestHome::new();
    let files = outside_dir();
    let mark = files.path().join("ran");
    let status = files.path().join("status");
    let py = python3();
    let args = [
        "run",
        "--status-fd",
        "9",
        "--",
        py.to_str().unwrap(),
        "-c",
        MARKS_IT_RAN,
        mark.to_str().unwrap(),
    ];
    let limit = Duration::from_secs(60);

    // Descriptor 9 is not open.
    let out = finish_within(cli_command(&home, &args, &[]), limit);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("envcloak: --status-fd names a descriptor that is not open"),
        "{}",
        stderr(&out)
    );
    assert!(!mark.exists(), "the command ran");

    // The listing of the inherited descriptors fails.
    let mut cmd = cli_command(&home, &args, &[(9, &status, false)]);
    cmd.env(envcloak_sys::testing::FAIL_SITE, "sys.fd.listing");
    let out = finish_within(cmd, limit);
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("envcloak: run_failed: the descriptors this run inherited"),
        "{}",
        stderr(&out)
    );
    assert_eq!(
        RunStatus::decode(&std::fs::read(&status).unwrap()),
        Some(RunStatus::NotStarted {
            token: "run_failed".into(),
            request: None,
        })
    );
    assert!(!mark.exists(), "the command ran");

    // Control: the listing works; with no daemon, nothing runs either.
    let out = finish_within(cli_command(&home, &args, &[(9, &status, false)]), limit);
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    assert_eq!(
        RunStatus::decode(&std::fs::read(&status).unwrap()),
        Some(RunStatus::NotStarted {
            token: "daemon_unavailable".into(),
            request: None,
        })
    );
    assert!(!mark.exists(), "the command ran");
}
