//! `envcloak run --status-fd N`'s own failures, before any daemon is
//! asked (M2 plan M2-RES1): a status descriptor that is not open, and a
//! sweep of the inherited descriptors that cannot list them, each start
//! nothing and say so, the second in its status record (Codex review of
//! M2-RES1: a sweep that could not list the descriptors guessed at their
//! numbers and reported success). And what the record carries of a
//! daemon's answer that a program answering in its place chose (M2-13):
//! no name shaped like a key.
#![allow(clippy::unwrap_used)]

mod common;

use std::time::Duration;

use common::{cli_command, finish_within, outside_dir, python3, stderr};
use envcloak_client::run_status::RunStatus;
use envcloak_testkit::{TestHome, assert_no_canary, canaries, fresh_seed};

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
        Some(RunStatus::not_started("run_failed"))
    );
    assert!(!mark.exists(), "the command ran");

    // Control: the listing works; with no daemon, nothing runs either.
    let out = finish_within(cli_command(&home, &args, &[(9, &status, false)]), limit);
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    assert_eq!(
        RunStatus::decode(&std::fs::read(&status).unwrap()),
        Some(RunStatus::not_started("daemon_unavailable"))
    );
    assert!(!mark.exists(), "the command ran");
}

/// The status record goes to a descriptor that can be a regular file,
/// read later by anyone, where no name is hidden for it (Codex, round 3:
/// the record carried the proposals' names as the daemon sent them, while
/// the terminal line and the MCP message hid one shaped like a key). A
/// program answering in the daemon's place, on its socket, answers
/// `run.request` pending with proposals whose names are generated
/// canaries' tokens, each of a name's grammar, beside an ordinary one:
/// the run's line hides them, and the record, a regular file, names the
/// ordinary proposal only and counts the others; its raw bytes hold no
/// canary and no token. The command never starts.
///
/// Mutation: `RunStatus::approval_required` keeping every proposal (its
/// `proposal_shown_whole` filter dropped): the run fails to write the
/// record at all (the writer refuses what the reader would not take), and
/// with the reader's check dropped too the tokens are in the file; this
/// fails either way.
#[test]
fn a_status_file_holds_no_name_shaped_like_a_key() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    use envcloak_ipc::proto::{IncomingRequest, RunAnswer, result_frame};
    use envcloak_policy::{BindingSource, Proposal};

    let home = TestHome::new();
    let cs = canaries(fresh_seed());
    let token: String = cs
        .iter()
        .flat_map(|c| c.value().to_vec())
        .filter(u8::is_ascii_alphanumeric)
        .map(|b| char::from(b).to_ascii_lowercase())
        .take(42)
        .chain("x1y2z3".chars())
        .collect();
    let x = |env: &str, live: &str, test: &str| Proposal {
        env_name: env.to_owned(),
        live_slug: live.to_owned(),
        test_slug: test.to_owned(),
        test_field: None,
        source: BindingSource::Env,
    };
    let key = format!("stripe/{token}");
    let proposals = vec![
        x("STRIPE_SECRET_KEY", "stripe/acme-live", "stripe/acme-test"),
        x("A_KEY", &key, "stripe/acme-test"),
        x("B_KEY", "stripe/acme-live", &key),
        x(
            &format!("K{}", token.to_ascii_uppercase()),
            "stripe/acme-live",
            "stripe/acme-test",
        ),
    ];
    let dir = envcloak_testkit::daemon_run_dir(&home);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let l = UnixListener::bind(envcloak_testkit::daemon_socket(&home)).unwrap();
    let answer = RunAnswer::pending("ABCDEFGH".to_owned(), proposals);
    let server = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        let f = envcloak_ipc::Frame::read_from(&mut s).unwrap();
        let req = IncomingRequest::parse(&f).unwrap();
        assert_eq!(req.method, "run.request");
        result_frame(req.id, &answer)
            .unwrap()
            .write_to(&mut s)
            .unwrap();
    });
    let files = outside_dir();
    let status = files.path().join("status");
    let mark = files.path().join("ran");
    let py = python3();
    let args = [
        "run",
        "--status-fd",
        "9",
        "--manifest",
        "/nowhere/acme/envcloak.toml",
        "--",
        py.to_str().unwrap(),
        "-c",
        MARKS_IT_RAN,
        mark.to_str().unwrap(),
    ];
    let out = finish_within(
        cli_command(&home, &args, &[(9, &status, false)]),
        Duration::from_secs(60),
    );
    server.join().unwrap();
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(125), "{err}");
    assert!(!mark.exists(), "the command ran");
    // The line hides them, and names the ordinary one.
    assert!(!err.to_ascii_lowercase().contains(&token), "{err}");
    assert!(err.contains(envcloak_client::render::HIDDEN), "{err}");
    assert!(
        err.contains(
            "STRIPE_SECRET_KEY is bound to the live key stripe/acme-live: to use the test key \
             stripe/acme-test instead, run `envcloak ref --manifest /nowhere/acme/envcloak.toml \
             STRIPE_SECRET_KEY=stripe/acme-test`"
        ),
        "{err}"
    );
    // The record: the ordinary one named, the rest counted; no byte of
    // any of them.
    let bytes = std::fs::read(&status).unwrap();
    assert_no_canary(&bytes, &cs);
    assert!(
        !String::from_utf8_lossy(&bytes)
            .to_ascii_lowercase()
            .contains(&token),
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    assert_eq!(
        RunStatus::decode(&bytes),
        Some(RunStatus::NotStarted {
            token: "approval_required".to_owned(),
            request: envcloak_policy::PendingId::parse("ABCDEFGH"),
            proposals: vec![x(
                "STRIPE_SECRET_KEY",
                "stripe/acme-live",
                "stripe/acme-test"
            )],
            proposals_left_out: 3,
        })
    );
}
