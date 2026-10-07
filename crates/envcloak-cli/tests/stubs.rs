//! The commands and options of M2 and M2b that later tasks land (M2 plan
//! D-23, R-M2-01): this build registers each one, and each exits 125 with
//! `not_in_this_build`, prints nothing on standard output and one fixed
//! line on standard error, whatever its arguments, one that is not UTF-8
//! included. Key-shaped ones (every canary, as an argument, an option's
//! value or a command after `--`) are never echoed. A listener on the
//! daemon's socket path sees no connection from any of them (with a
//! positive control that a command asking the daemon is seen), and the
//! home holds the same files after them as before (review M2R-10: the
//! test claimed both, and checked neither). The help lists every one of
//! them as not in this build, and never as available.
#![allow(clippy::unwrap_used)]

mod common;

use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use common::{cli_command, finish_within, run, stderr, stdout};
use envcloak_testkit::{TestHome, assert_no_canary, canaries, fresh_seed};

/// Each registered command or option (the words that select it) and how
/// its refusal names it.
const STUBS: &[(&[&str], &str)] = &[
    (&["scrub"], "`envcloak scrub`"),
    (&["agents", "migrate-mcp"], "`envcloak agents migrate-mcp`"),
    (&["mcp-bridge"], "`envcloak mcp-bridge`"),
    (&["standing"], "`envcloak standing`"),
    (&["login"], "`envcloak login`"),
    (&["signin"], "`envcloak signin`"),
];

/// Exit code of a stub, as of `run`'s own failures.
const NOT_IN_THIS_BUILD: i32 = 125;

/// The arguments tried after each stub's words, `{v}` standing for a
/// canary: none, the usual options, a value where a value could be pasted,
/// an option's value and a command.
const TAILS: &[&[&str]] = &[
    &[],
    &["--help"],
    &["--json"],
    &["{v}"],
    &["--value", "{v}"],
    &["--slug", "{v}", "--json"],
    &["--", "{v}"],
    &[
        "--url",
        "https://{v}.example/",
        "--header",
        "Authorization={v}",
    ],
];

/// Every file and directory under `dir`, sorted.
fn listing(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if std::fs::symlink_metadata(&p).unwrap().is_dir() {
                stack.push(p.clone());
            }
            out.push(p);
        }
    }
    out.sort();
    out
}

/// A listener on the daemon's socket path in `home`, taking connections
/// without blocking, so that every attempt to reach a daemon is seen.
fn daemon_listener(home: &TestHome) -> std::os::unix::net::UnixListener {
    use std::os::unix::fs::PermissionsExt;
    let dir = envcloak_testkit::daemon_run_dir(home);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let l = std::os::unix::net::UnixListener::bind(envcloak_testkit::daemon_socket(home)).unwrap();
    l.set_nonblocking(true).unwrap();
    l
}

/// Whether `l` has a connection waiting.
fn connected(l: &std::os::unix::net::UnixListener) -> bool {
    match l.accept() {
        // Dropped at once: the client's call ends.
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => false,
        Err(e) => panic!("accept: {e}"),
    }
}

/// No stub asks the daemon or writes in the home (review M2R-10): a
/// listener on the daemon's socket path sees no connection, and the home
/// lists the same files before and after; the positive control, `envcloak
/// lock`, which asks the daemon, is seen (its connection is closed
/// unanswered, so it fails at once).
///
/// Mutations checked: the doctor stub asking the daemon first
/// (`envcloak_client::connect::connect()`): the listener sees the
/// connection and this fails. The doctor stub writing a file in the home:
/// the listing differs and this fails.
#[test]
fn no_stub_asks_the_daemon_or_writes_in_the_home() {
    let home = TestHome::new();
    let l = daemon_listener(&home);
    let before = listing(home.root());
    for (words, what) in STUBS {
        let out = run(&home, words, &[]);
        assert_eq!(out.status.code(), Some(NOT_IN_THIS_BUILD), "{what}");
        assert!(!connected(&l), "{what} asked the daemon");
    }
    assert_eq!(listing(home.root()), before, "a stub wrote in the home");
    let seen = std::thread::spawn(move || {
        let end = std::time::Instant::now() + Duration::from_secs(30);
        while std::time::Instant::now() < end {
            if connected(&l) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    });
    let out = run(&home, &["lock"], &[]);
    assert_ne!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(
        seen.join().unwrap(),
        "the listener does not see the daemon's clients"
    );
}

/// A stub refuses an argument that is not UTF-8 as it refuses any other
/// (review M2R-9: the check that refuses such an argument as a usage
/// error ran first, so a stub exited 2 without `not_in_this_build`).
///
/// Mutations checked: the stubs routed after that check, as before: each
/// exits 2 and this fails. `agents status` still routed there once it
/// landed (M2-09): it runs the report, exits 0 and this fails.
#[test]
fn every_stub_refuses_an_argument_that_is_not_utf8() {
    let home = TestHome::new();
    let bad = std::ffi::OsStr::from_bytes(b"\xff\xfe");
    for (words, what) in STUBS {
        let want = format!(
            "envcloak: not_in_this_build: {what} is not in this build of EnvCloak; nothing was \
             done\n"
        );
        let mut cmd = cli_command(&home, words, &[]);
        cmd.arg(bad);
        let out = finish_within(cmd, Duration::from_secs(60));
        assert_eq!(
            out.status.code(),
            Some(NOT_IN_THIS_BUILD),
            "{what}: {}",
            stderr(&out)
        );
        assert_eq!(stdout(&out), "", "{what}");
        assert_eq!(stderr(&out), want, "{what}");
    }
    // Elsewhere the argument is the usage error it was, `agents status`
    // (landed by M2-09) and its `--probe` (landed by M2-28) included.
    for words in [
        &["run", "--"][..],
        &["agents", "status"],
        &["agents", "status", "--probe"],
    ] {
        let mut cmd = cli_command(&home, words, &[]);
        cmd.arg(bad);
        let out = finish_within(cmd, Duration::from_secs(60));
        assert_eq!(out.status.code(), Some(2), "{words:?}: {}", stderr(&out));
        assert_eq!(stdout(&out), "", "{words:?}");
    }
}

#[test]
fn every_stub_exits_125_and_echoes_nothing() {
    let cs = canaries(fresh_seed());
    let home = TestHome::new();
    for (i, (words, what)) in STUBS.iter().enumerate() {
        let want = format!(
            "envcloak: not_in_this_build: {what} is not in this build of EnvCloak; nothing was \
             done\n"
        );
        let words = words.iter().map(|w| (*w).to_owned());
        // Every canary at once, each its own argument, and then each tail
        // with a canary of its own.
        let mut runs: Vec<Vec<String>> = vec![
            words
                .clone()
                .chain(cs.iter().map(|c| c.as_str().to_owned()))
                .collect(),
        ];
        runs.extend(TAILS.iter().enumerate().map(|(j, tail)| {
            let v = cs[(i + j) % cs.len()].as_str();
            words
                .clone()
                .chain(tail.iter().map(|t| t.replace("{v}", v)))
                .collect()
        }));
        for args in runs {
            let argv: Vec<&str> = args.iter().map(String::as_str).collect();
            let out = run(&home, &argv, &[]);
            assert_no_canary(&out.stdout, &cs);
            assert_no_canary(&out.stderr, &cs);
            assert_eq!(
                out.status.code(),
                Some(NOT_IN_THIS_BUILD),
                "{what}: {}",
                stderr(&out)
            );
            assert_eq!(stdout(&out), "", "{what}");
            assert_eq!(stderr(&out), want, "{what}");
        }
    }
    home.assert_clean(&cs);
}

/// A subcommand that no task adds is a usage error, as any unknown
/// command is, and is not echoed either. `items` has its one subcommand
/// since M2-13 (`reclassify`); its usage names it, with no stub left.
#[test]
fn an_unknown_subcommand_of_a_stub_is_a_usage_error() {
    let cs = canaries(fresh_seed());
    let home = TestHome::new();
    let mut cases = vec![
        (vec!["agents"], true),
        (vec!["agents", "--json"], true),
        (vec!["items"], false),
        (vec!["items", "list"], false),
    ];
    for c in &cs {
        cases.push((vec!["agents", c.as_str()], true));
        cases.push((vec!["items", c.as_str()], false));
    }
    for (args, stub) in cases {
        let out = run(&home, &args, &[]);
        assert_no_canary(&out.stdout, &cs);
        assert_no_canary(&out.stderr, &cs);
        assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
        assert!(
            stderr(&out).starts_with("envcloak: usage: envcloak "),
            "{}",
            stderr(&out)
        );
        assert_eq!(
            stderr(&out).contains("in this build"),
            stub,
            "{}",
            stderr(&out)
        );
    }
}

/// Whether `section` of the help has a line `envcloak <words[0]> ...`
/// naming every other word of `words`.
fn lists(section: &str, words: &[&str]) -> bool {
    section.lines().any(|l| {
        let tokens: Vec<&str> = l.split([' ', '|']).filter(|t| !t.is_empty()).collect();
        tokens.first() == Some(&"envcloak")
            && tokens.get(1) == Some(&words[0])
            && words[1..].iter().all(|w| tokens[2..].contains(w))
    })
}

/// The help lists every stub under "Not in this build", and none among
/// the commands this build has, above it.
#[test]
fn the_help_lists_every_stub_as_not_in_this_build() {
    let home = TestHome::new();
    let out = run(&home, &["--help"], &[]);
    assert_eq!(out.status.code(), Some(0));
    let help = stdout(&out);
    let (available, unavailable) = help
        .split_once("Not in this build (each exits 125 with not_in_this_build):\n")
        .unwrap_or_else(|| panic!("no unavailable section: {help}"));
    for (words, what) in STUBS {
        assert!(lists(unavailable, words), "{what} is not listed: {help}");
        assert!(
            !lists(available, words),
            "{what} is listed as available: {help}"
        );
    }
    // The check sees the commands this build has, those M2-03 and M2-06
    // landed among them.
    assert!(lists(available, &["run"]));
    assert!(lists(available, &["pending"]));
    assert!(lists(available, &["mcp"]));
    let run = available
        .lines()
        .find(|l| l.trim_start().starts_with("envcloak run "))
        .unwrap();
    assert!(run.contains("[--manifest PATH] [--wait DURATION]"), "{run}");
    // M2-19 landed `run --pty`: listed with the command, not as a stub.
    assert!(run.contains("[--pty]"), "{run}");
    assert!(lists(available, &["grants", "list"]));
    assert!(lists(available, &["daemon", "uninstall"]));
}
