//! The commands and options of M2 and M2b that later tasks land (M2 plan
//! D-23, R-M2-01): this build registers each one, and each exits 125 with
//! `not_in_this_build`, prints nothing on standard output and one fixed
//! line on standard error, whatever its arguments. Key-shaped ones (every
//! canary, as an argument, an option's value or a command after `--`) are
//! never echoed. No daemon runs in these tests, so a stub that asked one
//! would fail otherwise, and nothing is written in the home. The help lists
//! every one of them as not in this build, and never as available.
#![allow(clippy::unwrap_used)]

mod common;

use common::{run, stderr, stdout};
use envcloak_testkit::{TestHome, assert_no_canary, canaries, fresh_seed};

/// Each registered command or option (the words that select it) and how
/// its refusal names it.
const STUBS: &[(&[&str], &str)] = &[
    (&["reveal"], "`envcloak reveal`"),
    (&["doctor"], "`envcloak doctor`"),
    (&["scrub"], "`envcloak scrub`"),
    (&["agents", "install"], "`envcloak agents install`"),
    (&["agents", "uninstall"], "`envcloak agents uninstall`"),
    (&["agents", "status"], "`envcloak agents status`"),
    (&["agents", "migrate-mcp"], "`envcloak agents migrate-mcp`"),
    (&["hook"], "`envcloak hook`"),
    (&["mcp"], "`envcloak mcp`"),
    (&["mcp-bridge"], "`envcloak mcp-bridge`"),
    (&["standing"], "`envcloak standing`"),
    (&["items", "reclassify"], "`envcloak items reclassify`"),
    (&["login"], "`envcloak login`"),
    (&["signin"], "`envcloak signin`"),
    (&["run", "--pty"], "`envcloak run --pty`"),
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
/// command is, and is not echoed either.
#[test]
fn an_unknown_subcommand_of_a_stub_is_a_usage_error() {
    let cs = canaries(fresh_seed());
    let home = TestHome::new();
    let mut cases = vec![
        vec!["agents"],
        vec!["agents", "--json"],
        vec!["items"],
        vec!["items", "list"],
    ];
    for c in &cs {
        cases.push(vec!["agents", c.as_str()]);
        cases.push(vec!["items", c.as_str()]);
    }
    for args in cases {
        let out = run(&home, &args, &[]);
        assert_no_canary(&out.stdout, &cs);
        assert_no_canary(&out.stderr, &cs);
        assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
        assert!(
            stderr(&out).starts_with("envcloak: usage: envcloak "),
            "{}",
            stderr(&out)
        );
        assert!(stderr(&out).contains("in this build"), "{}", stderr(&out));
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
    // The check sees the commands this build has, those M2-03 landed
    // among them.
    assert!(lists(available, &["run"]));
    assert!(lists(available, &["pending"]));
    let run = available
        .lines()
        .find(|l| l.trim_start().starts_with("envcloak run "))
        .unwrap();
    assert!(run.contains("[--manifest PATH] [--wait DURATION]"), "{run}");
    assert!(lists(available, &["grants", "list"]));
    assert!(lists(available, &["daemon", "uninstall"]));
}
