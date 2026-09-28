//! Passphrases typed on a terminal (SPEC §5 "Unlock flow" step 5): the
//! CLI reads `/dev/tty` with echo off, so nothing typed shows in the
//! terminal's output; Backspace and Ctrl-C work; `vault create` asks twice
//! or offers a generated passphrase and shows the Recovery Kit on the
//! terminal only. Each run gets a pseudo-terminal of its own from a small
//! `python3` driver that waits for each prompt by its text before typing.
#![allow(clippy::unwrap_used)]

mod common;

use std::process::Output;

use common::{cli, drive, run, start_daemon, stdout};
use envcloak_testkit::{TestHome, assert_no_canary, by_label, canaries, fresh_seed, labels};

/// Runs `envcloak <args>` on a pseudo-terminal, typing `steps`.
fn on_terminal(home: &TestHome, args: &[&str], steps: &[(&str, &str)]) -> (Output, i32) {
    let mut argv = vec![cli().to_str().unwrap()];
    argv.extend_from_slice(args);
    drive(home, &argv, steps)
}

/// `vault create` on the terminal, then `unlock` there: typed passphrases
/// never show, and the kit is shown on the terminal and nowhere else.
#[test]
fn passphrases_typed_on_the_terminal_are_never_echoed() {
    let cs = canaries(fresh_seed());
    let pass = by_label(&cs, labels::VAULT_PASSPHRASE).as_str();
    let home = TestHome::new();
    let d = start_daemon(&home);

    let typed = format!("{pass}\r");
    let (out, code) = on_terminal(
        &home,
        &["vault", "create", "--kdf-memory", "64MiB"],
        &[
            ("New vault passphrase", &typed),
            ("Repeat the passphrase: ", &typed),
        ],
    );
    let shown = stdout(&out);
    assert_eq!(code, 0, "{shown}");
    assert!(shown.contains("Your Recovery Kit."), "{shown}");
    assert!(shown.contains("Vault created and unlocked."), "{shown}");
    assert_no_canary(&out.stdout, &cs);

    run(&home, &["lock"], &[]);
    // Backspace erases what was typed before the passphrase.
    let with_typo = format!("xy\u{7f}\u{7f}{pass}\r");
    let (out, code) = on_terminal(&home, &["unlock"], &[("Vault passphrase: ", &with_typo)]);
    assert_eq!(code, 0, "{}", stdout(&out));
    assert!(stdout(&out).contains("Vault unlocked."));
    assert_no_canary(&out.stdout, &cs);
    assert_no_canary(&d.log_bytes(), &cs);
}

#[test]
fn ctrl_c_cancels_without_sending_anything() {
    let cs = canaries(fresh_seed());
    let pass = by_label(&cs, labels::VAULT_PASSPHRASE).as_str();
    let home = TestHome::new();
    let d = start_daemon(&home);
    let typed = format!("{pass}\r");
    let (_, code) = on_terminal(
        &home,
        &["vault", "create", "--kdf-memory", "64MiB"],
        &[
            ("New vault passphrase", &typed),
            ("Repeat the passphrase: ", &typed),
        ],
    );
    assert_eq!(code, 0);
    run(&home, &["lock"], &[]);

    let half = format!("{}\u{3}", &pass[..6]);
    let (out, code) = on_terminal(&home, &["unlock"], &[("Vault passphrase: ", &half)]);
    assert_eq!(code, 1);
    assert!(
        stdout(&out).contains("envcloak: cancelled"),
        "{}",
        stdout(&out)
    );
    let status = stdout(&run(&home, &["status"], &[]));
    assert!(status.contains("vault: locked"), "{status}");
    assert!(
        !status.contains("failed unlocks"),
        "nothing reached the daemon: {status}"
    );
    assert_no_canary(&out.stdout, &cs);
    assert_no_canary(&d.log_bytes(), &cs);
}

/// Enter on an empty first prompt offers a generated six-word passphrase,
/// shown once on the terminal and typed back to confirm; a mismatch is
/// refused.
#[test]
fn vault_create_can_generate_the_passphrase() {
    let home = TestHome::new();
    let _d = start_daemon(&home);
    let (out, code) = on_terminal(
        &home,
        &["vault", "create", "--kdf-memory", "64MiB"],
        &[
            ("New vault passphrase", "\r"),
            ("Type it once to confirm: ", "not the words at all\r"),
        ],
    );
    assert_eq!(code, 1);
    assert!(stdout(&out).contains("envcloak: passphrase_mismatch"));

    let (out, code) = on_terminal(
        &home,
        &["vault", "create", "--kdf-memory", "64MiB"],
        &[
            ("New vault passphrase", "\r"),
            ("Type it once to confirm: ", "@SUGGESTED@\r"),
        ],
    );
    let shown = stdout(&out);
    assert_eq!(code, 0, "{shown}");
    assert!(shown.contains("Vault created and unlocked."), "{shown}");
    let words = shown
        .split("Write it down:")
        .nth(1)
        .unwrap()
        .trim_start()
        .lines()
        .next()
        .unwrap()
        .trim()
        .to_owned();
    assert_eq!(words.split(' ').count(), 6, "{words}");
    // The confirmation was not echoed: the words appear once, where shown.
    assert_eq!(shown.matches(&words).count(), 1, "{shown}");
}

/// Secret entry that ends before Enter (Ctrl-C, Ctrl-D on an empty line,
/// a paste over the 1024-byte limit) discards what was typed after it,
/// including the end of a paste that arrives a moment later: once echo is
/// back on, none of it reaches the next program reading the terminal, here
/// `head` in the same shell, or shows on the terminal. The driver types a
/// line of its own after the CLI exits, which `head` must read instead.
#[test]
fn input_left_after_secret_entry_ends_never_reaches_the_next_reader() {
    let home = TestHome::new();
    let _d = start_daemon(&home);
    let marker = format!("typeahead{:016x}", fresh_seed());
    let script = "\"$0\" vault create --kdf-memory 64MiB; echo CLI_EXITED; exec head -n 1";
    let long = "x".repeat(1100);
    for (key, token) in [
        ("\u{3}", "envcloak: cancelled"),
        ("\u{4}", "envcloak: no_input"),
        (long.as_str(), "envcloak: input_too_long"),
    ] {
        for typed in [
            format!("{key}{marker}\n"),
            format!("{key}@PAUSE@{marker}\n"),
        ] {
            let (out, code) = drive(
                &home,
                &["/bin/sh", "-c", script, cli().to_str().unwrap()],
                &[
                    ("New vault passphrase", &typed),
                    ("CLI_EXITED", "the next line\n"),
                ],
            );
            let shown = stdout(&out);
            assert_eq!(code, 0, "{shown}");
            assert!(shown.contains(token), "{shown}");
            assert!(!shown.contains(&marker), "left input leaked: {shown}");
            // Echoed as typed, then printed by `head`.
            assert_eq!(shown.matches("the next line").count(), 2, "{shown}");
        }
    }
    let status = stdout(&run(&home, &["status"], &[]));
    assert!(status.contains("vault: none yet"), "{status}");
}

/// A `SIGTERM` or `SIGINT` sent to the CLI while it reads a passphrase
/// ends it by that signal, but only after the terminal's settings are
/// back: the shell that follows (which ignores the signal here, so it is
/// the only survivor of the process group) still echoes what is typed, and
/// `head` reads a whole line. Nothing reached the daemon.
#[test]
fn external_termination_restores_the_terminal_first() {
    let home = TestHome::new();
    let _d = start_daemon(&home);
    let script = "trap '' TERM INT; \"$0\" vault create --kdf-memory 64MiB; \
                  echo CLI_EXITED=$?; exec head -n 1";
    for (send, code) in [("@SIGTERM@", 128 + 15), ("@SIGINT@", 128 + 2)] {
        let (out, exit) = drive(
            &home,
            &["/bin/sh", "-c", script, cli().to_str().unwrap()],
            &[
                ("New vault passphrase", send),
                ("CLI_EXITED", "the next line\n"),
            ],
        );
        let shown = stdout(&out);
        assert_eq!(exit, 0, "{shown}");
        assert!(
            shown.contains(&format!("CLI_EXITED={code}")),
            "{send}: {shown}"
        );
        // Echoed by the restored terminal, then printed by `head`.
        assert_eq!(shown.matches("the next line").count(), 2, "{send}: {shown}");
    }
    let status = stdout(&run(&home, &["status"], &[]));
    assert!(status.contains("vault: none yet"), "{status}");
}
