//! Passphrases typed on a terminal (SPEC §5 "Unlock flow" step 5): the
//! CLI reads `/dev/tty` with echo off, so nothing typed shows in the
//! terminal's output; Backspace and Ctrl-C work; `vault create` asks twice
//! or offers a generated passphrase and shows the Recovery Kit on the
//! terminal only. Each run gets a pseudo-terminal of its own from a small
//! `python3` driver that waits for each prompt by its text before typing.
#![allow(clippy::unwrap_used)]

mod common;

use std::process::Output;
use std::time::Duration;

use common::{cli, finish_within, outside_dir, python3, run, start_daemon, stdout};
use envcloak_testkit::{TestHome, assert_no_canary, by_label, canaries, fresh_seed, labels};

/// Runs argv[2..] on a new pseudo-terminal. argv[1] is a JSON file of
/// steps `[expect, send]`: wait until the terminal shows `expect`, then
/// type `send`, a piece at a time while the terminal's output is read, so
/// a paste larger than the terminal's input queue arrives whole.
/// `@SUGGESTED@` in `send` stands for the generated passphrase the
/// terminal showed, and `@PAUSE@` for a pause of 50 ms, as between two
/// pieces of a paste. Prints everything the terminal showed, then the exit
/// code on stderr.
const DRIVER: &str = r#"import json, os, pty, re, select, sys, time
steps = json.load(open(sys.argv[1]))
pid, fd = pty.fork()
if pid == 0:
    os.execv(sys.argv[2], sys.argv[2:])
out = b''
def more(deadline):
    global out
    r, _, _ = select.select([fd], [], [], max(0.0, deadline - time.time()))
    if not r:
        return False
    try:
        chunk = os.read(fd, 4096)
    except OSError:
        chunk = b''
    if not chunk:
        return False
    out += chunk
    return True
for expect, send in steps:
    deadline = time.time() + 60
    while expect.encode() not in out:
        if not more(deadline):
            sys.stdout.buffer.write(out)
            sys.exit('did not see ' + repr(expect))
    if '@SUGGESTED@' in send:
        words = re.search(rb'Write it down:\r?\n\r?\n    ([a-z -]+)\r?\n', out).group(1).decode()
        send = send.replace('@SUGGESTED@', words)
    for i, piece in enumerate(send.split('@PAUSE@')):
        if i:
            time.sleep(0.05)
        data = piece.encode()
        deadline = time.time() + 60
        while data:
            if time.time() > deadline:
                sys.exit('could not type ' + repr(expect))
            r, w, _ = select.select([fd], [fd], [], 1.0)
            if r:
                more(time.time())
            if w:
                data = data[os.write(fd, data[:256]):]
while more(time.time() + 60):
    pass
_, status = os.waitpid(pid, 0)
sys.stdout.buffer.write(out)
sys.stderr.write('exit=%d\n' % os.waitstatus_to_exitcode(status))
"#;

/// Runs `envcloak <args>` on a pseudo-terminal, typing `steps`.
fn on_terminal(home: &TestHome, args: &[&str], steps: &[(&str, &str)]) -> (Output, i32) {
    let mut argv = vec![cli().to_str().unwrap()];
    argv.extend_from_slice(args);
    drive(home, &argv, steps)
}

/// Runs `argv` on a pseudo-terminal, typing `steps`.
fn drive(home: &TestHome, argv: &[&str], steps: &[(&str, &str)]) -> (Output, i32) {
    let files = outside_dir();
    let script = files.path().join("steps.json");
    let json =
        serde_json::to_string(&steps.iter().map(|(a, b)| [a, b]).collect::<Vec<_>>()).unwrap();
    std::fs::write(&script, json).unwrap();
    let mut cmd = std::process::Command::new(python3());
    home.apply(&mut cmd)
        .args(["-c", DRIVER])
        .arg(&script)
        .args(argv)
        .current_dir(home.home())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let out = finish_within(cmd, Duration::from_secs(120));
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    let code = err
        .lines()
        .find_map(|l| l.strip_prefix("exit="))
        .unwrap_or_else(|| panic!("the driver failed: {err}\n{}", stdout(&out)))
        .parse()
        .unwrap();
    (out, code)
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
