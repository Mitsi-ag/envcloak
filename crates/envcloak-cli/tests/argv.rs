//! Gate 13, argv (SPEC §15.2): values are never accepted on argv, and
//! `ps` shows no value in the CLI's argv or environment while it holds
//! one.
//!
//! 1. No command takes a value: every canary, put where a value could be
//!    pasted (an extra argument, a `--value` or `--passphrase` option, a
//!    command's name), is a usage error that echoes nothing. A canary
//!    shaped like a key (a provider's key pattern, or a long run of mixed
//!    letters and digits) put in any name a command takes (a provider,
//!    slug, field, account, variable, reference or profile) is refused as
//!    one, with exit 2 and `value_on_argv`, also where the command would
//!    otherwise go on (`add` with a value on standard input, `ref`, which
//!    writes the manifest), so a pasted key is never kept as a name.
//!    Afterwards no item's metadata, no manifest, no log and nothing in
//!    the home holds a canary, and the vault holds no canary as a value
//!    but the ones it was seeded with. A value made of words, or a short
//!    one, cannot be told from a name, and is not tried in the name
//!    slots: a person can name an item anything.
//! 2. `envcloak rotate --stdin` holds the new value in memory while it
//!    waits for the passphrase on its terminal. At that moment `ps` shows
//!    no canary in its argv, nor in its environment: on macOS `ps -E`
//!    prints it; on Linux the process is non-dumpable, so its environment
//!    cannot be read at all by another process of the user, which the test
//!    records. `run`'s own `ps` check, while it runs a command, is in
//!    tests/run.rs.
//!
//! The approver's commands run on a terminal of their own, outside any
//! agent's tree (see tests/approve.rs); under a developer's Claude Code the
//! proofs are refused, as they must be.
#![allow(clippy::unwrap_used)]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use common::{
    MANIFEST, cli, cli_command, data_dir, finish_within, outside_dir, project, python3,
    run_on_terminal, secret_file, seed_vault, start_daemon, stderr,
};
use envcloak_core::SecretBytes;
use envcloak_core::vault::{LockedVault, VaultPaths};
use envcloak_testkit::{
    Canary, Daemon, TestHome, assert_no_canary, by_label, canaries, fresh_seed, labels,
};

/// Exit code of a usage error, `value_on_argv` included.
const USAGE: i32 = 2;

struct Fixture {
    cs: Vec<Canary>,
    home: TestHome,
    d: Daemon,
    project: PathBuf,
    files: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let mut cs = canaries(fresh_seed());
        let home = TestHome::new();
        let kit = seed_vault(&home, &cs);
        cs.push(kit);
        // A lowercase hex token: a valid slug, variable-free, and matched by
        // no provider's pattern; only its shape gives it away.
        let mut x = fresh_seed();
        let hex: String = (0..40)
            .map(|_| {
                x = x
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                char::from(b"0123456789abcdef"[usize::try_from(x >> 60).unwrap()])
            })
            .collect();
        cs.push(Canary::new("HEX_TOKEN", hex));
        let d = start_daemon(&home);
        let files = outside_dir();
        let pass = secret_file(
            files.path(),
            "pass",
            by_label(&cs, labels::VAULT_PASSPHRASE).value(),
        );
        let out = run_on_terminal(
            &home,
            &["unlock", "--passphrase-fd", "3"],
            &[(3, &pass, true)],
        );
        assert!(out.status.success(), "{}", stderr(&out));
        let project = project(&home, "acme-web", MANIFEST);
        Fixture {
            cs,
            home,
            d,
            project,
            files,
        }
    }

    /// `envcloak <args>` in the project directory, detached from any
    /// terminal, with standard input from `stdin` when given.
    fn run(&self, args: &[&str], stdin: Option<&Path>) -> std::process::Output {
        let fds: Vec<common::Fd<'_>> = stdin.map(|p| (0, p, true)).into_iter().collect();
        let mut cmd = cli_command(&self.home, args, &fds);
        cmd.current_dir(&self.project);
        finish_within(cmd, std::time::Duration::from_secs(60))
    }

    fn value(&self, label: &str) -> &str {
        by_label(&self.cs, label).as_str()
    }
}

fn filled(templates: &[&[&str]], v: &str) -> Vec<Vec<String>> {
    templates
        .iter()
        .map(|a| a.iter().map(|w| w.replace("{v}", v)).collect())
        .collect()
}

/// Every place a value could be pasted where no command takes one: an
/// extra argument, an option that does not exist, a command's name. Each
/// is a usage error, whatever the value.
fn value_slots(v: &str) -> Vec<Vec<String>> {
    filled(
        &[
            &["add", "openai", "{v}"],
            &["add", "--value", "{v}"],
            &["rotate", "openai/acme-web", "{v}"],
            &["rotate", "openai/acme-web", "--value", "{v}"],
            &["rotate", "--stdin", "openai/acme-web", "{v}"],
            &["rm", "openai/acme-web", "{v}"],
            &["show", "openai/acme-web", "{v}"],
            &["ls", "{v}"],
            &["ls", "--long", "{v}"],
            &["check", "{v}"],
            &["ref", "X=openai/acme-web", "{v}"],
            &["unlock", "{v}"],
            &["unlock", "--passphrase", "{v}"],
            &["lock", "{v}"],
            &["status", "{v}"],
            &["approve", "{v}"],
            &["approve", "ABCDEFGH", "{v}"],
            &["deny", "{v}"],
            &["grants", "revoke", "{v}"],
            &["grants", "list", "{v}"],
            &["audit", "verify", "{v}"],
            &["vault", "create", "--passphrase", "{v}"],
            &["run", "{v}", "--", "true"],
            &["run", "--value", "{v}", "--", "true"],
            &["{v}"],
        ],
        v,
    )
}

/// Every name a command takes (a provider, slug, field, account,
/// variable, reference or profile). A value shaped like a key there is
/// refused as one.
fn name_slots(v: &str) -> Vec<Vec<String>> {
    filled(
        &[
            &["add", "{v}"],
            &["add", "--stdin", "{v}"],
            &["add", "--slug", "{v}"],
            &["add", "--account", "{v}"],
            &["add", "--env", "{v}"],
            &["add", "--field", "{v}"],
            &["rotate", "{v}"],
            &["rotate", "openai/acme-web#{v}"],
            &["rm", "{v}"],
            &["show", "{v}"],
            &["ref", "{v}"],
            &["ref", "OPENAI_API_KEY={v}"],
            &["ref", "OPENAI_API_KEY=openai/{v}"],
            &["ref", "OPENAI_API_KEY=openai/acme-web#{v}"],
            &["ref", "{v}=openai/acme-web"],
            &["ref", "X=openai/acme-web", "--profile", "{v}"],
            &["run", "--ref", "OPENAI_API_KEY={v}", "--", "true"],
            &["run", "--ref", "{v}=openai/acme-web", "--", "true"],
            &["run", "--profile", "{v}", "--", "true"],
        ],
        v,
    )
}

/// The canaries shaped like keys: generated, with a provider's pattern or
/// a long run of mixed letters and digits.
const KEY_SHAPED: [&str; 4] = [
    labels::OPENAI_API_KEY,
    labels::STRIPE_SECRET_KEY,
    labels::GITHUB_TOKEN,
    "HEX_TOKEN",
];

/// Runs `args`, which must be refused with exit `code` and echo nothing.
fn refused(f: &Fixture, args: &[String], stdin: Option<&Path>, code: i32, label: &str) {
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = f.run(&argv, stdin);
    assert_no_canary(&out.stdout, &f.cs);
    assert_no_canary(&out.stderr, &f.cs);
    assert_eq!(
        out.status.code(),
        Some(code),
        "`envcloak {}` with {label}: {}",
        args[0],
        stderr(&out)
    );
}

/// Part 1: every command refuses a value on argv, and nothing is kept.
#[test]
fn values_are_never_accepted_on_argv() {
    let f = Fixture::new();
    let manifest_before =
        String::from_utf8(std::fs::read(f.project.join("envcloak.toml")).unwrap()).unwrap();
    // A value `add --stdin` accepts, so the commands below get as far as
    // they can.
    let ordinary = secret_file(
        f.files.path(),
        "ordinary",
        b"an ordinary value, not a canary",
    );
    for c in &f.cs {
        for args in value_slots(c.as_str()) {
            refused(&f, &args, None, USAGE, &c.label);
        }
    }
    for label in KEY_SHAPED {
        let v = f.value(label);
        for args in name_slots(v) {
            refused(&f, &args, None, USAGE, label);
            // Where the command would otherwise go on: a value to add.
            if args[0] == "add" && !args.iter().any(|a| a == "--stdin") {
                let mut with_stdin = args.clone();
                with_stdin.insert(1, "--stdin".to_owned());
                refused(&f, &with_stdin, Some(&ordinary), USAGE, label);
            }
        }
    }
    // The control: the same commands with names go through.
    let out = f.run(
        &["add", "--stdin", "--slug", "misc/ordinary"],
        Some(&ordinary),
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let out = f.run(&["ref", "EXTRA=misc/ordinary"], None);
    assert!(out.status.success(), "{}", stderr(&out));

    // Nothing was kept: no name in the vault, the manifest changed only by
    // the control, no log line and nothing in the home holds a canary.
    let listed = f.run(&["ls", "--long", "--json"], None);
    assert!(listed.status.success(), "{}", stderr(&listed));
    assert_no_canary(&listed.stdout, &f.cs);
    let manifest_after =
        String::from_utf8(std::fs::read(f.project.join("envcloak.toml")).unwrap()).unwrap();
    assert_eq!(
        manifest_after,
        manifest_before.replacen(
            "STRIPE_SECRET_KEY = \"stripe/acme-web\"\n",
            "STRIPE_SECRET_KEY = \"stripe/acme-web\"\nEXTRA = \"misc/ordinary\"\n",
            1
        ),
    );
    assert_no_canary(&f.d.log_bytes(), &f.cs);
    f.home.assert_clean(&f.cs);
    let Fixture {
        cs, home, mut d, ..
    } = f;
    d.signal("-TERM");
    assert!(d.wait_exit(std::time::Duration::from_secs(30)).is_some());
    let v = LockedVault::open(&VaultPaths::under(data_dir(&home)))
        .unwrap()
        .unlock_with_passphrase(&SecretBytes::copy_from(
            by_label(&cs, labels::VAULT_PASSPHRASE).value(),
        ))
        .map_err(|(_, e)| e)
        .unwrap();
    for c in &cs {
        let seeded = usize::from(matches!(
            c.label.as_str(),
            labels::OPENAI_API_KEY
                | labels::STRIPE_SECRET_KEY
                | labels::GITHUB_TOKEN
                | labels::SHORT_TOKEN
        ));
        assert_eq!(
            v.find_by_value(&SecretBytes::copy_from(c.value())).len(),
            seeded,
            "{}",
            c.label
        );
    }
    assert_eq!(v.items().len(), common::SLUGS.len() + 1);
}

/// Runs `argv` on a new pseudo-terminal with standard input from
/// argv[1]'s file. When the terminal shows argv[2], prints `PID <n>` for
/// the command and waits for a line on its own standard input; then types
/// argv[3] and Enter, and prints what the terminal showed and the exit
/// code.
const PS_DRIVER: &str = r#"import os, pty, select, sys, time
stdin_file, expect, typed = sys.argv[1], sys.argv[2].encode(), sys.argv[3]
pid, fd = pty.fork()
if pid == 0:
    f = os.open(stdin_file, os.O_RDONLY)
    os.dup2(f, 0)
    os.close(f)
    os.execv(sys.argv[4], sys.argv[4:])
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
deadline = time.time() + 60
while expect not in out:
    if not more(deadline):
        sys.stdout.write('NOPROMPT\n')
        sys.stdout.flush()
        sys.exit(1)
sys.stdout.write('PID %d\n' % pid)
sys.stdout.flush()
sys.stdin.readline()
os.write(fd, (typed + '\r').encode())
while more(time.time() + 60):
    pass
_, status = os.waitpid(pid, 0)
sys.stdout.write('EXIT %d\n' % os.waitstatus_to_exitcode(status))
sys.stdout.flush()
sys.stdout.buffer.write(out)
"#;

/// What `ps` shows of process `pid`: its command line, and on macOS its
/// environment too (`-E`). On Linux the environment is read as `ps e`
/// reads it, from `/proc/<pid>/environ`; `None` when that is refused.
fn ps(pid: &str) -> (Vec<u8>, Option<Vec<u8>>) {
    let args: &[&str] = if cfg!(target_os = "macos") {
        &["-E", "-ww", "-o", "command=", "-p", pid]
    } else {
        &["-ww", "-o", "args=", "-p", pid]
    };
    let out = Command::new("/bin/ps").args(args).output().unwrap();
    assert!(out.status.success(), "ps failed");
    assert!(!out.stdout.is_empty(), "ps showed nothing for the process");
    let environ = if cfg!(target_os = "linux") {
        std::fs::read(format!("/proc/{pid}/environ")).ok()
    } else {
        None
    };
    (out.stdout, environ)
}

/// The control for [`ps`]: a process with a canary in its argv and its
/// environment shows it to `ps`, in both on macOS, and in both on Linux
/// too, where it is dumpable. The check below can fail. The process is
/// `fixture-agent` (this workspace's, unsigned like the CLI under test,
/// since macOS does not show a platform binary's environment), holding
/// the canary as an argument of the shell it runs.
fn ps_sees_values_where_they_are(cs: &[Canary], home: &TestHome) {
    let v = by_label(cs, labels::GITHUB_TOKEN).as_str();
    let mut cmd = Command::new(envcloak_testkit::testkit_bin("fixture-agent"));
    home.apply(&mut cmd)
        .env("CONTROL_VALUE", v)
        .args(["--", "/bin/sh", "-c", "echo ready; read x", v])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().unwrap();
    // The shell runs (its argv and environment in place) once it says so.
    let mut ready = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert_eq!(ready, "ready\n");
    let (shown, environ) = ps(&child.id().to_string());
    let in_argv = envcloak_testkit::find(&shown, cs).len();
    let in_env = environ.map_or(0, |e| envcloak_testkit::find(&e, cs).len());
    drop(child.stdin.take());
    child.wait().unwrap();
    if cfg!(target_os = "macos") {
        // `ps -E`: the command line and the environment.
        assert!(in_argv >= 2, "ps missed the control's argv or environment");
    } else {
        assert!(in_argv >= 1, "ps missed the control's argv");
        assert!(in_env >= 1, "the control's environment was not read");
    }
}

/// Part 2: `ps` shows no value in the CLI's argv or environment while it
/// holds one (the new value of a rotation, read from standard input,
/// waiting for the passphrase).
#[test]
fn ps_shows_no_value_while_the_cli_holds_one() {
    let f = Fixture::new();
    ps_sees_values_where_they_are(&f.cs, &f.home);
    let new = secret_file(
        f.files.path(),
        "new",
        f.value(labels::OPENAI_API_KEY_ROTATED).as_bytes(),
    );
    let mut cmd = Command::new(python3());
    f.home
        .apply(&mut cmd)
        .args(["-c", PS_DRIVER])
        .arg(&new)
        .arg("Vault passphrase to rotate this:")
        .arg(f.value(labels::VAULT_PASSPHRASE))
        .arg(cli())
        .args(["rotate", "openai/acme-web", "--stdin"])
        .current_dir(&f.project)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut driver = cmd.spawn().unwrap();
    let mut to_driver = driver.stdin.take().unwrap();
    let mut from_driver = BufReader::new(driver.stdout.take().unwrap());
    let mut line = String::new();
    from_driver.read_line(&mut line).unwrap();
    let pid = line
        .strip_prefix("PID ")
        .unwrap_or_else(|| panic!("the prompt did not appear: {line}"))
        .trim()
        .to_owned();

    // The CLI has read the value and waits for the passphrase.
    let (shown, environ) = ps(&pid);
    assert_no_canary(&shown, &f.cs);
    assert!(
        String::from_utf8_lossy(&shown).contains("rotate openai/acme-web --stdin"),
        "ps did not show the command line"
    );
    if cfg!(target_os = "macos") {
        // `-E` appends the environment: the test home's variables, and no
        // value.
        assert!(
            String::from_utf8_lossy(&shown).contains("HOME="),
            "ps -E showed no environment"
        );
    }
    match environ {
        // Non-dumpable: no other process of the user reads it.
        None => {}
        Some(e) => assert_no_canary(&e, &f.cs),
    }
    if cfg!(target_os = "linux") {
        assert!(
            std::fs::read(format!("/proc/{pid}/environ")).is_err(),
            "the CLI's environment was readable on Linux"
        );
    }

    writeln!(to_driver, "go").unwrap();
    drop(to_driver);
    let mut rest = Vec::new();
    from_driver.read_to_end(&mut rest).unwrap();
    assert!(driver.wait().unwrap().success());
    assert_no_canary(&rest, &f.cs);
    let rest = String::from_utf8_lossy(&rest);
    assert!(rest.starts_with("EXIT 0\n"), "{rest}");
    assert!(rest.contains("Rotated openai/acme-web#value"), "{rest}");
    assert_no_canary(&f.d.log_bytes(), &f.cs);
    f.home.assert_clean(&f.cs);
}
