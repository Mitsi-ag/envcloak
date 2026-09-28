//! Shared helpers for the CLI's integration tests.
//!
//! The CLI reads passphrases from `/dev/tty`, so every command here runs in
//! a new session without a controlling terminal (a small `python3` wrapper
//! calls `setsid` and then `exec`s the CLI), and descriptors such as
//! `--passphrase-fd 3` are opened by that wrapper from files. A test that
//! wants a terminal gives the CLI a pseudo-terminal of its own.
#![allow(dead_code, clippy::unwrap_used)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use envcloak_core::crypto::{ItemClass, KdfParams};
use envcloak_core::vault::{FieldName, ItemDetails, NewItem, Slug, VaultPaths};
use envcloak_core::{RecoveryKit, SecretBytes, create_vault_with_kit};
use envcloak_testkit::{Canary, Daemon, TestHome, by_label, labels};

pub fn cli() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_envcloak"))
}

/// `envcloakd`, built next to `envcloak` (`cargo test --workspace`, or
/// `cargo build -p envcloakd` first).
pub fn daemon_exe() -> PathBuf {
    let p = cli().with_file_name("envcloakd");
    assert!(
        p.is_file(),
        "{} is missing: run the tests with --workspace, or build envcloakd first",
        p.display()
    );
    p
}

/// Starts a daemon in `home`.
pub fn start_daemon(home: &TestHome) -> Daemon {
    Daemon::start(home, &daemon_exe(), &[])
}

/// The absolute path of `python3`, found on this process's `PATH`.
pub fn python3() -> PathBuf {
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .map(|d| d.join("python3"))
        .find(|p| p.is_file())
        .expect("python3 is needed on PATH")
}

/// Runs in a new session (no controlling terminal), opens the descriptors
/// named in argv[1] (`3<path,4>path`), and execs argv[2..].
const DETACH: &str = "import os, sys
os.setsid()
for item in [i for i in sys.argv[1].split(',') if i]:
    if '<' in item:
        n, p = item.split('<', 1)
        fd = os.open(p, os.O_RDONLY)
    else:
        n, p = item.split('>', 1)
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    if fd != int(n):
        os.dup2(fd, int(n))
        os.close(fd)
    os.set_inheritable(int(n), True)
os.execv(sys.argv[2], sys.argv[2:])
";

/// A descriptor to open for the CLI: `(fd, path, for_reading)`.
pub type Fd<'a> = (i32, &'a Path, bool);

/// The CLI command `envcloak <args>` in `home`'s environment, detached
/// from any terminal, with `fds` opened.
pub fn cli_command(home: &TestHome, args: &[&str], fds: &[Fd<'_>]) -> Command {
    let spec: Vec<String> = fds
        .iter()
        .map(|(n, p, read)| format!("{n}{}{}", if *read { '<' } else { '>' }, p.display()))
        .collect();
    let mut cmd = Command::new(python3());
    home.apply(&mut cmd)
        .args(["-c", DETACH])
        .arg(spec.join(","))
        .arg(cli())
        .args(args)
        .current_dir(home.home())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

/// Runs `envcloak <args>` and waits up to a minute for it.
pub fn run(home: &TestHome, args: &[&str], fds: &[Fd<'_>]) -> Output {
    finish_within(cli_command(home, args, fds), Duration::from_secs(60))
}

/// Spawns `cmd` and waits up to `limit` for it, then collects its output.
/// A process that does not exit in time is killed and the test fails.
pub fn finish_within(mut cmd: Command, limit: Duration) -> Output {
    let mut child = cmd.spawn().unwrap();
    let mut out = child.stdout.take();
    let mut err = child.stderr.take();
    let reader = std::thread::spawn(move || {
        let mut o = Vec::new();
        let mut e = Vec::new();
        if let Some(s) = out.as_mut() {
            let _ = s.read_to_end(&mut o);
        }
        if let Some(s) = err.as_mut() {
            let _ = s.read_to_end(&mut e);
        }
        (o, e)
    });
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if start.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the process did not exit within {limit:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let (stdout, stderr) = reader.join().unwrap();
    Output {
        status,
        stdout,
        stderr,
    }
}

pub fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

pub fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// Writes `line` and a newline to a new file in `dir`.
pub fn secret_file(dir: &Path, name: &str, line: &[u8]) -> PathBuf {
    let p = dir.join(name);
    let mut v = line.to_vec();
    v.push(b'\n');
    std::fs::write(&p, v).unwrap();
    p
}

/// A directory outside the test home for files that hold secrets on
/// purpose (a passphrase to feed in, a Recovery Kit written out), so the
/// home's sweep is about what EnvCloak wrote.
pub fn outside_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("ecf")
        .tempdir_in("/tmp")
        .unwrap()
}

/// Runs argv[2..] on a new pseudo-terminal. argv[1] is a JSON file of
/// steps `[expect, send]`: wait until the terminal shows `expect`, then
/// type `send`, a piece at a time while the terminal's output is read, so
/// a paste larger than the terminal's input queue arrives whole.
/// `@SUGGESTED@` in `send` stands for the generated passphrase the
/// terminal showed, and `@PAUSE@` for a pause of 50 ms, as between two
/// pieces of a paste. Prints everything the terminal showed, then the exit
/// code on stderr.
pub const DRIVER: &str = r#"import json, os, pty, re, select, sys, time
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

/// Runs `argv` on a pseudo-terminal in the home directory, typing
/// `steps`.
pub fn drive(home: &TestHome, argv: &[&str], steps: &[(&str, &str)]) -> (Output, i32) {
    drive_from(home, &home.home(), argv, steps)
}

/// Runs `argv` on a pseudo-terminal in `cwd`, typing `steps`.
pub fn drive_from(
    home: &TestHome,
    cwd: &Path,
    argv: &[&str],
    steps: &[(&str, &str)],
) -> (Output, i32) {
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
        .current_dir(cwd)
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

/// The data directory of `home`, as the daemon resolves it.
pub fn data_dir(home: &TestHome) -> PathBuf {
    if cfg!(target_os = "macos") {
        home.home().join("Library/Application Support/EnvCloak")
    } else {
        home.root().join("data/envcloak")
    }
}

/// The slugs of the seeded items, in the order of [`seed_vault`].
pub const SLUGS: [&str; 4] = [
    "openai/acme-web",
    "stripe/acme-web",
    "github/acme-web",
    "short/acme-web",
];

/// Creates the vault in `home` with the canary passphrase, before any
/// daemon runs, and seeds it with one secret item per canary of the
/// story: `openai/acme-web`, `stripe/acme-web`, `github/acme-web` and
/// `short/acme-web`, each with a `value` field. The vault is left locked
/// on disk; the daemon opens it. Returns the kit's text as a canary.
pub fn seed_vault(home: &TestHome, cs: &[Canary]) -> Canary {
    let kit = RecoveryKit::generate();
    let text = kit.to_display();
    let paths = VaultPaths::under(data_dir(home));
    let pass = SecretBytes::copy_from(by_label(cs, labels::VAULT_PASSPHRASE).value());
    let mut v = create_vault_with_kit(&paths, &pass, &kit, KdfParams::minimum()).unwrap();
    let values = [
        labels::OPENAI_API_KEY,
        labels::STRIPE_SECRET_KEY,
        labels::GITHUB_TOKEN,
        labels::SHORT_TOKEN,
    ];
    v.transact(|t| {
        for (slug, label) in SLUGS.iter().zip(values) {
            let id = t.create_item(NewItem {
                class: ItemClass::Secret,
                slug: Slug::new(slug).unwrap(),
                details: ItemDetails {
                    title: (*slug).to_owned(),
                    ..ItemDetails::default()
                },
            })?;
            t.add_field(
                id,
                FieldName::new("value").unwrap(),
                SecretBytes::copy_from(by_label(cs, label).value()),
            )?;
        }
        Ok(())
    })
    .unwrap();
    drop(v);
    Canary::new("RECOVERY_KIT", text.to_string())
}

/// The manifest of the story's project: two bindings in the default
/// profile, one more in `short`.
pub const MANIFEST: &str = "[project]
name = \"acme-web\"

[env]
OPENAI_API_KEY = \"openai/acme-web\"
STRIPE_SECRET_KEY = \"stripe/acme-web\"

[env.short]
SHORT_TOKEN = \"short/acme-web\"
";

/// Writes a project directory `name` in `home` with `manifest`, and
/// returns the directory.
pub fn project(home: &TestHome, name: &str, manifest: &str) -> PathBuf {
    let dir = home.root().join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("envcloak.toml"), manifest).unwrap();
    dir
}
