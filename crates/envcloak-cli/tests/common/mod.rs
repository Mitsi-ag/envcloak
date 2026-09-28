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

use envcloak_testkit::{Daemon, TestHome};

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
