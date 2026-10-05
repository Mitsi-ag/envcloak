//! The M1 fixture acceptance story (SPEC §15.1; the plan's steps S1 to
//! S13) and gate 12, end to end through the built `envcloak` and
//! `envcloakd`. Test support only: never published, never a dependency of
//! a shipped crate.
//!
//! A [`Harness`] is one isolated user:
//! - a [`TestHome`] (`HOME` and every `XDG_*` directory under a short
//!   `/tmp/ecXXXXXX`, so the socket path stays under macOS's 104-byte
//!   `sun_path`), and a cleared environment for every process it starts;
//! - `envcloakd --foreground`, started by absolute path, its log kept, and
//!   restarted on request with the logs of the earlier ones kept too;
//! - the person ([`Harness::human`]): a command leading a session on a
//!   pseudo-terminal of its own, as in a terminal window, with no agent in
//!   its ancestry. What it asks for on the terminal is typed when its
//!   prompt shows (waiting for the text, never for a time), from
//!   descriptors opened on files outside the home;
//! - the agent ([`Harness::agent`]): `fixture-agent`, which the builtin
//!   catalog knows, running one shell for the whole story, with no
//!   terminal, so a grant for its process tree covers its later commands;
//! - the sweep ([`Harness::sweep`]): every byte any process printed, every
//!   daemon's log and the whole home, for every canary and every encoding
//!   of one, and for the bytes the emitters' serializers make of each
//!   ([`Harness::add_needle`]).
//!
//! Every output is swept before a test looks at it, so a failure message
//! that quotes one never shows a value. The binaries are those of this
//! target directory, or of `ENVCLOAK_E2E_BIN_DIR` (CI points it at the
//! release build).

use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Output, Stdio};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use envcloak_testkit::{Canary, Daemon, Detector, TestHome, canaries, fresh_seed, sweep_dir};

mod emitters;
pub mod k01;
mod network;

pub use emitters::{Emitters, NAMES, sha256_hex};
pub use network::{NETWORK_VAR, OPEN_RESOLVERS, check_network, open_resolver_imports};

/// How long one command may take before the test fails.
pub const COMMAND_LIMIT: Duration = Duration::from_secs(300);

/// The label tests give the Recovery Kit's canary, once they read it back
/// from the descriptor `vault create --kit-fd` wrote it to.
pub const RECOVERY_KIT: &str = "RECOVERY_KIT";
/// The passphrase the story's `recover` sets (S11).
pub const NEW_PASSPHRASE: &str = "NEW_PASSPHRASE";
/// A wrong passphrase the story types once (S5): not the vault's, and a
/// canary all the same, since it was typed where a secret goes.
pub const WRONG_PASSPHRASE: &str = "WRONG_PASSPHRASE";

/// Tests that start daemons run one at a time: Argon2id's memory for each
/// vault, times parallel tests, can exhaust a CI runner.
static SERIAL: Mutex<()> = Mutex::new(());

/// The directory holding `envcloak` and `envcloakd`: `ENVCLOAK_E2E_BIN_DIR`,
/// or the target directory this test binary was built in.
///
/// # Panics
/// When they are not there: run the tests with `--workspace`, or build
/// them first. The target directory's are also refused when they are
/// older than the sources they are built from, which `cargo test -p
/// envcloak-e2e` does not rebuild them for (review G3-V2).
pub fn bin_dir() -> PathBuf {
    let given = std::env::var_os("ENVCLOAK_E2E_BIN_DIR");
    let dir = match &given {
        Some(d) => PathBuf::from(d),
        None => target_dir(),
    };
    for name in ["envcloak", "envcloakd"] {
        let bin = dir.join(name);
        assert!(
            bin.is_file(),
            "{} is missing: run the tests with --workspace, or build it first",
            bin.display()
        );
        if given.is_none() {
            envcloak_testkit::assert_fresh(&bin, name);
        }
    }
    dir
}

/// The target directory of this test binary: the one above its `deps/`.
pub fn target_dir() -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_else(|e| panic!("no current exe: {e}"));
    exe.parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| panic!("the test binary is not in a target directory"))
}

/// crates/envcloak-e2e/agents/versions.toml: the agent hosts the M2 tests
/// drive, pinned (envcloak-testkit's `agents` module reads it).
pub fn versions_toml() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("agents/versions.toml")
}

/// An executable on this process's `PATH`.
pub fn find_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

/// `python3`, which drives the terminals.
///
/// # Panics
/// When it is not on `PATH`.
pub fn python3() -> PathBuf {
    find_on_path("python3").unwrap_or_else(|| panic!("python3 is needed on PATH"))
}

/// `s` as one shell word.
pub fn quoted(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// The token of a CLI failure line, `envcloak: <token>: ...`.
pub fn token(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    text.lines()
        .find_map(|l| l.strip_prefix("envcloak: "))
        .and_then(|r| r.split(':').next())
        .unwrap_or("")
        .to_owned()
}

/// Sets `p`'s modification time `ago` in the past: `init` deletes no file
/// changed in the last two minutes (gate 16).
///
/// # Panics
/// When the file cannot be changed.
pub fn age(p: &Path, ago: Duration) {
    let f = std::fs::File::options()
        .write(true)
        .open(p)
        .unwrap_or_else(|e| panic!("open {}: {e}", p.display()));
    f.set_modified(SystemTime::now() - ago)
        .unwrap_or_else(|e| panic!("set_modified: {e}"));
}

/// What a person's command did: its exit code, what it wrote to its
/// standard output and error (pipes), and what its terminal showed.
#[derive(Debug, Clone)]
pub struct Human {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub tty: Vec<u8>,
}

impl Human {
    pub fn out(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    pub fn err(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }

    pub fn shown(&self) -> String {
        String::from_utf8_lossy(&self.tty).into_owned()
    }

    /// Everything, for a failure message (swept already).
    pub fn all(&self) -> String {
        format!(
            "exit {}\n--- stdout\n{}--- stderr\n{}--- terminal\n{}",
            self.code,
            self.out(),
            self.err(),
            self.shown()
        )
    }
}

/// The text of an agent's command, for failure messages (swept already).
pub fn text(o: &Output) -> String {
    format!(
        "exit {:?}\n--- stdout\n{}--- stderr\n{}",
        o.status.code(),
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

/// One occurrence of a canary, or of a serializer's bytes for one, where
/// it must not be. Holds no value: [`std::fmt::Display`] names the canary
/// or needle, the encoding and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leak(String);

impl std::fmt::Display for Leak {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Runs argv[2..] leading a session on a new pseudo-terminal, as a shell
/// in a terminal window does: standard output and error stay this
/// driver's (pipes the harness reads apart), and standard input is the
/// terminal unless the spec puts a file on descriptor 0, in which case the
/// terminal stays open on descriptor 9 (on macOS a session whose terminal
/// no process holds open loses it). argv[1] is a JSON spec: `fds`
/// (`[n, path, "r" | "w"]`, opened in the child), `steps` (`[expect,
/// send]`: wait until the terminal shows `expect`, then type `send`, a
/// piece at a time while the terminal's output is read), `transcript` and
/// `code` (files for what the terminal showed and the exit code: 128 plus
/// the signal when one ended it). A prompt that does not show within the
/// limit writes the transcript and exits 3 with no code file.
const HUMAN: &str = r#"import json, os, pty, select, sys, time
spec = json.load(open(sys.argv[1]))
limit = spec["limit"]
out, err = os.dup(1), os.dup(2)
pid, fd = pty.fork()
if pid == 0:
    os.dup2(out, 1)
    os.dup2(err, 2)
    if any(n == 0 for n, _, _ in spec["fds"]):
        os.dup2(0, 9)
        os.set_inheritable(9, True)
    for n, p, mode in spec["fds"]:
        if mode == "r":
            f = os.open(p, os.O_RDONLY)
        else:
            f = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        if f != n:
            os.dup2(f, n)
            os.close(f)
        os.set_inheritable(n, True)
    os.execv(sys.argv[2], sys.argv[2:])
os.close(out)
os.close(err)
shown = b''
def more(deadline):
    global shown
    r, _, _ = select.select([fd], [], [], max(0.0, deadline - time.time()))
    if not r:
        return False
    try:
        chunk = os.read(fd, 4096)
    except OSError:
        chunk = b''
    if not chunk:
        return False
    shown += chunk
    return True
def save():
    with open(spec["transcript"], "wb") as t:
        t.write(shown)
closed = False
for expect, send in spec["steps"]:
    deadline = time.time() + limit
    while expect.encode() not in shown:
        if not more(deadline):
            save()
            os.kill(pid, 9)
            os.waitpid(pid, 0)
            sys.exit(3)
    data = send.encode()
    deadline = time.time() + limit
    while data and not closed:
        if time.time() > deadline:
            save()
            sys.exit(3)
        r, w, _ = select.select([fd], [fd], [], 1.0)
        if r:
            more(time.time())
        if w:
            try:
                data = data[os.write(fd, data[:256]):]
            except OSError:
                closed = True
    if closed:
        break
while more(time.time() + limit):
    pass
_, status = os.waitpid(pid, 0)
save()
code = os.waitstatus_to_exitcode(status)
with open(spec["code"] + ".tmp", "w") as c:
    c.write(str(code if code >= 0 else 128 - code))
os.rename(spec["code"] + ".tmp", spec["code"])
"#;

/// The person at a terminal of their own ([`Harness::person`]): each
/// command leads a session on a pseudo-terminal of its own, as
/// [`Harness::human_argv`] runs it, and can run from any thread.
pub struct Person {
    python: PathBuf,
    cli: PathBuf,
    env: Vec<(OsString, OsString)>,
    files: PathBuf,
    n: std::sync::atomic::AtomicUsize,
    kept: Mutex<Vec<(String, Vec<u8>)>>,
}

impl std::fmt::Debug for Person {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Person").finish_non_exhaustive()
    }
}

impl Person {
    /// `envcloak <args>` in `cwd`, typing each step's text once its prompt
    /// shows, within `limit`; `None` when it did not finish or a prompt did
    /// not show.
    pub fn run(
        &self,
        cwd: &Path,
        args: &[&str],
        steps: &[(&str, &str)],
        limit: Duration,
    ) -> Option<Human> {
        let n = self.n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let spec_path = self.files.join(format!("person-{n}.json"));
        let transcript = self.files.join(format!("person-{n}.tty"));
        let code = self.files.join(format!("person-{n}.code"));
        let spec = serde_json::json!({
            "limit": limit.as_secs().max(1),
            "fds": [],
            "steps": steps.iter().map(|(a, b)| serde_json::json!([a, b])).collect::<Vec<_>>(),
            "transcript": transcript.to_str().unwrap_or(""),
            "code": code.to_str().unwrap_or(""),
        });
        std::fs::write(&spec_path, spec.to_string()).ok()?;
        let mut cmd = Command::new(&self.python);
        cmd.env_clear()
            .envs(self.env.iter().map(|(k, v)| (k, v)))
            .arg("-c")
            .arg(HUMAN)
            .arg(&spec_path)
            .arg(&self.cli)
            .args(args)
            .current_dir(cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let out = finish_within(cmd, limit + Duration::from_secs(30));
        let tty = std::fs::read(&transcript).unwrap_or_default();
        let _ = std::fs::remove_file(&transcript);
        let _ = std::fs::remove_file(&spec_path);
        let code_text = std::fs::read_to_string(&code).ok();
        let _ = std::fs::remove_file(&code);
        {
            let mut kept = self.kept.lock().unwrap_or_else(PoisonError::into_inner);
            kept.push((
                format!("the person's command p{n} (stdout)"),
                out.stdout.clone(),
            ));
            kept.push((
                format!("the person's command p{n} (stderr)"),
                out.stderr.clone(),
            ));
            kept.push((format!("the person's command p{n} (terminal)"), tty.clone()));
        }
        let code = code_text.and_then(|c| c.trim().parse().ok())?;
        Some(Human {
            code,
            stdout: out.stdout,
            stderr: out.stderr,
            tty,
        })
    }
}

/// The agent: `fixture-agent` running one `/bin/sh` that takes one command
/// line after another. Killed on drop.
struct Agent {
    child: Child,
    stdin: ChildStdin,
    dir: PathBuf,
    n: usize,
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One isolated user with a daemon, a person and an agent. See the crate
/// documentation.
pub struct Harness {
    pub home: TestHome,
    pub daemon: Daemon,
    /// Every fixture secret: the story's canaries, the passphrases, and
    /// the Recovery Kit once there is one.
    pub canaries: Vec<Canary>,
    /// Serializer outputs to look for as they are, besides the canaries'
    /// own encodings.
    needles: Vec<(String, Vec<u8>)>,
    files: tempfile::TempDir,
    bins: PathBuf,
    env: Vec<(String, OsString)>,
    /// The logs of daemons stopped so far.
    old_logs: Vec<Vec<u8>>,
    /// Every stream captured, labeled.
    captured: Vec<(String, Vec<u8>)>,
    /// Files that hold plaintext on purpose for now (the fixture repo's env
    /// files before the import deletes them), which the sweep skips.
    allowed: Vec<PathBuf>,
    agent: Option<Agent>,
    humans: usize,
    _serial: MutexGuard<'static, ()>,
}

impl std::fmt::Debug for Harness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Harness")
            .field("home", &self.home)
            .field("canaries", &self.canaries)
            .finish_non_exhaustive()
    }
}

impl Harness {
    /// A new user with a daemon running and no vault.
    pub fn start() -> Harness {
        Harness::start_with(&[])
    }

    /// As [`Harness::start`], with `env` set for the daemon and every
    /// command (gate 12's `RUST_LOG=trace`, say).
    ///
    /// # Panics
    /// When the daemon does not start.
    pub fn start_with(env: &[(&str, &str)]) -> Harness {
        Harness::start_from(bin_dir(), env)
    }

    /// As [`Harness::start_with`], with `envcloak` and `envcloakd` from
    /// `bins`: a test's own copies, which it may replace while the daemon
    /// runs (the daemon's anchor, M2 task M2-27).
    ///
    /// # Panics
    /// When the daemon does not start.
    pub fn start_from(bins: PathBuf, env: &[(&str, &str)]) -> Harness {
        let serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
        let mut cs = canaries(fresh_seed());
        // Passphrases of six random words, as `vault create` suggests.
        let words = |seed: u64| {
            let c = canaries(seed);
            let w = c
                .iter()
                .find(|c| c.label == envcloak_testkit::labels::VAULT_PASSPHRASE)
                .map(|c| c.as_str().to_owned())
                .unwrap_or_default();
            format!("{w} {:04x}", seed & 0xffff)
        };
        cs.push(Canary::new(NEW_PASSPHRASE, words(fresh_seed())));
        cs.push(Canary::new(WRONG_PASSPHRASE, words(fresh_seed())));
        let home = TestHome::new();
        let files = tempfile::Builder::new()
            .prefix("ecf")
            .tempdir_in("/tmp")
            .unwrap_or_else(|e| panic!("cannot create the files directory: {e}"));
        let env: Vec<(String, OsString)> = env
            .iter()
            .map(|(k, v)| ((*k).to_owned(), OsString::from(v)))
            .collect();
        let daemon = start_daemon(&home, &bins, &env);
        Harness {
            home,
            daemon,
            canaries: cs,
            needles: Vec::new(),
            files,
            bins,
            env,
            old_logs: Vec::new(),
            captured: Vec::new(),
            allowed: Vec::new(),
            agent: None,
            humans: 0,
            _serial: serial,
        }
    }

    /// The `envcloak` under test.
    pub fn cli(&self) -> PathBuf {
        self.bins.join("envcloak")
    }

    /// The `envcloakd` under test.
    pub fn daemon_exe(&self) -> PathBuf {
        self.bins.join("envcloakd")
    }

    /// The directory for files that hold secrets on purpose (passphrases,
    /// the kit, a new value to rotate in): outside the home, so its sweep
    /// is about what EnvCloak wrote.
    pub fn files(&self) -> &Path {
        self.files.path()
    }

    /// The daemon's data directory in this home.
    pub fn data_dir(&self) -> PathBuf {
        if cfg!(target_os = "macos") {
            self.home
                .home()
                .join("Library/Application Support/EnvCloak")
        } else {
            self.home.root().join("data/envcloak")
        }
    }

    /// The canary labeled `label`.
    ///
    /// # Panics
    /// When there is none.
    pub fn canary(&self, label: &str) -> &Canary {
        envcloak_testkit::by_label(&self.canaries, label)
    }

    /// The value of the canary labeled `label`.
    pub fn value(&self, label: &str) -> &[u8] {
        self.canary(label).value()
    }

    /// Writes the canary labeled `label` (and a newline) to a file of its
    /// own in [`Harness::files`], for a descriptor or standard input.
    ///
    /// # Panics
    /// When it cannot be written.
    pub fn secret_file(&self, label: &str, newline: bool) -> PathBuf {
        let p = self.files().join(label.to_ascii_lowercase());
        let mut v = self.value(label).to_vec();
        if newline {
            v.push(b'\n');
        }
        std::fs::write(&p, v).unwrap_or_else(|e| panic!("write a secret file: {e}"));
        p
    }

    /// Adds a canary: looked for from now on, in everything so far too.
    pub fn add_canary(&mut self, c: Canary) {
        self.canaries.push(c);
    }

    /// Adds bytes a serializer made of a canary, looked for as they are.
    pub fn add_needle(&mut self, label: String, bytes: Vec<u8>) {
        if !bytes.is_empty() && !self.needles.iter().any(|(_, b)| *b == bytes) {
            self.needles.push((label, bytes));
        }
    }

    /// Lets the sweep skip `p`, which holds plaintext on purpose for now.
    pub fn allow_plaintext(&mut self, p: PathBuf) {
        self.allowed.push(p);
    }

    /// Ends every [`Harness::allow_plaintext`].
    pub fn allow_no_plaintext(&mut self) {
        self.allowed.clear();
    }

    /// Panics if `bytes` holds a canary or a needle, naming only labels.
    pub fn assert_clean(&self, what: &str, bytes: &[u8]) {
        let leaks = self.leaks_in(what, bytes);
        assert!(leaks.is_empty(), "{}", show(&leaks));
    }

    fn leaks_in(&self, what: &str, bytes: &[u8]) -> Vec<Leak> {
        let mut out: Vec<Leak> = Detector::new(&self.canaries)
            .find(bytes)
            .into_iter()
            .map(|f| {
                Leak(format!(
                    "{} as {} at offset {} of {what}",
                    f.label, f.encoding, f.offset
                ))
            })
            .collect();
        for (label, needle) in &self.needles {
            if let Some(at) = position(bytes, needle) {
                out.push(Leak(format!(
                    "{label} (a serializer's output) at offset {at} of {what}"
                )));
            }
        }
        out
    }

    fn keep(&mut self, what: String, bytes: &[u8]) {
        self.assert_clean(&what, bytes);
        self.captured.push((what, bytes.to_vec()));
    }

    /// Keeps `bytes`, something a process printed or answered that the
    /// test captured itself, for the sweep; panics now if it leaks.
    pub fn record(&mut self, what: &str, bytes: &[u8]) {
        self.keep(what.to_owned(), bytes);
    }

    /// Runs `program <args>` in this home's environment and the harness's
    /// variables (no terminal, not the agent), with standard input from
    /// `stdin` or empty, and returns its output, swept.
    ///
    /// # Panics
    /// When it does not finish.
    pub fn program(&mut self, program: &Path, args: &[&str], stdin: Option<&Path>) -> Output {
        let mut cmd = self.command(program);
        cmd.args(args)
            .current_dir(self.home.home())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        match stdin {
            Some(p) => {
                let f =
                    std::fs::File::open(p).unwrap_or_else(|e| panic!("open {}: {e}", p.display()));
                cmd.stdin(Stdio::from(f));
            }
            None => {
                cmd.stdin(Stdio::null());
            }
        }
        let out = finish_within(cmd, COMMAND_LIMIT);
        let name = program
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        self.keep(format!("{name} (stdout)"), &out.stdout);
        self.keep(format!("{name} (stderr)"), &out.stderr);
        out
    }

    /// Whether the binaries are this target directory's own test build,
    /// which has the test-only hooks (`ENVCLOAK_TEST_PANIC`), rather than
    /// `ENVCLOAK_E2E_BIN_DIR`'s.
    pub fn test_build(&self) -> bool {
        std::env::var_os("ENVCLOAK_E2E_BIN_DIR").is_none()
    }

    /// A command applied to this home's environment and the harness's own
    /// variables.
    fn command(&self, program: &Path) -> Command {
        let mut cmd = Command::new(program);
        self.home.apply(&mut cmd);
        cmd.envs(self.env.iter().map(|(k, v)| (k, v)));
        cmd
    }

    /// `argv` run by the person in `cwd` (see [`HUMAN`]): `fds` are
    /// `(n, path, for_reading)`, and `steps` what to type once the
    /// terminal shows each prompt. Swept before it is returned.
    ///
    /// # Panics
    /// When the command does not finish, or a prompt does not show.
    pub fn human_argv(
        &mut self,
        cwd: &Path,
        argv: &[&str],
        fds: &[(i32, &Path, bool)],
        steps: &[(&str, &str)],
    ) -> Human {
        self.humans += 1;
        let n = self.humans;
        let spec_path = self.files().join(format!("human-{n}.json"));
        let transcript = self.files().join(format!("human-{n}.tty"));
        let code = self.files().join(format!("human-{n}.code"));
        let spec = serde_json::json!({
            "limit": COMMAND_LIMIT.as_secs(),
            "fds": fds.iter().map(|(n, p, r)| {
                serde_json::json!([n, p.to_str().unwrap_or(""), if *r { "r" } else { "w" }])
            }).collect::<Vec<_>>(),
            "steps": steps.iter().map(|(a, b)| serde_json::json!([a, b])).collect::<Vec<_>>(),
            "transcript": transcript.to_str().unwrap_or(""),
            "code": code.to_str().unwrap_or(""),
        });
        std::fs::write(&spec_path, spec.to_string())
            .unwrap_or_else(|e| panic!("write the terminal spec: {e}"));
        let mut cmd = self.command(&python3());
        cmd.arg("-c")
            .arg(HUMAN)
            .arg(&spec_path)
            .args(argv)
            .current_dir(cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let out = finish_within(cmd, COMMAND_LIMIT + Duration::from_secs(60));
        let tty = std::fs::read(&transcript).unwrap_or_default();
        let _ = std::fs::remove_file(&transcript);
        let _ = std::fs::remove_file(&spec_path);
        let code_text = std::fs::read_to_string(&code).ok();
        let _ = std::fs::remove_file(&code);
        self.keep(format!("the person's command {n} (stdout)"), &out.stdout);
        self.keep(format!("the person's command {n} (stderr)"), &out.stderr);
        self.keep(format!("the person's command {n} (terminal)"), &tty);
        let Some(code) = code_text.and_then(|c| c.trim().parse().ok()) else {
            panic!(
                "the person's command {n} did not finish or a prompt did not show:\n{}\n--- \
                 terminal\n{}",
                text(&out),
                String::from_utf8_lossy(&tty)
            );
        };
        Human {
            code,
            stdout: out.stdout,
            stderr: out.stderr,
            tty,
        }
    }

    /// `envcloak <args>` run by the person in `cwd`. See
    /// [`Harness::human_argv`].
    pub fn human(
        &mut self,
        cwd: &Path,
        args: &[&str],
        fds: &[(i32, &Path, bool)],
        steps: &[(&str, &str)],
    ) -> Human {
        let cli = self.cli();
        let mut argv = vec![cli.to_str().unwrap_or("")];
        argv.extend_from_slice(args);
        self.human_argv(cwd, &argv, fds, steps)
    }

    /// The person, apart from the harness: for a thread that acts while
    /// something else runs (M2-09's probes ask for approvals while a host
    /// runs). What it runs is kept for [`Harness::keep_person`].
    pub fn person(&self) -> Person {
        let mut env: Vec<(OsString, OsString)> = self
            .home
            .vars()
            .into_iter()
            .map(|(k, v)| (OsString::from(k), v))
            .collect();
        env.extend(self.env.iter().map(|(k, v)| (OsString::from(k), v.clone())));
        let files = self.files().join("person");
        std::fs::create_dir_all(&files)
            .unwrap_or_else(|e| panic!("create the person's directory: {e}"));
        Person {
            python: python3(),
            cli: self.cli(),
            env,
            files,
            n: std::sync::atomic::AtomicUsize::new(0),
            kept: Mutex::new(Vec::new()),
        }
    }

    /// Sweeps and keeps what `person` printed and showed.
    pub fn keep_person(&mut self, person: &Person) {
        let kept = std::mem::take(&mut *person.kept.lock().unwrap_or_else(PoisonError::into_inner));
        for (what, bytes) in kept {
            self.keep(what, &bytes);
        }
    }

    /// Starts the agent, whose shell runs in `dir`, if it is not running.
    fn agent_session(&mut self, dir: &Path) -> &mut Agent {
        if self.agent.is_none() {
            let out_dir = self.home.root().join("agent");
            std::fs::create_dir_all(&out_dir)
                .unwrap_or_else(|e| panic!("create the agent's directory: {e}"));
            let mut cmd = self.command(&envcloak_testkit::testkit_bin("fixture-agent"));
            let mut child = cmd
                .args(["--", "/bin/sh"])
                .current_dir(dir)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap_or_else(|e| panic!("start fixture-agent: {e}"));
            let Some(stdin) = child.stdin.take() else {
                panic!("fixture-agent has no stdin");
            };
            self.agent = Some(Agent {
                child,
                stdin,
                dir: out_dir,
                n: 0,
            });
        }
        match self.agent.as_mut() {
            Some(a) => a,
            None => panic!("no agent"),
        }
    }

    /// The agent's pid: the root of every grant for its commands.
    pub fn agent_pid(&mut self, dir: &Path) -> u32 {
        self.agent_session(dir).child.id()
    }

    /// Runs `line` in the agent's shell, in `cwd` (the agent starts there
    /// if it is not running), and returns its output, swept.
    ///
    /// # Panics
    /// When the command does not finish.
    pub fn agent_line(&mut self, cwd: &Path, line: &str) -> Output {
        let agent = self.agent_session(cwd);
        agent.n += 1;
        let base = agent.dir.join(agent.n.to_string());
        let (out, err, code) = (
            base.with_extension("out"),
            base.with_extension("err"),
            base.with_extension("code"),
        );
        let path = |p: &Path| quoted(p.to_str().unwrap_or(""));
        let written = writeln!(
            agent.stdin,
            "( cd {} && {line} ) </dev/null >{} 2>{}; echo $? >{}.tmp; mv {}.tmp {}",
            path(cwd),
            path(&out),
            path(&err),
            path(&code),
            path(&code),
            path(&code)
        )
        .and_then(|()| agent.stdin.flush());
        if let Err(e) = written {
            panic!("the agent's shell is gone: {e}");
        }
        let n = agent.n;
        let end = Instant::now() + COMMAND_LIMIT;
        let status = loop {
            if let Ok(s) = std::fs::read_to_string(&code) {
                if let Ok(c) = s.trim().parse::<i32>() {
                    break ExitStatus::from_raw(c << 8);
                }
            }
            assert!(
                Instant::now() < end,
                "the agent's command {n} did not finish"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        let o = Output {
            status,
            stdout: std::fs::read(&out).unwrap_or_default(),
            stderr: std::fs::read(&err).unwrap_or_default(),
        };
        for p in [&out, &err, &code] {
            let _ = std::fs::remove_file(p);
        }
        self.keep(format!("the agent's command {n} (stdout)"), &o.stdout);
        self.keep(format!("the agent's command {n} (stderr)"), &o.stderr);
        o
    }

    /// Starts `line` in the background as a job of the agent's shell
    /// itself, in `cwd`, and returns at once: the agent stays its
    /// ancestor while it runs (a job of a subshell that exits would be
    /// reparented, and leave the agent's tree). Its output goes nowhere.
    ///
    /// # Panics
    /// When the agent's shell is gone.
    pub fn agent_spawn(&mut self, cwd: &Path, line: &str) {
        let agent = self.agent_session(cwd);
        let written = writeln!(
            agent.stdin,
            "cd {}; {line} </dev/null >/dev/null 2>&1 &",
            quoted(cwd.to_str().unwrap_or(""))
        )
        .and_then(|()| agent.stdin.flush());
        if let Err(e) = written {
            panic!("the agent's shell is gone: {e}");
        }
    }

    /// Kills, with SIGKILL, the job [`Harness::agent_spawn`] started last:
    /// the agent's shell signals its own child (`kill -KILL $!`), as an
    /// agent ending a program it started would. Returns at once.
    ///
    /// # Panics
    /// When the agent's shell is gone.
    pub fn agent_kill_last(&mut self) {
        let Some(agent) = self.agent.as_mut() else {
            panic!("no agent");
        };
        let written = writeln!(agent.stdin, "kill -KILL $!").and_then(|()| agent.stdin.flush());
        if let Err(e) = written {
            panic!("the agent's shell is gone: {e}");
        }
    }

    /// `envcloak <args>` run by the agent in `cwd`.
    pub fn agent(&mut self, cwd: &Path, args: &[&str]) -> Output {
        let mut line = quoted(self.cli().to_str().unwrap_or(""));
        for a in args {
            line.push(' ');
            line.push_str(&quoted(a));
        }
        self.agent_line(cwd, &line)
    }

    /// Stops the daemon with SIGTERM (it locks first) and keeps its log.
    /// Returns the log, swept: complete now, since the daemon has exited
    /// and its log has been read to the end, so a test checks there that
    /// a line never came.
    ///
    /// # Panics
    /// When it does not exit.
    pub fn stop_daemon(&mut self) -> String {
        self.daemon.signal("-TERM");
        assert!(
            self.daemon.wait_exit(Duration::from_secs(60)).is_some(),
            "the daemon did not stop"
        );
        let log = self.daemon.log_bytes();
        self.assert_clean("a stopped daemon's log", &log);
        let text = String::from_utf8_lossy(&log).into_owned();
        self.old_logs.push(log);
        text
    }

    /// Starts a new daemon, after [`Harness::stop_daemon`], with the
    /// harness's variables and `extra`.
    pub fn start_daemon(&mut self, extra: &[(&str, &str)]) {
        let mut env = self.env.clone();
        env.extend(
            extra
                .iter()
                .map(|(k, v)| ((*k).to_owned(), OsString::from(v))),
        );
        self.daemon = start_daemon(&self.home, &self.bins, &env);
    }

    /// Every leak: in what any process printed, in every daemon's log, and
    /// anywhere in the home but the files [`Harness::allow_plaintext`]
    /// names.
    pub fn sweep(&self) -> Vec<Leak> {
        let mut leaks = Vec::new();
        for (what, bytes) in &self.captured {
            leaks.extend(self.leaks_in(what, bytes));
        }
        for (i, log) in self.old_logs.iter().enumerate() {
            leaks.extend(self.leaks_in(&format!("the log of daemon {}", i + 1), log));
        }
        leaks.extend(self.leaks_in("the daemon's log", &self.daemon.log_bytes()));
        for hit in sweep_dir(self.home.root(), &self.canaries) {
            let path = match &hit {
                envcloak_testkit::Hit::Canary { path, .. }
                | envcloak_testkit::Hit::Name { path, .. }
                | envcloak_testkit::Hit::LinkTarget { path, .. }
                | envcloak_testkit::Hit::Unreadable { path, .. } => path.raw().to_path_buf(),
            };
            if !self.allowed.contains(&path) {
                leaks.push(Leak(hit.to_string()));
            }
        }
        leaks
    }

    /// Waits up to `limit` for the running daemon's log to hold a line
    /// with `text`. The client can have its answer before the daemon's
    /// line reaches the log (testkit's reader thread collects it), so a
    /// test reads the log only after this (review T14-3). On failure the
    /// log is swept first and then shown, so a failure message never
    /// prints a value.
    pub fn expect_log(&mut self, text: &str, limit: Duration) -> String {
        let seen = self.daemon.wait_for_log(text, limit);
        let log = self.daemon.log_bytes();
        self.assert_clean("the daemon's log", &log);
        let log = String::from_utf8_lossy(&log).into_owned();
        assert!(
            seen,
            "no line with {text:?} in the daemon's log after {limit:?}:\n{log}"
        );
        log
    }

    /// Panics if [`Harness::sweep`] finds anything, listing it without
    /// values.
    pub fn assert_swept(&self, when: &str) {
        let leaks = self.sweep();
        assert!(leaks.is_empty(), "{when}: {}", show(&leaks));
    }

    /// Everything captured so far, for a test that looks through it.
    pub fn captured(&self) -> &[(String, Vec<u8>)] {
        &self.captured
    }

    /// The logs of every daemon, stopped ones first.
    pub fn daemon_logs(&self) -> Vec<Vec<u8>> {
        let mut logs = self.old_logs.clone();
        logs.push(self.daemon.log_bytes());
        logs
    }
}

fn show(leaks: &[Leak]) -> String {
    let shown: Vec<String> = leaks.iter().take(12).map(Leak::to_string).collect();
    format!(
        "{} leak(s): {}{}",
        leaks.len(),
        shown.join("; "),
        if leaks.len() > shown.len() {
            "; ..."
        } else {
            ""
        }
    )
}

fn position(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    let first = needle[0];
    (0..=hay.len() - needle.len()).find(|&i| hay[i] == first && hay[i..i + needle.len()] == *needle)
}

/// `envcloakd --foreground` in `home`, by absolute path, with `env`.
fn start_daemon(home: &TestHome, bins: &Path, env: &[(String, OsString)]) -> Daemon {
    let mut cmd = Command::new(bins.join("envcloakd"));
    home.apply(&mut cmd);
    cmd.envs(env.iter().map(|(k, v)| (k, v)));
    Daemon::start_command(cmd, &[])
}

/// Spawns `cmd` and waits up to `limit` for it, collecting its output as
/// it comes (never `Command::output`, whose pipes can fill). A process
/// that does not exit in time is killed, and the test fails.
///
/// # Panics
/// As above, and when the process cannot start.
pub fn finish_within(mut cmd: Command, limit: Duration) -> Output {
    let mut child = cmd
        .spawn()
        .unwrap_or_else(|e| panic!("cannot start a process: {e}"));
    let out = child.stdout.take();
    let err = child.stderr.take();
    let read = |s: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut v = Vec::new();
            if let Some(mut s) = s {
                let _ = s.read_to_end(&mut v);
            }
            v
        })
    };
    let out = read(out.map(|s| Box::new(s) as Box<dyn Read + Send>));
    let err = read(err.map(|s| Box::new(s) as Box<dyn Read + Send>));
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) => {}
            Err(e) => panic!("wait: {e}"),
        }
        if start.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            panic!("a process did not exit within {limit:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Output {
        status,
        stdout: out.join().unwrap_or_default(),
        stderr: err.join().unwrap_or_default(),
    }
}

/// Makes `path` an executable shell script holding `body`.
///
/// # Panics
/// When it cannot be written.
pub fn write_script(path: &Path, body: &str) {
    std::fs::write(path, body).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .unwrap_or_else(|e| panic!("chmod {}: {e}", path.display()));
}
