//! PTY mode's job control through the whole of `envcloak run --pty` (M2
//! plan task M2-19, decision D-35, review F-76), on macOS and Linux, and
//! gate 23 in PTY mode.
//!
//! The isolated outer-shell gate: a private outer pseudo-terminal the test
//! owns runs a job-control shell (`/bin/sh -i`, `set -m`, the test home's
//! cleared environment, no rc files), which starts `envcloak run --pty`
//! against the fixture project (a vault made through the CLI, the repo's
//! values imported, a PEM-shaped item added and bound), its runs covered
//! by a grant the person gave from a terminal of their own for the shell's
//! session. In that shell:
//!
//! - `/bin/cat`, first under the plain shell for its baseline, then under
//!   `envcloak run --pty`: the outer terminal's suspend character gives the
//!   shell its prompt back, `jobs` lists the job as stopped, `stty -g` is
//!   what it was before, and `fg` resumes it; Linux cat reads on. BSD cat
//!   may read on or end with EINTR depending on whether the stop landed
//!   inside read. The retrying cat below must always read on;
//! - a cat that reads again on `EINTR`: the same, then (once it says it
//!   was continued) a fresh line round-trips, and values typed into it
//!   (the PEM-shaped one, whose CR LF form the terminal shows, and an API
//!   key) come back redacted (its echo turned off first: on Linux the echo
//!   of a later line falls between the copies of the lines before,
//!   measured in CI);
//! - a nested interactive shell as the command: the suspend character
//!   stops its job and gives it its prompt back while `envcloak run` stays
//!   running with the outer terminal raw, and `fg` in it resumes the job;
//! - a raw-mode program that reads the suspend character as data, puts its
//!   terminal back and stops itself (`kill(0, SIGTSTP)`): the outer shell
//!   gets its prompt and `fg` resumes it;
//! - the suspend character remapped (`stty susp ^X`: ^X suspends, ^Z
//!   reaches cat as data) and disabled (`stty susp undef`: nothing
//!   suspends, the byte reaches cat);
//! - SIGTSTP sent to `envcloak run` from outside (by the program that
//!   started it, its owner): the command is stopped before the outer
//!   terminal is restored, observed at the actual restore in testing
//!   builds. External release binaries have no test hooks; they still
//!   must leave the command stopped when the outer prompt comes, restore
//!   the settings and resume the command on `fg`;
//! - the retrying cat again under `/bin/dash -i`, a job of the outer shell
//!   in its session: dash, unlike bash, does not put its own terminal
//!   settings back when a job stops, so `stty -g` at its prompt is what
//!   `envcloak run` restored before it stopped;
//! - a panic in the relay (a test build's injected one) leaves the outer
//!   terminal as it was, echo on.
//! - startup status stays unknown after an observed side effect if the
//!   monitor's Started report is lost (testing builds); ordinary startup
//!   and descriptor-inheritance controls run on release binaries too.
//!
//! Gate 23 in PTY mode: `y` typed into the requester's terminal while a
//! `--pty --wait` run waits for approval approves nothing. And `--pty`
//! with no terminal (the agent's shell, on pipes) exits 125 with
//! `pty_unavailable` and asks the daemon nothing.
//!
//! Barriers are what the terminal shows (prompts, fixture lines), never a
//! sleep. The fixtures are Python programs written into the harness's
//! files directory; the only process the test signals is its own child.
//! Every byte the outer terminal showed is swept with the rest of the
//! harness's captures, for every canary in every encoding and the CR LF
//! form of the PEM-shaped value.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use envcloak_e2e::{Harness, age, python3, quoted, text, token};
use envcloak_sys::pty::open_pty;
use envcloak_sys::{TerminalSettings, wait_any};
use envcloak_testkit::{Canary, labels};

/// How long a step waits for what it expects.
const DEADLINE: Duration = Duration::from_secs(120);
const PROMPT: &str = "EC-OUTER> ";
const INNER: &str = "EC-INNER> ";
/// Typed into a shell first: bash (macOS's `/bin/sh` is bash 3.2) turns
/// its line editing off, so readline's own signal handling is out of the
/// way; dash has no `BASH_VERSION`.
const NO_EDITING: &str = "case ${BASH_VERSION-} in ?*) set +o emacs +o vi;; esac; ";
/// The PEM-shaped item's label, slug and variable.
const PEM: &str = "PEM_BLOCK";
const PEM_CRLF: &str = "PEM_BLOCK_CRLF";
const PEM_SLUG: &str = "tls/acme-web";
const OPENAI_SLUG: &str = "openai/acme-web";

/// Leads a new session on the terminal on its standard input and becomes
/// argv[1..] (`exec`: the same process).
const LEAD: &str = "import fcntl, os, sys, termios\n\
os.setsid()\n\
fcntl.ioctl(0, termios.TIOCSCTTY, 0)\n\
os.execv(sys.argv[1], sys.argv[1:])\n";

/// A cat that reads again when a read is interrupted (`EINTR`, PEP 475),
/// writes whole, and keeps SIGTSTP's default. Prints `CAT-READY` first,
/// and `CAT-CONT` each time it is continued (SIGCONT), so a line is typed
/// after `fg` only once it reads again. On the line `QUIET` it turns its
/// terminal's echo off before it copies the line, so what is typed after
/// shows only as its copy: the line discipline's echo of a later line
/// cannot fall between the copies of the lines before (it does on Linux,
/// measured), and a value typed over several lines comes back whole.
const RETRY_CAT: &str = r"import os, signal, termios
signal.signal(signal.SIGCONT, lambda sig, frame: os.write(1, b'CAT-CONT\n'))
os.write(1, b'CAT-READY\n')
while True:
    b = os.read(0, 65536)
    if not b:
        break
    if b == b'QUIET\n':
        t = termios.tcgetattr(0)
        t[3] &= ~termios.ECHO
        termios.tcsetattr(0, termios.TCSANOW, t)
    while b:
        b = b[os.write(1, b):]
";

/// Raw mode (no signal characters), `RAW-READY`; on the suspend byte read
/// as data: `GOT-SUSPEND-BYTE`, the terminal put back, and SIGTSTP to its
/// own group; once continued, `RAW-RESUMED`, then one line read and shown
/// as `LINE [...]`.
const RAW_SUSPEND: &str = r"import os, signal, sys, termios, tty
saved = termios.tcgetattr(0)
tty.setraw(0)
os.write(1, b'RAW-READY\r\n')
while True:
    b = os.read(0, 1)
    if not b:
        sys.exit(2)
    if b == b'\x1a':
        break
os.write(1, b'GOT-SUSPEND-BYTE\r\n')
termios.tcsetattr(0, termios.TCSAFLUSH, saved)
os.kill(0, signal.SIGTSTP)
os.write(1, b'RAW-RESUMED\n')
line = sys.stdin.buffer.readline().rstrip(b'\r\n')
os.write(1, b'LINE [' + line + b']\n')
";

/// `TICKER-READY <pid>`, then a line appended to argv[1] every 10 ms while
/// it runs; `GOT [...]` for each line read; exits 0 on `done`.
const TICKER: &str = r"import os, sys, threading, time
path = sys.argv[1]
def tick():
    while True:
        with open(path, 'a') as f:
            f.write('t\n')
        time.sleep(0.01)
threading.Thread(target=tick, daemon=True).start()
os.write(1, b'TICKER-READY %d\n' % os.getpid())
for line in sys.stdin.buffer:
    line = line.rstrip(b'\r\n')
    if line == b'done':
        break
    os.write(1, b'GOT [' + line + b']\n')
";

/// Starts argv[2..] as its child and owns it: a signal name on the FIFO
/// argv[1] signals that child (its own unreaped child, never a
/// number read from elsewhere). Exits as the child did.
const SIGNALLER: &str = r"import os, select, signal, sys
fifo = sys.argv[1]
signals = {b'TSTP': signal.SIGTSTP, b'INT': signal.SIGINT,
           b'QUIT': signal.SIGQUIT, b'TERM': signal.SIGTERM, b'HUP': signal.SIGHUP}
pid = os.fork()
if pid == 0:
    os.execv(sys.argv[2], sys.argv[2:])
fd = os.open(fifo, os.O_RDWR)
while True:
    r, _, _ = select.select([fd], [], [], 0.05)
    if r:
        for word in os.read(fd, 64).split():
            if word in signals:
                os.kill(pid, signals[word])
    done, status = os.waitpid(pid, os.WNOHANG)
    if done:
        code = os.waitstatus_to_exitcode(status)
        os._exit(code if code >= 0 else 128 - code)
";

/// A PEM-shaped block made at run time: header and footer split so no
/// key-shaped literal is in the source, a base64 body of the harness's
/// random canary bytes in lines of 64, each ended by LF (none after the
/// footer).
fn pem(seed_text: &str) -> String {
    let body: String = seed_text
        .bytes()
        .cycle()
        .take(192)
        .enumerate()
        .map(|(i, b)| {
            let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            char::from(alphabet[(usize::from(b) * 7 + i * 13) % 64])
        })
        .collect();
    let kind = concat!("ENVCLOAK ", "JOB ", "BLOCK");
    let mut out = format!("-----{} {kind}-----\n", "BEGIN");
    for line in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----{} {kind}-----", "END"));
    out
}

fn crlf(value: &str) -> String {
    value.replace('\n', "\r\n")
}

/// A vault made through the CLI, unlocked, with the story's repo imported
/// (`.env` taken out after an encrypted backup), the PEM-shaped item
/// added and bound as `PEM_BLOCK`, and the passphrase on a file.
fn project(h: &mut Harness) -> (PathBuf, PathBuf) {
    let pass = h.secret_file(labels::VAULT_PASSPHRASE, true);
    let kit = h.files().join("kit");
    let home = h.home.home();
    let made = h.human(
        &home,
        &[
            "vault",
            "create",
            "--passphrase-fd",
            "3",
            "--kit-fd",
            "4",
            "--kdf-memory",
            "64MiB",
        ],
        &[(3, &pass, true), (4, &kit, false)],
        &[],
    );
    assert_eq!(made.code, 0, "{}", made.all());
    let text_kit = std::fs::read_to_string(&kit).unwrap();
    h.add_canary(Canary::new(
        envcloak_e2e::RECOVERY_KIT,
        text_kit.trim_end().to_owned(),
    ));
    let repo = h.home.root().join("acme-web");
    std::fs::create_dir_all(&repo).unwrap();
    let env = format!(
        "OPENAI_API_KEY={}\nDATABASE_URL='{}'\n",
        h.canary(labels::OPENAI_API_KEY).as_str(),
        h.canary(labels::DATABASE_URL).as_str().replace('\'', "")
    );
    std::fs::write(repo.join(".env"), env).unwrap();
    age(&repo.join(".env"), Duration::from_secs(600));
    h.allow_plaintext(repo.join(".env"));
    let imported = h.human(&repo, &["init", "--import", "--yes"], &[], &[]);
    assert_eq!(imported.code, 0, "{}", imported.all());
    let confirmed = h.human(
        &repo,
        &["recovery", "confirm", "--kit-fd", "4"],
        &[(4, &kit, true)],
        &[],
    );
    assert_eq!(confirmed.code, 0, "{}", confirmed.all());
    let deleted = h.human(&repo, &["init", "--delete-plaintext"], &[], &[]);
    assert_eq!(deleted.code, 0, "{}", deleted.all());
    h.allow_no_plaintext();
    // The PEM-shaped item, from standard input, bound in the manifest.
    let value = pem(h.canary(labels::GITHUB_TOKEN).as_str());
    h.add_canary(Canary::new(PEM, value.clone()));
    h.add_canary(Canary::new(PEM_CRLF, crlf(&value)));
    let file = h.files().join("pem");
    std::fs::write(&file, &value).unwrap();
    let added = h.human(
        &repo,
        &["add", "--slug", PEM_SLUG, "--stdin", "--json"],
        &[(0, &file, true)],
        &[],
    );
    assert_eq!(added.code, 0, "{}", added.all());
    let _ = std::fs::remove_file(&file);
    let bound = h.human(&repo, &["ref", &format!("{PEM}={PEM_SLUG}")], &[], &[]);
    assert_eq!(bound.code, 0, "{}", bound.all());
    (repo, pass)
}

/// The person's terminal: a pseudo-terminal the test owns, and all it
/// has shown.
struct Outer {
    master: File,
    slave: OwnedFd,
    seen: Vec<u8>,
    /// What a message never shows: the harness's canaries.
    cs: Vec<Canary>,
}

impl Outer {
    fn new(cs: Vec<Canary>) -> Outer {
        let size = envcloak_sys::WindowSize {
            rows: 24,
            cols: 80,
            ..envcloak_sys::WindowSize::default()
        };
        let pty = open_pty(Some(size), None).unwrap();
        Outer {
            master: File::from(pty.master),
            slave: pty.slave,
            seen: Vec::new(),
            cs,
        }
    }

    fn settings(&self) -> TerminalSettings {
        TerminalSettings::read(self.slave.as_fd()).unwrap()
    }

    fn type_bytes(&self, bytes: &[u8]) {
        (&self.master).write_all(bytes).unwrap();
    }

    fn count_since(&self, mark: usize, needle: &[u8]) -> usize {
        count(self.seen.get(mark..).unwrap_or_default(), needle)
    }

    /// What the terminal showed since `mark`, for a message: as it is
    /// when it holds no canary, otherwise only where each one is, so a
    /// failure never prints a value.
    fn shown_since(&self, mark: usize) -> String {
        let seen = self.seen.get(mark..).unwrap_or_default();
        let found = envcloak_testkit::find(seen, &self.cs);
        if found.is_empty() {
            return String::from_utf8_lossy(seen).into_owned();
        }
        let at: Vec<String> = found
            .iter()
            .map(|f| format!("{} as {} at {}", f.label, f.encoding, f.offset))
            .collect();
        format!(
            "<{} bytes not shown: they hold {}>",
            seen.len(),
            at.join(", ")
        )
    }

    fn text(&self) -> String {
        self.shown_since(0)
    }

    /// Reads what comes for `limit`, or until `done` holds.
    fn wait_for_within(&mut self, limit: Duration, done: impl Fn(&Outer) -> bool) -> bool {
        let end = Instant::now() + limit;
        loop {
            if done(self) {
                return true;
            }
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            let shown = wait_any(
                &[(Some(self.master.as_fd()), true, false)],
                Some(left.min(Duration::from_millis(20))),
            )
            .unwrap();
            if !shown[0].readable {
                continue;
            }
            let mut buf = [0u8; 8192];
            match (&self.master).read(&mut buf) {
                Ok(n) => self.seen.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return done(self),
            }
        }
    }

    /// Waits until `needle` has been shown `times` times since `mark`.
    fn expect_since(&mut self, mark: usize, needle: &[u8], times: usize, what: &str) {
        let ok = self.wait_for_within(DEADLINE, |o| o.count_since(mark, needle) >= times);
        assert!(
            ok,
            "{what}: {:?} was not shown {times} time(s) since the mark; the terminal \
             showed:\n{}",
            String::from_utf8_lossy(needle),
            self.text()
        );
    }
}

fn count(hay: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || hay.len() < needle.len() {
        return 0;
    }
    hay.windows(needle.len()).filter(|w| *w == needle).count()
}

/// The outer job-control shell, leading a session on [`Outer`] in the
/// repo, with the test home's environment.
struct Shell {
    outer: Outer,
    child: Child,
    prompts: usize,
    syncs: usize,
}

impl Shell {
    fn start(h: &Harness, repo: &Path) -> Shell {
        let outer = Outer::new(h.canaries.clone());
        let mut cmd = Command::new(python3());
        h.home.apply(&mut cmd);
        let slave = || Stdio::from(outer.slave.try_clone().unwrap());
        cmd.arg("-c")
            .arg(LEAD)
            .arg("/bin/sh")
            .arg("-i")
            .env("PS1", PROMPT)
            .env("LC_ALL", "C")
            .current_dir(repo)
            .stdin(slave())
            .stdout(slave())
            .stderr(slave());
        let child = cmd.spawn().unwrap();
        let mut sh = Shell {
            outer,
            child,
            prompts: 1,
            syncs: 0,
        };
        sh.outer
            .expect_since(0, PROMPT.as_bytes(), 1, "the outer shell's first prompt");
        sh.say(&format!("{NO_EDITING}set -m"));
        sh
    }

    fn mark(&self) -> usize {
        self.outer.seen.len()
    }

    /// Types `line` and waits for the next prompt.
    fn say(&mut self, line: &str) {
        self.outer.type_bytes(format!("{line}\r").as_bytes());
        self.prompt_again(line);
    }

    /// Waits for the shell's next prompt (a job stopped or ended).
    fn prompt_again(&mut self, what: &str) {
        self.prompts += 1;
        self.outer
            .expect_since(0, PROMPT.as_bytes(), self.prompts, what);
    }

    /// Types `line` (a job's command line) without waiting for a prompt.
    fn start_job(&mut self, line: &str) {
        self.outer.type_bytes(format!("{line}\r").as_bytes());
    }

    /// A barrier: the shell echoes a fresh word (typed in two quoted
    /// halves, so the typed line never shows it whole), and the prompt
    /// after it comes; the prompts are counted from there.
    fn sync(&mut self) {
        self.syncs += 1;
        let word = format!("SYNC-{:04}", self.syncs);
        let mark = self.mark();
        self.outer
            .type_bytes(format!("echo \"SYN\"\"C-{:04}\"\r", self.syncs).as_bytes());
        let line = format!("{word}\r\n");
        self.outer
            .expect_since(mark, line.as_bytes(), 1, "the shell's barrier");
        let at = mark
            + self.outer.seen[mark..]
                .windows(line.len())
                .position(|w| w == line.as_bytes())
                .unwrap();
        self.outer
            .expect_since(at, PROMPT.as_bytes(), 1, "the prompt after the barrier");
        self.prompts = count(&self.outer.seen, PROMPT.as_bytes());
    }

    /// The exit status of the last command, through `echo`.
    fn status(&mut self) -> i32 {
        let mark = self.mark();
        self.say("echo \"rc=$?\"");
        let shown = self.outer.shown_since(mark);
        // The last `rc=`: the first is the typed line's echo.
        shown
            .rsplit("rc=")
            .next()
            .and_then(|r| r.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|n| n.parse().ok())
            .unwrap_or_else(|| panic!("no status: {shown}"))
    }

    /// `jobs` lists the job as stopped (bash and Linux's dash say
    /// "Stopped", macOS's dash "Suspended", `strsignal`'s name for
    /// SIGTSTP there).
    fn job_stopped(&mut self) {
        let mark = self.mark();
        self.say("jobs");
        assert!(
            self.outer.count_since(mark, b"Stopped") + self.outer.count_since(mark, b"Suspended")
                >= 1,
            "jobs did not list a stopped job:\n{}",
            self.outer.text()
        );
    }

    /// `stty -g`, through a file.
    fn stty_g(&mut self, dir: &Path, name: &str) -> Vec<u8> {
        let path = dir.join(name);
        self.say(&format!("stty -g > {}", quoted(path.to_str().unwrap())));
        std::fs::read(path).unwrap()
    }

    fn exit(mut self) {
        self.outer.type_bytes(b"exit 0\r");
        let end = Instant::now() + DEADLINE;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert_eq!(status.code(), Some(0), "{}", self.outer.text());
                return;
            }
            assert!(Instant::now() < end, "the outer shell did not exit");
            self.outer
                .wait_for_within(Duration::from_millis(20), |_| false);
        }
    }
}

impl Drop for Shell {
    /// A test that failed with the shell running: killed (its own,
    /// unreaped child), its terminal read meanwhile (a session's leader on
    /// macOS waits, as it exits, until its terminal's output has been
    /// read) for at most 10 seconds, never waited for beyond that.
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let end = Instant::now() + Duration::from_secs(10);
            while self.child.try_wait().ok().flatten().is_none() && Instant::now() < end {
                self.outer
                    .wait_for_within(Duration::from_millis(20), |_| false);
            }
        }
    }
}

/// `envcloak run --pty -- <command>` as typed into the shell.
fn run_pty(h: &Harness, command: &[&str]) -> String {
    let mut line = format!("{} run --pty --", quoted(h.cli().to_str().unwrap()));
    for c in command {
        line.push(' ');
        line.push_str(&quoted(c));
    }
    line
}

/// Writes a fixture program into the harness's files directory.
fn fixture(h: &Harness, name: &str, body: &str) -> String {
    let p = h.files().join(name);
    std::fs::write(&p, body).unwrap();
    p.to_str().unwrap().to_owned()
}

/// The process state `ps` shows for `pid` (read, never signalled).
fn state_of(pid: u32) -> String {
    let out = Command::new("/bin/ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

fn lines(path: &Path) -> usize {
    std::fs::read(path).map_or(0, |b| b.iter().filter(|c| **c == b'\n').count())
}

/// Missing startup evidence must not authorize retrying a side effect.
/// Release artifacts have no injected loss; the ordinary status controls
/// still run there. Expected records are raw wire bytes, not the codec.
fn startup_status(h: &mut Harness, sh: &mut Shell, py: &str) {
    let status = h.files().join("startup-status");
    let missing = h.files().join("missing-command");
    let not_executable = fixture(h, "not-executable", "not executable\n");
    for (command, code, record) in [
        (
            "/usr/bin/true",
            0,
            b"{\"v\":1,\"state\":\"ran\",\"code\":0}\n".as_slice(),
        ),
        (
            missing.to_str().unwrap(),
            127,
            b"{\"v\":1,\"state\":\"not_started\",\"token\":\"command_not_found\"}\n".as_slice(),
        ),
        (
            not_executable.as_str(),
            126,
            b"{\"v\":1,\"state\":\"not_started\",\"token\":\"command_not_executable\"}\n"
                .as_slice(),
        ),
    ] {
        sh.say(&format!(
            "{} run --pty --status-fd 9 -- {} 9>{}",
            quoted(h.cli().to_str().unwrap()),
            quoted(command),
            quoted(status.to_str().unwrap())
        ));
        assert_eq!(
            sh.status(),
            code,
            "the startup status control: {}",
            sh.outer.text()
        );
        let bytes = std::fs::read(&status).unwrap();
        h.record("startup status control", &bytes);
        assert_eq!(bytes, record, "the startup status control record");
    }
    if !h.test_build() {
        println!(
            "startup loss: external release binaries have no injected loss; status controls passed"
        );
        return;
    }
    let ran = h.files().join("startup-side-effect");
    let release = h.files().join("startup-release");
    let command = fixture(
        h,
        "startup-side-effect.py",
        "import os, sys\nwith open(sys.argv[1], 'x') as f:\n    f.write('ran\\n')\nos.read(0, 1)\n",
    );
    let before = sh.outer.settings();
    let mark = sh.mark();
    let check_by = Instant::now() + Duration::from_secs(30);
    sh.start_job(&format!(
        "ENVCLOAK_TEST_FAIL=sys.pty.start-report ENVCLOAK_TEST_PAUSE=sys.pty.start-report \
         ENVCLOAK_TEST_PAUSE_RELEASE={} {} run --pty --status-fd 9 -- {} {} {} 9>{}",
        quoted(release.to_str().unwrap()),
        quoted(h.cli().to_str().unwrap()),
        quoted(py),
        quoted(&command),
        quoted(ran.to_str().unwrap()),
        quoted(status.to_str().unwrap())
    ));
    assert!(
        sh.outer.wait_for_within(Duration::from_secs(30), |o| {
            o.count_since(mark, b"envcloak test: paused at sys.pty.start-report") == 1
                && std::fs::read(&ran).is_ok_and(|b| b == b"ran\n")
        }),
        "the startup loss needs a paused CLI and the command's side effect: {}",
        sh.outer.text()
    );
    assert!(Instant::now() < check_by, "the startup witness expired");
    std::fs::write(release, b"").unwrap();
    sh.prompt_again("the lost startup report ended the run");
    assert_eq!(sh.status(), 125, "startup loss must fail");
    assert!(
        sh.outer.settings().same_as(&before),
        "startup loss left the terminal raw"
    );
    let bytes = std::fs::read(status).unwrap();
    h.record("lost startup status", &bytes);
    assert_eq!(
        bytes, b"{\"v\":1,\"state\":\"unknown\"}\n",
        "a lost startup report must not claim the command never ran"
    );
    println!("startup loss: command side effect witnessed, status unknown, terminal restored");
}

/// Pipe mode passes inherited descriptors through without --status-fd.
/// PTY mode replaces 0..2 and closes the rest, even without that option.
fn inherited_descriptors(h: &mut Harness, sh: &mut Shell, py: &str) {
    let source = h.files().join("inherited-source");
    std::fs::write(&source, b"owned descriptor fixture\n").unwrap();
    let probe = fixture(
        h,
        "descriptor-probe.py",
        r"import json, os, sys
source = os.stat(sys.argv[1])
def inherited(fd):
    try:
        got = os.fstat(fd)
        return (got.st_dev, got.st_ino) == (source.st_dev, source.st_ino)
    except OSError:
        return False
result = {'inherited': [inherited(3), inherited(8)],
          'tty': [os.isatty(fd) for fd in (0, 1, 2)]}
with open(sys.argv[2], 'x') as f:
    json.dump(result, f)
",
    );
    for pty in [false, true] {
        for status_fd in [false, true] {
            let result = h.files().join(format!("descriptors-{pty}-{status_fd}"));
            let status = h
                .files()
                .join(format!("descriptor-status-{pty}-{status_fd}"));
            sh.say(&format!(
                "{} run {} {} -- {} {} {} {} 3<{} 8<{} 9>{}",
                quoted(h.cli().to_str().unwrap()),
                if pty { "--pty" } else { "" },
                if status_fd { "--status-fd 9" } else { "" },
                quoted(py),
                quoted(&probe),
                quoted(source.to_str().unwrap()),
                quoted(result.to_str().unwrap()),
                quoted(source.to_str().unwrap()),
                quoted(source.to_str().unwrap()),
                quoted(status.to_str().unwrap())
            ));
            assert_eq!(
                sh.status(),
                0,
                "descriptor probe: pty={pty}, status={status_fd}"
            );
            let bytes = std::fs::read(result).unwrap();
            h.record("descriptor probe", &bytes);
            let got: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let inherit = !pty && !status_fd;
            assert_eq!(
                got,
                serde_json::json!({
                    "inherited": [inherit, inherit], "tty": [true, pty, pty]
                }),
                "descriptor inheritance: pty={pty}, status={status_fd}"
            );
            if status_fd {
                assert_eq!(
                    std::fs::read(status).unwrap(),
                    b"{\"v\":1,\"state\":\"ran\",\"code\":0}\n"
                );
            }
            println!("descriptor inheritance: pty={pty}, status={status_fd}, inherited={inherit}");
        }
    }
}

/// The real CLI is the signaller's owned child. Both a direct command and
/// a nested shell's foreground job keep one counter per forwarded signal.
fn cli_signal_receipts(h: &Harness, sh: &mut Shell, py: &str, signaller: &str) {
    const NAMES: [&str; 4] = ["INT", "QUIT", "TERM", "HUP"];
    let counter = fixture(
        h,
        "signal-counter.py",
        r"import os, pathlib, select, signal, sys, time
root = pathlib.Path(sys.argv[1])
names = {signal.SIGINT: 'INT', signal.SIGQUIT: 'QUIT',
         signal.SIGTERM: 'TERM', signal.SIGHUP: 'HUP'}
def got(sig, frame):
    with (root / ('job-' + names[sig])).open('a') as f:
        f.write('x\n')
for sig in names:
    signal.signal(sig, got)
os.write(1, b'RECEIPT-READY\n')
end = time.monotonic() + 30
while root.exists() and time.monotonic() < end:
    ready, _, _ = select.select([0], [], [], 0.05)
    if not ready:
        continue
    try:
        line = os.read(0, 65536)
    except OSError:
        break
    if not line or line.strip() == b'done':
        break",
    );
    #[cfg(target_os = "linux")]
    let narrow = !envcloak_sys::testing::group_signal_supported();
    #[cfg(not(target_os = "linux"))]
    let narrow = false;
    for nested in [false, true] {
        let name = if nested { "nested" } else { "direct" };
        let dir = h.files().join(format!("receipts-{name}"));
        std::fs::create_dir(&dir).unwrap();
        let fifo = dir.join("signals");
        assert!(
            Command::new("/usr/bin/mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let root = dir.to_str().unwrap();
        let command = if nested {
            run_pty(h, &["/bin/sh", "-i"])
        } else {
            run_pty(h, &[py, &counter, root])
        };
        let mark = sh.mark();
        sh.start_job(&format!(
            "PS1={} {} {} {} {command}",
            quoted(INNER),
            quoted(py),
            quoted(signaller),
            quoted(fifo.to_str().unwrap())
        ));
        if nested {
            // The typed command echoes the prompt's text once.
            sh.outer
                .expect_since(mark, INNER.as_bytes(), 2, "the receipt shell");
            let traps: String = NAMES
                .iter()
                .map(|sig| {
                    let path = quoted(dir.join(format!("shell-{sig}")).to_str().unwrap());
                    format!("trap {} {sig}; ", quoted(&format!("echo x >> {path}")))
                })
                .collect();
            sh.outer
                .type_bytes(format!("{traps}{NO_EDITING}set -m\r").as_bytes());
            sh.outer
                .expect_since(mark, INNER.as_bytes(), 3, "the shell's receipt traps");
            sh.outer.type_bytes(
                format!("{} {} {}\r", quoted(py), quoted(&counter), quoted(root)).as_bytes(),
            );
        }
        sh.outer
            .expect_since(mark, b"RECEIPT-READY", 1, "the signal counter");
        let counts = |who: &str| NAMES.map(|sig| lines(&dir.join(format!("{who}-{sig}"))));
        let mut job = [0; 4];
        let mut shell = [0; 4];
        for (i, sig) in NAMES.iter().enumerate() {
            std::fs::OpenOptions::new()
                .write(true)
                .open(&fifo)
                .unwrap()
                .write_all(format!("{sig}\n").as_bytes())
                .unwrap();
            if nested && narrow && matches!(*sig, "TERM" | "HUP") {
                shell[i] = 1;
            } else {
                assert!(
                    sh.outer
                        .wait_for_within(Duration::from_secs(10), |_| counts("job")[i] > 0),
                    "real CLI {name}: SIG{sig} missed the job; job {:?}, shell {:?}; {}",
                    counts("job"),
                    counts("shell"),
                    sh.outer.text()
                );
                job[i] = 1;
            }
            assert_eq!(counts("job"), job, "real CLI {name}, SIG{sig}");
        }
        sh.outer.type_bytes(b"done\r");
        if nested {
            sh.outer
                .expect_since(mark, INNER.as_bytes(), 4, "the receipt job ended");
            sh.outer.type_bytes(b":\r");
            sh.outer
                .expect_since(mark, INNER.as_bytes(), 5, "the shell handled pending traps");
            sh.outer.type_bytes(b"exit 0\r");
        }
        sh.prompt_again("the real CLI receipt run ended");
        assert_eq!(sh.status(), 0);
        assert_eq!(counts("job"), job, "real CLI {name}, final job counts");
        assert_eq!(
            counts("shell"),
            shell,
            "real CLI {name}, final shell counts"
        );
        println!(
            "real CLI ({}, {name}): job {job:?}, shell {shell:?}",
            std::env::consts::OS
        );
    }
}

/// The suspend character's cycle for a job just started: it stops, the
/// shell's prompt comes back with the job stopped and the terminal as
/// `before`, and `fg` resumes it; when the command says so once continued
/// (`resumed`, the retrying cat's `CAT-CONT`), that is waited for, so the
/// next line is typed once it reads again (the verifier's review of M2-19:
/// a line typed at once after `fg` makes the round trip depend on timing).
fn suspend_and_resume(
    sh: &mut Shell,
    files: &Path,
    before: &[u8],
    (suspend, resumed): (u8, Option<&[u8]>),
    what: &str,
) {
    sh.outer.type_bytes(&[suspend]);
    sh.prompt_again(&format!(
        "{what}: the suspend character gave the shell its prompt"
    ));
    sh.job_stopped();
    assert_eq!(
        sh.stty_g(files, "after"),
        before,
        "{what}: the outer terminal was not restored when the job stopped"
    );
    let mark = sh.mark();
    sh.outer.type_bytes(b"fg\r");
    if let Some(resumed) = resumed {
        sh.outer
            .expect_since(mark, resumed, 1, &format!("{what}: continued by fg"));
    }
}

/// What `/bin/cat`, continued by `fg` inside a read of its terminal, does
/// next: nothing is typed for a second, its chance to exit with EINTR on
/// macOS if the stop interrupted its read. A stop between reads may leave
/// it reading on. Each run is observed independently; if it is still there,
/// `line` must round-trip (the echo and the copy). Returns whether it read
/// on.
fn cat_after_fg(sh: &mut Shell, line: &str) -> bool {
    let mark = sh.mark();
    let failed = sh.outer.wait_for_within(Duration::from_secs(1), |o| {
        o.count_since(mark, b"Interrupted system call") > 0
    });
    if failed {
        return false;
    }
    sh.outer.type_bytes(format!("{line}\r").as_bytes());
    sh.outer
        .expect_since(mark, line.as_bytes(), 2, "a fresh line after fg");
    true
}

/// The isolated outer-shell gate (see the file's documentation), through
/// `envcloak run --pty` against the fixture project.
///
/// Mutations checked: the command as its own session's leader without the
/// monitor (the suspend character stops nothing: no prompt comes back);
/// every suspend character turned into a stop signal for the command (the
/// raw-mode program never reads its byte, and the nested shell's job does
/// not stop); the CLI stopped before the outer terminal is restored (under
/// dash the terminal is left raw, so `stty -g` at its prompt never runs;
/// bash puts its own settings back when a job stops and cannot show it);
/// the outer terminal restored on an outside SIGTSTP without the command
/// stopped first (the ticker is running at the actual restore barrier); the PTY
/// redactor without the CR LF forms (the PEM-shaped value shows).
/// Resume-before-raw is caught by the exec unit order model and
/// pty_relay::the_command_is_resumed_only_once_the_outer_terminal_is_raw_again,
/// whose barrier observes the settings before Resume. This gate's post-fg
/// round trip alone does not establish that ordering.
#[test]
fn the_outer_shell_gets_its_terminal_back_and_fg_resumes_through_envcloak_run_pty() {
    let mut h = Harness::start();
    let (repo, pass) = project(&mut h);
    let files = h.files().to_path_buf();
    let python = python3();
    let py = python.to_str().unwrap().to_owned();
    let retry_cat = fixture(&h, "retry_cat.py", RETRY_CAT);
    let raw_suspend = fixture(&h, "raw_suspend.py", RAW_SUSPEND);
    let ticker = fixture(&h, "ticker.py", TICKER);
    let signaller = fixture(&h, "signaller.py", SIGNALLER);
    let mut sh = Shell::start(&h, &repo);

    // Gate 23 in PTY mode: the run waits for an approval that a `y` typed
    // into its own terminal never gives; its request is approved from the
    // person's own terminal afterwards, which covers this shell's runs.
    let mark = sh.mark();
    sh.start_job(&format!(
        "{} run --pty --wait 10s -- /bin/cat",
        quoted(h.cli().to_str().unwrap())
    ));
    sh.outer
        .expect_since(mark, b"approval_required", 1, "the run waits");
    sh.outer.type_bytes(b"y\r");
    sh.sync();
    let shown = sh.outer.shown_since(mark);
    let id = shown
        .split("request=")
        .nth(1)
        .and_then(|r| r.get(..8))
        .unwrap_or_else(|| panic!("no request id: {shown}"))
        .to_owned();
    let grants = h.human(&repo, &["grants", "list", "--json"], &[], &[]);
    let listed: serde_json::Value = serde_json::from_slice(&grants.stdout).unwrap();
    assert_eq!(
        listed["grants"].as_array().map(Vec::len),
        Some(0),
        "a `y` typed into the requester's terminal approved something: {listed}"
    );
    let approved = h.human(
        &repo,
        &["approve", &id, "--for", "1h", "--passphrase-fd", "3"],
        &[(3, &pass, true)],
        &[],
    );
    assert_eq!(approved.code, 0, "{}", approved.all());

    startup_status(&mut h, &mut sh, &py);
    inherited_descriptors(&mut h, &mut sh, &py);

    // `/bin/cat`'s baseline, under the plain shell.
    let before = sh.stty_g(&files, "before");
    let mark = sh.mark();
    sh.start_job("/bin/cat");
    sh.outer.type_bytes(b"base-one\r");
    sh.outer
        .expect_since(mark, b"base-one", 2, "a line round-trips through cat");
    suspend_and_resume(
        &mut sh,
        &files,
        &before,
        (0x1a, None),
        "/bin/cat under the shell",
    );
    let reads_on = cat_after_fg(&mut sh, "base-two");
    if reads_on {
        sh.outer.type_bytes(b"\x04");
    }
    sh.sync();
    println!(
        "pty_job_control ({}): /bin/cat {} after a stop and fg under a plain shell",
        std::env::consts::OS,
        if reads_on {
            "reads on"
        } else {
            "ends with EINTR"
        }
    );

    // `/bin/cat` under `envcloak run --pty`.
    let mark = sh.mark();
    sh.start_job(&run_pty(&h, &["/bin/cat"]));
    sh.outer.expect_since(
        mark,
        b"PTY mode: output a program rebuilds",
        1,
        "the coverage line",
    );
    sh.outer.type_bytes(b"env-one\r");
    sh.outer
        .expect_since(mark, b"env-one", 2, "a line round-trips through cat");
    suspend_and_resume(&mut sh, &files, &before, (0x1a, None), "/bin/cat");
    // BSD cat may either read on or end with EINTR, depending on whether
    // the stop interrupted read. The baseline records an observation,
    // not an oracle for that scheduling choice. The retrying cat below
    // must always complete the post-fg round trip on both systems.
    let resumed_reads = cat_after_fg(&mut sh, "env-two");
    #[cfg(not(target_os = "macos"))]
    assert!(resumed_reads, "cat did not read after fg");
    if resumed_reads {
        sh.outer.type_bytes(b"\x04");
    }
    sh.prompt_again("cat and the run ended");
    assert_eq!(sh.status(), if resumed_reads { 0 } else { 1 });

    // The retrying cat: the round trip after fg, and values typed into it
    // come back redacted, the CR LF form included.
    let mark = sh.mark();
    sh.start_job(&run_pty(&h, &[&py, &retry_cat]));
    sh.outer.expect_since(mark, b"CAT-READY", 1, "cat");
    sh.outer.type_bytes(b"r-one\r");
    sh.outer
        .expect_since(mark, b"r-one", 2, "a line round-trips through cat");
    suspend_and_resume(
        &mut sh,
        &files,
        &before,
        (0x1a, Some(b"CAT-CONT")),
        "the retrying cat",
    );
    let mark = sh.mark();
    sh.outer.type_bytes(b"r-two\r");
    sh.outer
        .expect_since(mark, b"r-two", 2, "a fresh line after fg");
    sh.outer.type_bytes(b"QUIET\r");
    sh.outer
        .expect_since(mark, b"QUIET", 2, "cat turned its echo off");
    let pem_value = h.canary(PEM).as_str().to_owned();
    sh.outer.type_bytes(format!("{pem_value}\r").as_bytes());
    let pem_marker = format!("[envcloak:{PEM_SLUG}]");
    sh.outer.expect_since(
        mark,
        pem_marker.as_bytes(),
        1,
        "the PEM-shaped value typed and copied back in its CR LF form, redacted",
    );
    let key = h.canary(labels::OPENAI_API_KEY).as_str().to_owned();
    sh.outer.type_bytes(format!("{key}\r").as_bytes());
    let key_marker = format!("[envcloak:{OPENAI_SLUG}]");
    sh.outer.expect_since(
        mark,
        key_marker.as_bytes(),
        1,
        "the key typed and copied back, redacted",
    );
    sh.outer.type_bytes(b"\x04");
    sh.prompt_again("the run ended");
    assert_eq!(sh.status(), 0);
    h.record(
        "the outer terminal, through the retrying cat",
        &sh.outer.seen,
    );

    // A nested interactive shell keeps its own job control; the run stays
    // raw and running.
    let mark = sh.mark();
    let outer_prompts = count(&sh.outer.seen, PROMPT.as_bytes());
    sh.start_job(&format!(
        "PS1={} {}",
        quoted(INNER),
        run_pty(&h, &["/bin/sh", "-i"])
    ));
    // The typed line echoes the inner prompt's text once.
    sh.outer
        .expect_since(mark, INNER.as_bytes(), 2, "the nested shell's prompt");
    sh.outer
        .type_bytes(format!("{NO_EDITING}set -m\r").as_bytes());
    sh.outer
        .expect_since(mark, INNER.as_bytes(), 3, "set -m in the nested shell");
    sh.outer
        .type_bytes(format!("{} {}\r", quoted(&py), quoted(&retry_cat)).as_bytes());
    sh.outer
        .expect_since(mark, b"CAT-READY", 1, "the inner job");
    sh.outer.type_bytes(b"n-one\r");
    sh.outer.expect_since(
        mark,
        b"n-one",
        2,
        "a line round-trips through the inner job",
    );
    sh.outer.type_bytes(&[0x1a]);
    sh.outer.expect_since(
        mark,
        INNER.as_bytes(),
        4,
        "the suspend character gave the nested shell its prompt",
    );
    assert_eq!(
        count(&sh.outer.seen, PROMPT.as_bytes()),
        outer_prompts,
        "the outer shell got its prompt while the nested shell runs"
    );
    assert!(
        sh.outer.settings().is_raw(),
        "the outer terminal is not raw while the run goes on"
    );
    sh.outer.type_bytes(b"fg\r");
    sh.outer.type_bytes(b"n-two\r");
    sh.outer
        .expect_since(mark, b"n-two", 2, "fg in the nested shell resumed its job");
    sh.outer.type_bytes(b"\x04");
    sh.outer
        .expect_since(mark, INNER.as_bytes(), 5, "the inner job ended");
    sh.outer.type_bytes(b"exit 0\r");
    sh.prompt_again("the nested shell and the run ended");
    assert_eq!(sh.status(), 0);

    // A raw-mode program reads the suspend character as data and stops
    // itself.
    let mark = sh.mark();
    sh.start_job(&run_pty(&h, &[&py, &raw_suspend]));
    sh.outer
        .expect_since(mark, b"RAW-READY", 1, "the raw program");
    suspend_and_resume(
        &mut sh,
        &files,
        &before,
        (0x1a, None),
        "the raw-mode program",
    );
    assert_eq!(
        sh.outer.count_since(mark, b"GOT-SUSPEND-BYTE"),
        1,
        "the raw-mode program did not read the suspend character as data"
    );
    let mark = sh.mark();
    sh.outer
        .expect_since(mark, b"RAW-RESUMED", 1, "fg resumed the raw-mode program");
    sh.outer.type_bytes(b"after-raw\r");
    sh.outer
        .expect_since(mark, b"LINE [after-raw]", 1, "it reads on");
    sh.prompt_again("the raw-mode program and the run ended");
    assert_eq!(sh.status(), 0);

    // The suspend character remapped: ^X suspends, ^Z is data.
    sh.say("stty susp '^X'");
    let remapped = sh.stty_g(&files, "remapped");
    let mark = sh.mark();
    sh.start_job(&run_pty(&h, &[&py, &retry_cat]));
    sh.outer.expect_since(mark, b"CAT-READY", 1, "cat");
    sh.outer.type_bytes(b"z1\x1az2\r");
    sh.outer
        .expect_since(mark, b"z1\x1az2", 1, "^Z reached cat as data");
    suspend_and_resume(
        &mut sh,
        &files,
        &remapped,
        (0x18, Some(b"CAT-CONT")),
        "^X remapped",
    );
    let mark = sh.mark();
    sh.outer.type_bytes(b"x-two\r");
    sh.outer
        .expect_since(mark, b"x-two", 2, "a fresh line after fg");
    sh.outer.type_bytes(b"\x04");
    sh.prompt_again("the run ended");

    // The suspend character disabled: nothing suspends, the byte is data.
    sh.say("stty susp undef");
    let mark = sh.mark();
    sh.start_job(&run_pty(&h, &[&py, &retry_cat]));
    sh.outer.expect_since(mark, b"CAT-READY", 1, "cat");
    sh.outer.type_bytes(b"\x1aw1\r");
    sh.outer
        .expect_since(mark, b"\x1aw1", 1, "the byte reached cat as data");
    assert_eq!(
        sh.outer.count_since(mark, PROMPT.as_bytes()),
        0,
        "something suspended"
    );
    sh.outer.type_bytes(b"\x04");
    sh.prompt_again("the run ended");
    sh.say("stty susp '^Z'");
    assert_eq!(
        sh.stty_g(&files, "back"),
        before,
        "the suspend character back"
    );

    // SIGTSTP from outside: testing builds must stop at the actual restore
    // barrier. External release binaries check the visible contract below.
    // Select this by the harness's explicit binary mode, never by whether
    // the barrier shows up: a missing testing hook must fail the gate.
    let fifo = files.join("signals");
    let made = Command::new("/usr/bin/mkfifo").arg(&fifo).status().unwrap();
    assert!(made.success());
    let ticks = files.join("ticks");
    let restored = files.join("restore-checked");
    let before_tstp = sh.outer.settings();
    let mark = sh.mark();
    let pause = if h.test_build() {
        format!(
            "ENVCLOAK_TEST_PAUSE=termios.restored ENVCLOAK_TEST_PAUSE_RELEASE={} ",
            quoted(restored.to_str().unwrap())
        )
    } else {
        String::new()
    };
    let mut line = format!(
        "{pause}{} {} {} {} run --pty --",
        quoted(&py),
        quoted(&signaller),
        quoted(fifo.to_str().unwrap()),
        quoted(h.cli().to_str().unwrap())
    );
    for w in [py.as_str(), ticker.as_str(), ticks.to_str().unwrap()] {
        line.push(' ');
        line.push_str(&quoted(w));
    }
    sh.start_job(&line);
    sh.outer
        .expect_since(mark, b"TICKER-READY ", 1, "the ticker");
    let shown = sh.outer.shown_since(mark);
    let pid: u32 = shown
        .split("TICKER-READY ")
        .nth(1)
        .and_then(|r| r.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|n| n.parse().ok())
        .unwrap();
    assert!(
        sh.outer.wait_for_within(DEADLINE, |_| lines(&ticks) >= 3),
        "the ticker does not tick"
    );
    assert!(!state_of(pid).starts_with('T'), "the ticker starts running");
    // pause_point releases itself after 60 seconds. An observation made
    // after that must fail, even if a later stop made its state look right.
    let check_by = Instant::now() + Duration::from_secs(30);
    std::fs::OpenOptions::new()
        .write(true)
        .open(&fifo)
        .unwrap()
        .write_all(b"TSTP\n")
        .unwrap();
    if h.test_build() {
        assert!(
            sh.outer
                .wait_for_within(check_by.saturating_duration_since(Instant::now()), |o| o
                    .count_since(mark, b"envcloak test: paused at termios.restored")
                    >= 1),
            "testing binary missed the actual outer-terminal restore barrier; the terminal showed:\n{}",
            sh.outer.text()
        );
        // The barrier is inside TerminalGuard::restore, after tcsetattr. It
        // catches an early restore through either relay call site, before a
        // later Suspend or Stopped report can hide the wrong ordering.
        let at_restore = state_of(pid);
        let settings_restored = sh.outer.settings().same_as(&before_tstp);
        let barrier_held = Instant::now() < check_by;
        std::fs::write(&restored, b"").unwrap();
        assert!(barrier_held, "the restore observation outlived its barrier");
        assert!(
            at_restore.starts_with('T'),
            "the command ran at the actual terminal restore: state {at_restore:?}"
        );
        assert!(
            settings_restored,
            "the restore barrier precedes restored settings"
        );
        println!(
            "outside SIGTSTP ({}): command {at_restore:?}, terminal restored at the restore barrier",
            std::env::consts::OS
        );
    } else {
        println!(
            "outside SIGTSTP ({}): external release binaries have no restore barrier; \
             checking the stopped job, terminal settings and fg",
            std::env::consts::OS
        );
    }
    sh.prompt_again("SIGTSTP from outside gave the shell its prompt");
    let state = state_of(pid);
    assert!(
        state.starts_with('T'),
        "the command ran while the outer terminal was restored: state {state:?}"
    );
    sh.job_stopped();
    assert_eq!(
        sh.stty_g(&files, "after-tstp"),
        before,
        "the outer terminal"
    );
    let ticked = lines(&ticks);
    sh.outer.type_bytes(b"fg\r");
    assert!(
        sh.outer
            .wait_for_within(DEADLINE, |_| lines(&ticks) > ticked + 2),
        "fg did not resume the ticker"
    );
    let mark = sh.mark();
    sh.outer.type_bytes(b"done\r");
    sh.outer
        .expect_since(mark, b"done", 1, "the ticker read done");
    sh.prompt_again("the ticker and the run ended");
    assert_eq!(sh.status(), 0);

    cli_signal_receipts(&h, &mut sh, &py, &signaller);

    // Under dash, which leaves the terminal as a stopped job had it (bash
    // and ksh put back their own settings when a job stops, dash does not;
    // measured on macOS 26.4, and Ubuntu's /bin/sh is dash): `stty -g` at
    // its prompt shows what `envcloak run` itself put back before it
    // stopped (the verifier's review of M2-19). A job of the outer shell,
    // in its session, so the person's grant covers its runs; its prompt
    // typed in two quoted halves, so the typed line never shows it whole.
    if Path::new("/bin/dash").exists() {
        sh.start_job("PS1='EC-OUT''ER> ' /bin/dash -i");
        sh.prompt_again("dash's first prompt");
        sh.say("set -m");
        let before_dash = sh.stty_g(&files, "before-dash");
        let mark = sh.mark();
        sh.start_job(&run_pty(&h, &[&py, &retry_cat]));
        sh.outer
            .expect_since(mark, b"CAT-READY", 1, "cat under dash");
        sh.outer.type_bytes(b"d-one\r");
        sh.outer.expect_since(
            mark,
            b"d-one",
            2,
            "a line round-trips through cat under dash",
        );
        suspend_and_resume(
            &mut sh,
            &files,
            &before_dash,
            (0x1a, Some(b"CAT-CONT")),
            "the retrying cat under dash",
        );
        let mark = sh.mark();
        sh.outer.type_bytes(b"d-two\r");
        sh.outer
            .expect_since(mark, b"d-two", 2, "a fresh line after fg under dash");
        sh.outer.type_bytes(b"\x04");
        sh.prompt_again("the run under dash ended");
        assert_eq!(sh.status(), 0);
        sh.outer.type_bytes(b"exit 0\r");
        sh.prompt_again("dash ended");
    }

    // A panic in the relay (a test build's injected one) leaves the outer
    // terminal as it was.
    if h.test_build() {
        let mark = sh.mark();
        sh.start_job(&format!(
            "ENVCLOAK_TEST_PANIC=exec.pty.relay {}",
            run_pty(&h, &["/bin/cat"])
        ));
        sh.outer.expect_since(
            mark,
            b"envcloak: internal error: a panic at ",
            1,
            "the panic's one line",
        );
        sh.prompt_again("the panicked run ended");
        assert_eq!(
            sh.stty_g(&files, "after-panic"),
            before,
            "the outer terminal after a panic"
        );
        assert!(sh.outer.settings().echo(), "echo is off after a panic");
    }

    h.record("the outer terminal", &sh.outer.seen);
    sh.exit();
    h.assert_swept("the PTY job-control gate");
}

/// `--pty` without a terminal: the agent's shell runs on pipes, so the run
/// exits 125 with `pty_unavailable` before it asks the daemon anything (no
/// request is opened for it), and never falls back to pipe mode.
#[test]
fn pty_mode_without_a_terminal_is_refused_before_the_daemon_is_asked() {
    let mut h = Harness::start();
    let (repo, _) = project(&mut h);
    let pending = |h: &mut Harness| -> usize {
        let p = h.human(&repo, &["pending", "--json"], &[], &[]);
        assert_eq!(p.code, 0, "{}", p.all());
        let v: serde_json::Value = serde_json::from_slice(&p.stdout).unwrap();
        v["requests"].as_array().map_or(0, Vec::len)
    };
    let before = pending(&mut h);
    let out = h.agent(&repo, &["run", "--pty", "--", "./missing-command"]);
    assert_eq!(out.status.code(), Some(125), "{}", text(&out));
    assert_eq!(token(&out.stderr), "pty_unavailable", "{}", text(&out));
    assert!(out.stdout.is_empty(), "{}", text(&out));
    assert_eq!(pending(&mut h), before, "a request was opened");
    // The same run without --pty asks, and is held for approval.
    let asked = h.agent(&repo, &["run", "--", "./missing-command"]);
    assert_eq!(
        token(&asked.stderr),
        "approval_required",
        "{}",
        text(&asked)
    );
    assert_eq!(pending(&mut h), before + 1);
    h.assert_swept("pty_unavailable");
}
