//! envcloak-exec's runner as a real process (SPEC §6.1 steps 6 to 8):
//! gate 8 with real serializers, gate 9, signals with and without a
//! controlling terminal, exit codes, prompts, a lost reader, backpressure
//! and a descendant that keeps the pipes open.
//!
//! This binary has no libtest harness (`harness = false`): it is also the
//! runner. Started as `runner --ec-runner ...`, it does what `envcloak run`
//! does once the daemon has released the values: it generates the canaries
//! from a seed (never passing a value on argv or in its own environment),
//! refuses short values, prints the coverage report, and runs the command
//! through `envcloak_exec::run`, exiting with the child's shell code. The
//! tests start it through `python3`, in a new session with no controlling
//! terminal (`setsid`) or leading one on a new pseudo-terminal, so which
//! signal mode it takes does not depend on how the tests themselves were
//! started. Every command gets an isolated HOME ([`TestHome`]) and a
//! cleared environment.
//!
//! The runner's output is read through pipes, and every byte of it, and of
//! the test home, is swept for every canary and its encodings.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitCode, ExitStatus, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use envcloak_core::SecretBytes;
use envcloak_core::vault::Slug;
use envcloak_exec::{ExecError, IDLE_FLUSH, Label, RunSpec, ShortPolicy, build_redactor, run};
use envcloak_policy::EnvName;
use envcloak_testkit::{
    Canary, TestHome, assert_no_canary, by_label, canaries, fresh_seed, labels,
};

#[global_allocator]
static ALLOCATOR: envcloak_sys::WipingAllocator = envcloak_sys::WipingAllocator;

const RUNNER: &str = "--ec-runner";

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if args.first().is_some_and(|a| a == RUNNER) {
        return runner(&args[1..]);
    }
    harness(&args)
}

// ---------------------------------------------------------------------------
// The runner.

/// Canaries of 7 and 15 bytes, for gate 9, generated from the seed.
const SEVEN: &str = "SEVEN_BYTES";
const FIFTEEN: &str = "FIFTEEN_BYTES";

/// The story's canaries for `seed`, plus a 7-byte and a 15-byte one.
fn all_canaries(seed: u64) -> Vec<Canary> {
    let mut cs = canaries(seed);
    let mut x = seed ^ 0x5eed_0f5e_7e15_bad0;
    let mut word = |n: usize| -> String {
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                char::from(b"abcdefghijkmnpqrstuvwxyz23456789"[usize::try_from(x % 32).unwrap()])
            })
            .collect()
    };
    let (seven, fifteen) = (word(7), word(15));
    cs.push(Canary::new(SEVEN, seven));
    cs.push(Canary::new(FIFTEEN, fifteen));
    cs
}

/// The slug a canary is labeled with: `openai_api_key/t`.
fn slug_of(label: &str) -> String {
    format!("{}/t", label.to_ascii_lowercase())
}

/// `--ec-runner --seed S [--idle-ms N] [--value ENV:LABEL[:allow]]...
/// [--file ENV:PATH]... -- <argv...>`
fn runner(args: &[OsString]) -> ExitCode {
    let mut it = args.iter();
    let mut seed = None;
    let mut idle = IDLE_FLUSH;
    let mut values: Vec<String> = Vec::new();
    let mut files: Vec<String> = Vec::new();
    loop {
        let Some(a) = it.next().and_then(|a| a.to_str()) else {
            eprintln!("runner: bad arguments");
            return ExitCode::from(2);
        };
        let mut next = || it.next().and_then(|v| v.to_str()).unwrap().to_owned();
        match a {
            "--" => break,
            "--seed" => seed = Some(next().parse::<u64>().unwrap()),
            "--idle-ms" => idle = Duration::from_millis(next().parse().unwrap()),
            "--value" => values.push(next()),
            "--file" => files.push(next()),
            _ => {
                eprintln!("runner: bad arguments");
                return ExitCode::from(2);
            }
        }
    }
    let argv: Vec<OsString> = it.cloned().collect();
    let cs = all_canaries(seed.unwrap());
    let mut owned: Vec<(EnvName, Slug, SecretBytes, ShortPolicy)> = Vec::new();
    for v in &values {
        let parts: Vec<&str> = v.split(':').collect();
        let c = by_label(&cs, parts[1]);
        owned.push((
            EnvName::new(parts[0]).unwrap(),
            Slug::new(&slug_of(parts[1])).unwrap(),
            SecretBytes::copy_from(c.value()),
            ShortPolicy::from(parts.get(2) == Some(&"allow")),
        ));
    }
    for (i, f) in files.iter().enumerate() {
        let (env, path) = f.split_once(':').unwrap();
        owned.push((
            EnvName::new(env).unwrap(),
            Slug::new(&format!("fixture{i}/t")).unwrap(),
            SecretBytes::from_vec(std::fs::read(path).unwrap()),
            ShortPolicy::Refuse,
        ));
    }
    let built = {
        let labels: Vec<Label<'_>> = owned
            .iter()
            .map(|(_, slug, value, short)| Label {
                slug,
                value,
                short: *short,
            })
            .collect();
        build_redactor(&labels)
    };
    let (redactor, report) = match built {
        Ok(b) => b,
        Err(e) => {
            let slugs = match &e {
                ExecError::ValueTooShort(r) => r
                    .refused_short
                    .iter()
                    .map(Slug::as_str)
                    .collect::<Vec<_>>()
                    .join(", "),
                _ => String::new(),
            };
            eprintln!("envcloak: {}: {} ({slugs})", e.token(), e.message());
            return ExitCode::from(e.exit_code());
        }
    };
    for s in &report.warned_short {
        eprintln!("envcloak: coverage: {s}: 8 to 15 bytes, allowed short");
    }
    for s in &report.partial {
        eprintln!("envcloak: coverage: {s}: partial inside longer base64");
    }
    let injected = owned.into_iter().map(|(n, _, v, _)| (n, v)).collect();
    let spec = RunSpec {
        argv,
        injected,
        redactor,
        idle_flush: idle,
        stdin: None,
        stdout: std::io::stdout().as_fd().try_clone_to_owned().unwrap(),
        stderr: std::io::stderr().as_fd().try_clone_to_owned().unwrap(),
    };
    match run(spec) {
        Ok(exit) => ExitCode::from(exit.shell_code()),
        Err(e) => {
            eprintln!("envcloak: {}: {}", e.token(), e.message());
            ExitCode::from(e.exit_code())
        }
    }
}

// ---------------------------------------------------------------------------
// The harness.

type Test = (&'static str, fn());

const TESTS: &[Test] = &[
    (
        "gate8_real_serializers_split_at_every_byte_are_redacted",
        gate8_real_serializers_split_at_every_byte_are_redacted,
    ),
    (
        "gate9_short_values_are_refused_or_warned",
        gate9_short_values_are_refused_or_warned,
    ),
    (
        "without_a_terminal_signals_go_to_the_childs_own_group",
        without_a_terminal_signals_go_to_the_childs_own_group,
    ),
    (
        "on_a_terminal_ctrl_c_reaches_the_child_and_the_runner_stays",
        on_a_terminal_ctrl_c_reaches_the_child_and_the_runner_stays,
    ),
    (
        "on_a_terminal_sigterm_is_passed_to_the_child",
        on_a_terminal_sigterm_is_passed_to_the_child,
    ),
    ("exit_codes_pass_through", exit_codes_pass_through),
    (
        "a_prompt_shows_and_the_start_of_a_value_waits",
        a_prompt_shows_and_the_start_of_a_value_waits,
    ),
    (
        "a_lost_reader_closes_the_childs_pipe",
        a_lost_reader_closes_the_childs_pipe,
    ),
    (
        "backpressure_holds_the_child_through_100_mb",
        backpressure_holds_the_child_through_100_mb,
    ),
    (
        "a_descendant_holding_the_pipes_is_cut_off_after_2_s",
        a_descendant_holding_the_pipes_is_cut_off_after_2_s,
    ),
    (
        "harness_a_dropped_runner_takes_its_childs_group_with_it",
        harness_a_dropped_runner_takes_its_childs_group_with_it,
    ),
    (
        "harness_a_runner_that_never_exits_on_a_terminal_is_killed_with_its_session",
        harness_a_runner_that_never_exits_on_a_terminal_is_killed_with_its_session,
    ),
];

fn harness(args: &[OsString]) -> ExitCode {
    if args.iter().any(|a| a == "--list") {
        for (name, _) in TESTS {
            println!("{name}: test");
        }
        return ExitCode::SUCCESS;
    }
    let filters: Vec<&str> = args
        .iter()
        .filter_map(|a| a.to_str())
        .filter(|a| !a.starts_with('-'))
        .collect();
    let chosen: Vec<&Test> = TESTS
        .iter()
        .filter(|(n, _)| filters.is_empty() || filters.iter().any(|f| n.contains(f)))
        .collect();
    println!("\nrunning {} tests", chosen.len());
    let started = Instant::now();
    let results: Vec<(&str, bool)> = std::thread::scope(|s| {
        let handles: Vec<_> = chosen
            .iter()
            .map(|(name, f)| (*name, s.spawn(*f)))
            .collect();
        handles
            .into_iter()
            .map(|(name, h)| {
                let ok = h.join().is_ok();
                println!("test {name} ... {}", if ok { "ok" } else { "FAILED" });
                (name, ok)
            })
            .collect()
    });
    let failed: Vec<&str> = results.iter().filter(|r| !r.1).map(|r| r.0).collect();
    println!(
        "\ntest result: {}. {} passed; {} failed; finished in {:.2}s\n",
        if failed.is_empty() { "ok" } else { "FAILED" },
        results.len() - failed.len(),
        failed.len(),
        started.elapsed().as_secs_f64()
    );
    if failed.is_empty() {
        ExitCode::SUCCESS
    } else {
        for f in failed {
            println!("failed: {f}");
        }
        ExitCode::FAILURE
    }
}

// ---------------------------------------------------------------------------
// Helpers.

/// An executable on this process's `PATH`.
fn find(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

fn python3() -> PathBuf {
    find("python3").expect("python3 is needed on PATH")
}

fn emitter() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/emitters/emit.py")
}

/// Runs argv[1..] in a new session, without a controlling terminal.
const DETACH: &str = "import os, sys\nos.setsid()\nos.execv(sys.argv[1], sys.argv[1:])\n";

/// Runs argv[4..] leading a session on a new pseudo-terminal. Waits until
/// the terminal shows `ready`, then (argv[1]) types Ctrl-C, or sends
/// SIGTERM to the process. Reads until the terminal has been quiet for
/// argv[2] seconds, then waits up to argv[3] seconds for the process to
/// exit. Prints `RUNNER <pid>`, then `EXIT <code>` and everything the
/// terminal showed. A process that is not ready in time, or does not exit
/// in time, is killed with its whole process group (it leads the
/// terminal's session and group, and on a terminal its child stays in
/// that group), reaped, and reported as `NOREADY` or `NOEXIT` in place of
/// the `EXIT` line, with exit status 1: the driver never waits for ever,
/// and never leaves the runner or its child behind (review T12-5).
const ON_PTY: &str = r#"import os, pty, select, signal, sys, time
send, quiet, patience = sys.argv[1], float(sys.argv[2]), float(sys.argv[3])
pid, fd = pty.fork()
if pid == 0:
    os.execv(sys.argv[4], sys.argv[4:])
sys.stdout.buffer.write(b'RUNNER %d\n' % pid)
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
def give_up(why):
    try:
        os.killpg(pid, signal.SIGKILL)
    except OSError:
        pass
    try:
        os.waitpid(pid, 0)
    except OSError:
        pass
    sys.stdout.buffer.write(why + b'\n' + out)
    sys.exit(1)
deadline = time.time() + 60
while b'ready' not in out:
    if not more(deadline):
        give_up(b'NOREADY')
if send == 'ctrl-c':
    os.write(fd, b'\x03')
else:
    os.kill(pid, signal.SIGTERM)
while more(time.time() + quiet):
    pass
end = time.time() + patience
while True:
    done, status = os.waitpid(pid, os.WNOHANG)
    if done:
        break
    if time.time() > end:
        give_up(b'NOEXIT')
    time.sleep(0.02)
sys.stdout.buffer.write(b'EXIT %d\n' % os.waitstatus_to_exitcode(status))
sys.stdout.buffer.write(out)
"#;

/// What the runner is given: the seed, the idle interval, the values to
/// inject (`ENV:LABEL[:allow]`) and value files (`ENV:PATH`).
struct Setup<'a> {
    seed: u64,
    idle_ms: Option<u64>,
    values: &'a [&'a str],
    files: &'a [String],
}

fn runner_args(s: &Setup<'_>, argv: &[&OsStr]) -> Vec<OsString> {
    let mut a: Vec<OsString> = vec![
        std::env::current_exe().unwrap().into(),
        RUNNER.into(),
        "--seed".into(),
        s.seed.to_string().into(),
    ];
    if let Some(ms) = s.idle_ms {
        a.extend(["--idle-ms".into(), ms.to_string().into()]);
    }
    for v in s.values {
        a.extend(["--value".into(), (*v).into()]);
    }
    for f in s.files {
        a.extend(["--file".into(), f.into()]);
    }
    a.push("--".into());
    a.extend(argv.iter().map(|x| x.to_os_string()));
    a
}

/// The runner in a new session without a controlling terminal, in
/// `home`'s environment, with piped standard streams.
fn detached(home: &TestHome, s: &Setup<'_>, argv: &[&OsStr]) -> Command {
    let mut cmd = Command::new(python3());
    home.apply(&mut cmd)
        .args(["-c", DETACH])
        .args(runner_args(s, argv))
        .current_dir(home.home())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

/// How [`ON_PTY`] ended.
#[derive(Debug, PartialEq, Eq)]
enum PtyEnd {
    Exit(i32),
    NoReady,
    NoExit,
}

/// What [`on_pty_within`] saw: the runner's pid, how it ended, and what
/// the terminal showed.
struct Pty {
    runner: i32,
    end: PtyEnd,
    shown: Vec<u8>,
}

/// The runner leading a session on a pseudo-terminal (see [`ON_PTY`]).
/// Returns the exit code and what the terminal showed.
fn on_pty(home: &TestHome, send: &str, s: &Setup<'_>, argv: &[&OsStr]) -> (i32, Vec<u8>) {
    let p = on_pty_within(home, send, (60, 60), s, argv);
    match p.end {
        PtyEnd::Exit(code) => (code, p.shown),
        other => panic!("the runner on a terminal ended as {other:?}"),
    }
}

/// [`on_pty`], with the quiet time that ends the reading and the time
/// then allowed for the exit, in seconds.
fn on_pty_within(
    home: &TestHome,
    send: &str,
    (quiet, patience): (u64, u64),
    s: &Setup<'_>,
    argv: &[&OsStr],
) -> Pty {
    let mut cmd = Command::new(python3());
    home.apply(&mut cmd)
        .args([
            "-c",
            ON_PTY,
            send,
            &quiet.to_string(),
            &patience.to_string(),
        ])
        .args(runner_args(s, argv))
        .current_dir(home.home())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let limit = Duration::from_secs(60 + quiet + patience + 30);
    let (status, out, err) = Proc::spawn(cmd).finish(limit);
    let (first, rest) = out.split_at(out.iter().position(|b| *b == b'\n').map_or(0, |n| n + 1));
    let runner = std::str::from_utf8(first)
        .ok()
        .and_then(|l| l.trim_end().strip_prefix("RUNNER "))
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("the pty driver failed to start: {}", lossy(&err)));
    let nl = rest.iter().position(|b| *b == b'\n').expect("no end line");
    let end = match &rest[..nl] {
        b"NOREADY" => PtyEnd::NoReady,
        b"NOEXIT" => PtyEnd::NoExit,
        line => PtyEnd::Exit(
            std::str::from_utf8(line)
                .ok()
                .and_then(|l| l.strip_prefix("EXIT "))
                .and_then(|c| c.parse().ok())
                .expect("no EXIT line"),
        ),
    };
    assert_eq!(
        status.success(),
        matches!(end, PtyEnd::Exit(_)),
        "the pty driver: {status:?}, {}",
        lossy(&err)
    );
    Pty {
        runner,
        end,
        shown: rest[nl + 1..].to_vec(),
    }
}

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || hay.windows(needle.len()).any(|w| w == needle)
}

fn count(hay: &[u8], needle: &[u8]) -> usize {
    hay.windows(needle.len()).filter(|w| *w == needle).count()
}

/// What a process wrote, collected by two reader threads.
#[derive(Default)]
struct Captured {
    streams: Mutex<[Vec<u8>; 2]>,
    changed: Condvar,
}

/// A running process with its output collected as it comes.
struct Proc {
    child: Child,
    stdin: Option<ChildStdin>,
    cap: Arc<Captured>,
    readers: Vec<JoinHandle<()>>,
}

impl Proc {
    fn spawn(mut cmd: Command) -> Proc {
        let mut child = cmd.spawn().unwrap();
        let cap = Arc::new(Captured::default());
        let mut readers = Vec::new();
        let sources: [Option<Box<dyn Read + Send>>; 2] = [
            child
                .stdout
                .take()
                .map(|s| Box::new(s) as Box<dyn Read + Send>),
            child
                .stderr
                .take()
                .map(|s| Box::new(s) as Box<dyn Read + Send>),
        ];
        for (i, src) in sources.into_iter().enumerate() {
            let Some(mut src) = src else { continue };
            let cap = Arc::clone(&cap);
            readers.push(std::thread::spawn(move || {
                let mut b = [0u8; 65536];
                while let Ok(n) = src.read(&mut b) {
                    if n == 0 {
                        break;
                    }
                    cap.streams.lock().unwrap()[i].extend_from_slice(&b[..n]);
                    cap.changed.notify_all();
                }
            }));
        }
        let stdin = child.stdin.take();
        Proc {
            child,
            stdin,
            cap,
            readers,
        }
    }

    fn pid(&self) -> i32 {
        i32::try_from(self.child.id()).unwrap()
    }

    /// Waits until stream `i` (0 stdout, 1 stderr) holds `pat`.
    fn wait_for(&self, i: usize, pat: &[u8], limit: Duration) -> bool {
        let end = Instant::now() + limit;
        let mut s = self.cap.streams.lock().unwrap();
        loop {
            if contains(&s[i], pat) {
                return true;
            }
            let now = Instant::now();
            if now >= end {
                return false;
            }
            s = self.cap.changed.wait_timeout(s, end - now).unwrap().0;
        }
    }

    fn write(&mut self, b: &[u8]) {
        let w = self.stdin.as_mut().unwrap();
        w.write_all(b).unwrap();
        w.flush().unwrap();
    }

    fn close_stdin(&mut self) {
        self.stdin = None;
    }

    /// Waits up to `limit` for the process and its output. A process that
    /// does not exit in time is killed and the test fails.
    fn finish(mut self, limit: Duration) -> (ExitStatus, Vec<u8>, Vec<u8>) {
        self.stdin = None;
        let end = Instant::now() + limit;
        let status = loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                break s;
            }
            if Instant::now() > end {
                self.kill_all();
                panic!("the process did not exit within {limit:?}");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        for r in self.readers.drain(..) {
            r.join().unwrap();
        }
        let [out, err] = std::mem::take(&mut *self.cap.streams.lock().unwrap());
        (status, out, err)
    }
}

impl Proc {
    /// Kills the process and everything it started, as a failed test must
    /// (review T12-5): the runner leads a session and group of its own
    /// (`DETACH`, or `ON_PTY`'s terminal), and without a terminal its
    /// child leads another, which killing the runner alone would leave
    /// running. So every descendant is found first (while it still is
    /// one: an orphan is reparented), then each of their process groups
    /// is killed, then each of them, then the process itself, which is
    /// reaped.
    fn kill_all(&mut self) {
        let root = self.pid();
        let tree = descendants(root);
        let own = process_table()
            .into_iter()
            .find(|p| p.pid == i32::try_from(std::process::id()).unwrap_or(0))
            .map_or(0, |p| p.pgid);
        let mut groups: Vec<i32> = tree.iter().map(|p| p.pgid).collect();
        groups.sort_unstable();
        groups.dedup();
        for g in groups.into_iter().filter(|g| *g > 1 && *g != own) {
            let _ = envcloak_sys::signal_group(g, libc::SIGKILL);
        }
        for p in &tree {
            let _ = envcloak_sys::signal_process(p.pid, libc::SIGKILL);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        self.kill_all();
    }
}

/// One row of `ps`.
#[derive(Debug, Clone, Copy)]
struct PsRow {
    pid: i32,
    ppid: i32,
    pgid: i32,
}

/// Every process's pid, parent and process group, from `ps`.
fn process_table() -> Vec<PsRow> {
    let Ok(out) = Command::new("ps")
        .args(["-A", "-o", "pid=", "-o", "ppid=", "-o", "pgid="])
        .output()
    else {
        return Vec::new();
    };
    lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace().map(str::parse::<i32>);
            match (f.next(), f.next(), f.next()) {
                (Some(Ok(pid)), Some(Ok(ppid)), Some(Ok(pgid))) => Some(PsRow { pid, ppid, pgid }),
                _ => None,
            }
        })
        .collect()
}

/// `root` and every process below it.
fn descendants(root: i32) -> Vec<PsRow> {
    let table = process_table();
    let mut found: Vec<PsRow> = table.iter().copied().filter(|p| p.pid == root).collect();
    let mut i = 0;
    while i < found.len() {
        let parent = found[i].pid;
        found.extend(
            table
                .iter()
                .copied()
                .filter(|p| p.ppid == parent && p.pid != parent),
        );
        i += 1;
    }
    found
}

/// Whether process `pid` still exists, waiting up to `limit` for it to
/// be gone (a killed orphan is reaped by init in its own time).
fn gone_within(pid: i32, limit: Duration) -> bool {
    let end = Instant::now() + limit;
    loop {
        if envcloak_sys::signal_process(pid, 0).is_err() {
            return true;
        }
        if Instant::now() >= end {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Kills `pid` on drop: a test's cleanup, whatever its assertions said.
struct KillOnDrop(Vec<i32>);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        for pid in &self.0 {
            let _ = envcloak_sys::signal_process(*pid, libc::SIGKILL);
        }
    }
}

fn sh(script: &str) -> Vec<OsString> {
    vec!["/bin/sh".into(), "-c".into(), script.into()]
}

fn os(v: &[OsString]) -> Vec<&OsStr> {
    v.iter().map(OsString::as_os_str).collect()
}

/// A number the child printed as `key=<n>`.
fn field(out: &[u8], key: &str) -> i32 {
    let text = lossy(out);
    let at = text
        .find(&format!("{key}="))
        .unwrap_or_else(|| panic!("no {key} in the output"));
    text[at + key.len() + 1..]
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

// ---------------------------------------------------------------------------
// Gate 8.

/// Where the recorded serializer output of generate.sh lives, and the two
/// values it encodes.
fn redact_fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../envcloak-redact/tests/fixtures")
}

/// Node, PHP and a built Go serializer, where installed. Required ones
/// are named in `ENVCLOAK_TEST_REQUIRE_SERIALIZERS` (comma-separated);
/// CI names the runtimes its runners have.
struct Runtimes {
    node: Option<PathBuf>,
    php: Option<PathBuf>,
    go: Option<PathBuf>,
}

impl Runtimes {
    fn find() -> Runtimes {
        let go = find("go").and_then(|go| {
            let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("go-serializer");
            std::fs::create_dir_all(&dir).unwrap();
            let bin = dir.join("serialize");
            let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/emitters/serialize.go");
            let home = TestHome::new();
            let mut cmd = Command::new(&go);
            home.apply(&mut cmd)
                .env("GOCACHE", dir.join("cache"))
                .env("GOPATH", dir.join("path"))
                .env("GOTOOLCHAIN", "local")
                .env("GO111MODULE", "off")
                .env("CGO_ENABLED", "0")
                .arg("build")
                .arg("-o")
                .arg(&bin)
                .arg(src);
            let ok = cmd.status().map(|s| s.success()).unwrap_or(false);
            ok.then_some(bin)
        });
        let r = Runtimes {
            node: find("node"),
            php: find("php"),
            go,
        };
        let required = std::env::var("ENVCLOAK_TEST_REQUIRE_SERIALIZERS").unwrap_or_default();
        for name in required.split(',').filter(|n| !n.is_empty()) {
            let there = match name {
                "node" => r.node.is_some(),
                "php" => r.php.is_some(),
                "go" => r.go.is_some(),
                "python" => true,
                other => panic!("unknown serializer {other}"),
            };
            assert!(there, "the {name} serializer is required but not installed");
        }
        r
    }

    fn args(&self) -> Vec<OsString> {
        let mut a = Vec::new();
        for (flag, p) in [
            ("--node", &self.node),
            ("--php", &self.php),
            ("--go", &self.go),
        ] {
            if let Some(p) = p {
                a.push(flag.into());
                a.push(p.into());
            }
        }
        a
    }
}

/// Gate 8 through real processes: each value's output from real
/// serializers (Python's JSON, `quote` and `quote_plus` in both hex cases,
/// form encoding, base64 and base64url padded and unpadded at offsets 0, 1
/// and 2, hex; Node, PHP and Go where installed; serde_json from this
/// test; and the recorded output of .NET, Go, Node, Python and Ruby) is
/// written by the child on stdout and stderr at once, whole and then a
/// byte at a time with an idle flush between bytes, followed by malformed
/// UTF-8, end of stream, or SIGTERM. No canary, and none of its encodings,
/// reaches the runner's output, and every payload's frame does.
fn gate8_real_serializers_split_at_every_byte_are_redacted() {
    let seed = fresh_seed();
    let mut cs = all_canaries(seed);
    let fixtures = redact_fixtures();
    for (label, file) in [
        ("FIXTURE_JSON", "value-json.txt"),
        ("FIXTURE_URL", "value-url.txt"),
    ] {
        let v = std::fs::read_to_string(fixtures.join(file)).unwrap();
        cs.push(Canary::new(label, v));
    }
    let runtimes = Runtimes::find();
    let jobs = [
        (labels::OPENAI_API_KEY, "malformed", true),
        (labels::STRIPE_SECRET_KEY, "eof", false),
        (labels::GITHUB_TOKEN, "sigterm", false),
        (labels::DATABASE_URL, "malformed", false),
    ];
    let values: Vec<String> = jobs.iter().map(|(l, _, _)| format!("{l}:{l}")).collect();
    let value_refs: Vec<&str> = values.iter().map(String::as_str).collect();
    let files = vec![
        format!("FIXTURE_JSON:{}", fixtures.join("value-json.txt").display()),
        format!("FIXTURE_URL:{}", fixtures.join("value-url.txt").display()),
    ];
    std::thread::scope(|s| {
        for (label, tail, with_fixtures) in jobs {
            let (cs, runtimes, files, value_refs, fixtures) =
                (&cs, &runtimes, &files, &value_refs, &fixtures);
            s.spawn(move || {
                let home = TestHome::new();
                let mut argv: Vec<OsString> = vec![
                    python3().into(),
                    emitter().into(),
                    "--names".into(),
                    label.into(),
                    "--tail".into(),
                    tail.into(),
                    "--pause-ms".into(),
                    "2".into(),
                    "--stdin".into(),
                ];
                argv.extend(runtimes.args());
                if with_fixtures {
                    for d in ["json", "url"] {
                        argv.push("--fixtures".into());
                        argv.push(fixtures.join(d).into());
                    }
                }
                let setup = Setup {
                    seed,
                    idle_ms: Some(1),
                    values: value_refs,
                    files: if with_fixtures { files } else { &[] },
                };
                let mut p = Proc::spawn(detached(&home, &setup, &os(&argv)));
                // serde_json's encoding, from this process, on stdin.
                let mut payload = serde_json::to_vec(by_label(cs, label).as_str()).unwrap();
                payload.push(0);
                p.write(&payload);
                p.close_stdin();
                if tail == "sigterm" {
                    assert!(
                        p.wait_for(1, b"READY\n", Duration::from_secs(120)),
                        "{label}: the emitter did not get to its tail"
                    );
                    envcloak_sys::signal_process(p.pid(), libc::SIGTERM).unwrap();
                }
                let (status, out, err) = p.finish(Duration::from_secs(180));
                assert_no_canary(&out, cs);
                assert_no_canary(&err, cs);
                home.assert_clean(cs);
                let want = if tail == "sigterm" {
                    128 + libc::SIGTERM
                } else {
                    0
                };
                assert_eq!(status.code(), Some(want), "{label}: {}", lossy(&err));
                let text = lossy(&err);
                let line = text
                    .lines()
                    .find(|l| l.starts_with("SERIALIZERS "))
                    .unwrap_or_else(|| panic!("{label}: no SERIALIZERS line: {text}"));
                let n: usize = line.rsplit(' ').next().unwrap().parse().unwrap();
                println!("gate 8 {label}: {line}");
                assert!(n >= 20, "{label}: {line}");
                let both = [out.as_slice(), err.as_slice()].concat();
                assert_eq!(count(&both, b"<W|"), n, "{label}: whole payloads lost");
                assert_eq!(count(&both, b"<B|"), n, "{label}: split payloads lost");
                assert!(
                    count(&both, b"[envcloak:") >= 2 * n,
                    "{label}: {} markers for {n} payloads",
                    count(&both, b"[envcloak:")
                );
                match tail {
                    "malformed" => {
                        assert!(contains(&out, b"M:\xff\xfe\xc3(\xe2\x82"), "{label}");
                        assert!(contains(&out, b"END\n"), "{label}");
                        assert!(contains(&err, b"M:\xc0\xaf\xed\xa0\x80\n"), "{label}");
                        assert!(contains(&err, b"DONE\n"), "{label}");
                    }
                    "eof" => assert!(contains(&err, b"DONE\n"), "{label}"),
                    _ => assert!(contains(&out, b"H:"), "{label}"),
                }
            });
        }
    });
}

// ---------------------------------------------------------------------------
// Gate 9.

/// Gate 9 through real processes: a 10-byte value with `allow_short` is
/// injected and reported, and its whole-value encodings, written a byte at
/// a time, are redacted; without `allow_short`, or under 8 bytes whatever
/// the item says, the run is refused with 125 and `value_too_short`
/// naming the slug, and the command never starts.
fn gate9_short_values_are_refused_or_warned() {
    let seed = fresh_seed();
    let cs = all_canaries(seed);
    let home = TestHome::new();
    let argv: Vec<OsString> = vec![
        python3().into(),
        emitter().into(),
        "--names".into(),
        "SHORT_TOKEN".into(),
        "--whole-only".into(),
    ];
    let setup = Setup {
        seed,
        idle_ms: Some(1),
        values: &[
            "SHORT_TOKEN:SHORT_TOKEN:allow",
            "FIFTEEN:FIFTEEN_BYTES:allow",
        ],
        files: &[],
    };
    let (status, out, err) =
        Proc::spawn(detached(&home, &setup, &os(&argv))).finish(Duration::from_secs(120));
    assert_eq!(status.code(), Some(0), "{}", lossy(&err));
    let short = [by_label(&cs, labels::SHORT_TOKEN).clone()];
    assert_no_canary(&out, &short);
    assert_no_canary(&err, &short);
    let e = lossy(&err);
    assert!(
        e.contains("envcloak: coverage: short_token/t: 8 to 15 bytes"),
        "{e}"
    );
    assert!(
        e.contains("envcloak: coverage: fifteen_bytes/t: 8 to 15 bytes"),
        "{e}"
    );
    assert!(
        e.contains("envcloak: coverage: short_token/t: partial"),
        "{e}"
    );
    let n: usize = e
        .lines()
        .find_map(|l| l.strip_prefix("SERIALIZERS python PAYLOADS "))
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        count(
            &[out.as_slice(), err.as_slice()].concat(),
            b"[envcloak:short_token/t]"
        ) >= 2 * n
    );

    // Refused: the command would leave a mark.
    let mark = home.root().join("started");
    let touch = sh(&format!("touch '{}'", mark.display()));
    for values in [
        &["SHORT_TOKEN:SHORT_TOKEN"][..],
        &["FIFTEEN:FIFTEEN_BYTES"],
        &["SEVEN:SEVEN_BYTES:allow"],
        &["OPENAI_API_KEY:OPENAI_API_KEY", "SEVEN:SEVEN_BYTES"],
    ] {
        let setup = Setup {
            seed,
            idle_ms: None,
            values,
            files: &[],
        };
        let (status, out, err) =
            Proc::spawn(detached(&home, &setup, &os(&touch))).finish(Duration::from_secs(60));
        assert_eq!(status.code(), Some(125), "{values:?}");
        let e = lossy(&err);
        assert!(e.starts_with("envcloak: value_too_short: "), "{e}");
        let refused = values.last().unwrap().split(':').nth(1).unwrap();
        assert!(e.contains(&slug_of(refused)), "{e}");
        assert!(!e.contains("openai_api_key/t"), "{e}");
        assert!(out.is_empty());
        assert!(!mark.exists(), "{values:?}: the command started");
    }
    home.assert_clean(&cs);
}

// ---------------------------------------------------------------------------
// Signals.

/// The child reports its group and pid, says `ready`, and waits; on
/// SIGINT it prints a value and exits 130.
const TRAPS_INT: &str = r#"trap 'printf "%s\n" "$OPENAI_API_KEY"; echo got-int; exit 130' INT
echo "pgid=$(ps -o pgid= -p $$ | tr -d ' ') pid=$$ ppid=$PPID"
echo ready
while :; do sleep 0.05; done"#;

/// Without a controlling terminal the child leads its own group, and
/// SIGINT and SIGTERM sent to the runner are passed on to that group: the
/// child's trap runs (its output redacted) and the runner exits with the
/// child's code, or 128 plus the signal that ended it.
fn without_a_terminal_signals_go_to_the_childs_own_group() {
    let seed = fresh_seed();
    let cs = all_canaries(seed);
    let home = TestHome::new();
    let setup = Setup {
        seed,
        idle_ms: None,
        values: &["OPENAI_API_KEY:OPENAI_API_KEY"],
        files: &[],
    };
    let p = Proc::spawn(detached(&home, &setup, &os(&sh(TRAPS_INT))));
    assert!(p.wait_for(0, b"ready\n", Duration::from_secs(60)));
    let runner = p.pid();
    envcloak_sys::signal_process(runner, libc::SIGINT).unwrap();
    let (status, out, err) = p.finish(Duration::from_secs(60));
    assert_eq!(status.code(), Some(130), "{}", lossy(&err));
    assert!(
        contains(&out, b"[envcloak:openai_api_key/t]\ngot-int\n"),
        "{}",
        lossy(&out)
    );
    let (pgid, pid, ppid) = (field(&out, "pgid"), field(&out, "pid"), field(&out, "ppid"));
    assert_eq!(ppid, runner);
    assert_eq!(pgid, pid, "the child does not lead its own group");
    assert_ne!(pgid, runner);
    assert_no_canary(&out, &cs);
    assert_no_canary(&err, &cs);

    // SIGTERM, no trap: the child dies of it, and the runner says so.
    let p = Proc::spawn(detached(
        &home,
        &setup,
        &os(&sh("echo ready; while :; do sleep 0.05; done")),
    ));
    assert!(p.wait_for(0, b"ready\n", Duration::from_secs(60)));
    envcloak_sys::signal_process(p.pid(), libc::SIGTERM).unwrap();
    let (status, _, err) = p.finish(Duration::from_secs(60));
    assert_eq!(status.code(), Some(128 + libc::SIGTERM), "{}", lossy(&err));
    home.assert_clean(&cs);
}

/// On a terminal the child stays in the runner's group: Ctrl-C reaches
/// it from the terminal, the runner stays to redact what it prints on its
/// way out, and exits with its code.
fn on_a_terminal_ctrl_c_reaches_the_child_and_the_runner_stays() {
    let seed = fresh_seed();
    let cs = all_canaries(seed);
    let home = TestHome::new();
    let setup = Setup {
        seed,
        idle_ms: None,
        values: &["OPENAI_API_KEY:OPENAI_API_KEY"],
        files: &[],
    };
    let (code, shown) = on_pty(&home, "ctrl-c", &setup, &os(&sh(TRAPS_INT)));
    assert_eq!(code, 130, "{}", lossy(&shown));
    assert!(
        contains(&shown, b"[envcloak:openai_api_key/t]"),
        "{}",
        lossy(&shown)
    );
    assert!(contains(&shown, b"got-int"), "{}", lossy(&shown));
    let (pgid, ppid) = (field(&shown, "pgid"), field(&shown, "ppid"));
    assert_eq!(pgid, ppid, "the child left the runner's group");
    assert_no_canary(&shown, &cs);
    home.assert_clean(&cs);
}

/// On a terminal, SIGTERM sent to the runner alone is passed on to the
/// child.
fn on_a_terminal_sigterm_is_passed_to_the_child() {
    let seed = fresh_seed();
    let cs = all_canaries(seed);
    let home = TestHome::new();
    let setup = Setup {
        seed,
        idle_ms: None,
        values: &["STRIPE_SECRET_KEY:STRIPE_SECRET_KEY"],
        files: &[],
    };
    let script = r#"trap 'printf "%s\n" "$STRIPE_SECRET_KEY"; echo got-term; exit 143' TERM
echo ready
while :; do sleep 0.05; done"#;
    let (code, shown) = on_pty(&home, "sigterm", &setup, &os(&sh(script)));
    assert_eq!(code, 143, "{}", lossy(&shown));
    assert!(
        contains(&shown, b"[envcloak:stripe_secret_key/t]"),
        "{}",
        lossy(&shown)
    );
    assert!(contains(&shown, b"got-term"), "{}", lossy(&shown));
    assert_no_canary(&shown, &cs);
    home.assert_clean(&cs);
}

// ---------------------------------------------------------------------------
// Exit codes, prompts, a lost reader, backpressure, a descendant.

/// The child's code passes through; a signal becomes 128 plus its number;
/// a missing command is 127 and one that cannot be run 126, as `env(1)`
/// has them.
fn exit_codes_pass_through() {
    let seed = fresh_seed();
    let home = TestHome::new();
    let setup = Setup {
        seed,
        idle_ms: None,
        values: &["OPENAI_API_KEY:OPENAI_API_KEY"],
        files: &[],
    };
    let plain = home.root().join("plain");
    std::fs::write(&plain, b"echo hi\n").unwrap();
    let cases: Vec<(Vec<OsString>, i32, &str)> = vec![
        (sh("exit 0"), 0, ""),
        (sh("exit 3"), 3, ""),
        (sh("exit 255"), 255, ""),
        (sh("kill -KILL $$"), 128 + libc::SIGKILL, ""),
        (sh("kill -USR1 $$"), 128 + libc::SIGUSR1, ""),
        (
            vec![home.root().join("missing").into()],
            127,
            "envcloak: command_not_found:",
        ),
        (
            vec!["envcloak-no-such-command-anywhere".into()],
            127,
            "envcloak: command_not_found:",
        ),
        (vec![plain.into()], 126, "envcloak: command_not_executable:"),
    ];
    for (argv, code, message) in cases {
        let (status, _, err) =
            Proc::spawn(detached(&home, &setup, &os(&argv))).finish(Duration::from_secs(60));
        assert_eq!(status.code(), Some(code), "{argv:?}: {}", lossy(&err));
        assert!(
            lossy(&err).starts_with(message),
            "{argv:?}: {}",
            lossy(&err)
        );
    }
}

/// A prompt without a newline shows while the child waits for its
/// answer (the answer is only typed once it has): the idle flush releases
/// it. The first bytes of a value, written without a newline, are held
/// while the pipe is quiet, and released as they were once what follows
/// shows they are not the value.
fn a_prompt_shows_and_the_start_of_a_value_waits() {
    let seed = fresh_seed();
    let cs = all_canaries(seed);
    let home = TestHome::new();
    let setup = Setup {
        seed,
        idle_ms: None,
        values: &["OPENAI_API_KEY:OPENAI_API_KEY"],
        files: &[],
    };
    let script = r#"printf 'before\n'
sleep 0.3
printf 'Password: '
read answer
printf 'got %s\n' "$answer"
printf '%.12s' "$OPENAI_API_KEY"
read more
printf '!\n'"#;
    let mut p = Proc::spawn(detached(&home, &setup, &os(&sh(script))));
    assert!(p.wait_for(0, b"before\n", Duration::from_secs(60)));
    let t0 = Instant::now();
    assert!(
        p.wait_for(0, b"Password: ", Duration::from_secs(10)),
        "the prompt did not show while the child waited"
    );
    println!("prompt: shown {:?} after the line before it", t0.elapsed());
    assert!(t0.elapsed() < Duration::from_secs(1));
    p.write(b"yes\n");
    assert!(p.wait_for(0, b"got yes\n", Duration::from_secs(10)));
    let prefix = &by_label(&cs, labels::OPENAI_API_KEY).value()[..12];
    assert!(
        !p.wait_for(0, prefix, Duration::from_millis(300)),
        "the start of a value was released"
    );
    p.write(b"\n");
    let (status, out, _) = p.finish(Duration::from_secs(60));
    assert_eq!(status.code(), Some(0));
    assert!(contains(&out, &[prefix, b"!\n"].concat()));
    assert_no_canary(&out, &cs);
}

/// When the runner's standard output has no reader, the child's pipe is
/// closed too: `yes` dies of SIGPIPE as it would writing to the reader
/// directly, and standard error still works.
fn a_lost_reader_closes_the_childs_pipe() {
    let seed = fresh_seed();
    let cs = all_canaries(seed);
    let home = TestHome::new();
    let setup = Setup {
        seed,
        idle_ms: None,
        values: &["OPENAI_API_KEY:OPENAI_API_KEY"],
        files: &[],
    };
    for (script, code, err_has) in [
        (r#"exec yes "$OPENAI_API_KEY""#, 128 + libc::SIGPIPE, ""),
        (
            r#"yes "$OPENAI_API_KEY"; echo "yes ended $? $OPENAI_API_KEY" >&2"#,
            0,
            "yes ended 141 [envcloak:openai_api_key/t]\n",
        ),
    ] {
        let mut cmd = detached(&home, &setup, &os(&sh(script)));
        cmd.stdin(Stdio::null());
        let mut child = cmd.spawn().unwrap();
        drop(child.stdout.take());
        let mut p = Proc {
            stdin: None,
            cap: Arc::default(),
            readers: Vec::new(),
            child,
        };
        let mut err_pipe = p.child.stderr.take().unwrap();
        let reader = std::thread::spawn(move || {
            let mut e = Vec::new();
            err_pipe.read_to_end(&mut e).unwrap();
            e
        });
        let status = {
            let end = Instant::now() + Duration::from_secs(60);
            loop {
                if let Some(s) = p.child.try_wait().unwrap() {
                    break s;
                }
                assert!(
                    Instant::now() < end,
                    "the runner kept going without a reader"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        };
        let err = reader.join().unwrap();
        assert_eq!(status.code(), Some(code), "{script}: {}", lossy(&err));
        assert!(
            contains(&err, err_has.as_bytes()),
            "{script}: {}",
            lossy(&err)
        );
        assert!(!contains(&err, b"panicked"));
        assert_no_canary(&err, &cs);
    }
}

/// 100 MB through the runner to a reader that stops: the child is held
/// up once the pipes are full, never more than a few pipe buffers ahead
/// of what was read, and every byte arrives once reading resumes.
fn backpressure_holds_the_child_through_100_mb() {
    const CHUNK: usize = 1 << 16;
    const CHUNKS: usize = 1600;
    let seed = fresh_seed();
    let home = TestHome::new();
    let setup = Setup {
        seed,
        idle_ms: None,
        values: &["OPENAI_API_KEY:OPENAI_API_KEY"],
        files: &[],
    };
    let progress = home.root().join("progress");
    let writer = format!(
        "import os\nchunk = bytes(range(256)) * {}\nfd = os.open({:?}, os.O_WRONLY | os.O_CREAT, 0o600)\n\
         total = 0\nfor _ in range({CHUNKS}):\n    os.write(1, chunk)\n    total += len(chunk)\n    \
         os.pwrite(fd, b'%020d' % total, 0)\n",
        CHUNK / 256,
        progress.to_str().unwrap()
    );
    let argv: Vec<OsString> = vec![python3().into(), "-c".into(), writer.into()];
    let mut cmd = detached(&home, &setup, &os(&argv));
    cmd.stdin(Stdio::null());
    let mut child = cmd.spawn().unwrap();
    let mut out = child.stdout.take().unwrap();
    let written = || -> usize {
        std::fs::read_to_string(&progress)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    };
    // Nothing is read: the child must stall with a bounded lead.
    let bound = 1 << 20;
    let mut last = (0, Instant::now());
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let w = written();
        assert!(w <= bound, "the child wrote {w} bytes with nothing read");
        if w != last.0 {
            last = (w, Instant::now());
        } else if w > 0 && last.1.elapsed() > Duration::from_millis(500) {
            break;
        }
        assert!(Instant::now() < deadline, "the child never started writing");
        std::thread::sleep(Duration::from_millis(20));
    }
    println!("backpressure: the child stalled {} bytes ahead", last.0);
    let started = Instant::now();
    let pattern: Vec<u8> = (0..CHUNK + 256).map(|i| (i % 256) as u8).collect();
    let mut total = 0usize;
    let mut b = vec![0u8; CHUNK];
    loop {
        let n = out.read(&mut b).unwrap();
        if n == 0 {
            break;
        }
        let at = total % 256;
        assert!(b[..n] == pattern[at..at + n], "bytes changed after {total}");
        total += n;
    }
    let status = child.wait().unwrap();
    println!(
        "backpressure: {total} bytes read in {:?}",
        started.elapsed()
    );
    assert!(status.success(), "{status:?}");
    assert_eq!(total, CHUNK * CHUNKS);
}

/// A descendant that keeps the pipes open after the child exits: its
/// output in the first 2 seconds is still read and redacted, then the
/// pipes are closed and the runner returns; what it writes later is lost.
fn a_descendant_holding_the_pipes_is_cut_off_after_2_s() {
    let seed = fresh_seed();
    let cs = all_canaries(seed);
    let home = TestHome::new();
    let setup = Setup {
        seed,
        idle_ms: None,
        values: &[
            "OPENAI_API_KEY:OPENAI_API_KEY",
            "STRIPE_SECRET_KEY:STRIPE_SECRET_KEY",
        ],
        files: &[],
    };
    let script = r#"printf 'first %s\n' "$OPENAI_API_KEY"
( sleep 0.5; printf 'late-ok %s\n' "$STRIPE_SECRET_KEY"; sleep 3.5; echo too-late; exec sleep 30 ) &
echo "gc=$!"
exit 0"#;
    let started = Instant::now();
    let (status, out, err) =
        Proc::spawn(detached(&home, &setup, &os(&sh(script)))).finish(Duration::from_secs(30));
    let took = started.elapsed();
    let gc = field(&out, "gc");
    let _ = envcloak_sys::signal_process(gc, libc::SIGKILL);
    assert_eq!(status.code(), Some(0), "{}", lossy(&err));
    println!("cutoff: the runner returned after {took:?}");
    assert!(took >= Duration::from_secs(2), "{took:?}");
    assert!(took < Duration::from_secs(4), "{took:?}");
    assert!(
        contains(&out, b"first [envcloak:openai_api_key/t]\n"),
        "{}",
        lossy(&out)
    );
    assert!(
        contains(&out, b"late-ok [envcloak:stripe_secret_key/t]\n"),
        "{}",
        lossy(&out)
    );
    assert!(!contains(&out, b"too-late"));
    assert_no_canary(&out, &cs);
    assert_no_canary(&err, &cs);
}

// ---------------------------------------------------------------------------
// The harness itself (review T12-5): a failed test leaves nothing running
// and never waits for ever.

/// A child that reports its pid, says `ready`, and then ignores every
/// signal a runner passes on, so only SIGKILL ends it.
const STUBBORN: &str = r#"trap '' INT TERM HUP
echo "pid=$$"
echo ready
while :; do sleep 0.05; done"#;

/// A test that fails with a runner running drops its `Proc`. Without a
/// terminal the runner's child leads its own process group, so killing the
/// runner alone would leave it running, reparented. Dropping the `Proc`
/// kills the child's group too.
fn harness_a_dropped_runner_takes_its_childs_group_with_it() {
    let seed = fresh_seed();
    let home = TestHome::new();
    let setup = Setup {
        seed,
        idle_ms: None,
        values: &["OPENAI_API_KEY:OPENAI_API_KEY"],
        files: &[],
    };
    let p = Proc::spawn(detached(&home, &setup, &os(&sh(STUBBORN))));
    assert!(p.wait_for(0, b"ready\n", Duration::from_secs(60)));
    let runner = p.pid();
    let child = field(&p.cap.streams.lock().unwrap()[0], "pid");
    let _cleanup = KillOnDrop(vec![child, runner]);
    assert_ne!(child, runner);
    drop(p);
    assert!(
        gone_within(runner, Duration::from_secs(10)),
        "the runner is still running"
    );
    assert!(
        gone_within(child, Duration::from_secs(10)),
        "the runner's child is still running after its Proc was dropped"
    );
}

/// A runner on a terminal that never exits (its child ignores the SIGTERM
/// passed on): the pty driver gives up after its patience, kills the
/// terminal's process group, which holds the runner and its child, and
/// says `NOEXIT`, instead of waiting for ever.
fn harness_a_runner_that_never_exits_on_a_terminal_is_killed_with_its_session() {
    let seed = fresh_seed();
    let home = TestHome::new();
    let setup = Setup {
        seed,
        idle_ms: None,
        values: &["OPENAI_API_KEY:OPENAI_API_KEY"],
        files: &[],
    };
    let started = Instant::now();
    let p = on_pty_within(&home, "sigterm", (1, 2), &setup, &os(&sh(STUBBORN)));
    let child = field(&p.shown, "pid");
    let _cleanup = KillOnDrop(vec![child, p.runner]);
    assert_eq!(p.end, PtyEnd::NoExit, "{}", lossy(&p.shown));
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "{:?}",
        started.elapsed()
    );
    assert!(
        gone_within(p.runner, Duration::from_secs(10)),
        "the runner is still running"
    );
    assert!(
        gone_within(child, Duration::from_secs(10)),
        "the runner's child is still running after the driver gave up"
    );
}
