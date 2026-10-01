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
//!
//! Cleanup signals only processes the harness owns (review F-62): a
//! process it spawned and has not reaped, whose pid therefore cannot name
//! any other process ([`Proc`]). It never looks for the processes those
//! start in the process table, and never signals a pid it read: once a
//! process is reaped elsewhere its pid can be another's. So every fixture
//! the runner starts that would otherwise run on (a loop waiting for a
//! signal, a descendant writing) has a [`Lifetime`]: it ends when the test
//! asks it to, or removes the home the request is in, as the test ends
//! (passed, failed or timed out), or by itself at a deadline longer than
//! any test waits, should the test process die first. It records how it
//! ended; that record is an acknowledgment written just before it exits,
//! not proof that it has been reaped, which only its parent could give.
//! The pty driver kills the terminal's process group only while it has
//! not reaped the group's leader, and then waits on a pipe every process
//! of the tree holds, so its report that the tree is gone rests on the
//! kernel, not on pids.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitCode, ExitStatus, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use envcloak_core::SecretBytes;
use envcloak_core::vault::Slug;
use envcloak_exec::{ExecError, Label, RunSpec, ShortPolicy, build_redactor, run};
use envcloak_policy::EnvName;
use envcloak_sys::StartTime;
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
    let mut idle = None;
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
            "--idle-ms" => idle = Some(Duration::from_millis(next().parse().unwrap())),
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
    // As `envcloak run` builds it: the idle flush is IDLE_FLUSH unless
    // --idle-ms names another.
    let mut spec = RunSpec::new(
        argv,
        injected,
        redactor,
        std::io::stdout().as_fd().try_clone_to_owned().unwrap(),
        std::io::stderr().as_fd().try_clone_to_owned().unwrap(),
    );
    if let Some(idle) = idle {
        spec.idle_flush = idle;
    }
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
    (
        "on_a_terminal_sigint_and_sigquit_from_a_process_reach_the_child",
        on_a_terminal_sigint_and_sigquit_from_a_process_reach_the_child,
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
        "a_stalled_reader_does_not_hold_a_descendants_pipe_past_the_cutoff",
        a_stalled_reader_does_not_hold_a_descendants_pipe_past_the_cutoff,
    ),
    (
        "a_stalled_reader_is_given_up_with_the_signals_blocked",
        a_stalled_reader_is_given_up_with_the_signals_blocked,
    ),
    (
        "a_signal_after_the_exit_stops_a_stalled_run",
        a_signal_after_the_exit_stops_a_stalled_run,
    ),
    (
        "a_signal_after_the_exit_stops_a_stalled_run_with_the_signals_blocked",
        a_signal_after_the_exit_stops_a_stalled_run_with_the_signals_blocked,
    ),
    (
        "harness_a_dropped_runner_is_reaped_and_its_child_ends_when_asked",
        harness_a_dropped_runner_is_reaped_and_its_child_ends_when_asked,
    ),
    (
        "harness_a_runner_that_never_exits_on_a_terminal_is_killed_with_its_session",
        harness_a_runner_that_never_exits_on_a_terminal_is_killed_with_its_session,
    ),
    (
        "harness_the_pty_driver_says_when_a_process_outlives_the_kill",
        harness_the_pty_driver_says_when_a_process_outlives_the_kill,
    ),
    (
        "harness_cleanup_after_a_successful_finish_signals_nothing",
        harness_cleanup_after_a_successful_finish_signals_nothing,
    ),
    (
        "harness_cleanup_kills_only_its_own_process_once",
        harness_cleanup_kills_only_its_own_process_once,
    ),
    (
        "harness_a_fixture_ends_when_its_test_fails_before_or_after_readiness",
        harness_a_fixture_ends_when_its_test_fails_before_or_after_readiness,
    ),
    (
        "harness_a_fixture_whose_lifetime_is_gone_ends",
        harness_a_fixture_whose_lifetime_is_gone_ends,
    ),
    (
        "harness_finish_gives_up_on_output_a_survivor_holds",
        harness_finish_gives_up_on_output_a_survivor_holds,
    ),
    (
        "harness_a_writer_blocked_on_a_full_pipe_ends_at_its_deadline",
        harness_a_writer_blocked_on_a_full_pipe_ends_at_its_deadline,
    ),
    (
        "harness_a_writer_whose_reader_is_lost_ends",
        harness_a_writer_whose_reader_is_lost_ends,
    ),
    (
        "harness_a_fixture_whose_test_died_ends_at_its_deadline",
        harness_a_fixture_whose_test_died_ends_at_its_deadline,
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

/// [`DETACH`], with SIGURG and the four signals the runner catches blocked
/// before the `exec`: a signal mask survives it, so a program can start
/// the runner so (review R-8).
const DETACH_MASKED: &str = "import os, signal, sys\n\
signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGURG, signal.SIGINT, signal.SIGTERM, \
signal.SIGHUP, signal.SIGQUIT})\n\
os.setsid()\nos.execv(sys.argv[1], sys.argv[1:])\n";

/// Runs argv[4..] leading a session on a new pseudo-terminal. Waits until
/// the terminal shows `ready`, then (argv[1]) types Ctrl-C (`ctrl-c`),
/// sends the process SIGTERM, SIGINT or SIGQUIT from this driver, in
/// another session (`sigterm`, `sigint`, `sigquit`), or does nothing
/// (`none`: the command signals the process itself). Reads until the
/// terminal has been quiet for
/// argv[2] seconds, then waits up to argv[3] seconds for the process to
/// exit. Prints `RUNNER <pid>`, then `EXIT <code>` and everything the
/// terminal showed. A process that is not ready in time, or does not exit
/// in time, is killed with its whole process group (it leads the
/// terminal's session and group, and on a terminal its child stays in
/// that group), while this driver has not reaped it, so the group cannot
/// be another's; then reported as `NOREADY` or `NOEXIT` in place of the
/// `EXIT` line, with exit status 1: the driver never waits for ever, and
/// never leaves the runner or its child behind (review T12-5).
///
/// Whether they are gone rests on a lifeline, not on pids (review F-62):
/// the process inherits the write end of a pipe, which the runner passes
/// on to its child and that to everything it starts, and the driver keeps
/// only the read end. The read end ends when every process holding the
/// write end has exited. After a kill the driver waits up to 10 seconds
/// for that, reading the terminal meanwhile (macOS holds a process's exit
/// while the terminal has output nobody reads), reaps the process, and
/// adds `gone` or `left` to the line. A process that closed the
/// descriptor itself would not be seen; the fixtures here do not.
const ON_PTY: &str = r#"import os, pty, select, signal, sys, time
send, quiet, patience = sys.argv[1], float(sys.argv[2]), float(sys.argv[3])
life_r, life_w = os.pipe()
os.set_inheritable(life_w, True)
pid, fd = pty.fork()
if pid == 0:
    os.close(life_r)
    os.execv(sys.argv[4], sys.argv[4:])
os.close(life_w)
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
def tree_gone(limit):
    global out
    end = time.time() + limit
    watched = [fd, life_r]
    while True:
        r, _, _ = select.select(watched, [], [], max(0.0, end - time.time()))
        if not r:
            return False
        if life_r in r and not os.read(life_r, 4096):
            return True
        if fd in r:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                chunk = b''
            if chunk:
                out += chunk
            else:
                watched = [life_r]
def give_up(why):
    try:
        os.killpg(pid, signal.SIGKILL)
    except OSError:
        pass
    gone = tree_gone(10)
    try:
        os.waitpid(pid, 0)
    except OSError:
        pass
    sys.stdout.buffer.write(why + (b' gone' if gone else b' left') + b'\n' + out)
    sys.exit(1)
deadline = time.time() + 60
while b'ready' not in out:
    if not more(deadline):
        give_up(b'NOREADY')
if send == 'ctrl-c':
    os.write(fd, b'\x03')
elif send != 'none':
    sig = {'sigterm': signal.SIGTERM, 'sigint': signal.SIGINT, 'sigquit': signal.SIGQUIT}[send]
    os.kill(pid, sig)
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
    detached_by(DETACH, home, s, argv)
}

/// [`detached`], started by the Python program `launcher` ([`DETACH`] or
/// [`DETACH_MASKED`]).
fn detached_by(launcher: &str, home: &TestHome, s: &Setup<'_>, argv: &[&OsStr]) -> Command {
    let mut cmd = Command::new(python3());
    home.apply(&mut cmd)
        .args(["-c", launcher])
        .args(runner_args(s, argv))
        .current_dir(home.home())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

/// How [`ON_PTY`] ended. A process it gave up on was killed with its
/// group; `gone` says whether every process of its tree had then exited
/// (the lifeline pipe ended) within 10 seconds.
#[derive(Debug, PartialEq, Eq)]
enum PtyEnd {
    Exit(i32),
    NoReady { gone: bool },
    NoExit { gone: bool },
}

/// What [`on_pty_within`] saw: how it ended, and what the terminal
/// showed.
struct Pty {
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
    let _runner: i32 = std::str::from_utf8(first)
        .ok()
        .and_then(|l| l.trim_end().strip_prefix("RUNNER "))
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("the pty driver failed to start: {}", lossy(&err)));
    let nl = rest.iter().position(|b| *b == b'\n').expect("no end line");
    let end = match &rest[..nl] {
        b"NOREADY gone" => PtyEnd::NoReady { gone: true },
        b"NOREADY left" => PtyEnd::NoReady { gone: false },
        b"NOEXIT gone" => PtyEnd::NoExit { gone: true },
        b"NOEXIT left" => PtyEnd::NoExit { gone: false },
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

/// What a process wrote, collected by two reader threads, and how many of
/// them have reached the end of their stream.
#[derive(Default)]
struct Captured {
    streams: Mutex<([Vec<u8>; 2], usize)>,
    changed: Condvar,
}

/// A running process the harness spawned, with its output collected as it
/// comes. The harness owns it until it reaps it, and its cleanup signals
/// nothing else (review F-62): see [`Proc::kill_owned`].
struct Proc {
    child: Child,
    stdin: Option<ChildStdin>,
    cap: Arc<Captured>,
    readers: Vec<JoinHandle<()>>,
    /// How cleanup kills the process ([`Live`], or a recording [`Model`]
    /// in the harness's own tests).
    host: Arc<dyn Host>,
    /// The child has been reaped. Its pid can then be another process's,
    /// so cleanup does nothing more (review F-62).
    reaped: bool,
}

impl Proc {
    fn spawn(cmd: Command) -> Proc {
        Proc::spawn_on(cmd, Arc::new(Live))
    }

    /// [`Proc::spawn`], with cleanup killing through `host`.
    fn spawn_on(mut cmd: Command, host: Arc<dyn Host>) -> Proc {
        Proc::collect(cmd.spawn().unwrap(), host)
    }

    /// [`Proc::spawn`], with standard output left unread: it is returned,
    /// open, for the test to read when it chooses. Standard error is
    /// collected.
    fn spawn_holding_stdout(mut cmd: Command) -> (Proc, ChildStdout) {
        let mut child = cmd.spawn().unwrap();
        let stdout = child.stdout.take().unwrap();
        (Proc::collect(child, Arc::new(Live)), stdout)
    }

    /// Collects what `child` writes on the streams it still has.
    fn collect(mut child: Child, host: Arc<dyn Host>) -> Proc {
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
                    cap.streams.lock().unwrap().0[i].extend_from_slice(&b[..n]);
                    cap.changed.notify_all();
                }
                cap.streams.lock().unwrap().1 += 1;
                cap.changed.notify_all();
            }));
        }
        let stdin = child.stdin.take();
        Proc {
            child,
            stdin,
            cap,
            readers,
            host,
            reaped: false,
        }
    }

    /// A process whose output the test reads itself.
    fn bare(child: Child) -> Proc {
        Proc {
            child,
            stdin: None,
            cap: Arc::default(),
            readers: Vec::new(),
            host: Arc::new(Live),
            reaped: false,
        }
    }

    fn pid(&self) -> i32 {
        i32::try_from(self.child.id()).unwrap()
    }

    /// The exit status, once the process has exited. It is reaped then,
    /// and cleanup is disarmed: its pid may be another process's from now
    /// on (review F-62).
    fn try_wait(&mut self) -> Option<ExitStatus> {
        let status = self.child.try_wait().unwrap();
        self.reaped |= status.is_some();
        status
    }

    /// Waits until stream `i` (0 stdout, 1 stderr) holds `pat`.
    fn wait_for(&self, i: usize, pat: &[u8], limit: Duration) -> bool {
        let end = Instant::now() + limit;
        let mut s = self.cap.streams.lock().unwrap();
        loop {
            if contains(&s.0[i], pat) {
                return true;
            }
            let now = Instant::now();
            if now >= end {
                return false;
            }
            s = self.cap.changed.wait_timeout(s, end - now).unwrap().0;
        }
    }

    /// What stream `i` (0 stdout, 1 stderr) holds so far.
    fn captured(&self, i: usize) -> Vec<u8> {
        self.cap.streams.lock().unwrap().0[i].clone()
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
    /// does not exit in time is killed, and the test fails. One that exits
    /// is reaped here, and nothing is signalled after that.
    ///
    /// Its exit does not end its output: a process it started can hold the
    /// pipes open. The output is collected until both streams end within
    /// the same `limit`, never waited for without one (review F-62); a
    /// stream still open then fails the test, which asks its fixtures to
    /// stop as it unwinds ([`Lifetime`]).
    fn finish(mut self, limit: Duration) -> (ExitStatus, Vec<u8>, Vec<u8>) {
        self.stdin = None;
        let end = Instant::now() + limit;
        let status = loop {
            if let Some(s) = self.try_wait() {
                break s;
            }
            if Instant::now() > end {
                self.kill_owned();
                panic!("the process did not exit within {limit:?}");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let readers = self.readers.len();
        let mut s = self.cap.streams.lock().unwrap();
        while s.1 < readers {
            let now = Instant::now();
            if now >= end {
                let ended = s.1;
                drop(s);
                panic!(
                    "the process exited, but {} of its {readers} output streams were still \
                     open {limit:?} after it started",
                    readers - ended
                );
            }
            s = self.cap.changed.wait_timeout(s, end - now).unwrap().0;
        }
        let [out, err] = std::mem::take(&mut s.0);
        drop(s);
        for r in self.readers.drain(..) {
            r.join().unwrap();
        }
        (status, out, err)
    }

    /// Kills the process and reaps it, as a failed test must (review
    /// T12-5), once, and only while it is not reaped (review F-62): until
    /// then its pid is still its own, even after it exits. Nothing else is
    /// signalled. The processes it started are its own business: without
    /// a terminal the runner's child leads a group of its own, and it and
    /// anything it started end on their own ([`Lifetime`]), or when the
    /// pipes to the killed runner close. Earlier versions found them in
    /// the process table and killed them by pid, which could reach a
    /// process that took over a pid in between.
    fn kill_owned(&mut self) {
        if self.reaped {
            return;
        }
        self.host.kill(&mut self.child);
        let _ = self.child.wait();
        self.reaped = true;
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        self.kill_owned();
    }
}

/// How the harness's cleanup kills a process it owns: on the live system
/// ([`Live`]), or, in the harness's own tests, recording what it kills
/// ([`Model`], review F-62).
trait Host: Send + Sync {
    /// Sends SIGKILL to `child`, which the harness spawned and has not
    /// reaped.
    fn kill(&self, child: &mut Child);
}

/// The live system: `Child::kill`, which signals only an unreaped child.
struct Live;

impl Host for Live {
    fn kill(&self, child: &mut Child) {
        let _ = child.kill();
    }
}

/// Records the pid of every process cleanup kills, then kills it as
/// [`Live`] does: the harness's tests run real short children, and end
/// them.
#[derive(Default)]
struct Model {
    killed: Mutex<Vec<i32>>,
}

impl Model {
    fn killed(&self) -> Vec<i32> {
        self.killed.lock().unwrap().clone()
    }
}

impl Host for Model {
    fn kill(&self, child: &mut Child) {
        self.killed
            .lock()
            .unwrap()
            .push(i32::try_from(child.id()).unwrap());
        let _ = child.kill();
    }
}

/// How long a fixture waits for its stop request before it ends by
/// itself: longer than any test here waits for anything, so it never
/// decides a test's outcome.
const FIXTURE_DEADLINE_SECS: u64 = 300;

/// The lifetime of the fixture processes a test has the runner start
/// (review F-62). The harness kills only what it spawned itself
/// ([`Proc::kill_owned`]); a fixture that would otherwise run on (a loop
/// waiting for a signal, a descendant writing) waits for this stop
/// request instead, which the test makes when it drops this: as it
/// passes, fails an assertion or times out. It ends by itself at its
/// deadline should that never come (the test process died first).
///
/// The request is a file in a directory of the test's home, and the
/// home, made before this, is dropped right after it, taking the request
/// with it within microseconds: a fixture that looks every 50 ms would
/// mostly miss it, and run on to its deadline. So the directory being
/// gone is a stop request too, and every fixture looks for both.
///
/// Each fixture appends how it ended to [`Lifetime::ended_path`]:
/// `stopped`, `gone` (the directory was), `deadline`, or, for a writer,
/// `pipe_closed` when its output was closed. That is an acknowledgment
/// written just before it exits, not proof that it has been reaped (only
/// its parent could give that); a fixture that reached its deadline,
/// where a test expected it to be stopped, is a failure. The record is
/// in the directory, and goes with it, unless a harness test keeps it
/// elsewhere ([`Lifetime::recording_at`]) to read once the home is gone.
struct Lifetime {
    dir: PathBuf,
    record: PathBuf,
    deadline_secs: u64,
}

impl Lifetime {
    /// A lifetime in `home`, named `name`, with the long deadline.
    fn new(home: &TestHome, name: &str) -> Lifetime {
        Lifetime::with_deadline(home, name, FIXTURE_DEADLINE_SECS)
    }

    fn with_deadline(home: &TestHome, name: &str, deadline_secs: u64) -> Lifetime {
        Lifetime::made(home, name, deadline_secs, None)
    }

    /// [`Lifetime::with_deadline`], with the record at `record`, outside
    /// `home`, where it outlives it.
    fn recording_at(home: &TestHome, name: &str, deadline_secs: u64, record: PathBuf) -> Lifetime {
        Lifetime::made(home, name, deadline_secs, Some(record))
    }

    fn made(home: &TestHome, name: &str, deadline_secs: u64, record: Option<PathBuf>) -> Lifetime {
        let dir = home.root().join(format!("life-{name}"));
        std::fs::create_dir_all(&dir).unwrap();
        Lifetime {
            record: record.unwrap_or_else(|| dir.join("ended")),
            dir,
            deadline_secs,
        }
    }

    /// The stop request. The directory it is in being gone is one too.
    fn stop_path(&self) -> PathBuf {
        self.dir.join("stop")
    }

    fn ended_path(&self) -> PathBuf {
        self.record.clone()
    }

    /// Asks the fixtures to stop.
    fn stop(&self) {
        let _ = std::fs::write(self.stop_path(), b"");
    }

    /// Shell text that waits for the stop request or for its directory to
    /// be gone, checking every 50 ms, until the deadline, then records how
    /// it ended (a record in a directory that is gone is not written) and
    /// exits: 0 when asked to stop, 124 at the deadline. A trap set before
    /// it still runs on its signal, between two checks. `exit` ends a
    /// subshell only.
    fn sh_wait(&self) -> String {
        format!(
            "n=0; while [ -d {dir} ] && [ ! -e {stop} ]; do if [ $n -ge {max} ]; then \
             echo deadline >>{ended}; exit 124; fi; sleep 0.05; n=$((n+1)); done; \
             if [ -e {stop} ]; then how=stopped; else how=gone; fi; \
             {{ echo $how >>{ended}; }} 2>/dev/null; exit 0",
            dir = quoted_path(&self.dir),
            stop = quoted_path(&self.stop_path()),
            ended = quoted_path(&self.ended_path()),
            max = self.deadline_secs * 20,
        )
    }

    /// Shell text that records `what` (`started`, `ready`) in the record.
    fn sh_note(&self, what: &str) -> String {
        format!("echo {what} >>{}", quoted_path(&self.ended_path()))
    }

    /// The shell command line of [`WRITER`]: a descendant that writes the
    /// value on standard output until its output is closed, it is asked
    /// to stop, or its deadline.
    fn sh_writer(&self) -> String {
        format!(
            "{} -c {} {} {} {}",
            quoted_path(&python3()),
            quoted(WRITER),
            quoted_path(&self.stop_path()),
            quoted_path(&self.ended_path()),
            self.deadline_secs
        )
    }

    /// The record's lines so far.
    fn record(&self) -> Vec<String> {
        record_at(&self.ended_path())
    }

    /// [`ended_within`] this lifetime's record.
    fn ended_within(&self, n: usize, limit: Duration) -> Option<Vec<String>> {
        ended_within(&self.ended_path(), n, limit)
    }
}

/// The lines of the record at `path` so far.
fn record_at(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// Waits up to `limit` until the record at `path` holds `n` lines that
/// say how a fixture ended (not `started` or `ready`), and returns the
/// record; `None` if it does not by then.
fn ended_within(path: &Path, n: usize, limit: Duration) -> Option<Vec<String>> {
    let end = Instant::now() + limit;
    loop {
        let lines = record_at(path);
        let ends = lines
            .iter()
            .filter(|l| !matches!(l.as_str(), "started" | "ready"))
            .count();
        if ends >= n {
            return Some(lines);
        }
        if Instant::now() >= end {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

impl Drop for Lifetime {
    fn drop(&mut self) {
        self.stop();
    }
}

/// `s` as one shell word.
fn quoted(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// `p` as one shell word.
fn quoted_path(p: &Path) -> String {
    quoted(p.to_str().unwrap())
}

/// A descendant fixture, run by `python3 -c WRITER <stop> <ended> <secs>`:
/// writes `$OPENAI_API_KEY` and a newline on standard output for ever. It
/// ends when its output is closed (it records `pipe_closed`: Python
/// ignores SIGPIPE, so the write fails with EPIPE), when it is asked to
/// stop or the stop request's directory is gone (`stopped`, `gone`,
/// checked after every 256 writes), or at its deadline (`deadline`):
/// SIGALRM, whose handler runs even while a write is blocked on a full
/// pipe, where it could never see the stop request. A record in a
/// directory that is gone is not written. It inherits an ignored SIGTERM
/// from a shell that ignores it.
const WRITER: &str = r#"import os, signal, sys
stop, ended = sys.argv[1], sys.argv[2]
life = os.path.dirname(stop)
def record(how):
    try:
        with open(ended, 'a') as f:
            f.write(how + '\n')
    except OSError:
        pass
def deadline(*_):
    record('deadline')
    os._exit(124)
signal.signal(signal.SIGALRM, deadline)
signal.alarm(int(sys.argv[3]))
line = (os.environ['OPENAI_API_KEY'] + '\n').encode()
n = 0
try:
    while True:
        os.write(1, line)
        n += 1
        if n % 256 == 0 and (os.path.exists(stop) or not os.path.isdir(life)):
            break
    record('stopped' if os.path.exists(stop) else 'gone')
except BrokenPipeError:
    record('pipe_closed')
"#;

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
                // The `sigterm` tail waits for the signal, or for this.
                let life = Lifetime::new(&home, "emitter");
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
                    "--stop".into(),
                    life.stop_path().into(),
                    "--ended".into(),
                    life.ended_path().into(),
                    "--deadline".into(),
                    life.deadline_secs.to_string().into(),
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

/// The child reports its group and pid, says `ready`, and waits (until
/// `life` asks it to stop); on SIGINT it prints a value and exits 130.
fn traps_int(life: &Lifetime) -> String {
    format!(
        "trap 'printf \"%s\\n\" \"$OPENAI_API_KEY\"; echo got-int; exit 130' INT\n\
         echo \"pgid=$(ps -o pgid= -p $$ | tr -d ' ') pid=$$ ppid=$PPID\"\n\
         echo ready\n\
         {}",
        life.sh_wait()
    )
}

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
    let life = Lifetime::new(&home, "signals");
    let p = Proc::spawn(detached(&home, &setup, &os(&sh(&traps_int(&life)))));
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
        &os(&sh(&format!("echo ready; {}", life.sh_wait()))),
    ));
    assert!(p.wait_for(0, b"ready\n", Duration::from_secs(60)));
    envcloak_sys::signal_process(p.pid(), libc::SIGTERM).unwrap();
    let (status, _, err) = p.finish(Duration::from_secs(60));
    assert_eq!(status.code(), Some(128 + libc::SIGTERM), "{}", lossy(&err));

    // SIGHUP and SIGQUIT are passed on the same way (review T12-1).
    for (sig, name) in [(libc::SIGHUP, "HUP"), (libc::SIGQUIT, "QUIT")] {
        let p = Proc::spawn(detached(&home, &setup, &os(&sh(&traps(name, sig, &life)))));
        assert!(p.wait_for(0, b"ready\n", Duration::from_secs(60)));
        envcloak_sys::signal_process(p.pid(), sig).unwrap();
        let (status, out, err) = p.finish(Duration::from_secs(60));
        assert_eq!(status.code(), Some(128 + sig), "{name}: {}", lossy(&err));
        let want = format!("[envcloak:openai_api_key/t]\ngot-{name}\n");
        assert!(contains(&out, want.as_bytes()), "{name}: {}", lossy(&out));
        assert_no_canary(&out, &cs);
        assert_no_canary(&err, &cs);
    }
    home.assert_clean(&cs);
}

/// A child that traps `name` (signal `sig`): it reports its pid, says
/// `ready` and waits (until `life` asks it to stop); on the signal it
/// prints the value, says `got-<name>` and exits 128 plus the signal's
/// number. `then` runs after `ready`, before the wait.
fn traps_then(name: &str, sig: i32, then: &str, life: &Lifetime) -> String {
    format!(
        "trap 'printf \"%s\\n\" \"$OPENAI_API_KEY\"; echo got-{name}; exit {code}' {name}\n\
         echo \"pid=$$\"\n\
         echo ready\n\
         {then}\n\
         {wait}",
        code = 128 + sig,
        wait = life.sh_wait()
    )
}

/// [`traps_then`], waiting as soon as it is ready.
fn traps(name: &str, sig: i32, life: &Lifetime) -> String {
    traps_then(name, sig, ":", life)
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
    let life = Lifetime::new(&home, "ctrl-c");
    let (code, shown) = on_pty(&home, "ctrl-c", &setup, &os(&sh(&traps_int(&life))));
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
    let life = Lifetime::new(&home, "sigterm");
    let script = format!(
        "trap 'printf \"%s\\n\" \"$STRIPE_SECRET_KEY\"; echo got-term; exit 143' TERM\n\
         echo ready\n\
         {}",
        life.sh_wait()
    );
    let (code, shown) = on_pty(&home, "sigterm", &setup, &os(&sh(&script)));
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

/// Review T12-1: on a terminal, a SIGINT or SIGQUIT that a process sends
/// the runner by pid (not the terminal's Ctrl-C or Ctrl-\, which reach
/// the child themselves) is passed on to the child: its trap runs, its
/// output redacted, and the runner exits with its code. Sent by the
/// command itself, in the runner's session, on both systems. Sent by the
/// pty driver, in another session: passed on on Linux, whose `si_code`
/// tells `kill` from the terminal; on macOS, which reports both alike and
/// then takes the terminal's side, left to the child, which never gets it
/// (docs/RUN.md), and the driver gives up, killing the terminal's group
/// with the child in it: the whole tree is gone.
fn on_a_terminal_sigint_and_sigquit_from_a_process_reach_the_child() {
    let seed = fresh_seed();
    let cs = all_canaries(seed);
    let home = TestHome::new();
    let setup = Setup {
        seed,
        idle_ms: None,
        values: &["OPENAI_API_KEY:OPENAI_API_KEY"],
        files: &[],
    };
    let life = Lifetime::new(&home, "from-a-process");
    for (sig, name, send) in [
        (libc::SIGINT, "INT", "sigint"),
        (libc::SIGQUIT, "QUIT", "sigquit"),
    ] {
        let want = format!("got-{name}");
        // The command signals the runner, its parent.
        let own = traps_then(name, sig, &format!("kill -{name} $PPID"), &life);
        let p = on_pty_within(&home, "none", (2, 30), &setup, &os(&sh(&own)));
        assert_eq!(
            p.end,
            PtyEnd::Exit(128 + sig),
            "{name}: {}",
            lossy(&p.shown)
        );
        assert!(contains(&p.shown, want.as_bytes()), "{}", lossy(&p.shown));
        assert!(
            contains(&p.shown, b"[envcloak:openai_api_key/t]"),
            "{}",
            lossy(&p.shown)
        );
        assert_no_canary(&p.shown, &cs);

        // The driver, in another session, signals the runner.
        let traps = traps(name, sig, &life);
        if cfg!(target_os = "linux") {
            let p = on_pty_within(&home, send, (2, 30), &setup, &os(&sh(&traps)));
            assert_eq!(
                p.end,
                PtyEnd::Exit(128 + sig),
                "{name}: {}",
                lossy(&p.shown)
            );
            assert!(contains(&p.shown, want.as_bytes()), "{}", lossy(&p.shown));
            assert_no_canary(&p.shown, &cs);
        } else {
            let p = on_pty_within(&home, send, (1, 2), &setup, &os(&sh(&traps)));
            assert_eq!(
                p.end,
                PtyEnd::NoExit { gone: true },
                "{name}: {}",
                lossy(&p.shown)
            );
            assert!(!contains(&p.shown, want.as_bytes()), "{}", lossy(&p.shown));
            assert_no_canary(&p.shown, &cs);
        }
    }
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
/// it. It is timed from a marker the child prints just before it, in the
/// same write, followed by more than any value's longest encoding, so the
/// redactor releases the marker at once and holds the prompt until the
/// idle flush: the prompt shows within 400 ms of it, which a longer idle
/// flush than SPEC's 40 ms fails (review T12-4). The first bytes of a
/// value, written without a newline, are held while the pipe is quiet,
/// and released as they were once what follows shows they are not the
/// value.
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
    let script = r#"printf 'mark%8192sPassword: ' ''
read answer
printf 'got %s\n' "$answer"
printf '%.12s' "$OPENAI_API_KEY"
read more
printf '!\n'"#;
    let mut p = Proc::spawn(detached(&home, &setup, &os(&sh(script))));
    assert!(p.wait_for(0, b"mark", Duration::from_secs(60)));
    let t0 = Instant::now();
    assert!(
        p.wait_for(0, b"Password: ", Duration::from_secs(10)),
        "the prompt did not show while the child waited"
    );
    let took = t0.elapsed();
    println!("prompt: shown {took:?} after the marker before it");
    assert!(took < Duration::from_millis(400), "{took:?}");
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
        let mut p = Proc::bare(child);
        let mut err_pipe = p.child.stderr.take().unwrap();
        let reader = std::thread::spawn(move || {
            let mut e = Vec::new();
            err_pipe.read_to_end(&mut e).unwrap();
            e
        });
        let status = {
            let end = Instant::now() + Duration::from_secs(60);
            loop {
                if let Some(s) = p.try_wait() {
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
    // Owned, so a failure below kills and reaps the runner.
    let mut p = Proc::bare(child);
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
    let end = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = p.try_wait() {
            break status;
        }
        assert!(Instant::now() < end, "the runner did not exit");
        std::thread::sleep(Duration::from_millis(10));
    };
    println!(
        "backpressure: {total} bytes read in {:?}",
        started.elapsed()
    );
    assert!(status.success(), "{status:?}");
    assert_eq!(total, CHUNK * CHUNKS);
}

/// A descendant that keeps the pipes open after the child exits: its
/// output in the first 2 seconds is still read and redacted, then the
/// pipes are closed and the runner returns; what it writes later is lost
/// (its next write, at 4 seconds, kills it with SIGPIPE; should the pipes
/// still be open, it waits for its lifetime's stop request, which comes
/// as the test ends).
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
    let life = Lifetime::new(&home, "late-writer");
    let script = format!(
        "printf 'first %s\\n' \"$OPENAI_API_KEY\"\n\
         ( sleep 0.5; printf 'late-ok %s\\n' \"$STRIPE_SECRET_KEY\"; sleep 3.5; echo too-late; {} ) &\n\
         exit 0",
        life.sh_wait()
    );
    let started = Instant::now();
    let (status, out, err) =
        Proc::spawn(detached(&home, &setup, &os(&sh(&script)))).finish(Duration::from_secs(30));
    let took = started.elapsed();
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

/// The child ignores SIGTERM (so does all it starts), starts a descendant
/// that prints the value for ever ([`WRITER`], with `life`), reports its
/// own pid, lets the output fill for a second, says `exiting` and exits 0.
fn leaves_a_writer_script(life: &Lifetime) -> String {
    format!(
        "trap '' TERM\n\
         {} &\n\
         echo \"child=$$\" >&2\n\
         echo pids >&2\n\
         sleep 1\n\
         echo exiting >&2\n\
         exit 0",
        life.sh_writer()
    )
}

/// What [`leaves_a_writer`] started: the runner, its standard output when
/// it is left unread, the descendant's lifetime (which says how it ended),
/// the child's pid and start time, and the moment the child said it was
/// exiting.
struct LeftAWriter {
    p: Proc,
    stdout: Option<ChildStdout>,
    writer: Lifetime,
    child: (i32, Option<StartTime>),
    exiting: Instant,
}

/// The runner with [`leaves_a_writer_script`], its standard output read as
/// it comes (`drained`) or never, started by `launcher` ([`DETACH`] or
/// [`DETACH_MASKED`]).
fn leaves_a_writer(
    launcher: &str,
    home: &TestHome,
    setup: &Setup<'_>,
    drained: bool,
) -> LeftAWriter {
    let writer = Lifetime::new(home, &format!("writer-{drained}"));
    let script = leaves_a_writer_script(&writer);
    let mut cmd = detached_by(launcher, home, setup, &os(&sh(&script)));
    cmd.stdin(Stdio::null());
    let (p, stdout) = if drained {
        (Proc::spawn(cmd), None)
    } else {
        let (p, stdout) = Proc::spawn_holding_stdout(cmd);
        (p, Some(stdout))
    };
    assert!(p.wait_for(1, b"pids\n", Duration::from_secs(60)));
    // The child sleeps: its start time is its own.
    let child = field(&p.captured(1), "child");
    let child = (child, envcloak_sys::process_start_time(child).ok());
    assert!(p.wait_for(1, b"exiting\n", Duration::from_secs(60)));
    LeftAWriter {
        p,
        stdout,
        writer,
        child,
        exiting: Instant::now(),
    }
}

/// Whether `writer`'s descendant saw its output closed within 10 seconds:
/// its next write failed (review F-62: it says so itself, and is never
/// signalled by pid).
fn writer_saw_its_pipe_closed(writer: &Lifetime) -> bool {
    writer.ended_within(1, Duration::from_secs(10)) == Some(vec!["pipe_closed".to_owned()])
}

/// Waits up to `limit` until process `pid`, which started at `started`,
/// has been reaped: no process has its pid (a zombie still has it), or a
/// process started at another time does.
fn reaped_within((pid, started): (i32, Option<StartTime>), limit: Duration) -> bool {
    let end = Instant::now() + limit;
    loop {
        let reaped = match envcloak_sys::signal_process(pid, 0) {
            Err(_) => true,
            Ok(()) => matches!(envcloak_sys::process_start_time(pid), Ok(t) if Some(t) != started),
        };
        if reaped {
            return true;
        }
        if Instant::now() >= end {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Review F-49: the child exits while a descendant keeps writing to the
/// pipes, and nobody reads the runner's standard output, so the runner is
/// stuck writing what it released when the cutoff passes. It gives the
/// write up, closes the pipes (the descendant's next write fails), and
/// returns the child's 0 within the cutoff plus a margin, as
/// it does beside the control, whose output is read.
fn a_stalled_reader_does_not_hold_a_descendants_pipe_past_the_cutoff() {
    stalled_reader_given_up(DETACH, &[true, false]);
}

/// Review R-8: the same, unread, with the runner started with SIGURG
/// (and the signals it catches) blocked: the stuck write is given up at
/// the cutoff all the same.
fn a_stalled_reader_is_given_up_with_the_signals_blocked() {
    stalled_reader_given_up(DETACH_MASKED, &[false]);
}

/// The two tests above: the runner started by `launcher`, its output read
/// or not as each of `drains` says.
fn stalled_reader_given_up(launcher: &str, drains: &[bool]) {
    let seed = fresh_seed();
    let cs = all_canaries(seed);
    let home = TestHome::new();
    let setup = Setup {
        seed,
        idle_ms: None,
        values: &["OPENAI_API_KEY:OPENAI_API_KEY"],
        files: &[],
    };
    for &drained in drains {
        let LeftAWriter {
            p,
            stdout,
            writer,
            exiting,
            ..
        } = leaves_a_writer(launcher, &home, &setup, drained);
        let (status, out, err) = p.finish(Duration::from_secs(30));
        let took = exiting.elapsed();
        println!("stalled reader ({drained}): the runner returned {took:?} after the exit");
        assert_eq!(status.code(), Some(0), "{drained}: {}", lossy(&err));
        assert!(took >= Duration::from_millis(1500), "{drained}: {took:?}");
        assert!(took < Duration::from_millis(3500), "{drained}: {took:?}");
        assert!(
            writer_saw_its_pipe_closed(&writer),
            "{drained}: the descendant's pipe was not closed: {:?}",
            writer.record()
        );
        let out = match stdout {
            Some(mut unread) => {
                let mut held = Vec::new();
                unread.read_to_end(&mut held).unwrap();
                held
            }
            None => out,
        };
        assert!(
            contains(&out, b"[envcloak:openai_api_key/t]\n"),
            "{drained}: {} bytes",
            out.len()
        );
        assert_no_canary(&out, &cs);
        assert_no_canary(&err, &cs);
    }
    home.assert_clean(&cs);
}

/// Review T12-2: after the child exits, with a descendant writing and
/// nobody reading the runner's standard output, SIGTERM to the runner
/// stops the run at once: it exits 143 well before the cutoff would have
/// ended it (with the child's 0), and the descendant's pipes are closed.
/// One SIGTERM is sent, once the runner has reaped the child: the runner
/// marks the exit before it reaps, so the signal is caught after the mark
/// (an earlier one would be passed on to the child's group, and a later
/// one, repeated, could land after the run returned and the default
/// action was back).
fn a_signal_after_the_exit_stops_a_stalled_run() {
    signal_stops_a_stalled_run(DETACH);
}

/// Review R-8: the same with the runner started with SIGTERM (and SIGURG)
/// blocked: the SIGTERM is caught and stops the run all the same, where a
/// runner that left it blocked would run on to the cutoff and exit 0.
fn a_signal_after_the_exit_stops_a_stalled_run_with_the_signals_blocked() {
    signal_stops_a_stalled_run(DETACH_MASKED);
}

/// The two tests above, the runner started by `launcher`.
fn signal_stops_a_stalled_run(launcher: &str) {
    let seed = fresh_seed();
    let cs = all_canaries(seed);
    let home = TestHome::new();
    let setup = Setup {
        seed,
        idle_ms: None,
        values: &["OPENAI_API_KEY:OPENAI_API_KEY"],
        files: &[],
    };
    let LeftAWriter {
        p,
        stdout,
        writer,
        child,
        exiting,
    } = leaves_a_writer(launcher, &home, &setup, false);
    assert!(
        reaped_within(child, Duration::from_secs(10)),
        "the runner did not reap its child"
    );
    envcloak_sys::signal_process(p.pid(), libc::SIGTERM).unwrap();
    let (status, _, err) = p.finish(Duration::from_secs(20));
    let took = exiting.elapsed();
    println!("stopped: the runner exited {took:?} after the child");
    assert_eq!(status.code(), Some(128 + libc::SIGTERM), "{status:?}");
    assert!(took < Duration::from_millis(1500), "{took:?}");
    assert!(
        writer_saw_its_pipe_closed(&writer),
        "the descendant's pipe was not closed: {:?}",
        writer.record()
    );
    let mut held = Vec::new();
    stdout.unwrap().read_to_end(&mut held).unwrap();
    assert_no_canary(&held, &cs);
    assert_no_canary(&err, &cs);
    home.assert_clean(&cs);
}

// ---------------------------------------------------------------------------
// The harness itself (review T12-5): a failed test leaves nothing running
// and never waits for ever; and (review F-62) its cleanup signals only the
// processes it owns, while the fixtures it does not own end by themselves.

/// A child that says it started, reports its pid, says `ready`, and then
/// ignores every signal a runner passes on, so only SIGKILL or `life`
/// ends it.
fn stubborn(life: &Lifetime) -> String {
    format!(
        "trap '' INT TERM HUP\n\
         {started}\n\
         echo \"pid=$$\"\n\
         echo ready\n\
         {wait}",
        started = life.sh_note("started"),
        wait = life.sh_wait()
    )
}

/// The setup the harness's own tests give the runner.
fn harness_setup(seed: u64) -> Setup<'static> {
    Setup {
        seed,
        idle_ms: None,
        values: &["OPENAI_API_KEY:OPENAI_API_KEY"],
        files: &[],
    }
}

/// A test that fails with a runner running drops its `Proc`, which kills
/// and reaps the runner, the one process it owns. Without a terminal the
/// runner's child leads a group of its own and ignores the signals a
/// runner passes on; the harness does not look for it or signal it
/// (review F-62), and it runs on until its lifetime asks it to stop, as
/// the test ends, and then says it stopped.
fn harness_a_dropped_runner_is_reaped_and_its_child_ends_when_asked() {
    let home = TestHome::new();
    let life = Lifetime::new(&home, "stubborn");
    let p = Proc::spawn(detached(
        &home,
        &harness_setup(fresh_seed()),
        &os(&sh(&stubborn(&life))),
    ));
    assert!(p.wait_for(0, b"ready\n", Duration::from_secs(60)));
    let runner = (p.pid(), envcloak_sys::process_start_time(p.pid()).ok());
    drop(p);
    assert!(
        reaped_within(runner, Duration::ZERO),
        "the dropped runner was not reaped"
    );
    assert_eq!(life.record(), ["started"], "the child did not run on");
    life.stop();
    assert_eq!(
        life.ended_within(1, Duration::from_secs(10)),
        Some(vec!["started".to_owned(), "stopped".to_owned()]),
        "the runner's child did not end when asked"
    );
}

/// A runner on a terminal that never exits (its child ignores the SIGTERM
/// passed on): the pty driver gives up after its patience, kills the
/// terminal's process group, which holds the runner and its child, and
/// says `NOEXIT`, instead of waiting for ever; and every process of the
/// tree is gone, as the lifeline says (see [`ON_PTY`]).
fn harness_a_runner_that_never_exits_on_a_terminal_is_killed_with_its_session() {
    let home = TestHome::new();
    let life = Lifetime::new(&home, "stubborn");
    let started = Instant::now();
    let p = on_pty_within(
        &home,
        "sigterm",
        (1, 2),
        &harness_setup(fresh_seed()),
        &os(&sh(&stubborn(&life))),
    );
    assert_eq!(p.end, PtyEnd::NoExit { gone: true }, "{}", lossy(&p.shown));
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "{:?}",
        started.elapsed()
    );
    // Killed with the group: it never got to its stop request.
    assert_eq!(life.record(), ["started"]);
}

/// The pty driver's `gone` rests on the lifeline, not on the kill: a
/// process of the tree in a process group of its own survives the kill
/// of the terminal's group, keeps the lifeline, and the driver says
/// `left`. The survivor ends when its lifetime asks it to.
fn harness_the_pty_driver_says_when_a_process_outlives_the_kill() {
    let home = TestHome::new();
    let life = Lifetime::new(&home, "survivor");
    let survivor = format!(
        "{} -c {} {} &",
        quoted_path(&python3()),
        quoted(
            "import os, sys\nos.setpgid(0, 0)\nos.execv('/bin/sh', ['/bin/sh', '-c', sys.argv[1]])\n"
        ),
        quoted(&life.sh_wait())
    );
    let script = format!("trap '' TERM\n{survivor}\necho ready\nexec sleep 30");
    let p = on_pty_within(
        &home,
        "sigterm",
        (1, 2),
        &harness_setup(fresh_seed()),
        &os(&sh(&script)),
    );
    assert_eq!(p.end, PtyEnd::NoExit { gone: false }, "{}", lossy(&p.shown));
    life.stop();
    assert_eq!(
        life.ended_within(1, Duration::from_secs(10)),
        Some(vec!["stopped".to_owned()]),
        "the survivor did not end when asked"
    );
}

/// A command with no input or output.
fn quiet(program: &str, args: &[&str]) -> Command {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd
}

/// Review F-62: `finish` reaps the child, so its pid can be handed to
/// another process at once. Neither the drop at the end of `finish` nor
/// anything else kills anything then: the model records every kill.
fn harness_cleanup_after_a_successful_finish_signals_nothing() {
    let model = Arc::new(Model::default());
    let p = Proc::spawn_on(quiet("/bin/sh", &["-c", "exit 0"]), model.clone());
    let (status, _, _) = p.finish(Duration::from_secs(60));
    assert!(status.success(), "{status:?}");
    assert!(
        model.killed().is_empty(),
        "cleanup ran after the child was reaped"
    );
}

/// Review F-62: a process still running is killed once, however often
/// cleanup is asked for (explicitly twice and then by its drop, or by a
/// missed deadline in `finish` and then by the drop as the panic
/// unwinds), and cleanup kills that process only: it never finds others
/// to kill, so a pid reused between two steps of a cleanup is never one
/// of its targets.
fn harness_cleanup_kills_only_its_own_process_once() {
    let model = Arc::new(Model::default());
    let mut p = Proc::spawn_on(quiet("/bin/sleep", &["60"]), model.clone());
    let pid = p.pid();
    p.kill_owned();
    p.kill_owned();
    drop(p);
    assert_eq!(model.killed(), [pid], "cleanup ran again after it reaped");

    let model = Arc::new(Model::default());
    let p = Proc::spawn_on(quiet("/bin/sleep", &["60"]), model.clone());
    let pid = p.pid();
    let t0 = Instant::now();
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        p.finish(Duration::from_millis(300))
    }));
    assert!(r.is_err(), "a process running past its limit passed");
    assert!(t0.elapsed() < Duration::from_secs(30), "{:?}", t0.elapsed());
    assert_eq!(
        model.killed(),
        [pid],
        "a missed deadline killed other than once"
    );
}

/// Review F-62: a test that fails before its fixture is ready, or after,
/// leaves nothing running: the unwinding kills and reaps the runner (its
/// `Proc`), asks the fixture to stop (its [`Lifetime`]) and removes the
/// test's home, as every test here declares them, and the fixture, which
/// the harness never signals, ends at once, saying it was asked to stop
/// or found its lifetime gone with the home. The home is made and dropped
/// inside the failing test, as in the real ones; only the record is kept
/// outside it, to be read afterwards. The fixture is ready once it has
/// read a line from its standard input, which the test writes, or which
/// ends when the runner's `Proc` goes.
fn harness_a_fixture_ends_when_its_test_fails_before_or_after_readiness() {
    let kept = TestHome::new();
    for ready_first in [false, true] {
        let record = kept.root().join(format!("ended-{ready_first}"));
        let setup = harness_setup(fresh_seed());
        let t0 = Instant::now();
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let home = TestHome::new();
            let life = Lifetime::recording_at(&home, "fixture", 20, record.clone());
            let script = format!(
                "trap '' INT TERM HUP\n{}\nread go\n{}\n{}",
                life.sh_note("started"),
                life.sh_note("ready"),
                life.sh_wait()
            );
            let mut p = Proc::spawn(detached(&home, &setup, &os(&sh(&script))));
            let want: &[&str] = if ready_first {
                p.write(b"go\n");
                &["started", "ready"]
            } else {
                &["started"]
            };
            let end = Instant::now() + Duration::from_secs(60);
            while life.record() != want {
                assert!(Instant::now() < end, "{:?}", life.record());
                std::thread::sleep(Duration::from_millis(20));
            }
            panic!("the test fails here, with its fixture running");
        }));
        assert!(failed.is_err());
        let lines = ended_within(&record, 1, Duration::from_secs(30));
        let ends = ["stopped", "gone"];
        assert!(
            lines.as_ref().is_some_and(|l| l.len() == 3
                && l[..2] == ["started", "ready"]
                && ends.contains(&l[2].as_str())),
            "ready first: {ready_first}: {lines:?}"
        );
        assert!(t0.elapsed() < Duration::from_secs(60), "{:?}", t0.elapsed());
    }
}

/// Review F-62: the directory a fixture's stop request would be in being
/// gone is a stop request too, for each kind of fixture: the shell's wait
/// ([`Lifetime::sh_wait`]), the writer ([`WRITER`]) and the gate 8
/// emitter's wait for SIGTERM. A failing test asks its fixtures to stop
/// and removes its home microseconds later, request and all, so a fixture
/// that looked only for the request would run on to its deadline. Here
/// the request is never made (the lifetime is not dropped): once the
/// fixture is running, its home is removed, and it ends at once, says
/// `gone` in a record kept outside the home, and exits 0. Each is a child
/// of the test itself, so a fixture that does not end is killed when its
/// `finish` gives up.
fn harness_a_fixture_whose_lifetime_is_gone_ends() {
    let kept = TestHome::new();
    for kind in ["wait", "writer", "emitter"] {
        let record = kept.root().join(format!("ended-{kind}"));
        let home = TestHome::new();
        let life = Lifetime::recording_at(&home, kind, 20, record.clone());
        let (cmd, ready): (Command, &[u8]) = match kind {
            "wait" => {
                let script = format!("echo ready; {}", life.sh_wait());
                let mut cmd = quiet("/bin/sh", &["-c", &script]);
                home.apply(&mut cmd).stdout(Stdio::piped());
                (cmd, b"ready\n")
            }
            "writer" => (writer_command(&home, &life, "x"), b"x\nx\n"),
            _ => {
                let mut cmd = Command::new(python3());
                home.apply(&mut cmd)
                    .arg(emitter())
                    .args(["--names", "FIXTURE_LINE", "--tail", "sigterm"])
                    .args(["--whole-only", "--pause-ms", "0", "--stop"])
                    .arg(life.stop_path())
                    .arg("--ended")
                    .arg(life.ended_path())
                    .args(["--deadline", &life.deadline_secs.to_string()])
                    .env("FIXTURE_LINE", "a line of the harness, not a value")
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                (cmd, b"READY\n")
            }
        };
        let stream = usize::from(kind == "emitter");
        let p = Proc::spawn(cmd);
        assert!(
            p.wait_for(stream, ready, Duration::from_secs(60)),
            "{kind} did not start"
        );
        std::mem::forget(life);
        drop(home);
        let t0 = Instant::now();
        let (status, _, err) = p.finish(Duration::from_secs(60));
        assert_eq!(
            (record_at(&record), status.code()),
            (vec!["gone".to_owned()], Some(0)),
            "{kind}: {}",
            lossy(&err[err.len().saturating_sub(300)..])
        );
        assert!(
            t0.elapsed() < Duration::from_secs(10),
            "{kind}: {:?}",
            t0.elapsed()
        );
    }
}

/// [`WRITER`] as a direct child of the harness, writing `line` (not a
/// value), with its standard output piped.
fn writer_command(home: &TestHome, life: &Lifetime, line: &str) -> Command {
    let mut cmd = Command::new("/bin/sh");
    home.apply(&mut cmd)
        .args(["-c", &format!("exec {}", life.sh_writer())])
        .env("OPENAI_API_KEY", line)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

/// Review F-62: a process that exits while something it started still
/// holds its output (a subshell waiting for its lifetime): `finish` gives
/// the output up at its limit and fails, rather than wait for the streams
/// to end, and the survivor, asked to stop as the test fails, says it
/// stopped.
fn harness_finish_gives_up_on_output_a_survivor_holds() {
    let home = TestHome::new();
    let life = Lifetime::new(&home, "survivor");
    let mut cmd = Command::new("/bin/sh");
    home.apply(&mut cmd)
        .args(["-c", &format!("( {} ) & exit 0", life.sh_wait())])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let t0 = Instant::now();
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Proc::spawn(cmd).finish(Duration::from_secs(2))
    }));
    assert!(r.is_err(), "finish returned with its output still open");
    assert!(t0.elapsed() < Duration::from_secs(30), "{:?}", t0.elapsed());
    life.stop();
    assert_eq!(
        life.ended_within(1, Duration::from_secs(10)),
        Some(vec!["stopped".to_owned()])
    );
}

/// Review F-62: a writer blocked on a full pipe nobody reads cannot see
/// its stop request; its deadline (SIGALRM) ends it all the same. Its
/// first write, longer than a pipe holds (64 KiB on Linux and macOS),
/// blocks before it ever looks for the request. The line stays under
/// Linux's 128 KiB limit on one environment string.
fn harness_a_writer_blocked_on_a_full_pipe_ends_at_its_deadline() {
    let home = TestHome::new();
    let life = Lifetime::with_deadline(&home, "blocked", 2);
    let line = "x".repeat(100_000);
    let (p, unread) = Proc::spawn_holding_stdout(writer_command(&home, &life, &line));
    life.stop();
    assert_eq!(
        life.ended_within(1, Duration::from_secs(30)),
        Some(vec!["deadline".to_owned()])
    );
    let (status, _, _) = p.finish(Duration::from_secs(30));
    assert_eq!(status.code(), Some(124));
    drop(unread);
}

/// Review F-62: a writer whose reader goes away sees its pipe closed and
/// ends.
fn harness_a_writer_whose_reader_is_lost_ends() {
    let home = TestHome::new();
    let life = Lifetime::new(&home, "lost-reader");
    let (p, unread) =
        Proc::spawn_holding_stdout(writer_command(&home, &life, "a line nobody reads"));
    drop(unread);
    assert_eq!(
        life.ended_within(1, Duration::from_secs(10)),
        Some(vec!["pipe_closed".to_owned()])
    );
    let (status, _, _) = p.finish(Duration::from_secs(30));
    assert!(status.success(), "{status:?}");
}

/// Review F-62: a fixture whose test died before it could ask it to stop
/// (its `Lifetime` never dropped) ends at its deadline and says so.
fn harness_a_fixture_whose_test_died_ends_at_its_deadline() {
    let home = TestHome::new();
    let life = Lifetime::with_deadline(&home, "orphaned", 1);
    let record = life.ended_path();
    let script = life.sh_wait();
    std::mem::forget(life);
    let mut cmd = quiet("/bin/sh", &["-c", &script]);
    home.apply(&mut cmd);
    let (status, _, _) = Proc::spawn(cmd).finish(Duration::from_secs(60));
    assert_eq!(status.code(), Some(124));
    assert_eq!(
        ended_within(&record, 1, Duration::ZERO),
        Some(vec!["deadline".to_owned()])
    );
}
