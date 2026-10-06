//! PTY mode's relay as a real process (`envcloak run --pty`; SPEC §6.1
//! steps 7 and 8, M2 plan task M2-19, decisions D-19, D-34 and D-35):
//! gate 8 through a real pseudo-terminal with the CR LF forms, prompts,
//! canonical and raw input, a password typed with echo off, one SIGINT per
//! Ctrl-C, the window size, the forwarded-signal receipt gate (a direct
//! command and a nested shell's job, per signal), the stop and continue
//! races at barriers, the monitor's death, the command's own `/dev/tty`,
//! the 2-second cutoff, a panic that aborts, an agent-style outer
//! terminal, `pty_unavailable`, and `ps` during a run.
//!
//! This binary has no libtest harness (`harness = false`): it is also the
//! runner. Started as `pty_relay --ec-pty-runner ...`, it does what
//! `envcloak run --pty` does once the daemon has released the values: it
//! generates the canaries from a seed (never passing a value on argv or in
//! its own environment), builds the PTY redactor (`build_pty_redactor`),
//! opens the outer terminal (`OuterTerminal::open`) and runs the command
//! through `envcloak_exec::run` with `RunSpec::pty`, exiting with the
//! command's shell code or 125 and the failure's token.
//!
//! The person's terminal is a pseudo-terminal the test owns. The runner
//! leads a new session on it (a Python launcher calls `setsid` and takes
//! the terminal with `TIOCSCTTY`, then `exec`s the runner), so it is this
//! process's own unreaped child, the only process the test signals; or a
//! job-control shell (`/bin/sh -i`, `set -m`, cleared environment, no rc
//! files) leads it and starts the runner as a job, for the suspension
//! races. Fixtures are Python programs written into each case's directory:
//! a counter of signals, a cat that reads again on `EINTR` (Python retries
//! an interrupted read, PEP 475), a raw-mode reader. Barriers are the
//! runner's own pause points (`ENVCLOAK_TEST_PAUSE`) and what the terminal
//! shows, never a sleep; every fixture that would otherwise run on ends at
//! a stop file or a deadline of its own.
//!
//! Every byte the outer terminal shows is searched for every canary in
//! every encoding the detector knows, and for the CR LF form of the one
//! value holding LF (`ONLCR` writes it so; the kernel is the oracle, as in
//! `crates/envcloak-redact/tests/crlf_kernel.rs`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use envcloak_core::SecretBytes;
use envcloak_core::vault::Slug;
use envcloak_exec::{
    DRAIN_LIMIT, EXIT_READ_LIMIT, ExecError, Label, OUTPUT_LIMIT, OuterTerminal, RunSpec,
    ShortPolicy, build_pty_redactor,
};
use envcloak_policy::EnvName;
use envcloak_sys::pty::open_pty;
use envcloak_sys::{TerminalSettings, WindowSize, set_window_size, wait_any};
use envcloak_testkit::{
    Canary, TestHome, assert_no_canary, by_label, canaries, fresh_seed, labels,
};

#[global_allocator]
static ALLOCATOR: envcloak_sys::WipingAllocator = envcloak_sys::WipingAllocator;

const RUNNER: &str = "--ec-pty-runner";
/// How long a step waits for what it expects before the case fails.
const DEADLINE: Duration = Duration::from_secs(30);
/// The label of the PEM-shaped value, the one holding LF.
const PEM: &str = "PEM_BLOCK";
/// The label of its CR LF form, as a terminal shows it.
const PEM_CRLF: &str = "PEM_BLOCK_CRLF";
/// The outer job-control shell's prompt.
const PROMPT: &str = "EC-OUTER> ";
/// The nested shell's prompt.
const INNER: &str = "EC-INNER> ";
/// Typed into a shell first: bash (macOS's `/bin/sh` is bash 3.2) turns
/// its line editing off, so readline's own signal handling is out of the
/// way (M2-17's `pty_signals.rs`); dash has no `BASH_VERSION`.
const NO_EDITING: &str = "case ${BASH_VERSION-} in ?*) set +o emacs +o vi;; esac; ";

const SIGNALS: [(i32, &str); 4] = [
    (libc::SIGINT, "INT"),
    (libc::SIGQUIT, "QUIT"),
    (libc::SIGTERM, "TERM"),
    (libc::SIGHUP, "HUP"),
];

fn main() {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if args.first().is_some_and(|a| a == RUNNER) {
        std::process::exit(runner(&args[1..]));
    }
    envcloak_sys::testing::libtest::run_cases(
        "pty_relay",
        &[
            (
                "gate8_real_serializers_through_a_pty_are_redacted_crlf_forms_included",
                gate8_real_serializers_through_a_pty_are_redacted_crlf_forms_included,
            ),
            (
                "a_prompt_without_a_newline_shows_and_the_start_of_a_value_waits",
                a_prompt_without_a_newline_shows_and_the_start_of_a_value_waits,
            ),
            (
                "inherited_output_translations_are_cleared_before_redaction",
                inherited_output_translations_are_cleared_before_redaction,
            ),
            (
                "canonical_and_raw_input_reach_the_command",
                canonical_and_raw_input_reach_the_command,
            ),
            (
                "a_command_that_turns_echo_off_reads_a_password_unseen",
                a_command_that_turns_echo_off_reads_a_password_unseen,
            ),
            (
                "each_ctrl_c_is_one_sigint_for_the_command",
                each_ctrl_c_is_one_sigint_for_the_command,
            ),
            (
                "a_resize_reaches_the_command_through_stty_size",
                a_resize_reaches_the_command_through_stty_size,
            ),
            (
                "forwarded_signals_reach_the_command_once_each",
                forwarded_signals_reach_the_command_once_each,
            ),
            (
                "forwarded_signals_reach_a_nested_shells_job_and_not_the_shell",
                forwarded_signals_reach_a_nested_shells_job_and_not_the_shell,
            ),
            (
                "without_the_group_signal_sigterm_and_sighup_are_narrowed_to_the_shell",
                without_the_group_signal_sigterm_and_sighup_are_narrowed_to_the_shell,
            ),
            (
                "a_suspend_typed_during_a_resize_stops_once_and_fg_brings_the_new_size",
                a_suspend_typed_during_a_resize_stops_once_and_fg_brings_the_new_size,
            ),
            (
                "fg_typed_before_the_stop_is_handled_is_discarded_with_the_input",
                fg_typed_before_the_stop_is_handled_is_discarded_with_the_input,
            ),
            (
                "two_suspend_characters_in_one_read_stop_the_command_once",
                two_suspend_characters_in_one_read_stop_the_command_once,
            ),
            (
                "a_sigcont_while_the_output_drains_loses_nothing",
                a_sigcont_while_the_output_drains_loses_nothing,
            ),
            (
                "the_command_is_resumed_only_once_the_outer_terminal_is_raw_again",
                the_command_is_resumed_only_once_the_outer_terminal_is_raw_again,
            ),
            (
                "raw_mode_refused_after_fg_resumes_nothing_and_ends_the_run",
                raw_mode_refused_after_fg_resumes_nothing_and_ends_the_run,
            ),
            (
                "raw_mode_refused_on_sigcont_ends_the_run",
                raw_mode_refused_on_sigcont_ends_the_run,
            ),
            (
                "background_continues_never_save_the_shells_line_editor_settings",
                background_continues_never_save_the_shells_line_editor_settings,
            ),
            (
                "a_stty_change_made_while_stopped_reaches_the_command_and_stays",
                a_stty_change_made_while_stopped_reaches_the_command_and_stays,
            ),
            (
                "a_monitor_that_dies_hangs_the_command_up_and_the_run_fails_monitor_lost",
                a_monitor_that_dies_hangs_the_command_up_and_the_run_fails_monitor_lost,
            ),
            #[cfg(target_os = "linux")]
            (
                "output_written_after_monitor_loss_is_still_redacted",
                output_written_after_monitor_loss_is_still_redacted,
            ),
            (
                "a_monitor_that_dies_after_the_exit_report_keeps_the_commands_status",
                a_monitor_that_dies_after_the_exit_report_keeps_the_commands_status,
            ),
            (
                "the_commands_own_dev_tty_writes_are_redacted",
                the_commands_own_dev_tty_writes_are_redacted,
            ),
            (
                "the_run_ends_when_its_command_does",
                the_run_ends_when_its_command_does,
            ),
            (
                "a_grandchild_holding_the_terminal_is_cut_off_2_s_after_the_exit",
                a_grandchild_holding_the_terminal_is_cut_off_2_s_after_the_exit,
            ),
            (
                "a_slow_reader_gets_everything_a_command_wrote_before_it_exited",
                a_slow_reader_gets_everything_a_command_wrote_before_it_exited,
            ),
            (
                "a_pty_holds_far_less_than_the_relay_reads_after_the_exit",
                a_pty_holds_far_less_than_the_relay_reads_after_the_exit,
            ),
            (
                "a_sigterm_caught_after_the_last_output_still_ends_the_run_with_143",
                a_sigterm_caught_after_the_last_output_still_ends_the_run_with_143,
            ),
            (
                "a_panic_that_aborts_leaves_the_outer_terminal_as_it_was",
                a_panic_that_aborts_leaves_the_outer_terminal_as_it_was,
            ),
            (
                "an_agent_style_outer_pty_with_burst_input_and_polled_reads_sees_no_value",
                an_agent_style_outer_pty_with_burst_input_and_polled_reads_sees_no_value,
            ),
            (
                "without_a_terminal_on_both_sides_pty_mode_is_unavailable",
                without_a_terminal_on_both_sides_pty_mode_is_unavailable,
            ),
            (
                "ps_shows_no_value_in_the_runners_argv_or_environment",
                ps_shows_no_value_in_the_runners_argv_or_environment,
            ),
        ],
    );
}

// ---------------------------------------------------------------------------
// The runner.

/// The story's canaries for `seed`, the PEM-shaped value (its lines ended
/// by LF), and that value's CR LF form, which is what a terminal shows of
/// it (looked for, never injected).
fn all_canaries(seed: u64) -> Vec<Canary> {
    let mut cs = canaries(seed);
    let pem = pem(seed);
    let crlf = crlf(pem.as_bytes());
    cs.push(Canary::new(PEM, pem));
    cs.push(Canary::new(PEM_CRLF, String::from_utf8(crlf).unwrap()));
    cs
}

/// A PEM-shaped block made at run time from `seed`: a header and footer
/// split so no key-shaped literal is in the source, and a base64 body of
/// random bytes in 64-character lines, each ended by LF.
fn pem(seed: u64) -> String {
    use base64::Engine as _;
    let mut state = seed ^ 0x7e57_b10c_0000_0001;
    let bytes: Vec<u8> = (0..144)
        .map(|_| {
            // SplitMix64, one byte per step.
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            u8::try_from((z ^ (z >> 31)) & 0xff).unwrap()
        })
        .collect();
    let body = base64::engine::general_purpose::STANDARD.encode(&bytes);
    let kind = concat!("ENVCLOAK ", "RELAY ", "BLOCK");
    let mut out = format!("-----{} {kind}-----\n", "BEGIN");
    for line in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----{} {kind}-----", "END"));
    out
}

/// Every LF preceded by a CR, as `ONLCR` writes it.
fn crlf(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 8);
    for &b in value {
        if b == b'\n' {
            out.push(b'\r');
        }
        out.push(b);
    }
    out
}

/// The slug a canary is labeled with: `openai_api_key/t`.
fn slug_of(label: &str) -> String {
    format!("{}/t", label.to_ascii_lowercase())
}

/// `--ec-pty-runner --seed S [--idle-ms N] [--value ENV:LABEL]...
/// [--file ENV:PATH]... [--abort] [--no-group-signal] -- <argv...>`:
/// `--abort` ends a panic as a release build does (the hook, then
/// `abort`, no destructor); `--no-group-signal` makes this process's
/// session deliveries act as on a Linux kernel before 6.9.
fn runner(args: &[OsString]) -> i32 {
    envcloak_sys::install_panic_hook("envcloak");
    // An abort leaves no core file in the test's tree.
    let _ = envcloak_sys::disable_core_dumps();
    let mut it = args.iter();
    let (mut seed, mut idle) = (None, None);
    let (mut values, mut files) = (Vec::new(), Vec::new());
    loop {
        let Some(a) = it.next().and_then(|a| a.to_str()) else {
            eprintln!("runner: bad arguments");
            return 2;
        };
        let mut next = || it.next().and_then(|v| v.to_str()).unwrap().to_owned();
        match a {
            "--" => break,
            "--seed" => seed = Some(next().parse::<u64>().unwrap()),
            "--idle-ms" => idle = Some(Duration::from_millis(next().parse().unwrap())),
            "--value" => values.push(next()),
            "--file" => files.push(next()),
            "--abort" => {
                let hook = std::panic::take_hook();
                std::panic::set_hook(Box::new(move |info| {
                    hook(info);
                    std::process::abort();
                }));
            }
            "--no-group-signal" => {
                #[cfg(target_os = "linux")]
                envcloak_sys::testing::force_no_group_signal(true);
            }
            _ => {
                eprintln!("runner: bad arguments");
                return 2;
            }
        }
    }
    let argv: Vec<OsString> = it.cloned().collect();
    let cs = all_canaries(seed.unwrap());
    let mut owned: Vec<(EnvName, Slug, SecretBytes)> = Vec::new();
    for v in &values {
        let (env, label) = v.split_once(':').unwrap();
        owned.push((
            EnvName::new(env).unwrap(),
            Slug::new(&slug_of(label)).unwrap(),
            SecretBytes::copy_from(by_label(&cs, label).value()),
        ));
    }
    for (i, f) in files.iter().enumerate() {
        let (env, path) = f.split_once(':').unwrap();
        owned.push((
            EnvName::new(env).unwrap(),
            Slug::new(&format!("fixture{i}/t")).unwrap(),
            SecretBytes::from_vec(std::fs::read(path).unwrap()),
        ));
    }
    let built = {
        let labels: Vec<Label<'_>> = owned
            .iter()
            .map(|(_, slug, value)| Label {
                slug,
                value,
                short: ShortPolicy::Refuse,
            })
            .collect();
        build_pty_redactor(&labels)
    };
    let (redactor, _) = match built {
        Ok(b) => b,
        Err(e) => return failed(&e),
    };
    let terminal = match OuterTerminal::open(std::io::stdin().as_fd(), std::io::stdout().as_fd()) {
        Ok(t) => t,
        Err(e) => return failed(&e),
    };
    let injected = owned.into_iter().map(|(n, _, v)| (n, v)).collect();
    let mut spec = RunSpec::pty(argv, injected, redactor, terminal);
    if let Some(idle) = idle {
        spec.idle_flush = idle;
    }
    match envcloak_exec::run(spec) {
        Ok(exit) => i32::from(exit.shell_code()),
        Err(e) => failed(&e),
    }
}

/// Says why the run failed, as `envcloak run` does, and gives its code.
fn failed(e: &ExecError) -> i32 {
    eprintln!("envcloak: {}: {}", e.token(), e.message());
    i32::from(e.exit_code())
}

// ---------------------------------------------------------------------------
// The harness.

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

/// Leads a new session on the terminal on its standard input (`setsid`,
/// then `TIOCSCTTY`), as a terminal emulator starts a shell, and becomes
/// argv[1..] (`exec`: the same process).
const LEAD: &str = "import fcntl, os, sys, termios\n\
os.setsid()\n\
fcntl.ioctl(0, termios.TIOCSCTTY, 0)\n\
os.execv(sys.argv[1], sys.argv[1:])\n";

/// Leads a new session with no controlling terminal (`setsid` only) and
/// becomes argv[1..]: the terminal on its standard streams is then not
/// its session's, so its exit does not hang the terminal up (macOS
/// revokes a session's terminal when its leader exits), and the test can
/// read the terminal's settings after the run.
const DETACH: &str = "import os, sys\nos.setsid()\nos.execv(sys.argv[1], sys.argv[1:])\n";

/// The counting fixture: `counter.py DIR WHO [VAR]`. Appends a line to
/// `DIR/WHO-<SIG>` for each SIGINT, SIGQUIT, SIGTERM and SIGHUP it gets;
/// prints `JOB-READY <pid> <pgid>` (and, with `VAR`, the variable's
/// length), then `GOT [<line>]` for each line it reads (one read of its
/// terminal, which in canonical mode is one line), and exits 0 on `done`
/// or at the end of its input. It never blocks in a read for more than
/// 50 ms: Python runs a signal's handler only between its own steps, so a
/// signal caught while a handler for the one before is still running, and
/// before the read it then goes back to, would otherwise wait for the next
/// key (a SIGINT lost for 30 seconds on macOS CI, run 37297793188).
const COUNTER: &str = r#"import os, select, signal, sys
d, who = sys.argv[1], sys.argv[2]
names = {signal.SIGINT: 'INT', signal.SIGQUIT: 'QUIT', signal.SIGTERM: 'TERM', signal.SIGHUP: 'HUP'}
def got(sig, frame):
    with open(os.path.join(d, '%s-%s' % (who, names[sig])), 'a') as f:
        f.write('x\n')
for s in names:
    signal.signal(s, got)
extra = b''
if len(sys.argv) > 3:
    extra = b' len=%d' % len(os.environb.get(sys.argv[3].encode(), b''))
os.write(1, b'JOB-READY %d %d%s\n' % (os.getpid(), os.getpgrp(), extra))
while True:
    try:
        ready, _, _ = select.select([0], [], [], 0.05)
        if not ready:
            continue
        line = os.read(0, 65536)
    except OSError:
        break
    if not line or line.strip() == b'done':
        break
    os.write(1, b'GOT [' + line.rstrip(b'\r\n') + b']\n')
"#;

/// A cat that reads again when a read is interrupted (`EINTR`): Python
/// retries both calls (PEP 475), writes whole, and leaves SIGTSTP at its
/// default, so the suspend character stops it. Prints `CAT-READY` first.
const RETRY_CAT: &str = r"import os
os.write(1, b'CAT-READY\n')
while True:
    b = os.read(0, 65536)
    if not b:
        break
    while b:
        b = b[os.write(1, b):]
";

/// Raw mode on its terminal (no echo, no line editing, no signal
/// characters), then one line `B<hex>` per byte read until `q`.
const RAW_BYTES: &str = r"import os, termios, tty
saved = termios.tcgetattr(0)
tty.setraw(0)
os.write(1, b'RAW-READY\r\n')
while True:
    b = os.read(0, 1)
    if not b or b == b'q':
        break
    os.write(1, b'B%02x\r\n' % b[0])
termios.tcsetattr(0, termios.TCSAFLUSH, saved)
";

/// Counts SIGINT as `counter.py` does (`<dir>/raw-INT`), puts its terminal
/// in raw mode (no signal characters), prints `RAW-READY`, then one line
/// `B<hex>` per byte read until `q`.
const RAW_COUNTER: &str = r"import os, signal, sys, termios, tty
d = sys.argv[1]
def got(sig, frame):
    with open(os.path.join(d, 'raw-INT'), 'a') as f:
        f.write('x\n')
signal.signal(signal.SIGINT, got)
saved = termios.tcgetattr(0)
tty.setraw(0)
os.write(1, b'RAW-READY\r\n')
while True:
    b = os.read(0, 1)
    if not b or b == b'q':
        break
    os.write(1, b'B%02x\r\n' % b[0])
termios.tcsetattr(0, termios.TCSAFLUSH, saved)
";

/// Prints `JOB-READY`, then `tick <n> <value>` every 20 ms, the value from
/// the variable argv[3]; on SIGHUP appends a line to argv[1]/job-HUP and
/// exits 3; ends by itself at the stop file argv[2] or after 60 s.
const TICKER: &str = r#"import os, signal, sys, time
d, stop, var = sys.argv[1], sys.argv[2], sys.argv[3]
def hup(sig, frame):
    with open(os.path.join(d, 'job-HUP'), 'a') as f:
        f.write('x\n')
    os._exit(3)
signal.signal(signal.SIGHUP, hup)
value = os.environb[var.encode()]
os.write(1, b'JOB-READY\n')
end = time.monotonic() + 60
i = 0
while time.monotonic() < end and not os.path.exists(stop):
    try:
        os.write(1, b'tick %d %s\n' % (i, value))
    except OSError:
        pass
    i += 1
    time.sleep(0.02)
"#;

/// `writer.py RECORD VAR`: numbered lines (every 97th holding the
/// variable's value) written to a non-blocking standard output as fast as
/// it takes them, until a write has waited a second for room (the runner
/// holds all it may for a reader that reads nothing); then the bytes and
/// whole lines written go to RECORD, and it exits 0.
const SLOW_WRITER: &str = r"import fcntl, os, select, sys
record, var = sys.argv[1], sys.argv[2]
value = os.environb[var.encode()]
fl = fcntl.fcntl(1, fcntl.F_GETFL)
fcntl.fcntl(1, fcntl.F_SETFL, fl | os.O_NONBLOCK)
data = b''.join(b'line %06d %s\n' % (i, value if i % 97 == 0 else b'-' * 40) for i in range(20000))
at = 0
while at < len(data):
    try:
        at += os.write(1, data[at:at + 4096])
    except BlockingIOError:
        _, w, _ = select.select([], [1], [], 1.0)
        if not w:
            break
with open(record + '.tmp', 'w') as f:
    f.write('%d %d\n' % (at, data[:at].count(b'\n')))
os.rename(record + '.tmp', record)
";

/// Writes the value of argv[1] three bytes at a time with a pause between
/// pieces, then `ECHO-START`, then copies its input to its output until
/// the end of it.
const SPLIT_THEN_CAT: &str = r"import os, sys, time
value = os.environb[sys.argv[1].encode()]
for i in range(0, len(value), 3):
    os.write(1, value[i:i + 3])
    time.sleep(0.005)
os.write(1, b'\nECHO-START\n')
while True:
    b = os.read(0, 65536)
    if not b:
        break
    while b:
        b = b[os.write(1, b):]
";

/// An agent-style host (Codex `tty: true`, Gemini's `node-pty`): the
/// runner (argv[2..]) on a PTY of Python's own (`pty.fork`), echo off (a
/// program feeding a terminal; the line discipline may drop the echo of a
/// burst it cannot queue, never the command's own writes). Waits for
/// `ECHO-START`, writes argv[1] lines `burst-NNNN` in one write, reads in
/// polled reads of at most 7 bytes, sends EOF once the last line came
/// back, and prints `EXIT <code>` and everything read.
/// Gives up (kills the runner's group, its own unreaped child's) after 60
/// seconds.
const AGENT: &str = r"import os, pty, select, signal, sys, termios, time
n = int(sys.argv[1])
pid, fd = pty.fork()
if pid == 0:
    t = termios.tcgetattr(0)
    t[3] &= ~termios.ECHO
    termios.tcsetattr(0, termios.TCSANOW, t)
    os.execv(sys.argv[2], sys.argv[2:])
out = b''
def read_for(limit):
    global out
    end = time.time() + limit
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.001)
        if r:
            try:
                chunk = os.read(fd, 7)
            except OSError:
                return False
            if not chunk:
                return False
            out += chunk
    return True
deadline = time.time() + 60
while b'ECHO-START' not in out and time.time() < deadline:
    if not read_for(0.05):
        break
os.write(fd, b''.join(b'burst-%04d\n' % i for i in range(n)))
last = b'burst-%04d' % (n - 1)
while out.count(last) < 1 and time.time() < deadline:
    if not read_for(0.05):
        break
os.write(fd, b'\x04')
while time.time() < deadline:
    done, status = os.waitpid(pid, os.WNOHANG)
    if done:
        break
    read_for(0.05)
else:
    os.killpg(pid, signal.SIGKILL)
    done, status = os.waitpid(pid, 0)
read_for(0.2)
sys.stdout.buffer.write(b'EXIT %d\n' % os.waitstatus_to_exitcode(status))
sys.stdout.buffer.write(out)
";

/// A case's directory: the fixtures' files, counters and stop files, under
/// a short private path, and the test home the runner runs in.
struct Case {
    dir: tempfile::TempDir,
    home: TestHome,
    seed: u64,
    cs: Vec<Canary>,
}

impl Case {
    fn new() -> Case {
        let seed = fresh_seed();
        let cs = all_canaries(seed);
        never_shown(&cs);
        Case {
            dir: tempfile::Builder::new()
                .prefix("ecrl")
                .tempdir_in("/tmp")
                .unwrap(),
            home: TestHome::new(),
            seed,
            cs,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Writes a fixture program into the case's directory; returns its
    /// path.
    fn script(&self, name: &str, body: &str) -> PathBuf {
        let p = self.path(name);
        std::fs::write(&p, body).unwrap();
        p
    }

    /// The runner's argv: `values` are `ENV:LABEL`, `flags` the runner's
    /// own options, then the command.
    fn runner_argv(&self, values: &[&str], flags: &[&str], command: &[&OsStr]) -> Vec<OsString> {
        let mut a: Vec<OsString> = vec![
            std::env::current_exe().unwrap().into(),
            RUNNER.into(),
            "--seed".into(),
            self.seed.to_string().into(),
        ];
        for v in values {
            a.extend(["--value".into(), (*v).into()]);
        }
        a.extend(flags.iter().map(OsString::from));
        a.push("--".into());
        a.extend(command.iter().map(|c| c.to_os_string()));
        a
    }

    /// No canary in `bytes`, in any encoding, nor in the test home.
    fn assert_clean(&self, bytes: &[u8]) {
        assert_no_canary(bytes, &self.cs);
        self.home.assert_clean(&self.cs);
    }
}

/// The person's terminal: a pseudo-terminal the test owns, and everything
/// it has shown.
struct Outer {
    master: File,
    slave: OwnedFd,
    seen: Vec<u8>,
}

impl Outer {
    fn new(rows: u16, cols: u16) -> Outer {
        let size = WindowSize {
            rows,
            cols,
            ..WindowSize::default()
        };
        let pty = open_pty(Some(size), None).unwrap();
        Outer {
            master: File::from(pty.master),
            slave: pty.slave,
            seen: Vec::new(),
        }
    }

    /// The terminal's settings now, as the person's shell would find them.
    fn settings(&self) -> TerminalSettings {
        TerminalSettings::read(self.slave.as_fd()).unwrap()
    }

    fn type_bytes(&self, bytes: &[u8]) {
        (&self.master).write_all(bytes).unwrap();
    }

    fn resize(&self, rows: u16, cols: u16) {
        let size = WindowSize {
            rows,
            cols,
            ..WindowSize::default()
        };
        set_window_size(self.master.as_fd(), size).unwrap();
    }

    fn count(&self, needle: &str) -> usize {
        count(&self.seen, needle.as_bytes())
    }

    fn count_since(&self, mark: usize, needle: &str) -> usize {
        count(self.seen.get(mark..).unwrap_or_default(), needle.as_bytes())
    }

    /// What the terminal showed, for a message: as it is when it holds no
    /// canary of any case so far ([`never_shown`]), otherwise only where
    /// each one is, so a failure never prints a value.
    fn text(&self) -> String {
        let cs = SHOWN_NEVER.lock().unwrap_or_else(PoisonError::into_inner);
        let found = envcloak_testkit::find(&self.seen, &cs);
        if found.is_empty() {
            return String::from_utf8_lossy(&self.seen).into_owned();
        }
        let at: Vec<String> = found
            .iter()
            .map(|f| format!("{} as {} at {}", f.label, f.encoding, f.offset))
            .collect();
        format!(
            "<{} bytes not shown: they hold {}>",
            self.seen.len(),
            at.join(", ")
        )
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
                // EIO: no process holds the slave side but this test.
                Err(_) => return done(self),
            }
        }
    }

    /// Waits until `needle` has been shown `times` times in all.
    fn expect(&mut self, needle: &str, times: usize, what: &str) {
        let ok = self.wait_for_within(DEADLINE, |o| o.count(needle) >= times);
        assert!(
            ok,
            "{what}: {needle:?} was not shown {times} time(s); the terminal showed:\n{}",
            self.text()
        );
    }

    /// Reads on until `child` (this process's own) exits, up to `limit`;
    /// kills it (unreaped, so its number is its own) when it does not.
    fn wait_exit(&mut self, child: &mut Child, limit: Duration) -> ExitStatus {
        let end = Instant::now() + limit;
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                // What it wrote just before it exited.
                self.wait_for_within(Duration::from_millis(100), |_| false);
                return status;
            }
            if Instant::now() >= end {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "the runner did not exit; the terminal showed:\n{}",
                    self.text()
                );
            }
            self.wait_for_within(Duration::from_millis(20), |_| false);
        }
    }
}

fn count(hay: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || hay.len() < needle.len() {
        return 0;
    }
    hay.windows(needle.len()).filter(|w| *w == needle).count()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    count(hay, needle) > 0
}

/// Starts `argv` leading a new session on `outer`, with `case`'s home's
/// environment and `env`, in the case's directory. The process (after the
/// launcher's `exec`, the same one) is this test's own child.
fn lead(case: &Case, outer: &Outer, argv: &[OsString], env: &[(&str, &OsStr)]) -> Child {
    start_on(LEAD, case, outer, argv, env)
}

/// As [`lead`], but the terminal is not the session's (see [`DETACH`]).
fn detach(case: &Case, outer: &Outer, argv: &[OsString], env: &[(&str, &OsStr)]) -> Child {
    start_on(DETACH, case, outer, argv, env)
}

fn start_on(
    launcher: &str,
    case: &Case,
    outer: &Outer,
    argv: &[OsString],
    env: &[(&str, &OsStr)],
) -> Child {
    start_on_with_stderr(
        launcher,
        case,
        outer,
        argv,
        env,
        Stdio::from(outer.slave.try_clone().unwrap()),
    )
}

fn start_on_with_stderr(
    launcher: &str,
    case: &Case,
    outer: &Outer,
    argv: &[OsString],
    env: &[(&str, &OsStr)],
    stderr: Stdio,
) -> Child {
    let mut cmd = Command::new(python3());
    case.home.apply(&mut cmd);
    let slave = || Stdio::from(outer.slave.try_clone().unwrap());
    cmd.arg("-c")
        .arg(launcher)
        .args(argv)
        .envs(env.iter().map(|(k, v)| (k, v)))
        .current_dir(case.dir.path())
        .stdin(slave())
        .stdout(slave())
        .stderr(stderr);
    cmd.spawn().unwrap()
}

/// A runner leading the outer terminal, killed (its own, unreaped child)
/// if the case fails before it exits.
struct Running {
    child: Child,
}

impl Running {
    fn pid(&self) -> i32 {
        i32::try_from(self.child.id()).unwrap()
    }

    fn signal(&self, sig: i32) {
        envcloak_sys::signal_process(self.pid(), sig).unwrap();
    }
}

impl Drop for Running {
    /// A case that failed before the runner exited: killed (its own,
    /// unreaped child) and not waited for. A session's leader on macOS
    /// waits, as it exits, until its terminal's output has been read, and
    /// the outer terminal is read no more here: it ends when the terminal
    /// is dropped after this, and is reaped with this process.
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.try_wait();
        }
    }
}

/// Lines in `path`, 0 when it does not exist.
fn lines(path: &Path) -> usize {
    std::fs::read(path).map_or(0, |b| b.iter().filter(|c| **c == b'\n').count())
}

/// Reads `outer` until `path` has at least `n` lines, up to the deadline.
fn wait_lines(outer: &mut Outer, path: &Path, n: usize) -> bool {
    outer.wait_for_within(DEADLINE, |_| lines(path) >= n)
}

fn counts(dir: &Path, who: &str) -> Vec<usize> {
    SIGNALS
        .iter()
        .map(|(_, name)| lines(&dir.join(format!("{who}-{name}"))))
        .collect()
}

/// Every canary any case has made: a terminal's text is never shown in a
/// message while it holds one ([`Outer::text`]).
static SHOWN_NEVER: Mutex<Vec<Canary>> = Mutex::new(Vec::new());

/// Adds `cs` to the canaries a message never shows.
fn never_shown(cs: &[Canary]) {
    SHOWN_NEVER
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .extend(cs.iter().cloned());
}

/// The marker the redactor writes for the canary labeled `label`.
fn marker(label: &str) -> String {
    format!("[envcloak:{}]", slug_of(label))
}

// ---------------------------------------------------------------------------
// Gate 8 through a real PTY.

/// Node, PHP and a built Go serializer, where installed; required ones are
/// named in `ENVCLOAK_TEST_REQUIRE_SERIALIZERS` (comma-separated), as for
/// the runner's gate 8 (`runner.rs`).
fn runtimes() -> Vec<OsString> {
    let go = find("go").and_then(|go| {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("go-serializer-pty");
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
    let found = [("node", find("node")), ("php", find("php")), ("go", go)];
    let required = std::env::var("ENVCLOAK_TEST_REQUIRE_SERIALIZERS").unwrap_or_default();
    for name in required.split(',').filter(|n| !n.is_empty()) {
        let there = name == "python" || found.iter().any(|(n, p)| *n == name && p.is_some());
        assert!(there, "the {name} serializer is required but not installed");
    }
    let mut a = Vec::new();
    for (name, p) in found {
        if let Some(p) = p {
            a.push(format!("--{name}").into());
            a.push(p.into());
        }
    }
    a
}

/// Gate 8 through a real terminal: each value's output from real
/// serializers (Python's JSON, `quote` and `quote_plus` in both hex cases,
/// form encoding, base64 and base64url padded and unpadded at offsets 0, 1
/// and 2, hex; Node, PHP and Go where installed; serde_json from this test;
/// the recorded output of .NET, Go, Node, Python and Ruby) is written on
/// standard output and standard error, which are one terminal here, whole
/// and then a byte at a time with an idle flush between bytes, followed by
/// malformed UTF-8, end of stream, or SIGTERM (sent to the runner, which
/// forwards it to the terminal's foreground job). One job's values include
/// the PEM-shaped value, whose raw form the terminal shows with CR LF.
/// No canary, in any encoding, and no CR LF form reaches the outer
/// terminal, and every payload's frame does.
///
/// Mutation checked: build the PTY redactor without the CR LF variants
/// (`crlf_variants(false)` in `build_pty_redactor`): the PEM job fails,
/// its CR LF form on the screen.
fn gate8_real_serializers_through_a_pty_are_redacted_crlf_forms_included() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../envcloak-redact/tests/fixtures");
    let runtimes = runtimes();
    let jobs = [
        (labels::OPENAI_API_KEY, "", "malformed", true),
        (labels::STRIPE_SECRET_KEY, PEM, "eof", false),
        (labels::GITHUB_TOKEN, "", "sigterm", false),
        (labels::DATABASE_URL, "", "malformed", false),
    ];
    // The case runs with standard output locked by the case runner: the
    // jobs' threads return their lines, printed once they are joined.
    let lines: Vec<String> = std::thread::scope(|s| {
        let handles: Vec<_> = jobs
            .into_iter()
            .map(|(label, second, tail, with_fixtures)| {
                let (runtimes, fixtures) = (&runtimes, &fixtures);
                s.spawn(move || -> String {
                    let case = Case::new();
                    let mut cs = case.cs.clone();
                    for (l, file) in [
                        ("FIXTURE_JSON", "value-json.txt"),
                        ("FIXTURE_URL", "value-url.txt"),
                    ] {
                        let v = std::fs::read_to_string(fixtures.join(file)).unwrap();
                        cs.push(Canary::new(l, v));
                    }
                    never_shown(&cs);
                    // serde_json's encoding of each value, as a fixture file.
                    let serde = case.path("serde");
                    std::fs::create_dir(&serde).unwrap();
                    let mut names = vec![label];
                    if !second.is_empty() {
                        names.push(second);
                    }
                    for n in &names {
                        let json = serde_json::to_vec(by_label(&cs, n).as_str()).unwrap();
                        std::fs::write(serde.join(format!("serde-{n}")), json).unwrap();
                    }
                    let stop = case.path("stop");
                    let mut argv: Vec<OsString> = vec![
                        python3().into(),
                        Path::new(env!("CARGO_MANIFEST_DIR"))
                            .join("tests/emitters/emit.py")
                            .into(),
                        "--names".into(),
                        names.join(",").into(),
                        "--tail".into(),
                        tail.into(),
                        "--pause-ms".into(),
                        "1".into(),
                        "--merged".into(),
                        "--fixtures".into(),
                        serde.clone().into(),
                        "--stop".into(),
                        stop.clone().into(),
                        "--ended".into(),
                        case.path("ended").into(),
                        "--deadline".into(),
                        "120".into(),
                    ];
                    argv.extend(runtimes.iter().cloned());
                    if with_fixtures {
                        for d in ["json", "url"] {
                            argv.push("--fixtures".into());
                            argv.push(fixtures.join(d).into());
                        }
                    }
                    let values: Vec<String> = names.iter().map(|n| format!("{n}:{n}")).collect();
                    let values: Vec<&str> = values.iter().map(String::as_str).collect();
                    let files = [
                        format!("FIXTURE_JSON:{}", fixtures.join("value-json.txt").display()),
                        format!("FIXTURE_URL:{}", fixtures.join("value-url.txt").display()),
                    ];
                    let mut flags = vec!["--idle-ms", "1"];
                    if with_fixtures {
                        for f in &files {
                            flags.extend(["--file", f.as_str()]);
                        }
                    }
                    let argv: Vec<&OsStr> = argv.iter().map(OsString::as_os_str).collect();
                    let mut outer = Outer::new(24, 80);
                    let mut run = Running {
                        child: lead(
                            &case,
                            &outer,
                            &case.runner_argv(&values, &flags, &argv),
                            &[],
                        ),
                    };
                    if tail == "sigterm" {
                        outer.expect("READY", 1, &format!("{label}: the emitter's tail"));
                        run.signal(libc::SIGTERM);
                    }
                    let status = outer.wait_exit(&mut run.child, Duration::from_secs(300));
                    let _ = std::fs::write(&stop, b"");
                    let shown = outer.seen.clone();
                    assert_no_canary(&shown, &cs);
                    case.home.assert_clean(&cs);
                    let want = if tail == "sigterm" {
                        128 + libc::SIGTERM
                    } else {
                        0
                    };
                    assert_eq!(status.code(), Some(want), "{label}: {}", outer.text());
                    let text = outer.text();
                    let line = text
                        .lines()
                        .find(|l| l.contains("SERIALIZERS "))
                        .unwrap_or_else(|| panic!("{label}: no SERIALIZERS line: {text}"));
                    let n: usize = line
                        .trim_end_matches('\r')
                        .rsplit(' ')
                        .next()
                        .unwrap()
                        .parse()
                        .unwrap();
                    let said = format!("pty gate 8 {label}: {}", line.trim_end_matches('\r'));
                    assert!(n >= 20 * names.len(), "{label}: {line}");
                    assert_eq!(count(&shown, b"<W|"), n, "{label}: whole payloads lost");
                    assert_eq!(count(&shown, b"<B|"), n, "{label}: split payloads lost");
                    assert!(
                        count(&shown, b"[envcloak:") >= 2 * n,
                        "{label}: {} markers for {n} payloads",
                        count(&shown, b"[envcloak:")
                    );
                    if second == PEM {
                        // The raw payloads of the PEM value, whole and split, as
                        // the terminal shows them: redacted.
                        assert!(
                            count(&shown, marker(PEM).as_bytes()) >= 2,
                            "{label}: the PEM value's raw form was not redacted"
                        );
                    }
                    match tail {
                        "malformed" => {
                            assert!(contains(&shown, b"M:\xff\xfe\xc3(\xe2\x82"), "{label}");
                            assert!(contains(&shown, b"M:\xc0\xaf\xed\xa0\x80\r\n"), "{label}");
                            assert!(contains(&shown, b"END\r\n"), "{label}");
                            assert!(contains(&shown, b"DONE\r\n"), "{label}");
                        }
                        "eof" => assert!(contains(&shown, b"DONE\r\n"), "{label}"),
                        _ => assert!(contains(&shown, b"H:"), "{label}"),
                    }
                    said
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or_else(|e| std::panic::resume_unwind(e)))
            .collect()
    });
    for line in lines {
        println!("{line}");
    }
}

// ---------------------------------------------------------------------------
// Prompts, input, echo, Ctrl-C and the window size.

/// An acknowledgement barrier precedes each prompt: timing starts before
/// the child can emit it. Every sample must meet the 100 ms bound. The
/// exact 40 ms deadline is checked separately with an injected time.
fn a_prompt_without_a_newline_shows_and_the_start_of_a_value_waits() {
    let case = Case::new();
    let script = r#"i=0
while [ $i -lt 5 ]; do
  printf 'mark-%d\n' $i
  read ready
  printf 'Password: '
  read answer
  printf 'got %s\n' "$answer"
  i=$((i+1))
done
printf '%.12s' "$OPENAI_API_KEY"
read more
printf '!\n'"#;
    let mut outer = Outer::new(24, 80);
    let argv = case.runner_argv(
        &["OPENAI_API_KEY:OPENAI_API_KEY"],
        &[],
        &[OsStr::new("/bin/sh"), OsStr::new("-c"), OsStr::new(script)],
    );
    let mut run = Running {
        child: lead(&case, &outer, &argv, &[]),
    };
    let mut took = Vec::new();
    for i in 0..5 {
        outer.expect(&format!("mark-{i}"), 1, "the marker");
        let t0 = Instant::now();
        outer.type_bytes(b"ready\r");
        outer.expect("Password: ", i + 1, "the prompt while the command waits");
        took.push(t0.elapsed());
        outer.type_bytes(b"yes\r");
        outer.expect("got yes", i + 1, "the answer reached the command");
    }
    println!("pty prompt: shown {took:?} after acknowledgement");
    assert!(
        took.iter().all(|t| *t <= Duration::from_millis(100)),
        "{took:?}"
    );
    let prefix = &by_label(&case.cs, labels::OPENAI_API_KEY).value()[..12];
    let early = outer.wait_for_within(Duration::from_millis(300), |o| contains(&o.seen, prefix));
    assert!(!early, "the start of a value was released");
    outer.type_bytes(b"\r");
    let status = outer.wait_exit(&mut run.child, DEADLINE);
    assert_eq!(status.code(), Some(0), "{}", outer.text());
    assert!(contains(&outer.seen, prefix), "{}", outer.text());
    assert!(contains(&outer.seen, b"!\r\n"), "{}", outer.text());
    case.assert_clean(&outer.seen);
}

/// The kernel is the independent oracle: each inherited translation is
/// enabled on the outer terminal, and the plain command
/// records its actual byte rewrite. Through the runner only OPOST/ONLCR
/// remain, and a value containing tabs, CR, LF, lowercase and EOT is masked.
/// Platform constants come from libc: Apple's Python omits OXTABS/ONOEOT.
/// A flag the kernel refuses is named; an entirely skipped gate fails.
fn inherited_output_translations_are_cleared_before_redaction() {
    let case = Case::new();
    let value = format!("\rline{:x}\tcol\rnext\x04end\n", case.seed);
    let canary = Canary::new("OUTPUT_FLAGS", value.clone());
    never_shown(std::slice::from_ref(&canary));
    let value_file = case.path("value");
    std::fs::write(&value_file, value.as_bytes()).unwrap();
    let launcher = case.script(
        "translations.py",
        r"import errno, os, sys, termios
name, flags = sys.argv[1], int(sys.argv[2])
def unsupported(reason):
    print('FLAG_UNSUPPORTED %s: %s' % (name, reason), file=sys.stderr, flush=True)
    sys.exit(77)
settings = termios.tcgetattr(0)
settings[1] = flags
try:
    termios.tcsetattr(0, termios.TCSANOW, settings)
except termios.error as error:
    if error.args[0] in (errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP):
        unsupported('tcsetattr rejected output flags: %s' % (error,))
    raise
actual = termios.tcgetattr(0)[1]
if actual != flags:
    unsupported('tcgetattr returned %d instead of requested %d' % (actual, flags))
os.execv(sys.argv[3], sys.argv[3:])",
    );
    let emitter = case.script(
        "output.py",
        r"import os, pathlib, sys, termios
if sys.argv[1] == 'env':
    flags = termios.tcgetattr(1)[1]
    os.write(1, ('FLAGS=%d\n' % flags).encode())
    value = os.environ['TEST_VALUE'].encode()
else:
    value = pathlib.Path(sys.argv[1]).read_bytes()
os.write(1, value)",
    );
    let python = python3();
    let capture = |argv: &[OsString]| {
        let mut outer = Outer::new(24, 80);
        // A failed session leader can revoke the PTY before its traceback
        // is read. Keep stderr independently, without a pipe that can fill.
        let mut errors = tempfile::tempfile().unwrap();
        let mut child = Running {
            child: start_on_with_stderr(
                LEAD,
                &case,
                &outer,
                argv,
                &[],
                Stdio::from(errors.try_clone().unwrap()),
            ),
        };
        let status = outer.wait_exit(&mut child.child, DEADLINE);
        let stdout_len = outer.seen.len();
        errors.rewind().unwrap();
        errors.read_to_end(&mut outer.seen).unwrap();
        (outer, status, stdout_len)
    };
    #[cfg(target_os = "macos")]
    let flags = [
        ("OXTABS", libc::OXTABS),
        ("ONOEOT", libc::ONOEOT),
        ("OCRNL", libc::OCRNL),
        ("ONOCR", libc::ONOCR),
        ("ONLRET", libc::ONLRET),
    ];
    #[cfg(target_os = "linux")]
    let flags = [
        ("TAB3", libc::TAB3),
        ("OLCUC", libc::OLCUC),
        ("OCRNL", libc::OCRNL),
        ("ONOCR", libc::ONOCR),
        ("ONLRET", libc::ONLRET),
    ];
    let mut exercised = 0;
    for (flag, bit) in flags {
        let oflags = (libc::OPOST | libc::ONLCR | bit).to_string();
        let argv = vec![
            python.clone().into_os_string(),
            launcher.clone().into_os_string(),
            flag.into(),
            oflags.clone().into(),
            python.clone().into_os_string(),
            emitter.clone().into_os_string(),
            value_file.clone().into_os_string(),
        ];
        let (plain, status, stdout_len) = capture(&argv);
        if status.code() == Some(77)
            && stdout_len == 0
            && plain
                .seen
                .starts_with(format!("FLAG_UNSUPPORTED {flag}: ").as_bytes())
        {
            println!("PTY output flag {flag}: skipped: {}", plain.text().trim());
            continue;
        }
        assert_eq!(
            status.code(),
            Some(0),
            "{flag}: plain launcher failed; PTY output and stderr:\n{}",
            plain.text()
        );
        assert_eq!(
            stdout_len,
            plain.seen.len(),
            "{flag}: plain launcher wrote stderr:\n{}",
            plain.text()
        );
        if flag != "ONLRET" {
            assert_ne!(
                plain.seen,
                crlf(value.as_bytes()),
                "{flag}: kernel control did not rewrite output:\n{}",
                plain.text()
            );
        }
        let file_arg = format!("TEST_VALUE:{}", value_file.display());
        let runner = case.runner_argv(
            &[],
            &["--file", &file_arg],
            &[python.as_os_str(), emitter.as_os_str(), OsStr::new("env")],
        );
        let mut argv = vec![
            python.clone().into_os_string(),
            launcher.clone().into_os_string(),
            flag.into(),
            oflags.into(),
        ];
        argv.extend(runner);
        let (outer, status, stdout_len) = capture(&argv);
        assert_eq!(
            status.code(),
            Some(0),
            "{flag}: relay launcher failed; PTY output and stderr:\n{}",
            outer.text()
        );
        assert_eq!(
            stdout_len,
            outer.seen.len(),
            "{flag}: relay launcher wrote stderr:\n{}",
            outer.text()
        );
        let expected = format!(
            "FLAGS={}\r\n[envcloak:fixture0/t]",
            libc::OPOST | libc::ONLCR
        );
        assert!(
            outer.seen == expected.as_bytes(),
            "{flag}: unexpected output flags or value not redacted:\n{}",
            outer.text()
        );
        assert_no_canary(&outer.seen, std::slice::from_ref(&canary));
        exercised += 1;
        println!("PTY output flag {flag}: kernel control and redaction passed");
    }
    assert!(
        exercised > 0,
        "no supported PTY output flags were exercised"
    );
}

/// Canonical input: a typed line is echoed by the command's terminal and
/// copied by cat. Raw input: a program that puts its terminal in raw mode
/// reads every key as a byte, the interrupt, suspend and quit characters
/// included, and gets no signal for them.
fn canonical_and_raw_input_reach_the_command() {
    let case = Case::new();
    let cat = case.script("cat.py", RETRY_CAT);
    let mut outer = Outer::new(24, 80);
    let python = python3();
    let argv = case.runner_argv(&[], &[], &[python.as_os_str(), cat.as_os_str()]);
    let mut run = Running {
        child: lead(&case, &outer, &argv, &[]),
    };
    outer.expect("CAT-READY", 1, "cat");
    outer.type_bytes(b"hello-canon\r");
    outer.expect("hello-canon", 2, "the echo and cat's copy");
    outer.type_bytes(b"\x04");
    let status = outer.wait_exit(&mut run.child, DEADLINE);
    assert_eq!(status.code(), Some(0), "{}", outer.text());

    let raw = case.script("raw.py", RAW_BYTES);
    let mut outer = Outer::new(24, 80);
    let argv = case.runner_argv(&[], &[], &[python.as_os_str(), raw.as_os_str()]);
    let mut run = Running {
        child: lead(&case, &outer, &argv, &[]),
    };
    outer.expect("RAW-READY", 1, "the raw reader");
    outer.type_bytes(b"a\x03\x1a\x1cq");
    let status = outer.wait_exit(&mut run.child, DEADLINE);
    assert_eq!(status.code(), Some(0), "{}", outer.text());
    for b in ["B61", "B03", "B1a", "B1c"] {
        assert_eq!(outer.count(b), 1, "{b}: {}", outer.text());
    }
    case.assert_clean(&outer.seen);
}

/// A command that turns its terminal's echo off reads a typed password
/// that the terminal never shows; with echo on, the same line shows
/// (the positive control).
fn a_command_that_turns_echo_off_reads_a_password_unseen() {
    let case = Case::new();
    for (echo, script) in [
        (
            false,
            r#"stty -echo; printf 'Password: '; read pw; stty echo; printf '\nlen=%s\n' "${#pw}""#,
        ),
        (
            true,
            r#"printf 'Password: '; read pw; printf '\nlen=%s\n' "${#pw}""#,
        ),
    ] {
        let mut outer = Outer::new(24, 80);
        let argv = case.runner_argv(
            &[],
            &[],
            &[OsStr::new("/bin/sh"), OsStr::new("-c"), OsStr::new(script)],
        );
        let mut run = Running {
            child: lead(&case, &outer, &argv, &[]),
        };
        outer.expect("Password: ", 1, "the prompt");
        outer.type_bytes(b"typed-word-xyz\r");
        let status = outer.wait_exit(&mut run.child, DEADLINE);
        assert_eq!(status.code(), Some(0), "{}", outer.text());
        assert_eq!(outer.count("len=14"), 1, "{}", outer.text());
        assert_eq!(
            outer.count("typed-word-xyz"),
            usize::from(echo),
            "echo {echo}: {}",
            outer.text()
        );
    }
}

/// Each Ctrl-C typed on the outer terminal, which is raw for the run,
/// reaches the command's terminal as a byte, and its line discipline sends
/// the command a SIGINT for it; the run goes on. `envcloak run` sends none
/// of its own: a command that turned its terminal's signal characters off
/// (raw mode) reads each Ctrl-C as a byte and gets no SIGINT at all. (Two
/// SIGINTs sent at once can merge into one pending signal, so a count of
/// one per Ctrl-C alone could not show a second; the raw-mode count of
/// zero can.)
///
/// Mutation checked: forward a typed interrupt byte as a signal as well
/// (`forward_signal` on reading `0x03`): the raw-mode command gets SIGINTs
/// and this fails.
fn each_ctrl_c_is_one_sigint_for_the_command() {
    let case = Case::new();
    let counter = case.script("counter.py", COUNTER);
    let mut outer = Outer::new(24, 80);
    let python = python3();
    let d = case.dir.path().as_os_str();
    let argv = case.runner_argv(
        &[],
        &[],
        &[
            python.as_os_str(),
            counter.as_os_str(),
            d,
            OsStr::new("job"),
        ],
    );
    let mut run = Running {
        child: lead(&case, &outer, &argv, &[]),
    };
    outer.expect("JOB-READY", 1, "the counter");
    let file = case.path("job-INT");
    for n in 1..=3 {
        outer.type_bytes(b"\x03");
        assert!(
            wait_lines(&mut outer, &file, n),
            "Ctrl-C {n} did not arrive"
        );
    }
    // Anything sent besides arrives before the line typed after it is read.
    outer.type_bytes(b"sync\r");
    outer.expect("GOT [sync]", 1, "the counter read on");
    assert_eq!(counts(case.dir.path(), "job"), vec![3, 0, 0, 0]);
    outer.type_bytes(b"done\r");
    let status = outer.wait_exit(&mut run.child, DEADLINE);
    assert_eq!(status.code(), Some(0), "{}", outer.text());

    let raw = case.script("raw_counter.py", RAW_COUNTER);
    let mut outer = Outer::new(24, 80);
    let argv = case.runner_argv(&[], &[], &[python.as_os_str(), raw.as_os_str(), d]);
    let mut run = Running {
        child: lead(&case, &outer, &argv, &[]),
    };
    outer.expect("RAW-READY", 1, "the raw-mode counter");
    outer.type_bytes(b"\x03\x03\x03q");
    let status = outer.wait_exit(&mut run.child, DEADLINE);
    assert_eq!(status.code(), Some(0), "{}", outer.text());
    assert_eq!(outer.count("B03"), 3, "{}", outer.text());
    assert_eq!(lines(&case.path("raw-INT")), 0, "envcloak run sent SIGINT");
}

/// The PTY starts with the outer terminal's size, and a resize of the
/// outer terminal (SIGWINCH to the runner) reaches the command's terminal:
/// `stty size` inside reads it.
fn a_resize_reaches_the_command_through_stty_size() {
    let case = Case::new();
    let sizes = case.script(
        "sizes.sh",
        "echo SIZES-READY; while read l; do stty size; done\n",
    );
    let mut outer = Outer::new(24, 80);
    let argv = case.runner_argv(&[], &[], &[OsStr::new("/bin/sh"), sizes.as_os_str()]);
    let mut run = Running {
        child: lead(&case, &outer, &argv, &[]),
    };
    outer.expect("SIZES-READY", 1, "the command");
    outer.type_bytes(b"\r");
    outer.expect("24 80", 1, "the first size");
    outer.resize(50, 132);
    // The new size reaches the command once the runner has had SIGWINCH:
    // asked again until it shows.
    let end = Instant::now() + DEADLINE;
    while outer.count("50 132") == 0 {
        assert!(
            Instant::now() < end,
            "the new size never showed:\n{}",
            outer.text()
        );
        outer.type_bytes(b"\r");
        outer.wait_for_within(Duration::from_millis(200), |o| o.count("50 132") > 0);
    }
    outer.type_bytes(b"\x04");
    let status = outer.wait_exit(&mut run.child, DEADLINE);
    assert_eq!(status.code(), Some(0), "{}", outer.text());
}

// ---------------------------------------------------------------------------
// The forwarded-signal receipt gate (CR-4).

/// SIGINT, SIGQUIT, SIGTERM and SIGHUP sent to the runner by another
/// process (this test, in another session) each reach the command exactly
/// once, on a counter per signal; the run goes on, and ends when the
/// command does.
fn forwarded_signals_reach_the_command_once_each() {
    let case = Case::new();
    let counter = case.script("counter.py", COUNTER);
    let mut outer = Outer::new(24, 80);
    let python = python3();
    let d = case.dir.path().as_os_str();
    let argv = case.runner_argv(
        &[],
        &[],
        &[
            python.as_os_str(),
            counter.as_os_str(),
            d,
            OsStr::new("job"),
        ],
    );
    let mut run = Running {
        child: lead(&case, &outer, &argv, &[]),
    };
    outer.expect("JOB-READY", 1, "the counter");
    let mut expected = vec![0; 4];
    for (i, (sig, name)) in SIGNALS.iter().enumerate() {
        run.signal(*sig);
        assert!(
            wait_lines(&mut outer, &case.path(&format!("job-{name}")), 1),
            "SIG{name} did not reach the command; counts {:?}",
            counts(case.dir.path(), "job")
        );
        expected[i] = 1;
        assert_eq!(counts(case.dir.path(), "job"), expected, "after SIG{name}");
    }
    outer.type_bytes(b"done\r");
    let status = outer.wait_exit(&mut run.child, DEADLINE);
    assert_eq!(status.code(), Some(0), "{}", outer.text());
    assert_eq!(counts(case.dir.path(), "job"), vec![1, 1, 1, 1]);
}

/// Whether SIGTERM and SIGHUP are narrowed to the command's group in a
/// runner with `--no-group-signal` (Linux), or on this kernel.
fn narrowed(forced: bool, sig: i32) -> bool {
    cfg!(target_os = "linux")
        && matches!(sig, libc::SIGTERM | libc::SIGHUP)
        && (forced || !group_signal_supported())
}

#[cfg(target_os = "linux")]
fn group_signal_supported() -> bool {
    envcloak_sys::testing::group_signal_supported()
}

#[cfg(not(target_os = "linux"))]
fn group_signal_supported() -> bool {
    false
}

/// The receipt gate with a nested shell (`/bin/sh -i`, `set -m`) as the
/// command, running the counter as a job in its own foreground group: each
/// of the four, sent to the runner, reaches the job exactly once and the
/// shell never (separate counters per process and per signal). Where D-35
/// narrows a signal (Linux kernels before 6.9: SIGTERM and SIGHUP), the
/// narrowed counts hold instead: the job 0, the shell 1 (its trap runs once
/// the job has ended).
///
/// Mutations checked: forward the four through the monitor's direct child
/// group (`MonitorCommand::Signal` for every signal): the job counts 0 and
/// the shell 1, and this fails for each; send SIGTERM through `TIOCSIG` on
/// Linux and ignore its error: the job counts 0 for SIGTERM.
fn forwarded_signals_reach_a_nested_shells_job_and_not_the_shell() {
    nested_receipts(false);
}

/// The receipt gate where the kernel cannot signal a process group
/// through a pidfd (Linux before 6.9: Ubuntu 24.04's 6.8, Debian 12, RHEL
/// 9), forced in the runner on the kernel this runs on: SIGTERM and SIGHUP
/// go to the command's own group, the nested shell, not its job, as
/// docs/RUN.md and `run --pty`'s help say. macOS sends all four with
/// `TIOCSIG` and narrows nothing.
fn without_the_group_signal_sigterm_and_sighup_are_narrowed_to_the_shell() {
    let run_md =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/RUN.md"))
            .unwrap();
    for named in [
        "SIGTERM and SIGHUP",
        "kernels before 6.9",
        "the shell, not its job",
    ] {
        assert!(
            run_md.contains(named),
            "docs/RUN.md does not name the narrowing: {named:?}"
        );
    }
    if cfg!(target_os = "linux") {
        nested_receipts(true);
    } else {
        println!(
            "pty_relay ({}): no signal is narrowed here (TIOCSIG takes all four)",
            std::env::consts::OS
        );
    }
}

fn nested_receipts(forced: bool) {
    let case = Case::new();
    let counter = case.script("counter.py", COUNTER);
    let mut outer = Outer::new(24, 80);
    let flags: &[&str] = if forced { &["--no-group-signal"] } else { &[] };
    let argv = case.runner_argv(&[], flags, &[OsStr::new("/bin/sh"), OsStr::new("-i")]);
    let mut run = Running {
        child: lead(&case, &outer, &argv, &[("PS1", OsStr::new(INNER))]),
    };
    let d = case.dir.path().display();
    outer.expect(INNER, 1, "the nested shell's prompt");
    let traps: String = SIGNALS
        .iter()
        .map(|(_, name)| format!("trap 'echo x >> {d}/shell-{name}' {name}; "))
        .collect();
    outer.type_bytes(format!("{traps}{NO_EDITING}set -m\r").as_bytes());
    outer.expect(INNER, 2, "the shell set its traps");
    outer.type_bytes(
        format!(
            "'{}' '{}' '{d}' job\r",
            python3().display(),
            counter.display()
        )
        .as_bytes(),
    );
    outer.expect("JOB-READY", 1, "the job started");
    let mut job = vec![0; 4];
    let mut shell = vec![0; 4];
    for (i, (sig, name)) in SIGNALS.iter().enumerate() {
        run.signal(*sig);
        if narrowed(forced, *sig) {
            shell[i] = 1;
        } else {
            assert!(
                wait_lines(&mut outer, &case.path(&format!("job-{name}")), 1),
                "SIG{name} did not reach the job; job {:?}, shell {:?}",
                counts(case.dir.path(), "job"),
                counts(case.dir.path(), "shell")
            );
            job[i] = 1;
        }
        assert_eq!(counts(case.dir.path(), "job"), job, "after SIG{name}");
    }
    // The job ends; the shell runs any trap pending (a narrowed signal's)
    // once it has read and run the next command: `:` is typed until the
    // traps due ran, and once when none is due, so one that was not would
    // have run too.
    outer.type_bytes(b"done\r");
    outer.expect(INNER, 3, "the job ended");
    let due: usize = shell.iter().sum();
    let mut prompts = 3;
    let end = Instant::now() + DEADLINE;
    loop {
        outer.type_bytes(b":\r");
        prompts += 1;
        outer.expect(INNER, prompts, "the shell ran :");
        if counts(case.dir.path(), "shell").iter().sum::<usize>() >= due {
            break;
        }
        assert!(
            Instant::now() < end,
            "the shell's traps did not run: {:?}",
            counts(case.dir.path(), "shell")
        );
    }
    assert_eq!(counts(case.dir.path(), "job"), job, "the job's counts");
    assert_eq!(
        counts(case.dir.path(), "shell"),
        shell,
        "the shell's counts"
    );
    outer.type_bytes(b"exit 0\r");
    let status = outer.wait_exit(&mut run.child, DEADLINE);
    assert_eq!(status.code(), Some(0), "{}", outer.text());
    println!(
        "pty_relay ({}{}): job {job:?}, shell {shell:?} for {:?}",
        std::env::consts::OS,
        if forced { ", group signal refused" } else { "" },
        SIGNALS.map(|(_, n)| n)
    );
}

// ---------------------------------------------------------------------------
// Suspension races at barriers, under an outer job-control shell.

/// A job-control shell on a terminal the test owns, which starts the
/// runner as a job.
struct JobShell {
    outer: Outer,
    shell: Child,
    prompts: usize,
}

impl JobShell {
    /// `/bin/sh -i` leading a session on a new terminal, cleared
    /// environment (no rc files: `HOME` is the case's, `ENV` unset), job
    /// control on; `env` is passed to the shell, so its jobs get it too.
    fn start(case: &Case, env: &[(&str, &OsStr)]) -> JobShell {
        let outer = Outer::new(24, 80);
        let mut all: Vec<(&str, &OsStr)> = vec![("PS1", OsStr::new(PROMPT))];
        all.extend_from_slice(env);
        let shell = lead(
            case,
            &outer,
            &[OsString::from("/bin/sh"), "-i".into()],
            &all,
        );
        let mut js = JobShell {
            outer,
            shell,
            prompts: 1,
        };
        js.outer.expect(PROMPT, 1, "the outer shell's first prompt");
        js.say(&format!("{NO_EDITING}set -m"));
        js
    }

    /// Types `line` and waits for the next prompt.
    fn say(&mut self, line: &str) {
        self.outer.type_bytes(format!("{line}\r").as_bytes());
        self.prompts += 1;
        self.outer.expect(PROMPT, self.prompts, line);
    }

    /// Types `line` without waiting for a prompt (the runner starts).
    fn start_job(&mut self, line: &str) {
        self.outer.type_bytes(format!("{line}\r").as_bytes());
    }

    /// Waits for the prompt the shell prints when its job stops or ends.
    fn prompt_again(&mut self, what: &str) {
        self.prompts += 1;
        self.outer.expect(PROMPT, self.prompts, what);
    }

    /// `jobs` lists the job as stopped.
    fn job_stopped(&mut self) {
        let mark = self.outer.seen.len();
        self.say("jobs");
        assert!(
            self.outer.count_since(mark, "Stopped") >= 1,
            "jobs did not list a stopped job:\n{}",
            self.outer.text()
        );
    }

    /// `stty -g` into `path`.
    fn stty_g(&mut self, path: &Path) -> Vec<u8> {
        self.say(&format!("stty -g > '{}'", path.display()));
        std::fs::read(path).unwrap()
    }

    /// The exit status of the last command, through `echo`.
    fn status(&mut self) -> i32 {
        let mark = self.outer.seen.len();
        self.say("echo \"rc=$?\"");
        let shown = String::from_utf8_lossy(&self.outer.seen[mark..]).into_owned();
        // The last `rc=`: the first is the typed line's echo.
        shown
            .rsplit("rc=")
            .next()
            .and_then(|r| r.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|n| n.parse().ok())
            .unwrap_or_else(|| panic!("no status: {shown}"))
    }

    fn exit(mut self) {
        self.outer.type_bytes(b"exit 0\r");
        let status = self.outer.wait_exit(&mut self.shell, DEADLINE);
        assert_eq!(status.code(), Some(0), "{}", self.outer.text());
    }
}

impl Drop for JobShell {
    /// A case that failed with the shell running: killed (its own,
    /// unreaped child), its terminal read meanwhile (a session's leader on
    /// macOS waits, as it exits, until its terminal's output has been
    /// read) for at most 10 seconds, never waited for beyond that.
    fn drop(&mut self) {
        if self.shell.try_wait().ok().flatten().is_none() {
            let _ = self.shell.kill();
            let end = Instant::now() + Duration::from_secs(10);
            while self.shell.try_wait().ok().flatten().is_none() && Instant::now() < end {
                self.outer
                    .wait_for_within(Duration::from_millis(20), |_| false);
            }
        }
    }
}

/// The process state `ps` shows for `pid` (read, never signalled).
fn state_of(pid: u32) -> String {
    let out = Command::new("/bin/ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// The pid `counter.py` printed in its `JOB-READY` line.
fn job_pid(outer: &Outer) -> u32 {
    let text = String::from_utf8_lossy(&outer.seen).into_owned();
    text[text.find("JOB-READY ").unwrap() + 10..]
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

/// The runner's command line as typed into a shell, every word quoted.
fn typed(argv: &[OsString]) -> String {
    argv.iter()
        .map(|a| format!("'{}'", a.to_str().unwrap().replace('\'', r"'\''")))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The pause point `site`, released by the file `release`.
fn pause_env<'a>(site: &'a str, release: &'a Path) -> [(&'a str, &'a OsStr); 2] {
    [
        ("ENVCLOAK_TEST_PAUSE", OsStr::new(site)),
        ("ENVCLOAK_TEST_PAUSE_RELEASE", release.as_os_str()),
    ]
}

/// The suspend character typed while the runner is held inside a resize
/// (SIGWINCH read, the new size not yet set on the PTY): once let go, it
/// sets the size, relays the byte, and the stop goes as ever: the outer
/// shell's prompt, the job stopped, `stty -g` as before; `fg` resumes, and
/// the command reads the new size.
fn a_suspend_typed_during_a_resize_stops_once_and_fg_brings_the_new_size() {
    let case = Case::new();
    let release = case.path("go");
    let mut js = JobShell::start(&case, &pause_env("exec.pty.winch", &release));
    let before = js.stty_g(&case.path("before"));
    let sizes = case.script(
        "sizes.sh",
        "echo SIZES-READY; while read l; do stty size; done\n",
    );
    let argv = case.runner_argv(&[], &[], &[OsStr::new("/bin/sh"), sizes.as_os_str()]);
    js.start_job(&typed(&argv));
    js.outer.expect("SIZES-READY", 1, "the command");
    js.outer.type_bytes(b"\r");
    js.outer.expect("24 80", 1, "the first size");
    js.outer.resize(40, 100);
    js.outer.expect(
        "paused at exec.pty.winch",
        1,
        "the runner held in the resize",
    );
    js.outer.type_bytes(&[0x1a]);
    std::fs::write(&release, b"").unwrap();
    js.prompt_again("the suspend character gave the outer shell its prompt back");
    js.job_stopped();
    assert_eq!(js.stty_g(&case.path("after")), before, "the outer terminal");
    js.outer.type_bytes(b"fg\r");
    let end = Instant::now() + DEADLINE;
    while js.outer.count("40 100") == 0 {
        assert!(
            Instant::now() < end,
            "the new size never showed:\n{}",
            js.outer.text()
        );
        js.outer.type_bytes(b"\r");
        js.outer
            .wait_for_within(Duration::from_millis(200), |o| o.count("40 100") > 0);
    }
    js.outer.type_bytes(b"\x04");
    js.prompt_again("the command and the runner ended");
    js.exit();
}

/// `fg` typed while the runner holds the monitor's stop report and has not
/// yet handled it (the outer terminal still raw): the restore discards it
/// (`TCSAFLUSH`), so the outer shell does not run it, its prompt comes
/// back with the job stopped, and the outer terminal is as before; the
/// `fg` typed at the prompt then resumes the command, which reads a fresh
/// line.
///
/// Mutation checked: restore the outer terminal with `TCSANOW`: the shell
/// reads the early `fg` and resumes the job at once, and the stopped job's
/// prompt never comes.
fn fg_typed_before_the_stop_is_handled_is_discarded_with_the_input() {
    let case = Case::new();
    let release = case.path("go");
    let mut js = JobShell::start(&case, &pause_env("exec.pty.stopped", &release));
    let before = js.stty_g(&case.path("before"));
    let cat = case.script("cat.py", RETRY_CAT);
    let python = python3();
    let argv = case.runner_argv(&[], &[], &[python.as_os_str(), cat.as_os_str()]);
    js.start_job(&typed(&argv));
    js.outer.expect("CAT-READY", 1, "cat");
    js.outer.type_bytes(b"line-one\r");
    js.outer
        .expect("line-one", 2, "a line round-trips through cat");
    js.outer.type_bytes(&[0x1a]);
    js.outer.expect(
        "paused at exec.pty.stopped",
        1,
        "the runner held the report",
    );
    js.outer.type_bytes(b"fg\r");
    std::fs::write(&release, b"").unwrap();
    js.prompt_again("the stop gave the outer shell its prompt back");
    js.job_stopped();
    assert_eq!(js.stty_g(&case.path("after")), before, "the outer terminal");
    js.outer.type_bytes(b"fg\r");
    js.outer.type_bytes(b"line-two\r");
    js.outer
        .expect("line-two", 2, "a fresh line round-trips after fg");
    js.outer.type_bytes(b"\x04");
    js.prompt_again("cat and the runner ended");
    js.exit();
}

/// Two suspend characters in one write: the command stops once (the
/// second finds its group stopped, or the monitor's in the foreground, and
/// SIGCONT discards a stop signal still pending), the outer shell's prompt
/// comes back once, and after `fg` cat reads on and the run ends with it,
/// with no second stop.
fn two_suspend_characters_in_one_read_stop_the_command_once() {
    let case = Case::new();
    let mut js = JobShell::start(&case, &[]);
    let before = js.stty_g(&case.path("before"));
    let cat = case.script("cat.py", RETRY_CAT);
    let python = python3();
    let argv = case.runner_argv(&[], &[], &[python.as_os_str(), cat.as_os_str()]);
    js.start_job(&typed(&argv));
    js.outer.expect("CAT-READY", 1, "cat");
    js.outer.type_bytes(b"line-one\r");
    js.outer
        .expect("line-one", 2, "a line round-trips through cat");
    js.outer.type_bytes(&[0x1a, 0x1a]);
    js.prompt_again("the stop gave the outer shell its prompt back");
    js.job_stopped();
    assert_eq!(js.stty_g(&case.path("after")), before, "the outer terminal");
    let prompts = js.outer.count(PROMPT);
    js.outer.type_bytes(b"fg\r");
    js.outer.type_bytes(b"line-two\r");
    js.outer
        .expect("line-two", 2, "a fresh line round-trips after fg");
    assert_eq!(js.outer.count(PROMPT), prompts, "a second stop");
    js.outer.type_bytes(b"\x04");
    js.prompt_again("cat and the runner ended");
    js.exit();
}

/// SIGCONT sent to the runner while it drains the command's output after
/// the exit (held at the exit's report): raw mode and the size are taken
/// again, and nothing else changes: every line comes, redacted, the run
/// ends with the command's status, and the outer terminal is as before.
/// The runner's own line about its pause goes to the same terminal and
/// can land inside a marker it had half written (the verifier's review of
/// M2-19: `[envcloak:openai_api_ke<pause line>y/t]`), so it is taken out
/// before anything is counted.
fn a_sigcont_while_the_output_drains_loses_nothing() {
    let case = Case::new();
    let release = case.path("go");
    let mut outer = Outer::new(24, 80);
    let before = outer.settings();
    let script = r#"i=0; while [ $i -lt 300 ]; do printf '%s line %d\n' "$OPENAI_API_KEY" $i; i=$((i+1)); done; exit 7"#;
    let argv = case.runner_argv(
        &["OPENAI_API_KEY:OPENAI_API_KEY"],
        &[],
        &[OsStr::new("/bin/sh"), OsStr::new("-c"), OsStr::new(script)],
    );
    let mut run = Running {
        child: detach(
            &case,
            &outer,
            &argv,
            &pause_env("exec.pty.exited", &release),
        ),
    };
    outer.expect("paused at exec.pty.exited", 1, "the runner held the exit");
    run.signal(libc::SIGCONT);
    std::fs::write(&release, b"").unwrap();
    let status = outer.wait_exit(&mut run.child, DEADLINE);
    assert_eq!(status.code(), Some(7), "{}", outer.text());
    let shown = without_once(&outer.seen, b"envcloak test: paused at exec.pty.exited\n");
    let m = marker(labels::OPENAI_API_KEY);
    assert_eq!(count(&shown, m.as_bytes()), 300, "{}", outer.text());
    for i in 0..300 {
        let line = format!("{m} line {i}\r\n");
        assert_eq!(
            count(&shown, line.as_bytes()),
            1,
            "line {i}: {}",
            outer.text()
        );
    }
    assert!(outer.settings().same_as(&before), "the outer terminal");
    case.assert_clean(&outer.seen);
}

/// `hay` with the first `needle` in it taken out (a harness line the
/// runner wrote to the terminal under test), or as it is.
fn without_once(hay: &[u8], needle: &[u8]) -> Vec<u8> {
    match hay.windows(needle.len()).position(|w| w == needle) {
        Some(at) => [&hay[..at], &hay[at + needle.len()..]].concat(),
        None => hay.to_vec(),
    }
}

/// D-35's order at its last barrier: when the runner is held just before
/// it sends `Resume` (`exec.pty.resume`, after the person's `fg`), the
/// outer terminal is raw again already and the command is still stopped,
/// for as long as it is held; once let go, the command reads on.
///
/// Mutation checked: send `Resume` before re-entering raw mode (the
/// verifier's review of M2-19 asked for this case, as the end-to-end round
/// trip cannot tell): the command is running at the barrier, and this
/// fails.
fn the_command_is_resumed_only_once_the_outer_terminal_is_raw_again() {
    let case = Case::new();
    let release = case.path("go");
    let mut js = JobShell::start(&case, &pause_env("exec.pty.resume", &release));
    let counter = case.script("counter.py", COUNTER);
    let python = python3();
    let argv = case.runner_argv(
        &[],
        &[],
        &[
            python.as_os_str(),
            counter.as_os_str(),
            case.dir.path().as_os_str(),
            OsStr::new("job"),
        ],
    );
    js.start_job(&typed(&argv));
    js.outer.expect("JOB-READY", 1, "the command");
    let pid = job_pid(&js.outer);
    js.outer.type_bytes(b"one\r");
    js.outer.expect("GOT [one]", 1, "a line read");
    js.outer.type_bytes(&[0x1a]);
    js.prompt_again("the suspend character gave the outer shell its prompt back");
    js.job_stopped();
    js.outer.type_bytes(b"fg\r");
    js.outer.expect(
        "paused at exec.pty.resume",
        1,
        "the runner held before Resume",
    );
    // Held there: raw, and the command stopped, throughout.
    let watch = Instant::now() + Duration::from_millis(300);
    loop {
        assert!(
            js.outer.settings().is_raw(),
            "the outer terminal is not raw before Resume"
        );
        let state = state_of(pid);
        assert!(
            state.starts_with('T'),
            "the command runs before Resume: state {state:?}"
        );
        if Instant::now() >= watch {
            break;
        }
        js.outer
            .wait_for_within(Duration::from_millis(50), |_| false);
    }
    std::fs::write(&release, b"").unwrap();
    js.outer.type_bytes(b"two\r");
    js.outer
        .expect("GOT [two]", 1, "the command read on after Resume");
    js.outer.type_bytes(b"done\r");
    js.prompt_again("the command and the runner ended");
    js.exit();
}

/// Codex's review of M2-19 (high): raw mode that cannot be taken again
/// after `fg` (a test build's injected failure in the suspension's own
/// step, `exec.pty.raw`; the SIGCONT that follows takes raw mode as ever)
/// resumes nothing. The command stays stopped and gets no key: the run
/// ends at once, 125 with `run_failed`, the outer shell's prompt comes
/// back with the terminal as before, and the command is hung up with its
/// session.
///
/// Mutation checked: ignore the failure and resume the command (as before
/// the review): the run goes on, no prompt comes, and this fails.
fn raw_mode_refused_after_fg_resumes_nothing_and_ends_the_run() {
    let case = Case::new();
    let mut js = JobShell::start(&case, &[("ENVCLOAK_TEST_FAIL", OsStr::new("exec.pty.raw"))]);
    let before = js.stty_g(&case.path("before"));
    let counter = case.script("counter.py", COUNTER);
    let python = python3();
    let argv = case.runner_argv(
        &[],
        &[],
        &[
            python.as_os_str(),
            counter.as_os_str(),
            case.dir.path().as_os_str(),
            OsStr::new("job"),
        ],
    );
    js.start_job(&typed(&argv));
    js.outer.expect("JOB-READY", 1, "the command");
    js.outer.type_bytes(b"one\r");
    js.outer.expect("GOT [one]", 1, "a line read");
    js.outer.type_bytes(&[0x1a]);
    js.prompt_again("the suspend character gave the outer shell its prompt back");
    js.job_stopped();
    js.outer.type_bytes(b"fg\r");
    js.prompt_again("the run ended without resuming the command");
    assert_eq!(
        js.outer
            .count("envcloak: run_failed: your terminal could not be put back in raw mode"),
        1,
        "{}",
        js.outer.text()
    );
    assert_eq!(js.status(), 125);
    assert_eq!(js.stty_g(&case.path("after")), before, "the outer terminal");
    // Hung up with its session: its group, orphaned with a stopped member
    // once the monitor is gone, gets SIGHUP and SIGCONT from the kernel.
    assert!(
        wait_lines(&mut js.outer, &case.path("job-HUP"), 1),
        "the stopped command was not hung up"
    );
    js.exit();
}

/// The same class on the other path to raw mode (Codex's review of M2-19,
/// swept): a SIGCONT the suspension did not wait for (the runner stopped
/// by another process, or continued twice) takes raw mode again before the
/// command reads another key; refused there (`exec.pty.raw-on-sigcont`),
/// the run ends at once, 125 with `run_failed`, no key typed after it
/// reaches the command, and the outer terminal is as before.
///
/// Mutation checked: ignore the failure there (as before the review): the
/// run goes on, the typed line reaches the command, the run exits 0, and
/// this fails.
fn raw_mode_refused_on_sigcont_ends_the_run() {
    let case = Case::new();
    let counter = case.script("counter.py", COUNTER);
    let mut outer = Outer::new(24, 80);
    let before = outer.settings();
    let python = python3();
    let argv = case.runner_argv(
        &[],
        &[],
        &[
            python.as_os_str(),
            counter.as_os_str(),
            case.dir.path().as_os_str(),
            OsStr::new("job"),
        ],
    );
    let mut run = Running {
        child: detach(
            &case,
            &outer,
            &argv,
            &[("ENVCLOAK_TEST_FAIL", OsStr::new("exec.pty.raw-on-sigcont"))],
        ),
    };
    outer.expect("JOB-READY", 1, "the command");
    outer.type_bytes(b"one\r");
    outer.expect("GOT [one]", 1, "a line read");
    run.signal(libc::SIGCONT);
    outer.expect("envcloak: run_failed: ", 1, "the run ended");
    outer.type_bytes(b"two\r");
    let status = outer.wait_exit(&mut run.child, DEADLINE);
    assert_eq!(status.code(), Some(125), "{}", outer.text());
    assert_eq!(outer.count("GOT [two]"), 0, "{}", outer.text());
    assert!(outer.settings().same_as(&before), "the outer terminal");
}

/// A terminal-owning parent performs the shell's job-control steps. Unlike
/// bash's fg, it does not repair the child's final settings. Both an
/// outside stop and a monitor-reported stop must wait for the foreground
/// before saving settings. The temporary line-editor mode is not raw:
/// ISIG remains on, as at zsh's prompt.
fn background_continues_never_save_the_shells_line_editor_settings() {
    let case = Case::new();
    let controller = case.script(
        "foreground.py",
        r"import copy, os, signal, subprocess, sys, termios, time
ready, route, *argv = sys.argv[1:]
end = time.monotonic() + 20
before = termios.tcgetattr(0)
parent = os.getpgrp()
signal.signal(signal.SIGTTOU, signal.SIG_IGN)
def child_setup():
    os.setpgid(0, 0)
    signal.signal(signal.SIGTTOU, signal.SIG_DFL)
p = subprocess.Popen(argv, preexec_fn=child_setup)
reaped = False
def stopped():
    global reaped
    while time.monotonic() < end:
        pid, status = os.waitpid(p.pid, os.WUNTRACED | os.WNOHANG)
        if pid:
            if os.WIFSTOPPED(status): return
            reaped = True
            raise AssertionError('runner exited before stop')
    raise AssertionError('runner did not stop')
try:
    os.tcsetpgrp(0, p.pid)
    # A background start may have stopped at its first terminal write.
    os.kill(p.pid, signal.SIGCONT)
    while not os.path.exists(ready):
        assert time.monotonic() < end, 'command never ready'
    os.kill(p.pid, getattr(signal, 'SIG' + route))
    stopped()
    os.tcsetpgrp(0, parent)
    editor = copy.deepcopy(before)
    editor[3] &= ~(termios.ICANON | termios.ECHO)
    editor[3] |= termios.ISIG
    editor[6][termios.VSUSP] = bytes([os.fpathconf(0, 'PC_VDISABLE')])
    termios.tcsetattr(0, termios.TCSANOW, editor)
    editor = termios.tcgetattr(0)
    os.kill(p.pid, signal.SIGCONT)
    stopped()
    # The editor's settings stay its own while the job is in background.
    assert termios.tcgetattr(0) == editor, 'background job changed editor'
    termios.tcsetattr(0, termios.TCSANOW, before)
    os.tcsetpgrp(0, p.pid)
    os.kill(p.pid, signal.SIGCONT)
    while termios.tcgetattr(0)[3] & (termios.ICANON | termios.ECHO | termios.ISIG):
        assert time.monotonic() < end, 'foreground job never took raw mode'
    os.write(1, b'FOREGROUND\n')
    status = p.wait(timeout=max(0.1, end-time.monotonic()))
    reaped = True
    assert status == 0
    os.tcsetpgrp(0, parent)
    os.write(1, b'CHECK-SETTINGS\n')
    # Like a shell reading the next stty command, consume pending input.
    # Darwin clears its transient PENDIN bit on this read.
    assert os.read(0, 100) == b'check\n'
    assert termios.tcgetattr(0) == before, 'saved the line editor settings'
    os.write(1, b'RESTORED\n')
finally:
    if not reaped:
        os.killpg(p.pid, signal.SIGKILL)
        p.wait(timeout=5)
    os.tcsetpgrp(0, parent)
    termios.tcsetattr(0, termios.TCSANOW, before)
",
    );
    let cat = case.script(
        "cat.py",
        &format!(
            "import pathlib\npathlib.Path({:?}).touch()\n{RETRY_CAT}",
            case.path("ready").to_str().unwrap()
        ),
    );
    let python = python3();
    let mut outcomes = Vec::new();
    for route in ["STOP", "TSTP"] {
        let ready = case.path("ready");
        if ready.exists() {
            std::fs::remove_file(&ready).unwrap();
        }
        let runner = case.runner_argv(&[], &[], &[python.as_os_str(), cat.as_os_str()]);
        let mut argv = vec![
            python.clone().into_os_string(),
            controller.clone().into_os_string(),
            ready.into_os_string(),
            route.into(),
        ];
        argv.extend(runner);
        let mut outer = Outer::new(24, 80);
        let mut run = Running {
            child: lead(&case, &outer, &argv, &[]),
        };
        outer.expect("FOREGROUND", 1, "the job regained its terminal");
        outer.type_bytes(b"after-fg\r");
        outer.expect("after-fg", 2, "the echo and resumed cat");
        outer.type_bytes(b"\x04");
        outer.expect("CHECK-SETTINGS", 1, "the terminal owner regained control");
        outer.type_bytes(b"check\r");
        let status = outer.wait_exit(&mut run.child, DEADLINE);
        outcomes.push((route, status.code(), outer.count("RESTORED")));
    }
    assert_eq!(outcomes, vec![("STOP", Some(0), 1), ("TSTP", Some(0), 1)]);
}

/// The verifier's review of M2-19 (L-09): what the person changes on
/// their terminal while the job is stopped is what the run takes from
/// then on. `stty susp '^X'` made at the outer shell's prompt: after `fg`
/// the remapped character reaches the command's terminal as its suspend
/// character (^X stops the command), and the restores put the remapped
/// settings back, at the next stop and at the end of the run (`stty -g`
/// equal to what the person set, not to the settings from before the
/// run).
///
/// Mutation checked: take raw mode and later restores from the settings
/// saved at the start (no `refresh_settings` after the stop): ^X reaches
/// cat as data, no prompt comes back, and this fails.
fn a_stty_change_made_while_stopped_reaches_the_command_and_stays() {
    let case = Case::new();
    let mut js = JobShell::start(&case, &[]);
    let before = js.stty_g(&case.path("before"));
    let cat = case.script("cat.py", RETRY_CAT);
    let python = python3();
    let argv = case.runner_argv(&[], &[], &[python.as_os_str(), cat.as_os_str()]);
    js.start_job(&typed(&argv));
    js.outer.expect("CAT-READY", 1, "cat");
    js.outer.type_bytes(b"line-one\r");
    js.outer
        .expect("line-one", 2, "a line round-trips through cat");
    js.outer.type_bytes(&[0x1a]);
    js.prompt_again("the suspend character gave the outer shell its prompt back");
    js.job_stopped();
    assert_eq!(js.stty_g(&case.path("after")), before, "the outer terminal");
    js.say("stty susp '^X'");
    let remapped = js.stty_g(&case.path("remapped"));
    assert_ne!(remapped, before);
    js.outer.type_bytes(b"fg\r");
    js.outer.type_bytes(b"line-two\r");
    js.outer
        .expect("line-two", 2, "a fresh line round-trips after fg");
    js.outer.type_bytes(&[0x18]);
    js.prompt_again("the remapped suspend character stopped the command");
    js.job_stopped();
    assert_eq!(
        js.stty_g(&case.path("after-x")),
        remapped,
        "the outer terminal at the second stop"
    );
    js.outer.type_bytes(b"fg\r");
    js.outer.type_bytes(b"line-three\r");
    js.outer.expect(
        "line-three",
        2,
        "a fresh line round-trips after the second fg",
    );
    js.outer.type_bytes(b"\x04");
    js.prompt_again("cat and the runner ended");
    assert_eq!(
        js.stty_g(&case.path("end")),
        remapped,
        "the outer terminal after the run"
    );
    js.say("stty susp '^Z'");
    js.exit();
}

// ---------------------------------------------------------------------------
// The monitor's death, /dev/tty, the cutoff, an abort.

/// The monitor dies (a test build kills it, SIGKILL through the runner's
/// own handle, when it has read a key): the kernel hangs the session up,
/// so the command gets SIGHUP; the runner restores the outer terminal,
/// drains the output redacted and exits 125 with `pty_monitor_lost`.
fn a_monitor_that_dies_hangs_the_command_up_and_the_run_fails_monitor_lost() {
    let case = Case::new();
    let ticker = case.script("ticker.py", TICKER);
    let stop = case.path("stop");
    let mut outer = Outer::new(24, 80);
    let before = outer.settings();
    let python = python3();
    let argv = case.runner_argv(
        &["OPENAI_API_KEY:OPENAI_API_KEY"],
        &[],
        &[
            python.as_os_str(),
            ticker.as_os_str(),
            case.dir.path().as_os_str(),
            stop.as_os_str(),
            OsStr::new("OPENAI_API_KEY"),
        ],
    );
    let mut run = Running {
        child: detach(
            &case,
            &outer,
            &argv,
            &[("ENVCLOAK_TEST_FAIL", OsStr::new("exec.pty.keys"))],
        ),
    };
    outer.expect("tick 3 ", 1, "the command ticks");
    outer.type_bytes(b"k");
    let status = outer.wait_exit(&mut run.child, DEADLINE);
    let _ = std::fs::write(&stop, b"");
    assert_eq!(status.code(), Some(125), "{}", outer.text());
    assert_eq!(
        outer.count("envcloak: pty_monitor_lost: "),
        1,
        "{}",
        outer.text()
    );
    assert!(
        wait_lines(&mut outer, &case.path("job-HUP"), 1),
        "the command did not get SIGHUP"
    );
    assert!(outer.settings().same_as(&before), "the outer terminal");
    assert!(outer.count(&marker(labels::OPENAI_API_KEY)) >= 3);
    case.assert_clean(&outer.seen);
}

/// Linux keeps the slave writable after its session leader dies. macOS
/// revokes it instead, so the existing hangup gate covers that platform.
/// The writer ignores HUP and emits numbered values only after the relay
/// has marked its monitor lost. A write receipt precedes releasing the
/// relay's drain, so a pre-loss redaction cannot satisfy this gate.
#[cfg(target_os = "linux")]
fn output_written_after_monitor_loss_is_still_redacted() {
    let case = Case::new();
    let writer = case.script(
        "after-loss.py",
        r"import os, pathlib, select, signal, sys, time
root = pathlib.Path(sys.argv[1])
signal.signal(signal.SIGHUP, signal.SIG_IGN)
value = os.environ['OPENAI_API_KEY'].encode()
def emit(line):
    while line:
        line = line[os.write(1, line):]
emit(b'BEFORE-LOSS ' + value + b'\n')
end = time.monotonic() + 15
while not (root / 'write-after-loss').exists():
    if not root.exists() or time.monotonic() >= end:
        sys.exit(2)
    select.select([], [], [], 0.01)
for n in range(1, 4):
    emit(b'AFTER-LOSS %d ' % n + value + b' \xff\x00\n')
(root / 'written-after-loss').write_text('3\n')",
    );
    let mut outer = Outer::new(24, 80);
    let before = outer.settings();
    let python = python3();
    let release = case.path("drain");
    let argv = case.runner_argv(
        &["OPENAI_API_KEY:OPENAI_API_KEY"],
        &[],
        &[
            python.as_os_str(),
            writer.as_os_str(),
            case.dir.path().as_os_str(),
        ],
    );
    let mut run = Running {
        child: detach(
            &case,
            &outer,
            &argv,
            &[
                ("ENVCLOAK_TEST_FAIL", OsStr::new("exec.pty.keys")),
                ("ENVCLOAK_TEST_PAUSE", OsStr::new("exec.pty.monitor-lost")),
                ("ENVCLOAK_TEST_PAUSE_RELEASE", release.as_os_str()),
            ],
        ),
    };
    let masked = marker(labels::OPENAI_API_KEY);
    outer.expect(
        &format!("BEFORE-LOSS {masked}"),
        1,
        "the writer's first value",
    );
    outer.type_bytes(b"k");
    outer.expect(
        "envcloak test: paused at exec.pty.monitor-lost",
        1,
        "the relay has observed the monitor's loss",
    );
    let after_loss = outer.seen.len();
    std::fs::write(case.path("write-after-loss"), b"").unwrap();
    assert!(
        outer.wait_for_within(DEADLINE, |_| case.path("written-after-loss").exists()),
        "the surviving writer did not finish its post-loss writes"
    );
    std::fs::write(&release, b"").unwrap();
    let status = outer.wait_exit(&mut run.child, DEADLINE);
    assert_eq!(status.code(), Some(125), "{}", outer.text());
    assert_eq!(
        outer.count("envcloak: pty_monitor_lost: "),
        1,
        "{}",
        outer.text()
    );
    for n in 1..=3 {
        let line = format!("AFTER-LOSS {n} {masked} ");
        assert_eq!(outer.count_since(after_loss, &line), 1, "{}", outer.text());
    }
    assert!(outer.settings().same_as(&before), "the outer terminal");
    case.assert_clean(&outer.seen);
}

/// The monitor dies once it has reported the command's exit: the run
/// still ends with the command's status, its output redacted.
fn a_monitor_that_dies_after_the_exit_report_keeps_the_commands_status() {
    let case = Case::new();
    let mut outer = Outer::new(24, 80);
    let argv = case.runner_argv(
        &["OPENAI_API_KEY:OPENAI_API_KEY"],
        &[],
        &[
            OsStr::new("/bin/sh"),
            OsStr::new("-c"),
            OsStr::new(r#"printf '%s\n' "$OPENAI_API_KEY"; read x; exit 5"#),
        ],
    );
    let mut run = Running {
        child: lead(
            &case,
            &outer,
            &argv,
            &[("ENVCLOAK_TEST_FAIL", OsStr::new("exec.pty.exited"))],
        ),
    };
    // The line is read before the command exits: the monitor's death skips
    // its wait for a late reader, and macOS drops what is unread at the
    // slave's last close.
    outer.expect(&marker(labels::OPENAI_API_KEY), 1, "the command's line");
    outer.type_bytes(b"\r");
    let status = outer.wait_exit(&mut run.child, DEADLINE);
    assert_eq!(status.code(), Some(5), "{}", outer.text());
    assert_eq!(outer.count(&marker(labels::OPENAI_API_KEY)), 1);
    assert_eq!(outer.count("pty_monitor_lost"), 0, "{}", outer.text());
    case.assert_clean(&outer.seen);
}

/// What the command writes to its controlling terminal by name
/// (`/dev/tty`) is the PTY's, and is redacted like the rest.
fn the_commands_own_dev_tty_writes_are_redacted() {
    let case = Case::new();
    let mut outer = Outer::new(24, 80);
    let argv = case.runner_argv(
        &["OPENAI_API_KEY:OPENAI_API_KEY"],
        &[],
        &[
            OsStr::new("/bin/sh"),
            OsStr::new("-c"),
            OsStr::new(r#"printf 'tty:%s\n' "$OPENAI_API_KEY" > /dev/tty; echo done"#),
        ],
    );
    let mut run = Running {
        child: lead(&case, &outer, &argv, &[]),
    };
    let status = outer.wait_exit(&mut run.child, DEADLINE);
    assert_eq!(status.code(), Some(0), "{}", outer.text());
    let m = format!("tty:{}", marker(labels::OPENAI_API_KEY));
    assert_eq!(outer.count(&m), 1, "{}", outer.text());
    case.assert_clean(&outer.seen);
}

/// A run ends when its command does, with nothing left holding the
/// terminal: `/bin/sh` (bash on macOS, whose session then keeps the PTY
/// open until the session's leader exits) prints a line and exits, and the
/// run ends well before the 2-second cutoff.
///
/// Mutation checked: keep the monitor's channel open until the output's
/// end (no `end_channel` at the exit's report): on macOS every run waits
/// out the cutoff, and this fails.
fn the_run_ends_when_its_command_does() {
    let case = Case::new();
    for _ in 0..3 {
        let mut outer = Outer::new(24, 80);
        let argv = case.runner_argv(
            &[],
            &[],
            &[
                OsStr::new("/bin/sh"),
                OsStr::new("-c"),
                OsStr::new("echo done-here"),
            ],
        );
        let mut run = Running {
            child: lead(&case, &outer, &argv, &[]),
        };
        outer.expect("done-here", 1, "the command's line");
        let shown = Instant::now();
        let status = outer.wait_exit(&mut run.child, DEADLINE);
        let took = shown.elapsed();
        println!("pty end: the run ended {took:?} after the command's last line");
        assert_eq!(status.code(), Some(0), "{}", outer.text());
        assert!(took < Duration::from_millis(1500), "{took:?}");
    }
}

/// The command exits while a background process it started (ignoring
/// SIGHUP) still holds the terminal and writes values to it. The session
/// ends at the exit: on Linux the descendant keeps the terminal, the run
/// reads on for 2 seconds from the exit, one deadline (not the monitor's
/// wait and then a second one), then closes the PTY; on macOS the
/// session's end revokes the terminal for the descendant, so the run ends
/// at once. Either way the run exits with the command's status, what the
/// descendant writes after that is lost, and nothing passes unredacted.
///
/// Mutation checked: pass the bytes through after the cutoff (the master
/// read on and written to the outer terminal unredacted): the
/// descendant's values show and the run does not end at the cutoff, and
/// this fails.
fn a_grandchild_holding_the_terminal_is_cut_off_2_s_after_the_exit() {
    let case = Case::new();
    let stop = case.path("stop");
    let ended = case.path("ended");
    let script = case.script(
        "leaves.sh",
        r#"( trap '' HUP
  i=0
  while [ ! -e "$1" ] && [ $i -lt 600 ]; do
    printf 'late %d %s\n' $i "$OPENAI_API_KEY" 2>/dev/null
    i=$((i+1))
    sleep 0.05
  done
  echo ended > "$2" ) &
echo EXITING
exit 4
"#,
    );
    let mut outer = Outer::new(24, 80);
    let argv = case.runner_argv(
        &["OPENAI_API_KEY:OPENAI_API_KEY"],
        &[],
        &[
            OsStr::new("/bin/sh"),
            script.as_os_str(),
            stop.as_os_str(),
            ended.as_os_str(),
        ],
    );
    let mut run = Running {
        child: lead(&case, &outer, &argv, &[]),
    };
    outer.expect("EXITING", 1, "the command's last line");
    let exited = Instant::now();
    let status = outer.wait_exit(&mut run.child, DEADLINE);
    let took = exited.elapsed();
    let after = outer.seen.len();
    outer.wait_for_within(Duration::from_millis(300), |_| false);
    std::fs::write(&stop, b"").unwrap();
    println!(
        "pty cutoff ({}): the run ended {took:?} after the command's exit, with {} late \
         line(s)",
        std::env::consts::OS,
        outer.count("late ")
    );
    assert_eq!(status.code(), Some(4), "{}", outer.text());
    if cfg!(target_os = "macos") {
        // The session's end revoked the terminal for the descendant.
        assert!(took < Duration::from_millis(1500), "{took:?}");
    } else {
        assert!(
            took >= Duration::from_millis(1500) && took < Duration::from_millis(3500),
            "{took:?}"
        );
        assert!(outer.count("late ") >= 1, "{}", outer.text());
    }
    assert_eq!(outer.seen.len(), after, "output after the runner's exit");
    case.assert_clean(&outer.seen);
    // The descendant, given its stop, ends.
    let gone = outer.wait_for_within(DEADLINE, |_| ended.exists());
    assert!(gone, "the descendant did not end");
}

/// The verifier's review of M2-19: a command writes more than the runner
/// may hold for its reader while it runs ([`OUTPUT_LIMIT`]), and exits,
/// while the reader reads nothing until longer than the cutoff after the
/// exit. No process holds the PTY any more, so nothing is given up: the
/// runner reads on after the exit whatever the reader does, the PTY ends,
/// and every line the command wrote arrives, redacted, at the reader's
/// pace, with the command's status.
///
/// Mutation checked: read no further than `OUTPUT_LIMIT` after the exit
/// (the read limit before the review): the PTY never reaches its end, the
/// cutoff gives up what the reader had not taken (about 1 KiB arrived of
/// 67 KiB in the verifier's run), and this fails.
fn a_slow_reader_gets_everything_a_command_wrote_before_it_exited() {
    let case = Case::new();
    let writer = case.script("writer.py", SLOW_WRITER);
    let record = case.path("wrote");
    let mut outer = Outer::new(24, 80);
    let python = python3();
    let argv = case.runner_argv(
        &["OPENAI_API_KEY:OPENAI_API_KEY"],
        &[],
        &[
            python.as_os_str(),
            writer.as_os_str(),
            record.as_os_str(),
            OsStr::new("OPENAI_API_KEY"),
        ],
    );
    let mut run = Running {
        child: lead(&case, &outer, &argv, &[]),
    };
    // The reader reads nothing while the command writes, nor until the
    // cutoff has long passed after its exit: the scenario itself, an idle
    // reader, not a wait for something to happen.
    let end = Instant::now() + DEADLINE;
    while !record.exists() {
        assert!(Instant::now() < end, "the command never finished writing");
        std::thread::sleep(Duration::from_millis(10));
    }
    std::thread::sleep(DRAIN_LIMIT + Duration::from_secs(1));
    let status = outer.wait_exit(&mut run.child, DEADLINE);
    let wrote = std::fs::read_to_string(&record).unwrap();
    let mut words = wrote
        .split_whitespace()
        .map(|w| w.parse::<usize>().unwrap());
    let (bytes, lines) = (words.next().unwrap(), words.next().unwrap());
    println!(
        "pty slow reader ({}): the command wrote {bytes} bytes ({lines} whole lines; the \
         runner holds {OUTPUT_LIMIT} for a reader while it runs) and exited; {} bytes arrived",
        std::env::consts::OS,
        outer.seen.len()
    );
    assert_eq!(status.code(), Some(0), "{}", outer.text());
    let mut missing = Vec::new();
    for i in 0..lines {
        if outer.count(&format!("line {i:06} ")) != 1 {
            missing.push(i);
        }
    }
    assert!(
        missing.is_empty(),
        "{} of {lines} lines did not arrive once (first {:?})",
        missing.len(),
        missing.iter().take(5).collect::<Vec<_>>()
    );
    assert_eq!(
        outer.count(&marker(labels::OPENAI_API_KEY)),
        lines.div_ceil(97),
        "{}",
        outer.text()
    );
    case.assert_clean(&outer.seen);
}

/// What a PTY holds with nobody reading its master side, on the system
/// this runs on (a non-blocking writer fills its slave side until a write
/// would wait): far less than what the relay reads on after the command's
/// exit ([`EXIT_READ_LIMIT`]), so a PTY no process holds always reaches
/// its end. docs/RUN.md's figures come from here.
fn a_pty_holds_far_less_than_the_relay_reads_after_the_exit() {
    let pty = open_pty(None, None).unwrap();
    envcloak_sys::set_nonblocking(pty.slave.as_fd()).unwrap();
    let slave = File::from(pty.slave);
    let mut held = 0usize;
    for size in [4096, 1] {
        let chunk = vec![b'x'; size];
        loop {
            match (&slave).write(&chunk) {
                Ok(n) => held += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("{e}"),
            }
            assert!(held <= EXIT_READ_LIMIT, "the PTY took {held} bytes");
        }
    }
    println!(
        "pty capacity ({}): {held} bytes with nobody reading",
        std::env::consts::OS
    );
    assert!(held > 0);
    assert!(held * 16 <= EXIT_READ_LIMIT, "{held}");
    drop(pty.master);
}

/// Codex's review of M2-19: a SIGTERM caught once the output has been
/// delivered, before the run's result is chosen (the runner held there,
/// `exec.pty.ended`), still ends the run with 128 plus its number (or, had
/// it come after the line the runner draws, by SIGTERM itself), never with
/// the command's status; the outer terminal is restored.
///
/// Mutation checked: choose the result without reading the signals caught
/// since the loop's last look (`after_the_boundary` returning the result
/// as it is): the run exits 3, and this fails.
fn a_sigterm_caught_after_the_last_output_still_ends_the_run_with_143() {
    let case = Case::new();
    let release = case.path("go");
    let mut outer = Outer::new(24, 80);
    let before = outer.settings();
    let argv = case.runner_argv(
        &[],
        &[],
        &[
            OsStr::new("/bin/sh"),
            OsStr::new("-c"),
            OsStr::new("echo LAST-LINE; exit 3"),
        ],
    );
    let mut run = Running {
        child: detach(&case, &outer, &argv, &pause_env("exec.pty.ended", &release)),
    };
    outer.expect("paused at exec.pty.ended", 1, "the runner held its result");
    assert_eq!(outer.count("LAST-LINE"), 1, "{}", outer.text());
    run.signal(libc::SIGTERM);
    std::fs::write(&release, b"").unwrap();
    let status = outer.wait_exit(&mut run.child, DEADLINE);
    assert!(
        status.code() == Some(143) || status.signal() == Some(libc::SIGTERM),
        "{status:?}: {}",
        outer.text()
    );
    assert!(outer.settings().same_as(&before), "the outer terminal");
}

/// A panic in the relay, with the outer terminal raw and the command
/// running, ended as a release build ends one (the hook, then `abort`: no
/// destructor runs): the hook puts the outer terminal back as it was, echo
/// on, and prints its one line, never the message.
///
/// Mutation checked: skip the panic hook's restore
/// (`restore_outer_terminal` in `envcloak_sys::install_panic_hook`): the
/// terminal is left raw, echo off, and this fails.
fn a_panic_that_aborts_leaves_the_outer_terminal_as_it_was() {
    let case = Case::new();
    let mut outer = Outer::new(24, 80);
    let before = outer.settings();
    assert!(before.echo());
    let argv = case.runner_argv(&[], &["--abort"], &[OsStr::new("/bin/cat")]);
    let mut run = Running {
        child: detach(
            &case,
            &outer,
            &argv,
            &[("ENVCLOAK_TEST_PANIC", OsStr::new("exec.pty.relay"))],
        ),
    };
    let status = outer.wait_exit(&mut run.child, DEADLINE);
    assert_eq!(status.signal(), Some(libc::SIGABRT), "{}", outer.text());
    let now = outer.settings();
    assert!(now.echo(), "echo is off after the abort");
    assert!(now.same_as(&before), "the outer terminal was not restored");
    assert_eq!(
        outer.count("envcloak: internal error: a panic at "),
        1,
        "{}",
        outer.text()
    );
    assert_eq!(outer.count("panicked at"), 0, "{}", outer.text());
}

// ---------------------------------------------------------------------------
// An agent-style host, no terminal, and `ps`.

/// An agent-style host: a PTY of its own (Python's `pty.fork`, standing in
/// for Codex's `tty: true` and Gemini's `node-pty`) runs the runner, whose
/// command writes a value in pieces with pauses; the host reads in polled
/// reads of at most 7 bytes, so its reads split what it is shown, and
/// writes 200 lines in one burst. What the host collects holds no value,
/// in any encoding, even read whole; the value's marker is there; and each
/// burst line comes back once (the command's copy; the host's terminal
/// does not echo), none lost.
fn an_agent_style_outer_pty_with_burst_input_and_polled_reads_sees_no_value() {
    let case = Case::new();
    let split = case.script("split.py", SPLIT_THEN_CAT);
    let agent = case.script("agent.py", AGENT);
    let python = python3();
    let argv = case.runner_argv(
        &["OPENAI_API_KEY:OPENAI_API_KEY"],
        &[],
        &[
            python.as_os_str(),
            split.as_os_str(),
            OsStr::new("OPENAI_API_KEY"),
        ],
    );
    let mut cmd = Command::new(&python);
    case.home.apply(&mut cmd);
    cmd.arg(&agent)
        .arg("200")
        .args(&argv)
        .current_dir(case.dir.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = cmd.output().unwrap();
    // Swept before anything quotes it.
    assert_no_canary(&out.stdout, &case.cs);
    assert_no_canary(&out.stderr, &case.cs);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let (first, rest) = out
        .stdout
        .split_at(out.stdout.iter().position(|b| *b == b'\n').unwrap() + 1);
    assert_eq!(
        first,
        b"EXIT 0\n",
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert_eq!(
        count(rest, marker(labels::OPENAI_API_KEY).as_bytes()),
        1,
        "{}",
        String::from_utf8_lossy(rest)
    );
    for i in [0, 99, 199] {
        let line = format!("burst-{i:04}\r\n");
        assert_eq!(count(rest, line.as_bytes()), 1, "{line:?}");
    }
    assert_eq!(count(rest, b"burst-"), 200);
    case.home.assert_clean(&case.cs);
}

/// `--pty` needs a terminal on standard input and standard output: with a
/// pipe on either, the run exits 125 with `pty_unavailable` and starts
/// nothing (the command would leave a file); it never falls back to pipe
/// mode.
///
/// Mutation checked: fall back to pipe mode when the terminal cannot be
/// opened: the command runs (its file appears, the exit is 0), and this
/// fails.
fn without_a_terminal_on_both_sides_pty_mode_is_unavailable() {
    let case = Case::new();
    let outer = Outer::new(24, 80);
    let started = case.path("STARTED");
    let touch = format!("touch '{}'", started.display());
    let argv = case.runner_argv(
        &["OPENAI_API_KEY:OPENAI_API_KEY"],
        &[],
        &[OsStr::new("/bin/sh"), OsStr::new("-c"), OsStr::new(&touch)],
    );
    let slave = || Stdio::from(outer.slave.try_clone().unwrap());
    for (what, stdin, stdout) in [
        ("pipes", Stdio::piped(), Stdio::piped()),
        ("a terminal in, a pipe out", slave(), Stdio::piped()),
        ("a pipe in, a terminal out", Stdio::piped(), slave()),
    ] {
        let mut cmd = Command::new(&argv[0]);
        case.home.apply(&mut cmd);
        cmd.args(&argv[1..])
            .current_dir(case.dir.path())
            .stdin(stdin)
            .stdout(stdout)
            .stderr(Stdio::piped());
        let out = cmd.output().unwrap();
        assert_no_canary(&out.stdout, &case.cs);
        assert_no_canary(&out.stderr, &case.cs);
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(125), "{what}: {err}");
        assert!(
            err.starts_with("envcloak: pty_unavailable: "),
            "{what}: {err}"
        );
        assert!(!started.exists(), "{what}: the command ran");
    }
}

/// Gate 13 in PTY mode: while the command runs, the runner's argv and
/// environment, read from outside as another process of the user reads
/// them (Linux `/proc/<pid>/cmdline` and `environ`; macOS `ps -E`), hold no
/// value; the command's environment does (the positive control, on Linux
/// where it is readable), as does nothing else.
fn ps_shows_no_value_in_the_runners_argv_or_environment() {
    let case = Case::new();
    let counter = case.script("counter.py", COUNTER);
    let mut outer = Outer::new(24, 80);
    let python = python3();
    let d = case.dir.path().as_os_str();
    let argv = case.runner_argv(
        &["OPENAI_API_KEY:OPENAI_API_KEY"],
        &[],
        &[
            python.as_os_str(),
            counter.as_os_str(),
            d,
            OsStr::new("job"),
            OsStr::new("OPENAI_API_KEY"),
        ],
    );
    let mut run = Running {
        child: lead(
            &case,
            &outer,
            &argv,
            &[("ENVCLOAK_PTY_RELAY_MARK", OsStr::new("visible-mark"))],
        ),
    };
    outer.expect("JOB-READY", 1, "the command");
    let text = outer.text();
    let len = by_label(&case.cs, labels::OPENAI_API_KEY).value().len();
    assert!(text.contains(&format!("len={len}")), "{text}");
    let seen_from_outside = |pid: u32| -> Vec<u8> {
        if cfg!(target_os = "linux") {
            let mut v = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
            v.extend(std::fs::read(format!("/proc/{pid}/environ")).unwrap_or_default());
            v
        } else {
            Command::new("/bin/ps")
                .args(["-E", "-ww", "-o", "command=", "-p", &pid.to_string()])
                .output()
                .unwrap()
                .stdout
        }
    };
    let runner = seen_from_outside(run.child.id());
    assert_no_canary(&runner, &case.cs);
    assert!(
        contains(&runner, b"visible-mark"),
        "the reading shows no environment: {}",
        String::from_utf8_lossy(&runner)
    );
    if cfg!(target_os = "linux") {
        let pid: u32 = text[text.find("JOB-READY ").unwrap() + 10..]
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let command = seen_from_outside(pid);
        assert!(
            contains(&command, by_label(&case.cs, labels::OPENAI_API_KEY).value()),
            "the command's environment does not hold the value"
        );
    }
    outer.type_bytes(b"done\r");
    let status = outer.wait_exit(&mut run.child, DEADLINE);
    assert_eq!(status.code(), Some(0), "{}", outer.text());
    case.assert_clean(&outer.seen);
}
