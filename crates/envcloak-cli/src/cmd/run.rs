//! `envcloak run [--profile NAME] [--ref NAME=slug[#field]]... [--env-file
//! FILE] [--manifest PATH] [--wait DURATION] -- <cmd...>` (SPEC §6.1): the
//! request for a run's values, the decision, and, when a grant covers it,
//! the command with the values in its environment and its output
//! redacted.
//!
//! 1. Under a tracer the CLI refuses at once, with exit 125 and `traced`
//!    (gate 19), before any contact with the daemon. Only a verified
//!    daemon is then asked; with none, run says how to start one and
//!    starts nothing. Without `--wait` the CLI connects first and asks on
//!    that connection once the request is built; with `--wait`, its first
//!    contact is the wait's first request, so that no call outlasts the
//!    wait (step 4).
//! 2. It finds the nearest `envcloak.toml` upward from the working
//!    directory, or takes the absolute path `--manifest` names, and sends
//!    that path. The daemon opens and canonicalizes the manifest itself
//!    either way, with every identity rule (a symlinked manifest is
//!    refused), so the same directory is the same project however it was
//!    named.
//! 3. It sends the profile and `--ref` bindings, the `--env-file`'s
//!    references and the names of its ordinary variables (never their
//!    values, which the runner sets for the command), the command line as
//!    display text, and the names of the agent markers in its
//!    environment. The env file can hold values, so its bytes are read
//!    only into a [`SecretBuf`], and an error names its kind and line,
//!    never text from the file (docs/MANIFEST.md "Env files").
//! 4. The daemon answers with the decision. When no grant covers the
//!    request, it is pending: exit 125 with `approval_required
//!    request=<id>`, naming `envcloak approve <id>`, and, for each live
//!    binding whose provider has a test item, that item and the
//!    `envcloak ref` line that binds it (SPEC §10b "Live-key guard": the
//!    daemon proposes it and never substitutes it). With `--wait`, the
//!    line is printed once and the CLI waits up to that long (at most the
//!    request's 10-minute lifetime) without holding a connection: it asks
//!    the request's state on fresh connections, backing off from 250 ms
//!    to 1 s, and longer when the daemon answers `busy`; a request over a
//!    pending cap (`too_many_pending`) is asked again the same way.
//!    Approved, it asks again and runs; denied, it exits 125 with
//!    `approval_denied`; still pending at the deadline, or expired, it
//!    exits 125, the `approval_required` line being its failure
//!    ([`envcloak_ipc::wait`]). A call the daemon did not take (its
//!    connection closed unanswered, as at its connection limit) is asked
//!    again the same way until the deadline. The wait never outlasts its
//!    deadline by more than 5 seconds, or by the shorter grace
//!    `--wait-grace` gives (1 to 5 seconds; `envcloak mcp` passes 1, so
//!    that its tool answers within its host's timeout): every call, from
//!    its connect to the last byte of its answer, is given only the time
//!    left to that limit,
//!    however the daemon paces what it sends or reads, and an answer read
//!    later is dropped, its values wiped, with exit 125 and
//!    `daemon_unavailable`. Before each request
//!    that could carry values, the CLI looks for a tracer again, and stops
//!    with `traced` if one is attached now. SIGINT and SIGTERM end the
//!    wait as they end any program (a shell reports 130 or 143), also
//!    when the run was started with them ignored or blocked (`envcloak
//!    mcp` blocks them in every thread): their default action is restored
//!    and they are unblocked, with SIGHUP, before the wait begins; nothing
//!    is held open then, and nothing starts. SIGHUP keeps the disposition
//!    the run came with (`nohup`).
//!    Approval input is never read here: the terminal this command runs
//!    in may be an agent's.
//! 5. A covered answer carries the bindings' values, which the daemon
//!    sent after their audit entry was on disk. The connection is closed,
//!    and the runner ([`envcloak_exec`]) takes over: values under 8 bytes,
//!    and values of 8 to 15 bytes whose item lacks `allow_short`, are
//!    refused (exit 125, `value_too_short`, naming the slugs); what the
//!    redactor covers less than fully is printed by slug on standard
//!    error; then the command starts with the values and the env file's
//!    ordinary variables in its environment only, its standard output and
//!    standard error each through the redactor, and this command exits
//!    with its code, or 128 plus the signal that ended it (or that stopped
//!    the run after it exited). A command that is not found exits 127, and
//!    one that cannot be run 126, as with `env(1)`. The command sees pipes
//!    rather than a terminal, so programs that color their output only on
//!    a terminal print plain text, unless the run is in PTY mode (below).
//!
//! `--pty` runs the command on a pseudo-terminal of its own (docs/RUN.md
//! "PTY mode"): its standard output and standard error merged, through one
//! stream of the redactor (which also matches the CR LF form a terminal
//! shows of a value holding LF), the person's terminal in raw mode so
//! every key reaches the command's terminal as a byte, the terminal's
//! suspend character stopping the command and suspending `envcloak run`
//! in the person's shell, and SIGINT, SIGQUIT, SIGTERM and SIGHUP sent by
//! another process forwarded to the command's terminal's foreground job.
//! It needs a terminal on standard input and standard output: without
//! one it exits 125 with `pty_unavailable` before anything is sent, and
//! never falls back to pipe mode. When the PTY monitor dies before it
//! reports the command's exit, the run restores the terminal, drains the
//! output redacted and exits 125 with `pty_monitor_lost`; when the
//! person's terminal cannot be put back in raw mode after a stop, the
//! command is not continued and the run exits 125 with `run_failed`.
//! After `--`, `--pty` is the command's.
//!
//! `--status-fd N` is for a program that starts `envcloak run` and must
//! know how it ended (`envcloak mcp`; docs/RUN.md "Status descriptor"):
//! the command's exit code and output are the command's own, and a
//! command can exit 125 after printing EnvCloak's own failure line (Codex
//! F-113). Before anything else, the run takes the inherited descriptor
//! `N` as its own and sets the close-on-exec flag on it and on every
//! other descriptor it inherited above the standard streams, so the
//! command inherits none of them; as it ends, it writes one record there
//! ([`envcloak_client::run_status`]): refused before the command started
//! (with the token, and the request id for `approval_required`), the
//! command's exit, or unknown when the runner failed after the command
//! may have started. In pipe mode, a run without `--status-fd` passes
//! inherited descriptors on to its command, as `env(1)` does. PTY mode
//! always closes inherited descriptors above the standard streams.
//!
//! No argument is ever echoed, and no value is ever accepted on the
//! command line (gate 13): `--ref` names an item, never a value. The
//! values never enter this process's environment or argv, or a file.

use std::cell::RefCell;
use std::ffi::OsString;
use std::io::Read;
use std::os::fd::AsFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use envcloak_client::claims::claims;
use envcloak_client::connect::{connect, run_paths};
use envcloak_client::fail::{Failure, RUN_FAILURE, USAGE, refuse_if_traced, traced, usage};
use envcloak_client::render::{looks_like_value, proposal_text};
use envcloak_client::run_status::{Exit, RunStatus};
use envcloak_core::vault::Slug;
use envcloak_core::{SecretBuf, SecretBytes};
use envcloak_exec::{
    ChildExit, CoverageReport, ExecError, Label, OuterTerminal, RunSpec, ShortPolicy,
};
use envcloak_ipc::proto::{EnvFileParams, ReleasedValue, RunAnswer, RunRequestParams};
use envcloak_ipc::view::DecisionView;
use envcloak_ipc::wait::{
    CALL_GRACE, Fresh, MAX_WAIT, Notice, SystemClock, Transport, Waited, wait_for_run_with_grace,
};
use envcloak_ipc::{Client, ClientError};
use envcloak_policy::{
    Binding, EnvFileRefs, EnvName, GrantId, MAX_ENV_FILE, Mode, PendingId, PendingState, PlainVar,
    Proposal, find_manifest, parse_env_file_refs,
};
use zeroize::Zeroize;

const USAGE_TEXT: &str = "envcloak run [--profile NAME] [--ref NAME=slug[#field]]... [--env-file FILE] \
     [--manifest /absolute/path/envcloak.toml] [--wait DURATION (1s to 10m) [--wait-grace 1s..5s]] \
     [--status-fd N] [--pty] -- <cmd...>";

/// What `envcloak run --help` adds about `--pty` (SPEC §6.1 steps 7 and 8,
/// docs/RUN.md "PTY mode"): what it does, and the signals some systems
/// narrow (M2 plan D-35, as task M2-17 measured).
const PTY_HELP: &str = "--pty runs the command on a terminal of its own: its output and errors merged, \
     redacted on the way to yours (output a program rebuilds on the screen by moving the cursor \
     is not covered). Your terminal is raw while it runs, so every key reaches the command, \
     Ctrl-C included. The suspend key (Ctrl-Z, or whatever `stty susp` sets) stops the command \
     and gives your shell its prompt back; `fg` resumes both. SIGINT, SIGQUIT, SIGTERM and SIGHUP \
     sent to envcloak run by another process reach the command's foreground job (a nested \
     shell's job included); a second SIGTERM kills the command. On Linux kernels before 6.9 \
     (Ubuntu 24.04's original 6.8, Debian 12, RHEL 9), and for a job whose first process has \
     ended, SIGTERM and SIGHUP go to the command's own process group instead: with a nested \
     shell that is the shell, not its job. --pty needs a terminal on standard input and standard \
     output, and exits 125 with pty_unavailable without one.";

/// The parsed command line.
#[derive(Debug, Default, PartialEq, Eq)]
struct RunArgs {
    profile: Option<String>,
    refs: Vec<String>,
    env_file: Option<String>,
    /// `--manifest`: an absolute path, sent as it is.
    manifest: Option<String>,
    /// `--wait`: how long to wait for an approval.
    wait: Option<Duration>,
    /// `--wait-grace`: how long after the wait's deadline the daemon's
    /// last answer is waited for ([`CALL_GRACE`] when not given).
    wait_grace: Option<Duration>,
    /// `--status-fd`: the inherited descriptor the status record goes to.
    status_fd: Option<i32>,
    /// `--pty`: the command on a pseudo-terminal of its own.
    pty: bool,
    argv: Vec<String>,
}

/// `<n>s` or `<n>m`, from 1 second to the pending request's lifetime
/// ([`MAX_WAIT`], 10 minutes).
fn parse_wait(s: &str) -> Option<Duration> {
    // The unit is matched as a suffix, never split off at a byte offset.
    let (digits, per_unit) = if let Some(d) = s.strip_suffix('s') {
        (d, 1)
    } else {
        (s.strip_suffix('m')?, 60)
    };
    if digits.is_empty() || digits.len() > 4 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let d = Duration::from_secs(digits.parse::<u64>().ok()?.checked_mul(per_unit)?);
    (Duration::from_secs(1)..=MAX_WAIT)
        .contains(&d)
        .then_some(d)
}

/// `--wait-grace`: `<n>s`, from 1 second to [`CALL_GRACE`].
fn parse_grace(s: &str) -> Option<Duration> {
    let digits = s.strip_suffix('s')?;
    if digits.is_empty() || digits.len() > 1 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let d = Duration::from_secs(digits.parse::<u64>().ok()?);
    (Duration::from_secs(1)..=CALL_GRACE)
        .contains(&d)
        .then_some(d)
}

/// A duration in words.
fn words(d: Duration) -> String {
    let (m, s) = (d.as_secs() / 60, d.as_secs() % 60);
    match (m, s) {
        (0, s) => format!("{s}s"),
        (m, 0) => format!("{m}m"),
        (m, s) => format!("{m}m {s}s"),
    }
}

/// Why a command line was not taken.
#[derive(Debug, PartialEq, Eq)]
enum ParseError {
    /// A usage error: what was wrong, as fixed text.
    Usage(&'static str),
}

impl From<&'static str> for ParseError {
    fn from(why: &'static str) -> Self {
        ParseError::Usage(why)
    }
}

/// Parses the options up to `--` and the command after it. Values are
/// never accepted here: a `--ref` is a name and a reference.
fn parse(args: &[&str]) -> Result<RunArgs, ParseError> {
    let mut a = RunArgs::default();
    let mut it = args.iter();
    loop {
        match it.next() {
            None => return Err("run needs a command: envcloak run ... -- <cmd...>".into()),
            Some(&"--") => break,
            Some(&"--profile") => {
                if a.profile.is_some() {
                    return Err("--profile is given twice".into());
                }
                a.profile = Some((*it.next().ok_or("--profile needs a name")?).to_owned());
            }
            Some(&"--ref") => {
                let r = *it.next().ok_or("--ref needs NAME=<slug>[#field]")?;
                // Checked here, so a malformed one (a pasted value, say)
                // is refused before anything is sent, and never echoed.
                if Binding::parse_arg(r).is_err() {
                    return Err("--ref needs NAME=<slug>[#field]".into());
                }
                a.refs.push(r.to_owned());
            }
            Some(&"--env-file") => {
                if a.env_file.is_some() {
                    return Err("--env-file is given twice".into());
                }
                a.env_file = Some((*it.next().ok_or("--env-file needs a file")?).to_owned());
            }
            Some(&"--manifest") => {
                if a.manifest.is_some() {
                    return Err("--manifest is given twice".into());
                }
                let p = *it
                    .next()
                    .ok_or("--manifest needs the absolute path of an envcloak.toml")?;
                // The daemon opens it and checks the rest (its name, a
                // symlink, its owner); a relative path is refused here, as
                // it would be there, without being echoed.
                if !Path::new(p).is_absolute() {
                    return Err("--manifest needs the absolute path of an envcloak.toml".into());
                }
                a.manifest = Some(p.to_owned());
            }
            Some(&"--wait") => {
                if a.wait.is_some() {
                    return Err("--wait is given twice".into());
                }
                let d = it
                    .next()
                    .and_then(|v| parse_wait(v))
                    .ok_or("--wait needs a duration from 1s to 10m, such as 30s or 5m")?;
                a.wait = Some(d);
            }
            Some(&"--wait-grace") => {
                if a.wait_grace.is_some() {
                    return Err("--wait-grace is given twice".into());
                }
                let d = it
                    .next()
                    .and_then(|v| parse_grace(v))
                    .ok_or("--wait-grace needs a duration from 1s to 5s")?;
                a.wait_grace = Some(d);
            }
            Some(&"--status-fd") => {
                if a.status_fd.is_some() {
                    return Err("--status-fd is given twice".into());
                }
                let n = it
                    .next()
                    .and_then(|v| super::fd_number(v))
                    .filter(|n| *n >= 3)
                    .ok_or("--status-fd needs a descriptor number of 3 or more")?;
                a.status_fd = Some(n);
            }
            Some(&"--launch") => {
                return Err("--launch takes nothing else: envcloak run --launch <id>".into());
            }
            Some(&"--pty") => {
                if a.pty {
                    return Err("--pty is given twice".into());
                }
                a.pty = true;
            }
            Some(_) => return Err("unknown option; see envcloak run --help".into()),
        }
    }
    a.argv = it.map(|s| (*s).to_owned()).collect();
    if a.argv.is_empty() {
        return Err("run needs a command after --".into());
    }
    if a.wait_grace.is_some() && a.wait.is_none() {
        return Err("--wait-grace needs --wait".into());
    }
    Ok(a)
}

pub fn run(args: &[&str]) -> ExitCode {
    if args == ["--help"] || args == ["-h"] {
        println!("usage: {USAGE_TEXT}\n\n{PTY_HELP}");
        return ExitCode::SUCCESS;
    }
    // The runner the daemon starts for a managed server (M2 task M2-27).
    if let ["--launch", launch] = args {
        return run_launch(launch);
    }
    let a = match parse(args) {
        Ok(a) => a,
        Err(ParseError::Usage(why)) => {
            eprintln!("envcloak: {why}");
            return usage(USAGE_TEXT);
        }
    };
    // The status descriptor is taken first, before anything is opened or
    // started, and with every other inherited descriptor above the
    // standard streams it is closed on exec: the command never holds it.
    let mut status = match a.status_fd {
        None => None,
        Some(n) => match envcloak_sys::claim_inherited_fd(n) {
            Ok(fd) => Some(std::fs::File::from(fd)),
            Err(_) => {
                eprintln!("envcloak: --status-fd names a descriptor that is not open");
                return usage(USAGE_TEXT);
            }
        },
    };
    let ended = if status.is_some() && envcloak_sys::close_on_exec_above(2).is_err() {
        Ended::refused(
            Failure::new(
                "run_failed",
                "the descriptors this run inherited could not be closed on exec; nothing was \
                 started",
            ),
            RUN_FAILURE,
        )
    } else {
        checked(a)
    };
    ended.finish(status.as_mut())
}

/// How a run ended: what it exits with, and the status record it writes
/// with `--status-fd`.
enum Ended {
    /// EnvCloak's own failure before the command was started: nothing
    /// ran. `printed` when its line is out already (the wait's
    /// `approval_required` line, which is the failure at the deadline).
    NotStarted {
        failure: Failure,
        code: u8,
        request: Option<PendingId>,
        /// With `approval_required`: the test items the daemon proposed in
        /// place of live ones, which the record names for `envcloak mcp`.
        proposals: Vec<Proposal>,
        printed: bool,
    },
    /// The command was started and followed to its end.
    Ran(ChildExit),
    /// The runner failed after the command may have been started.
    Lost(ExecError),
}

impl Ended {
    /// `failure`, before the command was started, exiting with `code`.
    fn refused(failure: Failure, code: u8) -> Ended {
        Ended::NotStarted {
            failure,
            code,
            request: None,
            proposals: Vec::new(),
            printed: false,
        }
    }

    /// A runner failure: 127 for a command not found and 126 for one that
    /// could not be run, as `env(1)` has them, and 125 for EnvCloak's own;
    /// one after the command may have started is [`Ended::Lost`].
    fn exec(e: ExecError) -> Ended {
        if e.may_have_started() {
            return Ended::Lost(e);
        }
        let code = e.exit_code();
        Ended::refused(Failure::new(e.token(), e.message()), code)
    }

    /// Prints what is left to print, writes the status record when there
    /// is a status descriptor, and returns the exit code.
    fn finish(self, status: Option<&mut std::fs::File>) -> ExitCode {
        let (record, code) = match self {
            Ended::NotStarted {
                failure,
                code,
                request,
                proposals,
                printed,
            } => {
                if !printed {
                    failure.report(code);
                }
                let record = match request {
                    Some(id) if failure.token() == "approval_required" => {
                        RunStatus::approval_required(id, &proposals)
                    }
                    _ => RunStatus::not_started(failure.token()),
                };
                (record, code)
            }
            Ended::Ran(exit) => {
                let record = RunStatus::Ran(match exit {
                    ChildExit::Code(c) => Exit::Code(c),
                    ChildExit::Signal(s) => Exit::Signal(s),
                    ChildExit::Stopped(s) => Exit::Stopped(s),
                });
                (record, exit.shell_code())
            }
            Ended::Lost(e) => {
                Failure::new(e.token(), e.message()).report(e.exit_code());
                (RunStatus::Unknown, e.exit_code())
            }
        };
        // A reader that is gone makes the write fail (SIGPIPE is ignored):
        // the run's exit is the same either way.
        if let Some(out) = status {
            let _ = record.write_to(out);
        }
        ExitCode::from(code)
    }
}

/// The run once the command line is parsed (and the status descriptor
/// taken).
fn checked(a: RunArgs) -> Ended {
    // Names only (gate 13): a `--ref` or `--profile` shaped like a key is
    // refused, unechoed, before anything is sent. The command after `--`
    // is the user's own, which the audit entry masks.
    let mut names: Vec<&str> = a.profile.iter().map(String::as_str).collect();
    names.extend(a.refs.iter().flat_map(|r| r.split(['=', '#'])));
    if let Err(f) = super::refuse_value_like(&names) {
        return Ended::refused(f, USAGE);
    }
    // PTY mode needs the person's terminal on standard input and standard
    // output, opened for the relay now, before the daemon is asked: without
    // one, nothing is sent and nothing falls back to pipe mode.
    let terminal = if a.pty {
        match OuterTerminal::open(std::io::stdin().as_fd(), std::io::stdout().as_fd()) {
            Ok(t) => Some(t),
            Err(e) => return Ended::exec(e),
        }
    } else {
        None
    };
    match request(a, terminal) {
        Ok(ended) => ended,
        Err(f) => Ended::refused(f, RUN_FAILURE),
    }
}

/// How the request is asked.
enum Ask {
    /// Once, on this verified connection.
    Now(Client),
    /// Waiting up to this long for an approval, each call on a connection
    /// of its own, and up to the grace after it for a last answer.
    Waiting(Duration, Duration),
}

fn request(a: RunArgs, terminal: Option<OuterTerminal>) -> Result<Ended, Failure> {
    refuse_if_traced()?;
    // Only a verified daemon is ever asked; with none, run says how to
    // start one and starts nothing. A waiting run connects only within its
    // wait, for each call (`wait_for`): a connection made here, with the
    // ordinary call timeout, could hold it past its deadline.
    let ask = match a.wait {
        None => Ask::Now(connect()?),
        Some(wait) => Ask::Waiting(wait, a.wait_grace.unwrap_or(CALL_GRACE)),
    };
    let manifest = match a.manifest {
        Some(p) => p,
        None => found_manifest()?,
    };
    // Its ordinary variables' values stay here: the runner sets them for
    // the command.
    let env_file = a.env_file.as_deref().map(read_env_file).transpose()?;
    let params = RunRequestParams {
        manifest,
        profile: a.profile,
        refs: a.refs,
        env_file: env_file.as_ref().map(|f| EnvFileParams::from(&f.names())),
        argv: a.argv.clone(),
        claims: claims(),
        launch: None,
        bridge: None,
        fds: Vec::new(),
    };
    let answer = match ask {
        Ask::Now(mut client) => {
            let answer = client.run_request(&params)?;
            drop(client);
            answer
        }
        // No connection is held while waiting: each step opens its own.
        Ask::Waiting(wait, grace) => match wait_for(&params, wait, grace)? {
            Ok(answer) => answer,
            Err(ended) => return Ok(ended),
        },
    };
    let decision = answer.decision;
    match decision {
        DecisionView::Pending { request } => {
            // The id is printed only in its canonical form: a program
            // answering in the daemon's place could send anything.
            let id = PendingId::parse(&request).ok_or_else(protocol)?;
            Ok(Ended::NotStarted {
                failure: Failure::new(
                    "approval_required",
                    format!(
                        "request={id}: run \"envcloak approve {id}\" in a terminal you control{}",
                        proposed(&answer.proposals, &params.manifest)
                    ),
                ),
                code: RUN_FAILURE,
                request: Some(id),
                proposals: answer.proposals,
                printed: false,
            })
        }
        // `started` answers a managed server's launch, which this request
        // does not name: no daemon sends it here.
        DecisionView::Started {} => Err(protocol()),
        DecisionView::Denied { .. } => {
            let message = decision
                .deny_reason()
                .map(|r| r.message())
                .ok_or_else(protocol)?;
            Err(Failure::new("approval_denied", message))
        }
        DecisionView::Covered { grant, mode, .. } => {
            GrantId::parse(&grant).ok_or_else(protocol)?;
            // Proxy mode is M6's; the daemon refuses it before deciding.
            if mode != Mode::Inject {
                return Err(protocol());
            }
            // The answer's `redact` is always true in M1, which has no way
            // to turn redaction off; the runner redacts whatever it says.
            let plain = env_file.map(|f| f.plain).unwrap_or_default();
            start(answer.values, plain, a.argv, terminal)
        }
    }
}

/// The nearest `envcloak.toml` at or above the working directory.
fn found_manifest() -> Result<String, Failure> {
    let manifest = match find_manifest(Path::new(".")) {
        Ok(Some(p)) => p,
        Ok(None) => {
            return Err(Failure::new(
                "manifest_invalid",
                "no envcloak.toml in this directory or above it; run `envcloak init` first",
            ));
        }
        Err(_) => {
            return Err(Failure::new(
                "manifest_invalid",
                "the working directory could not be read while looking for envcloak.toml",
            ));
        }
    };
    manifest.to_str().map(str::to_owned).ok_or_else(|| {
        Failure::new(
            "manifest_invalid",
            "the manifest's path is not valid UTF-8, which this build cannot send",
        )
    })
}

/// Waits up to `wait` for the request `params` to be covered or denied,
/// and up to `grace` after that for a last answer, on fresh connections
/// ([`wait_for_run_with_grace`]), printing the
/// `approval_required` line once per request and the `too_many_pending`
/// line once. Returns the deciding answer, or how the run ended when the
/// wait ended with nothing decided (still pending at the deadline,
/// expired, or every place taken): the line already printed is then the
/// failure, and the run exits 125.
fn wait_for(
    params: &RunRequestParams,
    wait: Duration,
    grace: Duration,
) -> Result<Result<RunAnswer, Ended>, Failure> {
    // SIGINT and SIGTERM end the wait whatever this process was started
    // with, and a SIGHUP not ignored ends it too: an ignored or blocked
    // signal survives `exec` (a shell starts a background job with SIGINT
    // ignored; a program that takes these signals on one thread, as
    // `envcloak mcp` does, blocks them), and a wait one could not end
    // would start the command on an approval that comes later. One sent
    // before this point waited, blocked, and ends the run here.
    envcloak_sys::termination_ends_process().map_err(|_| {
        Failure::new(
            "run_failed",
            "SIGINT and SIGTERM could not be made to end the wait; nothing was sent",
        )
    })?;
    let paths = run_paths()?;
    let latest = RefCell::new(Vec::new());
    let mut fresh = Proposing {
        fresh: Fresh {
            paths: &paths,
            params,
        },
        latest: &latest,
    };
    let shown = words(wait);
    let mut notice = |n: Notice| match n {
        // Announced right after the answer that named the request, whose
        // proposals `latest` holds.
        Notice::Pending(id) => eprintln!(
            "envcloak: approval_required: request={id}: run \"envcloak approve {id}\" in a \
             terminal you control{}; waiting up to {shown} for it",
            proposed(&latest.borrow(), &params.manifest)
        ),
        Notice::TooManyPending(e) => {
            let f = Failure::from(ClientError::Rpc(e));
            eprintln!(
                "envcloak: {}: {}; waiting up to {shown} for a place",
                f.token(),
                f.message()
            );
        }
    };
    match wait_for_run_with_grace(
        &mut fresh,
        &mut SystemClock::new(),
        wait,
        grace,
        &mut notice,
    )? {
        Waited::Answer(answer) => Ok(Ok(answer)),
        Waited::Denied(id) => Err(Failure::new(
            "approval_denied",
            format!("request={id} was denied; nothing was started"),
        )),
        Waited::Expired(id) | Waited::TimedOut(id) => Ok(Err(printed_already(
            "approval_required",
            Some(id),
            latest.take(),
        ))),
        Waited::TooManyPending(_) => Ok(Err(printed_already("too_many_pending", None, Vec::new()))),
        // A tracer attached while it waited: no request that could carry
        // values was sent.
        Waited::Traced => Err(traced()),
        Waited::Unanswered => Err(Failure::new(
            "daemon_unavailable",
            format!(
                "the daemon did not answer within the wait ({shown}, and {}s for a last \
                 answer); nothing was started",
                grace.as_secs()
            ),
        )),
    }
}

/// What the `approval_required` line adds for the test items the daemon
/// proposes in place of live ones (SPEC §10b "Live-key guard"): for each,
/// the variable, the live item, the test item and how to bind it for the
/// layer the live binding came from, an edit of the manifest naming
/// `manifest`, the one this run sent (`Proposal::advice`: the line can be
/// followed from any directory), and
/// [`envcloak_client::render::proposal_text`]'s masking (names escaped,
/// one shaped like a key or token hidden). The daemon never substitutes
/// one. The client took only an answer whose names have the daemon's
/// shapes (`RunAnswer::well_formed`).
fn proposed(proposals: &[Proposal], manifest: &str) -> String {
    proposals
        .iter()
        .map(|x| {
            format!(
                "; {}",
                proposal_text(x, &x.advice(manifest, &looks_like_value), "run this again")
            )
        })
        .collect()
}

/// [`Fresh`], keeping the test items the latest `run.request` answer
/// proposed, for the `approval_required` line that names its request.
struct Proposing<'a> {
    fresh: Fresh<'a>,
    latest: &'a RefCell<Vec<Proposal>>,
}

impl Transport for Proposing<'_> {
    fn traced(&mut self) -> bool {
        self.fresh.traced()
    }

    fn request(&mut self, within: Duration) -> Result<RunAnswer, ClientError> {
        let answer = self.fresh.request(within)?;
        self.latest.replace(answer.proposals.clone());
        Ok(answer)
    }

    fn poll(&mut self, id: &PendingId, within: Duration) -> Result<PendingState, ClientError> {
        self.fresh.poll(id, within)
    }
}

/// A wait that ended with nothing decided: the line it printed for the
/// request (or for the pending cap), `token`'s, is the failure; the
/// request's latest answer proposed `proposals`.
fn printed_already(
    token: &'static str,
    request: Option<PendingId>,
    proposals: Vec<Proposal>,
) -> Ended {
    Ended::NotStarted {
        failure: Failure::new(token, ""),
        code: RUN_FAILURE,
        request,
        proposals,
        printed: true,
    }
}

/// Runs `argv` with the released values and the env file's ordinary
/// variables in its environment, its output redacted: on pipes, or on a
/// pseudo-terminal relayed to `terminal` (PTY mode). Returns how the run
/// ended.
fn start(
    values: Vec<ReleasedValue>,
    plain: Vec<PlainVar>,
    argv: Vec<String>,
    terminal: Option<OuterTerminal>,
) -> Result<Ended, Failure> {
    let mut bound: Vec<(EnvName, Slug, SecretBytes, ShortPolicy)> =
        Vec::with_capacity(values.len());
    for v in values {
        let name = EnvName::new(&v.env_name).map_err(|_| protocol())?;
        let slug = Slug::new(&v.slug).map_err(|_| protocol())?;
        bound.push((
            name,
            slug,
            v.value.into_inner(),
            ShortPolicy::from(v.allow_short),
        ));
    }
    let built = {
        let labels: Vec<Label<'_>> = bound
            .iter()
            .map(|(_, slug, value, short)| Label {
                slug,
                value,
                short: *short,
            })
            .collect();
        // PTY mode also redacts the CR LF form a terminal shows of a value
        // holding LF.
        if terminal.is_some() {
            envcloak_exec::build_pty_redactor(&labels)
        } else {
            envcloak_exec::build_redactor(&labels)
        }
    };
    let (redactor, report) = match built {
        Ok(b) => b,
        Err(ExecError::ValueTooShort(r)) => return Err(too_short(&r)),
        Err(e) => return Ok(Ended::exec(e)),
    };
    // Gate 12: a test build panics here on request, holding the values and
    // the redactor built from them.
    envcloak_sys::panic_point("cli.run.released");
    print_coverage(&report, terminal.is_some());
    let out = |fd: std::os::fd::BorrowedFd<'_>| {
        fd.try_clone_to_owned().map_err(|_| {
            Failure::new(
                "run_failed",
                "this command's standard output or standard error is not open",
            )
        })
    };
    // The env file's ordinary variables first: a binding of the same name
    // (the daemon refuses one) could not be overridden by them.
    let mut injected: Vec<(EnvName, SecretBytes)> =
        plain.into_iter().map(|p| (p.name, p.value)).collect();
    injected.extend(bound.into_iter().map(|(name, _, value, _)| (name, value)));
    let argv: Vec<OsString> = argv.into_iter().map(OsString::from).collect();
    // The idle flush is IDLE_FLUSH; on pipes, standard input is this
    // process's own.
    let spec = match terminal {
        Some(t) => RunSpec::pty(argv, injected, redactor, t),
        None => RunSpec::new(
            argv,
            injected,
            redactor,
            out(std::io::stdout().as_fd())?,
            out(std::io::stderr().as_fd())?,
        ),
    };
    match envcloak_exec::run(spec) {
        Ok(exit) => Ok(Ended::Ran(exit)),
        Err(e) => Ok(Ended::exec(e)),
    }
}

/// `value_too_short`, naming the refused items by slug.
fn too_short(r: &CoverageReport) -> Failure {
    let slugs: Vec<&str> = r.refused_short.iter().map(Slug::as_str).collect();
    Failure::new(
        "value_too_short",
        format!(
            "{}: a value under 8 bytes is never injected, and one of 8 to 15 bytes only when \
             its item allows short values; nothing was started",
            slugs.join(", ")
        ),
    )
}

/// What the redactor covers less than fully, one line per item on
/// standard error, before the command starts; in PTY mode also what no
/// redactor of a terminal's output covers (SPEC §6.1 "Redaction coverage").
fn print_coverage(r: &CoverageReport, pty: bool) {
    if pty {
        eprintln!(
            "envcloak: coverage: PTY mode: output a program rebuilds on the terminal by moving the \
             cursor (a value redrawn from pieces) is not redacted"
        );
    }
    for s in &r.warned_short {
        eprintln!(
            "envcloak: coverage: {s} is 8 to 15 bytes (allowed short): the value and its \
             whole-value encodings are redacted, but a short value can also match ordinary output"
        );
    }
    for s in &r.partial {
        eprintln!(
            "envcloak: coverage: {s}: inside a longer base64 stream it is redacted at some byte \
             alignments only"
        );
    }
    for s in &r.truncated {
        eprintln!(
            "envcloak: coverage: {s}: JSON escapes are redacted as common serializers write \
             them, not in every combination of options"
        );
    }
}

/// Reads and parses the `--env-file` at `path`. Only a regular file of at
/// most [`MAX_ENV_FILE`] bytes is read, into a [`SecretBuf`] sized for it;
/// it is opened non-blocking, so a FIFO named here cannot hang the run.
/// Errors name the kind and line, never the path's contents.
fn read_env_file(path: &str) -> Result<EnvFileRefs, Failure> {
    let fail = |m: &'static str| Failure::new("binding_unresolved", m);
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| fail("the --env-file could not be opened"))?;
    let meta = f
        .metadata()
        .map_err(|_| fail("the --env-file could not be read"))?;
    if !meta.is_file() {
        return Err(fail("the --env-file is not a regular file"));
    }
    let len = usize::try_from(meta.len()).unwrap_or(usize::MAX);
    if len > MAX_ENV_FILE {
        return Err(fail("the --env-file is larger than 1 MiB"));
    }
    let mut buf = SecretBuf::with_capacity(len);
    buf.read_exact_from(&mut f, len)
        .map_err(|_| fail("the --env-file changed while it was read"))?;
    // Anything past the length it had is a file still being written.
    let mut more = [0u8; 1];
    let grew = f.read(&mut more);
    more.zeroize();
    if !matches!(grew, Ok(0)) {
        return Err(fail("the --env-file changed while it was read"));
    }
    parse_env_file_refs(&buf.freeze())
        .map_err(|e| Failure::new(e.token(), format!("--env-file: {e}")))
}

fn protocol() -> Failure {
    Failure::new("protocol_error", "the daemon's answer was malformed")
}

/// `envcloak run --launch <id>`: EnvCloak's runner for a managed stdio
/// server (SPEC §6.6; M2 plan D-33, D-36; task M2-27), which only the
/// daemon starts, from its own retained image, on the pipe ends a client
/// handed over.
///
/// Before it reads anything it checks that the daemon started it: its
/// descriptor 3 must be a Unix socket whose peer is its parent, and the
/// daemon serving the socket must be its parent too. Anything else (a
/// person, an agent or a test program starting it) exits 125 with
/// `not_started_by_daemon`, having received nothing; nothing is started.
/// Then it reads the daemon's `Release` from that channel: the values and
/// the launch, which must be the one it was started for. It builds the
/// server's environment from the release and the fixed passthrough list
/// only (`envcloak_policy::managed::launch_environment`), refuses values
/// too short to redact, as `run` does, and serves the server
/// ([`envcloak_exec::launch::serve`]): from the sealed copy the daemon
/// checked (Linux), the checked descriptor once its stamp is the same, or
/// the registered path (on macOS started suspended, and resumed only on
/// the daemon's `Confirmed`), in the checked working directory, its
/// output redacted onto the client's pipes. It exits with the server's
/// code, or 125 with `managed_launch_changed` when the file changed after
/// the daemon's check or the daemon refused the started server.
fn run_launch(launch: &str) -> ExitCode {
    use envcloak_ipc::control::{
        self, CWD_FD, ExecSpec, FromRunner, IMAGE_FD, LIFELINE_FD, Recipient, ToRunner,
    };
    // Blocked before any thread starts, so the serving loop takes them.
    let Ok(signals) = envcloak_sys::TerminationSignals::block() else {
        return Failure::new("run_failed", "the runner's signals could not be set up")
            .report(RUN_FAILURE);
    };
    if let Err(f) = refuse_if_traced() {
        return f.report(RUN_FAILURE);
    }
    let not_started = || {
        Failure::new(
            "not_started_by_daemon",
            "envcloak run --launch is started only by envcloakd, for a managed server; nothing \
             was received and nothing was started",
        )
        .report(RUN_FAILURE)
    };
    let changed = || {
        Failure::new(
            "managed_launch_changed",
            "the managed server's program changed after EnvCloak checked it; nothing was \
             started. Run envcloak migrate-mcp --update to register it again",
        )
        .report(RUN_FAILURE)
    };
    let failed = |what: &'static str| Failure::new("run_failed", what).report(RUN_FAILURE);
    let Some(control) = started_by_daemon() else {
        return not_started();
    };
    let _ = control.set_read_timeout(Some(Duration::from_secs(30)));
    let release = match control::receive::<ToRunner>(&control) {
        Ok(ToRunner::Release(r)) => r,
        _ => return not_started(),
    };
    let control::Release { bindings, to } = *release;
    let Recipient::Runner {
        launch: given,
        spec,
    } = to
    else {
        return not_started();
    };
    if given != launch {
        return not_started();
    }
    let claim = |n: i32| envcloak_sys::claim_inherited_fd(n).ok();
    let (Some(lifeline), Some(cwd)) = (claim(LIFELINE_FD), claim(CWD_FD)) else {
        return failed("the runner's descriptors are not all open; nothing was started");
    };
    let image = claim(IMAGE_FD);
    let (program, suspended) = match (spec.exec, image) {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        (ExecSpec::Image, Some(fd)) => {
            (envcloak_exec::launch::ServerProgram::Descriptor(fd), false)
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        (ExecSpec::Descriptor { stamp }, Some(fd)) => {
            // Checked at rest: run from the checked descriptor only while
            // the file is still as the daemon saw it.
            let same = envcloak_exec::launch::same_stamp(
                fd.as_fd(),
                stamp.dev,
                stamp.ino,
                stamp.size,
                stamp.mtime_ns,
                stamp.ctime_ns,
            );
            if !matches!(same, Ok(true)) {
                return changed();
            }
            (envcloak_exec::launch::ServerProgram::Descriptor(fd), false)
        }
        (ExecSpec::Path { confirm }, _) => (
            envcloak_exec::launch::ServerProgram::Path(spec.executable.as_bytes().to_vec()),
            confirm,
        ),
        _ => return failed("the launch the daemon sent cannot be run here; nothing was started"),
    };
    // The values: each under its variable, with its slug for the redactor.
    let mut bound: Vec<(EnvName, Slug, SecretBytes, ShortPolicy)> =
        Vec::with_capacity(bindings.len());
    for v in bindings {
        let (Ok(name), Ok(slug)) = (EnvName::new(&v.env_name), Slug::new(&v.slug)) else {
            return failed("the daemon's release was not well formed; nothing was started");
        };
        bound.push((
            name,
            slug,
            v.value.into_inner(),
            ShortPolicy::from(v.allow_short),
        ));
    }
    let built = {
        let labels: Vec<Label<'_>> = bound
            .iter()
            .map(|(_, slug, value, short)| Label {
                slug,
                value,
                short: *short,
            })
            .collect();
        envcloak_exec::build_redactor(&labels)
    };
    let redactor = match built {
        Ok((r, report)) => {
            print_coverage(&report, false);
            r
        }
        Err(ExecError::ValueTooShort(r)) => return too_short(&r).report(RUN_FAILURE),
        Err(_) => return failed("the redactor could not be built; nothing was started"),
    };
    let env = {
        let inherited: Vec<(std::ffi::OsString, std::ffi::OsString)> =
            std::env::vars_os().collect();
        let values: Vec<(EnvName, SecretBytes)> = bound
            .drain(..)
            .map(|(name, _, value, _)| (name, value))
            .collect();
        envcloak_exec::launch::server_env(&inherited, spec.path_env.as_bytes(), &spec.vars, &values)
    };
    drop(bound);
    let own = |fd: std::os::fd::BorrowedFd<'_>| fd.try_clone_to_owned().ok();
    let (Some(input), Some(output), Some(errors)) = (
        own(std::io::stdin().as_fd()),
        own(std::io::stdout().as_fd()),
        own(std::io::stderr().as_fd()),
    ) else {
        return failed("the runner's standard streams are not open; nothing was started");
    };
    let server = envcloak_exec::launch::ServerLaunch {
        program,
        argv: spec.argv.iter().map(|a| a.as_bytes().to_vec()).collect(),
        env,
        cwd,
        suspended,
        redactor,
        idle_flush: envcloak_exec::IDLE_FLUSH,
    };
    let io = envcloak_exec::launch::RunnerIo {
        input,
        output,
        errors,
        lifeline,
    };
    // macOS: the daemon checks the suspended server's code directory hash
    // before it may run.
    let confirm = |pid: u32| {
        control::send(&control, &FromRunner::ConfirmSpawn(pid)).is_ok()
            && matches!(
                control::receive::<ToRunner>(&control),
                Ok(ToRunner::Confirmed)
            )
    };
    match envcloak_exec::launch::serve(server, io, signals, confirm) {
        Ok(exit) => ExitCode::from(exit.shell_code()),
        Err(envcloak_exec::launch::LaunchError::Refused) => changed(),
        Err(e) => Failure::new(e.token(), e.describe()).report(RUN_FAILURE),
    }
}

/// The runner's control channel, when the daemon started this process:
/// descriptor 3 a Unix socket whose peer is the parent, and the parent
/// the process that serves the daemon's socket. `None` otherwise; nothing
/// was read from descriptor 3.
fn started_by_daemon() -> Option<std::os::unix::net::UnixStream> {
    use envcloak_sys::fdpass::{DescriptorKind, descriptor_kind};
    let parent = i32::try_from(std::os::unix::process::parent_id()).ok()?;
    if parent <= 1 {
        return None;
    }
    let fd = envcloak_sys::claim_inherited_fd(envcloak_ipc::control::CONTROL_FD).ok()?;
    let (kind, _) = descriptor_kind(fd.as_fd()).ok()?;
    if kind != DescriptorKind::Socket {
        return None;
    }
    if envcloak_sys::peer_identity(fd.as_fd()).ok()?.pid != parent {
        return None;
    }
    let daemon = connect().ok()?;
    if envcloak_sys::peer_identity(daemon.as_fd()).ok()?.pid != parent {
        return None;
    }
    Some(std::os::unix::net::UnixStream::from(fd))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The record and exit code a runner failure ends a run with: one
    /// after the command may have started is `unknown` (Codex's
    /// completion-channel gate 6: never "not run"), one before it is
    /// `not_started` with its token, and a command not found or not
    /// executable keeps `env(1)`'s code. Read back as the server reads it.
    ///
    /// Mutation checked: `ExecError::may_have_started` always false (every
    /// runner failure taken as before the start): the `unknown` record is
    /// written `not_started` and this fails.
    #[test]
    fn a_runner_failure_after_the_start_is_recorded_as_may_have_run() {
        use std::io::{Seek, SeekFrom};
        for (e, record, code) in [
            (
                ExecError::Followed(std::io::ErrorKind::Other),
                RunStatus::Unknown,
                125u8,
            ),
            (
                ExecError::NotFound,
                RunStatus::not_started("command_not_found"),
                127,
            ),
            (
                ExecError::NotExecutable(std::io::ErrorKind::PermissionDenied),
                RunStatus::not_started("command_not_executable"),
                126,
            ),
            (
                ExecError::Setup(std::io::ErrorKind::OutOfMemory),
                RunStatus::not_started("run_failed"),
                125,
            ),
        ] {
            let what = format!("{e:?}");
            let mut file = tempfile::tempfile().unwrap();
            let exit = Ended::exec(e).finish(Some(&mut file));
            assert_eq!(exit, ExitCode::from(code), "{what}");
            file.seek(SeekFrom::Start(0)).unwrap();
            let mut written = Vec::new();
            file.read_to_end(&mut written).unwrap();
            assert_eq!(RunStatus::decode(&written), Some(record), "{what}");
        }
    }

    /// The `approval_required` line's test keys (SPEC §10b "Live-key
    /// guard"): each with how to bind it; a name shaped like a key or
    /// token (generated canaries, each a valid name of its kind) is never
    /// printed, the words every metadata command prints in its place are
    /// (Codex, round 2: the line escaped names but did not mask them). The
    /// control: ordinary names are printed.
    ///
    /// Mutation: `proposal_text` escaping only: the canaries are on the
    /// line and this fails.
    #[test]
    fn the_line_names_each_test_key_and_hides_a_key_shaped_name() {
        use envcloak_policy::BindingSource;
        let cs = envcloak_testkit::canaries(envcloak_testkit::fresh_seed());
        let token: String = cs
            .iter()
            .flat_map(|c| c.value().to_vec())
            .filter(u8::is_ascii_alphanumeric)
            .map(|b| char::from(b).to_ascii_lowercase())
            .take(42)
            .chain("x1y2z3".chars())
            .collect();
        let x = |env: &str, live: &str, test: &str, field: Option<&str>| Proposal {
            env_name: env.to_owned(),
            live_slug: live.to_owned(),
            test_slug: test.to_owned(),
            test_field: field.map(str::to_owned),
            source: BindingSource::EnvFile { line: 4 },
        };
        let upper = format!("K{}", token.to_ascii_uppercase());
        let slug = format!("stripe/{token}");
        let line = proposed(
            &[
                x("STRIPE_SECRET_KEY", "stripe/live", "stripe/test", None),
                x(&upper, "stripe/live", "stripe/test", None),
                x("A_KEY", &slug, "stripe/test", None),
                x("B_KEY", "stripe/live", &slug, None),
                x("C_KEY", "stripe/live", "stripe/test", Some(&token)),
            ],
            "/p/acme/envcloak.toml",
        );
        assert!(!line.to_ascii_lowercase().contains(&token), "{line}");
        assert_eq!(
            line.matches(envcloak_client::render::HIDDEN).count(),
            7,
            "{line}"
        );
        assert!(
            line.starts_with(
                "; STRIPE_SECRET_KEY is bound to the live key stripe/live: to use the test key \
                 stripe/test instead, set line 4 of the --env-file to \
                 `STRIPE_SECRET_KEY=envcloak://stripe/test`, and run this again; "
            ),
            "{line}"
        );
        assert_eq!(proposed(&[], "/p/acme/envcloak.toml"), "");
        // A binding of the manifest: the edit names the manifest this run
        // sent, as one shell word (Codex, round 3: `envcloak ref` alone
        // edits the manifest nearest the directory it runs in).
        let mut p = x("STRIPE_SECRET_KEY", "stripe/live", "stripe/test", None);
        p.source = BindingSource::Profile {
            profile: "dev".to_owned(),
        };
        assert_eq!(
            proposed(&[p], "/p/my acme/envcloak.toml"),
            "; STRIPE_SECRET_KEY is bound to the live key stripe/live: to use the test key \
             stripe/test instead, run `envcloak ref --manifest '/p/my acme/envcloak.toml' \
             --profile dev STRIPE_SECRET_KEY=stripe/test`, and run this again"
        );
    }

    #[test]
    fn options_come_before_the_command() {
        assert_eq!(
            parse(&["--", "./emit", "-x"]).unwrap(),
            RunArgs {
                argv: vec!["./emit".into(), "-x".into()],
                ..RunArgs::default()
            }
        );
        assert_eq!(
            parse(&[
                "--profile",
                "short",
                "--ref",
                "A=openai/x",
                "--env-file",
                ".env.refs",
                "--ref",
                "B=stripe/x#value",
                "--",
                "true"
            ])
            .unwrap(),
            RunArgs {
                profile: Some("short".into()),
                refs: vec!["A=openai/x".into(), "B=stripe/x#value".into()],
                env_file: Some(".env.refs".into()),
                argv: vec!["true".into()],
                ..RunArgs::default()
            }
        );
        assert_eq!(
            parse(&[
                "--manifest",
                "/p/acme/envcloak.toml",
                "--wait",
                "90s",
                "--",
                "true"
            ])
            .unwrap(),
            RunArgs {
                manifest: Some("/p/acme/envcloak.toml".into()),
                wait: Some(Duration::from_secs(90)),
                argv: vec!["true".into()],
                ..RunArgs::default()
            }
        );
        // Options after `--` belong to the command.
        assert_eq!(
            parse(&["--", "sh", "--profile", "x"]).unwrap().argv,
            vec!["sh", "--profile", "x"]
        );
        for bad in [
            &[][..],
            &["--"],
            &["true"],
            &["--profile", "--", "true"],
            &["--profile", "a", "--profile", "b", "--", "true"],
            &["--ref"],
            &["--ref", "not a reference", "--", "true"],
            &["--ref", "A=", "--", "true"],
            &["--env-file"],
            &["--env-file", "a", "--env-file", "b", "--", "true"],
            &["--bogus", "--", "true"],
            // A relative or missing --manifest, or one given twice.
            &["--manifest"],
            &["--manifest", "envcloak.toml", "--", "true"],
            &["--manifest", "./acme/envcloak.toml", "--", "true"],
            &["--manifest", "", "--", "true"],
            &[
                "--manifest",
                "/a/envcloak.toml",
                "--manifest",
                "/b/envcloak.toml",
                "--",
                "true",
            ],
            // A --wait outside 1s to 10m, malformed, missing or twice.
            &["--wait"],
            &["--wait", "--", "true"],
            &["--wait", "0s", "--", "true"],
            &["--wait", "11m", "--", "true"],
            &["--wait", "601s", "--", "true"],
            &["--wait", "1h", "--", "true"],
            &["--wait", "5", "--", "true"],
            &["--wait", "-5s", "--", "true"],
            &["--wait", "1.5m", "--", "true"],
            &["--wait", "5\u{e9}", "--", "true"],
            &["--wait", "1m", "--wait", "2m", "--", "true"],
            // A --wait-grace outside 1s to 5s, malformed, twice or
            // without --wait.
            &["--wait", "8s", "--wait-grace"],
            &["--wait", "8s", "--wait-grace", "0s", "--", "true"],
            &["--wait", "8s", "--wait-grace", "6s", "--", "true"],
            &["--wait", "8s", "--wait-grace", "10s", "--", "true"],
            &["--wait", "8s", "--wait-grace", "1", "--", "true"],
            &["--wait", "8s", "--wait-grace", "1m", "--", "true"],
            &["--wait", "8s", "--wait-grace", "500ms", "--", "true"],
            &[
                "--wait",
                "8s",
                "--wait-grace",
                "1s",
                "--wait-grace",
                "1s",
                "--",
                "true",
            ],
            &["--wait-grace", "1s", "--", "true"],
            // A --status-fd that is not a descriptor number of 3 or more,
            // or given twice.
            &["--status-fd"],
            &["--status-fd", "--", "true"],
            &["--status-fd", "2", "--", "true"],
            &["--status-fd", "0", "--", "true"],
            &["--status-fd", "-3", "--", "true"],
            &["--status-fd", "3x", "--", "true"],
            &["--status-fd", "3", "--status-fd", "4", "--", "true"],
        ] {
            assert!(matches!(parse(bad), Err(ParseError::Usage(_))), "{bad:?}");
        }
        assert_eq!(
            parse(&["--wait", "8s", "--status-fd", "7", "--", "true"]).unwrap(),
            RunArgs {
                wait: Some(Duration::from_secs(8)),
                status_fd: Some(7),
                argv: vec!["true".into()],
                ..RunArgs::default()
            }
        );
        assert_eq!(
            parse(&["--wait-grace", "1s", "--wait", "7s", "--", "true"]).unwrap(),
            RunArgs {
                wait: Some(Duration::from_secs(7)),
                wait_grace: Some(Duration::from_secs(1)),
                argv: vec!["true".into()],
                ..RunArgs::default()
            }
        );
        for (ok, secs) in [("1s", 1), ("3s", 3), ("5s", 5)] {
            assert_eq!(parse_grace(ok), Some(Duration::from_secs(secs)), "{ok}");
        }
        for (ok, secs) in [
            ("1s", 1),
            ("59s", 59),
            ("600s", 600),
            ("10m", 600),
            ("2m", 120),
        ] {
            assert_eq!(parse_wait(ok), Some(Duration::from_secs(secs)), "{ok}");
        }
        assert_eq!(words(Duration::from_secs(90)), "1m 30s");
        assert_eq!(words(Duration::from_secs(600)), "10m");
        assert_eq!(words(Duration::from_secs(45)), "45s");
        // PTY mode, wherever it comes before `--`, once; after `--` it is
        // the command's.
        assert_eq!(
            parse(&["--manifest", "/p/envcloak.toml", "--pty", "--", "true"]).unwrap(),
            RunArgs {
                manifest: Some("/p/envcloak.toml".into()),
                pty: true,
                argv: vec!["true".into()],
                ..RunArgs::default()
            }
        );
        assert!(parse(&["--pty", "--wait", "5s", "--", "true"]).unwrap().pty);
        for bad in [
            &["--pty", "--pty", "--", "true"][..],
            &["--profile", "a", "--pty"],
            &["--pty"],
        ] {
            assert!(matches!(parse(bad), Err(ParseError::Usage(_))), "{bad:?}");
        }
        assert!(!parse(&["--", "sh", "--pty"]).unwrap().pty);
        assert_eq!(
            parse(&["--", "sh", "--pty", "--wait", "--manifest"])
                .unwrap()
                .argv,
            vec!["sh", "--pty", "--wait", "--manifest"]
        );
    }

    /// `run --help` says what PTY mode does not cover and where D-35
    /// narrows a forwarded signal (M2-17 measured it): SIGTERM and SIGHUP
    /// on Linux kernels before 6.9, named, go to the command's own group,
    /// with a nested shell the shell and not its job; and it names
    /// `pty_unavailable`. docs/RUN.md says the same
    /// (`crates/envcloak-exec/tests/pty_relay.rs` checks it).
    #[test]
    fn the_help_names_what_pty_mode_narrows() {
        for said in [
            "SIGTERM and SIGHUP",
            "Linux kernels before 6.9",
            "Ubuntu 24.04's original 6.8, Debian 12, RHEL 9",
            "the shell, not its job",
            "moving the cursor is not covered",
            "pty_unavailable",
        ] {
            assert!(PTY_HELP.contains(said), "{said}");
        }
    }

    /// `--env-file` is read only from a regular file of at most 1 MiB, a
    /// FIFO does not hang the run, and an error names the kind and line,
    /// never text from the file.
    #[test]
    fn an_env_file_is_read_only_from_a_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = |name: &str| dir.path().join(name).to_str().unwrap().to_owned();
        let message = |p: &str| read_env_file(p).unwrap_err().message().to_owned();

        std::fs::write(
            path("good"),
            "OPENAI_API_KEY=envcloak://openai/acme-web\nexport PLAIN='x y'\n",
        )
        .unwrap();
        let names = read_env_file(&path("good")).unwrap().names();
        assert_eq!(
            EnvFileParams::from(&names),
            EnvFileParams {
                refs: vec![envcloak_ipc::proto::EnvFileLine {
                    line: 1,
                    text: "OPENAI_API_KEY=openai/acme-web".into()
                }],
                plain: vec![envcloak_ipc::proto::EnvFileLine {
                    line: 2,
                    text: "PLAIN".into()
                }],
            }
        );

        let hidden = "do-not-echo-this-text";
        std::fs::write(
            path("bad"),
            format!("A=envcloak://openai/acme-web\nB='{hidden}\n"),
        )
        .unwrap();
        let e = read_env_file(&path("bad")).unwrap_err();
        assert_eq!(e.token(), "binding_unresolved");
        assert_eq!(
            e.message(),
            "--env-file: env file line 2: a quoted value is not closed"
        );
        assert!(!e.message().contains(hidden));

        std::fs::write(path("big"), vec![b'#'; MAX_ENV_FILE + 1]).unwrap();
        assert_eq!(message(&path("big")), "the --env-file is larger than 1 MiB");
        std::fs::write(path("full"), vec![b'#'; MAX_ENV_FILE]).unwrap();
        assert!(
            read_env_file(&path("full"))
                .unwrap()
                .names()
                .refs
                .is_empty()
        );

        assert_eq!(
            message(dir.path().to_str().unwrap()),
            "the --env-file is not a regular file"
        );
        assert_eq!(
            message(&path("missing")),
            "the --env-file could not be opened"
        );
        // A FIFO with no writer: opened without blocking, then refused.
        let status = std::process::Command::new("mkfifo")
            .arg(path("fifo"))
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(
            message(&path("fifo")),
            "the --env-file is not a regular file"
        );
    }
}
