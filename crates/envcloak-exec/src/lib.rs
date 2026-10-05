//! The run pipeline (SPEC §6.1 steps 6 to 8), used by `envcloak run`: the
//! child's environment, its redacted output, signals and exit codes.
//!
//! The caller has the values already (the daemon released them after their
//! audit entry was on disk) and has refused any it may not inject. Then:
//!
//! 1. [`build_redactor`] builds one [`Redactor`] for the run, labeled with
//!    the items' slugs, and a [`CoverageReport`]: values of 8 to 15 bytes
//!    without `allow_short`, and every value under 8 bytes, are refused
//!    ([`ExecError::ValueTooShort`]) before anything starts; the gaps in
//!    what is redacted are listed by slug for the caller to print.
//! 2. [`run`] starts the command with the values in its environment only:
//!    never in argv, a temporary file or this process's own environment.
//!    `Command::env` keeps C-string copies of them until the spawn; the
//!    wiping allocator the binaries install clears those when they are
//!    freed, as it clears the patterns the redactor's automata copy.
//! 3. Standard output and standard error are separate pipes, each read by
//!    its own thread through its own [`envcloak_redact::StreamRedactor`]:
//!    `push` on every read, `flush_idle` when the pipe has been quiet for
//!    [`RunSpec::idle_flush`] (40 ms, [`IDLE_FLUSH`]), `finish` at end of
//!    stream. Only what the redactor releases is written out. Relative
//!    order between the two streams is not kept. Standard input is
//!    inherited. The child sees pipes, not a terminal, so programs that
//!    color their output only on a terminal print plain text. PTY mode
//!    (`--pty`) starts the command on a pseudo-terminal of its own instead
//!    ([`start_pty`], M2 task M2-17; the relay is M2-19's).
//! 4. Signals ([`signals`]): with a controlling terminal the child stays in
//!    this process's group, so the terminal's SIGINT and SIGQUIT reach it
//!    directly; SIGTERM and SIGHUP are passed on, and so are a SIGINT or
//!    SIGQUIT another process sent. Without one the child leads a group of
//!    its own, and SIGINT, SIGTERM, SIGHUP and SIGQUIT are passed on to
//!    that group. This process outlives them all, so every byte the child
//!    writes goes through the redactor. A second SIGTERM is sent as
//!    SIGKILL; without a terminal, once a SIGTERM was passed on, what is
//!    left of the child's group when the child exits is killed, and so it
//!    is when a SIGTERM comes while the child's output is still read
//!    after its exit: the child is reaped only after that, so the group
//!    is still its own.
//! 5. The exit: [`ChildExit`], the child's code or the signal that ended
//!    it, which a shell reports as 128 plus its number
//!    ([`ChildExit::shell_code`]). After the child exits, output is read
//!    until end of stream; when a descendant still holds the pipes
//!    [`DRAIN_LIMIT`] (2 seconds) later, they are closed, and what it
//!    writes after that is lost, never passed through. A write to an
//!    output nobody reads is given up then too, so a stalled reader cannot
//!    hold such a pipe open past the cutoff (review F-49); what is left in
//!    a pipe that no process holds any more is delivered at the reader's
//!    pace. SIGINT, SIGTERM, SIGHUP or SIGQUIT caught after the exit stops
//!    the run at once, whatever is left: [`ChildExit::Stopped`], 128 plus
//!    its number (review T12-2).
//!
//! When the reader of this process's output goes away (`EPIPE`), the
//! child's end of that pipe is closed too, so the child gets `SIGPIPE` or
//! `EPIPE` on its next write, as it would writing to the reader directly.
//! A slow reader slows the child: nothing is buffered beyond one read and
//! what the redactor holds back.
//!
//! The command is never `exec`ed in this process's place: that would end
//! redaction. [`run`] takes over SIGINT, SIGTERM, SIGHUP and SIGQUIT for
//! the process while it runs, and `SIGURG`, with which it breaks its own
//! output threads out of a write they must give up
//! ([`envcloak_sys::Interrupter`]), so there is one run at a time per
//! process.

mod coverage;
pub mod launch;
mod pump;
mod signals;
mod spawn;

use std::ffi::OsString;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::time::Duration;

use envcloak_core::SecretBytes;
use envcloak_policy::EnvName;
pub use envcloak_redact::Redactor;
use envcloak_sys::pty::SessionMonitor;
use envcloak_sys::{Interrupter, TerminalSettings, WindowSize};

pub use coverage::{
    COMFORT_LEN, CoverageReport, Label, MIN_VALUE_LEN, ShortPolicy, build_redactor,
};

/// A command started on a pseudo-terminal of its own (PTY mode; M2 task
/// M2-17 starts it, M2-19 relays it): the PTY's master side, which carries
/// the command's merged output and takes its input, and the PTY monitor
/// that leads the command's session ([`envcloak_sys::pty`]).
pub struct PtyCommand {
    pub master: OwnedFd,
    pub monitor: SessionMonitor,
}

impl std::fmt::Debug for PtyCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PtyCommand")
            .field("monitor", &self.monitor)
            .finish_non_exhaustive()
    }
}

/// Starts `argv` with `injected` in its environment on a new PTY whose
/// slave side starts with `settings` (the outer terminal's) and `size`:
/// the PTY monitor leads the session and the command runs as its
/// foreground process group (M2 plan D-35). The values reach the
/// command's environment only, as in [`run`].
///
/// # Errors
/// [`ExecError::NoCommand`], [`ExecError::NulByte`], [`ExecError::NotFound`]
/// and [`ExecError::NotExecutable`] before anything runs, and
/// [`ExecError::Setup`] when no PTY can be opened or the monitor cannot set
/// the session up.
pub fn start_pty(
    argv: &[OsString],
    injected: &[(EnvName, SecretBytes)],
    size: Option<WindowSize>,
    settings: Option<&TerminalSettings>,
) -> Result<PtyCommand, ExecError> {
    if argv.is_empty() {
        return Err(ExecError::NoCommand);
    }
    let pty =
        envcloak_sys::pty::open_pty(size, settings).map_err(|e| ExecError::Setup(e.kind()))?;
    let monitor = spawn::spawn_session(argv, injected, pty.slave)?;
    Ok(PtyCommand {
        master: pty.master,
        monitor,
    })
}

/// How long a pipe must be quiet before the redactor releases what it held
/// back that cannot be the start of a value: 40 ms (SPEC §6.1 step 7), so
/// a prompt without a newline shows within 100 ms.
pub const IDLE_FLUSH: Duration = Duration::from_millis(40);

/// How long output is still read after the child exits, while a
/// descendant holds its pipes open.
pub const DRAIN_LIMIT: Duration = Duration::from_secs(2);

/// What [`run`] starts, and where its output goes.
pub struct RunSpec {
    /// The command and its arguments. The first is looked up on `PATH`
    /// when it has no `/`, as `execvp` does.
    pub argv: Vec<OsString>,
    /// Variables set in the child's environment, on top of this process's
    /// own: the values of the run's bindings and an env file's ordinary
    /// variables. A later entry for a name wins.
    pub injected: Vec<(EnvName, SecretBytes)>,
    /// Built by [`build_redactor`] from the bindings' values.
    pub redactor: Redactor,
    /// [`IDLE_FLUSH`] ([`RunSpec::new`]), or shorter in tests.
    pub idle_flush: Duration,
    /// The child's standard input; `None` shares this process's.
    pub stdin: Option<OwnedFd>,
    /// Where the redacted standard output goes.
    pub stdout: OwnedFd,
    /// Where the redacted standard error goes.
    pub stderr: OwnedFd,
}

impl RunSpec {
    /// A run of `argv` with `injected` in its environment, its output
    /// through `redactor` to `stdout` and `stderr`: the idle flush is
    /// [`IDLE_FLUSH`], and standard input this process's own.
    pub fn new(
        argv: Vec<OsString>,
        injected: Vec<(EnvName, SecretBytes)>,
        redactor: Redactor,
        stdout: OwnedFd,
        stderr: OwnedFd,
    ) -> RunSpec {
        RunSpec {
            argv,
            injected,
            redactor,
            idle_flush: IDLE_FLUSH,
            stdin: None,
            stdout,
            stderr,
        }
    }
}

impl core::fmt::Debug for RunSpec {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let names: Vec<&str> = self.injected.iter().map(|(n, _)| n.as_str()).collect();
        f.debug_struct("RunSpec")
            .field("args", &self.argv.len())
            .field("injected", &names)
            .field("redactor", &self.redactor)
            .field("idle_flush", &self.idle_flush)
            .finish_non_exhaustive()
    }
}

/// How the child ended, or how the run was stopped after it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChildExit {
    /// It exited with this code.
    Code(u8),
    /// This signal ended it.
    Signal(i32),
    /// It exited, and this signal, caught after its exit was seen, stopped
    /// the run before its output was all read or delivered: what was left
    /// is lost, never passed through (review T12-2).
    Stopped(i32),
}

impl ChildExit {
    /// The code a shell reports: the exit code, or 128 plus the number of
    /// the signal that ended the child or stopped the run.
    pub fn shell_code(&self) -> u8 {
        match *self {
            ChildExit::Code(c) => c,
            ChildExit::Signal(s) | ChildExit::Stopped(s) => {
                u8::try_from(128 + s.clamp(0, 127)).unwrap_or(u8::MAX)
            }
        }
    }
}

impl From<ExitStatus> for ChildExit {
    fn from(s: ExitStatus) -> Self {
        match (s.code(), s.signal()) {
            (Some(c), _) => ChildExit::Code(u8::try_from(c & 0xff).unwrap_or(u8::MAX)),
            (None, Some(sig)) => ChildExit::Signal(sig),
            // A stopped or continued status is never what `wait` returns.
            (None, None) => ChildExit::Code(u8::MAX),
        }
    }
}

/// Why a run did not start or could not be followed to its end. Carries
/// kinds and slugs only, never a value or an argument.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExecError {
    /// There is no command.
    NoCommand,
    /// Some values may not be injected: [`CoverageReport::refused_short`]
    /// names them.
    ValueTooShort(CoverageReport),
    /// A value holds a NUL byte, which no environment variable can carry.
    NulByte,
    /// The command was not found (exit 127, as `env(1)`).
    NotFound,
    /// The command was found but could not be run (exit 126, as `env(1)`).
    NotExecutable(io::ErrorKind),
    /// Setting up the run failed before the command was started: its
    /// signals, or the spawn itself (out of descriptors, processes or
    /// memory).
    Setup(io::ErrorKind),
    /// The command was started, but could not be followed to its end: its
    /// output threads, or waiting for it, failed. It may have run, and
    /// did what it did; how it ended is not known
    /// ([`ExecError::may_have_started`]).
    Followed(io::ErrorKind),
}

impl ExecError {
    /// The exit code `envcloak run` gives: 127 and 126 keep their `env(1)`
    /// meanings, and EnvCloak's own failures are 125 (SPEC §6.1 step 9).
    pub fn exit_code(&self) -> u8 {
        match self {
            ExecError::NotFound => 127,
            ExecError::NotExecutable(_) => 126,
            _ => 125,
        }
    }

    /// The stable token printed with the failure.
    pub fn token(&self) -> &'static str {
        match self {
            ExecError::NoCommand => "usage",
            ExecError::ValueTooShort(_) => "value_too_short",
            ExecError::NulByte => "binding_unresolved",
            ExecError::NotFound => "command_not_found",
            ExecError::NotExecutable(_) => "command_not_executable",
            ExecError::Setup(_) | ExecError::Followed(_) => "run_failed",
        }
    }

    /// Whether the command may have been started before this failure:
    /// only [`ExecError::Followed`]. Every other failure comes before the
    /// command could run (a spawn that fails runs nothing), so a program
    /// that started `envcloak run` may tell "not started" from "may have
    /// run" by this, never by the exit code or the output.
    pub fn may_have_started(&self) -> bool {
        matches!(self, ExecError::Followed(_))
    }

    /// A fixed message: no argument, value or path.
    pub fn message(&self) -> &'static str {
        match self {
            ExecError::NoCommand => "run needs a command after --",
            ExecError::ValueTooShort(_) => {
                "a value is too short to inject: under 8 bytes it never is, and 8 to 15 bytes \
                 need allow_short on the item"
            }
            ExecError::NulByte => {
                "a value holds a NUL byte, which no environment variable can carry"
            }
            ExecError::NotFound => "the command was not found",
            ExecError::NotExecutable(_) => "the command could not be run",
            ExecError::Setup(_) => {
                "the command could not be started (signals, descriptors, processes or memory); \
                 nothing was run"
            }
            ExecError::Followed(_) => {
                "the command was started, but could not be followed to its end (pipes, threads \
                 or waiting for it): it may have run"
            }
        }
    }
}

impl core::fmt::Display for ExecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for ExecError {}

/// Starts `spec.argv` with the injected variables and redacts its output
/// until it exits (see the crate documentation). Returns how it ended.
///
/// # Errors
/// [`ExecError::NoCommand`], [`ExecError::NulByte`], [`ExecError::NotFound`]
/// and [`ExecError::NotExecutable`] before anything runs, and
/// [`ExecError::Setup`] when signals cannot be set up or the spawn fails;
/// [`ExecError::Followed`] once the command was started, when its output
/// threads cannot be set up (it is then killed and reaped) or waiting for
/// it fails.
pub fn run(spec: RunSpec) -> Result<ChildExit, ExecError> {
    let RunSpec {
        argv,
        injected,
        redactor,
        idle_flush,
        stdin,
        stdout,
        stderr,
    } = spec;
    if argv.is_empty() {
        return Err(ExecError::NoCommand);
    }
    let terminal = signals::controlling_terminal();
    // Caught before the child exists, so a signal that arrives just after
    // it starts is passed on rather than ending this process mid-output.
    let forwarder =
        signals::Forwarder::install(terminal).map_err(|e| ExecError::Setup(e.kind()))?;
    let interrupter = Interrupter::install().map_err(|e| ExecError::Setup(e.kind()))?;
    let spawned = spawn::spawn(&argv, &injected, stdin, !terminal);
    // The values are in the child's environment now; the redactor holds
    // the only other copies.
    drop(injected);
    let child = spawned?;
    let threads = Threads {
        forwarder: &forwarder,
        interrupter: &interrupter,
    };
    follow(child, threads, &redactor, idle_flush, stdout, stderr)
}

/// What [`follow`] needs of this process for the run: its caught signals
/// and the means to break its output threads out of a write.
#[derive(Clone, Copy)]
struct Threads<'a> {
    forwarder: &'a signals::Forwarder,
    interrupter: &'a Interrupter,
}

/// Pumps the child's output, passes signals on and waits for it: see the
/// crate documentation.
fn follow(
    mut child: std::process::Child,
    threads: Threads<'_>,
    redactor: &Redactor,
    idle: Duration,
    stdout: OwnedFd,
    stderr: OwnedFd,
) -> Result<ChildExit, ExecError> {
    let Threads {
        forwarder,
        interrupter,
    } = threads;
    let setup = |e: io::Error| ExecError::Followed(e.kind());
    let Ok(pid) = i32::try_from(child.id()) else {
        return Err(abandon(child, io::ErrorKind::InvalidData.into()));
    };
    let (Some(out), Some(err)) = (child.stdout.take(), child.stderr.take()) else {
        return Err(abandon(child, io::ErrorKind::BrokenPipe.into()));
    };
    let state = signals::ChildState::running(pid);
    let cutoff = pump::Cutoff::default();
    std::thread::scope(|s| {
        // Each pump is counted before its thread starts; a thread that
        // cannot start drops its closure, and the count with it.
        // A pump whose thread cannot be made interruptible (its signal
        // mask cannot be changed) does not run: its pipe closes, so the
        // child's next write to it fails, and the run reports the failure.
        let token = cutoff.pump_token();
        let a = std::thread::Builder::new()
            .name("envcloak-stdout".into())
            .spawn_scoped(s, move || {
                interrupter.run(|| pump::pump(out, stdout, redactor, idle, token))
            });
        let token = cutoff.pump_token();
        let b = std::thread::Builder::new()
            .name("envcloak-stderr".into())
            .spawn_scoped(s, move || {
                interrupter.run(|| pump::pump(err, stderr, redactor, idle, token))
            });
        let f = std::thread::Builder::new()
            .name("envcloak-signals".into())
            .spawn_scoped(s, || forwarder.forward(&state, &cutoff));
        // Without its threads the child would block on a full pipe, or run
        // with no one to pass signals on: it is killed. The threads that
        // did start end with its pipes, the cutoff and the forwarder's
        // stop.
        let failed = [a.as_ref().err(), b.as_ref().err(), f.as_ref().err()]
            .into_iter()
            .flatten()
            .map(io::Error::kind)
            .next();
        let forwarding = || f.as_ref().is_ok_and(|f| !f.is_finished());
        if failed.is_some() {
            state.exited();
            let _ = child.kill();
            forwarder.stop(forwarding);
        }
        // A test build can make the wait fail here, after the command has
        // run, to reach the "may have run" failure no fixture can cause.
        let waited = envcloak_sys::wait_for_exit(pid)
            .and_then(|w| envcloak_sys::fail_point("exec.follow.wait").map(|()| w));
        // The child has exited and is not reaped yet, so the group it led
        // is still its own; it stays unreaped until its output has been
        // read. A run that got a SIGTERM, passed on to the child, ends what
        // is left of that group (a descendant that ignored the SIGTERM) now,
        // so a descendant holding the output does not hold up the drain.
        // The forwarder read that SIGTERM before it passed it on, so before
        // the child's exit.
        let end_group = || {
            if waited.is_ok() && forwarder.ends_childs_group() {
                let _ = envcloak_sys::signal_group(pid, libc::SIGKILL);
            }
        };
        end_group();
        // Signals caught from here on stop the run (review T12-2).
        forwarder.child_exited();
        state.exited();
        cutoff.start(DRAIN_LIMIT);
        // Bounded by the cutoff while a descendant holds a pipe, and by a
        // signal that stops the run (review F-49).
        cutoff.wait_for_pumps(interrupter);
        let mut pumped = Ok(());
        for pump in [a, b].into_iter().flatten() {
            if let Ok(Err(e)) = pump.join() {
                pumped = Err(e.kind());
            }
        }
        forwarder.stop(forwarding);
        if let Ok(f) = f {
            let _ = f.join();
        }
        // The forwarder has read every signal caught before its stop: a
        // SIGTERM that came while the output was read (it stopped the run)
        // ends what the child left in its group too, before the child is
        // reaped and the group can be another's (Codex review of M2-06,
        // high: `envcloak mcp` cancelling a call in those 2 seconds).
        end_group();
        let status = child.wait();
        if let Some(kind) = failed {
            return Err(ExecError::Followed(kind));
        }
        pumped.map_err(ExecError::Followed)?;
        waited.map_err(setup)?;
        let status = status.map_err(setup)?;
        Ok(match cutoff.stopped_by() {
            Some(sig) => ChildExit::Stopped(sig),
            None => ChildExit::from(status),
        })
    })
}

/// Kills and reaps a child that cannot be followed, and returns the error:
/// it was started, so it may have run.
fn abandon(mut child: std::process::Child, e: io::Error) -> ExecError {
    let _ = child.kill();
    let _ = child.wait();
    ExecError::Followed(e.kind())
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use super::*;

    fn dev_null() -> OwnedFd {
        File::options()
            .write(true)
            .open("/dev/null")
            .unwrap()
            .into()
    }

    /// SPEC §6.1 step 7: the idle flush is 40 ms, and a run built with
    /// [`RunSpec::new`] (as `envcloak run` builds it) uses it (review
    /// T12-4). The runner tests measure the real delay.
    #[test]
    fn the_idle_flush_is_40_ms_and_a_new_run_uses_it() {
        assert_eq!(IDLE_FLUSH, Duration::from_millis(40));
        let (redactor, _) = envcloak_redact::RedactorBuilder::new().build();
        let spec = RunSpec::new(
            vec!["true".into()],
            Vec::new(),
            redactor,
            dev_null(),
            dev_null(),
        );
        assert_eq!(spec.idle_flush, IDLE_FLUSH);
        assert!(spec.stdin.is_none());
    }

    /// A run stopped by a signal after the child's exit reports 128 plus
    /// the signal, as a death by that signal would.
    #[test]
    fn a_stopped_run_reports_128_plus_its_signal() {
        assert_eq!(ChildExit::Stopped(libc::SIGTERM).shell_code(), 143);
        assert_eq!(ChildExit::Stopped(libc::SIGINT).shell_code(), 130);
        assert_eq!(ChildExit::Signal(libc::SIGTERM).shell_code(), 143);
        assert_eq!(ChildExit::Code(3).shell_code(), 3);
    }
}
