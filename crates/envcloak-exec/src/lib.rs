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
//!    color their output only on a terminal print plain text; PTY mode
//!    (`--pty`) is M2's.
//! 4. Signals ([`signals`]): with a controlling terminal the child stays in
//!    this process's group, so the terminal's SIGINT and SIGQUIT reach it
//!    directly, and SIGTERM and SIGHUP are passed on. Without one the child
//!    leads a group of its own, and SIGINT, SIGTERM, SIGHUP and SIGQUIT are
//!    passed on to that group. This process outlives them all, so every
//!    byte the child writes goes through the redactor.
//! 5. The exit: [`ChildExit`], the child's code or the signal that ended
//!    it, which a shell reports as 128 plus its number
//!    ([`ChildExit::shell_code`]). After the child exits, output is read
//!    until end of stream; when a descendant still holds the pipes
//!    [`DRAIN_LIMIT`] (2 seconds) later, they are closed, and what it
//!    writes after that is lost, never passed through.
//!
//! When the reader of this process's output goes away (`EPIPE`), the
//! child's end of that pipe is closed too, so the child gets `SIGPIPE` or
//! `EPIPE` on its next write, as it would writing to the reader directly.
//! A slow reader slows the child: nothing is buffered beyond one read and
//! what the redactor holds back.
//!
//! The command is never `exec`ed in this process's place: that would end
//! redaction. [`run`] takes over SIGINT, SIGTERM, SIGHUP and SIGQUIT for
//! the process while it runs, so there is one run at a time per process.

mod coverage;
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

pub use coverage::{
    COMFORT_LEN, CoverageReport, Label, MIN_VALUE_LEN, ShortPolicy, build_redactor,
};

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

/// How the child ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChildExit {
    /// It exited with this code.
    Code(u8),
    /// This signal ended it.
    Signal(i32),
}

impl ChildExit {
    /// The code a shell reports: the exit code, or 128 plus the signal's
    /// number.
    pub fn shell_code(&self) -> u8 {
        match *self {
            ChildExit::Code(c) => c,
            ChildExit::Signal(s) => u8::try_from(128 + s.clamp(0, 127)).unwrap_or(u8::MAX),
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
    /// Setting up the run failed: signals, pipes, threads, or waiting for
    /// the child.
    Setup(io::ErrorKind),
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
            ExecError::Setup(_) => "run_failed",
        }
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
                "the command could not be started or followed (signals, pipes or threads)"
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
/// [`ExecError::Setup`] when signals, pipes or threads cannot be set up (a
/// child already started is then killed and reaped) or waiting for it
/// fails.
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
    let spawned = spawn::spawn(&argv, &injected, stdin, !terminal);
    // The values are in the child's environment now; the redactor holds
    // the only other copies.
    drop(injected);
    let child = spawned?;
    follow(child, &forwarder, &redactor, idle_flush, stdout, stderr)
}

/// Pumps the child's output, passes signals on and waits for it: see the
/// crate documentation.
fn follow(
    mut child: std::process::Child,
    forwarder: &signals::Forwarder,
    redactor: &Redactor,
    idle: Duration,
    stdout: OwnedFd,
    stderr: OwnedFd,
) -> Result<ChildExit, ExecError> {
    let setup = |e: io::Error| ExecError::Setup(e.kind());
    let Ok(pid) = i32::try_from(child.id()) else {
        return Err(abandon(child, io::ErrorKind::InvalidData.into()));
    };
    let (Some(out), Some(err)) = (child.stdout.take(), child.stderr.take()) else {
        return Err(abandon(child, io::ErrorKind::BrokenPipe.into()));
    };
    let state = signals::ChildState::running(pid);
    let cutoff = pump::Cutoff::default();
    std::thread::scope(|s| {
        let started = (|| {
            let a = std::thread::Builder::new()
                .name("envcloak-stdout".into())
                .spawn_scoped(s, || pump::pump(out, stdout, redactor, idle, &cutoff))?;
            let b = std::thread::Builder::new()
                .name("envcloak-stderr".into())
                .spawn_scoped(s, || pump::pump(err, stderr, redactor, idle, &cutoff))?;
            let f = std::thread::Builder::new()
                .name("envcloak-signals".into())
                .spawn_scoped(s, || forwarder.forward(&state))?;
            Ok::<_, io::Error>((a, b, f))
        })();
        // Without its threads the child would block on a full pipe, or run
        // with no one to pass signals on: it is killed. The threads that
        // did start end with its pipes and the forwarder's stop.
        let threads = started.inspect_err(|_| {
            state.exited();
            let _ = child.kill();
            forwarder.stop();
        });
        let waited = envcloak_sys::wait_for_exit(pid);
        state.exited();
        let status = child.wait();
        cutoff.start(DRAIN_LIMIT);
        let threads = threads.map_err(setup)?;
        let _ = threads.0.join();
        let _ = threads.1.join();
        forwarder.stop();
        let _ = threads.2.join();
        waited.map_err(setup)?;
        Ok(ChildExit::from(status.map_err(setup)?))
    })
}

/// Kills and reaps a child that cannot be followed, and returns the error.
fn abandon(mut child: std::process::Child, e: io::Error) -> ExecError {
    let _ = child.kill();
    let _ = child.wait();
    ExecError::Setup(e.kind())
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
}
