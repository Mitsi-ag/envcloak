//! The runner's core (SPEC §6.6; M2 plan D-33, D-34, D-36; task M2-27):
//! what `envcloak run --launch <id>` does once the daemon that started it
//! has given it a managed server's launch and values. `cmd/run.rs` reads
//! the control channel (`envcloak_ipc::control`) and hands this module
//! plain types, so this crate depends on no IPC (D-02).
//!
//! [`serve`] starts the registered server as an [`OwnedChild`] leading a
//! process group of its own, with the environment it is given (the
//! launch's, built by `envcloak_policy::managed::launch_environment`:
//! nothing of this process's is added), in the working directory the
//! daemon checked (a descriptor), from:
//! - on Linux, for a `bound` launch, the sealed copy the daemon checked
//!   ([`ServerProgram::Descriptor`], `execveat`); for a launch checked at
//!   rest, the checked descriptor, once its stamp is read again
//!   (`cmd/run.rs` compares it);
//! - otherwise the registered path ([`ServerProgram::Path`]); on macOS,
//!   with the daemon's check, started suspended: [`serve`] calls `confirm`
//!   with its pid, and resumes it only on `true`; on `false` it kills it
//!   through its handle before it runs ([`confirm_or_kill`]) and fails with
//!   [`LaunchError::Refused`] (`managed_launch_changed`).
//!
//! A start that fails is a failure: nothing is started again from another
//! file.
//!
//! The server's standard output and error are separate pipes, each read
//! through a stream of the run's [`Redactor`] and written to this
//! process's standard output and error, which are the client's pipes;
//! what the client writes to this process's standard input is copied to
//! the server's. When the client is gone (the lifeline's end of file),
//! its input ends, or a termination signal arrives, the server's group is
//! stopped through its handle: SIGTERM, then SIGKILL after
//! [`STOP_GRACE`]. Its output is then read until its end, at most
//! [`crate::DRAIN_LIMIT`] longer, and it is reaped.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::mpsc;
use std::time::Duration;

use envcloak_sys::launch::{Program, Session, Spawn, spawn};
use envcloak_sys::{Interrupter, OwnedChild, ProcessOps, TerminationSignals};
use zeroize::Zeroizing;

use crate::pump::{Cutoff, pump};
use crate::{ChildExit, DRAIN_LIMIT, Redactor};

/// How long a server has to exit after SIGTERM before SIGKILL.
pub const STOP_GRACE: Duration = Duration::from_secs(5);

/// What the server runs.
#[derive(Debug)]
pub enum ServerProgram {
    /// Linux: an open executable (the sealed copy, or the descriptor
    /// checked at rest), run with `execveat`.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    Descriptor(OwnedFd),
    /// The registered path.
    Path(Vec<u8>),
}

/// A registered launch, as the runner starts it. Its `Debug` shows counts
/// only: the environment holds the values.
pub struct ServerLaunch {
    pub program: ServerProgram,
    /// `argv[0]` first.
    pub argv: Vec<Vec<u8>>,
    /// The whole environment, each `NAME=value`, wiped when dropped.
    pub env: Vec<Zeroizing<Vec<u8>>>,
    /// The working directory the daemon checked.
    pub cwd: OwnedFd,
    /// macOS: start suspended for the daemon's check (see the module
    /// documentation).
    pub suspended: bool,
    pub redactor: Redactor,
    /// [`crate::IDLE_FLUSH`], or shorter in tests.
    pub idle_flush: Duration,
}

impl core::fmt::Debug for ServerLaunch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServerLaunch")
            .field("program", &self.program)
            .field("args", &self.argv.len())
            .field("env", &self.env.len())
            .field("suspended", &self.suspended)
            .finish_non_exhaustive()
    }
}

/// The runner's own descriptors: the client's pipe ends and the lifeline.
#[derive(Debug)]
pub struct RunnerIo {
    pub input: OwnedFd,
    pub output: OwnedFd,
    pub errors: OwnedFd,
    pub lifeline: OwnedFd,
}

/// Why a launch did not run to its end.
#[derive(Debug)]
pub enum LaunchError {
    /// The server could not be started; nothing ran, and nothing is
    /// started in its place.
    Start(io::Error),
    /// The daemon refused the started server (macOS): it was killed before
    /// it ran.
    Refused,
    /// Setting up the pipes, threads or signals failed before the server
    /// started.
    Setup(io::Error),
    /// The server started, but waiting for it failed.
    Followed(io::Error),
}

impl LaunchError {
    /// What failed, for the failure's message: the step and the system's
    /// error kind, never a path, an argument or a value.
    pub fn describe(&self) -> String {
        match self {
            LaunchError::Refused => "the started server was not the registered program".to_owned(),
            LaunchError::Start(e) => {
                format!("the managed server could not be started ({})", e.kind())
            }
            LaunchError::Setup(e) => format!("the runner could not be set up ({})", e.kind()),
            LaunchError::Followed(e) => format!(
                "the managed server could not be followed ({}, os error {})",
                e.kind(),
                e.raw_os_error().unwrap_or(0)
            ),
        }
    }

    /// The token printed with the failure.
    pub fn token(&self) -> &'static str {
        match self {
            LaunchError::Refused => "managed_launch_changed",
            LaunchError::Start(_) | LaunchError::Setup(_) | LaunchError::Followed(_) => {
                "run_failed"
            }
        }
    }
}

/// Resumes `child`, started suspended, when `confirmed`; otherwise kills
/// it through its handle (it never ran) and reaps it, so no signal can
/// reach its number afterwards.
///
/// # Errors
/// [`LaunchError::Refused`] when not confirmed; [`LaunchError::Start`]
/// when it could not be resumed (it is then killed).
pub fn confirm_or_kill<O: ProcessOps>(
    child: OwnedChild<O>,
    confirmed: bool,
) -> Result<OwnedChild<O>, LaunchError> {
    if !confirmed {
        let _ = child.kill_and_reap();
        return Err(LaunchError::Refused);
    }
    match child.resume() {
        Ok(()) => Ok(child),
        Err(e) => {
            let _ = child.kill_and_reap();
            Err(LaunchError::Start(e))
        }
    }
}

/// What ends the wait for the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ending {
    /// The client's input ended.
    Input,
    /// The lifeline ended: the client is gone.
    Lifeline,
    /// A termination signal.
    Signal(i32),
}

fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    envcloak_sys::pipe_cloexec()
}

/// Copies the client's input to the server's until it ends, then closes
/// the server's input and says so.
fn relay_input(input: OwnedFd, to_server: OwnedFd, tx: &mpsc::Sender<Ending>) {
    let mut from = File::from(input);
    let mut to = File::from(to_server);
    let mut buf = Zeroizing::new(vec![0u8; 16 * 1024]);
    loop {
        match from.read(&mut buf[..]) {
            Ok(0) => break,
            Ok(n) => {
                if to.write_all(buf.get(..n).unwrap_or_default()).is_err() {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    drop(to);
    let _ = tx.send(Ending::Input);
}

/// Waits for the lifeline's end of file. Bytes written on it (the client
/// never writes it) are read and ignored.
fn watch_lifeline(lifeline: OwnedFd, tx: &mpsc::Sender<Ending>) {
    let mut f = File::from(lifeline);
    let mut buf = [0u8; 64];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    let _ = tx.send(Ending::Lifeline);
}

/// Starts the server of `l` on `io`'s descriptors and serves it until it
/// exits or is stopped (see the module documentation). `signals` must be
/// blocked already, before any thread was started; `confirm` is asked
/// with the pid of a server started suspended.
///
/// # Errors
/// [`LaunchError`].
pub fn serve(
    l: ServerLaunch,
    io: RunnerIo,
    signals: TerminationSignals,
    confirm: impl FnOnce(u32) -> bool,
) -> Result<ChildExit, LaunchError> {
    let ServerLaunch {
        program,
        argv,
        env,
        cwd,
        suspended,
        redactor,
        idle_flush,
    } = l;
    // Every thread is started, and every step that can fail is taken,
    // before the server exists: after its start nothing returns without
    // stopping its group and reaping it. A thread started for a server
    // that then never starts ends with its pipe (the pumps and the input),
    // or with this process (the lifeline and the signals).
    let interrupter = Interrupter::install().map_err(LaunchError::Setup)?;
    let cutoff = Cutoff::default();
    let (tx, rx) = mpsc::channel::<Ending>();
    let (server_in, to_server) = pipe().map_err(LaunchError::Setup)?;
    let input_tx = tx.clone();
    let input = io.input;
    std::thread::Builder::new()
        .name("server-input".into())
        .spawn(move || relay_input(input, to_server, &input_tx))
        .map_err(LaunchError::Setup)?;
    let life_tx = tx.clone();
    let lifeline = io.lifeline;
    std::thread::Builder::new()
        .name("lifeline".into())
        .spawn(move || watch_lifeline(lifeline, &life_tx))
        .map_err(LaunchError::Setup)?;
    let sig_tx = tx;
    std::thread::Builder::new()
        .name("signals".into())
        .spawn(move || {
            while let Ok(sig) = signals.wait() {
                if sig_tx.send(Ending::Signal(sig)).is_err() {
                    break;
                }
            }
        })
        .map_err(LaunchError::Setup)?;
    let (output, errors) = (io.output, io.errors);
    // The pumps are scoped: the scope ends only once they have, and the
    // server's ends of their pipes are made, and closed, inside it.
    std::thread::scope(|s| {
        let (from_out, server_out) = pipe().map_err(LaunchError::Setup)?;
        let (from_err, server_err) = pipe().map_err(LaunchError::Setup)?;
        let redactor = &redactor;
        let interrupter = &interrupter;
        let mut pumps = Vec::new();
        for (source, sink) in [(from_out, output), (from_err, errors)] {
            // Counted before its thread starts, so the drain waits for it
            // (`Cutoff::wait_for_pumps`); a thread that cannot start drops
            // its closure and the count with it.
            let token = cutoff.pump_token();
            pumps.push(
                std::thread::Builder::new()
                    .name("server-output".into())
                    .spawn_scoped(s, move || {
                        // Interruptible, so a write the drain must give up
                        // is broken off.
                        interrupter
                            .run(|| pump(File::from(source), sink, redactor, idle_flush, token))
                    })
                    .map_err(LaunchError::Setup)?,
            );
        }
        // A test makes the start fail here, as a refused `execveat` would:
        // no other file is started in its place.
        envcloak_sys::fail_point("launch.server_exec").map_err(LaunchError::Start)?;
        let argv_refs: Vec<&[u8]> = argv.iter().map(Vec::as_slice).collect();
        let env_refs: Vec<&[u8]> = env.iter().map(|e| e.as_slice()).collect();
        let fds = [
            (server_in.as_fd(), 0),
            (server_out.as_fd(), 1),
            (server_err.as_fd(), 2),
        ];
        let program = match &program {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            ServerProgram::Descriptor(fd) => Program::Descriptor(fd.as_fd()),
            ServerProgram::Path(p) => Program::Path(p),
        };
        let spawned = spawn(&Spawn {
            program,
            argv: &argv_refs,
            env: &env_refs,
            fds: &fds,
            cwd: Some(cwd.as_fd()),
            session: Session::Group,
            suspended,
        });
        drop(env_refs);
        drop(env);
        drop(server_in);
        drop(server_out);
        drop(server_err);
        let child =
            spawned.map_err(|e| LaunchError::Start(io::Error::new(e.io().kind(), "spawn")))?;
        let child = if suspended {
            let ok = confirm(child.id());
            confirm_or_kill(child, ok)?
        } else {
            child
        };
        let followed = follow(&child, &rx, &cutoff, interrupter, pumps);
        let status = child.reap().map_err(LaunchError::Followed);
        let stopped_by = followed?;
        let status = status?;
        Ok(match stopped_by {
            Some(Ending::Signal(sig)) => ChildExit::Stopped(sig),
            _ => ChildExit::from(status),
        })
    })
}

/// What ended the wait for a server: `None` when it exited on its own.
type StoppedBy = Option<Ending>;

/// Waits for the started server `child` until it exits or `rx` says the
/// client or a signal ended it; then stops its whole group (a server that
/// exited first may have left descendants in it, which hold the values
/// too) and drains its output, while a signal or the client's going stops
/// the drain at once. Whatever fails, the group is stopped; the caller
/// reaps the child.
fn follow<O: ProcessOps>(
    child: &OwnedChild<O>,
    rx: &mpsc::Receiver<Ending>,
    cutoff: &Cutoff,
    interrupter: &Interrupter,
    pumps: Vec<std::thread::ScopedJoinHandle<'_, io::Result<crate::pump::PumpEnd>>>,
) -> Result<StoppedBy, LaunchError> {
    let mut failed = None;
    let stopped_by = loop {
        match child.has_exited() {
            Ok(true) => break None,
            Ok(false) => {}
            Err(e) => {
                failed = Some(e);
                break None;
            }
        }
        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(end) => break Some(end),
            Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => {}
        }
    };
    envcloak_sys::test_event(match stopped_by {
        None => "runner: the server exited, stopping its group",
        Some(Ending::Input) => "runner: input ended, stopping the server",
        Some(Ending::Lifeline) => "runner: lifeline ended, stopping the server",
        Some(Ending::Signal(_)) => "runner: signal, stopping the server",
    });
    // Always: the group outlives a leader that exited first while any of
    // its members runs, and the leader, unreaped, keeps its number its own.
    let stopped = child.stop_group(STOP_GRACE);
    cutoff.start(DRAIN_LIMIT);
    // The client gone, or a signal: nothing is left to deliver to.
    match stopped_by {
        Some(Ending::Lifeline) => cutoff.stop_now(libc::SIGHUP),
        Some(Ending::Signal(sig)) => cutoff.stop_now(sig),
        Some(Ending::Input) | None => {}
    }
    drain(rx, cutoff, interrupter);
    for p in pumps {
        let _ = p.join();
    }
    if let Some(e) = failed {
        return Err(LaunchError::Followed(e));
    }
    stopped.map_err(LaunchError::Followed)?;
    Ok(stopped_by)
}

/// Waits for the pumps to end, interrupting a write they must give up
/// (`Cutoff::wait_for_pumps`), while the client's going (the lifeline's
/// end) or a signal read from `rx` stops the drain at once: a pump
/// writing to an output nobody reads never holds the runner up after
/// that.
fn drain(rx: &mpsc::Receiver<Ending>, cutoff: &Cutoff, interrupter: &Interrupter) {
    std::thread::scope(|s| {
        let waiter = s.spawn(|| cutoff.wait_for_pumps(interrupter));
        while !waiter.is_finished() {
            match rx.recv_timeout(Duration::from_millis(20)) {
                Ok(Ending::Lifeline) => cutoff.stop_now(libc::SIGHUP),
                Ok(Ending::Signal(sig)) => cutoff.stop_now(sig),
                Ok(Ending::Input) | Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    // Nothing can stop the drain any more but its own
                    // deadline and the reader.
                    let _ = waiter.join();
                    return;
                }
            }
        }
    });
}

/// The server's whole environment, each `NAME=value`, wiped when
/// dropped: `envcloak_policy::managed::launch_environment` of `inherited`
/// (this process's own, which the daemon set), the recorded `PATH` and
/// variables, and the bindings' values. Nothing else of this process's
/// environment passes.
#[allow(clippy::disallowed_methods)] // The values go to the server's environment.
pub fn server_env(
    inherited: &[(std::ffi::OsString, std::ffi::OsString)],
    path_env: &[u8],
    vars: &[(String, String)],
    bindings: &[(envcloak_policy::EnvName, envcloak_core::SecretBytes)],
) -> Vec<Zeroizing<Vec<u8>>> {
    use secrecy::ExposeSecret;
    use std::os::unix::ffi::OsStrExt;
    let values: Vec<(&str, &[u8])> = bindings
        .iter()
        .map(|(name, value)| (name.as_str(), value.expose_secret()))
        .collect();
    envcloak_policy::managed::launch_environment(
        inherited.iter().map(|(k, v)| (k.as_bytes(), v.as_bytes())),
        path_env,
        vars,
        &values,
    )
    .into_iter()
    .map(|(k, v)| {
        let v = Zeroizing::new(v);
        Zeroizing::new([k.as_slice(), b"=", v.as_slice()].concat())
    })
    .collect()
}

/// Whether `fd` is still the file `stamp` describes (device, inode, size
/// and change times): a launch checked at rest is run from its checked
/// descriptor only then.
///
/// # Errors
/// `fstat`'s.
pub fn same_stamp(
    fd: BorrowedFd<'_>,
    dev: u64,
    ino: u64,
    size: u64,
    mtime_ns: i128,
    ctime_ns: i128,
) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let f = File::from(fd.try_clone_to_owned()?);
    let m = f.metadata()?;
    let ns = |s: i64, n: i64| i128::from(s) * 1_000_000_000 + i128::from(n);
    Ok(m.dev() == dev
        && m.ino() == ino
        && m.len() == size
        && ns(m.mtime(), m.mtime_nsec()) == mtime_ns
        && ns(m.ctime(), m.ctime_nsec()) == ctime_ns)
}

#[cfg(test)]
mod tests {
    use super::*;
    use envcloak_sys::owned::{Recorded, RecordingProcesses};

    /// D-34: a refused suspended child is signalled through its unreaped
    /// handle only, then reaped; no call names its pid after that (the
    /// handle is consumed: `OwnedChild`'s compile-fail test). A confirmed
    /// one is resumed and nothing else.
    ///
    /// Mutation checked: signal the refused child by its numeric pid after
    /// reaping (`libc::kill` after `reap`): the recorded calls end in a
    /// reap no more, and the clippy ban refuses the call.
    #[test]
    fn a_refused_child_is_killed_through_its_handle_before_it_is_reaped() {
        let ops = RecordingProcesses::new();
        let child = ops.child(4242);
        assert!(matches!(
            confirm_or_kill(child, false),
            Err(LaunchError::Refused)
        ));
        let calls = ops.calls();
        assert_eq!(
            calls,
            vec![
                Recorded::Signal(4242, false, libc::SIGKILL),
                Recorded::Reap(4242)
            ],
            "{calls:?}"
        );
        let ops = RecordingProcesses::new();
        let child = ops.child(4343);
        let child = confirm_or_kill(child, true).unwrap();
        assert_eq!(
            ops.calls(),
            vec![Recorded::Signal(4343, false, libc::SIGCONT)]
        );
        ops.exit(4343);
        child.reap().unwrap();
    }
}
