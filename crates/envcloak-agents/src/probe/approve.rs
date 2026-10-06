//! The probe's approval path on a person's machine (M2 plan task M2-28).
//!
//! The output and sentinel probes make requests that only a person may
//! approve, and no proof rule is relaxed for them (SPEC §10b; gate 23).
//! [`approve_pending`] approves one, against the probe daemon only, by
//! running `envcloak approve <id> --once --passphrase-fd N` with the probe
//! passphrase written to a pipe that is descriptor `N` of that command
//! alone. The command runs in this process's own session and on its own
//! controlling terminal, the person's: the daemon judges it as it judges
//! any approval, so it refuses it when this process is an agent's (its
//! ancestry, or the agent markers this process carries, which the command
//! is given too), has no controlling terminal, or shares a session or a
//! terminal with the request's chain (T9-3, F-70's launcher cases). The
//! host whose request it is runs in a session and on a terminal of its own
//! ([`super::HostSession`]), so this approval is never one from the host's.
//!
//! [`ProbeApprover`] is the probes' [`super::Approver`]: it finds the
//! request with `pending.list`, as this process (which the daemon shows only
//! the requests this process may approve), then approves it as above.
//!
//! The plan's first design ran the approver in a fresh pseudo-terminal
//! session of the runner's own making. A process that makes its own
//! terminal is a terminal subject to the daemon (docs/AGENTS.md "Limits":
//! `script`, `tmux`), so a runner with no terminal, or one an agent
//! started with its ancestry cut, would have approved; the plan requires
//! the opposite (a runner without a controlling terminal reads
//! `probe_needs_terminal`). So the approval is the person's terminal's, and
//! the fresh session and terminal are the host's instead.

use std::ffi::OsString;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use envcloak_policy::PendingId;

use super::local::ProbeDaemon;

/// How long one `envcloak approve` may take (Argon2id runs in the daemon).
pub const APPROVE_LIMIT: Duration = Duration::from_secs(120);
/// How long to wait between two looks at the pending requests.
const POLL: Duration = Duration::from_millis(250);
/// How long the output of a finished `envcloak approve` is read for.
pub const DRAIN_GRACE: Duration = Duration::from_secs(2);

/// Why an approval was not given. Value-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApproveError {
    /// The probe daemon holds no passphrase: its vault was not created.
    NoVault,
    /// `envcloak approve` could not be started.
    Spawn,
    /// It did not finish within its limit or the host run's, or the run
    /// ended first, and it was stopped.
    TimedOut,
    /// It exited with this code: the daemon refused the approval (a proof
    /// refused, the request gone), or the command refused it first.
    Refused(i32),
}

impl ApproveError {
    /// What it means, value-free.
    pub fn message(self) -> &'static str {
        match self {
            ApproveError::NoVault => "the probe daemon has no vault",
            ApproveError::Spawn => "envcloak approve could not be started",
            ApproveError::TimedOut => "envcloak approve did not finish in time",
            ApproveError::Refused(_) => "the approval was refused",
        }
    }
}

/// Approves request `id` of the probe daemon, once (see the module
/// documentation): `envcloak` is the `envcloak` to run, `markers` the
/// agent markers of this process's environment, which the command gets
/// too. It is given until `deadline` (the host run's) or [`APPROVE_LIMIT`],
/// whichever comes first, and is stopped once `stop` is set (the host's run
/// ended): a command past either is killed while it is this process's own
/// unreaped child (D-34), then reaped, and its output is read for at most
/// [`DRAIN_GRACE`] more (a process it left holding its output does not hold
/// this one). A child whose state cannot be read is taken as running, and
/// is killed before it is waited for (Codex cycle488 F144).
///
/// # Errors
/// See [`ApproveError`].
pub fn approve_pending(
    daemon: &ProbeDaemon,
    id: &PendingId,
    envcloak: &Path,
    markers: &[(OsString, OsString)],
    deadline: Instant,
    stop: &AtomicBool,
) -> Result<(), ApproveError> {
    let pass = daemon.passphrase().ok_or(ApproveError::NoVault)?;
    let (read, write) = envcloak_sys::pipe_cloexec().map_err(|_| ApproveError::Spawn)?;
    let id_text = id.to_string();
    let fd_text = read.as_raw_fd().to_string();
    let mut cmd = Command::new(envcloak);
    cmd.env_clear()
        .envs(daemon.env().iter().map(|(k, v)| (k, v)))
        .envs(markers.iter().map(|(k, v)| (k, v)))
        .args([
            "approve",
            id_text.as_str(),
            "--once",
            "--passphrase-fd",
            fd_text.as_str(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    envcloak_sys::inherit_on_spawn(&mut cmd, read.as_fd()).map_err(|_| ApproveError::Spawn)?;
    let spawned = crate::detect::spawn_unreaped(&mut cmd);
    // `cmd` and this process's read side go now: the command holds the
    // only read side, so the pipe ends for it once the passphrase is in.
    drop(cmd);
    drop(read);
    let child = spawned.map_err(|_| ApproveError::Spawn)?;
    let mut write = std::fs::File::from(write);
    let written = write
        .write_all(pass.as_bytes())
        .and_then(|()| write.write_all(b"\n"));
    drop(write);
    let (stopped, status) = await_child(child, approval_end(deadline), stop);
    if stopped {
        return Err(ApproveError::TimedOut);
    }
    match status {
        Ok(s) if s.success() && written.is_ok() => Ok(()),
        Ok(s) => Err(ApproveError::Refused(s.code().unwrap_or(-1))),
        Err(_) => Err(ApproveError::Spawn),
    }
}

/// When an approval started now must end: the host run's `deadline`, or
/// [`APPROVE_LIMIT`] from now, whichever comes first.
fn approval_end(deadline: Instant) -> Instant {
    deadline.min(Instant::now() + APPROVE_LIMIT)
}

/// Waits for `child` (its standard output and error piped) until `end` or
/// until `stop` is set, reading and dropping its output; one still running
/// then, or whose state cannot be read, is killed while it is this
/// process's own unreaped child (D-34). Reaps it, and reads its output for
/// at most [`DRAIN_GRACE`] more. Returns whether it was stopped, and its
/// status.
fn await_child(
    mut child: std::process::Child,
    end: Instant,
    stop: &AtomicBool,
) -> (bool, std::io::Result<std::process::ExitStatus>) {
    let drains: Vec<_> = [
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
    ]
    .into_iter()
    .map(|s| {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            drain(s);
            let _ = tx.send(());
        });
        rx
    })
    .collect();
    let pid = i32::try_from(child.id()).unwrap_or(0);
    let mut stopped = false;
    loop {
        match envcloak_sys::has_exited(pid) {
            Ok(true) => break,
            Ok(false) if Instant::now() < end && !stop.load(Ordering::SeqCst) => {
                std::thread::sleep(Duration::from_millis(20));
            }
            // Its state not known: not known to be this process's own child
            // any more (its pid may be another process's), so nothing is
            // sent; the wait below returns at once for a child not there.
            Err(_) => {
                stopped = true;
                break;
            }
            // Past its time or told to stop: still this process's own
            // unreaped child (started by `spawn_unreaped`), so the signal
            // is its.
            Ok(false) => {
                stopped = true;
                let _ = child.kill();
                break;
            }
        }
    }
    let status = child.wait();
    let grace = Instant::now() + DRAIN_GRACE;
    for d in drains {
        let _ = d.recv_timeout(grace.saturating_duration_since(Instant::now()));
    }
    (stopped, status)
}

/// Reads what a stream says to its end, and drops it.
fn drain(s: Option<Box<dyn std::io::Read + Send>>) {
    let Some(mut s) = s else { return };
    let mut buf = [0u8; 8192];
    while let Ok(n) = s.read(&mut buf) {
        if n == 0 {
            break;
        }
    }
}

/// The probes' approver on a person's machine: see the module
/// documentation.
pub struct ProbeApprover<'d> {
    daemon: &'d ProbeDaemon,
    envcloak: PathBuf,
    markers: Vec<(OsString, OsString)>,
    claims: Vec<String>,
    given: AtomicUsize,
}

impl std::fmt::Debug for ProbeApprover<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProbeApprover")
            .field("daemon", self.daemon)
            .field("given", &self.given())
            .finish_non_exhaustive()
    }
}

impl<'d> ProbeApprover<'d> {
    pub fn new(
        daemon: &'d ProbeDaemon,
        envcloak: PathBuf,
        markers: Vec<(OsString, OsString)>,
        claims: Vec<String>,
    ) -> ProbeApprover<'d> {
        ProbeApprover {
            daemon,
            envcloak,
            markers,
            claims,
            given: AtomicUsize::new(0),
        }
    }

    /// How many approvals it gave.
    pub fn given(&self) -> usize {
        self.given.load(Ordering::SeqCst)
    }
}

impl super::Approver for ProbeApprover<'_> {
    fn approve(&self, deadline: Instant, stop: &AtomicBool) -> Result<(), String> {
        while Instant::now() < deadline && !stop.load(Ordering::SeqCst) {
            let first = self
                .daemon
                .connect()
                .and_then(|mut c| c.pending_list(&self.claims))
                .ok()
                .filter(envcloak_ipc::view::PendingListView::well_formed)
                .and_then(|l| l.requests.into_iter().next())
                .and_then(|r| PendingId::parse(&r.request));
            if let Some(id) = first {
                return match approve_pending(
                    self.daemon,
                    &id,
                    &self.envcloak,
                    &self.markers,
                    deadline,
                    stop,
                ) {
                    Ok(()) => {
                        self.given.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    }
                    Err(e) => Err(e.message().to_owned()),
                };
            }
            std::thread::sleep(POLL);
        }
        Err("no request was pending".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str) -> std::process::Child {
        Command::new("/bin/sh")
            .args(["-c", script])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("{e}"))
    }

    /// An approval command is held to the host run's deadline and its stop,
    /// not to its own limit alone, and a process it leaves holding its
    /// output does not hold the wait (Codex cycle488 F144). Mutations
    /// checked: the deadline left out of `approval_end` (`APPROVE_LIMIT`
    /// alone: its end is then two minutes on); the stop flag not looked at
    /// (the second case waits for its deadline); the output drains joined
    /// without a bound (the third case waits for the left process, 30 s).
    #[test]
    fn an_approval_is_held_to_the_runs_deadline_and_stop() {
        let soon = Instant::now() + Duration::from_millis(500);
        assert!(approval_end(soon) <= soon);
        let later = Instant::now() + Duration::from_secs(3600);
        assert!(approval_end(later) <= Instant::now() + APPROVE_LIMIT);
        let t = Instant::now();
        let (stopped, _) = await_child(
            sh("sleep 30"),
            Instant::now() + Duration::from_millis(500),
            &AtomicBool::new(false),
        );
        assert!(stopped);
        assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());

        let t = Instant::now();
        let stop = AtomicBool::new(false);
        let (stopped, _) = std::thread::scope(|s| {
            s.spawn(|| {
                std::thread::sleep(Duration::from_millis(300));
                stop.store(true, Ordering::SeqCst);
            });
            await_child(
                sh("sleep 30"),
                Instant::now() + Duration::from_secs(60),
                &stop,
            )
        });
        assert!(stopped);
        assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());

        let t = Instant::now();
        let (stopped, status) = await_child(
            sh("sleep 30 & echo done; exit 3"),
            Instant::now() + Duration::from_secs(60),
            &AtomicBool::new(false),
        );
        assert!(!stopped);
        assert_eq!(status.ok().and_then(|s| s.code()), Some(3));
        assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
    }
}
