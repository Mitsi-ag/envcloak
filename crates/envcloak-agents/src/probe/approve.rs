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
use std::time::{Duration, Instant};

use envcloak_policy::PendingId;

use super::local::ProbeDaemon;

/// How long one `envcloak approve` may take (Argon2id runs in the daemon).
pub const APPROVE_LIMIT: Duration = Duration::from_secs(120);
/// How long to wait between two looks at the pending requests.
const POLL: Duration = Duration::from_millis(250);

/// Why an approval was not given. Value-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApproveError {
    /// The probe daemon holds no passphrase: its vault was not created.
    NoVault,
    /// `envcloak approve` could not be started.
    Spawn,
    /// It did not finish within its limit, and was stopped.
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
/// too.
///
/// # Errors
/// See [`ApproveError`].
pub fn approve_pending(
    daemon: &ProbeDaemon,
    id: &PendingId,
    envcloak: &Path,
    markers: &[(OsString, OsString)],
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
    let spawned = cmd.spawn();
    // `cmd` and this process's read side go now: the command holds the
    // only read side, so the pipe ends for it once the passphrase is in.
    drop(cmd);
    drop(read);
    let mut child = spawned.map_err(|_| ApproveError::Spawn)?;
    let mut write = std::fs::File::from(write);
    let written = write
        .write_all(pass.as_bytes())
        .and_then(|()| write.write_all(b"\n"));
    drop(write);
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
    .map(|s| std::thread::spawn(move || drain(s)))
    .collect();
    let pid = i32::try_from(child.id()).unwrap_or(0);
    let end = Instant::now() + APPROVE_LIMIT;
    let mut timed_out = false;
    while !envcloak_sys::has_exited(pid).unwrap_or(true) {
        if Instant::now() > end {
            timed_out = true;
            // Still this process's own unreaped child (D-34).
            let _ = child.kill();
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let status = child.wait();
    for d in drains {
        let _ = d.join();
    }
    if timed_out {
        return Err(ApproveError::TimedOut);
    }
    match status {
        Ok(s) if s.success() && written.is_ok() => Ok(()),
        Ok(s) => Err(ApproveError::Refused(s.code().unwrap_or(-1))),
        Err(_) => Err(ApproveError::Spawn),
    }
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
                return match approve_pending(self.daemon, &id, &self.envcloak, &self.markers) {
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
