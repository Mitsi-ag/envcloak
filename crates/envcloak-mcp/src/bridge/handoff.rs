//! Descriptor handoff, D-04 waiting on `run.request`, and daemon-parent
//! verification for `envcloak mcp-bridge` (SPEC §6.4, §6.6; M2 plan D-04,
//! D-18, D-33, D-36; task M2-18).
//!
//! Neither `mcp-bridge` (HTTP client mode) nor `mcp-bridge --stdio` ever
//! receives a secret value from the daemon: both create pipes and a
//! lifeline, attach the child-side descriptors to `run.request` via
//! `SCM_RIGHTS` (`Client::run_request_with_fds`), and receive only
//! `DecisionView::Started` while the daemon spawns `envcloak mcp-bridge
//! --relay` or `envcloak run --launch <id>` from its own retained anchor
//! and delivers the values on the control channel (D-36).

use std::cell::RefCell;
use std::fs::File;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use envcloak_agents::tool_timeouts::{self, LAST_ANSWER_GRACE, person_wait};
use envcloak_client::connect::{connect, run_paths};
use envcloak_client::fail::{Failure, refuse_if_traced, traced};
use envcloak_client::render::{looks_like_value, proposal_text};
use envcloak_ipc::frame::FrameError;
use envcloak_ipc::proto::{RunAnswer, RunRequestParams};
use envcloak_ipc::view::DecisionView;
use envcloak_ipc::wait::{
    CALL_GRACE, Notice, SystemClock, Transport, Waited, wait_for_run_with_grace,
};
use envcloak_ipc::{Client, ClientError, ClientFds};
use envcloak_policy::{
    AgentCatalog, Claims, PendingId, PendingState, Proposal, SubjectEvidence, gather,
};
use envcloak_sys::fdpass::{DescriptorKind, descriptor_kind};
use envcloak_sys::{PeerIdentity, PeerSource};

/// Wait budget for a bridge `run.request`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaitBudget {
    /// How long to wait for a person's approval.
    pub wait: Duration,
    /// Grace after `wait` for the daemon's final answer.
    pub grace: Duration,
}

impl WaitBudget {
    /// Explicit `--wait <duration>` from the command line, using
    /// [`CALL_GRACE`].
    #[must_use]
    pub fn explicit(wait: Duration) -> Self {
        WaitBudget {
            wait,
            grace: CALL_GRACE,
        }
    }

    /// Host-bounded wait budget (`tool_timeouts`), splitting `total` into
    /// [`person_wait`] and [`LAST_ANSWER_GRACE`].
    #[must_use]
    pub fn from_host_total(total: Duration) -> Self {
        WaitBudget {
            wait: person_wait(total),
            grace: LAST_ANSWER_GRACE,
        }
    }
}

/// Pipe ends kept by the bridge client after the daemon starts the relay or
/// runner.
#[derive(Debug)]
pub struct StartedPipes {
    /// Write end of the child's standard input.
    pub to_child: File,
    /// Read end of the child's standard output.
    pub from_child: File,
    /// Read end of the child's standard error (for `--stdio`).
    pub from_errors: Option<File>,
    /// Write end of the lifeline pipe; dropping it signals EOF to the
    /// child's lifeline descriptor.
    pub lifeline: File,
}

/// Detects the calling agent host from the process ancestry when it is one
/// of [`tool_timeouts::HOSTS`] (`claude-code` or `codex`).
#[must_use]
pub fn detected_host_wait() -> Option<WaitBudget> {
    let pid = i32::try_from(std::process::id()).ok()?;
    let me = PeerIdentity {
        uid: envcloak_sys::effective_uid(),
        pid,
        start_time: envcloak_sys::process_start_time(pid).ok()?,
        pidversion: None,
        source: PeerSource::PeerCred,
    };
    let catalog = match envcloak_core::vault::VaultPaths::for_user() {
        Ok(p) => AgentCatalog::load(&p.data_dir),
        Err(_) => AgentCatalog::builtin(),
    };
    let ev: SubjectEvidence = gather(&me, Claims::from_env(&catalog), &catalog).ok()?;
    let id = ev.label()?.name.as_str();
    tool_timeouts::host(id)
        .map(|_| WaitBudget::from_host_total(tool_timeouts::default_wait(Some(id))))
}

/// Default wait budget when `--wait` is given without a duration: uses the
/// detected host when known, otherwise `default_wait(None)` (8s).
#[must_use]
pub fn default_wait_budget() -> WaitBudget {
    detected_host_wait()
        .unwrap_or_else(|| WaitBudget::from_host_total(tool_timeouts::default_wait(None)))
}

/// Sends `params` with freshly created pipe ends (including a `stderr` pipe
/// when `with_stderr` is true), waiting according to `budget` (or
/// [`detected_host_wait`] when `budget` is `None`).
///
/// # Errors
/// Returns a [`Failure`] when the daemon refuses, the request remains
/// pending or is denied, a tracer is attached, or the daemon returns an
/// unexpected answer.
pub fn request_pipes(
    params: &RunRequestParams,
    with_stderr: bool,
    budget: Option<WaitBudget>,
) -> Result<StartedPipes, Failure> {
    refuse_if_traced()?;
    let io_fail = || {
        Failure::new(
            "run_failed",
            "the pipes for the managed server could not be created; nothing was started",
        )
    };
    let (child_in, to_child) = envcloak_sys::pipe_cloexec().map_err(|_| io_fail())?;
    let (from_child, child_out) = envcloak_sys::pipe_cloexec().map_err(|_| io_fail())?;
    let (life_read, life_write) = envcloak_sys::pipe_cloexec().map_err(|_| io_fail())?;
    let (from_errors, child_err) = if with_stderr {
        let (r, w) = envcloak_sys::pipe_cloexec().map_err(|_| io_fail())?;
        (Some(File::from(r)), Some(w))
    } else {
        (None, None)
    };
    let fds = ClientFds {
        stdin: child_in,
        stdout: child_out,
        stderr: child_err,
        lifeline: life_read,
    };

    let effective_budget = budget.or_else(detected_host_wait);
    let answer = match effective_budget {
        None => {
            let mut client = connect()?;
            let ans = client.run_request_with_fds(params, &fds)?;
            drop(client);
            ans
        }
        Some(b) => wait_with_fds(params, &fds, b)?,
    };
    // Drop the child ends so only the daemon-spawned runner or relay holds
    // them.
    drop(fds);

    validate_started_answer(&answer, &params.manifest)?;
    Ok(StartedPipes {
        to_child: File::from(to_child),
        from_child: File::from(from_child),
        from_errors,
        lifeline: File::from(life_write),
    })
}

/// Validates that a `run.request` answer for a managed bridge or launch
/// carried zero secret values and `DecisionView::Started` (D-36).
///
/// # Errors
/// Returns `protocol_error` if any secret value was returned or the decision
/// was `Covered`, `approval_required` for `Pending`, or `approval_denied`
/// for `Denied`.
pub fn validate_started_answer(answer: &RunAnswer, manifest: &str) -> Result<(), Failure> {
    if !answer.values.is_empty() {
        return Err(protocol_error());
    }
    match &answer.decision {
        DecisionView::Started {} => Ok(()),
        DecisionView::Pending { request } => {
            let id = PendingId::parse(request).ok_or_else(protocol_error)?;
            Err(Failure::new(
                "approval_required",
                format!(
                    "request={id}: run \"envcloak approve {id}\" in a terminal you control{}",
                    proposed(&answer.proposals, manifest)
                ),
            ))
        }
        DecisionView::Denied { reason } => Err(Failure::new(
            "approval_denied",
            format!("denied ({reason}); nothing was started"),
        )),
        DecisionView::Covered { .. } => Err(protocol_error()),
    }
}

struct BridgeTransport<'a> {
    paths: &'a envcloak_ipc::paths::RunPaths,
    params: &'a RunRequestParams,
    fds: &'a ClientFds,
    latest: &'a RefCell<Vec<Proposal>>,
}

impl Transport for BridgeTransport<'_> {
    fn traced(&mut self) -> bool {
        !matches!(envcloak_sys::tracer_present(), Ok(false))
    }

    fn request(&mut self, within: Duration) -> Result<RunAnswer, ClientError> {
        let _ = Instant::now()
            .checked_add(within)
            .ok_or(ClientError::Frame(FrameError::Io(
                std::io::ErrorKind::InvalidInput,
            )))?;
        let mut client = Client::connect(self.paths)?;
        let answer = client.run_request_with_fds(self.params, self.fds)?;
        self.latest.replace(answer.proposals.clone());
        Ok(answer)
    }

    fn poll(&mut self, id: &PendingId, within: Duration) -> Result<PendingState, ClientError> {
        let deadline = Instant::now()
            .checked_add(within)
            .ok_or(ClientError::Frame(FrameError::Io(
                std::io::ErrorKind::InvalidInput,
            )))?;
        Client::connect_by(self.paths, deadline)?.pending_state(id)
    }
}

fn wait_with_fds(
    params: &RunRequestParams,
    fds: &ClientFds,
    budget: WaitBudget,
) -> Result<RunAnswer, Failure> {
    if envcloak_sys::termination_ends_process().is_err() {
        return Err(Failure::new(
            "run_failed",
            "SIGINT and SIGTERM could not be made to end the wait; nothing was sent",
        ));
    }
    let paths = run_paths()?;
    let latest = RefCell::new(Vec::new());
    let mut transport = BridgeTransport {
        paths: &paths,
        params,
        fds,
        latest: &latest,
    };
    let shown = words(budget.wait);
    let mut announced_id = None;
    let mut notice = |n: Notice| match n {
        Notice::Pending(id) => {
            announced_id = Some(id);
            eprintln!(
                "envcloak: approval_required: request={id}: run \"envcloak approve {id}\" in a \
                 terminal you control{}; waiting up to {shown} for it",
                proposed(&latest.borrow(), &params.manifest)
            );
        }
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
        &mut transport,
        &mut SystemClock::new(),
        budget.wait,
        budget.grace,
        &mut notice,
    )? {
        Waited::Answer(answer) => Ok(answer),
        Waited::Denied(id) => Err(Failure::new(
            "approval_denied",
            format!("request={id} was denied; nothing was started"),
        )),
        Waited::Expired(id) | Waited::TimedOut(id) => Err(Failure::new(
            "approval_required",
            format!(
                "request={id}: run \"envcloak approve {id}\" in a terminal you control{}",
                proposed(&latest.borrow(), &params.manifest)
            ),
        )),
        Waited::TooManyPending(e) => Err(Failure::from(ClientError::Rpc(e))),
        Waited::Traced => Err(traced()),
        Waited::Unanswered => Err(Failure::new(
            "daemon_unavailable",
            format!(
                "the daemon did not answer within the wait ({shown}, and {}s for a last \
                 answer); nothing was started",
                budget.grace.as_secs()
            ),
        )),
    }
}

fn proposed(proposals: &[Proposal], manifest: &str) -> String {
    if manifest.is_empty() {
        return String::new();
    }
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

fn words(d: Duration) -> String {
    let (m, s) = (d.as_secs() / 60, d.as_secs() % 60);
    match (m, s) {
        (0, s) => format!("{s}s"),
        (m, 0) => format!("{m}m"),
        (m, s) => format!("{m}m {s}s"),
    }
}

fn protocol_error() -> Failure {
    Failure::new("protocol_error", "the daemon's answer was malformed")
}

/// Verifies that this process (`envcloak mcp-bridge --relay`) was started
/// by `envcloakd` (M2 plan D-36):
/// 1. parent PID > 1;
/// 2. inherited descriptor 3 ([`envcloak_ipc::control::CONTROL_FD`]) is a
///    Unix domain socket whose kernel peer PID equals the parent PID;
/// 3. a fresh verified connection to the daemon socket reports that same
///    parent PID.
///
/// Returns `None` if any check fails, without reading from descriptor 3.
#[must_use]
pub fn started_by_daemon() -> Option<UnixStream> {
    let parent = i32::try_from(std::os::unix::process::parent_id()).ok()?;
    if parent <= 1 {
        return None;
    }
    let fd = envcloak_sys::claim_inherited_fd(envcloak_ipc::control::CONTROL_FD).ok()?;
    let (kind, _) = descriptor_kind(fd.as_fd()).ok()?;
    if kind != DescriptorKind::Socket {
        return None;
    }
    match envcloak_sys::peer_identity(fd.as_fd()) {
        Ok(peer) if peer.pid == parent => {}
        // On macOS, `envcloakd` drops its end of `CONTROL_FD` right after
        // writing the `Release` frame (`Started::release` has `confirm = None`
        // for `Role::Relay`), which disconnects the socketpair and makes
        // `LOCAL_PEERTOKEN` return `ENOTCONN` (`ErrorKind::NotFound`) while
        // the buffered `Release` frame is still unread. The daemon socket
        // check below still proves `parent` is `envcloakd`.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        _ => return None,
    }
    let daemon = connect().ok()?;
    if envcloak_sys::peer_identity(daemon.as_fd()).ok()?.pid != parent {
        return None;
    }
    Some(UnixStream::from(fd))
}
