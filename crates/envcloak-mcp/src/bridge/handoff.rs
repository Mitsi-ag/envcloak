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
use std::io::{self, Write};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use envcloak_agents::tool_timeouts::{self, LAST_ANSWER_GRACE, MAX_WAIT, person_wait};
use envcloak_client::connect::{connect, run_paths};
use envcloak_client::fail::{Failure, refuse_if_traced, traced};
use envcloak_client::render::{looks_like_value, proposal_text};
use envcloak_ipc::frame::FrameError;
use envcloak_ipc::proto::{ErrorKind, RunAnswer, RunRequestParams};
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
use serde_json::{Value, json};

use crate::lifecycle::{self, Phase};
use crate::router::ToolResult;
use crate::rpc::{self, Incoming, PARSE_ERROR, PARSE_MESSAGE};
use crate::stdio::{Line, LineReader};

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

/// Established bridge session after either an immediate grant, an explicit
/// `--wait` approval, or the MCP pre-approval handshake and polling loop.
pub struct BridgeSession {
    /// Pipe ends connected to the daemon-started runner or relay.
    pub pipes: StartedPipes,
    /// Optional receiver of lines from `stdin` if a reader thread was started
    /// during the MCP pre-approval phase.
    pub stdin_rx: Option<mpsc::Receiver<io::Result<Line>>>,
    /// Any `stdin` lines that arrived on the pre-approval channel right as
    /// approval completed, to be forwarded after the relay handshake and
    /// `initialize` replay.
    pub queued_stdin: Vec<Vec<u8>>,
    /// Optional `initialize` request line that was already answered locally by
    /// the bridge while pending and must be replayed to the started child
    /// (absorbing its `initialize` reply and emitting
    /// `notifications/tools/list_changed`).
    pub replayed_initialize: Option<Vec<u8>>,
    /// Whether the host already sent `notifications/initialized` during the
    /// pre-approval phase.
    pub saw_initialized_notification: bool,
}

impl std::fmt::Debug for BridgeSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BridgeSession")
            .field("pipes", &self.pipes)
            .field("has_stdin_rx", &self.stdin_rx.is_some())
            .field("queued_stdin_len", &self.queued_stdin.len())
            .field(
                "has_replayed_initialize",
                &self.replayed_initialize.is_some(),
            )
            .field(
                "saw_initialized_notification",
                &self.saw_initialized_notification,
            )
            .finish()
    }
}

/// Events handled during the MCP pre-approval state machine.
enum PreApprovalEvent {
    Stdin(io::Result<Line>),
    Approved(Option<StartedPipes>),
    Terminal(Failure),
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

fn make_pipes(with_stderr: bool) -> Result<(StartedPipes, ClientFds), Failure> {
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
    let pipes = StartedPipes {
        to_child: File::from(to_child),
        from_child: File::from(from_child),
        from_errors,
        lifeline: File::from(life_write),
    };
    Ok((pipes, fds))
}

/// Sends `params` with freshly created pipe ends (including a `stderr` pipe
/// when `with_stderr` is true), waiting synchronously when `budget` is `Some`.
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
    let (pipes, fds) = make_pipes(with_stderr)?;
    let answer = match budget {
        None => {
            let mut client = connect()?;
            let ans = client.run_request_with_fds(params, &fds)?;
            drop(client);
            ans
        }
        Some(b) => wait_with_fds(params, &fds, b)?,
    };
    drop(fds);
    validate_started_answer(&answer, &params.manifest)?;
    Ok(pipes)
}

/// Connects a bridge session to the daemon-started runner or relay.
///
/// - When `explicit_wait` is `Some(budget)`, waits synchronously via D-04
///   before reading `stdin`.
/// - When `explicit_wait` is `None` (the standard MCP host invocation written
///   by `migrate-mcp`), sends an initial `run.request`:
///   - If already covered by a grant (`DecisionView::Started`), returns
///     immediately.
///   - If `Pending` (or `too_many_pending`), answers `initialize` at once on
///     `stdout` (`< 100ms`), answers `tools/list` with `{"tools": []}`,
///     answers `tools/call` with `isError: true` naming the pending request and
///     `envcloak pending`, polls `pending.state` with D-04 backoff, and upon
///     approval hands fresh pipe ends and a lifeline to `envcloakd` so the
///     caller can replay `initialize` and emit
///     `notifications/tools/list_changed`.
///   - If `with_stderr` is true (`--stdio`) and the daemon refuses with
///     `managed_launch_changed`, answers `initialize` on `stdin`/`stdout` and
///     returns `isError: true` with `"This server changed"` and the
///     `envcloak migrate-mcp --update` command on every `tools/call` without
///     starting anything.
///
/// # Errors
/// Returns a [`Failure`] when the daemon refuses or the session ends without
/// approval.
pub fn connect_bridge(
    params: &RunRequestParams,
    with_stderr: bool,
    explicit_wait: Option<WaitBudget>,
) -> Result<BridgeSession, Failure> {
    if let Some(b) = explicit_wait {
        let pipes = request_pipes(params, with_stderr, Some(b))?;
        return Ok(BridgeSession {
            pipes,
            stdin_rx: None,
            queued_stdin: Vec::new(),
            replayed_initialize: None,
            saw_initialized_notification: false,
        });
    }

    refuse_if_traced()?;
    let (pipes, fds) = make_pipes(with_stderr)?;
    let mut client = connect()?;
    let first_attempt = client.run_request_with_fds(params, &fds);
    drop(client);
    drop(fds);

    match first_attempt {
        Ok(answer) => {
            if !answer.values.is_empty() {
                return Err(protocol_error());
            }
            match &answer.decision {
                DecisionView::Started {} => Ok(BridgeSession {
                    pipes,
                    stdin_rx: None,
                    queued_stdin: Vec::new(),
                    replayed_initialize: None,
                    saw_initialized_notification: false,
                }),
                DecisionView::Pending { request } => {
                    drop(pipes);
                    let id = PendingId::parse(request).ok_or_else(protocol_error)?;
                    run_pending_mcp_state_machine(params, with_stderr, Some(id), &answer.proposals)
                }
                DecisionView::Denied { reason } => Err(Failure::new(
                    "approval_denied",
                    format!("denied ({reason}); nothing was started"),
                )),
                DecisionView::Covered { .. } => Err(protocol_error()),
            }
        }
        Err(ClientError::Rpc(ref rpc_err))
            if matches!(rpc_err.kind, ErrorKind::TooManyPending | ErrorKind::Busy) =>
        {
            drop(pipes);
            run_pending_mcp_state_machine(params, with_stderr, None, &[])
        }
        Err(err) => {
            drop(pipes);
            let failure = Failure::from(err);
            if with_stderr && failure.token() == "managed_launch_changed" {
                serve_changed_launch_if_mcp(&failure);
            }
            Err(failure)
        }
    }
}

fn spawn_stdin_line_reader() -> mpsc::Receiver<io::Result<Line>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = LineReader::new(io::stdin());
        loop {
            let item = reader.next_line();
            let done = matches!(item, Ok(Line::End) | Err(_));
            if tx.send(item).is_err() || done {
                break;
            }
        }
    });
    rx
}

fn serve_changed_launch_if_mcp(failure: &Failure) {
    let rx = spawn_stdin_line_reader();
    let Ok(Ok(first)) = rx.recv() else {
        return;
    };
    if matches!(first, Line::End) {
        return;
    }
    let mut stdout = io::stdout().lock();
    let mut phase = Phase::New;
    let err_msg = format!(
        "This server changed since it was registered: {}; run `envcloak migrate-mcp --update` in \
         your own terminal (nothing was started)",
        failure.message()
    );
    handle_changed_launch_line(first, &mut phase, &err_msg, &mut stdout);
    while let Ok(Ok(line)) = rx.recv() {
        if matches!(line, Line::End) {
            break;
        }
        handle_changed_launch_line(line, &mut phase, &err_msg, &mut stdout);
    }
}

fn handle_changed_launch_line<W: Write>(
    line: Line,
    phase: &mut Phase,
    err_msg: &str,
    stdout: &mut W,
) {
    match line {
        Line::End => {}
        Line::Oversized => {
            let _ = stdout.write_all(&rpc::error(None, PARSE_ERROR, PARSE_MESSAGE));
            let _ = stdout.flush();
        }
        Line::Message(bytes) => match rpc::parse(&bytes) {
            Incoming::Response | Incoming::Notification { .. } => {}
            Incoming::Invalid { id, code, message } => {
                let _ = stdout.write_all(&rpc::error(id.as_ref(), code, message));
                let _ = stdout.flush();
            }
            Incoming::Request { id, method, params } => {
                let params = params.unwrap_or_default();
                let reply = match (method.as_str(), *phase) {
                    ("ping", _) => rpc::result(&id, json!({})),
                    ("initialize", Phase::New) => {
                        let asked = params
                            .get("protocolVersion")
                            .and_then(Value::as_str)
                            .unwrap_or("2025-11-25");
                        *phase = Phase::Ready;
                        let mut res = lifecycle::initialize_result(lifecycle::negotiate(asked));
                        res["capabilities"]["tools"]["listChanged"] = json!(true);
                        rpc::result(&id, res)
                    }
                    ("initialize", Phase::Ready) => rpc::error(
                        Some(&id),
                        rpc::INVALID_REQUEST,
                        "the session is initialized already",
                    ),
                    ("tools/list" | "tools/call", Phase::New) => rpc::error(
                        Some(&id),
                        rpc::INVALID_REQUEST,
                        "the session is not initialized: send initialize first",
                    ),
                    ("tools/list", Phase::Ready) => rpc::result(&id, json!({"tools": []})),
                    ("tools/call", Phase::Ready) => {
                        let tool_err = ToolResult::Err(Failure::new(
                            "managed_launch_changed",
                            err_msg.to_owned(),
                        ));
                        rpc::result(&id, tool_err.to_json())
                    }
                    _ => rpc::error(Some(&id), rpc::METHOD_NOT_FOUND, "method not found"),
                };
                let _ = stdout.write_all(&reply);
                let _ = stdout.flush();
            }
        },
    }
}

fn run_pending_mcp_state_machine(
    params: &RunRequestParams,
    with_stderr: bool,
    initial_id: Option<PendingId>,
    proposals: &[Proposal],
) -> Result<BridgeSession, Failure> {
    let prop_suffix = proposed(proposals, &params.manifest);
    let fallback_failure = |id_opt: Option<&PendingId>| match id_opt {
        Some(id) => Failure::new(
            "approval_required",
            format!(
                "request={id}: run \"envcloak approve {id}\" in a terminal you control{prop_suffix}"
            ),
        ),
        None => Failure::new(
            "too_many_pending",
            "too many requests are already waiting for approval; nothing was started",
        ),
    };

    let (ev_tx, ev_rx) = mpsc::channel::<PreApprovalEvent>();
    let (stdin_forward_tx, stdin_forward_rx) = mpsc::channel::<io::Result<Line>>();
    let in_relay_mode = Arc::new(AtomicBool::new(false));

    // Single reader thread on `stdin`: sends to `ev_tx` while in pre-approval,
    // and once `in_relay_mode` is set, sends directly to `stdin_forward_tx`.
    {
        let ev_tx = ev_tx.clone();
        let mode = Arc::clone(&in_relay_mode);
        std::thread::spawn(move || {
            let mut reader = LineReader::new(io::stdin());
            loop {
                let item = reader.next_line();
                let is_end = matches!(item, Ok(Line::End) | Err(_));
                if mode.load(Ordering::SeqCst) {
                    if stdin_forward_tx.send(item).is_err() || is_end {
                        break;
                    }
                } else if ev_tx.send(PreApprovalEvent::Stdin(item)).is_err() || is_end {
                    break;
                }
            }
        });
    }

    // Background D-04 poller thread.
    let stop_poller = Arc::new(AtomicBool::new(false));
    let current_id = Arc::new(std::sync::Mutex::new(initial_id));
    {
        let stop = Arc::clone(&stop_poller);
        let shared_id = Arc::clone(&current_id);
        let params_clone = params.clone();
        let prop_clone = prop_suffix.clone();
        std::thread::spawn(move || {
            let paths = match run_paths() {
                Ok(p) => p,
                Err(f) => {
                    let _ = ev_tx.send(PreApprovalEvent::Terminal(f));
                    return;
                }
            };
            let start = Instant::now();
            let mut sleep_dur = Duration::from_millis(100);
            while !stop.load(Ordering::SeqCst) {
                if !matches!(envcloak_sys::tracer_present(), Ok(false)) {
                    let _ = ev_tx.send(PreApprovalEvent::Terminal(traced()));
                    return;
                }
                if start.elapsed() >= MAX_WAIT {
                    let guard = shared_id
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let f = match *guard {
                        Some(ref id) => Failure::new(
                            "approval_required",
                            format!(
                                "request={id}: run \"envcloak approve {id}\" in a terminal you \
                                 control{prop_clone}"
                            ),
                        ),
                        None => Failure::new(
                            "too_many_pending",
                            "too many requests are waiting for approval; nothing was started",
                        ),
                    };
                    let _ = ev_tx.send(PreApprovalEvent::Terminal(f));
                    return;
                }

                let known_id = *shared_id
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(id) = known_id {
                    let deadline = Instant::now() + CALL_GRACE;
                    if let Ok(mut client) = Client::connect_by(&paths, deadline) {
                        match client.pending_state(&id) {
                            Ok(PendingState::Pending) => {
                                sleep_dur = Duration::from_millis(120);
                            }
                            Ok(PendingState::Approved) => {
                                let _ = ev_tx.send(PreApprovalEvent::Approved(None));
                                return;
                            }
                            Ok(PendingState::Denied) => {
                                let _ = ev_tx.send(PreApprovalEvent::Terminal(Failure::new(
                                    "approval_denied",
                                    format!("request={id} was denied; nothing was started"),
                                )));
                                return;
                            }
                            Ok(PendingState::Expired | PendingState::Unknown) => {
                                let _ = ev_tx.send(PreApprovalEvent::Terminal(Failure::new(
                                    "approval_required",
                                    format!(
                                        "request={id}: run \"envcloak approve {id}\" in a \
                                         terminal you control{prop_clone}"
                                    ),
                                )));
                                return;
                            }
                            Err(ClientError::Rpc(r)) if r.kind == ErrorKind::Busy => {
                                sleep_dur = (sleep_dur * 2).min(Duration::from_millis(500));
                            }
                            Err(_) => {}
                        }
                    }
                } else if let Ok((pipes, fds)) = make_pipes(with_stderr) {
                    if let Ok(mut client) = Client::connect(&paths) {
                        let attempt = client.run_request_with_fds(&params_clone, &fds);
                        drop(client);
                        drop(fds);
                        match attempt {
                            Ok(ans) => match ans.decision {
                                DecisionView::Started {} => {
                                    let _ = ev_tx.send(PreApprovalEvent::Approved(Some(pipes)));
                                    return;
                                }
                                DecisionView::Pending { request } => {
                                    drop(pipes);
                                    if let Some(parsed) = PendingId::parse(&request) {
                                        *shared_id
                                            .lock()
                                            .unwrap_or_else(std::sync::PoisonError::into_inner) =
                                            Some(parsed);
                                    }
                                }
                                DecisionView::Denied { reason } => {
                                    drop(pipes);
                                    let _ = ev_tx.send(PreApprovalEvent::Terminal(Failure::new(
                                        "approval_denied",
                                        format!("denied ({reason}); nothing was started"),
                                    )));
                                    return;
                                }
                                DecisionView::Covered { .. } => {
                                    drop(pipes);
                                    let _ =
                                        ev_tx.send(PreApprovalEvent::Terminal(protocol_error()));
                                    return;
                                }
                            },
                            Err(ClientError::Rpc(r))
                                if matches!(
                                    r.kind,
                                    ErrorKind::TooManyPending | ErrorKind::Busy
                                ) =>
                            {
                                drop(pipes);
                                sleep_dur = (sleep_dur * 2).min(Duration::from_millis(500));
                            }
                            Err(other) => {
                                drop(pipes);
                                let _ =
                                    ev_tx.send(PreApprovalEvent::Terminal(Failure::from(other)));
                                return;
                            }
                        }
                    }
                }
                std::thread::sleep(sleep_dur);
            }
        });
    }

    let mut stdout = io::stdout().lock();
    let mut phase = Phase::New;
    let mut saved_init: Option<Vec<u8>> = None;
    let mut saw_initialized_notif = false;
    let mut queued_after_init: Vec<Vec<u8>> = Vec::new();
    let mut announced_stderr = false;

    loop {
        match ev_rx.recv() {
            Err(_) | Ok(PreApprovalEvent::Stdin(Ok(Line::End) | Err(_))) => {
                stop_poller.store(true, Ordering::SeqCst);
                let id_now = *current_id
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                return Err(fallback_failure(id_now.as_ref()));
            }
            Ok(PreApprovalEvent::Terminal(f)) => {
                stop_poller.store(true, Ordering::SeqCst);
                return Err(f);
            }
            Ok(PreApprovalEvent::Stdin(Ok(Line::Oversized))) => {
                let _ = stdout.write_all(&rpc::error(None, PARSE_ERROR, PARSE_MESSAGE));
                let _ = stdout.flush();
            }
            Ok(PreApprovalEvent::Stdin(Ok(Line::Message(bytes)))) => {
                if !announced_stderr {
                    announced_stderr = true;
                    if let Some(pid) = *current_id
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                    {
                        eprintln!(
                            "envcloak: approval_required: request={pid}: run \"envcloak pending\" \
                             and \"envcloak approve {pid}\" in a terminal you control{prop_suffix}"
                        );
                    }
                }
                match rpc::parse(&bytes) {
                    Incoming::Response => {}
                    Incoming::Notification { method, .. } => {
                        if method == "notifications/initialized" {
                            saw_initialized_notif = true;
                        }
                    }
                    Incoming::Invalid { id, code, message } => {
                        let _ = stdout.write_all(&rpc::error(id.as_ref(), code, message));
                        let _ = stdout.flush();
                    }
                    Incoming::Request { id, method, params } => {
                        let params = params.unwrap_or_default();
                        let reply = match (method.as_str(), phase) {
                            ("ping", _) => rpc::result(&id, json!({})),
                            ("initialize", Phase::New) => {
                                let asked = params
                                    .get("protocolVersion")
                                    .and_then(Value::as_str)
                                    .unwrap_or("2025-11-25");
                                phase = Phase::Ready;
                                saved_init = Some(bytes);
                                let mut res =
                                    lifecycle::initialize_result(lifecycle::negotiate(asked));
                                res["capabilities"]["tools"]["listChanged"] = json!(true);
                                rpc::result(&id, res)
                            }
                            ("initialize", Phase::Ready) => rpc::error(
                                Some(&id),
                                rpc::INVALID_REQUEST,
                                "the session is initialized already",
                            ),
                            ("tools/list" | "tools/call", Phase::New) => rpc::error(
                                Some(&id),
                                rpc::INVALID_REQUEST,
                                "the session is not initialized: send initialize first",
                            ),
                            ("tools/list", Phase::Ready) => rpc::result(&id, json!({"tools": []})),
                            ("tools/call", Phase::Ready) => {
                                let id_now = *current_id
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                                let msg = match id_now {
                                    Some(pid) => format!(
                                        "approval_required: request={pid}: run `envcloak pending` \
                                         in your own terminal (or `envcloak approve \
                                         {pid}`){prop_suffix}"
                                    ),
                                    None => "too_many_pending: too many requests are waiting for \
                                             approval; run `envcloak pending` in your own terminal"
                                        .to_owned(),
                                };
                                let tool_err =
                                    ToolResult::Err(Failure::new("approval_required", msg));
                                rpc::result(&id, tool_err.to_json())
                            }
                            _ => rpc::error(Some(&id), rpc::METHOD_NOT_FOUND, "method not found"),
                        };
                        let _ = stdout.write_all(&reply);
                        let _ = stdout.flush();
                    }
                }
            }
            Ok(PreApprovalEvent::Approved(already_started)) => {
                stop_poller.store(true, Ordering::SeqCst);
                in_relay_mode.store(true, Ordering::SeqCst);
                while let Ok(ev) = ev_rx.try_recv() {
                    if let PreApprovalEvent::Stdin(Ok(Line::Message(b))) = ev {
                        queued_after_init.push(b);
                    }
                }
                let pipes = match already_started {
                    Some(p) => p,
                    None => request_pipes(params, with_stderr, None)?,
                };
                drop(stdout);
                return Ok(BridgeSession {
                    pipes,
                    stdin_rx: Some(stdin_forward_rx),
                    queued_stdin: queued_after_init,
                    replayed_initialize: saved_init,
                    saw_initialized_notification: saw_initialized_notif,
                });
            }
        }
    }
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
