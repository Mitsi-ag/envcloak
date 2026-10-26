//! Daemon sign-in attempt supervision (`SPEC.md` §6.8, M2 plan D-25, D-31,
//! D-34, D-36, F-73, F-74, CR-3, gates `b3`, `b12`, `b14`, `b15`, `b16`, `b17`,
//! task `M2b-09`).
//!
//! Responsibilities:
//! - Long-lived supervision thread that spawns `envcloakd --signin-driver` and
//!   `envcloakd --signin-reaper` from the daemon's retained startup image
//!   ([`EntryImageAnchor`]), so Linux `PR_SET_PDEATHSIG` is bound to a thread
//!   that lives as long as the daemon.
//! - Durable `signin_intent` audit before spawning the driver or decrypting any
//!   login field; an audit failure starts no driver and decrypts nothing.
//! - Per-account serialization and step-locked TOTP generation via
//!   [`TotpState`] and [`AttemptLease`].
//! - Step-by-step credential release over the private driver pipe (`NeedUsername`,
//!   `NeedPassword`, `NeedCode`, `NeedAdapterKey`).
//! - Immediate teardown on driver exit, reaper exit, vault lock, machine sleep,
//!   requester root exit, per-attempt timeout, cancel, or login revision change,
//!   using only owned [`OwnedChild`] handles (never a stored or reported PID)
//!   and verifying on-disk `teardown.confirmed` (`CR-3`).
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, mpsc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use envcloak_browser::{
    AttemptOutcome, AttemptSpec, DaemonToDriver, DeclaredState, DriverMessage, EntryImageAnchor,
    LaunchSpec, WorkerStopReason,
};
use envcloak_core::SecretBytes;
use envcloak_core::vault::{AttemptLease, FieldKind, ItemId, Vault};
use envcloak_signin::{AttemptFailure, RequestId, StopReason, WorkerId};
use envcloak_sys::{
    OwnedChild, ProcessOps, SystemProcesses, fail_point, pause_point, pipe_cloexec,
};

use crate::signin::driver::{DriverSession, spawn_driver};
use crate::signin::ops::CapturedBrowserState;
use crate::signin::reaper::{ReaperSession, spawn_reaper};
use crate::signin::sweep::{BootId, finalize_active_attempt, prepare_attempt_dir};
use crate::totp::{
    AttemptGuard, TotpError, TotpState, code_to_zeroizing_utf8, secret_to_zeroizing_utf8,
};

/// Owned process handles and lifeline write end for a running sign-in attempt
/// (`M2b-09`).
#[derive(Debug)]
pub struct AttemptHandle<P: ProcessOps = SystemProcesses> {
    pub driver: OwnedChild<P>,
    pub reaper: OwnedChild<P>,
    pub lifeline_w: OwnedFd,
}

impl<P: ProcessOps> AttemptHandle<P> {
    /// Stops and reaps both the driver and reaper handles in strict owned-handle
    /// order (`D-34`, `F-73`):
    /// 1. Observe driver exit without reaping (`driver.has_exited()`).
    /// 2. Signal the driver's process group while the driver is unreaped.
    /// 3. Reap the driver (`driver.reap()`).
    /// 4. Drop `lifeline_w` so the reaper sees EOF even if its control pipe
    ///    closed.
    /// 5. Wait for the reaper to finish teardown (`reaper.wait_exit()`) and
    ///    reap the reaper (`reaper.reap()`).
    ///
    /// Never signals any process after reaping its handle.
    pub fn teardown_owned(self) -> io::Result<()> {
        let Self {
            driver,
            reaper,
            lifeline_w,
        } = self;

        if driver.has_exited().is_ok() {
            let _ = driver.signal_group_before_reap(libc::SIGKILL);
            let _ = driver.reap();
        }
        drop(lifeline_w);

        if reaper.has_exited().is_ok() {
            let _ = reaper.wait_exit();
            let _ = reaper.reap();
        }
        Ok(())
    }
}

/// Active daemon-side sessions for an in-flight attempt.
pub struct ActiveAttemptSession {
    pub request: RequestId,
    pub worker: WorkerId,
    pub item: ItemId,
    pub attempt_id: String,
    pub attempt_dir: PathBuf,
    pub started_wall_secs: u64,
    pub boot_id: Option<BootId>,
    pub driver: DriverSession,
    pub reaper: ReaperSession,
    pub lifeline_w: OwnedFd,
    pub account_guard: AttemptGuard,
    pub lease: AttemptLease,
    pub cancelled: Arc<AtomicBool>,
    pub stop_override: Arc<Mutex<Option<StopReason>>>,
}

/// Snapshot of a live attempt's directory and helper PIDs once started.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AttemptReadySnapshot {
    pub request: String,
    pub attempt_id: String,
    pub attempt_dir: PathBuf,
    pub driver_pid: u32,
    pub reaper_pid: u32,
}

/// Control handle kept in [`AttemptSupervisor::active`] while an attempt is
/// running so [`AttemptSupervisor::on_event`] can cancel and wake a session
/// even while `run_attempt_to_completion` is executing on another thread.
struct ActiveAttemptControl {
    item: ItemId,
    snapshot: AttemptReadySnapshot,
    cancelled: Arc<AtomicBool>,
    stop_override: Arc<Mutex<Option<StopReason>>>,
    driver_reader_clone: Option<std::os::unix::net::UnixStream>,
    driver_writer_clone: Option<std::os::unix::net::UnixStream>,
    unclaimed: Mutex<Option<ActiveAttemptSession>>,
}

/// Supervision events that tear down one or more active attempts (`b17`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Vault locked (`envcloak lock`, idle timeout, or panic/abort).
    Lock,
    /// Machine sleep detected on the daemon's monotonic/wall clock pair.
    Sleep,
    /// The requesting agent root process exited.
    RootExit { request: RequestId },
    /// The operation was cancelled (`signin.cancel` or `signin.end`).
    Cancel { request: RequestId },
    /// The per-attempt timeout expired.
    Timeout { request: RequestId },
    /// The login item's credentials were rotated/replaced.
    RevisionChange { item: ItemId, new_revision: u64 },
    /// The driver process exited before completing the attempt.
    DriverExited {
        request: RequestId,
        worker: WorkerId,
    },
    /// The reaper process exited unexpectedly while the attempt was running.
    ReaperExited {
        request: RequestId,
        worker: WorkerId,
    },
}

/// Outcome of a supervised sign-in attempt.
#[derive(Debug)]
pub enum SupervisedAttemptResult {
    /// Declared state was captured and worker cleanup was verified.
    Captured {
        attempt_id: String,
        state: CapturedBrowserState,
        cleanup_confirmed: bool,
    },
    /// Attempt failed or was stopped before capture.
    Failed {
        attempt_id: String,
        failure: AttemptFailure,
        stop_reason: Option<StopReason>,
        cleanup_confirmed: bool,
    },
}

impl SupervisedAttemptResult {
    /// Returns the attempt identifier (`req-<req>-w-<gen>`).
    pub fn attempt_id(&self) -> &str {
        match self {
            Self::Captured { attempt_id, .. } | Self::Failed { attempt_id, .. } => attempt_id,
        }
    }

    /// Returns whether reaper teardown was confirmed on disk (`teardown.confirmed`).
    pub const fn cleanup_confirmed(&self) -> bool {
        match self {
            Self::Captured {
                cleanup_confirmed, ..
            }
            | Self::Failed {
                cleanup_confirmed, ..
            } => *cleanup_confirmed,
        }
    }
}

/// Request sent to the long-lived supervision thread to spawn the driver and
/// reaper children so their `PR_SET_PDEATHSIG` on Linux is bound to the
/// long-lived thread.
struct SpawnJob {
    anchor: Arc<EntryImageAnchor>,
    spec: AttemptSpec,
    launch: LaunchSpec,
    reply: mpsc::SyncSender<io::Result<(DriverSession, ReaperSession, OwnedFd)>>,
}

/// Long-lived thread that spawns all driver and reaper children (`M2b-09`).
struct SupervisionSpawner {
    tx: Option<mpsc::SyncSender<SpawnJob>>,
    join: Option<JoinHandle<()>>,
}

impl SupervisionSpawner {
    fn start() -> Self {
        let (tx, rx) = mpsc::sync_channel::<SpawnJob>(16);
        let join = thread::Builder::new()
            .name("envcloakd-signin-supervisor".to_owned())
            .spawn(move || {
                while let Ok(job) = rx.recv() {
                    let res = spawn_pair_on_supervisor_thread(&job.anchor, &job.spec, job.launch);
                    let _ = job.reply.send(res);
                }
            })
            .expect("spawn envcloakd-signin-supervisor thread");
        Self {
            tx: Some(tx),
            join: Some(join),
        }
    }

    fn spawn_pair(
        &self,
        anchor: Arc<EntryImageAnchor>,
        spec: AttemptSpec,
        launch: LaunchSpec,
    ) -> io::Result<(DriverSession, ReaperSession, OwnedFd)> {
        let tx = self
            .tx
            .as_ref()
            .ok_or_else(|| io::Error::other("supervision spawner shut down"))?;
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        tx.send(SpawnJob {
            anchor,
            spec,
            launch,
            reply: reply_tx,
        })
        .map_err(|_| io::Error::other("supervision spawner channel closed"))?;
        reply_rx
            .recv()
            .map_err(|_| io::Error::other("supervision spawner thread exited"))?
    }
}

impl Drop for SupervisionSpawner {
    fn drop(&mut self) {
        self.tx.take();
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

fn spawn_pair_on_supervisor_thread(
    anchor: &EntryImageAnchor,
    spec: &AttemptSpec,
    mut launch: LaunchSpec,
) -> io::Result<(DriverSession, ReaperSession, OwnedFd)> {
    let (lifeline_r, lifeline_w) = pipe_cloexec()?;
    // Chrome reads from `chrome_cdp_in_r` (fd 3) and writes to `chrome_cdp_out_w` (fd 4).
    // Driver writes to `driver_cdp_w` and reads from `driver_cdp_r`.
    let (chrome_cdp_in_r, driver_cdp_w) = pipe_cloexec()?;
    let (driver_cdp_r, chrome_cdp_out_w) = pipe_cloexec()?;

    let driver = spawn_driver(
        anchor,
        spec,
        Some(driver_cdp_r.as_fd()),
        Some(driver_cdp_w.as_fd()),
    )?;
    // Close daemon's copies of the driver's CDP pipe ends immediately.
    drop(driver_cdp_r);
    drop(driver_cdp_w);

    if driver.proxy_addr.is_some() {
        launch.proxy_server.clone_from(&driver.proxy_addr);
    }

    let reaper = match spawn_reaper(
        anchor,
        launch,
        lifeline_r,
        chrome_cdp_in_r,
        chrome_cdp_out_w,
    ) {
        Ok(r) => r,
        Err(e) => {
            let _ = driver.child.kill_and_reap();
            return Err(e);
        }
    };

    Ok((driver, reaper, lifeline_w))
}

/// Converts a worker [`DeclaredState`] into the daemon's wiping
/// [`CapturedBrowserState`].
pub fn convert_declared_state(
    declared: DeclaredState,
) -> Result<CapturedBrowserState, AttemptFailure> {
    let mut cookies = Vec::with_capacity(declared.cookies.len());
    for c in declared.cookies {
        let secret = SecretBytes::copy_from(c.value.as_bytes());
        cookies.push((c.declaration, secret));
    }

    let mut storage = Vec::with_capacity(declared.storage.len());
    for s in declared.storage {
        let secret = SecretBytes::copy_from(s.value.as_bytes());
        storage.push((
            s.declaration.origin.to_string(),
            s.declaration.key.as_str().to_owned(),
            secret,
        ));
    }

    Ok(CapturedBrowserState { cookies, storage })
}

/// Maps a [`WorkerStopReason`] reported by the driver to an [`AttemptFailure`].
pub const fn map_worker_stop_reason(reason: WorkerStopReason) -> AttemptFailure {
    match reason {
        WorkerStopReason::CredentialsRejected => AttemptFailure::CredentialsRejected,
        WorkerStopReason::CodeRejected => AttemptFailure::CodeRejected,
        WorkerStopReason::HandoffRequired => AttemptFailure::HandoffRequired,
        WorkerStopReason::OffOrigin => AttemptFailure::OffOrigin,
        WorkerStopReason::IdentityUnverified => AttemptFailure::CredentialsRejected,
        WorkerStopReason::UnsupportedSessionScope => AttemptFailure::UnsupportedSessionScope,
        WorkerStopReason::WorkerLost => AttemptFailure::WorkerLost,
    }
}

/// Daemon sign-in attempt supervisor (`M2b-09`).
pub struct AttemptSupervisor {
    data_dir: PathBuf,
    boot_id: Option<BootId>,
    anchor: OnceLock<Option<Arc<EntryImageAnchor>>>,
    totp: Arc<TotpState>,
    spawner: OnceLock<SupervisionSpawner>,
    active: Mutex<BTreeMap<RequestId, Arc<ActiveAttemptControl>>>,
    held_states: Arc<AtomicUsize>,
}

impl core::fmt::Debug for AttemptSupervisor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AttemptSupervisor")
            .field("data_dir", &self.data_dir)
            .field("boot_id", &self.boot_id)
            .field("held_state_count", &self.held_state_count())
            .finish_non_exhaustive()
    }
}

impl AttemptSupervisor {
    /// Creates a new [`AttemptSupervisor`] with a long-lived supervision thread.
    pub fn new(
        data_dir: PathBuf,
        start_unix: u64,
        anchor: Option<Arc<EntryImageAnchor>>,
        boot_id: Option<BootId>,
    ) -> Self {
        Self::with_totp(
            data_dir,
            Arc::new(TotpState::after_start(start_unix)),
            anchor,
            boot_id,
        )
    }

    /// Creates a new [`AttemptSupervisor`] sharing an existing [`TotpState`].
    pub fn with_totp(
        data_dir: PathBuf,
        totp: Arc<TotpState>,
        anchor: Option<Arc<EntryImageAnchor>>,
        boot_id: Option<BootId>,
    ) -> Self {
        let anchor_cell = OnceLock::new();
        if let Some(a) = anchor {
            let _ = anchor_cell.set(Some(a));
        }
        Self {
            data_dir,
            boot_id,
            anchor: anchor_cell,
            totp,
            spawner: OnceLock::new(),
            active: Mutex::new(BTreeMap::new()),
            held_states: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Captures the daemon's own startup executable image (`D-36`) if not
    /// already captured.
    pub fn ensure_anchor(&self) -> Option<Arc<EntryImageAnchor>> {
        self.anchor
            .get_or_init(|| EntryImageAnchor::capture_current_exe().ok().map(Arc::new))
            .clone()
    }

    /// Returns the shared [`TotpState`] for per-account serialization and
    /// step-locked TOTP generation.
    pub fn totp(&self) -> &Arc<TotpState> {
        &self.totp
    }

    /// Returns the number of captured browser states currently held in memory
    /// outside a published recipient context (`b12` introspection).
    pub fn held_state_count(&self) -> usize {
        self.held_states.load(Ordering::SeqCst)
    }

    /// Returns the number of currently active attempt sessions.
    pub fn active_attempt_count(&self) -> usize {
        self.active
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Returns the live snapshot for `request` if an attempt is currently active.
    pub fn active_snapshot(&self, request: RequestId) -> Option<AttemptReadySnapshot> {
        self.active
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&request)
            .map(|c| c.snapshot.clone())
    }

    /// Increments the held captured-state counter when captured state is stored
    /// in the daemon awaiting supervisor injection.
    pub fn note_state_held(&self) {
        self.held_states.fetch_add(1, Ordering::SeqCst);
    }

    /// Decrements the held captured-state counter when captured state is
    /// injected into the supervisor or dropped on cancel/lock/timeout/end.
    pub fn note_state_released(&self) {
        loop {
            let cur = self.held_states.load(Ordering::SeqCst);
            let next = cur.saturating_sub(1);
            if self
                .held_states
                .compare_exchange(cur, next, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                break;
            }
        }
    }

    /// Resets the held captured-state counter to `0` (e.g. when locking the
    /// vault drops all operations' captured state).
    pub fn clear_held_states(&self) {
        self.held_states.store(0, Ordering::SeqCst);
    }

    /// Starts a sign-in attempt on the long-lived supervision thread after
    /// writing the durable `signin_intent` audit entry (`L-10`, `b14`).
    ///
    /// If `intent_audit_fn` returns `false` or `fail_point("signin.intent_audit")`
    /// triggers, returns `Err(AttemptFailure::AuditFailed)` before spawning any
    /// driver or decrypting any login field.
    #[allow(clippy::too_many_arguments)]
    pub fn start<F>(
        &self,
        request: RequestId,
        worker: WorkerId,
        item: ItemId,
        vault: &Vault,
        spec: AttemptSpec,
        chrome_exe: PathBuf,
        chrome_sha256: String,
        host_resolver_rules: Option<String>,
        test_ca_spki_sha256: Option<String>,
        extra_chrome_args: Vec<String>,
        started_wall_secs: u64,
        intent_audit_fn: F,
    ) -> Result<RequestId, AttemptFailure>
    where
        F: FnOnce() -> bool,
    {
        let account_guard = self.totp.acquire_account(item);
        self.start_with_guard(
            account_guard,
            request,
            worker,
            item,
            vault,
            spec,
            chrome_exe,
            chrome_sha256,
            host_resolver_rules,
            test_ca_spki_sha256,
            extra_chrome_args,
            started_wall_secs,
            intent_audit_fn,
        )
    }

    /// Starts a sign-in attempt with a pre-acquired [`AttemptGuard`] so callers
    /// that hold a daemon state mutex can acquire the per-account guard outside
    /// the state mutex.
    #[allow(clippy::too_many_arguments)]
    pub fn start_with_guard<F>(
        &self,
        account_guard: AttemptGuard,
        request: RequestId,
        worker: WorkerId,
        item: ItemId,
        vault: &Vault,
        spec: AttemptSpec,
        chrome_exe: PathBuf,
        chrome_sha256: String,
        host_resolver_rules: Option<String>,
        test_ca_spki_sha256: Option<String>,
        extra_chrome_args: Vec<String>,
        started_wall_secs: u64,
        intent_audit_fn: F,
    ) -> Result<RequestId, AttemptFailure>
    where
        F: FnOnce() -> bool,
    {
        let lease = self
            .totp
            .issue_lease(vault, item)
            .map_err(|_| AttemptFailure::CredentialsRejected)?;

        // Durable signin_intent audit BEFORE spawning driver or opening any field.
        if fail_point("signin.intent_audit").is_err() || !intent_audit_fn() {
            return Err(AttemptFailure::AuditFailed);
        }

        // Prepare 0700 attempt directory (enforces 64-tombstone cap).
        let attempt_id = format!("req-{request}-w-{}", worker.generation().get());
        let attempt_dir = prepare_attempt_dir(
            &self.data_dir,
            &attempt_id,
            started_wall_secs,
            self.boot_id.clone(),
        )
        .map_err(|_| AttemptFailure::WorkerLost)?;

        let Some(anchor) = self.ensure_anchor() else {
            let _ = finalize_active_attempt(
                &self.data_dir,
                &attempt_id,
                false,
                started_wall_secs,
                self.boot_id.clone(),
            );
            return Err(AttemptFailure::WorkerLost);
        };

        let mut launch = LaunchSpec::new(&attempt_id, chrome_exe, chrome_sha256, &attempt_dir);
        launch.host_resolver_rules = host_resolver_rules;
        launch.test_ca_spki_sha256 = test_ca_spki_sha256;
        launch.extra_args = extra_chrome_args;

        let spawner = self.spawner.get_or_init(SupervisionSpawner::start);
        let (driver, reaper, lifeline_w) = match spawner.spawn_pair(anchor, spec, launch) {
            Ok(pair) => pair,
            Err(_) => {
                let _ = finalize_active_attempt(
                    &self.data_dir,
                    &attempt_id,
                    false,
                    started_wall_secs,
                    self.boot_id.clone(),
                );
                return Err(AttemptFailure::WorkerLost);
            }
        };

        let snapshot = AttemptReadySnapshot {
            request: request.to_string(),
            attempt_id: attempt_id.clone(),
            attempt_dir: attempt_dir.clone(),
            driver_pid: driver.child.id(),
            reaper_pid: reaper.child.id(),
        };

        if envcloak_sys::test_trace() {
            log_line!(
                "envcloakd: test: signin attempt {} driver_pid={} reaper_pid={} attempt_dir={}",
                attempt_id,
                driver.child.id(),
                reaper.child.id(),
                attempt_dir.display()
            );
        }

        let cancelled = Arc::new(AtomicBool::new(false));
        let stop_override = Arc::new(Mutex::new(None));
        let driver_reader_clone = driver.reader.try_clone().ok();
        let driver_writer_clone = driver.writer.try_clone().ok();

        let session = ActiveAttemptSession {
            request,
            worker,
            item,
            attempt_id,
            attempt_dir,
            started_wall_secs,
            boot_id: self.boot_id.clone(),
            driver,
            reaper,
            lifeline_w,
            account_guard,
            lease,
            cancelled: Arc::clone(&cancelled),
            stop_override: Arc::clone(&stop_override),
        };

        let control = Arc::new(ActiveAttemptControl {
            item,
            snapshot,
            cancelled,
            stop_override,
            driver_reader_clone,
            driver_writer_clone,
            unclaimed: Mutex::new(Some(session)),
        });

        self.active
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(request, control);

        Ok(request)
    }

    /// Runs the credential-step loop on `request`'s active session until the
    /// driver reports `Captured` or `Stopped`, or an external event (`on_event`)
    /// cancels the attempt, then tears down the worker and reaper and verifies
    /// `teardown.confirmed` on disk (`CR-3`).
    #[allow(clippy::type_complexity)]
    pub fn run_attempt_to_completion(
        &self,
        request: RequestId,
        with_vault: &mut dyn FnMut(&mut dyn FnMut(&Vault)) -> bool,
        clock_fn: &mut dyn FnMut() -> u64,
        sleep_fn: &mut dyn FnMut(Duration),
        totp_audit_fn: &mut dyn FnMut(u64) -> bool,
    ) -> SupervisedAttemptResult {
        let control = {
            let map = self.active.lock().unwrap_or_else(PoisonError::into_inner);
            map.get(&request).cloned()
        };
        let Some(control) = control else {
            return SupervisedAttemptResult::Failed {
                attempt_id: format!("req-{request}-w-0"),
                failure: AttemptFailure::WorkerLost,
                stop_reason: None,
                cleanup_confirmed: false,
            };
        };

        let session = control
            .unclaimed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let Some(session) = session else {
            let _ = self
                .active
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&request);
            let override_reason = *control
                .stop_override
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            return SupervisedAttemptResult::Failed {
                attempt_id: format!("req-{request}-w-0"),
                failure: AttemptFailure::WorkerLost,
                stop_reason: override_reason,
                cleanup_confirmed: false,
            };
        };

        let ActiveAttemptSession {
            request: _,
            worker: _,
            item: _,
            attempt_id,
            attempt_dir: _,
            started_wall_secs,
            boot_id,
            mut driver,
            reaper,
            lifeline_w,
            account_guard,
            lease,
            cancelled,
            stop_override,
        } = session;

        let outcome = drive_session_loop(
            &self.totp,
            &account_guard,
            &lease,
            &mut driver,
            &reaper.child,
            &cancelled,
            with_vault,
            clock_fn,
            sleep_fn,
            totp_audit_fn,
        );

        let _ = self
            .active
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&request);

        // Always stop the driver, reap the driver handle, stop the reaper, and
        // verify the on-disk teardown confirmation record (`CR-3`).
        let _ = driver.send(&DaemonToDriver::Stop);
        drop(driver.reader);
        drop(driver.writer);
        if driver.child.has_exited().is_ok() {
            let _ = driver.child.signal_group_before_reap(libc::SIGKILL);
            let _ = driver.child.reap();
        }

        let reaper_confirmed = reaper.stop_and_verify();
        drop(lifeline_w);
        drop(account_guard);

        let cleanup_confirmed = finalize_active_attempt(
            &self.data_dir,
            &attempt_id,
            reaper_confirmed,
            started_wall_secs,
            boot_id,
        );

        let override_reason = *stop_override.lock().unwrap_or_else(PoisonError::into_inner);

        match (outcome, override_reason) {
            (_, Some(stop_reason)) => SupervisedAttemptResult::Failed {
                attempt_id,
                failure: AttemptFailure::WorkerLost,
                stop_reason: Some(stop_reason),
                cleanup_confirmed,
            },
            (Ok(AttemptOutcome::Captured(declared)), None) => {
                if !cleanup_confirmed {
                    return SupervisedAttemptResult::Failed {
                        attempt_id,
                        failure: AttemptFailure::WorkerLost,
                        stop_reason: None,
                        cleanup_confirmed: false,
                    };
                }
                match convert_declared_state(declared) {
                    Ok(state) => SupervisedAttemptResult::Captured {
                        attempt_id,
                        state,
                        cleanup_confirmed,
                    },
                    Err(failure) => SupervisedAttemptResult::Failed {
                        attempt_id,
                        failure,
                        stop_reason: None,
                        cleanup_confirmed,
                    },
                }
            }
            (Ok(AttemptOutcome::Stopped(WorkerStopReason::IdentityUnverified)), None) => {
                SupervisedAttemptResult::Failed {
                    attempt_id,
                    failure: AttemptFailure::CredentialsRejected,
                    stop_reason: Some(StopReason::IdentityUnverified),
                    cleanup_confirmed,
                }
            }
            (Ok(AttemptOutcome::Stopped(reason)), None) => SupervisedAttemptResult::Failed {
                attempt_id,
                failure: map_worker_stop_reason(reason),
                stop_reason: None,
                cleanup_confirmed,
            },
            (Err(failure), None) => SupervisedAttemptResult::Failed {
                attempt_id,
                failure,
                stop_reason: None,
                cleanup_confirmed,
            },
        }
    }

    /// Handles a lifecycle [`Event`] (`Lock`, `Sleep`, `RootExit`, `Cancel`,
    /// `Timeout`, `RevisionChange`, `DriverExited`, `ReaperExited`), marking
    /// matching active attempts cancelled and tearing down any unclaimed
    /// sessions still held in the supervisor table (`b17`).
    pub fn on_event(&self, event: Event) {
        match event {
            Event::Lock => {
                self.totp.on_lock();
                self.clear_held_states();
                self.cancel_all_with_reason(StopReason::Locked);
            }
            Event::Sleep => {
                self.totp.on_lock();
                self.clear_held_states();
                self.cancel_all_with_reason(StopReason::Locked);
            }
            Event::RootExit { request } => {
                self.cancel_one_with_reason(request, StopReason::RootExited);
            }
            Event::Cancel { request } => {
                self.cancel_one_with_reason(request, StopReason::Cancelled);
            }
            Event::Timeout { request } => {
                self.cancel_one_with_reason(request, StopReason::AttemptTimedOut);
            }
            Event::RevisionChange { item, new_revision } => {
                self.totp.on_login_replaced(item, new_revision);
                let matching: Vec<(RequestId, Arc<ActiveAttemptControl>)> = {
                    let map = self.active.lock().unwrap_or_else(PoisonError::into_inner);
                    map.iter()
                        .filter(|(_, c)| c.item == item)
                        .map(|(k, c)| (*k, Arc::clone(c)))
                        .collect()
                };
                for (req, ctrl) in matching {
                    self.signal_and_maybe_teardown_control(req, &ctrl, StopReason::RevisionChanged);
                }
            }
            Event::DriverExited { request, .. } | Event::ReaperExited { request, .. } => {
                self.cancel_one_with_reason(
                    request,
                    StopReason::AttemptFailed(AttemptFailure::WorkerLost),
                );
            }
        }
    }

    fn cancel_all_with_reason(&self, reason: StopReason) {
        let entries: Vec<(RequestId, Arc<ActiveAttemptControl>)> = {
            let map = self.active.lock().unwrap_or_else(PoisonError::into_inner);
            map.iter().map(|(k, c)| (*k, Arc::clone(c))).collect()
        };
        for (req, ctrl) in entries {
            self.signal_and_maybe_teardown_control(req, &ctrl, reason);
        }
    }

    fn cancel_one_with_reason(&self, request: RequestId, reason: StopReason) {
        let ctrl = {
            let map = self.active.lock().unwrap_or_else(PoisonError::into_inner);
            map.get(&request).cloned()
        };
        if let Some(ctrl) = ctrl {
            self.signal_and_maybe_teardown_control(request, &ctrl, reason);
        }
    }

    fn signal_and_maybe_teardown_control(
        &self,
        request: RequestId,
        ctrl: &Arc<ActiveAttemptControl>,
        reason: StopReason,
    ) {
        *ctrl
            .stop_override
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(reason);
        ctrl.cancelled.store(true, Ordering::SeqCst);
        if let Some(s) = &ctrl.driver_writer_clone {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
        if let Some(s) = &ctrl.driver_reader_clone {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
        let unclaimed = ctrl
            .unclaimed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(owned) = unclaimed {
            let _ = self
                .active
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&request);
            self.teardown_removed_session(owned);
        }
    }

    fn teardown_removed_session(&self, session: ActiveAttemptSession) {
        let ActiveAttemptSession {
            attempt_id,
            started_wall_secs,
            boot_id,
            mut driver,
            reaper,
            lifeline_w,
            account_guard,
            ..
        } = session;

        let _ = driver.send(&DaemonToDriver::Stop);
        drop(driver.reader);
        drop(driver.writer);
        if driver.child.has_exited().is_ok() {
            let _ = driver.child.signal_group_before_reap(libc::SIGKILL);
            let _ = driver.child.reap();
        }
        let reaper_confirmed = reaper.stop_and_verify();
        drop(lifeline_w);
        drop(account_guard);

        let _ = finalize_active_attempt(
            &self.data_dir,
            &attempt_id,
            reaper_confirmed,
            started_wall_secs,
            boot_id,
        );
    }
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn drive_session_loop(
    totp: &TotpState,
    account_guard: &AttemptGuard,
    lease: &AttemptLease,
    driver: &mut DriverSession,
    reaper_child: &OwnedChild,
    cancelled: &AtomicBool,
    with_vault: &mut dyn FnMut(&mut dyn FnMut(&Vault)) -> bool,
    clock_fn: &mut dyn FnMut() -> u64,
    sleep_fn: &mut dyn FnMut(Duration),
    totp_audit_fn: &mut dyn FnMut(u64) -> bool,
) -> Result<AttemptOutcome, AttemptFailure> {
    loop {
        if cancelled.load(Ordering::SeqCst) {
            let _ = driver.send(&DaemonToDriver::Stop);
            return Err(AttemptFailure::WorkerLost);
        }
        if reaper_child.has_exited().unwrap_or(true) {
            let _ = driver.send(&DaemonToDriver::Stop);
            return Err(AttemptFailure::WorkerLost);
        }

        let msg = match driver.recv() {
            Ok(m) => m,
            Err(_) => return Err(AttemptFailure::WorkerLost),
        };

        if cancelled.load(Ordering::SeqCst) {
            let _ = driver.send(&DaemonToDriver::Stop);
            return Err(AttemptFailure::WorkerLost);
        }

        match msg {
            DriverMessage::NeedUsername => {
                pause_point("signin.attempt.before_username");
                if cancelled.load(Ordering::SeqCst) {
                    let _ = driver.send(&DaemonToDriver::Stop);
                    return Err(AttemptFailure::WorkerLost);
                }
                let mut field_res: Option<Result<SecretBytes, TotpError>> = None;
                let vault_ok = with_vault(&mut |vault| {
                    field_res =
                        Some(totp.read_field(account_guard, lease, vault, FieldKind::Username));
                });
                let Some(field_res) = field_res.filter(|_| vault_ok) else {
                    let _ = driver.send(&DaemonToDriver::Stop);
                    return Err(AttemptFailure::WorkerLost);
                };
                let secret = field_res.map_err(map_totp_err)?;
                let utf8 = secret_to_zeroizing_utf8(&secret).map_err(map_totp_err)?;
                driver
                    .send(&DaemonToDriver::Username(utf8))
                    .map_err(|_| AttemptFailure::WorkerLost)?;
            }
            DriverMessage::NeedPassword => {
                pause_point("signin.attempt.before_password");
                if cancelled.load(Ordering::SeqCst) {
                    let _ = driver.send(&DaemonToDriver::Stop);
                    return Err(AttemptFailure::WorkerLost);
                }
                let mut field_res: Option<Result<SecretBytes, TotpError>> = None;
                let vault_ok = with_vault(&mut |vault| {
                    let pw = totp.read_field(account_guard, lease, vault, FieldKind::Password);
                    field_res = Some(match pw {
                        Ok(v) => Ok(v),
                        Err(_) => {
                            totp.read_field(account_guard, lease, vault, FieldKind::AdapterKey)
                        }
                    });
                });
                let Some(field_res) = field_res.filter(|_| vault_ok) else {
                    let _ = driver.send(&DaemonToDriver::Stop);
                    return Err(AttemptFailure::WorkerLost);
                };
                let secret = field_res.map_err(map_totp_err)?;
                let utf8 = secret_to_zeroizing_utf8(&secret).map_err(map_totp_err)?;
                driver
                    .send(&DaemonToDriver::Password(utf8))
                    .map_err(|_| AttemptFailure::WorkerLost)?;
            }
            DriverMessage::NeedCode { .. } => {
                pause_point("signin.attempt.before_code");
                if cancelled.load(Ordering::SeqCst) {
                    let _ = driver.send(&DaemonToDriver::Stop);
                    return Err(AttemptFailure::WorkerLost);
                }
                let (code, _step) = totp
                    .next_code_with_vault(
                        account_guard,
                        lease,
                        with_vault,
                        clock_fn,
                        sleep_fn,
                        totp_audit_fn,
                    )
                    .map_err(map_totp_err)?;
                if cancelled.load(Ordering::SeqCst) {
                    let _ = driver.send(&DaemonToDriver::Stop);
                    return Err(AttemptFailure::WorkerLost);
                }
                let utf8 = code_to_zeroizing_utf8(&code).map_err(map_totp_err)?;
                driver
                    .send(&DaemonToDriver::Code(utf8))
                    .map_err(|_| AttemptFailure::WorkerLost)?;
            }
            DriverMessage::Captured(state) => {
                return Ok(AttemptOutcome::Captured(state));
            }
            DriverMessage::Stopped(reason) => {
                return Ok(AttemptOutcome::Stopped(reason));
            }
        }
    }
}

const fn map_totp_err(err: TotpError) -> AttemptFailure {
    match err {
        TotpError::AuditFailed => AttemptFailure::AuditFailed,
        TotpError::LeaseStale | TotpError::VaultLocked => AttemptFailure::WorkerLost,
        TotpError::TooLateInStep
        | TotpError::RefusedAfterStart { .. }
        | TotpError::StepAlreadyUsed { .. }
        | TotpError::NoTotpEnrolled
        | TotpError::InvalidParams
        | TotpError::AccountMismatch
        | TotpError::Vault(_) => AttemptFailure::CodeRejected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use envcloak_sys::owned::{Recorded, RecordingProcesses};

    #[test]
    fn recording_process_ops_never_signals_reaped_or_reused_pid() {
        let model = RecordingProcesses::new();
        let driver = model.child(4100);
        let reaper = model.child(4200);
        let (_r, lifeline_w) = pipe_cloexec().expect("pipe");

        let handle = AttemptHandle {
            driver,
            reaper,
            lifeline_w,
        };
        handle.teardown_owned().expect("teardown");

        let calls = model.calls();
        assert_eq!(
            calls,
            vec![
                Recorded::HasExited(4100),
                Recorded::SignalGroup(4100, libc::SIGKILL),
                Recorded::Reap(4100),
                Recorded::HasExited(4200),
                Recorded::WaitExit(4200),
                Recorded::Reap(4200),
            ]
        );

        // If a child was reaped elsewhere (simulating PID reuse hazard), teardown_owned
        // emits zero signals to the reused number.
        let model_reused = RecordingProcesses::new();
        model_reused.reap_elsewhere(5100);
        model_reused.reap_elsewhere(5200);
        let (_r2, lifeline_w2) = pipe_cloexec().expect("pipe");
        let handle_reused = AttemptHandle {
            driver: model_reused.child(5100),
            reaper: model_reused.child(5200),
            lifeline_w: lifeline_w2,
        };
        handle_reused.teardown_owned().expect("teardown reused");
        assert!(
            model_reused.calls().is_empty(),
            "no signal or wait may be issued when a child was reaped elsewhere: {:?}",
            model_reused.calls()
        );
    }

    #[test]
    fn held_state_count_tracks_hold_and_release() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let sup = AttemptSupervisor::new(tmp.path().to_path_buf(), 1_000, None, None);
        assert_eq!(sup.held_state_count(), 0);
        sup.note_state_held();
        assert_eq!(sup.held_state_count(), 1);
        sup.note_state_released();
        assert_eq!(sup.held_state_count(), 0);

        sup.note_state_held();
        sup.on_event(Event::Lock);
        assert_eq!(sup.held_state_count(), 0);
    }
}
