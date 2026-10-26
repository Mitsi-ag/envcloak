//! Sign-in operation lifecycle, retry store integration, live `World`
//! verification, pipe-origin-bound supervisor messaging, and approval /
//! grant integration in the daemon (SPEC §6.8, §10b, task M2b-05).

use std::collections::BTreeMap;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use envcloak_core::SecretBytes;
use envcloak_core::audit::{AuditKind, SubjectSummary};
use envcloak_core::crypto::{CryptoErrorKind, ItemClass};
use envcloak_core::vault::{
    Classification, ItemId, LoginMeta, LoginTier, PolicyId, Slug, Vault, VaultErrorKind,
};
use envcloak_ipc::control::{
    FromSupervisor, SupervisorCheck, SupervisorClose, SupervisorCookieEntry,
    SupervisorIdentityResponse, SupervisorInjectState, SupervisorPublish, SupervisorStorageEntry,
    ToSupervisor, receive as recv_from_supervisor, send as send_to_supervisor,
};
use envcloak_ipc::proto::{
    ApproveParams, ErrorKind, PendingGetOutput, PendingGetParams, PendingStateParams,
    RequestParams, SigninEndParams, SigninOperationParams, SigninRequestParams,
};
use envcloak_ipc::view::{
    ApprovedView, DeniedView, GrantBindingView, GrantView, PendingStateView, PendingView,
    SigninStatusView,
};
use envcloak_ipc::{RpcError, WireSecret};
use envcloak_policy::{
    MAX_AGENT_TTL, MAX_TERMINAL_TTL, Mode, Now, PendingState, ProcessInstance,
    ProcessSummary as PolicyProcessSummary, ScopeFingerprint, SubjectEvidence, SubjectKind,
    SubjectSummary as PolicySubjectSummary, Uses, load_project, project_identity,
};
use envcloak_signin::{
    ApproveError as SignInApproveError, AttemptFailure, AuthorizationId, AuthorizationKind,
    Channel, Cleanup, Current, DaemonInstance, DeclaredCookie, Delivery, DeliveryMode, Effect,
    Environment, Epochs, Fresh, IdentityResponse, Instance, Label, Limits, LoginNow, MAX_APPROVAL,
    MAX_DEV_ATTEMPTS, MAX_SESSION_LIFETIME, Nonce, OperationKey, OperationStore, Options, Phase,
    ProjectScope, PublishDecision, Request, RequestError, RequestId, Requester, Revocation,
    SignInDevOptions, SignInDevOptionsExt, SignInPendingDescriptor, SignInPendingDescriptorExt,
    SignInScope, State as OpState, Status, StopReason, Subject, SupervisorId, TargetNow, Tier,
    WorkerId, World,
};
use envcloak_sys::PeerIdentity;
use sha2::{Digest, Sha256};

use crate::audit::AuditEvent;
use crate::clock::now_of;
use crate::lock::Reading;
use crate::requests::{
    alive, digest_of, evidence, manifest_error, refuse_unless_prover, subject_summary,
};
use crate::server::{Shared, locked, refuse_if_traced};
use crate::signin::targets::{find_target_by_id, find_target_by_name_and_role, target_from_vault};
use crate::state::{Slot, State, slot_unlocked, vault_reason};

/// Default per-attempt timeout (5 minutes).
pub const DEFAULT_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(300);

/// Destination of a daemon message recorded in [`SigninState::send_log`].
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendDestination {
    SupervisorControlPipe { generation: u64 },
    IpcReply { method: &'static str },
}

/// Record of a message sent during a sign-in operation.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendRecord {
    pub request: RequestId,
    pub destination: SendDestination,
    pub contains_captured_state: bool,
}

/// Captured browser state held in wiping buffers inside the daemon between
/// worker capture and supervisor injection.
#[allow(dead_code)]
#[derive(Default)]
pub struct CapturedBrowserState {
    pub cookies: Vec<(DeclaredCookie, SecretBytes)>,
    pub storage: Vec<(String, String, SecretBytes)>,
}

impl core::fmt::Debug for CapturedBrowserState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CapturedBrowserState")
            .field("cookies", &self.cookies.len())
            .field("storage", &self.storage.len())
            .finish()
    }
}

/// Daemon-held end of a supervisor control socket created on
/// [`Effect::StartSupervisor`].
#[allow(dead_code)]
#[derive(Debug)]
pub struct SupervisorPipe {
    pub request: RequestId,
    pub supervisor: SupervisorId,
    pub daemon_stream: UnixStream,
    pub peer_stream: Option<UnixStream>,
}

/// Per-operation daemon metadata alongside [`OperationStore`].
#[allow(dead_code)]
#[derive(Debug)]
pub struct SigninOperationMeta {
    pub request: RequestId,
    pub scope: SignInScope,
    pub peer: PeerIdentity,
    pub subject: SubjectEvidence,
    pub subject_summary: SubjectSummary,
    pub claims: Vec<String>,
    pub manifest_path: PathBuf,
    pub project_dir: PathBuf,
    pub login_item: ItemId,
    pub login_slug: Slug,
    pub target_policy_id: PolicyId,
    pub target_name: String,
    pub shared_loopback_cookie_jar: bool,
    pub created_awake: Duration,
    pub captured_state: Option<CapturedBrowserState>,
    pub active_worker: Option<WorkerId>,
    pub supervisor_pipe: Option<SupervisorPipe>,
    pub tool_pipes: Option<(OwnedFd, OwnedFd)>,
    pub publish_audited: bool,
    pub end_audited: bool,
}

/// Metadata kept per `Dev` sign-in authorization for `grants.list` and
/// `grants.revoke`.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct SigninAuthMeta {
    pub id: AuthorizationId,
    pub scope_fingerprint: ScopeFingerprint,
    pub subject: SubjectEvidence,
    pub project_dir: PathBuf,
    pub login_item: ItemId,
    pub login_slug: Slug,
    pub target_name: String,
    pub role: String,
    pub created_wall: SystemTime,
}

/// Optional test overrides for [`LiveDaemonWorld`] in unit tests.
#[allow(dead_code)]
#[derive(Debug, Default, Clone)]
pub struct WorldOverrides {
    pub requester: Option<Requester>,
    pub browser_generation: Option<u64>,
    pub config_digest: Option<[u8; 32]>,
    pub root_alive: Option<bool>,
}

/// Daemon sign-in state held inside [`State`].
#[allow(dead_code)]
#[derive(Debug)]
pub struct SigninState {
    daemon_instance: DaemonInstance,
    store: OperationStore,
    ops: BTreeMap<RequestId, SigninOperationMeta>,
    auths: BTreeMap<AuthorizationId, SigninAuthMeta>,
    browser_generation: u64,
    send_log: Vec<SendRecord>,
    world_overrides: WorldOverrides,
}

impl Default for SigninState {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
impl SigninState {
    pub fn new() -> Self {
        let mut instance_bytes = [0u8; 16];
        envcloak_core::crypto::fill_random_or_panic(&mut instance_bytes);
        let daemon_instance = DaemonInstance::from_bytes(instance_bytes);
        SigninState {
            daemon_instance,
            store: OperationStore::new(daemon_instance),
            ops: BTreeMap::new(),
            auths: BTreeMap::new(),
            browser_generation: 1,
            send_log: Vec::new(),
            world_overrides: WorldOverrides::default(),
        }
    }

    pub fn browser_generation(&self) -> u64 {
        self.browser_generation
    }

    pub fn bump_browser_generation(&mut self) -> u64 {
        self.browser_generation = self.browser_generation.saturating_add(1);
        self.browser_generation
    }

    pub fn daemon_instance(&self) -> DaemonInstance {
        self.daemon_instance
    }

    pub fn store(&self) -> &OperationStore {
        &self.store
    }

    pub fn send_log(&self) -> &[SendRecord] {
        &self.send_log
    }

    pub fn world_overrides_mut(&mut self) -> &mut WorldOverrides {
        &mut self.world_overrides
    }

    pub fn operation_meta(&self, id: RequestId) -> Option<&SigninOperationMeta> {
        self.ops.get(&id)
    }

    pub fn operation_meta_mut(&mut self, id: RequestId) -> Option<&mut SigninOperationMeta> {
        self.ops.get_mut(&id)
    }

    /// Subjects of all currently `PendingApproval` sign-in operations, used by
    /// `refuse_item_prover` and `requester_terminal_in` to enforce terminal
    /// origin separation across secret and sign-in requests alike.
    pub fn pending_subjects(&self) -> impl Iterator<Item = &SubjectEvidence> {
        self.ops.iter().filter_map(|(id, meta)| {
            self.store
                .operation(id)
                .is_some_and(|op| op.stop().is_none() && op.phase() == Phase::PendingApproval)
                .then_some(&meta.subject)
        })
    }
}

/// Computes the SHA-256 digest of `.envcloak.toml` in `project_dir` (or
/// `[0u8; 32]` when no manifest file exists).
pub(crate) fn signin_config_digest(project_dir: &Path) -> [u8; 32] {
    let manifest = project_dir.join(envcloak_policy::MANIFEST_NAME);
    match std::fs::read(&manifest) {
        Ok(bytes) => Sha256::digest(&bytes).into(),
        Err(_) => [0u8; 32],
    }
}

pub(crate) fn subject_evidence_digest(ev: &SubjectEvidence) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"envcloak-signin-evidence/1\n");
    let kind_b = match ev.kind() {
        SubjectKind::Terminal => 1u8,
        SubjectKind::Agent => 2u8,
        SubjectKind::Unknown => 3u8,
    };
    h.update([kind_b]);
    h.update(ev.root().pid.to_be_bytes());
    h.update(ev.root().start_time.raw().to_be_bytes());
    if let Some(l) = ev.label() {
        h.update((l.id.len() as u32).to_be_bytes());
        h.update(l.id.as_bytes());
    } else {
        h.update(0u32.to_be_bytes());
    }
    h.finalize().into()
}

pub(crate) fn compute_effective_limits(
    login_meta: &LoginMeta,
    login_class: Classification,
    target_tier: LoginTier,
    target_approval: Duration,
    target_session: Duration,
    subject_kind: SubjectKind,
) -> Option<Limits> {
    let is_agent = subject_kind == SubjectKind::Agent;
    if is_agent
        && (login_meta.tier == LoginTier::NeverAgent || target_tier == LoginTier::NeverAgent)
    {
        return None;
    }
    if is_agent && login_class != Classification::Test {
        return None;
    }
    let tier = match (login_meta.tier, target_tier, login_class) {
        (LoginTier::Dev, LoginTier::Dev, Classification::Test) => Tier::Dev,
        _ => Tier::Each,
    };
    let attempts = match tier {
        Tier::Each => 1,
        Tier::Dev => MAX_DEV_ATTEMPTS,
    };
    let max_subj_approval = match subject_kind {
        SubjectKind::Agent => MAX_AGENT_TTL,
        SubjectKind::Terminal | SubjectKind::Unknown => MAX_TERMINAL_TTL,
    };
    let approval = target_approval.min(max_subj_approval).min(MAX_APPROVAL);
    let session_lifetime = Duration::from_secs(login_meta.session_lifetime)
        .min(target_session)
        .min(MAX_SESSION_LIFETIME);
    Limits::new(
        tier,
        attempts,
        approval,
        DEFAULT_ATTEMPT_TIMEOUT,
        session_lifetime,
    )
    .ok()
}

fn live_instance_alive(inst: &Instance) -> bool {
    let proc_inst = ProcessInstance {
        pid: inst.pid,
        start_time: envcloak_sys::StartTime::from_raw(inst.start_time),
        pidversion: None,
        exe: None,
    };
    alive(&proc_inst)
}

fn live_requester_state(
    catalog: Option<&envcloak_policy::AgentCatalog>,
    ops: &BTreeMap<RequestId, SigninOperationMeta>,
    auths: &BTreeMap<AuthorizationId, SigninAuthMeta>,
    scope: &SignInScope,
) -> Requester {
    let req = scope.delivery().requester;
    if !live_instance_alive(&req) {
        return Requester::Exited;
    }
    let meta_opt = ops.values().find(|m| m.scope == *scope);
    let pinned_subject = meta_opt.map(|m| &m.subject).or_else(|| {
        auths
            .values()
            .find(|a| a.scope_fingerprint == *scope.fingerprint().as_bytes())
            .map(|a| &a.subject)
    });
    let Some(pinned) = pinned_subject else {
        return Requester::Covered;
    };
    let pinned_root = pinned.root();
    if !alive(&pinned_root) {
        return Requester::Uncovered;
    }
    if let (Some(cat), Some(meta)) = (catalog, meta_opt)
        && let Ok(claims) = envcloak_policy::Claims::from_markers(&meta.claims)
    {
        if let Ok(live_ev) = envcloak_policy::gather(&meta.peer, claims, cat) {
            if !live_ev.covered_by(&pinned_root, pinned.kind()) {
                return Requester::Uncovered;
            }
            return Requester::Covered;
        }
        return Requester::Exited;
    }
    if !pinned.covered_by(&pinned_root, pinned.kind()) {
        return Requester::Uncovered;
    }
    Requester::Covered
}

struct LiveDaemonWorld<'a> {
    daemon: DaemonInstance,
    vault: Option<&'a Vault>,
    catalog: Option<&'a envcloak_policy::AgentCatalog>,
    browser_generation: u64,
    ops: &'a BTreeMap<RequestId, SigninOperationMeta>,
    auths: &'a BTreeMap<AuthorizationId, SigninAuthMeta>,
    overrides: &'a WorldOverrides,
}

std::thread_local! {
    static CURRENT_CACHE: std::cell::RefCell<BTreeMap<ScopeFingerprint, Current>> =
        const { std::cell::RefCell::new(BTreeMap::new()) };
}

impl World for LiveDaemonWorld<'_> {
    fn epochs(&self) -> Epochs {
        CURRENT_CACHE.with(|c| c.borrow_mut().clear());
        let (vault_epoch, policy_epoch) = self
            .vault
            .and_then(|v| {
                let h = v.header().ok()?;
                Some((u64::from(v.epoch()), h.policy_epoch))
            })
            .unwrap_or((0, 0));
        Epochs {
            daemon: self.daemon,
            vault: vault_epoch,
            policy: policy_epoch,
        }
    }

    fn alive(&self, instance: &Instance) -> bool {
        if let Some(override_alive) = self.overrides.root_alive {
            return override_alive;
        }
        live_instance_alive(instance)
    }

    fn current(&self, scope: &SignInScope) -> Current {
        let use_cache = self.ops.len() > 1;
        let fp = *scope.fingerprint().as_bytes();
        if use_cache && let Some(cached) = CURRENT_CACHE.with(|c| c.borrow().get(&fp).cloned()) {
            return cached;
        }
        let dir_path = Path::new(std::ffi::OsStr::from_bytes(&scope.project().dir));
        let manifest_path = dir_path.join(envcloak_policy::MANIFEST_NAME);
        let project = project_identity(&manifest_path).ok().map(|id| {
            let config = self
                .overrides
                .config_digest
                .unwrap_or_else(|| signin_config_digest(&id.canonical_dir));
            ProjectScope::new(&id, config)
        });

        let mut login_meta_opt = None;
        let mut login_class_opt = None;
        let login = self.vault.and_then(|v| {
            let meta = v.item(scope.account().login_item)?;
            if meta.class != ItemClass::Login {
                return None;
            }
            let rev = v.login_revision(meta.id)?;
            login_meta_opt = meta.login;
            login_class_opt = Some(meta.details.classification);
            let environment = match meta.details.classification {
                Classification::Test => Environment::Test,
                Classification::Unknown | Classification::Live => Environment::Live,
            };
            Some(LoginNow {
                revision: rev,
                environment,
            })
        });

        let parsed_target = self
            .vault
            .and_then(|v| find_target_by_id(v, scope.target().id).ok().flatten());
        let target = parsed_target.as_ref().map(|pt| TargetNow {
            revision: pt.target.revision,
            adapter: pt.target.adapter,
            adapter_revision: pt.target.adapter_revision,
        });

        let subj_kind = self
            .ops
            .values()
            .find(|m| m.scope == *scope)
            .map(|m| m.subject.kind())
            .or_else(|| {
                self.auths
                    .values()
                    .find(|a| a.scope_fingerprint == *scope.fingerprint().as_bytes())
                    .map(|a| a.subject.kind())
            })
            .unwrap_or(SubjectKind::Terminal);

        let limits = match (&login_meta_opt, login_class_opt, &parsed_target) {
            (Some(lm), Some(lc), Some(pt)) => compute_effective_limits(
                lm,
                lc,
                pt.tier,
                pt.approval_lifetime,
                pt.session_lifetime,
                subj_kind,
            )
            .unwrap_or_else(|| fallback_different_limits(scope.limits())),
            _ => scope.limits().clone(),
        };

        let browser = self
            .overrides
            .browser_generation
            .unwrap_or(self.browser_generation);

        let requester = self
            .overrides
            .requester
            .unwrap_or_else(|| live_requester_state(self.catalog, self.ops, self.auths, scope));

        let out = Current {
            project,
            login,
            target,
            limits,
            browser,
            requester,
        };
        if use_cache {
            CURRENT_CACHE.with(|c| {
                c.borrow_mut().insert(fp, out.clone());
            });
        }
        out
    }
}

fn fallback_different_limits(pinned: &Limits) -> Limits {
    let alt_approval = if pinned.approval() == Duration::from_secs(1) {
        Duration::from_secs(2)
    } else {
        Duration::from_secs(1)
    };
    Limits::new(
        Tier::Each,
        1,
        alt_approval,
        DEFAULT_ATTEMPT_TIMEOUT,
        Duration::from_secs(60),
    )
    .unwrap_or_else(|_| pinned.clone())
}

#[allow(dead_code)]
impl State {
    pub fn signin(&self) -> &SigninState {
        &self.signin
    }

    pub fn signin_mut(&mut self) -> &mut SigninState {
        &mut self.signin
    }

    /// Reconciles `OperationStore` against the current live world and
    /// executes any resulting [`Effect`]s. Returns `(ended_operations,
    /// revoked_authorizations)`.
    pub fn signin_reconcile_counts(&mut self, shared: &Shared) -> (usize, usize) {
        let now = now_of(&shared.clocks);
        self.signin_reconcile_at(&now, Some(&shared.catalog))
    }

    /// Reconciles `OperationStore` against the current live world and
    /// returns the number of operations that ended.
    pub fn signin_reconcile(&mut self, shared: &Shared) -> usize {
        self.signin_reconcile_counts(shared).0
    }

    pub fn signin_reconcile_at(
        &mut self,
        now: &Now,
        catalog: Option<&envcloak_policy::AgentCatalog>,
    ) -> (usize, usize) {
        if matches!(self.slot, Slot::Busy) {
            return (0, 0);
        }
        let ops_before = self.signin_live_ops_count();
        let auths_before = self.signin_live_auths_count(now);
        let effects = {
            let vault = slot_unlocked(&self.slot);
            let world = LiveDaemonWorld {
                daemon: self.signin.daemon_instance,
                vault,
                catalog,
                browser_generation: self.signin.browser_generation,
                ops: &self.signin.ops,
                auths: &self.signin.auths,
                overrides: &self.signin.world_overrides,
            };
            self.signin.store.reconcile(now, &world);
            self.signin.store.drain_effects()
        };
        self.execute_signin_effects(effects, now, catalog);
        let ops_after = self.signin_live_ops_count();
        let auths_after = self.signin_live_auths_count(now);
        (
            ops_before.saturating_sub(ops_after),
            auths_before.saturating_sub(auths_after),
        )
    }

    pub fn signin_on_lock(&mut self, now: &Now) {
        let effects = {
            let vault = slot_unlocked(&self.slot);
            let world = LiveDaemonWorld {
                daemon: self.signin.daemon_instance,
                vault,
                catalog: None,
                browser_generation: self.signin.browser_generation,
                ops: &self.signin.ops,
                auths: &self.signin.auths,
                overrides: &self.signin.world_overrides,
            };
            self.signin.store.lock(now, &world);
            self.signin.store.drain_effects()
        };
        self.execute_signin_effects(effects, now, None);
    }

    pub fn signin_on_sleep(&mut self, now: &Now) {
        self.signin_on_lock(now);
    }

    pub fn signin_sweep(&mut self, now: &Now) {
        let _ = self.signin_reconcile_at(now, None);
    }

    fn signin_live_ops_count(&self) -> usize {
        self.signin
            .store
            .operations()
            .filter(|op| op.stop().is_none())
            .count()
    }

    fn signin_live_auths_count(&self, now: &Now) -> usize {
        let epochs = {
            let vault = self.unlocked().ok();
            let (v_ep, p_ep) = vault
                .and_then(|v| Some((u64::from(v.epoch()), v.header().ok()?.policy_epoch)))
                .unwrap_or((0, 0));
            Epochs {
                daemon: self.signin.daemon_instance,
                vault: v_ep,
                policy: p_ep,
            }
        };
        self.signin
            .store
            .authorizations()
            .filter(|a| a.in_force(&epochs, now))
            .count()
    }

    pub(crate) fn execute_signin_effects(
        &mut self,
        effects: Vec<Effect>,
        _now: &Now,
        _catalog: Option<&envcloak_policy::AgentCatalog>,
    ) {
        for effect in effects {
            match effect {
                Effect::StartAttempt {
                    request, worker, ..
                } => {
                    if let Some(meta) = self.signin.ops.get_mut(&request) {
                        meta.active_worker = Some(worker);
                    }
                }
                Effect::StartSupervisor {
                    request,
                    supervisor,
                } => {
                    if let Ok((daemon_stream, peer_stream)) = UnixStream::pair()
                        && let Some(meta) = self.signin.ops.get_mut(&request)
                    {
                        meta.supervisor_pipe = Some(SupervisorPipe {
                            request,
                            supervisor,
                            daemon_stream,
                            peer_stream: Some(peer_stream),
                        });
                    }
                }
                Effect::TearDown {
                    request,
                    generation,
                    ..
                } => {
                    if let Some(meta) = self.signin.ops.get_mut(&request) {
                        meta.captured_state = None;
                        if meta
                            .active_worker
                            .is_some_and(|w| w.generation() == generation)
                        {
                            meta.active_worker = None;
                        }
                        if let Some(pipe) = meta.supervisor_pipe.take()
                            && pipe.supervisor.generation() == generation
                        {
                            let context = self.signin.store.operation(&request).map_or_else(
                                || "0".to_owned(),
                                |op| op.context().get().to_string(),
                            );
                            let _ = send_to_supervisor(
                                &pipe.daemon_stream,
                                &ToSupervisor::Close(SupervisorClose {
                                    request: request.to_string(),
                                    generation: generation.get(),
                                    context,
                                }),
                            );
                        }
                    }
                }
            }
        }
        self.audit_signin_transitions();
    }

    fn audit_signin_transitions(&mut self) {
        let live_auth_ids: Vec<AuthorizationId> =
            self.signin.store.authorizations().map(|a| a.id()).collect();
        self.signin.auths.retain(|id, _| live_auth_ids.contains(id));

        let mut events = Vec::new();
        for (id, meta) in &mut self.signin.ops {
            let Some(op) = self.signin.store.operation(id) else {
                continue;
            };
            if op.stop().is_none() && op.phase() == Phase::Published && !meta.publish_audited {
                meta.publish_audited = true;
                events.push(AuditEvent::SigninPublish {
                    pid: meta.peer.pid,
                    subject: meta.subject_summary.clone(),
                    outcome: "published",
                    request: id.to_string(),
                    authorization: op.authorization().map(|a| a.to_string()),
                    item: Some((meta.login_item, meta.login_slug.clone())),
                    reason: None,
                });
            }
            if let Some(stop) = op.stop()
                && !meta.end_audited
            {
                meta.end_audited = true;
                events.push(AuditEvent::SigninEnd {
                    pid: meta.peer.pid,
                    subject: meta.subject_summary.clone(),
                    outcome: if stop.delivered { "ended" } else { "stopped" },
                    request: id.to_string(),
                    authorization: op.authorization().map(|a| a.to_string()),
                    method: None,
                    reason: Some(stop_reason_token(stop.reason)),
                });
            }
        }
        for ev in events {
            self.audit(ev);
        }
    }

    /// Sends captured state over the bound supervisor control pipe for
    /// `request` if and only if `Channel::Supervisor(pipe.supervisor)` is
    /// authorized by `OperationStore::inject_state`. Records the send in
    /// [`SigninState::send_log`].
    pub fn signin_inject_over_bound_pipe(
        &mut self,
        request: RequestId,
        now: &Now,
    ) -> Result<(), RpcError> {
        let supervisor = {
            let meta = self
                .signin
                .ops
                .get(&request)
                .ok_or(RpcError::new(ErrorKind::NoSuchRequest))?;
            let pipe = meta
                .supervisor_pipe
                .as_ref()
                .ok_or(RpcError::new(ErrorKind::InvalidParams))?;
            pipe.supervisor
        };
        let (inj, effects) = {
            let vault = slot_unlocked(&self.slot);
            let world = LiveDaemonWorld {
                daemon: self.signin.daemon_instance,
                vault,
                catalog: None,
                browser_generation: self.signin.browser_generation,
                ops: &self.signin.ops,
                auths: &self.signin.auths,
                overrides: &self.signin.world_overrides,
            };
            let res = self.signin.store.inject_state(
                &Channel::Supervisor(supervisor),
                &request,
                now,
                &world,
            );
            let eff = self.signin.store.drain_effects();
            (res, eff)
        };
        self.execute_signin_effects(effects, now, None);
        let inj =
            inj.map_err(|_| RpcError::with_reason(ErrorKind::InvalidParams, "inject_refused"))?;

        let meta = self
            .signin
            .ops
            .get_mut(&request)
            .ok_or(RpcError::new(ErrorKind::NoSuchRequest))?;
        let pipe = meta
            .supervisor_pipe
            .as_ref()
            .ok_or(RpcError::new(ErrorKind::InvalidParams))?;

        let mut cookies_wire = Vec::new();
        let mut storage_wire = Vec::new();
        if let Some(captured) = meta.captured_state.take() {
            for (decl, val) in captured.cookies {
                let (domain, host_only) = match &decl.domain {
                    envcloak_signin::CookieDomain::HostOnly(h) => (h.to_string(), true),
                    envcloak_signin::CookieDomain::Domain(hn) => (hn.as_str().to_owned(), false),
                };
                let partition_top_site = match &decl.partition {
                    envcloak_signin::CookiePartition::Unpartitioned => None,
                    envcloak_signin::CookiePartition::Partitioned { site, .. } => {
                        Some(format!("{}://{}", site.scheme.as_str(), site.host))
                    }
                };
                cookies_wire.push(SupervisorCookieEntry {
                    domain,
                    host_only,
                    path: decl.path.as_str().to_owned(),
                    name: decl.name.as_str().to_owned(),
                    partition_top_site,
                    value: WireSecret::from(val),
                });
            }
            for (origin, key, val) in captured.storage {
                storage_wire.push(SupervisorStorageEntry {
                    origin,
                    key,
                    value: WireSecret::from(val),
                });
            }
        }

        let msg = ToSupervisor::InjectState(SupervisorInjectState {
            request: request.to_string(),
            generation: inj.generation.get(),
            context: inj.context.get().to_string(),
            cookies: cookies_wire,
            storage: storage_wire,
        });
        send_to_supervisor(&pipe.daemon_stream, &msg)
            .map_err(|_| RpcError::new(ErrorKind::Internal))?;
        self.signin.send_log.push(SendRecord {
            request,
            destination: SendDestination::SupervisorControlPipe {
                generation: inj.generation.get(),
            },
            contains_captured_state: true,
        });
        Ok(())
    }

    /// Re-reads the recipient's stored cookie metadata after import and
    /// refuses before publication on any change (`Codex cycle342`: e.g., a
    /// cookie path with a space `/a b` percent-encoded to `/a%20b` on import).
    pub fn signin_verify_imported_cookies(
        &mut self,
        request: RequestId,
        stored_cookies: &[DeclaredCookie],
        now: &Now,
    ) -> Result<(), RpcError> {
        let expected: Vec<DeclaredCookie> = {
            let op = self
                .signin
                .store
                .operation(&request)
                .ok_or(RpcError::new(ErrorKind::NoSuchRequest))?;
            op.scope()
                .target()
                .transfer
                .cookies
                .iter()
                .cloned()
                .collect()
        };
        let actual_set = envcloak_signin::SortedSet::new(stored_cookies.to_vec()).ok();
        let matches = actual_set
            .as_ref()
            .is_some_and(|set| set.iter().cloned().collect::<Vec<_>>() == expected);
        if !matches {
            let worker = self.signin.ops.get(&request).and_then(|m| m.active_worker);
            if let Some(w) = worker {
                let effects = {
                    let vault = slot_unlocked(&self.slot);
                    let world = LiveDaemonWorld {
                        daemon: self.signin.daemon_instance,
                        vault,
                        catalog: None,
                        browser_generation: self.signin.browser_generation,
                        ops: &self.signin.ops,
                        auths: &self.signin.auths,
                        overrides: &self.signin.world_overrides,
                    };
                    let _ = self.signin.store.worker_failed(
                        &request,
                        &w,
                        AttemptFailure::UnsupportedSessionScope,
                        now,
                        &world,
                    );
                    self.signin.store.drain_effects()
                };
                self.execute_signin_effects(effects, now, None);
            }
            return Err(RpcError::with_reason(
                ErrorKind::InvalidParams,
                "cookie_metadata_changed_on_import",
            ));
        }
        Ok(())
    }

    /// Processes one message read from the daemon's bound supervisor pipe
    /// for `bound_request`. The `bound_request` and `Channel::Supervisor`
    /// are derived exclusively from the pipe registration in `SigninState`,
    /// never from message fields (`Codex cycle339`).
    pub fn signin_handle_supervisor_pipe_msg(
        &mut self,
        bound_request: RequestId,
        msg: FromSupervisor,
        now: &Now,
    ) -> Result<bool, RpcError> {
        let supervisor = {
            let meta = self
                .signin
                .ops
                .get(&bound_request)
                .ok_or(RpcError::new(ErrorKind::NoSuchRequest))?;
            let pipe = meta
                .supervisor_pipe
                .as_ref()
                .ok_or(RpcError::new(ErrorKind::InvalidParams))?;
            pipe.supervisor
        };
        let channel = Channel::Supervisor(supervisor);

        match msg {
            FromSupervisor::IdentityResponse(SupervisorIdentityResponse {
                request: msg_req,
                generation: msg_gen,
                context: msg_ctx,
                account,
                tenant,
                role,
            }) => {
                if msg_gen != supervisor.generation().get() || msg_req != bound_request.to_string()
                {
                    return Err(RpcError::with_reason(
                        ErrorKind::InvalidParams,
                        "pipe_origin_mismatch",
                    ));
                }
                let expected_ctx = self
                    .signin
                    .store
                    .operation(&bound_request)
                    .map(|op| op.context().get().to_string())
                    .ok_or(RpcError::new(ErrorKind::NoSuchRequest))?;
                if msg_ctx != expected_ctx {
                    return Err(RpcError::with_reason(
                        ErrorKind::InvalidParams,
                        "context_mismatch",
                    ));
                }
                let acct_lbl = account
                    .as_deref()
                    .and_then(|s| Label::new(s).ok())
                    .unwrap_or_else(|| Label::new("__unverified__").expect("static label"));
                let tenant_lbl = tenant.as_deref().map(|t| {
                    Label::new(t)
                        .unwrap_or_else(|_| Label::new("__invalid__").expect("static label"))
                });
                let role_lbl = role
                    .as_deref()
                    .and_then(|s| Label::new(s).ok())
                    .unwrap_or_else(|| Label::new("__unverified__").expect("static label"));
                let identity = IdentityResponse {
                    account: acct_lbl,
                    tenant: tenant_lbl,
                    role: role_lbl,
                };

                let (decision, effects) = {
                    let vault = slot_unlocked(&self.slot);
                    let world = LiveDaemonWorld {
                        daemon: self.signin.daemon_instance,
                        vault,
                        catalog: None,
                        browser_generation: self.signin.browser_generation,
                        ops: &self.signin.ops,
                        auths: &self.signin.auths,
                        overrides: &self.signin.world_overrides,
                    };
                    let dec = self.signin.store.identity_response(
                        &channel,
                        &bound_request,
                        &identity,
                        now,
                        &world,
                    );
                    let eff = self.signin.store.drain_effects();
                    (dec, eff)
                };
                self.execute_signin_effects(effects, now, None);
                let decision = decision.map_err(|_| {
                    RpcError::with_reason(ErrorKind::InvalidParams, "channel_refused")
                })?;
                let published = matches!(decision, PublishDecision::Publish);
                if published {
                    let pub_effects = {
                        let vault = slot_unlocked(&self.slot);
                        let world = LiveDaemonWorld {
                            daemon: self.signin.daemon_instance,
                            vault,
                            catalog: None,
                            browser_generation: self.signin.browser_generation,
                            ops: &self.signin.ops,
                            auths: &self.signin.auths,
                            overrides: &self.signin.world_overrides,
                        };
                        let _ = self
                            .signin
                            .store
                            .published(&channel, &bound_request, now, &world);
                        self.signin.store.drain_effects()
                    };
                    self.execute_signin_effects(pub_effects, now, None);
                }
                if let Some(meta) = self.signin.ops.get(&bound_request)
                    && let Some(pipe) = meta.supervisor_pipe.as_ref()
                {
                    let _ = send_to_supervisor(
                        &pipe.daemon_stream,
                        &ToSupervisor::Publish(SupervisorPublish {
                            request: bound_request.to_string(),
                            generation: supervisor.generation().get(),
                            context: expected_ctx,
                            published,
                        }),
                    );
                }
                Ok(published)
            }
            FromSupervisor::Check(chk) => {
                if chk.generation != supervisor.generation().get()
                    || chk.request != bound_request.to_string()
                {
                    return Err(RpcError::with_reason(
                        ErrorKind::InvalidParams,
                        "pipe_origin_mismatch",
                    ));
                }
                if let Some(cleaned) = chk.cleaned {
                    let worker = self
                        .signin
                        .ops
                        .get(&bound_request)
                        .and_then(|m| m.active_worker);
                    if let Some(w) = worker {
                        let effects = {
                            let vault = slot_unlocked(&self.slot);
                            let world = LiveDaemonWorld {
                                daemon: self.signin.daemon_instance,
                                vault,
                                catalog: None,
                                browser_generation: self.signin.browser_generation,
                                ops: &self.signin.ops,
                                auths: &self.signin.auths,
                                overrides: &self.signin.world_overrides,
                            };
                            let _ = self.signin.store.cleanup_result(
                                &bound_request,
                                &w,
                                cleaned,
                                now,
                                &world,
                            );
                            self.signin.store.drain_effects()
                        };
                        self.execute_signin_effects(effects, now, None);
                    }
                    return Ok(cleaned);
                }
                let (res, effects) = {
                    let vault = slot_unlocked(&self.slot);
                    let world = LiveDaemonWorld {
                        daemon: self.signin.daemon_instance,
                        vault,
                        catalog: None,
                        browser_generation: self.signin.browser_generation,
                        ops: &self.signin.ops,
                        auths: &self.signin.auths,
                        overrides: &self.signin.world_overrides,
                    };
                    let r = self
                        .signin
                        .store
                        .check(&channel, &bound_request, now, &world);
                    let eff = self.signin.store.drain_effects();
                    (r, eff)
                };
                self.execute_signin_effects(effects, now, None);
                Ok(res.is_ok())
            }
        }
    }

    /// Reads and processes one message from the daemon's bound supervisor
    /// pipe for `bound_request`.
    pub fn signin_poll_supervisor_pipe(
        &mut self,
        bound_request: RequestId,
        now: &Now,
    ) -> Result<bool, RpcError> {
        let msg: FromSupervisor = {
            let meta = self
                .signin
                .ops
                .get(&bound_request)
                .ok_or(RpcError::new(ErrorKind::NoSuchRequest))?;
            let pipe = meta
                .supervisor_pipe
                .as_ref()
                .ok_or(RpcError::new(ErrorKind::InvalidParams))?;
            recv_from_supervisor(&pipe.daemon_stream)
                .map_err(|_| RpcError::new(ErrorKind::InvalidParams))?
        };
        self.signin_handle_supervisor_pipe_msg(bound_request, msg, now)
    }

    /// Reports worker capture on `request` for `worker`.
    pub fn signin_worker_captured(
        &mut self,
        request: RequestId,
        worker: WorkerId,
        captured: CapturedBrowserState,
        now: &Now,
    ) -> Result<(), RpcError> {
        if let Some(meta) = self.signin.ops.get_mut(&request)
            && meta.active_worker == Some(worker)
        {
            meta.captured_state = Some(captured);
        }
        let (res, effects) = {
            let vault = slot_unlocked(&self.slot);
            let world = LiveDaemonWorld {
                daemon: self.signin.daemon_instance,
                vault,
                catalog: None,
                browser_generation: self.signin.browser_generation,
                ops: &self.signin.ops,
                auths: &self.signin.auths,
                overrides: &self.signin.world_overrides,
            };
            let r = self
                .signin
                .store
                .worker_captured(&request, &worker, now, &world);
            let eff = self.signin.store.drain_effects();
            (r, eff)
        };
        self.execute_signin_effects(effects, now, None);
        res.map_err(|_| RpcError::with_reason(ErrorKind::InvalidParams, "worker_discarded"))
    }

    /// Reports worker failure on `request` for `worker`.
    pub fn signin_worker_failed(
        &mut self,
        request: RequestId,
        worker: WorkerId,
        failure: AttemptFailure,
        now: &Now,
    ) -> Result<(), RpcError> {
        let (res, effects) = {
            let vault = slot_unlocked(&self.slot);
            let world = LiveDaemonWorld {
                daemon: self.signin.daemon_instance,
                vault,
                catalog: None,
                browser_generation: self.signin.browser_generation,
                ops: &self.signin.ops,
                auths: &self.signin.auths,
                overrides: &self.signin.world_overrides,
            };
            let r = self
                .signin
                .store
                .worker_failed(&request, &worker, failure, now, &world);
            let eff = self.signin.store.drain_effects();
            (r, eff)
        };
        self.execute_signin_effects(effects, now, None);
        res.map_err(|_| RpcError::with_reason(ErrorKind::InvalidParams, "worker_discarded"))
    }
}

fn state_token(s: OpState) -> &'static str {
    match s {
        OpState::Requested => "requested",
        OpState::PendingApproval => "pending_approval",
        OpState::Approved => "approved",
        OpState::AttemptRunning => "attempt_running",
        OpState::Captured => "captured",
        OpState::PublishDecided => "publish_decided",
        OpState::Published => "published",
        OpState::Ended => "ended",
        OpState::Cancelled => "cancelled",
        OpState::Failed => "failed",
    }
}

fn cleanup_token(c: Cleanup) -> &'static str {
    match c {
        Cleanup::NotNeeded => "not_needed",
        Cleanup::Pending => "pending",
        Cleanup::Done => "done",
        Cleanup::Failed => "failed",
    }
}

fn revocation_token(r: Revocation) -> &'static str {
    match r {
        Revocation::Unknown => "unknown",
    }
}

fn stop_reason_token(r: StopReason) -> &'static str {
    match r {
        StopReason::Cancelled => "cancelled",
        StopReason::EndedByOwner => "ended_by_owner",
        StopReason::Locked => "locked",
        StopReason::RootExited => "root_exited",
        StopReason::EpochChanged => "epoch_changed",
        StopReason::ProjectChanged => "project_changed",
        StopReason::RevisionChanged => "revision_changed",
        StopReason::LimitsChanged => "limits_changed",
        StopReason::RecipientReplaced => "recipient_replaced",
        StopReason::SubjectIneligible => "subject_ineligible",
        StopReason::Revoked => "revoked",
        StopReason::StatementExpired => "statement_expired",
        StopReason::AuthorizationEnded => "authorization_ended",
        StopReason::AttemptTimedOut => "attempt_timed_out",
        StopReason::SessionExpired => "session_expired",
        StopReason::IdentityUnverified => "identity_unverified",
        StopReason::AttemptFailed(f) => match f {
            AttemptFailure::CredentialsRejected => "credentials_rejected",
            AttemptFailure::CodeRejected => "code_rejected",
            AttemptFailure::HandoffRequired => "handoff_required",
            AttemptFailure::OffOrigin => "off_origin",
            AttemptFailure::UnsupportedSessionScope => "unsupported_session_scope",
            AttemptFailure::AuditFailed => "audit_failed",
            AttemptFailure::WorkerLost => "worker_lost",
        },
    }
}

fn status_view_of(
    s: &State,
    request: RequestId,
    status: Status,
    shared_loopback_cookie_jar: bool,
) -> SigninStatusView {
    let op = s.signin.store.operation(&request);
    let delivered_context = if status.receipt.delivered {
        op.map(|o| format!("ctx-{}", o.context().get()))
    } else {
        None
    };
    let authorization = op.and_then(|o| o.authorization().map(|a| a.to_string()));
    let retry_until_secs = status
        .retry_until
        .and_then(|w| w.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs());

    SigninStatusView {
        request: request.to_string(),
        revision: status.revision,
        state: state_token(status.state).to_owned(),
        retry_until_secs,
        delivered_context,
        cleanup: cleanup_token(status.receipt.cleanup).to_owned(),
        revocation: revocation_token(status.receipt.revocation).to_owned(),
        reason: status
            .receipt
            .reason
            .map(|r| stop_reason_token(r).to_owned()),
        shared_loopback_cookie_jar,
        authorization,
    }
}

/// `signin.request`.
pub fn request(
    shared: &Shared,
    peer: &PeerIdentity,
    p: SigninRequestParams,
    fds: Vec<OwnedFd>,
) -> Result<SigninStatusView, RpcError> {
    let tool_pipes = if fds.is_empty() {
        None
    } else if fds.len() == 2 {
        let mut it = fds.into_iter();
        match (it.next(), it.next()) {
            (Some(a), Some(b)) => Some((a, b)),
            _ => return Err(RpcError::new(ErrorKind::InvalidParams)),
        }
    } else {
        return Err(RpcError::new(ErrorKind::InvalidParams));
    };
    let manifest_path = Path::new(&p.manifest);
    if !manifest_path.is_absolute() {
        return Err(RpcError::with_reason(
            ErrorKind::ManifestInvalid,
            "invalid_path",
        ));
    }
    let loaded = load_project(manifest_path).map_err(manifest_error)?;
    let config_digest = signin_config_digest(&loaded.identity.canonical_dir);
    let project_scope = ProjectScope::new(&loaded.identity, config_digest);

    let key = OperationKey::parse(&p.operation_key)
        .map_err(|_| RpcError::with_reason(ErrorKind::InvalidParams, "invalid_operation_key"))?;

    let caller = evidence(shared, peer, &p.claims)?;
    let requester_inst = Instance::from(caller.caller());
    let root_inst = Instance::from(&caller.root());
    let ev_digest = subject_evidence_digest(&caller);

    let mut s_guard = locked(&shared.state);
    let s: &mut State = &mut s_guard;
    let now = now_of(&shared.clocks);
    s.signin_reconcile_at(&now, Some(&shared.catalog));

    let (
        login_item,
        login_slug,
        login_class,
        login_rev,
        login_meta,
        parsed_target,
        vault_epoch,
        policy_epoch,
    ) = {
        let v = s.unlocked()?;
        let h = v.header().map_err(|e| {
            RpcError::with_reason(ErrorKind::VaultUnavailable, vault_reason(e.kind()))
        })?;
        let (target_pid, target_rec) =
            find_target_by_name_and_role(v, &p.target, p.role.as_deref())?
                .ok_or_else(|| RpcError::with_reason(ErrorKind::NoSuchItem, "unknown_target"))?;
        let (parsed_target, _) = target_from_vault(v, target_pid, &target_rec, 0, 0)?;

        let item_meta = v
            .item(parsed_target.login_item)
            .filter(|m| m.class == ItemClass::Login)
            .ok_or_else(|| RpcError::with_reason(ErrorKind::NoSuchItem, "unknown_login_item"))?
            .clone();
        let login_rev = v
            .login_revision(item_meta.id)
            .ok_or(RpcError::new(ErrorKind::Internal))?;
        let login_meta = item_meta.login.ok_or(RpcError::new(ErrorKind::Internal))?;
        (
            item_meta.id,
            item_meta.slug,
            item_meta.details.classification,
            login_rev,
            login_meta,
            parsed_target,
            u64::from(v.epoch()),
            h.policy_epoch,
        )
    };

    let subj_kind = caller.kind();
    if subj_kind == SubjectKind::Agent {
        if login_meta.tier == LoginTier::NeverAgent || parsed_target.tier == LoginTier::NeverAgent {
            return Err(RpcError::with_reason(
                ErrorKind::ProofRefused,
                "never_agent",
            ));
        }
        if login_class != Classification::Test {
            return Err(RpcError::with_reason(
                ErrorKind::ProofRefused,
                "live_login_agent",
            ));
        }
    }

    let limits = compute_effective_limits(
        &login_meta,
        login_class,
        parsed_target.tier,
        parsed_target.approval_lifetime,
        parsed_target.session_lifetime,
        subj_kind,
    )
    .ok_or_else(|| RpcError::with_reason(ErrorKind::InvalidParams, "invalid_limits"))?;

    let browser_gen = s
        .signin
        .world_overrides
        .browser_generation
        .unwrap_or(s.signin.browser_generation);

    let delivery = Delivery {
        mode: DeliveryMode::BrowserSession,
        requester: requester_inst,
        browser: browser_gen,
    };
    let epochs = Epochs {
        daemon: s.signin.daemon_instance,
        vault: vault_epoch,
        policy: policy_epoch,
    };
    let account = parsed_target.build_account(login_rev, login_class);
    let scope = SignInScope::new(
        Subject {
            root: root_inst,
            evidence: ev_digest,
        },
        project_scope,
        account,
        parsed_target.target.clone(),
        delivery,
        limits,
        epochs,
    )
    .map_err(|_| RpcError::with_reason(ErrorKind::InvalidParams, "invalid_signin_scope"))?;

    let shared_jar = parsed_target.shared_loopback_cookie_jar;
    let subj_summary = subject_summary(peer, &caller);
    let (lookup, effects) = loop {
        let mut req_bytes = [0u8; 16];
        let mut nonce_bytes = [0u8; 32];
        envcloak_core::crypto::fill_random_or_panic(&mut req_bytes);
        envcloak_core::crypto::fill_random_or_panic(&mut nonce_bytes);
        let fresh = Fresh {
            request: RequestId::from_bytes(req_bytes),
            nonce: Nonce::from_bytes(nonce_bytes),
        };
        if s.signin.ops.contains_key(&fresh.request) {
            continue;
        }
        s.signin.ops.insert(
            fresh.request,
            SigninOperationMeta {
                request: fresh.request,
                scope: scope.clone(),
                peer: *peer,
                subject: caller.clone(),
                subject_summary: subj_summary.clone(),
                claims: p.claims.clone(),
                manifest_path: manifest_path.to_path_buf(),
                project_dir: loaded.identity.canonical_dir.clone(),
                login_item,
                login_slug: login_slug.clone(),
                target_policy_id: parsed_target.policy_id,
                target_name: parsed_target.name.clone(),
                shared_loopback_cookie_jar: shared_jar,
                created_awake: now.awake,
                captured_state: None,
                active_worker: None,
                supervisor_pipe: None,
                tool_pipes: None,
                publish_audited: false,
                end_audited: false,
            },
        );
        let res = {
            let vault = slot_unlocked(&s.slot);
            let world = LiveDaemonWorld {
                daemon: s.signin.daemon_instance,
                vault,
                catalog: Some(&shared.catalog),
                browser_generation: s.signin.browser_generation,
                ops: &s.signin.ops,
                auths: &s.signin.auths,
                overrides: &s.signin.world_overrides,
            };
            s.signin.store.lookup_or_reserve(
                Request {
                    key: key.clone(),
                    scope: scope.clone(),
                },
                fresh,
                &now,
                &world,
            )
        };
        match res {
            Ok(l) => {
                if l.status().request != fresh.request {
                    s.signin.ops.remove(&fresh.request);
                }
                let eff = s.signin.store.drain_effects();
                break (l, eff);
            }
            Err(RequestError::IdInUse) => {
                s.signin.ops.remove(&fresh.request);
                continue;
            }
            Err(RequestError::Conflict) => {
                s.signin.ops.remove(&fresh.request);
                return Err(RpcError::new(ErrorKind::RequestConflict));
            }
            Err(RequestError::Full) => {
                s.signin.ops.remove(&fresh.request);
                return Err(RpcError::new(ErrorKind::TooManyPending));
            }
            Err(RequestError::WrongDaemon) => {
                s.signin.ops.remove(&fresh.request);
                return Err(RpcError::new(ErrorKind::Internal));
            }
        }
    };

    let status = lookup.status();
    let req_id = status.request;
    if let Some(pipes) = tool_pipes
        && let Some(meta) = s.signin.ops.get_mut(&req_id)
        && meta.tool_pipes.is_none()
    {
        meta.tool_pipes = Some(pipes);
    }

    s.execute_signin_effects(effects, &now, Some(&shared.catalog));

    let view = status_view_of(s, req_id, status, shared_jar);
    s.signin.send_log.push(SendRecord {
        request: req_id,
        destination: SendDestination::IpcReply {
            method: "signin.request",
        },
        contains_captured_state: false,
    });
    write_test_send_log(&s.signin.send_log);
    drop(s_guard);
    maybe_drive_test_stub_supervisor(shared, req_id);
    if std::env::var_os("ENVCLOAK_TEST_STUB_SIGNIN_DIR").is_some() {
        let mut s_guard = locked(&shared.state);
        let s: &mut State = &mut s_guard;
        if let Some(op) = s.signin.store.operation(&req_id) {
            return Ok(status_view_of(s, req_id, op.status(), shared_jar));
        }
    }
    Ok(view)
}

fn parse_signin_req_id(raw: &str) -> Result<RequestId, RpcError> {
    RequestId::parse(raw).ok_or(RpcError::new(ErrorKind::NoSuchRequest))
}

/// `signin.status`. Refused before any metadata if called from another root.
pub fn status(
    shared: &Shared,
    peer: &PeerIdentity,
    p: SigninOperationParams,
) -> Result<SigninStatusView, RpcError> {
    let req_id = parse_signin_req_id(&p.request)?;
    let caller = evidence(shared, peer, &[])?;
    let caller_root = Instance::from(&caller.root());
    let mut s_guard = locked(&shared.state);
    let s: &mut State = &mut s_guard;
    let now = now_of(&shared.clocks);
    let (res, effects) = {
        let vault = slot_unlocked(&s.slot);
        let world = LiveDaemonWorld {
            daemon: s.signin.daemon_instance,
            vault,
            catalog: Some(&shared.catalog),
            browser_generation: s.signin.browser_generation,
            ops: &s.signin.ops,
            auths: &s.signin.auths,
            overrides: &s.signin.world_overrides,
        };
        let r = s.signin.store.status(&caller_root, &req_id, &now, &world);
        let eff = s.signin.store.drain_effects();
        (r, eff)
    };
    s.execute_signin_effects(effects, &now, Some(&shared.catalog));
    let st = res.map_err(|_| RpcError::new(ErrorKind::NoSuchRequest))?;
    let shared_jar = s
        .signin
        .ops
        .get(&req_id)
        .is_some_and(|m| m.shared_loopback_cookie_jar);
    let view = status_view_of(s, req_id, st, shared_jar);
    s.signin.send_log.push(SendRecord {
        request: req_id,
        destination: SendDestination::IpcReply {
            method: "signin.status",
        },
        contains_captured_state: false,
    });
    write_test_send_log(&s.signin.send_log);
    Ok(view)
}

/// `signin.cancel`. Refused before any metadata if called from another root.
pub fn cancel(
    shared: &Shared,
    peer: &PeerIdentity,
    p: SigninOperationParams,
) -> Result<SigninStatusView, RpcError> {
    let req_id = parse_signin_req_id(&p.request)?;
    let caller = evidence(shared, peer, &[])?;
    let caller_root = Instance::from(&caller.root());
    let mut s_guard = locked(&shared.state);
    let s: &mut State = &mut s_guard;
    let now = now_of(&shared.clocks);
    let (res, effects) = {
        let vault = slot_unlocked(&s.slot);
        let world = LiveDaemonWorld {
            daemon: s.signin.daemon_instance,
            vault,
            catalog: Some(&shared.catalog),
            browser_generation: s.signin.browser_generation,
            ops: &s.signin.ops,
            auths: &s.signin.auths,
            overrides: &s.signin.world_overrides,
        };
        let r = s.signin.store.cancel(&caller_root, &req_id, &now, &world);
        let eff = s.signin.store.drain_effects();
        (r, eff)
    };
    s.execute_signin_effects(effects, &now, Some(&shared.catalog));
    let st = res.map_err(|_| RpcError::new(ErrorKind::NoSuchRequest))?;
    let shared_jar = s
        .signin
        .ops
        .get(&req_id)
        .is_some_and(|m| m.shared_loopback_cookie_jar);
    Ok(status_view_of(s, req_id, st, shared_jar))
}

/// `signin.end`. Accepts either the request id (32 hex) or the delivered
/// context id (`ctx-<n>` or `<n>`), from the owner root.
pub fn end(
    shared: &Shared,
    peer: &PeerIdentity,
    p: SigninEndParams,
) -> Result<SigninStatusView, RpcError> {
    let caller = evidence(shared, peer, &[])?;
    let caller_root = Instance::from(&caller.root());
    let mut s_guard = locked(&shared.state);
    let s: &mut State = &mut s_guard;
    let now = now_of(&shared.clocks);

    let req_id = if let Some(id) = RequestId::parse(&p.session) {
        id
    } else {
        let ctx_str = p.session.strip_prefix("ctx-").unwrap_or(&p.session);
        let ctx_num: u64 = ctx_str
            .parse()
            .map_err(|_| RpcError::new(ErrorKind::NoSuchRequest))?;
        s.signin
            .store
            .operations()
            .find(|op| op.context().get() == ctx_num && op.owner() == caller_root)
            .map(|op| op.request())
            .ok_or(RpcError::new(ErrorKind::NoSuchRequest))?
    };

    let (res, effects) = {
        let vault = slot_unlocked(&s.slot);
        let world = LiveDaemonWorld {
            daemon: s.signin.daemon_instance,
            vault,
            catalog: Some(&shared.catalog),
            browser_generation: s.signin.browser_generation,
            ops: &s.signin.ops,
            auths: &s.signin.auths,
            overrides: &s.signin.world_overrides,
        };
        let r = s.signin.store.end(&caller_root, &req_id, &now, &world);
        let eff = s.signin.store.drain_effects();
        (r, eff)
    };
    s.execute_signin_effects(effects, &now, Some(&shared.catalog));
    let st = res.map_err(|_| RpcError::new(ErrorKind::NoSuchRequest))?;
    let shared_jar = s
        .signin
        .ops
        .get(&req_id)
        .is_some_and(|m| m.shared_loopback_cookie_jar);
    Ok(status_view_of(s, req_id, st, shared_jar))
}

fn policy_subject_summary(ev: &SubjectEvidence) -> PolicySubjectSummary {
    let root = ev.root();
    PolicySubjectSummary {
        kind: ev.kind(),
        label: ev.label().map(|l| l.name.clone()),
        caller_pid: ev.caller().pid,
        root: PolicyProcessSummary {
            pid: root.pid,
            start_time: root.start_time.raw(),
            exe: root
                .exe
                .as_ref()
                .map(|e| e.path.to_string_lossy().into_owned()),
        },
    }
}

/// Builds the live [`SignInPendingDescriptor`] for a pending sign-in
/// operation.
pub(crate) fn build_pending_descriptor(
    s: &mut State,
    req_id: RequestId,
    options_override: Option<Options>,
    now: &Now,
    catalog: Option<&envcloak_policy::AgentCatalog>,
) -> Result<SignInPendingDescriptor, RpcError> {
    let default_opts = {
        let op = s
            .signin
            .store
            .operation(&req_id)
            .ok_or(RpcError::new(ErrorKind::NoSuchRequest))?;
        Options::default_for(op.scope().limits())
    };
    let opts = options_override.unwrap_or(default_opts);
    let (stmt_opt, effects) = {
        let vault = slot_unlocked(&s.slot);
        let world = LiveDaemonWorld {
            daemon: s.signin.daemon_instance,
            vault,
            catalog,
            browser_generation: s.signin.browser_generation,
            ops: &s.signin.ops,
            auths: &s.signin.auths,
            overrides: &s.signin.world_overrides,
        };
        let st = s.signin.store.statement(&req_id, opts, now, &world);
        let eff = s.signin.store.drain_effects();
        (st, eff)
    };
    s.execute_signin_effects(effects, now, catalog);
    let stmt = stmt_opt.ok_or(RpcError::new(ErrorKind::NoSuchRequest))?;
    let meta = s
        .signin
        .ops
        .get(&req_id)
        .ok_or(RpcError::new(ErrorKind::NoSuchRequest))?;
    Ok(SignInPendingDescriptor::from_statement(
        &stmt,
        policy_subject_summary(&meta.subject),
        meta.login_slug.as_str().to_owned(),
        meta.target_name.clone(),
    ))
}

/// Views of all currently pending sign-in operations for `pending.list`.
pub(crate) fn pending_views(
    s: &mut State,
    caller: &SubjectEvidence,
    now: &Now,
) -> Vec<PendingView> {
    s.signin_sweep(now);
    let mut out = Vec::new();
    let ids: Vec<RequestId> = s.signin.ops.keys().copied().collect();
    for id in ids {
        let Some(op) = s.signin.store.operation(&id) else {
            continue;
        };
        if op.stop().is_some() || op.phase() != Phase::PendingApproval {
            continue;
        }
        let expires_in_secs = op.statement_deadline().remaining(now).as_secs();
        let Some(meta) = s.signin.ops.get(&id) else {
            continue;
        };
        if caller.approval_refusal(&meta.subject, &alive).is_some() {
            continue;
        }
        let kind = meta.subject.kind();
        let age = now.awake.saturating_sub(meta.created_awake);
        out.push(PendingView {
            request: id.to_string(),
            age_secs: age.as_secs(),
            expires_in_secs,
            kind,
            agent: match kind {
                SubjectKind::Agent => meta.subject.label().map(|l| l.name.clone()),
                SubjectKind::Terminal | SubjectKind::Unknown => None,
            },
            project: meta.project_dir.to_string_lossy().into_owned(),
            bindings: vec![format!(
                "signin:{}#{}={}",
                meta.target_name,
                meta.scope.account().role.as_str(),
                meta.login_slug.as_str()
            )],
            more_bindings: 0,
        });
    }
    out
}

/// State of a 32-hex sign-in request id for `pending.state`.
pub(crate) fn pending_state(
    shared: &Shared,
    peer: &PeerIdentity,
    p: PendingStateParams,
) -> Result<PendingStateView, RpcError> {
    let req_id = RequestId::parse(&p.request).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let caller = evidence(shared, peer, &[])?;
    let caller_root = Instance::from(&caller.root());
    let mut s_guard = locked(&shared.state);
    let s: &mut State = &mut s_guard;
    let now = now_of(&shared.clocks);
    let (res, effects) = {
        let vault = slot_unlocked(&s.slot);
        let world = LiveDaemonWorld {
            daemon: s.signin.daemon_instance,
            vault,
            catalog: Some(&shared.catalog),
            browser_generation: s.signin.browser_generation,
            ops: &s.signin.ops,
            auths: &s.signin.auths,
            overrides: &s.signin.world_overrides,
        };
        let r = s.signin.store.status(&caller_root, &req_id, &now, &world);
        let eff = s.signin.store.drain_effects();
        (r, eff)
    };
    s.execute_signin_effects(effects, &now, Some(&shared.catalog));
    let Ok(st) = res else {
        return Ok(PendingStateView {
            state: PendingState::Unknown,
        });
    };
    let state = match st.state {
        OpState::Requested | OpState::PendingApproval => PendingState::Pending,
        OpState::Approved
        | OpState::AttemptRunning
        | OpState::Captured
        | OpState::PublishDecided
        | OpState::Published
        | OpState::Ended => PendingState::Approved,
        OpState::Cancelled => PendingState::Denied,
        OpState::Failed => PendingState::Unknown,
    };
    Ok(PendingStateView { state })
}

/// `pending.get` for a 32-hex sign-in request id.
pub(crate) fn pending_get(
    shared: &Shared,
    peer: &PeerIdentity,
    p: PendingGetParams,
) -> Result<PendingGetOutput, RpcError> {
    let req_id = RequestId::parse(&p.request).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let caller = evidence(shared, peer, &p.claims)?;
    refuse_unless_prover(shared, peer, &caller, "pending.get")?;
    let mut s = locked(&shared.state);
    s.refuse_if_tampered()?;
    let now = now_of(&shared.clocks);
    let meta_subject = s
        .signin
        .ops
        .get(&req_id)
        .map(|m| m.subject.clone())
        .ok_or(RpcError::new(ErrorKind::NoSuchRequest))?;
    if let Some(r) = caller.approval_refusal(&meta_subject, &alive) {
        s.audit(AuditEvent::ProofRefused {
            pid: peer.pid,
            method: "pending.get",
            reason: r.token(),
        });
        return Err(RpcError::with_reason(ErrorKind::ProofRefused, r.token()));
    }
    let desc = build_pending_descriptor(&mut s, req_id, None, &now, Some(&shared.catalog))?;
    Ok(PendingGetOutput::SignIn(Box::new(desc)))
}

fn resolve_approve_options(
    dev: Option<SignInDevOptions>,
    limits: &Limits,
) -> Result<Options, RpcError> {
    let opts = match dev {
        None => Options::Once,
        Some(d) => d.to_options(),
    };
    opts.allowed_by(limits)
        .map_err(|_| RpcError::new(ErrorKind::InvalidOptions))?;
    Ok(opts)
}

/// `approve` for a 32-hex sign-in request id.
pub(crate) fn approve(
    shared: &Shared,
    peer: &PeerIdentity,
    p: ApproveParams,
) -> Result<ApprovedView, RpcError> {
    let pass = p.passphrase.map(|w| w.into_inner());
    if p.options.standing.is_some() || !p.options.live.is_empty() {
        return Err(RpcError::new(ErrorKind::InvalidOptions));
    }
    if p.dev.is_none() && p.options.uses != Uses::Once {
        return Err(RpcError::new(ErrorKind::InvalidOptions));
    }
    let req_id = RequestId::parse(&p.request).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let digest = digest_of(&p.digest).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    refuse_if_traced()?;
    let caller = evidence(shared, peer, &p.claims)?;
    refuse_unless_prover(shared, peer, &caller, "approve")?;

    let (vault, generation, pass, chosen_options) = {
        let mut s = locked(&shared.state);
        let now = now_of(&shared.clocks);
        s.signin_reconcile_at(&now, Some(&shared.catalog));
        let meta = s
            .signin
            .ops
            .get(&req_id)
            .ok_or(RpcError::new(ErrorKind::NoSuchRequest))?;
        if let Some(r) = caller.approval_refusal(&meta.subject, &alive) {
            s.audit(AuditEvent::ProofRefused {
                pid: peer.pid,
                method: "approve",
                reason: r.token(),
            });
            return Err(RpcError::with_reason(ErrorKind::ProofRefused, r.token()));
        }
        let op = s
            .signin
            .store
            .operation(&req_id)
            .ok_or(RpcError::new(ErrorKind::NoSuchRequest))?;
        if op.stop().is_some() || op.phase() != Phase::PendingApproval {
            return Err(RpcError::new(ErrorKind::NoSuchRequest));
        }
        let chosen_options = resolve_approve_options(p.dev, op.scope().limits())?;
        let desc = build_pending_descriptor(
            &mut s,
            req_id,
            Some(chosen_options),
            &now,
            Some(&shared.catalog),
        )?;
        let stmt = desc
            .to_statement(chosen_options)
            .ok_or(RpcError::new(ErrorKind::Internal))?;
        if stmt.digest() != digest {
            return Err(RpcError::new(ErrorKind::StatementMismatch));
        }

        let pass = pass.ok_or(RpcError::new(ErrorKind::InvalidParams))?;
        s.limiter()
            .check(&now)
            .map_err(|_| RpcError::new(ErrorKind::TooManyAttempts))?;
        let (vault, generation) = s.begin_proof()?;
        (vault, generation, pass, chosen_options)
    };

    let verified = {
        let _gate = locked(&shared.proof_gate);
        vault.verify_passphrase(&pass)
    };
    drop(pass);

    {
        let mut s = locked(&shared.state);
        let now = now_of(&shared.clocks);
        let back = s.finish_proof(generation, vault);
        match verified {
            Ok(()) => {
                s.limiter().succeeded();
                back?;
            }
            Err(e) if e.kind() == VaultErrorKind::Crypto(CryptoErrorKind::Unlock) => {
                s.limiter().failed(&now);
                s.audit(AuditEvent::ProofFailed {
                    pid: peer.pid,
                    kind: AuditKind::SigninApprove,
                });
                back?;
                return Err(RpcError::new(ErrorKind::WrongPassphrase));
            }
            Err(e) => {
                back?;
                return Err(RpcError::with_reason(
                    ErrorKind::VaultUnavailable,
                    vault_reason(e.kind()),
                ));
            }
        }
    }

    envcloak_sys::pause_point("signin.approve.during_proof");

    let mut s = locked(&shared.state);
    let now = now_of(&shared.clocks);
    let caller = evidence(shared, peer, &p.claims)?;
    let meta_subject = s
        .signin
        .ops
        .get(&req_id)
        .map(|m| m.subject.clone())
        .ok_or(RpcError::new(ErrorKind::NoSuchRequest))?;
    if let Some(r) = caller.approval_refusal(&meta_subject, &alive) {
        s.audit(AuditEvent::ProofRefused {
            pid: peer.pid,
            method: "approve",
            reason: r.token(),
        });
        return Err(RpcError::with_reason(ErrorKind::ProofRefused, r.token()));
    }
    let res = finish_signin_approve(
        &mut s,
        shared,
        peer,
        &caller,
        req_id,
        chosen_options,
        &digest,
        &now,
    )?;
    drop(s);
    maybe_drive_test_stub_supervisor(shared, req_id);
    Ok(res)
}

#[allow(clippy::too_many_arguments)]
fn finish_signin_approve(
    s: &mut State,
    shared: &Shared,
    peer: &PeerIdentity,
    caller: &SubjectEvidence,
    req_id: RequestId,
    options: Options,
    digest: &[u8; 32],
    now: &Now,
) -> Result<ApprovedView, RpcError> {
    let (res, effects) = {
        let vault = slot_unlocked(&s.slot);
        let world = LiveDaemonWorld {
            daemon: s.signin.daemon_instance,
            vault,
            catalog: Some(&shared.catalog),
            browser_generation: s.signin.browser_generation,
            ops: &s.signin.ops,
            auths: &s.signin.auths,
            overrides: &s.signin.world_overrides,
        };
        let r = s
            .signin
            .store
            .approve(&req_id, options, digest, now, &world);
        let eff = s.signin.store.drain_effects();
        (r, eff)
    };
    s.execute_signin_effects(effects, now, Some(&shared.catalog));

    let _status = res.map_err(|e| match e {
        SignInApproveError::NoSuchRequest | SignInApproveError::NotPending => {
            RpcError::new(ErrorKind::NoSuchRequest)
        }
        SignInApproveError::Options(_) => RpcError::new(ErrorKind::InvalidOptions),
        SignInApproveError::DigestMismatch => RpcError::new(ErrorKind::StatementMismatch),
        SignInApproveError::Full | SignInApproveError::Budget(_) => {
            RpcError::new(ErrorKind::TooManyPending)
        }
    })?;

    let auth_id = s
        .signin
        .store
        .operation(&req_id)
        .and_then(|op| op.authorization())
        .ok_or(RpcError::new(ErrorKind::Internal))?;

    let meta = s
        .signin
        .ops
        .get(&req_id)
        .ok_or(RpcError::new(ErrorKind::NoSuchRequest))?;
    let item_id = meta.login_item;
    let login_slug = meta.login_slug.clone();
    let target_name = meta.target_name.clone();
    let role = meta.scope.account().role.as_str().to_owned();
    let fp: ScopeFingerprint = *meta.scope.fingerprint().as_bytes();
    s.signin.auths.insert(
        auth_id,
        SigninAuthMeta {
            id: auth_id,
            scope_fingerprint: fp,
            subject: meta.subject.clone(),
            project_dir: meta.project_dir.clone(),
            login_item: item_id,
            login_slug: login_slug.clone(),
            target_name,
            role,
            created_wall: now.wall,
        },
    );

    let ttl_secs = match options {
        Options::Once => s
            .signin
            .store
            .authorization(&auth_id)
            .map_or(0, |a| a.deadline().remaining(now).as_secs()),
        Options::Dev { window, .. } => window.as_secs(),
    };

    s.touch(Reading::now(&shared.clocks));
    s.audit(AuditEvent::SigninApprove {
        pid: peer.pid,
        subject: subject_summary(peer, caller),
        outcome: "approved",
        request: Some(req_id.to_string()),
        authorization: Some(auth_id.to_string()),
        item: Some((item_id, login_slug)),
        reason: None,
        ttl_secs: Some(ttl_secs),
    });
    Ok(ApprovedView {
        grant: auth_id.to_string(),
        expires_in_secs: ttl_secs,
        standing: None,
        standing_expires_in_secs: None,
    })
}

/// `deny` for a 32-hex sign-in request id.
pub(crate) fn deny(
    shared: &Shared,
    peer: &PeerIdentity,
    p: RequestParams,
) -> Result<DeniedView, RpcError> {
    let req_id = RequestId::parse(&p.request).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let mut s_guard = locked(&shared.state);
    let s: &mut State = &mut s_guard;
    let now = now_of(&shared.clocks);
    let (res, effects) = {
        let vault = slot_unlocked(&s.slot);
        let world = LiveDaemonWorld {
            daemon: s.signin.daemon_instance,
            vault,
            catalog: Some(&shared.catalog),
            browser_generation: s.signin.browser_generation,
            ops: &s.signin.ops,
            auths: &s.signin.auths,
            overrides: &s.signin.world_overrides,
        };
        let r = s.signin.store.deny(&req_id, &now, &world);
        let eff = s.signin.store.drain_effects();
        (r, eff)
    };
    s.execute_signin_effects(effects, &now, Some(&shared.catalog));
    res.map_err(|_| RpcError::new(ErrorKind::NoSuchRequest))?;
    s.audit(AuditEvent::Denied {
        pid: peer.pid,
        request: req_id.to_string(),
        root_auto_denied: false,
    });
    Ok(DeniedView {
        root_auto_denied: false,
    })
}

/// Active sign-in authorizations formatted as [`GrantView`] for `grants.list`.
pub(crate) fn grant_views(s: &mut State, now: &Now) -> Vec<GrantView> {
    s.signin_sweep(now);
    let epochs = {
        let vault = slot_unlocked(&s.slot);
        let (v_ep, p_ep) = vault
            .and_then(|v| Some((u64::from(v.epoch()), v.header().ok()?.policy_epoch)))
            .unwrap_or((0, 0));
        Epochs {
            daemon: s.signin.daemon_instance,
            vault: v_ep,
            policy: p_ep,
        }
    };
    let mut out = Vec::new();
    for auth in s.signin.store.authorizations() {
        if !auth.in_force(&epochs, now) {
            continue;
        }
        let rem = auth.deadline().remaining(now);
        if rem.is_zero() {
            continue;
        }
        let Some(meta) = s.signin.auths.get(&auth.id()) else {
            continue;
        };
        let root = meta.subject.root();
        let uses = match auth.kind() {
            AuthorizationKind::Once => Uses::Once,
            AuthorizationKind::Dev => Uses::Session,
        };
        out.push(GrantView {
            id: auth.id().to_string(),
            kind: meta.subject.kind(),
            label: meta.subject.label().map(|l| l.name.clone()),
            root_pid: root.pid,
            root_exe: root
                .exe
                .as_ref()
                .map(|e| e.path.to_string_lossy().into_owned()),
            project_dir: meta.project_dir.to_string_lossy().into_owned(),
            bindings: vec![GrantBindingView {
                env_name: format!("signin:{}#{}", meta.target_name, meta.role),
                slug: meta.login_slug.as_str().to_owned(),
                live: false,
            }],
            mode: Mode::SignIn(meta.scope_fingerprint),
            uses,
            created_secs: meta
                .created_wall
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            remaining_secs: rem.as_secs(),
        });
    }
    out
}

/// Revokes matching sign-in authorizations for `grants.revoke` (one or
/// `--all`) via [`OperationStore::revoke`] / [`OperationStore::revoke_all`].
pub(crate) fn revoke_grants(
    s: &mut State,
    grant: Option<&str>,
    all: bool,
    now: &Now,
) -> Result<usize, RpcError> {
    if all {
        let (count, effects) = {
            let vault = slot_unlocked(&s.slot);
            let world = LiveDaemonWorld {
                daemon: s.signin.daemon_instance,
                vault,
                catalog: None,
                browser_generation: s.signin.browser_generation,
                ops: &s.signin.ops,
                auths: &s.signin.auths,
                overrides: &s.signin.world_overrides,
            };
            let n = s.signin.store.revoke_all(now, &world);
            let eff = s.signin.store.drain_effects();
            (n, eff)
        };
        s.execute_signin_effects(effects, now, None);
        return Ok(count);
    }

    let Some(raw) = grant else {
        return Ok(0);
    };
    let Some(aid) = AuthorizationId::parse(raw) else {
        return Ok(0);
    };
    let (revoked, effects) = {
        let vault = slot_unlocked(&s.slot);
        let world = LiveDaemonWorld {
            daemon: s.signin.daemon_instance,
            vault,
            catalog: None,
            browser_generation: s.signin.browser_generation,
            ops: &s.signin.ops,
            auths: &s.signin.auths,
            overrides: &s.signin.world_overrides,
        };
        let r = s.signin.store.revoke(&aid, now, &world);
        let eff = s.signin.store.drain_effects();
        (r, eff)
    };
    s.execute_signin_effects(effects, now, None);
    Ok(usize::from(revoked))
}

fn write_test_send_log(log: &[SendRecord]) {
    let Some(dir_os) = std::env::var_os("ENVCLOAK_TEST_STUB_SIGNIN_DIR") else {
        return;
    };
    let dir = PathBuf::from(dir_os);
    let mut out = String::new();
    for rec in log {
        let dest = match rec.destination {
            SendDestination::SupervisorControlPipe { generation } => {
                format!("supervisor:{generation}")
            }
            SendDestination::IpcReply { method } => format!("ipc:{method}"),
        };
        out.push_str(&format!(
            "request={} dest={} captured={}\n",
            rec.request, dest, rec.contains_captured_state
        ));
    }
    let _ = std::fs::write(dir.join("send_log.txt"), out);
}

fn maybe_drive_test_stub_supervisor(shared: &Shared, req_id: RequestId) {
    use std::io::Write;

    let Some(dir_os) = std::env::var_os("ENVCLOAK_TEST_STUB_SIGNIN_DIR") else {
        return;
    };
    let dir = PathBuf::from(dir_os);

    let (peer_stream, tool_pipes, default_account, default_tenant, default_role, declared_cookies) = {
        let mut s = locked(&shared.state);
        let now = now_of(&shared.clocks);
        let Some(meta) = s.signin.ops.get_mut(&req_id) else {
            return;
        };
        let Some(worker) = meta.active_worker else {
            return;
        };
        if meta.supervisor_pipe.is_some() {
            return;
        }
        let tool_pipes = meta.tool_pipes.take();
        let default_account = meta.scope.account().account.as_str().to_owned();
        let default_tenant = meta
            .scope
            .account()
            .tenant
            .as_ref()
            .map(|t| t.as_str().to_owned());
        let default_role = meta.scope.account().role.as_str().to_owned();
        let declared_cookies: Vec<DeclaredCookie> = meta
            .scope
            .target()
            .transfer
            .cookies
            .iter()
            .cloned()
            .collect();
        let captured = CapturedBrowserState {
            cookies: declared_cookies
                .iter()
                .cloned()
                .map(|c| (c, SecretBytes::copy_from(b"stub-cookie-value")))
                .collect(),
            storage: Vec::new(),
        };
        if s.signin_worker_captured(req_id, worker, captured, &now)
            .is_err()
        {
            write_test_send_log(&s.signin.send_log);
            return;
        }
        let Some(peer_stream) = s
            .signin
            .ops
            .get_mut(&req_id)
            .and_then(|m| m.supervisor_pipe.as_mut())
            .and_then(|p| p.peer_stream.take())
        else {
            write_test_send_log(&s.signin.send_log);
            return;
        };
        write_test_send_log(&s.signin.send_log);
        (
            peer_stream,
            tool_pipes,
            default_account,
            default_tenant,
            default_role,
            declared_cookies,
        )
    };

    envcloak_sys::pause_point("signin.after_capture");

    let mut s = locked(&shared.state);
    let now = now_of(&shared.clocks);

    if let Ok(path_override) = std::fs::read_to_string(dir.join("cookie_path_override.txt")) {
        let path_str = path_override.trim();
        let mut mutated = declared_cookies;
        if let Some(first) = mutated.first_mut()
            && let Ok(new_path) = envcloak_signin::CookiePath::new(path_str)
        {
            first.path = new_path;
        } else {
            mutated.clear();
        }
        if s.signin_verify_imported_cookies(req_id, &mutated, &now)
            .is_err()
        {
            write_test_send_log(&s.signin.send_log);
            return;
        }
    } else if s
        .signin_verify_imported_cookies(req_id, &declared_cookies, &now)
        .is_err()
    {
        write_test_send_log(&s.signin.send_log);
        return;
    }

    if s.signin_inject_over_bound_pipe(req_id, &now).is_err() {
        write_test_send_log(&s.signin.send_log);
        return;
    }
    write_test_send_log(&s.signin.send_log);

    let Ok(ToSupervisor::InjectState(inj)) = recv_from_supervisor(&peer_stream) else {
        return;
    };

    let (account, tenant, role) =
        if let Ok(override_txt) = std::fs::read_to_string(dir.join("identity_override.txt")) {
            let mut lines = override_txt.lines();
            let parse_opt = |l: Option<&str>| match l.map(str::trim) {
                Some("") | Some("<none>") | None => None,
                Some(v) => Some(v.to_owned()),
            };
            (
                parse_opt(lines.next()),
                parse_opt(lines.next()),
                parse_opt(lines.next()),
            )
        } else {
            (Some(default_account), default_tenant, Some(default_role))
        };

    let id_msg = FromSupervisor::IdentityResponse(SupervisorIdentityResponse {
        request: inj.request,
        generation: inj.generation,
        context: inj.context,
        account,
        tenant,
        role,
    });
    if send_to_supervisor(&peer_stream, &id_msg).is_err() {
        return;
    }
    let _ = s.signin_poll_supervisor_pipe(req_id, &now);
    write_test_send_log(&s.signin.send_log);

    if let Ok(ToSupervisor::Publish(pub_msg)) = recv_from_supervisor(&peer_stream)
        && pub_msg.published
    {
        let chk = FromSupervisor::Check(SupervisorCheck {
            request: pub_msg.request,
            generation: pub_msg.generation,
            context: pub_msg.context.clone(),
            tool: Some("browser_navigate".into()),
            cleaned: None,
        });
        if send_to_supervisor(&peer_stream, &chk).is_ok() {
            let _ = s.signin_poll_supervisor_pipe(req_id, &now);
        }
        if let Some((_from_client, to_client)) = tool_pipes {
            let mut f = std::fs::File::from(to_client);
            let _ = writeln!(f, "published:{}:{}", pub_msg.generation, pub_msg.context);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::items;
    use crate::signin::targets;
    use envcloak_core::crypto::KdfParams;
    use envcloak_core::vault::VaultPaths;
    use envcloak_core::{RecoveryKit, create_vault_with_kit};
    use envcloak_ipc::proto::{
        LoginAddParams, RotateParams, SigninTargetAddParams, SigninTargetEditParams,
    };
    use envcloak_ipc::view::{
        AdapterRefView, ClassificationView, CookieScopeView, IdentityCheckKindView,
        IdentityCheckView, LoginTierView, SessionFormatView,
    };
    use envcloak_signin::{CookieDomain, CookiePartition, CookiePath, Host, Label, Scheme, Site};

    struct TestEnv {
        _tmp: tempfile::TempDir,
        manifest_path: PathBuf,
        shared: Shared,
        peer: PeerIdentity,
        pass: &'static [u8],
    }

    impl TestEnv {
        fn new() -> Self {
            envcloak_sys::testing::enter_terminal_session()
                .expect("enter terminal session for daemon unit tests");
            let tmp = tempfile::tempdir().unwrap();
            let data_dir = tmp.path().join("data");
            std::fs::create_dir_all(&data_dir).unwrap();
            let paths = VaultPaths::under(data_dir);
            let pass_bytes: &'static [u8] = b"correct-horse-battery-staple-test";
            let pass = SecretBytes::copy_from(pass_bytes);
            let kit = RecoveryKit::generate();
            let v = create_vault_with_kit(&paths, &pass, &kit, KdfParams::minimum()).unwrap();
            drop(v);

            let project_dir = tmp.path().join("acme-web");
            std::fs::create_dir_all(&project_dir).unwrap();
            let manifest_path = project_dir.join("envcloak.toml");
            std::fs::write(&manifest_path, "[project]\nname = \"acme-web\"\n[env]\n").unwrap();

            use std::os::fd::AsFd;
            let shared = Shared::for_tests(paths);
            let (sock_a, _sock_b) = UnixStream::pair().unwrap();
            let peer = envcloak_sys::peer_identity(sock_a.as_fd()).unwrap();
            {
                let mut s = locked(&shared.state);
                let (locked_v, r) = match s.begin_unlock().unwrap() {
                    crate::state::BeginUnlock::Proceed(v, r) => (v, r),
                    crate::state::BeginUnlock::Already(_) => unreachable!(),
                };
                let res = locked_v.unlock_with_passphrase(&pass);
                s.finish_unlock(r, Reading::now(&shared.clocks), res)
                    .unwrap();
            }

            items::login_add(
                &shared,
                &peer,
                LoginAddParams {
                    slug: "acme/dev-bot".into(),
                    classification: ClassificationView::Test,
                    tier: LoginTierView::Dev,
                    session_lifetime_secs: 3600,
                    username: WireSecret::from(SecretBytes::copy_from(b"bot@acme.example")),
                    password: WireSecret::from(SecretBytes::copy_from(b"pw-secret-123456")),
                    totp: None,
                    adapter_key: None,
                    claims: Vec::new(),
                },
            )
            .unwrap();

            targets::add(
                &shared,
                &peer,
                SigninTargetAddParams {
                    name: "acme-console".into(),
                    manifest: Some(manifest_path.to_string_lossy().into_owned()),
                    login: "acme/dev-bot".into(),
                    app_origins: vec!["https://app.example.com".into()],
                    credential_origins: vec!["https://login.example.com".into()],
                    identity_provider_origins: Vec::new(),
                    callback_origins: vec!["https://app.example.com".into()],
                    identity_check: IdentityCheckView {
                        kind: IdentityCheckKindView::Endpoint,
                        locator: "https://app.example.com/api/me".into(),
                        account: "bot@acme.example".into(),
                        tenant: Some("acme-staging".into()),
                        role: "editor".into(),
                    },
                    cookies: vec![CookieScopeView {
                        domain: "app.example.com".into(),
                        host_only: Some(true),
                        path: "/a b".into(),
                        name: "__Host-s".into(),
                        partition_top_site: None,
                        cross_site_ancestor: false,
                    }],
                    storage: Vec::new(),
                    session_format: SessionFormatView::Cookies,
                    tier: LoginTierView::Dev,
                    adapter: Some(AdapterRefView {
                        id: "generic-web".into(),
                        version: "1".into(),
                    }),
                    approval_lifetime_secs: 900,
                    session_lifetime_secs: 900,
                    revocation: None,
                    passphrase: Some(WireSecret::from(SecretBytes::copy_from(pass_bytes))),
                    claims: Vec::new(),
                },
            )
            .unwrap();

            Self {
                _tmp: tmp,
                manifest_path,
                shared,
                peer,
                pass: pass_bytes,
            }
        }

        fn request_op(&self, key: &str) -> SigninStatusView {
            request(
                &self.shared,
                &self.peer,
                SigninRequestParams {
                    manifest: self.manifest_path.to_string_lossy().into_owned(),
                    operation_key: key.into(),
                    target: "acme-console".into(),
                    role: Some("editor".into()),
                    claims: Vec::new(),
                    fds: Vec::new(),
                },
                Vec::new(),
            )
            .unwrap()
        }

        fn approve_op(&self, req_id: &str, dev: Option<SignInDevOptions>) -> ApprovedView {
            let PendingGetOutput::SignIn(desc) = pending_get(
                &self.shared,
                &self.peer,
                PendingGetParams {
                    request: req_id.into(),
                    claims: Vec::new(),
                },
            )
            .unwrap() else {
                panic!("expected SignIn descriptor");
            };
            let opts = match dev {
                None => Options::Once,
                Some(d) => d.to_options(),
            };
            let stmt = desc.to_statement(opts).unwrap();
            let digest_hex: String = stmt.digest().iter().map(|b| format!("{b:02x}")).collect();
            approve(
                &self.shared,
                &self.peer,
                ApproveParams {
                    request: req_id.into(),
                    options: envcloak_policy::ApprovalOptions {
                        uses: Uses::Once,
                        ttl_secs: 0,
                        standing: None,
                        live: Vec::new(),
                    },
                    dev,
                    digest: digest_hex,
                    passphrase: Some(WireSecret::from(SecretBytes::copy_from(self.pass))),
                    claims: Vec::new(),
                },
            )
            .unwrap()
        }
    }

    /// Pinned-snapshot negative-control `World` for `Codex cycle341`: returns
    /// the snapshot recorded when the operation was created instead of reading
    /// live sources on every call.
    struct PinnedSnapshotWorld {
        epochs: Epochs,
        pinned: Current,
    }

    impl World for PinnedSnapshotWorld {
        fn epochs(&self) -> Epochs {
            self.epochs
        }
        fn alive(&self, _instance: &Instance) -> bool {
            true
        }
        fn current(&self, _scope: &SignInScope) -> Current {
            self.pinned.clone()
        }
    }

    #[test]
    fn cycle341_live_world_current_vs_pinned_snapshot_negative_control() {
        let env = TestEnv::new();
        let req = env.request_op("op-cycle341-1");
        let req_id = RequestId::parse(&req.request).unwrap();
        let scope = {
            let s = locked(&env.shared.state);
            s.signin.ops.get(&req_id).unwrap().scope.clone()
        };

        // Snapshot at creation time for the negative control.
        let (initial_epochs, pinned_snapshot) = {
            let s = locked(&env.shared.state);
            let vault = slot_unlocked(&s.slot);
            let live = LiveDaemonWorld {
                daemon: s.signin.daemon_instance,
                vault,
                catalog: Some(&env.shared.catalog),
                browser_generation: s.signin.browser_generation,
                ops: &s.signin.ops,
                auths: &s.signin.auths,
                overrides: &s.signin.world_overrides,
            };
            (live.epochs(), live.current(&scope))
        };
        let neg_world = PinnedSnapshotWorld {
            epochs: initial_epochs,
            pinned: pinned_snapshot,
        };

        // 1. Mutate .envcloak.toml on disk: LiveDaemonWorld sees the project
        //    config digest change; PinnedSnapshotWorld does not.
        std::fs::write(
            &env.manifest_path,
            "[project]\nname = \"acme-web\"\n[env]\nEXTRA = \"openai/acme-web\"\n",
        )
        .unwrap();
        {
            let mut s = locked(&env.shared.state);
            let now = now_of(&env.shared.clocks);
            let (ended, _) = s.signin_reconcile_at(&now, Some(&env.shared.catalog));
            assert_eq!(ended, 1, "live world must end op on project change");
            assert_eq!(
                s.signin
                    .store
                    .operation(&req_id)
                    .unwrap()
                    .stop()
                    .unwrap()
                    .reason,
                StopReason::ProjectChanged
            );
            assert_eq!(
                neg_world.current(&scope).project.as_ref(),
                Some(scope.project()),
                "negative control: pinned snapshot fails to see project change"
            );
        }

        // 2. Rotate login item in the vault: LiveDaemonWorld sees LoginNow
        //    revision bump; PinnedSnapshotWorld does not.
        let req2 = env.request_op("op-cycle341-2");
        let req2_id = RequestId::parse(&req2.request).unwrap();
        let _ = env.approve_op(
            &req2.request,
            Some(SignInDevOptions {
                window_secs: 600,
                attempts: 3,
            }),
        );
        let item_id = items::target_view(
            &env.shared,
            &env.peer,
            envcloak_ipc::proto::TargetParams {
                slug: "acme/dev-bot".into(),
                field: Some("password".into()),
                claims: Vec::new(),
            },
        )
        .unwrap()
        .item
        .id;
        items::rotate(
            &env.shared,
            &env.peer,
            RotateParams {
                slug: "acme/dev-bot".into(),
                field: Some("password".into()),
                item: item_id,
                value: WireSecret::from(SecretBytes::copy_from(b"new-pw-secret-789")),
                passphrase: WireSecret::from(SecretBytes::copy_from(env.pass)),
                claims: Vec::new(),
            },
        )
        .unwrap();
        {
            let s = locked(&env.shared.state);
            assert_eq!(
                s.signin
                    .store
                    .operation(&req2_id)
                    .unwrap()
                    .stop()
                    .unwrap()
                    .reason,
                StopReason::RevisionChanged
            );
            assert_eq!(
                neg_world.current(&scope).login.unwrap().revision,
                scope.account().authorization_revision,
                "negative control: pinned snapshot fails to see login revision change"
            );
        }

        // 3. Edit target in the vault: LiveDaemonWorld sees TargetNow revision
        //    bump and limits change; PinnedSnapshotWorld does not.
        let req3 = env.request_op("op-cycle341-3");
        let req3_id = RequestId::parse(&req3.request).unwrap();
        targets::edit(
            &env.shared,
            &env.peer,
            SigninTargetEditParams {
                name: "acme-console".into(),
                role: Some("editor".into()),
                manifest: Some(env.manifest_path.to_string_lossy().into_owned()),
                login: None,
                app_origins: None,
                credential_origins: None,
                identity_provider_origins: None,
                callback_origins: None,
                identity_check: None,
                cookies: None,
                storage: None,
                session_format: None,
                tier: None,
                adapter: None,
                approval_lifetime_secs: Some(600),
                session_lifetime_secs: None,
                revocation: None,
                passphrase: Some(WireSecret::from(SecretBytes::copy_from(env.pass))),
                claims: Vec::new(),
            },
        )
        .unwrap();
        {
            let s = locked(&env.shared.state);
            assert_eq!(
                s.signin
                    .store
                    .operation(&req3_id)
                    .unwrap()
                    .stop()
                    .unwrap()
                    .reason,
                StopReason::RevisionChanged
            );
            assert_eq!(
                neg_world.current(&scope).target.unwrap().revision,
                scope.target().revision,
                "negative control: pinned snapshot fails to see target revision change"
            );
        }

        // 4. Requester coverage (`covered_by`) failure and browser generation bump.
        let req4 = env.request_op("op-cycle341-4");
        let req4_id = RequestId::parse(&req4.request).unwrap();
        {
            let mut s = locked(&env.shared.state);
            s.signin.world_overrides_mut().requester = Some(Requester::Uncovered);
            let now = now_of(&env.shared.clocks);
            s.signin_reconcile_at(&now, Some(&env.shared.catalog));
            assert_eq!(
                s.signin
                    .store
                    .operation(&req4_id)
                    .unwrap()
                    .stop()
                    .unwrap()
                    .reason,
                StopReason::SubjectIneligible
            );
            s.signin.world_overrides_mut().requester = None;
        }
        let req5 = env.request_op("op-cycle341-5");
        let req5_id = RequestId::parse(&req5.request).unwrap();
        {
            let mut s = locked(&env.shared.state);
            s.signin.bump_browser_generation();
            let now = now_of(&env.shared.clocks);
            s.signin_reconcile_at(&now, Some(&env.shared.catalog));
            assert_eq!(
                s.signin
                    .store
                    .operation(&req5_id)
                    .unwrap()
                    .stop()
                    .unwrap()
                    .reason,
                StopReason::RecipientReplaced
            );
        }
    }

    #[test]
    fn cycle339_pipe_origin_binding_rejects_message_id_spoofing() {
        let env = TestEnv::new();
        let req_a = env.request_op("op-cycle339-a");
        let req_b = env.request_op("op-cycle339-b");
        let id_a = RequestId::parse(&req_a.request).unwrap();
        let id_b = RequestId::parse(&req_b.request).unwrap();

        let _ = env.approve_op(&req_a.request, None);
        let _ = env.approve_op(&req_b.request, None);

        let mut s = locked(&env.shared.state);
        let now = now_of(&env.shared.clocks);
        let worker_a = s.signin.ops.get(&id_a).unwrap().active_worker.unwrap();
        s.signin_worker_captured(id_a, worker_a, CapturedBrowserState::default(), &now)
            .unwrap();
        // Now that A is Captured, B's attempt is ready and starts on reconcile.
        s.signin_reconcile_at(&now, Some(&env.shared.catalog));
        let worker_b = s.signin.ops.get(&id_b).unwrap().active_worker.unwrap();
        s.signin_worker_captured(id_b, worker_b, CapturedBrowserState::default(), &now)
            .unwrap();
        let gen_b = s
            .signin
            .ops
            .get(&id_b)
            .unwrap()
            .supervisor_pipe
            .as_ref()
            .unwrap()
            .supervisor
            .generation()
            .get();
        let ctx_b = s
            .signin
            .store
            .operation(&id_b)
            .unwrap()
            .context()
            .get()
            .to_string();

        s.signin_inject_over_bound_pipe(id_a, &now).unwrap();
        s.signin_inject_over_bound_pipe(id_b, &now).unwrap();

        // Spoof: supervisor A sends an IdentityResponse and Check on A's bound
        // pipe naming B's request id, generation, and context.
        let spoof_identity = FromSupervisor::IdentityResponse(SupervisorIdentityResponse {
            request: id_b.to_string(),
            generation: gen_b,
            context: ctx_b.clone(),
            account: Some("bot@acme.example".into()),
            tenant: Some("acme-staging".into()),
            role: Some("editor".into()),
        });
        let err = s
            .signin_handle_supervisor_pipe_msg(id_a, spoof_identity, &now)
            .unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidParams);
        assert_eq!(
            s.signin.store.operation(&id_b).unwrap().phase(),
            Phase::Captured,
            "op_b must remain untouched in Captured when op_a's pipe spoofs op_b"
        );

        let spoof_check = FromSupervisor::Check(SupervisorCheck {
            request: id_b.to_string(),
            generation: gen_b,
            context: ctx_b,
            tool: Some("browser_navigate".into()),
            cleaned: None,
        });
        let err_chk = s
            .signin_handle_supervisor_pipe_msg(id_a, spoof_check, &now)
            .unwrap_err();
        assert_eq!(err_chk.kind, ErrorKind::InvalidParams);
    }

    #[test]
    fn cycle342_verify_imported_cookies_five_acceptance_rows() {
        let env = TestEnv::new();
        let host = Host::parse("app.example.com").unwrap();
        let exact_cookie = DeclaredCookie {
            domain: CookieDomain::HostOnly(host.clone()),
            path: CookiePath::new("/a b").unwrap(),
            name: Label::new("__Host-s").unwrap(),
            partition: CookiePartition::Unpartitioned,
        };

        // Row 1: exact match of declared cookies succeeds.
        {
            let req = env.request_op("op-cycle342-row1");
            let id = RequestId::parse(&req.request).unwrap();
            let _ = env.approve_op(&req.request, None);
            let mut s = locked(&env.shared.state);
            let now = now_of(&env.shared.clocks);
            let w = s.signin.ops.get(&id).unwrap().active_worker.unwrap();
            s.signin_worker_captured(id, w, CapturedBrowserState::default(), &now)
                .unwrap();
            s.signin_verify_imported_cookies(id, std::slice::from_ref(&exact_cookie), &now)
                .unwrap();
            assert_eq!(
                s.signin.store.operation(&id).unwrap().phase(),
                Phase::Captured
            );
        }

        // Rows 2..=5: each cookie mutation on import is refused before
        // publication and fails the attempt with UnsupportedSessionScope.
        let mutated_rows: Vec<(&str, Vec<DeclaredCookie>)> = vec![
            (
                "row2-path-percent-encoded",
                vec![DeclaredCookie {
                    path: CookiePath::new("/a%20b").unwrap(),
                    ..exact_cookie.clone()
                }],
            ),
            (
                "row3-host-only-to-domain",
                vec![DeclaredCookie {
                    domain: CookieDomain::Domain(
                        envcloak_signin::HostName::new("app.example.com").unwrap(),
                    ),
                    ..exact_cookie.clone()
                }],
            ),
            (
                "row4-unpartitioned-to-partitioned",
                vec![DeclaredCookie {
                    partition: CookiePartition::Partitioned {
                        site: Site {
                            scheme: Scheme::Https,
                            host: host.clone(),
                        },
                        cross_site_ancestor: false,
                    },
                    ..exact_cookie.clone()
                }],
            ),
            (
                "row5-extra-or-missing-cookie",
                vec![
                    exact_cookie.clone(),
                    DeclaredCookie {
                        name: Label::new("extra_cookie").unwrap(),
                        ..exact_cookie
                    },
                ],
            ),
        ];

        for (label, stored) in mutated_rows {
            let req = env.request_op(&format!("op-cycle342-{label}"));
            let id = RequestId::parse(&req.request).unwrap();
            let _ = env.approve_op(&req.request, None);
            let mut s = locked(&env.shared.state);
            let now = now_of(&env.shared.clocks);
            let w = s.signin.ops.get(&id).unwrap().active_worker.unwrap();
            s.signin_worker_captured(id, w, CapturedBrowserState::default(), &now)
                .unwrap();
            let err = s
                .signin_verify_imported_cookies(id, &stored, &now)
                .unwrap_err();
            assert_eq!(err.kind, ErrorKind::InvalidParams, "{label}");
            let stop = s.signin.store.operation(&id).unwrap().stop().expect(label);
            assert!(!stop.delivered, "{label}");
            assert_eq!(
                stop.reason,
                StopReason::AttemptFailed(AttemptFailure::UnsupportedSessionScope),
                "{label}"
            );
        }
    }

    #[test]
    fn exhausted_authorizations_pruned_so_256_cap_never_blocks_new_approvals() {
        let env = TestEnv::new();
        let caller = evidence(&env.shared, &env.peer, &[]).unwrap();
        for i in 0..260 {
            let req = env.request_op(&format!("op-cap-prune-{i}"));
            let req_id = RequestId::parse(&req.request).unwrap();
            if i == 0 {
                let _ = env.approve_op(&req.request, None);
            } else {
                let mut s = locked(&env.shared.state);
                let now = now_of(&env.shared.clocks);
                let desc =
                    build_pending_descriptor(&mut s, req_id, Some(Options::Once), &now, None)
                        .unwrap();
                let digest = desc.to_statement(Options::Once).unwrap().digest();
                finish_signin_approve(
                    &mut s,
                    &env.shared,
                    &env.peer,
                    &caller,
                    req_id,
                    Options::Once,
                    &digest,
                    &now,
                )
                .unwrap();
            }
            let worker = locked(&env.shared.state)
                .signin
                .ops
                .get(&req_id)
                .unwrap()
                .active_worker
                .unwrap();
            cancel(
                &env.shared,
                &env.peer,
                SigninOperationParams {
                    request: req.request,
                },
            )
            .unwrap();
            let mut s = locked(&env.shared.state);
            let now = now_of(&env.shared.clocks);
            let later = Now {
                awake: now.awake + envcloak_signin::RETRY_WINDOW + Duration::from_secs(1),
                including_sleep: now.including_sleep
                    + envcloak_signin::RETRY_WINDOW
                    + Duration::from_secs(1),
                wall: now.wall + envcloak_signin::RETRY_WINDOW + Duration::from_secs(1),
            };
            let eff = {
                let s_ref: &mut State = &mut s;
                let vault = slot_unlocked(&s_ref.slot);
                let world = LiveDaemonWorld {
                    daemon: s_ref.signin.daemon_instance,
                    vault,
                    catalog: Some(&env.shared.catalog),
                    browser_generation: s_ref.signin.browser_generation,
                    ops: &s_ref.signin.ops,
                    auths: &s_ref.signin.auths,
                    overrides: &s_ref.signin.world_overrides,
                };
                s_ref
                    .signin
                    .store
                    .cleanup_result(&req_id, &worker, true, &later, &world)
                    .unwrap();
                s_ref.signin.store.drain_effects()
            };
            s.execute_signin_effects(eff, &later, Some(&env.shared.catalog));
            s.signin_sweep(&later);
            assert_eq!(
                s.signin.store.authorizations().count(),
                0,
                "exhausted Once authorizations must be pruned on sweep (iter {i})"
            );
        }
    }

    #[test]
    fn send_log_records_captured_state_only_on_supervisor_control_pipe() {
        let env = TestEnv::new();
        let req = env.request_op("op-send-log-1");
        let id = RequestId::parse(&req.request).unwrap();
        let _ = env.approve_op(&req.request, None);

        {
            let mut s = locked(&env.shared.state);
            let now = now_of(&env.shared.clocks);
            let w = s.signin.ops.get(&id).unwrap().active_worker.unwrap();
            s.signin_worker_captured(id, w, CapturedBrowserState::default(), &now)
                .unwrap();
            let peer_stream = s
                .signin
                .ops
                .get_mut(&id)
                .unwrap()
                .supervisor_pipe
                .as_mut()
                .unwrap()
                .peer_stream
                .take()
                .unwrap();
            s.signin_inject_over_bound_pipe(id, &now).unwrap();

            let ToSupervisor::InjectState(inj) = recv_from_supervisor(&peer_stream).unwrap() else {
                panic!("expected InjectState on supervisor control pipe");
            };
            send_to_supervisor(
                &peer_stream,
                &FromSupervisor::IdentityResponse(SupervisorIdentityResponse {
                    request: inj.request,
                    generation: inj.generation,
                    context: inj.context,
                    account: Some("bot@acme.example".into()),
                    tenant: Some("acme-staging".into()),
                    role: Some("editor".into()),
                }),
            )
            .unwrap();
            assert!(s.signin_poll_supervisor_pipe(id, &now).unwrap());
        }

        let st = status(
            &env.shared,
            &env.peer,
            SigninOperationParams {
                request: req.request.clone(),
            },
        )
        .unwrap();
        assert_eq!(st.state, "published");

        let s = locked(&env.shared.state);
        let records: Vec<&SendRecord> = s
            .signin
            .send_log()
            .iter()
            .filter(|r| r.request == id)
            .collect();
        assert!(
            records.iter().any(|r| {
                matches!(
                    r.destination,
                    SendDestination::SupervisorControlPipe { generation: 1 }
                ) && r.contains_captured_state
            }),
            "send_log must record captured state on SupervisorControlPipe"
        );
        for rec in &records {
            if matches!(rec.destination, SendDestination::IpcReply { .. }) {
                assert!(
                    !rec.contains_captured_state,
                    "IPC reply must never carry captured state: {rec:?}"
                );
            }
        }
    }
}
