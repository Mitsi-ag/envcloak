//! The grant methods (SPEC §6.1 steps 2 to 4, §10a, §10b): `run.request`,
//! `pending.get`, `pending.state`, `pending.list`, `approve`, `deny`,
//! `grants.list` and `grants.revoke`.
//!
//! `run.request` decides, and a covered request is a delivery: its answer
//! carries the bindings' values. For every request the daemon:
//! 1. reads the caller's evidence from the kernel ([`gather`]), with the
//!    marker names the caller claims;
//! 2. opens the manifest itself, from the path the caller sent, and
//!    resolves the bindings from the file it read, the profile, the
//!    `--ref` arguments and the `--env-file` references and names the CLI
//!    sent ([`load_project`], [`resolve`]); the caller's argv is display
//!    text only;
//! 3. binds them to the vault's items ([`bind_items`]), and looks up
//!    whether the project and the items are new to the vault (SPEC §6.4
//!    "Adoption"). This is where a reference to a card or an issuer
//!    credential is rejected (`manifest_invalid`, gate 17), and the only
//!    source of the item ids a request releases;
//! 4. applies the effective policy (the vault's, tightened by the
//!    manifest's, for the subject's kind), which can refuse agent requests
//!    or require proxy mode (refused: M1 has none);
//! 5. asks the grant store ([`GrantStore::decide`]) and, for a `once`
//!    grant, consumes it under the same lock;
//! 6. records the decision in the audit log, with the command line masked
//!    for the request's values and the registry's key patterns
//!    ([`crate::redact`]). A covered request is a delivery
//!    ([`crate::state::State::deliver`]): under a tracer nothing is read;
//!    otherwise the values are read from the verified vault, the answer
//!    is framed as it will be sent, the entry is written and flushed, and
//!    only then does the answer go out. When a value cannot be read (the
//!    vault changed on disk and turns tampered) nothing is released; when
//!    the entry cannot be written the request is denied (`audit_failed`),
//!    the answer is dropped, and a `once` grant is left unused (SPEC §6.1
//!    step 5, gate 33). An answer too large for one frame is known before
//!    anything is committed (F-77): it is `frame_too_large`, audited as
//!    that, with nothing released and the grant left as it was, so a
//!    `once` grant still covers a smaller request. The values are read
//!    and the answer framed after the decision, so once the answer is
//!    built the grant is asked again on clocks read then: one that ran
//!    out meanwhile (by the wall clock or by time awake) commits nothing,
//!    and the request is decided again on fresh clocks, as one arriving
//!    then would be.
//!
//! `approve` takes the passphrase as the proof. Before Argon2id runs, the
//! approver must be a terminal subject with no agent by any evidence
//! (SPEC §10b: proofs from every other caller are refused), sharing no
//! session or terminal with an agent's or unknown requester's chain up to
//! its root or its nearest agent (`requester_terminal`; `pending.get` is
//! refused so too), the pending request must exist, the statement
//! digest must be its own with the options sent, built from the vault as
//! it is now (each binding's classification and the test items proposed
//! for live ones, L-09), the live-key guard must hold (an agent's or an
//! unknown subject's live bindings each ticked, or `live_not_ticked`,
//! audited with the items left unticked), and the attempt limiter must
//! admit the attempt. An `approve` sent without a passphrase is a check
//! (`envcloak approve` sends one where the guard refuses, so the refusal
//! is this daemon's, and audited): it runs every check above but the
//! limiter's and ends there, `invalid_params` when none refused, with no
//! attempt counted and nothing granted. Argon2id then runs outside the state lock, with the
//! vault taken out as an unlock takes it, one proof at a time; the store
//! checks all of it again against the vault after.
//!
//! A pending `run.request` answer carries the same provider's test items
//! proposed for its live bindings (`envcloak_policy::proposals`), which
//! `envcloak run`'s `approval_required` line names, read from the pending
//! request its id names, as `pending.get` reads them for the statement: a
//! request asked again through other layers is pending on its own, so the
//! answer and the statement advise the same edit. `pending.get` builds the
//! descriptor's classifications and proposals from the vault each time it
//! is asked.
//!
//! No grant is evaluated, and no proof taken, from a vault whose
//! integrity check failed ([`crate::state::State::unlocked`]).
//!
//! A request over a pending cap is answered `too_many_pending` with the
//! cap as its reason, and audited so: nothing was opened or refused, and a
//! waiter asks again later (M2 plan D-04). The first such answer to a
//! request is written at once, and the ones after it are counted and
//! written once a minute ([`crate::crowded`]), so waiting does not grow
//! the log.
//!
//! `pending.state` and `pending.list` are for waiting and finding a
//! request (M2 plan D-04). `pending.state` reads the caller's evidence
//! from the kernel and answers how a request stands only to the
//! request's own process tree (`unknown` to anyone else), within the
//! caller's root's poll limit (`busy` beyond it); it opens nothing and
//! writes no audit entry. `pending.list` lists the requests the caller
//! may approve: none to a caller whose proof would be refused, and for
//! one that may give a proof, none whose requester's session or terminal
//! it shares. Neither is activity: polling never keeps the vault open.

use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use envcloak_core::SecretBytes;
use envcloak_core::audit::{ProjectSummary, SubjectSummary};
use envcloak_core::crypto::CryptoErrorKind;
use envcloak_core::vault::{FieldId, ItemId, ItemMeta, Slug, Vault, VaultErrorKind};
use envcloak_ipc::control::{ExecSpec, LaunchSpec, Recipient, Release, ToRunner};
use envcloak_ipc::proto::{
    ApproveParams, EnvFileParams, ErrorKind, PendingGetParams, PendingListParams,
    PendingStateParams, ReleasedValue, RequestParams, RevokeParams, RunAnswer, RunRequest,
    RunRequestParams,
};
use envcloak_ipc::view::{
    ApprovedView, DecisionView, DeniedView, GrantBindingView, GrantView, GrantsView,
    MAX_LISTED_BINDINGS, PendingListView, PendingStateView, PendingView, RevokedView,
};
use envcloak_ipc::{Frame, RpcError, WireSecret};
use envcloak_policy::{
    AccessRequest, ApprovalOptions, ApprovalProof, ApproveError, BindError, BindErrorKind, Binding,
    BindingSource, BoundRef, Claims, Decision, DenyReason, EvidenceError, GrantId, ManifestError,
    Mode, Now, PENDING_TTL, Pending, PendingDescriptor, PendingId, PendingState, ProcessInstance,
    ProfileName, ProofKind, RevokeSelector, SubjectEvidence, SubjectKind, Uses, VaultProjectPolicy,
    bind_items, effective_policy, gather_hashed, load_project, resolve_sourced,
};
use envcloak_sys::PeerIdentity;

use crate::audit::{AuditEvent, RequestAudit};
use crate::clock::now_of;
use crate::launch_check::CheckedExec;
use crate::lock::Reading;
use crate::managed::{self, Checked};
use crate::server::{Shared, locked, refuse_if_traced, result_framed};
use crate::spawn_envcloak::{self, ClientEnds, Role};
use crate::state::{Delivery, vault_reason};

/// How many times one `run.request` is decided at most: a second decision
/// follows only a grant that ran out while its answer was prepared, and
/// that grant is expired on the clocks the next decision reads, unless
/// the wall clock was set back meanwhile. A request decided this often
/// is answered `internal`, with nothing committed.
const MAX_DECISIONS: u32 = 4;

/// Refuses a proof, or the statement a proof would approve, from a caller
/// that may not give one (SPEC §10b): an agent by any evidence, or no
/// terminal session ([`SubjectEvidence::proof_refusal`]). Audited with
/// the reason.
pub(crate) fn refuse_unless_prover(
    shared: &Shared,
    peer: &PeerIdentity,
    evidence: &SubjectEvidence,
    method: &'static str,
) -> Result<(), RpcError> {
    match evidence.proof_refusal() {
        None => Ok(()),
        Some(r) => {
            shared.audit(AuditEvent::ProofRefused {
                pid: peer.pid,
                method,
                reason: r.token(),
            });
            Err(RpcError::new(ErrorKind::ProofRefused))
        }
    }
}

/// Refuses `approver` for pending request `id` when it shares a session
/// or a terminal with the requester's chain up to its root or its nearest
/// agent, for a requester that is not a terminal subject
/// ([`SubjectEvidence::approval_refusal`]): approval input is never read
/// from the requester's terminal (gate 23). Audited with the reason
/// `requester_terminal`. Nothing is refused for a request that does not
/// exist: the caller's next check says so.
fn refuse_requester_terminal(
    s: &mut crate::state::State,
    peer: &PeerIdentity,
    approver: &SubjectEvidence,
    id: &PendingId,
    now: &envcloak_policy::Now,
    method: &'static str,
) -> Result<(), RpcError> {
    let refusal = s
        .grants()
        .pending(id, now)
        .and_then(|p| approver.approval_refusal(&p.request.subject, &alive));
    match refusal {
        None => Ok(()),
        Some(r) => {
            s.audit(AuditEvent::ProofRefused {
                pid: peer.pid,
                method,
                reason: r.token(),
            });
            Err(RpcError::with_reason(ErrorKind::ProofRefused, r.token()))
        }
    }
}

/// Reads the caller's evidence, its ancestors' executables hashed on
/// Linux (`crate::exe_hash`): the one place a request's evidence is read,
/// `unlock`'s included. Called before the state lock is taken, so hashing
/// never holds it.
pub(crate) fn evidence(
    shared: &Shared,
    peer: &PeerIdentity,
    claims: &[String],
) -> Result<SubjectEvidence, RpcError> {
    let claims =
        Claims::from_markers(claims).map_err(|_| RpcError::new(ErrorKind::InvalidParams))?;
    let mut hasher = crate::exe_hash::RequestHasher::new(&shared.exe_hashes);
    gather_hashed(peer, claims, &shared.catalog, &mut hasher)
        .map_err(|e: EvidenceError| RpcError::with_reason(ErrorKind::Evidence, e.token()))
}

/// A manifest or resolution error as the protocol reports it.
pub(crate) fn manifest_error(e: ManifestError) -> RpcError {
    let kind = if e.token() == "binding_unresolved" {
        ErrorKind::BindingUnresolved
    } else {
        ErrorKind::ManifestInvalid
    };
    RpcError::with_reason(kind, e.kind().token())
}

fn bind_error(e: &BindError) -> RpcError {
    match e.kind() {
        // Its own kind, with no reason: a login's field is refused as such
        // (SPEC §6.8), never taken for a manifest error or a missing item.
        BindErrorKind::LoginReference => RpcError::new(ErrorKind::LoginReference),
        k if e.token() == "binding_unresolved" => {
            RpcError::with_reason(ErrorKind::BindingUnresolved, k.token())
        }
        k => RpcError::with_reason(ErrorKind::ManifestInvalid, k.token()),
    }
}

fn approve_error(e: ApproveError) -> RpcError {
    match e {
        ApproveError::NoSuchRequest => RpcError::new(ErrorKind::NoSuchRequest),
        ApproveError::StatementMismatch => RpcError::new(ErrorKind::StatementMismatch),
        ApproveError::ProofRefused => RpcError::new(ErrorKind::ProofRefused),
        ApproveError::InvalidOptions(o) => {
            RpcError::with_reason(ErrorKind::InvalidOptions, o.token())
        }
        ApproveError::LiveNotTicked => RpcError::new(ErrorKind::LiveNotTicked),
        ApproveError::TooManyGrants => RpcError::new(ErrorKind::TooManyGrants),
    }
}

/// The bindings a run asks for, each with the layer that set it, bound to
/// the vault's items and carrying what the approval shows, plus whether
/// the project is new to the vault.
fn bind_request(
    vault: &Vault,
    sourced: &[(Binding, BindingSource)],
    project_key: &envcloak_core::vault::ProjectKey,
) -> Result<(Vec<BoundRef>, bool), RpcError> {
    let bindings: Vec<Binding> = sourced.iter().map(|(b, _)| b.clone()).collect();
    let bound = bind_items(&bindings, vault.items()).map_err(|e| bind_error(&e))?;
    // `bind_items` answers in the order it was given, one for each.
    if bound.len() != sourced.len() {
        return Err(RpcError::new(ErrorKind::Internal));
    }
    // No grant is evaluated from a vault that failed its integrity check:
    // its project index cannot be trusted either.
    let tampered = |_| RpcError::new(ErrorKind::VaultTampered);
    let new_project = vault.find_project(project_key).map_err(tampered)?.is_none();
    // An item is in first use when no adopted project's bindings name its
    // slug (SPEC §6.4 "Adoption").
    let used: Vec<String> = vault
        .projects()
        .map_err(tampered)?
        .flat_map(|(_, r)| r.bindings.iter().map(|b| b.reference.clone()))
        .collect();
    let refs = bound
        .into_iter()
        .zip(sourced.iter().map(|(_, layer)| layer.clone()))
        .map(|(b, source)| {
            let item = vault
                .item(b.item)
                .ok_or(RpcError::new(ErrorKind::Internal))?;
            let field = item
                .fields
                .iter()
                .find(|f| f.id == b.field)
                .ok_or(RpcError::new(ErrorKind::Internal))?;
            let slug = item.slug.as_str();
            let first_use = !used.iter().any(|r| {
                r == slug
                    || r.strip_prefix(slug)
                        .is_some_and(|rest| rest.starts_with('#'))
            });
            Ok(BoundRef {
                slug: item.slug.clone(),
                field_name: field.name.clone(),
                first_use,
                binding: b,
                source,
            })
        })
        .collect::<Result<Vec<_>, RpcError>>()?;
    Ok((refs, new_project))
}

/// Who asked, as the audit log records it.
pub(crate) fn subject_summary(peer: &PeerIdentity, e: &SubjectEvidence) -> SubjectSummary {
    let root = e.root();
    SubjectSummary {
        pid: peer.pid,
        uid: None,
        kind: Some(
            match e.kind() {
                SubjectKind::Agent => "agent",
                SubjectKind::Terminal => "terminal",
                SubjectKind::Unknown => "unknown",
            }
            .to_owned(),
        ),
        agent: e.label().map(|l| l.name.clone()),
        root_pid: Some(root.pid),
        root_exe: root
            .exe
            .as_ref()
            .map(|x| x.path.to_string_lossy().into_owned()),
    }
}

/// The request's command line as its audit entry keeps it: masked for
/// the values it binds and for key patterns. When a value cannot be read
/// to mask it, nothing of the command line is kept.
fn masked_argv(shared: &Shared, vault: &Vault, bound: &[BoundRef], argv: &[String]) -> Vec<String> {
    let mut values: Vec<(String, SecretBytes)> = Vec::with_capacity(bound.len());
    for b in bound {
        match vault.read_value(b.binding.field) {
            Ok(v) => values.push((b.slug.as_str().to_owned(), v)),
            Err(_) => {
                return vec![
                    "[envcloak: command line not kept: a value to mask it with could not be read]"
                        .to_owned(),
                ];
            }
        }
    }
    crate::redact::redact_argv(argv, &values, shared.registry.as_ref())
}

/// What a covered request releases, in the order of its bindings: each
/// field to read, and the variable, slug and `allow_short` its value goes
/// out with.
type ReleasePlan = (Vec<FieldId>, Vec<(String, String, bool)>);

fn release_plan(vault: &Vault, bound: &[BoundRef]) -> Result<ReleasePlan, RpcError> {
    let mut fields = Vec::with_capacity(bound.len());
    let mut meta = Vec::with_capacity(bound.len());
    for b in bound {
        let item = vault
            .item(b.binding.item)
            .ok_or(RpcError::new(ErrorKind::Internal))?;
        fields.push(b.binding.field);
        meta.push((
            b.binding.env_name.as_str().to_owned(),
            b.slug.as_str().to_owned(),
            item.details.allow_short,
        ));
    }
    Ok((fields, meta))
}

/// `run.request`, answering request `id` with its result frame, built
/// here so that a covered answer is framed before it is committed. See
/// the module documentation.
pub fn run_request(
    shared: &Shared,
    peer: &PeerIdentity,
    id: u64,
    p: RunRequestParams,
    fds: Vec<OwnedFd>,
) -> Result<Frame, RpcError> {
    let subject = evidence(shared, peer, &p.claims)?;
    let profile = p
        .profile
        .as_deref()
        .map(ProfileName::new)
        .transpose()
        .map_err(manifest_error)?;
    let refs = p
        .refs
        .iter()
        .map(|r| Binding::parse_arg(r))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| RpcError::with_reason(ErrorKind::BindingUnresolved, "invalid_reference"))?;
    // `--env-file`'s references and the names of its ordinary variables,
    // checked as `--ref` is; its values never cross.
    let env_file = p
        .env_file
        .as_ref()
        .map(EnvFileParams::names)
        .transpose()
        .map_err(|_| RpcError::with_reason(ErrorKind::BindingUnresolved, "invalid_reference"))?;
    // A managed launch's request may name only its launch: the record
    // names the project (`envcloak mcp-bridge --stdio --launch <id>`).
    let manifest_path = match (&p.launch, p.manifest.is_empty()) {
        (Some(launch), true) => launch_manifest(shared, peer, &subject, launch)?,
        _ => PathBuf::from(&p.manifest),
    };
    if !manifest_path.is_absolute() {
        return Err(RpcError::with_reason(
            ErrorKind::ManifestInvalid,
            "invalid_path",
        ));
    }
    // The daemon opens the manifest itself; nothing the caller sent about
    // its contents is used.
    let project = load_project(&manifest_path).map_err(manifest_error)?;
    let bindings = resolve_sourced(
        &project.manifest,
        profile.as_ref(),
        &refs,
        env_file.as_ref(),
    )
    .map_err(manifest_error)?;
    let kind = subject.kind();
    let policy = effective_policy(
        &VaultProjectPolicy::default(),
        &project.manifest.policy,
        kind,
    );
    if policy.deny {
        shared.audit(AuditEvent::Request(Box::new(RequestAudit {
            pid: peer.pid,
            decision: "policy_denied",
            request_id: None,
            grant_id: None,
            reason: None,
            subject: subject_summary(peer, &subject),
            project: Some(ProjectSummary {
                dir: project
                    .identity
                    .canonical_dir
                    .to_string_lossy()
                    .into_owned(),
                manifest_sha256: project.manifest.sha256,
                approved_sha256: None,
            }),
            items: Vec::new(),
            argv: Vec::new(),
            count: None,
        })));
        return Err(RpcError::new(ErrorKind::PolicyDenied));
    }
    if policy.mode == Mode::Proxy {
        return Err(RpcError::new(ErrorKind::ModeUnsupported));
    }
    // A managed project (SPEC §6.6, task M2-27): its record, found by the
    // project's identity however the manifest was found, and the checks
    // of its launch or bridge, all before any grant is consulted or any
    // pending request exists (`crate::managed`).
    let mut record = {
        let s = locked(&shared.state);
        managed::by_project(s.unlocked()?, &project.identity)?.map(|(_, r)| r)
    };
    // A managed project's request without a well-formed set of ends (none,
    // too few, of the wrong kind or the wrong access) has no ends: it is
    // refused `managed_command_mismatch` below, audited, as any request
    // that is not its registered launch's or bridge's. The descriptors
    // that came are closed.
    let ends = match &record {
        Some(r) if !fds.is_empty() => ClientEnds::from_request(
            fds,
            &p.fds,
            matches!(
                r.transport,
                envcloak_core::vault::ManagedTransport::Stdio(_)
            ),
        )
        .ok(),
        Some(_) => None,
        // No record: a request that names a launch or a bridge is refused
        // `managed_command_mismatch` below, descriptors or not; any other
        // takes none.
        None if (fds.is_empty() && p.fds.is_empty())
            || p.launch.is_some()
            || p.bridge.is_some() =>
        {
            None
        }
        None => {
            return Err(RpcError::new(ErrorKind::InvalidParams));
        }
    };
    // The check runs without the state lock, so a registration, an update
    // or a removal can commit meanwhile. The decision is taken only on the
    // record the check passed: under the lock the decision holds, the
    // record must still be the one checked, or the check runs again on the
    // current one. A request is never decided on a record that is no longer
    // the project's (a new registration, another revision, or none).
    let requested: Vec<&str> = bindings.iter().map(|(b, _)| b.env_name.as_str()).collect();
    let mut rechecks = 0;
    let (checked, mut s) = loop {
        let checked = managed::check_request(
            shared,
            peer,
            &subject,
            &project,
            record.as_ref(),
            &p,
            ends.is_some(),
            &requested,
        )?;
        // A test stops here, between the check and the decision.
        envcloak_sys::pause_point("launch.checked_before_decision");
        let s = locked(&shared.state);
        let current = managed::by_project(s.unlocked()?, &project.identity)?.map(|(_, r)| r);
        if current == record {
            break (checked, s);
        }
        drop(s);
        rechecks += 1;
        if rechecks > MAX_DECISIONS {
            return Err(RpcError::new(ErrorKind::Busy));
        }
        // The descriptors were taken for the record's transport; a record
        // of another transport refuses a request made for the first one
        // (`managed_command_mismatch`), whatever they are.
        record = current;
    };
    let managed_request = record.as_ref().map(managed::managed_request);
    // Where a covered request's values go, settled before any decision: a
    // managed project's only to the runner or relay on its checked ends,
    // never to the client, whatever let a request this far.
    let route = route(record.is_some(), checked, ends)?;

    let vault = s.unlocked()?;
    let (bound, new_project) = bind_request(vault, &bindings, &project.identity.vault_key())?;
    // What every entry for this request records.
    let project_dir = project
        .identity
        .canonical_dir
        .to_string_lossy()
        .into_owned();
    let entry = RequestAudit {
        pid: peer.pid,
        decision: "",
        request_id: None,
        grant_id: None,
        reason: None,
        subject: subject_summary(peer, &subject),
        project: Some(ProjectSummary {
            dir: project_dir.clone(),
            manifest_sha256: project.manifest.sha256,
            approved_sha256: None,
        }),
        items: bound
            .iter()
            .map(|b| (b.binding.item, b.slug.clone()))
            .collect::<Vec<(ItemId, Slug)>>(),
        argv: masked_argv(shared, vault, &bound, &p.argv),
        count: None,
    };
    let request = AccessRequest {
        subject,
        project: project.identity,
        manifest_sha256: project.manifest.sha256,
        bindings: bound,
        mode: policy.mode,
        argv_display: p.argv,
        new_project,
        managed: managed_request,
    };
    // A `once` grant is consumed under the same lock as the decision, so
    // of concurrent requests exactly one is covered by it (gate 30).
    let mut request = Some(request);
    // Each decision on clocks read for it: one taken again after a grant
    // ran out while its answer was prepared sees it expired (F-77).
    let mut decisions = 0;
    let decision = loop {
        decisions += 1;
        if decisions > MAX_DECISIONS {
            return Err(RpcError::new(ErrorKind::Internal));
        }
        let now = now_of(&shared.clocks);
        let r = request.take().ok_or(RpcError::new(ErrorKind::Internal))?;
        let again = r.clone();
        match s.grants().decide(r, &now) {
            Decision::Covered(g) => {
                // The hash at approval, when the manifest has changed since.
                let Some(approved) = s.grants().grant(g).map(|grant| grant.manifest_sha256) else {
                    request = Some(again);
                    continue;
                };
                let approved = Some(approved).filter(|h| *h != project.manifest.sha256);
                let redact = policy.redact;
                let changed = approved.is_some();
                // A delivery: its entry (which names the manifest's hash at
                // approval when it changed since) is on disk before the
                // answer, or the request is denied and the grant left as
                // it was.
                let mut covered = RequestAudit {
                    decision: "covered",
                    grant_id: Some(g.to_string()),
                    ..entry.clone()
                };
                if let Some(p) = covered.project.as_mut() {
                    p.approved_sha256 = approved;
                }
                // The daemon hands out no value under a tracer.
                refuse_if_traced()?;
                let (fields, released) = release_plan(s.unlocked()?, &again.bindings)?;
                if let Some((checked, ends)) = &route {
                    // A managed server's values go to the runner or relay
                    // the daemon starts, never to the client (D-36).
                    let c = Covered {
                        grant: g,
                        entry: covered,
                        fields,
                        released,
                    };
                    match prepare_runner(shared, id, &mut s, c, checked, ends) {
                        Prepared::Lapsed => {
                            request = Some(again);
                            continue;
                        }
                        Prepared::Done(r) => return r,
                        Prepared::Ready(ready) => {
                            // The values go out with the state lock
                            // released: on macOS the daemon then waits for
                            // the runner's `ConfirmSpawn`.
                            drop(s);
                            return ready.send(shared, peer);
                        }
                    }
                }
                let decision = DecisionView::Covered {
                    grant: g.to_string(),
                    redact,
                    mode: policy.mode,
                    manifest_changed: changed,
                };
                // The answer, framed as it will be sent, before its entry
                // is written or the grant used (F-77): one too large for
                // a frame commits nothing.
                let answer = |values: Vec<SecretBytes>| {
                    let answer = RunAnswer {
                        decision,
                        values: released
                            .into_iter()
                            .zip(values)
                            .map(|((env_name, slug, allow_short), value)| ReleasedValue {
                                env_name,
                                slug,
                                allow_short,
                                value: WireSecret::new(value),
                            })
                            .collect(),
                        proposals: Vec::new(),
                    };
                    let frame = result_framed::<RunRequest>(id, &answer);
                    // A test stops here, holding the framed answer and
                    // the state lock, to let the grant run out (F-77).
                    envcloak_sys::pause_point("run.answer_framed");
                    frame
                };
                let delivered = s.deliver(
                    g,
                    &shared.clocks,
                    &alive,
                    AuditEvent::Request(Box::new(covered)),
                    &fields,
                    Some(envcloak_core::vault::ProjectRecord {
                        key: again.project.vault_key(),
                        display_path: project_dir.clone(),
                        manifest_sha256: project.manifest.sha256,
                        bindings: bindings
                            .iter()
                            .filter(|(_, source)| {
                                matches!(source, BindingSource::Env | BindingSource::Profile { .. })
                            })
                            .map(|(b, _)| envcloak_core::vault::ProjectBinding {
                                env_name: b.env_name.as_str().to_owned(),
                                reference: b.reference.to_string(),
                            })
                            .collect(),
                        last_seen: 0, // Read at commit, after framing.
                    }),
                    answer,
                );
                let frame = match delivered {
                    Ok(frame) => frame,
                    Err(Delivery::Refused(e)) => {
                        s.audit(AuditEvent::Request(Box::new(RequestAudit {
                            decision: e.kind.token(),
                            grant_id: Some(g.to_string()),
                            ..entry
                        })));
                        return Err(e);
                    }
                    Err(Delivery::Lapsed) => {
                        // The grant ran out, or its root exited, while the
                        // answer was prepared or finalized: nothing was
                        // released, and a grant whose root exited is gone.
                        // The request is decided again on clocks read now,
                        // as if it came now, which that grant no longer
                        // covers.
                        request = Some(again);
                        continue;
                    }
                    Err(Delivery::Unsendable(e)) => {
                        // Nothing released and the grant as it was; the
                        // refusal is recorded, with the grant that would
                        // have covered it.
                        s.audit(AuditEvent::Request(Box::new(RequestAudit {
                            decision: e.kind.token(),
                            grant_id: Some(g.to_string()),
                            ..entry
                        })));
                        return Err(e);
                    }
                    Err(Delivery::AuditFailed) => {
                        let reason = DenyReason::AuditFailed.token();
                        s.audit(AuditEvent::Request(Box::new(RequestAudit {
                            decision: "denied",
                            grant_id: Some(g.to_string()),
                            reason: Some(reason),
                            ..entry
                        })));
                        break RunAnswer::decided(DecisionView::Denied {
                            reason: reason.to_owned(),
                        });
                    }
                };
                // Under the lock since the decision: the grant is there.
                if !s.grants().consume(g) {
                    return Err(RpcError::new(ErrorKind::Internal));
                }
                s.touch(Reading::now(&shared.clocks));
                // Gate 12: a test build panics here on request, holding the
                // answer about to be sent and the state lock.
                envcloak_sys::panic_point("daemon.release");
                envcloak_sys::test_event("run.request released values to the client");
                return Ok(frame);
            }
            Decision::Pending(id) => {
                // The same provider's test items, for the live bindings, so
                // the `approval_required` text names them (SPEC §10b); the
                // daemon substitutes nothing. Read from the pending request
                // the id names, as its statement is (`pending.get`): the
                // answer advises what the statement does.
                let items = s.unlocked()?.items().to_vec();
                let proposals = s
                    .grants()
                    .pending_descriptor(&id, &now, &items)
                    .ok_or(RpcError::new(ErrorKind::Internal))?
                    .proposals;
                s.audit(AuditEvent::Request(Box::new(RequestAudit {
                    decision: "pending",
                    request_id: Some(id.to_string()),
                    ..entry
                })));
                break RunAnswer::pending(id.to_string(), proposals);
            }
            Decision::TooManyPending(cap) => {
                // Written at once the first time, then counted and written
                // once a minute while the request is asked again
                // (crate::crowded).
                let e = RequestAudit {
                    decision: "too_many_pending",
                    reason: Some(cap.token()),
                    ..entry
                };
                s.audit_crowded(again.fingerprint(), e, now.awake);
                return Err(RpcError::with_reason(
                    ErrorKind::TooManyPending,
                    cap.token(),
                ));
            }
            Decision::Denied(reason) => {
                s.audit(AuditEvent::Request(Box::new(RequestAudit {
                    decision: "denied",
                    reason: Some(reason.token()),
                    ..entry
                })));
                break RunAnswer::decided(DecisionView::Denied {
                    reason: reason.token().to_owned(),
                });
            }
        }
    };
    result_framed::<RunRequest>(id, &decision)
}

/// The manifest of the project whose record has launch `launch`: a
/// request that names only its launch. No record has it:
/// `managed_command_mismatch`, audited.
fn launch_manifest(
    shared: &Shared,
    peer: &PeerIdentity,
    subject: &SubjectEvidence,
    launch: &str,
) -> Result<PathBuf, RpcError> {
    let id = envcloak_policy::managed::parse_launch_id(launch)
        .ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let mut s = locked(&shared.state);
    match managed::by_launch(s.unlocked()?, &id)? {
        Some((_, r)) => Ok(
            PathBuf::from(std::ffi::OsStr::from_bytes(&r.project.canonical_dir))
                .join(envcloak_policy::MANIFEST_NAME),
        ),
        None => {
            let kind = ErrorKind::ManagedCommandMismatch;
            s.audit(AuditEvent::ManagedLaunch {
                pid: peer.pid,
                subject: subject_summary(peer, subject),
                outcome: kind.token(),
                part: None,
                launch: Some(envcloak_policy::managed::launch_id_text(&id)),
                project: None,
                revision: None,
                old: None,
                new: None,
            });
            Err(RpcError::new(kind))
        }
    }
}

/// A covered request's delivery, as [`run_request`] prepared it.
struct Covered {
    grant: GrantId,
    entry: RequestAudit,
    fields: Vec<FieldId>,
    released: Vec<(String, String, bool)>,
}

/// The launch description the runner receives (`envcloak_ipc::control`).
fn launch_spec(l: &envcloak_core::vault::RegisteredLaunch, exec: &CheckedExec) -> LaunchSpec {
    let lossy = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    let (executable, exec) = match exec {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        CheckedExec::Image(_) => (lossy(&l.executable.path), ExecSpec::Image),
        #[cfg(any(target_os = "linux", target_os = "android"))]
        CheckedExec::Descriptor { stamp, .. } => (
            lossy(&l.executable.path),
            ExecSpec::Descriptor { stamp: *stamp },
        ),
        CheckedExec::Path { path, confirm } => (
            path.to_string_lossy().into_owned(),
            ExecSpec::Path {
                confirm: confirm.is_some(),
            },
        ),
    };
    LaunchSpec {
        argv: l.argv.iter().map(|a| lossy(a)).collect(),
        path_env: lossy(&l.env.path_env),
        vars: l.env.vars.clone(),
        executable,
        exec,
    }
}

/// The headers a relay inserts, from the record's (`headers`, each with
/// its binding) and the bindings released (`env_name` first): `None`
/// unless each header's binding is released exactly once and each binding
/// released is a header's.
fn relay_headers(
    headers: &[(String, String)],
    released: &[(String, String, bool)],
) -> Option<Vec<envcloak_ipc::control::RelayHeader>> {
    let once = |b: &str| released.iter().filter(|(n, _, _)| n == b).count() == 1;
    if released.len() != headers.len() || !headers.iter().all(|(_, b)| once(b)) {
        return None;
    }
    Some(
        headers
            .iter()
            .map(|(name, binding)| envcloak_ipc::control::RelayHeader {
                name: name.clone(),
                binding: binding.clone(),
            })
            .collect(),
    )
}

/// How a covered managed request's delivery went ([`prepare_runner`]).
enum Prepared {
    /// Delivered: the entry is on disk and the grant used; the values are
    /// to be sent to the runner.
    Ready(Box<Ready>),
    /// The grant ran out meanwhile: nothing was recorded or released, and
    /// the runner was killed; the request is decided again.
    Lapsed,
    /// Answered: refused, or denied (`audit_failed`).
    Done(Result<Frame, RpcError>),
}

/// A delivery made, whose values are still to go to the runner.
struct Ready {
    started: spawn_envcloak::Started,
    release: Frame,
    answer: Frame,
    entry: RequestAudit,
    launch: Option<String>,
}

impl Ready {
    /// Sends the values to the runner and answers the client `started`.
    fn send(self, shared: &Shared, peer: &PeerIdentity) -> Result<Frame, RpcError> {
        let sent = self.started.release(&self.release);
        drop(self.release);
        if let Err(e) = sent {
            if e.kind == ErrorKind::ManagedLaunchChanged {
                shared.audit(AuditEvent::ManagedLaunch {
                    pid: peer.pid,
                    subject: self.entry.subject.clone(),
                    outcome: e.kind.token(),
                    part: Some("executable"),
                    launch: self.launch,
                    project: self.entry.project.clone(),
                    revision: None,
                    old: None,
                    new: None,
                });
            }
            return Err(e);
        }
        envcloak_sys::test_event("run.request released values to a runner");
        Ok(self.answer)
    }
}

/// Where a request's covered values may go: `None` to the client, for an
/// unmanaged project only; `Some` to the runner or relay of a managed
/// project's checked launch or bridge, on the request's ends. A managed
/// project's request that reaches this without both is refused
/// `internal`, never answered as an unmanaged one: the request check
/// refuses it first (`managed_command_mismatch`), and this holds when it
/// does not.
fn route<C, E>(
    managed: bool,
    checked: Option<C>,
    ends: Option<E>,
) -> Result<Option<(C, E)>, RpcError> {
    match (managed, checked, ends) {
        (false, None, _) => Ok(None),
        (true, Some(c), Some(e)) => Ok(Some((c, e))),
        _ => Err(RpcError::new(ErrorKind::Internal)),
    }
}

/// A covered managed request (D-36): the daemon starts EnvCloak's runner
/// or relay from its anchor on the pipe ends the request handed over, then
/// delivers as for any covered request (the values read from the verified
/// vault, the entry on disk first), framing the values as the runner's
/// `Release`, not as the answer; the client is answered `started`. A
/// runner that cannot be started is `runner_unavailable` with nothing
/// released; one started before a delivery that did not happen is killed,
/// having received nothing.
fn prepare_runner(
    shared: &Shared,
    id: u64,
    s: &mut crate::state::State,
    c: Covered,
    checked: &Checked,
    ends: &ClientEnds,
) -> Prepared {
    let (launch, to) = match checked {
        Checked::Stdio { launch, checked } => {
            let text = envcloak_policy::managed::launch_id_text(&launch.launch_id);
            let spec = launch_spec(launch, &checked.exec);
            (Some(text.clone()), Recipient::Runner { launch: text, spec })
        }
        Checked::Bridge { origin, headers } => {
            // Every value released goes in one header, and every header
            // gets one: anything else was never registered.
            let Some(headers) = relay_headers(headers, &c.released) else {
                return Prepared::Done(Err(RpcError::new(ErrorKind::Internal)));
            };
            (
                None,
                Recipient::Relay {
                    origin: origin.clone(),
                    headers,
                },
            )
        }
    };
    // The role follows the check's transport alone: a checked launch is
    // never started as a relay, whatever else holds.
    let role = match (checked, launch.as_deref()) {
        (Checked::Stdio { checked, .. }, Some(text)) => Role::Runner {
            launch: text,
            checked,
        },
        (Checked::Bridge { .. }, None) => Role::Relay,
        _ => return Prepared::Done(Err(RpcError::new(ErrorKind::Internal))),
    };
    let started = match spawn_envcloak::start(&shared.anchor, role, ends) {
        Ok(st) => st,
        Err(e) => {
            s.audit(AuditEvent::Request(Box::new(RequestAudit {
                decision: e.kind.token(),
                grant_id: Some(c.grant.to_string()),
                ..c.entry
            })));
            return Prepared::Done(Err(e));
        }
    };
    // The client's answer, framed before anything is committed (F-77).
    let answer =
        match result_framed::<RunRequest>(id, &RunAnswer::decided(DecisionView::Started {})) {
            Ok(a) => a,
            Err(e) => {
                started.abandon();
                return Prepared::Done(Err(e));
            }
        };
    let released = c.released;
    let release = move |values: Vec<SecretBytes>| {
        let msg = ToRunner::Release(Box::new(Release {
            bindings: released
                .into_iter()
                .zip(values)
                .map(|((env_name, slug, allow_short), value)| ReleasedValue {
                    env_name,
                    slug,
                    allow_short,
                    value: WireSecret::new(value),
                })
                .collect(),
            to,
        }));
        Frame::encode(&msg).map_err(|_| RpcError::new(ErrorKind::FrameTooLarge))
    };
    let entry = c.entry.clone();
    let delivered = s.deliver(
        c.grant,
        &shared.clocks,
        &alive,
        AuditEvent::Request(Box::new(c.entry)),
        &c.fields,
        release,
    );
    let release = match delivered {
        Ok(frame) => frame,
        Err(e) => {
            started.abandon();
            return match e {
                Delivery::Refused(e) => Prepared::Done(Err(e)),
                Delivery::Lapsed => Prepared::Lapsed,
                Delivery::Unsendable(e) => {
                    s.audit(AuditEvent::Request(Box::new(RequestAudit {
                        decision: e.kind.token(),
                        grant_id: Some(c.grant.to_string()),
                        ..entry
                    })));
                    Prepared::Done(Err(e))
                }
                Delivery::AuditFailed => {
                    let reason = DenyReason::AuditFailed.token();
                    s.audit(AuditEvent::Request(Box::new(RequestAudit {
                        decision: "denied",
                        grant_id: Some(c.grant.to_string()),
                        reason: Some(reason),
                        ..entry
                    })));
                    Prepared::Done(result_framed::<RunRequest>(
                        id,
                        &RunAnswer::decided(DecisionView::Denied {
                            reason: reason.to_owned(),
                        }),
                    ))
                }
            };
        }
    };
    if !s.grants().consume(c.grant) {
        started.abandon();
        return Prepared::Done(Err(RpcError::new(ErrorKind::Internal)));
    }
    s.touch(Reading::now(&shared.clocks));
    Prepared::Ready(Box::new(Ready {
        started,
        release,
        answer,
        entry,
        launch,
    }))
}

fn request_id(p: &RequestParams) -> Result<PendingId, RpcError> {
    PendingId::parse(&p.request).ok_or(RpcError::new(ErrorKind::InvalidParams))
}

/// `pending.get`: the descriptor of a pending request, for a caller that
/// may give a proof. Everyone else is refused before anything is looked
/// up, so `envcloak approve` run where no proof is taken (an agent's
/// tree, a service manager's job) stops before it shows the statement or
/// asks for the passphrase. So does every caller while the vault has
/// failed its integrity check (`vault_tampered`).
pub fn pending_get(
    shared: &Shared,
    peer: &PeerIdentity,
    p: PendingGetParams,
) -> Result<PendingDescriptor, RpcError> {
    let id = PendingId::parse(&p.request).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let caller = evidence(shared, peer, &p.claims)?;
    refuse_unless_prover(shared, peer, &caller, "pending.get")?;
    let now = now_of(&shared.clocks);
    let mut s = locked(&shared.state);
    // No statement is shown from a vault that failed its integrity check:
    // `approve` would be refused before its proof (review T9 open 6).
    s.refuse_if_tampered()?;
    refuse_requester_terminal(&mut s, peer, &caller, &id, &now, "pending.get")?;
    if s.grants().pending(&id, &now).is_none() {
        return Err(RpcError::new(ErrorKind::NoSuchRequest));
    }
    // The classifications and the proposed test items as the vault has
    // them now (L-09), which `approve` builds again before it compares.
    let items = s.unlocked()?.items().to_vec();
    s.grants()
        .pending_descriptor(&id, &now, &items)
        .ok_or(RpcError::new(ErrorKind::NoSuchRequest))
}

/// Audits an approval of request `id` that the live-key guard refused,
/// with the items whose live bindings `opts` left unticked, and returns
/// the refusal.
fn live_refused(
    s: &mut crate::state::State,
    peer: &PeerIdentity,
    approver: SubjectSummary,
    id: &PendingId,
    opts: &ApprovalOptions,
    now: &Now,
    items: &[ItemMeta],
) -> RpcError {
    let unticked = s.grants().unticked_items(id, opts, now, items);
    s.audit(AuditEvent::LiveRefused {
        pid: peer.pid,
        subject: approver,
        request: id.to_string(),
        items: unticked,
    });
    RpcError::new(ErrorKind::LiveNotTicked)
}

/// `pending.state`: how a request stands, for the caller's own process
/// tree only, within its root's poll limit (`busy` beyond it). See the
/// module documentation. A malformed id is `invalid_params`, as for every
/// method; one no request has is `unknown`, as for another tree's.
pub fn pending_state(
    shared: &Shared,
    peer: &PeerIdentity,
    p: PendingStateParams,
) -> Result<PendingStateView, RpcError> {
    let id = PendingId::parse(&p.request).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let caller = evidence(shared, peer, &[])?;
    let mut s = locked(&shared.state);
    // Read under the lock, so polls reach the limiter in the order of
    // their times.
    let now = now_of(&shared.clocks);
    let answer = s.grants().poll(&id, &caller, &now);
    // A test build's trace, written under the state lock so that its order
    // in the log is the order of the decisions (an approval's audit line
    // comes before every poll it answers).
    if envcloak_sys::test_trace() {
        log_line!(
            "envcloakd: test: pending.state pid={} request={id} answer={}",
            peer.pid,
            answer.map_or("busy", PendingState::word)
        );
    }
    drop(s);
    answer
        .map(|state| PendingStateView { state })
        .map_err(|_| RpcError::new(ErrorKind::Busy))
}

/// `pending.list`: the requests waiting for approval that the caller may
/// approve, oldest first. A caller whose proof would be refused gets an
/// empty list, without being told why; a request whose requester shares a
/// session or a terminal with the caller is left out (SPEC §10b: an
/// approval surface does not show a request to a caller whose proof it
/// would refuse). Nothing is shown from a vault that failed its integrity
/// check. Each request names at most [`MAX_LISTED_BINDINGS`] bindings and
/// counts the rest, so the listing fits in one frame.
pub fn pending_list(
    shared: &Shared,
    peer: &PeerIdentity,
    p: PendingListParams,
) -> Result<PendingListView, RpcError> {
    let caller = evidence(shared, peer, &p.claims)?;
    if caller.proof_refusal().is_some() {
        return Ok(PendingListView {
            requests: Vec::new(),
        });
    }
    let mut s = locked(&shared.state);
    s.refuse_if_tampered()?;
    let now = now_of(&shared.clocks);
    let requests = s
        .grants()
        .pending_all(&now)
        .filter(|p| {
            caller
                .approval_refusal(&p.request.subject, &alive)
                .is_none()
        })
        .map(|p| pending_view(p, &now))
        .collect();
    Ok(PendingListView { requests })
}

/// What `envcloak pending` shows of one request.
fn pending_view(p: &Pending, now: &envcloak_policy::Now) -> PendingView {
    let kind = p.request.subject.kind();
    let age = p.age(now);
    PendingView {
        request: p.id.to_string(),
        age_secs: age.as_secs(),
        expires_in_secs: PENDING_TTL.saturating_sub(age).as_secs(),
        kind,
        agent: match kind {
            SubjectKind::Agent => p.request.subject.label().map(|l| l.name.clone()),
            SubjectKind::Terminal | SubjectKind::Unknown => None,
        },
        project: p
            .request
            .project
            .canonical_dir
            .to_string_lossy()
            .into_owned(),
        bindings: p
            .request
            .bindings
            .iter()
            .take(MAX_LISTED_BINDINGS)
            .map(|b| b.slug.as_str().to_owned())
            .collect(),
        more_bindings: u64::try_from(p.request.bindings.len().saturating_sub(MAX_LISTED_BINDINGS))
            .unwrap_or(u64::MAX),
    }
}

/// Decodes 64 hex characters.
pub(crate) fn digest_of(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

/// `approve`. See the module documentation.
pub fn approve(
    shared: &Shared,
    peer: &PeerIdentity,
    p: ApproveParams,
) -> Result<ApprovedView, RpcError> {
    // Without a passphrase the call is a check: every check before the
    // proof runs, and it ends at the proof (`invalid_params`), never in a
    // grant.
    let pass = p.passphrase.map(WireSecret::into_inner);
    let id = PendingId::parse(&p.request).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let digest = digest_of(&p.digest).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    refuse_if_traced()?;
    let approver = evidence(shared, peer, &p.claims)?;
    refuse_unless_prover(shared, peer, &approver, "approve")?;
    let _gate = locked(&shared.proof_gate);
    let (vault, generation, pass) = {
        let mut s = locked(&shared.state);
        let now = now_of(&shared.clocks);
        let items = s.unlocked()?.items().to_vec();
        refuse_requester_terminal(&mut s, peer, &approver, &id, &now, "approve")?;
        // Everything but the passphrase is checked before Argon2id runs,
        // the live-key guard included: an approval that leaves a live
        // binding unticked is refused, and audited, before the passphrase
        // is looked at (L-10).
        match s
            .grants()
            .check_approval(&id, &p.options, digest, &now, &items)
        {
            Ok(()) => {}
            Err(ApproveError::LiveNotTicked) => {
                let who = subject_summary(peer, &approver);
                return Err(live_refused(
                    &mut s, peer, who, &id, &p.options, &now, &items,
                ));
            }
            Err(e) => return Err(approve_error(e)),
        }
        // A check ends here, before the attempt limiter: no attempt is
        // made, and none counted.
        let pass = pass.ok_or(RpcError::new(ErrorKind::InvalidParams))?;
        s.limiter()
            .check(&now)
            .map_err(|_| RpcError::new(ErrorKind::TooManyAttempts))?;
        let (vault, generation) = s.begin_proof()?;
        (vault, generation, pass)
    };
    let verified = vault.verify_passphrase(&pass);
    drop(pass);
    let mut s = locked(&shared.state);
    let now = now_of(&shared.clocks);
    let back = s.finish_proof(generation, vault);
    match verified {
        Ok(()) => {
            s.limiter().succeeded();
            back?;
            let who = subject_summary(peer, &approver);
            let proof = ApprovalProof {
                approver,
                kind: ProofKind::Passphrase,
            };
            let ttl = p.options.ttl_secs;
            let uses = match p.options.uses {
                Uses::Once => "once",
                Uses::Session => "session",
            };
            // The vault as it is now, after Argon2id: the statement, and the
            // classifications the guard reads, are built from it again.
            let items = s.unlocked()?.items().to_vec();
            let opts = p.options.clone();
            let grant = match s
                .grants()
                .approve(&id, proof, p.options, digest, &now, &items)
            {
                Ok(g) => g,
                Err(ApproveError::LiveNotTicked) => {
                    return Err(live_refused(&mut s, peer, who, &id, &opts, &now, &items));
                }
                Err(e) => return Err(approve_error(e)),
            };
            s.touch(Reading::now(&shared.clocks));
            s.audit(AuditEvent::Approved {
                pid: peer.pid,
                request: id.to_string(),
                grant: grant.to_string(),
                uses,
                ttl_secs: ttl,
            });
            Ok(ApprovedView {
                grant: grant.to_string(),
                expires_in_secs: ttl,
            })
        }
        Err(e) if e.kind() == VaultErrorKind::Crypto(CryptoErrorKind::Unlock) => {
            s.limiter().failed(&now);
            s.audit(AuditEvent::ApproveFailed {
                pid: peer.pid,
                reason: "wrong_passphrase",
            });
            back?;
            Err(RpcError::new(ErrorKind::WrongPassphrase))
        }
        Err(e) => {
            back?;
            Err(RpcError::with_reason(
                ErrorKind::VaultUnavailable,
                vault_reason(e.kind()),
            ))
        }
    }
}

/// `deny`: refuses a pending request. Tightening needs no proof.
pub fn deny(
    shared: &Shared,
    peer: &PeerIdentity,
    p: RequestParams,
) -> Result<DeniedView, RpcError> {
    let id = request_id(&p)?;
    let now = now_of(&shared.clocks);
    let outcome = locked(&shared.state)
        .grants()
        .deny(&id, &now)
        .map_err(|_| RpcError::new(ErrorKind::NoSuchRequest))?;
    shared.audit(AuditEvent::Denied {
        pid: peer.pid,
        request: id.to_string(),
        root_auto_denied: outcome.root_auto_denied,
    });
    Ok(DeniedView {
        root_auto_denied: outcome.root_auto_denied,
    })
}

/// Whether the process instance `root` is still running: the pid exists
/// and has the recorded start time. A process that cannot be read is
/// taken as gone: a grant never outlives its root.
pub fn alive(root: &ProcessInstance) -> bool {
    envcloak_sys::proc_info(root.pid).is_ok_and(|p| p.start_time == root.start_time)
}

/// `grants.list`: the grants in force, after dropping those whose root
/// exited.
pub fn grants_list(shared: &Shared) -> Result<GrantsView, RpcError> {
    let now = now_of(&shared.clocks);
    let mut s = locked(&shared.state);
    let store = s.grants();
    store.sweep(&now, &alive);
    let grants = store
        .grants()
        .map(|g| GrantView {
            id: g.id.to_string(),
            kind: g.kind,
            label: g.label.clone(),
            root_pid: g.root.pid,
            root_exe: g
                .root
                .exe
                .as_ref()
                .map(|e| e.path.to_string_lossy().into_owned()),
            project_dir: g.project.canonical_dir.to_string_lossy().into_owned(),
            bindings: g
                .bindings
                .iter()
                .map(|b| GrantBindingView {
                    env_name: b.env_name.as_str().to_owned(),
                    slug: b.slug.as_str().to_owned(),
                    live: b.live,
                })
                .collect(),
            mode: g.mode,
            uses: g.uses,
            created_secs: g
                .created
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            remaining_secs: g.remaining(&now).as_secs(),
        })
        .collect();
    Ok(GrantsView { grants })
}

/// `grants.revoke`. Tightening needs no proof.
pub fn grants_revoke(
    shared: &Shared,
    peer: &PeerIdentity,
    p: RevokeParams,
) -> Result<RevokedView, RpcError> {
    let selector = match (&p.grant, p.all) {
        (Some(id), false) => {
            RevokeSelector::Id(GrantId::parse(id).ok_or(RpcError::new(ErrorKind::InvalidParams))?)
        }
        (None, true) => RevokeSelector::All,
        _ => return Err(RpcError::new(ErrorKind::InvalidParams)),
    };
    let revoked = locked(&shared.state).grants().revoke(selector);
    shared.audit(AuditEvent::Revoked {
        pid: peer.pid,
        count: revoked,
    });
    Ok(RevokedView {
        revoked: u64::try_from(revoked).unwrap_or(u64::MAX),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Gate 39, the backstop: a managed project's covered values go to its
    /// runner or relay on checked ends, or nowhere. A managed request that
    /// reaches the decision without a check or without ends is refused,
    /// never routed to the client; an unmanaged one goes to the client,
    /// any ends it brought unused. Mutation checked: the fall-through to
    /// the client release when either half is missing (`route` answering
    /// `Ok(None)` for a managed project): the managed cases fail.
    #[test]
    fn a_managed_request_is_routed_to_its_runner_or_refused() {
        let kind = |r: Result<Option<((), ())>, RpcError>| r.map_err(|e| e.kind);
        assert_eq!(kind(route(true, Some(()), Some(()))), Ok(Some(((), ()))));
        for (checked, ends) in [(Some(()), None), (None, Some(())), (None, None)] {
            assert_eq!(
                kind(route(true, checked, ends)),
                Err(ErrorKind::Internal),
                "{checked:?} {ends:?}"
            );
        }
        assert_eq!(kind(route(false, None, None)), Ok(None));
        assert_eq!(kind(route(false, None, Some(()))), Ok(None));
        assert_eq!(
            kind(route(false, Some(()), Some(()))),
            Err(ErrorKind::Internal)
        );
    }

    /// A relay's release names each header with the binding it carries,
    /// as the record registered them, for any number of headers; a
    /// release whose bindings are not exactly the headers' (one missing,
    /// one extra, one twice, a header renamed so its binding is another)
    /// has no relay headers and is refused. Mutation checked: the headers
    /// left out of the release (the previous `Recipient::Relay { origin
    /// }`): this does not compile; the binding check removed (any release
    /// mapped): the refused cases pass, and this fails.
    #[test]
    fn a_relay_is_told_which_value_goes_in_which_header() {
        let o = "https://api.example.test";
        let headers = envcloak_policy::managed::bridge_headers(
            &["Authorization".to_owned(), "X-Api-Key".to_owned()],
            o,
        )
        .unwrap();
        let rel = |names: &[&str]| -> Vec<(String, String, bool)> {
            names
                .iter()
                .map(|n| ((*n).to_owned(), "acme/key".to_owned(), false))
                .collect()
        };
        let auth = headers[0].1.as_str();
        let key = headers[1].1.as_str();
        let got = relay_headers(&headers, &rel(&[key, auth])).unwrap();
        assert_eq!(
            got.iter()
                .map(|h| (h.name.as_str(), h.binding.as_str()))
                .collect::<Vec<_>>(),
            vec![("Authorization", auth), ("X-Api-Key", key)]
        );
        let renamed = envcloak_policy::managed::bridge_headers(
            &["Authorization".to_owned(), "X-Other-Key".to_owned()],
            o,
        )
        .unwrap();
        for released in [
            rel(&[auth]),
            rel(&[auth, key, "PLAIN_KEY"]),
            rel(&[auth, auth]),
        ] {
            assert!(relay_headers(&headers, &released).is_none(), "{released:?}");
        }
        assert!(relay_headers(&renamed, &rel(&[auth, key])).is_none());
    }

    /// Gate 27, the sweep's half: a root is alive only while its pid has
    /// the start time the grant recorded. A pid in use by another process
    /// (the same pid, another start time) is a root that exited, and so is
    /// a pid no process has.
    #[test]
    fn a_root_is_alive_only_with_its_start_time() {
        let pid = i32::try_from(std::process::id()).unwrap();
        let me = envcloak_sys::proc_info(pid).unwrap();
        let root = ProcessInstance {
            pid,
            start_time: me.start_time,
            pidversion: None,
            exe: None,
        };
        assert!(alive(&root));
        for other in [
            me.start_time.raw() + 1,
            me.start_time.raw().saturating_sub(1),
        ] {
            let recycled = ProcessInstance {
                start_time: envcloak_sys::StartTime::from_raw(other),
                ..root.clone()
            };
            assert!(!alive(&recycled), "a pid with another start time");
        }
        let mut child = std::process::Command::new("/usr/bin/true").spawn().unwrap();
        let gone = i32::try_from(child.id()).unwrap();
        let started = envcloak_sys::proc_info(gone).map(|p| p.start_time);
        child.wait().unwrap();
        if let Ok(start_time) = started {
            let exited = ProcessInstance {
                pid: gone,
                start_time,
                pidversion: None,
                exe: None,
            };
            assert!(!alive(&exited), "an exited process");
        }
    }
}
