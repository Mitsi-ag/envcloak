//! The grant methods (SPEC §6.1 steps 2 to 4, §10a, §10b): `run.request`,
//! `pending.get`, `approve`, `deny`, `grants.list` and `grants.revoke`.
//!
//! `run.request` decides only; no value crosses the socket in this build
//! (the release path is T12's). For every request the daemon:
//! 1. reads the caller's evidence from the kernel ([`gather`]), with the
//!    marker names the caller claims;
//! 2. opens the manifest itself, from the path the caller sent, and
//!    resolves the bindings from the file it read ([`load_project`],
//!    [`resolve`]); the caller's argv is display text only;
//! 3. binds them to the vault's items ([`bind_items`]), and looks up
//!    whether the project and the items are new to the vault (SPEC §6.4
//!    "Adoption");
//! 4. applies the effective policy (the vault's, tightened by the
//!    manifest's, for the subject's kind), which can refuse agent requests
//!    or require proxy mode (refused: M1 has none);
//! 5. asks the grant store ([`GrantStore::decide`]) and, for a `once`
//!    grant, consumes it under the same lock.
//!
//! `approve` takes the passphrase as the proof. Before Argon2id runs, the
//! approver must be a terminal subject with no agent by any evidence
//! (SPEC §10b: proofs from every other caller are refused), the pending
//! request must exist, the statement
//! digest must be its own with the options sent, and the attempt limiter
//! must admit the attempt. Argon2id then runs outside the state lock, with
//! the vault taken out as an unlock takes it, one proof at a time.
//!
//! No grant is evaluated, and no proof taken, from a vault whose
//! integrity check failed ([`crate::state::State::unlocked`]).

use std::path::Path;

use envcloak_core::crypto::CryptoErrorKind;
use envcloak_core::vault::{Vault, VaultErrorKind};
use envcloak_ipc::RpcError;
use envcloak_ipc::proto::{
    ApproveParams, ErrorKind, PendingGetParams, RequestParams, RevokeParams, RunRequestParams,
};
use envcloak_ipc::view::{
    ApprovedView, DecisionView, DeniedView, GrantBindingView, GrantView, GrantsView, RevokedView,
};
use envcloak_policy::{
    AccessRequest, ApprovalProof, ApproveError, BindError, Binding, BoundRef, Claims, Decision,
    EvidenceError, GrantId, ManifestError, Mode, PendingDescriptor, PendingId, ProcessInstance,
    ProfileName, ProofKind, RevokeSelector, SubjectEvidence, VaultProjectPolicy, bind_items,
    effective_policy, gather, load_project, resolve,
};
use envcloak_sys::PeerIdentity;

use crate::audit::AuditEvent;
use crate::clock::now_of;
use crate::lock::Reading;
use crate::server::{Shared, locked, refuse_if_traced};
use crate::state::vault_reason;

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
            shared.audit.record(AuditEvent::ProofRefused {
                pid: peer.pid,
                method,
                reason: r.token(),
            });
            Err(RpcError::new(ErrorKind::ProofRefused))
        }
    }
}

/// Reads the caller's evidence.
pub(crate) fn evidence(
    shared: &Shared,
    peer: &PeerIdentity,
    claims: &[String],
) -> Result<SubjectEvidence, RpcError> {
    let claims =
        Claims::from_markers(claims).map_err(|_| RpcError::new(ErrorKind::InvalidParams))?;
    gather(peer, claims, &shared.catalog)
        .map_err(|e: EvidenceError| RpcError::with_reason(ErrorKind::Evidence, e.token()))
}

/// A manifest or resolution error as the protocol reports it.
fn manifest_error(e: ManifestError) -> RpcError {
    let kind = if e.token() == "binding_unresolved" {
        ErrorKind::BindingUnresolved
    } else {
        ErrorKind::ManifestInvalid
    };
    RpcError::with_reason(kind, e.kind().token())
}

fn bind_error(e: &BindError) -> RpcError {
    let kind = if e.token() == "binding_unresolved" {
        ErrorKind::BindingUnresolved
    } else {
        ErrorKind::ManifestInvalid
    };
    RpcError::with_reason(kind, e.kind().token())
}

fn approve_error(e: ApproveError) -> RpcError {
    match e {
        ApproveError::NoSuchRequest => RpcError::new(ErrorKind::NoSuchRequest),
        ApproveError::StatementMismatch => RpcError::new(ErrorKind::StatementMismatch),
        ApproveError::ProofRefused => RpcError::new(ErrorKind::ProofRefused),
        ApproveError::InvalidOptions(o) => {
            RpcError::with_reason(ErrorKind::InvalidOptions, o.token())
        }
        ApproveError::TooManyGrants => RpcError::new(ErrorKind::TooManyGrants),
    }
}

/// The bindings a run asks for, bound to the vault's items and carrying
/// what the approval shows, plus whether the project is new to the vault.
fn bind_request(
    vault: &Vault,
    bindings: &[Binding],
    project_key: &envcloak_core::vault::ProjectKey,
) -> Result<(Vec<BoundRef>, bool), RpcError> {
    let bound = bind_items(bindings, vault.items()).map_err(|e| bind_error(&e))?;
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
        .map(|b| {
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
            })
        })
        .collect::<Result<Vec<_>, RpcError>>()?;
    Ok((refs, new_project))
}

/// `run.request`. See the module documentation.
pub fn run_request(
    shared: &Shared,
    peer: &PeerIdentity,
    p: RunRequestParams,
) -> Result<DecisionView, RpcError> {
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
    let manifest_path = Path::new(&p.manifest);
    if !manifest_path.is_absolute() {
        return Err(RpcError::with_reason(
            ErrorKind::ManifestInvalid,
            "invalid_path",
        ));
    }
    // The daemon opens the manifest itself; nothing the caller sent about
    // its contents is used.
    let project = load_project(manifest_path).map_err(manifest_error)?;
    let bindings =
        resolve(&project.manifest, profile.as_ref(), &refs, None).map_err(manifest_error)?;
    let kind = subject.kind();
    let policy = effective_policy(
        &VaultProjectPolicy::default(),
        &project.manifest.policy,
        kind,
    );
    if policy.deny {
        shared.audit.record(AuditEvent::Request {
            pid: peer.pid,
            decision: "policy_denied",
            id: String::new(),
        });
        return Err(RpcError::new(ErrorKind::PolicyDenied));
    }
    if policy.mode == Mode::Proxy {
        return Err(RpcError::new(ErrorKind::ModeUnsupported));
    }

    let mut s = locked(&shared.state);
    let vault = s.unlocked()?;
    let (bound, new_project) = bind_request(vault, &bindings, &project.identity.vault_key())?;
    let request = AccessRequest {
        subject,
        project: project.identity,
        manifest_sha256: project.manifest.sha256,
        bindings: bound,
        mode: policy.mode,
        argv_display: p.argv,
        new_project,
    };
    let now = now_of(&shared.clocks);
    // A `once` grant is consumed under the same lock as the decision, so
    // of concurrent requests exactly one is covered by it (gate 30).
    let mut request = Some(request);
    let decision = loop {
        let r = request.take().ok_or(RpcError::new(ErrorKind::Internal))?;
        let again = r.clone();
        match s.grants().decide(r, &now) {
            Decision::Covered(g) => {
                // The hash at approval, when the manifest has changed since.
                let approved = s
                    .grants()
                    .grant(g)
                    .map(|grant| grant.manifest_sha256)
                    .filter(|h| *h != project.manifest.sha256);
                let redact = policy.redact;
                if !s.grants().consume(g) {
                    request = Some(again);
                    continue;
                }
                let changed = approved.is_some();
                if let Some(approved_sha256) = approved {
                    shared.audit.record(AuditEvent::ManifestChanged {
                        pid: peer.pid,
                        grant: g.to_string(),
                        approved_sha256,
                        sha256: project.manifest.sha256,
                    });
                }
                s.touch(Reading::now(&shared.clocks));
                shared.audit.record(AuditEvent::Request {
                    pid: peer.pid,
                    decision: "covered",
                    id: g.to_string(),
                });
                break DecisionView::Covered {
                    grant: g.to_string(),
                    redact,
                    mode: policy.mode,
                    manifest_changed: changed,
                };
            }
            Decision::Pending(id) => {
                shared.audit.record(AuditEvent::Request {
                    pid: peer.pid,
                    decision: "pending",
                    id: id.to_string(),
                });
                break DecisionView::Pending {
                    request: id.to_string(),
                };
            }
            Decision::Denied(reason) => {
                shared.audit.record(AuditEvent::Request {
                    pid: peer.pid,
                    decision: "denied",
                    id: reason.token().to_owned(),
                });
                break DecisionView::Denied {
                    reason: reason.token().to_owned(),
                };
            }
        }
    };
    Ok(decision)
}

fn request_id(p: &RequestParams) -> Result<PendingId, RpcError> {
    PendingId::parse(&p.request).ok_or(RpcError::new(ErrorKind::InvalidParams))
}

/// `pending.get`: the descriptor of a pending request, for a caller that
/// may give a proof. Everyone else is refused before anything is looked
/// up, so `envcloak approve` run where no proof is taken (an agent's
/// tree, a service manager's job) stops before it shows the statement or
/// asks for the passphrase.
pub fn pending_get(
    shared: &Shared,
    peer: &PeerIdentity,
    p: PendingGetParams,
) -> Result<PendingDescriptor, RpcError> {
    let id = PendingId::parse(&p.request).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let caller = evidence(shared, peer, &p.claims)?;
    refuse_unless_prover(shared, peer, &caller, "pending.get")?;
    let now = now_of(&shared.clocks);
    locked(&shared.state)
        .grants()
        .pending_descriptor(&id, &now)
        .cloned()
        .ok_or(RpcError::new(ErrorKind::NoSuchRequest))
}

/// Decodes 64 hex characters.
fn digest_of(hex: &str) -> Option<[u8; 32]> {
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
    let pass = p.passphrase.into_inner();
    let id = PendingId::parse(&p.request).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let digest = digest_of(&p.digest).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    refuse_if_traced()?;
    let approver = evidence(shared, peer, &p.claims)?;
    refuse_unless_prover(shared, peer, &approver, "approve")?;
    let _gate = locked(&shared.proof_gate);
    let (vault, generation) = {
        let mut s = locked(&shared.state);
        let now = now_of(&shared.clocks);
        s.unlocked()?;
        // Everything but the passphrase is checked before Argon2id runs.
        s.grants()
            .check_approval(&id, &p.options, digest, &now)
            .map_err(approve_error)?;
        s.limiter()
            .check(&now)
            .map_err(|_| RpcError::new(ErrorKind::TooManyAttempts))?;
        s.begin_proof()?
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
            let proof = ApprovalProof {
                approver,
                kind: ProofKind::Passphrase,
            };
            let ttl = p.options.ttl_secs;
            let grant = s
                .grants()
                .approve(&id, proof, p.options, digest, &now)
                .map_err(approve_error)?;
            s.touch(Reading::now(&shared.clocks));
            shared.audit.record(AuditEvent::Approved {
                pid: peer.pid,
                request: id.to_string(),
                grant: grant.to_string(),
            });
            Ok(ApprovedView {
                grant: grant.to_string(),
                expires_in_secs: ttl,
            })
        }
        Err(e) if e.kind() == VaultErrorKind::Crypto(CryptoErrorKind::Unlock) => {
            s.limiter().failed(&now);
            shared.audit.record(AuditEvent::ApproveFailed {
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
    shared.audit.record(AuditEvent::Denied {
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
    shared.audit.record(AuditEvent::Revoked {
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
