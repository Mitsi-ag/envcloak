//! Standing approvals in the daemon (SPEC §10b; M2 plan D-10, task M2-15):
//! `standing.list`, `standing.revoke`, `standing.confirm`, and the vault +
//! `<data>/policy-epoch` transaction helpers used by `approve` and
//! `run.request`.

use std::path::PathBuf;

use envcloak_core::audit::AuditKind;
use envcloak_core::crypto::CryptoErrorKind;
use envcloak_core::vault::{PolicyRecord, VaultErrorKind};
use envcloak_ipc::RpcError;
use envcloak_ipc::proto::{ErrorKind, NoParams, StandingConfirmParams, StandingRevokeParams};
use envcloak_ipc::view::{StandingConfirmedView, StandingListView, StandingRevokedView};
use envcloak_policy::standing::{
    StandingError, StandingId, StandingRecord, StandingRecordSummary, confirm_statement_digest,
};
use envcloak_policy::{OptionsError, SubjectEvidence};
use envcloak_sys::PeerIdentity;

use crate::audit::AuditEvent;
use crate::clock::now_of;
use crate::lock::Reading;
use crate::policy_epoch::{EpochState, PolicyEpoch, SidecarState};
use crate::requests::{
    digest_of, evidence, refuse_unless_prover_beside_pending, requester_terminal_in,
    subject_summary,
};
use crate::server::{Shared, locked, refuse_if_traced};
use crate::state::{State, vault_reason};

/// Current user's `HOME` directory when set to an absolute path.
pub(crate) fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

/// Maps a [`StandingError`] to the wire [`RpcError`].
pub(crate) fn standing_error(e: StandingError) -> RpcError {
    match e {
        StandingError::IdentityNotStandingCapable => {
            RpcError::new(ErrorKind::IdentityNotStandingCapable)
        }
        StandingError::IdentityOutsideInstallTree => {
            RpcError::new(ErrorKind::IdentityOutsideInstallTree)
        }
        StandingError::LaunchNotStandingCapable => {
            RpcError::new(ErrorKind::LaunchNotStandingCapable)
        }
        StandingError::PolicyEpochUnverified => RpcError::new(ErrorKind::PolicyEpochUnverified),
        StandingError::InvalidOptions(
            OptionsError::StandingNotTest | OptionsError::StandingInvalid,
        ) => RpcError::new(ErrorKind::InvalidOptions),
        StandingError::InvalidOptions(o) => {
            RpcError::with_reason(ErrorKind::InvalidOptions, o.token())
        }
    }
}

/// Returns the highest standing-set generation observed across the unlocked
/// vault header, the in-memory floor, and `<data>/policy-epoch`.
pub(crate) fn sidecar_generation_floor(s: &State) -> Result<u64, RpcError> {
    let v = s.unlocked()?;
    let h = v
        .header()
        .map_err(|e| RpcError::with_reason(ErrorKind::VaultUnavailable, vault_reason(e.kind())))?;
    let vault_id = v.vault_id().0;
    let pe = PolicyEpoch::new(vault_id, &s.paths().data_dir);
    let on_disk = match pe.load() {
        SidecarState::Present(sc) if sc.vault_id == vault_id => sc.generation,
        _ => 0,
    };
    Ok(s.standing_generation_floor()
        .max(h.standing_set.generation)
        .max(on_disk))
}

/// Writes `<data>/policy-epoch` from the unlocked vault's current
/// `standing_set` header, and returns its `generation`.
pub(crate) fn commit_sidecar(s: &mut State) -> Result<u64, RpcError> {
    let (vault_id, standing_set) = {
        let v = s.unlocked()?;
        let h = v.header().map_err(|e| {
            RpcError::with_reason(ErrorKind::VaultUnavailable, vault_reason(e.kind()))
        })?;
        (v.vault_id().0, h.standing_set)
    };
    let pe = PolicyEpoch::new(vault_id, &s.paths().data_dir);
    match pe.commit(standing_set) {
        Ok(()) => {
            s.raise_standing_generation_floor(standing_set.generation);
            s.set_epoch_state(EpochState::Verified);
            Ok(standing_set.generation)
        }
        Err(_) => {
            s.set_epoch_state(EpochState::Unverified);
            Err(RpcError::with_reason(ErrorKind::VaultUnavailable, "io"))
        }
    }
}

/// Persists `record` in `policies.sealed` (incrementing the vault header's
/// `standing_set.generation` past any observed floor and recomputing
/// `standing_set.set_digest`), updates the in-memory [`StandingStore`], and
/// writes `<data>/policy-epoch`.
pub(crate) fn put_record(s: &mut State, record: StandingRecord) -> Result<(), RpcError> {
    let floor = sidecar_generation_floor(s)?;
    envcloak_sys::pause_point("standing.before_vault_commit");
    envcloak_sys::panic_point("standing.before_vault_commit");
    let (policy_id, approval) = record.to_vault();
    {
        let v = s.unlocked_mut()?;
        v.transact(|txn| {
            txn.advance_standing_set(floor);
            txn.put_policy(policy_id, &PolicyRecord::StandingApproval(approval))
        })
        .map_err(|e| match e.kind() {
            VaultErrorKind::ReadOnly | VaultErrorKind::Tampered => {
                RpcError::new(ErrorKind::VaultTampered)
            }
            k => RpcError::with_reason(ErrorKind::VaultUnavailable, vault_reason(k)),
        })?;
    }
    envcloak_sys::pause_point("standing.after_vault_commit");
    envcloak_sys::panic_point("standing.after_vault_commit");

    s.standing_mut().insert(record);
    commit_sidecar(s)?;
    Ok(())
}

/// Deletes `ids` from `policies.sealed` in one vault transaction, removes
/// them from the in-memory [`StandingStore`], bumps `policy_epoch` (ending
/// derived session grants), and updates `<data>/policy-epoch` when
/// [`EpochState::Verified`] or when the standing set becomes empty.
///
/// When [`EpochState::Unverified`] and at least one unconfirmed standing
/// record remains after deleting `ids`, the vault's `standing_set.generation`
/// is frozen and `<data>/policy-epoch` is left untouched so selective
/// revocation without a passphrase never unpauses remaining unconfirmed
/// records or regresses the anti-rollback high-water mark.
///
/// Returns `(records_revoked, grants_ended)`.
pub(crate) fn delete_records(
    s: &mut State,
    ids: &[StandingId],
) -> Result<(usize, usize), RpcError> {
    delete_records_inner(s, ids, false)
}

fn delete_records_inner(
    s: &mut State,
    ids: &[StandingId],
    clear_all: bool,
) -> Result<(usize, usize), RpcError> {
    let present: Vec<StandingId> = ids
        .iter()
        .copied()
        .filter(|id| s.standing().get(*id).is_some())
        .collect();
    let unverified = s.epoch_state() == EpochState::Unverified;
    let remaining_after = s
        .standing()
        .all_records()
        .filter(|r| !present.contains(&r.id))
        .count();
    let clears_unverified_empty = unverified && (clear_all || remaining_after == 0);
    if present.is_empty() && !clears_unverified_empty {
        return Ok((0, 0));
    }
    let freeze_unverified = unverified && remaining_after > 0;
    let floor = sidecar_generation_floor(s)?;
    envcloak_sys::pause_point("standing.before_vault_commit");
    envcloak_sys::panic_point("standing.before_vault_commit");
    let policy_epoch = {
        let v = s.unlocked_mut()?;
        v.transact(|txn| {
            for id in &present {
                txn.delete_policy(id.policy_id())?;
            }
            if freeze_unverified {
                txn.freeze_unverified_standing_set();
            } else {
                txn.advance_standing_set(floor);
            }
            Ok(txn.bump_policy_epoch())
        })
        .map_err(|e| match e.kind() {
            VaultErrorKind::ReadOnly | VaultErrorKind::Tampered => {
                RpcError::new(ErrorKind::VaultTampered)
            }
            k => RpcError::with_reason(ErrorKind::VaultUnavailable, vault_reason(k)),
        })?
    };
    envcloak_sys::pause_point("standing.after_vault_commit");
    envcloak_sys::panic_point("standing.after_vault_commit");

    for id in &present {
        s.standing_mut().remove(*id);
    }
    let grants_before = s.grants().grants().count();
    s.grants().set_policy_epoch(policy_epoch);
    if !freeze_unverified {
        commit_sidecar(s)?;
    }
    Ok((present.len(), grants_before))
}

/// Builds the summaries of all unexpired standing records at `now`.
pub(crate) fn summaries(
    shared: &Shared,
    s: &State,
    now: std::time::SystemTime,
) -> Result<Vec<StandingRecordSummary>, RpcError> {
    let v = s.unlocked()?;
    let items = v.items();
    Ok(s.standing()
        .records(now)
        .map(|r| r.summary(now, &shared.catalog, items))
        .collect())
}

/// `standing.list`.
pub fn standing_list(
    shared: &Shared,
    _peer: &PeerIdentity,
    _p: NoParams,
) -> Result<StandingListView, RpcError> {
    let now = now_of(&shared.clocks);
    let mut s = locked(&shared.state);
    s.unlocked()?;
    let policy_epoch_unverified = s.epoch_state() == EpochState::Unverified;
    let standing = summaries(shared, &s, now.wall)?;
    Ok(StandingListView {
        standing,
        policy_epoch_unverified,
    })
}

/// `standing.revoke`: tightening, no proof required.
pub fn standing_revoke(
    shared: &Shared,
    peer: &PeerIdentity,
    p: StandingRevokeParams,
) -> Result<StandingRevokedView, RpcError> {
    let mut s = locked(&shared.state);
    s.unlocked()?;
    let ids: Vec<StandingId> = match (&p.id, &p.agent, &p.project, p.all) {
        (Some(id), None, None, false) => {
            let parsed = StandingId::parse(id).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
            vec![parsed]
        }
        (None, Some(agent), None, false) => s
            .standing()
            .all_records()
            .filter(|r| {
                r.agent_id == *agent
                    || shared
                        .catalog
                        .name(&r.agent_id)
                        .is_some_and(|n| n.eq_ignore_ascii_case(agent))
            })
            .map(|r| r.id)
            .collect(),
        (None, None, Some(project), false) => {
            let want = std::path::Path::new(project);
            s.standing()
                .all_records()
                .filter(|r| r.project.canonical_dir == want)
                .map(|r| r.id)
                .collect()
        }
        (None, None, None, true) => s.standing().all_records().map(|r| r.id).collect(),
        _ => return Err(RpcError::new(ErrorKind::InvalidParams)),
    };
    let (revoked, grants) = delete_records_inner(&mut s, &ids, p.all)?;
    s.audit(AuditEvent::StandingRevoked {
        pid: peer.pid,
        revoked,
        grants,
        reason: None,
    });
    Ok(StandingRevokedView {
        revoked: u64::try_from(revoked).unwrap_or(u64::MAX),
        grants_ended: u64::try_from(grants).unwrap_or(u64::MAX),
    })
}

/// `standing.confirm`: verifies the confirmation statement digest and a
/// passphrase proof from a terminal prover, then writes `<data>/policy-epoch`
/// and transitions to [`EpochState::Verified`].
pub fn standing_confirm(
    shared: &Shared,
    peer: &PeerIdentity,
    p: StandingConfirmParams,
) -> Result<StandingConfirmedView, RpcError> {
    let pass = p.passphrase.map(|w| w.into_inner());
    let digest = digest_of(&p.digest).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    refuse_if_traced()?;
    let caller: SubjectEvidence = evidence(shared, peer, &p.claims)?;
    refuse_unless_prover_beside_pending(shared, peer, &caller, "standing.confirm")?;
    let _gate = locked(&shared.proof_gate);
    let (vault, generation, pass) = {
        let mut s = locked(&shared.state);
        let now = now_of(&shared.clocks);
        let records = summaries(shared, &s, now.wall)?;
        if confirm_statement_digest(&records) != digest {
            return Err(RpcError::new(ErrorKind::StatementMismatch));
        }
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
            if let Some(r) = requester_terminal_in(&mut s, &caller, &now) {
                s.audit(AuditEvent::ProofRefused {
                    pid: peer.pid,
                    method: "standing.confirm",
                    reason: r.token(),
                });
                return Err(RpcError::with_reason(ErrorKind::ProofRefused, r.token()));
            }
            let records = summaries(shared, &s, now.wall)?;
            if confirm_statement_digest(&records) != digest {
                return Err(RpcError::new(ErrorKind::StatementMismatch));
            }
            let floor = sidecar_generation_floor(&s)?;
            {
                let v = s.unlocked_mut()?;
                v.transact(|txn| {
                    txn.advance_standing_set(floor);
                    Ok(())
                })
                .map_err(|e| match e.kind() {
                    VaultErrorKind::ReadOnly | VaultErrorKind::Tampered => {
                        RpcError::new(ErrorKind::VaultTampered)
                    }
                    k => RpcError::with_reason(ErrorKind::VaultUnavailable, vault_reason(k)),
                })?;
            }
            let epoch_gen = commit_sidecar(&mut s)?;
            s.touch(Reading::now(&shared.clocks));
            let confirmed = records.len();
            s.audit(AuditEvent::StandingConfirmed {
                pid: peer.pid,
                subject: subject_summary(peer, &caller),
                confirmed,
            });
            Ok(StandingConfirmedView {
                records: u64::try_from(confirmed).unwrap_or(u64::MAX),
                generation: epoch_gen,
            })
        }
        Err(e) if e.kind() == VaultErrorKind::Crypto(CryptoErrorKind::Unlock) => {
            s.limiter().failed(&now);
            s.audit(AuditEvent::ProofFailed {
                pid: peer.pid,
                kind: AuditKind::StandingConfirm,
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
