//! App-role signed approval handler (`app.approve`; SPEC §10b, M3 plan M3-09).

use envcloak_core::crypto::{P256_SIGNATURE_LEN, SeEnrolledUnder};
use envcloak_ipc::RpcError;
use envcloak_ipc::app::AppApproveParams;
use envcloak_ipc::proto::ErrorKind;
use envcloak_ipc::view::ApprovedView;
use envcloak_policy::{ApprovalProof, ApproveError, PendingId, ProofKind, Uses};
use envcloak_sys::PeerIdentity;

use crate::audit::AuditEvent;
use crate::clock::now_of;
use crate::lock::Reading;
use crate::requests::{
    self, approve_error, digest_of, live_refused, refresh_pending_standing, subject_summary,
};
use crate::server::{Shared, locked, refuse_if_traced};
use envcloak_core::audit::ProjectSummary;

use super::decode_fixed_bytes;

/// `app.approve`: rebuilds the canonical statement from the daemon's own
/// pending run request and `p.options`, refuses a different `p.digest`
/// (`statement_mismatch`), verifies the 64-byte raw P-256 signature over the
/// digest as a prehash with the `approve` key of an enrolled Secure Enclave
/// unlocker matching `enrolled_under` (`signature_invalid` otherwise), writes
/// the durable `approved` audit entry first, and commits the grant.
pub(crate) fn approve(
    shared: &Shared,
    peer: &PeerIdentity,
    enrolled_under: &SeEnrolledUnder,
    p: AppApproveParams,
) -> Result<ApprovedView, RpcError> {
    let id = PendingId::parse(&p.request).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let digest = digest_of(&p.digest).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let signature: [u8; P256_SIGNATURE_LEN] =
        decode_fixed_bytes(&p.signature).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    refuse_if_traced()?;
    let approver = requests::evidence(shared, peer, &p.claims)?;
    if approver.nearest_agent().is_some() || approver.claims().claims_agent() || approver.cut() {
        shared.audit(AuditEvent::ProofRefused {
            pid: peer.pid,
            method: "app.approve",
            reason: if approver.cut() { "chain_cut" } else { "agent" },
        });
        return Err(RpcError::new(ErrorKind::ProofRefused));
    }

    let home = crate::standing::home_dir();
    let mut s = locked(&shared.state);
    let now = now_of(&shared.clocks);
    let items = s.unlocked()?.items().to_vec();
    refresh_pending_standing(shared, &mut s, &id, &now, &items);

    if p.options.standing.is_some() {
        let pending_req = s
            .grants()
            .pending(&id, &now)
            .ok_or(RpcError::new(ErrorKind::NoSuchRequest))?
            .request
            .clone();
        if !s
            .grants()
            .unticked_items(&id, &p.options, &now, &items)
            .is_empty()
        {
            let who = subject_summary(peer, &approver);
            return Err(live_refused(
                &mut s, peer, who, &id, &p.options, &now, &items,
            ));
        }
        if s.epoch_state() == crate::policy_epoch::EpochState::Unverified {
            return Err(RpcError::new(ErrorKind::PolicyEpochUnverified));
        }
        let _ = s
            .standing()
            .build_record(
                &pending_req,
                &p.options,
                None,
                &shared.catalog,
                home.as_deref(),
                now.wall,
                &items,
            )
            .map_err(crate::standing::standing_error)?;
    }

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

    let Some(unlocker_id) = s
        .unlocked()?
        .verify_se_approval(enrolled_under, &digest, &signature)
    else {
        s.audit(AuditEvent::ApproveFailed {
            pid: peer.pid,
            reason: "signature_invalid",
        });
        return Err(RpcError::new(ErrorKind::SignatureInvalid));
    };

    let who = subject_summary(peer, &approver);
    let proof = ApprovalProof {
        approver,
        kind: ProofKind::SecureEnclave { unlocker_id },
    };
    let pending_req = s
        .grants()
        .pending(&id, &now)
        .ok_or(RpcError::new(ErrorKind::NoSuchRequest))?
        .request
        .clone();
    let standing_created = if let Some(standing_ttl) = p.options.standing {
        if s.epoch_state() == crate::policy_epoch::EpochState::Unverified {
            return Err(RpcError::new(ErrorKind::PolicyEpochUnverified));
        }
        let appended = s
            .standing()
            .self_update_target(
                &pending_req,
                &shared.catalog,
                home.as_deref(),
                now.wall,
                &items,
            )
            .is_some();
        let record = s
            .standing()
            .build_record(
                &pending_req,
                &p.options,
                Some(&proof),
                &shared.catalog,
                home.as_deref(),
                now.wall,
                &items,
            )
            .map_err(crate::standing::standing_error)?;
        let standing_id = record.id.to_string();
        crate::standing::put_record(&mut s, record)?;
        Some((standing_id, standing_ttl.as_secs(), appended))
    } else {
        None
    };

    let grant_id = s.grants().fresh_grant_id();
    let ttl = p.options.ttl_secs;
    let uses = match p.options.uses {
        Uses::Once => "once",
        Uses::Session => "session",
    };

    if !s.audit_delivery(AuditEvent::Approved {
        pid: peer.pid,
        request: id.to_string(),
        grant: grant_id.to_string(),
        uses,
        ttl_secs: ttl,
    }) {
        return Err(RpcError::new(ErrorKind::AuditFailed));
    }

    let opts = p.options.clone();
    let grant = match s
        .grants()
        .approve_with_id(&id, grant_id, proof, p.options, digest, &now, &items)
    {
        Ok(g) => g,
        Err(ApproveError::LiveNotTicked) => {
            return Err(live_refused(&mut s, peer, who, &id, &opts, &now, &items));
        }
        Err(e) => return Err(approve_error(e)),
    };
    s.touch(Reading::now(&shared.clocks));
    if let Some((ref standing_id, standing_secs, appended)) = standing_created {
        s.audit(AuditEvent::StandingCreated {
            pid: peer.pid,
            subject: who,
            standing: standing_id.clone(),
            grant: grant.to_string(),
            project: ProjectSummary {
                dir: pending_req
                    .project
                    .canonical_dir
                    .to_string_lossy()
                    .into_owned(),
                manifest_sha256: pending_req.manifest_sha256,
                approved_sha256: None,
            },
            items: pending_req
                .bindings
                .iter()
                .map(|b| (b.binding.item, b.slug.clone()))
                .collect(),
            ttl_secs: standing_secs,
            appended,
        });
    }
    let (standing, standing_expires_in_secs) = match standing_created {
        Some((id, secs, _)) => (Some(id), Some(secs)),
        None => (None, None),
    };
    Ok(ApprovedView {
        grant: grant.to_string(),
        expires_in_secs: ttl,
        standing,
        standing_expires_in_secs,
    })
}
