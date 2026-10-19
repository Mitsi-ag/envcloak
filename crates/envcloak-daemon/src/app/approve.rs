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
use crate::requests::{self, approve_error, digest_of, live_refused, subject_summary};
use crate::server::{Shared, locked, refuse_if_traced};

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

    let mut s = locked(&shared.state);
    let now = now_of(&shared.clocks);
    let items = s.unlocked()?.items().to_vec();

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

    let who = subject_summary(peer, &approver);
    let proof = ApprovalProof {
        approver,
        kind: ProofKind::SecureEnclave { unlocker_id },
    };
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
    Ok(ApprovedView {
        grant: grant.to_string(),
        expires_in_secs: ttl,
    })
}
