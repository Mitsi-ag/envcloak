//! Secure Enclave unlocker enrolment and removal (`app.unlocker.enroll.begin`,
//! `app.unlocker.enroll`, `app.unlocker.add`, `app.unlocker.remove`;
//! SPEC §5, §10b, M3 plan D3-08, M3-14).

use envcloak_core::crypto::{
    P256_PUBLIC_KEY_LEN, P256_SIGNATURE_LEN, SeEnrolledUnder, SeUnlockerRecord, UnlockerId,
    UnlockerKind, check_p256_public_key, check_se_label, p256_fingerprint,
};
use envcloak_ipc::RpcError;
use envcloak_ipc::app::{
    AppUnlockerAddParams, AppUnlockerAddedView, AppUnlockerEnrollBeginOutput,
    AppUnlockerEnrollBeginParams, AppUnlockerEnrollOutput, AppUnlockerEnrollParams,
    AppUnlockerRemoveParams, AppUnlockerRemovedView,
};
use envcloak_ipc::proto::ErrorKind;
use envcloak_policy::{
    PENDING_TTL, PendingId, UnlockerAddRequest, UnlockerEnrollOutcome, UnlockerTarget, WriteAction,
    WriteStatement, write_statement_digest,
};
use envcloak_sys::PeerIdentity;

use crate::audit::AuditEvent;
use crate::clock::now_of;
use crate::lock::Reading;
use crate::requests::{self, digest_of, subject_summary};
use crate::server::{Shared, locked, refuse_if_traced};
use crate::state::UnlockerWriteKind;

use super::{decode_fixed_bytes, decode_hex, hex_encode};

/// `app.unlocker.enroll.begin`: opens a pending `unlocker_add` request for
/// `envcloak approve <id>`.
pub(crate) fn begin(
    shared: &Shared,
    peer: &PeerIdentity,
    enrolled_under: &SeEnrolledUnder,
    p: AppUnlockerEnrollBeginParams,
) -> Result<AppUnlockerEnrollBeginOutput, RpcError> {
    refuse_if_traced()?;
    let subject = requests::evidence(shared, peer, &p.claims)?;
    let unlock_pub: [u8; P256_PUBLIC_KEY_LEN] =
        decode_fixed_bytes(&p.unlock_pub).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let approve_pub: [u8; P256_PUBLIC_KEY_LEN] =
        decode_fixed_bytes(&p.approve_pub).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    check_p256_public_key(&unlock_pub).map_err(|_| RpcError::new(ErrorKind::InvalidParams))?;
    check_p256_public_key(&approve_pub).map_err(|_| RpcError::new(ErrorKind::InvalidParams))?;
    if unlock_pub == approve_pub {
        return Err(RpcError::new(ErrorKind::InvalidParams));
    }
    check_se_label(&p.label).map_err(|_| RpcError::new(ErrorKind::InvalidParams))?;

    let mut s = locked(&shared.state);
    let vault_id = s.unlocked()?.vault_id();
    let now = now_of(&shared.clocks);
    let req = UnlockerAddRequest {
        subject,
        vault_id,
        unlock_pub,
        approve_pub,
        label: p.label,
        enrolled_under: enrolled_under.clone(),
    };
    let id = s
        .grants()
        .open_unlocker_add(req, &now)
        .map_err(|cap| RpcError::with_reason(ErrorKind::TooManyPending, cap.token()))?;
    Ok(AppUnlockerEnrollBeginOutput {
        request: id.to_string(),
        expires_in_secs: PENDING_TTL.as_secs(),
    })
}

/// `app.unlocker.enroll`: polls the outcome of a pending `unlocker_add`
/// request.
pub(crate) fn poll(
    shared: &Shared,
    p: AppUnlockerEnrollParams,
) -> Result<AppUnlockerEnrollOutput, RpcError> {
    let id = PendingId::parse(&p.request).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let mut s = locked(&shared.state);
    let _ = s.unlocked()?;
    let now = now_of(&shared.clocks);
    match s.grants().unlocker_enroll_outcome(&id, &now) {
        Some(UnlockerEnrollOutcome::Pending) => Ok(AppUnlockerEnrollOutput::Pending),
        Some(UnlockerEnrollOutcome::Enrolled(uid)) => Ok(AppUnlockerEnrollOutput::Enrolled {
            unlocker_id: hex_encode(&uid.0),
        }),
        Some(UnlockerEnrollOutcome::Denied) => Ok(AppUnlockerEnrollOutput::Denied),
        Some(UnlockerEnrollOutcome::Expired) => Ok(AppUnlockerEnrollOutput::Expired),
        None => Err(RpcError::new(ErrorKind::NoSuchRequest)),
    }
}

/// `app.unlocker.add`: enrolls a new Secure Enclave unlocker signed by an
/// existing enrolled Secure Enclave `approve` key under
/// `envcloak-write-statement/1`.
pub(crate) fn add(
    shared: &Shared,
    peer: &PeerIdentity,
    enrolled_under: &SeEnrolledUnder,
    p: AppUnlockerAddParams,
) -> Result<AppUnlockerAddedView, RpcError> {
    refuse_if_traced()?;
    let unlock_pub: [u8; P256_PUBLIC_KEY_LEN] =
        decode_fixed_bytes(&p.unlock_pub).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let approve_pub: [u8; P256_PUBLIC_KEY_LEN] =
        decode_fixed_bytes(&p.approve_pub).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    check_p256_public_key(&unlock_pub).map_err(|_| RpcError::new(ErrorKind::InvalidParams))?;
    check_p256_public_key(&approve_pub).map_err(|_| RpcError::new(ErrorKind::InvalidParams))?;
    if unlock_pub == approve_pub {
        return Err(RpcError::new(ErrorKind::InvalidParams));
    }
    check_se_label(&p.label).map_err(|_| RpcError::new(ErrorKind::InvalidParams))?;
    let nonce: [u8; 32] =
        decode_fixed_bytes(&p.nonce).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let digest = digest_of(&p.digest).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let signature: [u8; P256_SIGNATURE_LEN] =
        decode_fixed_bytes(&p.signature).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let caller = requests::evidence(shared, peer, &p.claims)?;

    let mut s = locked(&shared.state);
    let now = now_of(&shared.clocks);
    let vault_id = s.unlocked()?.vault_id();
    let unlock_fp = p256_fingerprint(&unlock_pub);
    let approve_fp = p256_fingerprint(&approve_pub);
    let stmt = WriteStatement {
        target: "unlocker_add".to_owned(),
        nonce: hex_encode(&nonce),
        vault_id: hex_encode(&vault_id.0),
        action: WriteAction::UnlockerAdd {
            label: p.label.clone(),
            unlock_pub_sha256: hex_encode(&unlock_fp),
            approve_pub_sha256: hex_encode(&approve_fp),
            team_id: enrolled_under.team_id.clone(),
            signing_id: enrolled_under.signing_id.clone(),
        },
    };
    let expected = write_statement_digest(&stmt);
    if expected != digest {
        return Err(RpcError::new(ErrorKind::StatementMismatch));
    }
    if s.unlocked()?
        .verify_se_approval(enrolled_under, &digest, &signature)
        .is_none()
    {
        s.audit(AuditEvent::ApproveFailed {
            pid: peer.pid,
            reason: "signature_invalid",
        });
        return Err(RpcError::new(ErrorKind::SignatureInvalid));
    }
    let Some(ut) = s.take_unlocker_write_target(&nonce, UnlockerWriteKind::Add, now.awake) else {
        return Err(RpcError::new(ErrorKind::StatementMismatch));
    };
    if ut.vault_id != vault_id {
        return Err(RpcError::new(ErrorKind::StatementMismatch));
    }

    let unlocker_id = {
        let v = s.unlocked()?;
        loop {
            let candidate = UnlockerId::generate();
            if v.unlocker(candidate).is_none() && v.se_unlocker(candidate).is_none() {
                break candidate;
            }
        }
    };
    let _ = p.created_secs;
    let now_secs = now
        .wall
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let record = SeUnlockerRecord {
        unlocker_id,
        unlock_pub,
        approve_pub,
        label: p.label.clone(),
        created_secs: now_secs,
        enrolled_under: enrolled_under.clone(),
    };
    let unlocker_hex = hex_encode(&unlocker_id.0);
    let audit_event = AuditEvent::UnlockerAdd {
        pid: peer.pid,
        subject: subject_summary(peer, &caller),
        request: "app.unlocker.add".to_owned(),
        unlocker: unlocker_hex.clone(),
        label: p.label,
        unlock_pub_sha256: unlock_fp,
        approve_pub_sha256: approve_fp,
    };
    s.enroll_se_unlocker(record, audit_event)?;
    s.touch(Reading::now(&shared.clocks));
    Ok(AppUnlockerAddedView {
        unlocker_id: unlocker_hex,
    })
}

/// `app.unlocker.remove`: removes the passphrase unlocker or a Secure Enclave
/// unlocker signed by an enrolled Secure Enclave `approve` key under
/// `envcloak-write-statement/1`.
pub(crate) fn remove(
    shared: &Shared,
    peer: &PeerIdentity,
    enrolled_under: &SeEnrolledUnder,
    p: AppUnlockerRemoveParams,
) -> Result<AppUnlockerRemovedView, RpcError> {
    refuse_if_traced()?;
    let nonce: [u8; 32] =
        decode_fixed_bytes(&p.nonce).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let digest = digest_of(&p.digest).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let signature: [u8; P256_SIGNATURE_LEN] =
        decode_fixed_bytes(&p.signature).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let _ = p.created_secs;
    if p.unlocker.is_empty() {
        return Err(RpcError::new(ErrorKind::InvalidParams));
    }
    let caller = requests::evidence(shared, peer, &p.claims)?;

    let mut s = locked(&shared.state);
    let now = now_of(&shared.clocks);
    let vault = s.unlocked()?;
    let vault_id = vault.vault_id();
    let (unlocker_id, target, kind_str, label, unlock_fp, approve_fp) = if p.unlocker
        == "passphrase"
    {
        let env = vault
            .unlockers()
            .find(|e| e.kind() == UnlockerKind::Passphrase)
            .ok_or(RpcError::new(ErrorKind::NoUnlocker))?;
        (
            env.unlocker_id(),
            UnlockerTarget::Passphrase,
            "passphrase",
            None,
            None,
            None,
        )
    } else if p.unlocker == "recovery_kit" {
        return Err(RpcError::new(ErrorKind::NoUnlocker));
    } else {
        let raw = decode_hex::<16>(&p.unlocker).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
        let id = UnlockerId(raw);
        if let Some(env) = vault.unlocker(id) {
            match env.kind() {
                UnlockerKind::Passphrase => (
                    id,
                    UnlockerTarget::Passphrase,
                    "passphrase",
                    None,
                    None,
                    None,
                ),
                UnlockerKind::RecoveryKit | UnlockerKind::SecureEnclave => {
                    return Err(RpcError::new(ErrorKind::NoUnlocker));
                }
            }
        } else if let Some(se) = vault.se_unlocker(id) {
            let rec = se.record();
            let lbl = rec.label.clone();
            let u_fp = p256_fingerprint(&rec.unlock_pub);
            let a_fp = p256_fingerprint(&rec.approve_pub);
            (
                id,
                UnlockerTarget::SecureEnclave {
                    unlocker_id: hex_encode(&id.0),
                    label: lbl.clone(),
                    unlock_pub_sha256: hex_encode(&u_fp),
                    approve_pub_sha256: hex_encode(&a_fp),
                },
                "secure_enclave",
                Some(lbl),
                Some(u_fp),
                Some(a_fp),
            )
        } else {
            return Err(RpcError::new(ErrorKind::NoUnlocker));
        }
    };

    let stmt = WriteStatement {
        target: "unlocker_remove".to_owned(),
        nonce: hex_encode(&nonce),
        vault_id: hex_encode(&vault_id.0),
        action: WriteAction::UnlockerRemove { unlocker: target },
    };
    let expected = write_statement_digest(&stmt);
    if expected != digest {
        return Err(RpcError::new(ErrorKind::StatementMismatch));
    }
    if s.unlocked()?
        .verify_se_approval(enrolled_under, &digest, &signature)
        .is_none()
    {
        s.audit(AuditEvent::ApproveFailed {
            pid: peer.pid,
            reason: "signature_invalid",
        });
        return Err(RpcError::new(ErrorKind::SignatureInvalid));
    }
    let Some(ut) = s.take_unlocker_write_target(&nonce, UnlockerWriteKind::Remove, now.awake)
    else {
        return Err(RpcError::new(ErrorKind::StatementMismatch));
    };
    if ut.vault_id != vault_id {
        return Err(RpcError::new(ErrorKind::StatementMismatch));
    }

    let unlocker_hex = hex_encode(&unlocker_id.0);
    let audit_event = AuditEvent::UnlockerRemove {
        pid: peer.pid,
        subject: subject_summary(peer, &caller),
        unlocker: unlocker_hex.clone(),
        kind: kind_str,
        label,
        unlock_pub_sha256: unlock_fp,
        approve_pub_sha256: approve_fp,
    };
    s.remove_daily_unlocker(unlocker_id, audit_event)?;
    s.touch(Reading::now(&shared.clocks));
    Ok(AppUnlockerRemovedView {
        removed: unlocker_hex,
    })
}
