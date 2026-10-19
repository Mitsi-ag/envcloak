//! Secure Enclave unlocker enrolment (`app.unlocker.enroll.begin`,
//! `app.unlocker.enroll`; SPEC §10b, M3 plan D3-08).

use envcloak_core::crypto::{
    P256_PUBLIC_KEY_LEN, SeEnrolledUnder, check_p256_public_key, check_se_label,
};
use envcloak_ipc::RpcError;
use envcloak_ipc::app::{
    AppUnlockerEnrollBeginOutput, AppUnlockerEnrollBeginParams, AppUnlockerEnrollOutput,
    AppUnlockerEnrollParams,
};
use envcloak_ipc::proto::ErrorKind;
use envcloak_policy::{PENDING_TTL, PendingId, UnlockerAddRequest, UnlockerEnrollOutcome};
use envcloak_sys::PeerIdentity;

use crate::clock::now_of;
use crate::requests;
use crate::server::{Shared, locked, refuse_if_traced};

use super::{decode_fixed_bytes, hex_encode};

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
