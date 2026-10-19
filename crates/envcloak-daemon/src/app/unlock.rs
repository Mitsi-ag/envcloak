//! Secure Enclave unlock (`app.unlock.begin`, `app.unlock`; SPEC §5 steps 2
//! to 4).

use envcloak_core::crypto::{SE_RESEAL_LEN, UnlockerId};
use envcloak_ipc::RpcError;
use envcloak_ipc::app::{AppUnlockBeginOutput, AppUnlockBeginParams, AppUnlockParams};
use envcloak_ipc::proto::ErrorKind;
use envcloak_ipc::view::UnlockedView;
use envcloak_policy::PendingId;
use envcloak_sys::PeerIdentity;

use crate::lock::Reading;
use crate::server::{Shared, locked, refuse_if_traced};

use super::{decode_fixed_bytes, decode_hex};

/// `app.unlock.begin`: starts a Secure Enclave unlock.
pub(crate) fn begin(
    shared: &Shared,
    p: AppUnlockBeginParams,
) -> Result<AppUnlockBeginOutput, RpcError> {
    refuse_if_traced()?;
    let unlocker_id = match p.unlocker_id.as_deref() {
        Some(hex) => Some(UnlockerId(
            decode_hex::<16>(hex).ok_or(RpcError::new(ErrorKind::InvalidParams))?,
        )),
        None => None,
    };
    let now = Reading::now(&shared.clocks);
    locked(&shared.state).begin_se_unlock(unlocker_id, now)
}

/// `app.unlock`: finishes a Secure Enclave unlock with the HPKE-sealed VMK.
pub(crate) fn finish(
    shared: &Shared,
    peer: &PeerIdentity,
    p: AppUnlockParams,
) -> Result<UnlockedView, RpcError> {
    refuse_if_traced()?;
    let request_id =
        PendingId::parse(&p.request_id).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let sealed: [u8; SE_RESEAL_LEN] =
        decode_fixed_bytes(&p.sealed).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let now = Reading::now(&shared.clocks);
    locked(&shared.state).finish_se_unlock(peer.pid, request_id, &sealed, now)
}
