//! App-role lock (`app.lock`; SPEC §5 "Lock", §10b, D3-11, M3-16).

use envcloak_ipc::RpcError;
use envcloak_ipc::app::{AppLockParams, AppLockReason};
use envcloak_ipc::view::{LockReason, LockedView};

use crate::backups;
use crate::server::{Shared, locked};

/// `app.lock`: locks the vault for `screen_lock`, `session_resign`, or `user`
/// (`request`). Answered whatever an `app` peer's caller evidence is, since
/// locking only tightens.
pub(crate) fn lock(shared: &Shared, p: AppLockParams) -> Result<LockedView, RpcError> {
    let reason = match p.reason {
        AppLockReason::ScreenLock => LockReason::ScreenLock,
        AppLockReason::SessionResign => LockReason::SessionResign,
        AppLockReason::User => LockReason::Request,
    };
    let was_unlocked = locked(&shared.state).lock(reason);
    if was_unlocked {
        log_line!("envcloakd: vault locked (reason: {})", reason.as_str());
    }
    backups::wait_for_deliveries(&shared.state, &shared.deliveries);
    envcloak_sys::test_event("lock answered");
    Ok(LockedView { was_unlocked })
}
