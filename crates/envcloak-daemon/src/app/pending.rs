//! App-role pending run request handlers (`app.pending.list`,
//! `app.pending.get`; SPEC §10a, §10b, M3 plan M3-09).

use envcloak_ipc::RpcError;
use envcloak_ipc::app::{
    AppPendingGetParams, AppPendingListParams, AppPendingListView, AppPendingView,
    RUN_STATEMENT_DOMAIN,
};
use envcloak_ipc::proto::ErrorKind;
use envcloak_policy::{PendingDescriptor, PendingId};
use envcloak_sys::PeerIdentity;

use crate::clock::now_of;
use crate::requests::{self, pending_view};
use crate::server::{Shared, locked};

/// `app.pending.list`: every pending run request, oldest first (at most 20),
/// with `pending.list`'s row shape plus `statement_domain`.
pub(crate) fn list(
    shared: &Shared,
    peer: &PeerIdentity,
    p: AppPendingListParams,
) -> Result<AppPendingListView, RpcError> {
    let _caller = requests::evidence(shared, peer, &p.claims)?;
    let mut s = locked(&shared.state);
    s.refuse_if_tampered()?;
    let now = now_of(&shared.clocks);
    let requests = s
        .grants()
        .pending_all(&now)
        .map(|pending| {
            let v = pending_view(pending, &now);
            AppPendingView {
                request: v.request,
                age_secs: v.age_secs,
                expires_in_secs: v.expires_in_secs,
                kind: v.kind,
                agent: v.agent,
                project: v.project,
                bindings: v.bindings,
                more_bindings: v.more_bindings,
                statement_domain: RUN_STATEMENT_DOMAIN.to_owned(),
            }
        })
        .collect();
    Ok(AppPendingListView { requests })
}

/// `app.pending.get`: the full [`PendingDescriptor`] of pending run request
/// `p.request`, with classifications and proposed test items rebuilt from the
/// current vault (L-09).
pub(crate) fn get(
    shared: &Shared,
    peer: &PeerIdentity,
    p: AppPendingGetParams,
) -> Result<PendingDescriptor, RpcError> {
    let id = PendingId::parse(&p.request).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let _caller = requests::evidence(shared, peer, &p.claims)?;
    let now = now_of(&shared.clocks);
    let mut s = locked(&shared.state);
    s.refuse_if_tampered()?;
    if s.grants().pending(&id, &now).is_none() {
        return Err(RpcError::new(ErrorKind::NoSuchRequest));
    }
    let items = s.unlocked()?.items().to_vec();
    s.grants()
        .pending_descriptor(&id, &now, &items)
        .ok_or(RpcError::new(ErrorKind::NoSuchRequest))
}
