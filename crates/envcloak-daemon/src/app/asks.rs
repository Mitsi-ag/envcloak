//! Secret-addition ask handlers: client-role `items.ask` and `items.ask_state`
//! and app-role `app.asks.list` and `app.asks.decline` (SPEC §6.3, §10b, M3
//! plan M3-14).

use std::path::Path;

use envcloak_ipc::RpcError;
use envcloak_ipc::app::{
    AppAskDeclinedView, AppAsksDeclineParams, AppAsksListParams, AppAsksListView,
};
use envcloak_ipc::proto::{AskParams, AskStateParams, ErrorKind};
use envcloak_ipc::view::AskOpenedView;
use envcloak_policy::{AskRequest, AskStateOutcome, EnvName, PENDING_TTL, PendingId};
use envcloak_sys::PeerIdentity;

use crate::audit::AuditEvent;
use crate::clock::now_of;
use crate::items::{looks_like_value, valid_account};
use crate::lock::Reading;
use crate::requests::{self, subject_summary};
use crate::server::{Shared, locked};

const MAX_NOTE_LEN: usize = 256;
const MAX_PROJECT_DIR_LEN: usize = 1024;

fn valid_note(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_NOTE_LEN
        && !s.chars().any(|c| {
            c.is_control()
                || matches!(
                    c,
                    '\u{200b}'..='\u{200f}'
                        | '\u{202a}'..='\u{202e}'
                        | '\u{2060}'..='\u{2069}'
                        | '\u{feff}'
                )
        })
}

fn valid_provider_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// Client-role `items.ask`: checks that no text field looks like a value,
/// reads caller evidence, enforces pending caps, opens a 10-minute pending ask
/// without creating any grant, and audits `ask` (`pending`).
pub(crate) fn ask(
    shared: &Shared,
    peer: &PeerIdentity,
    p: AskParams,
) -> Result<AskOpenedView, RpcError> {
    let fields = [
        p.provider.as_deref(),
        p.project_dir.as_deref(),
        p.account.as_deref(),
        p.env_hint.as_deref(),
        p.note.as_deref(),
    ];
    if fields
        .into_iter()
        .flatten()
        .any(|s| looks_like_value(shared, s))
    {
        return Err(RpcError::with_reason(
            ErrorKind::InvalidItem,
            "looks_like_value",
        ));
    }
    let provider = match p.provider.as_deref() {
        None => None,
        Some(id) => match shared.registry.as_ref() {
            Some(r) => Some(
                r.get(id)
                    .ok_or_else(|| {
                        RpcError::with_reason(ErrorKind::InvalidItem, "unknown_provider")
                    })?
                    .id
                    .to_string(),
            ),
            None => {
                if !valid_provider_id(id) {
                    return Err(RpcError::with_reason(
                        ErrorKind::InvalidItem,
                        "unknown_provider",
                    ));
                }
                Some(id.to_owned())
            }
        },
    };
    if let Some(dir) = p.project_dir.as_deref()
        && (dir.is_empty()
            || dir.len() > MAX_PROJECT_DIR_LEN
            || !Path::new(dir).is_absolute()
            || dir.chars().any(char::is_control))
    {
        return Err(RpcError::new(ErrorKind::InvalidParams));
    }
    if let Some(a) = p.account.as_deref()
        && !valid_account(a)
    {
        return Err(RpcError::with_reason(
            ErrorKind::InvalidItem,
            "invalid_account",
        ));
    }
    if let Some(e) = p.env_hint.as_deref() {
        EnvName::new(e)
            .map_err(|_| RpcError::with_reason(ErrorKind::InvalidItem, "invalid_env_name"))?;
    }
    if let Some(n) = p.note.as_deref()
        && !valid_note(n)
    {
        return Err(RpcError::new(ErrorKind::InvalidParams));
    }

    let subject = requests::evidence(shared, peer, &p.claims)?;
    let mut s = locked(&shared.state);
    let _ = s.unlocked()?;
    let now = now_of(&shared.clocks);
    s.sweep_expired_asks(&now);

    let req = AskRequest {
        subject: subject.clone(),
        provider,
        project_dir: p.project_dir,
        account: p.account,
        env_hint: p.env_hint,
        note: p.note,
    };
    let id = s
        .grants()
        .open_ask(req, &now)
        .map_err(|cap| RpcError::with_reason(ErrorKind::TooManyPending, cap.token()))?;
    s.audit(AuditEvent::Ask {
        pid: peer.pid,
        subject: subject_summary(peer, &subject),
        ask: id.to_string(),
        outcome: "pending",
        item: None,
    });
    Ok(AskOpenedView {
        ask: id.to_string(),
    })
}

/// Client-role `items.ask_state`: answers how an ask stands (`pending`,
/// `added { slug }`, `declined`, `expired`) ONLY to the requester's own
/// process tree, and `unknown` to any other tree or unknown id, within the
/// caller's root's poll limit (`busy` beyond it). Never creates a grant.
pub(crate) fn ask_state(
    shared: &Shared,
    peer: &PeerIdentity,
    p: AskStateParams,
) -> Result<AskStateOutcome, RpcError> {
    let id = PendingId::parse(&p.ask).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let caller = requests::evidence(shared, peer, &[])?;
    let mut s = locked(&shared.state);
    let now = now_of(&shared.clocks);
    s.sweep_expired_asks(&now);
    s.grants()
        .poll_ask(&id, &caller, &now)
        .map_err(|_| RpcError::new(ErrorKind::Busy))
}

/// App-role `app.asks.list`: lists pending asks, oldest first.
pub(crate) fn list(
    shared: &Shared,
    peer: &PeerIdentity,
    p: AppAsksListParams,
) -> Result<AppAsksListView, RpcError> {
    let _caller = requests::evidence(shared, peer, &p.claims)?;
    let mut s = locked(&shared.state);
    s.refuse_if_tampered()?;
    let _ = s.unlocked()?;
    let now = now_of(&shared.clocks);
    s.sweep_expired_asks(&now);
    let asks = s
        .grants()
        .pending_asks_all(&now)
        .map(|a| {
            let mut sum = a.summary.clone();
            let age = now.awake.saturating_sub(a.opened);
            sum.expires_in_secs = PENDING_TTL.saturating_sub(age).as_secs();
            sum
        })
        .collect();
    Ok(AppAsksListView { asks })
}

/// App-role `app.asks.decline`: declines an open ask (`ask_closed` if already
/// closed, declined, or expired) and audits `ask` (`declined`).
pub(crate) fn decline(
    shared: &Shared,
    peer: &PeerIdentity,
    p: AppAsksDeclineParams,
) -> Result<AppAskDeclinedView, RpcError> {
    let id = PendingId::parse(&p.ask).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let caller = requests::evidence(shared, peer, &p.claims)?;
    let mut s = locked(&shared.state);
    s.refuse_if_tampered()?;
    let _ = s.unlocked()?;
    let now = now_of(&shared.clocks);
    s.sweep_expired_asks(&now);
    let _declined = s
        .grants()
        .decline_ask(&id, &now)
        .map_err(|_| RpcError::new(ErrorKind::AskClosed))?;
    s.audit(AuditEvent::Ask {
        pid: peer.pid,
        subject: subject_summary(peer, &caller),
        ask: id.to_string(),
        outcome: "declined",
        item: None,
    });
    s.touch(Reading::now(&shared.clocks));
    Ok(AppAskDeclinedView {
        declined: id.to_string(),
    })
}
