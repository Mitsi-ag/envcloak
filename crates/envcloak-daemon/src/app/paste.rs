//! App-role sealed paste handlers (`app.paste.begin`, `app.paste.inspect`,
//! `app.paste`; SPEC §4.4, §6.3, M3 plan M3-14).

use envcloak_core::crypto::SE_SEALED_SECRET_OVERHEAD;
use envcloak_core::vault::{ItemDetails, MAX_FIELD};
use envcloak_ipc::RpcError;
use envcloak_ipc::app::{
    AppPasteBeginOutput, AppPasteBeginParams, AppPasteInspectOutput, AppPasteInspectParams,
    AppPasteParams,
};
use envcloak_ipc::proto::ErrorKind;
use envcloak_ipc::view::{AddedView, ClassificationView, LengthClass};
use envcloak_policy::PendingId;
use envcloak_sys::PeerIdentity;

use crate::audit::AuditEvent;
use crate::clock::now_of;
use crate::items::{
    DEFAULT_SLUG, RawNames, check_raw_names, check_value, commit_new_item, free_slug,
    prepare_new_item, resolve_new_slug,
};
use crate::lock::Reading;
use crate::requests::{self, subject_summary};
use crate::server::{Shared, locked, refuse_if_traced};
use crate::state::PASTE_STAGE_TTL;

use super::{decode_bytes, hex_encode};

/// `app.paste.begin`: opens a 2-minute awake-clock paste stage with a fresh
/// single-use X25519 daemon ephemeral keypair.
pub(crate) fn begin(
    shared: &Shared,
    peer: &PeerIdentity,
    p: AppPasteBeginParams,
) -> Result<AppPasteBeginOutput, RpcError> {
    refuse_if_traced()?;
    let _caller = requests::evidence(shared, peer, &p.claims)?;
    let mut s = locked(&shared.state);
    s.refuse_if_tampered()?;
    let _ = s.unlocked()?;
    let now = now_of(&shared.clocks);
    let (stage, daemon_eph_pub) = s.open_paste_stage(now.awake)?;
    Ok(AppPasteBeginOutput {
        stage: stage.to_string(),
        daemon_eph_pub: hex_encode(&daemon_eph_pub),
        expires_in_secs: PASTE_STAGE_TTL.as_secs(),
    })
}

/// `app.paste.inspect`: opens the HPKE-sealed value (`stage` AAD) into a
/// [`SecretBytes`] buffer, runs provider/classification/length detection
/// without storing or logging the secret, keeps the `SecretBytes` in the
/// 2-minute awake-clock paste stage, and returns the detection metadata.
pub(crate) fn inspect(
    shared: &Shared,
    peer: &PeerIdentity,
    p: AppPasteInspectParams,
) -> Result<AppPasteInspectOutput, RpcError> {
    refuse_if_traced()?;
    let stage_id = PendingId::parse(&p.stage).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let sealed = decode_bytes(&p.sealed, MAX_FIELD + SE_SEALED_SECRET_OVERHEAD)
        .ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let _caller = requests::evidence(shared, peer, &p.claims)?;

    let mut s = locked(&shared.state);
    s.refuse_if_tampered()?;
    let _ = s.unlocked()?;
    let now = now_of(&shared.clocks);
    let ephemeral = s
        .take_paste_ephemeral(stage_id, now.awake)
        .ok_or(RpcError::new(ErrorKind::NoSuchRequest))?;

    let value = match ephemeral.open_secret(p.stage.as_bytes(), &sealed) {
        Ok(v) => v,
        Err(_) => {
            s.remove_paste_stage(stage_id);
            return Err(RpcError::new(ErrorKind::InvalidParams));
        }
    };
    if let Err(e) = check_value(&value) {
        s.remove_paste_stage(stage_id);
        return Err(e);
    }

    let mut details = ItemDetails::default();
    let (provider, detected, ambiguous) = match shared.registry.as_ref() {
        Some(r) => {
            let d = r.detect(&value, None);
            r.prefill(&d, &mut details);
            let found = d.provider.as_ref().map(|id| id.as_str().to_owned());
            (found.clone(), found, d.ambiguous)
        }
        None => (None, None, false),
    };
    let length = LengthClass::of(value.len());
    let classification = ClassificationView::from(details.classification);
    let env_hint = details.env_hint.clone();
    let suggested_slug = {
        let v = s.unlocked()?;
        free_slug(v, provider.as_deref().unwrap_or(DEFAULT_SLUG))?
            .as_str()
            .to_owned()
    };

    if !s.store_paste_secret(stage_id, value, now.awake) {
        return Err(RpcError::new(ErrorKind::NoSuchRequest));
    }
    Ok(AppPasteInspectOutput {
        provider,
        detected,
        ambiguous,
        classification,
        length,
        suggested_slug: Some(suggested_slug),
        env_hint,
    })
}

/// `app.paste`: consumes the staged secret from `stage`, checks that `ask` (if
/// given) is open (`ask_closed` otherwise), adds the secret item to the vault,
/// resolves `ask` as `added { slug }` without creating any grant, and audits
/// `add` (and `ask` when fulfilling an ask).
pub(crate) fn paste(
    shared: &Shared,
    peer: &PeerIdentity,
    p: AppPasteParams,
) -> Result<AddedView, RpcError> {
    refuse_if_traced()?;
    let stage_id = PendingId::parse(&p.stage).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let ask_id = match p.ask.as_deref() {
        Some(raw) => Some(PendingId::parse(raw).ok_or(RpcError::new(ErrorKind::InvalidParams))?),
        None => None,
    };
    let names = check_raw_names(
        shared,
        RawNames {
            slug: p.slug.as_deref(),
            provider: p.provider.as_deref(),
            field: p.field.as_deref(),
            account: p.account.as_deref(),
            env_hint: p.env_hint.as_deref(),
        },
    )?;
    let caller = requests::evidence(shared, peer, &p.claims)?;

    let mut s = locked(&shared.state);
    s.refuse_if_tampered()?;
    let _ = s.unlocked()?;
    let now = now_of(&shared.clocks);
    s.sweep_expired_asks(&now);
    if let Some(aid) = &ask_id
        && s.grants().pending_ask(aid, &now).is_none()
    {
        return Err(RpcError::new(ErrorKind::AskClosed));
    }
    let value = s
        .take_paste_secret(stage_id, now.awake)
        .ok_or(RpcError::new(ErrorKind::NoSuchRequest))?;

    let (details, detected, ambiguous, length) =
        prepare_new_item(shared, &names, p.allow_short, &value);
    let (id, slug, field, item) = {
        let v = s.unlocked_mut()?;
        let slug = resolve_new_slug(v, names.slug, details.provider.as_deref())?;
        commit_new_item(v, slug, names.field, details, value)?
    };
    let who = subject_summary(peer, &caller);
    s.audit(AuditEvent::Added {
        pid: peer.pid,
        subject: who.clone(),
        item: id,
        slug: slug.clone(),
    });
    if let Some(aid) = ask_id {
        let _resolved = s
            .grants()
            .resolve_ask_added(&aid, &slug, &now)
            .map_err(|_| RpcError::new(ErrorKind::AskClosed))?;
        s.audit(AuditEvent::Ask {
            pid: peer.pid,
            subject: who,
            ask: aid.to_string(),
            outcome: "added",
            item: Some((id, slug)),
        });
    }
    s.touch(Reading::now(&shared.clocks));
    Ok(AddedView {
        item,
        field: field.as_str().to_owned(),
        detected,
        ambiguous,
        length,
    })
}
