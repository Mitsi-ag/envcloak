//! Signed reveal handlers: client-role `reveal.request` and app-role
//! `app.reveal.begin` and `app.reveal` (`envcloak-reveal-statement/1`;
//! SPEC §6.7, §10b, M3 plan M3-14).

use envcloak_core::audit::AuditKind;
use envcloak_core::crypto::{
    P256_SIGNATURE_LEN, SeEnrolledUnder, X25519_PUBLIC_KEY_LEN, se_reveal_aad,
    seal_secret_to_x25519,
};
use envcloak_ipc::app::{AppRevealBeginParams, AppRevealOutput, AppRevealParams};
use envcloak_ipc::proto::{AppReveal, ErrorKind, RevealRequestParams};
use envcloak_ipc::view::RevealRequestedView;
use envcloak_ipc::{Frame, RpcError};
use envcloak_policy::{PendingId, RevealDescriptor, RevealRequestSpec, reveal_statement_digest};
use envcloak_sys::PeerIdentity;

use crate::audit::AuditEvent;
use crate::clock::now_of;
use crate::items::{refuse_item_prover, target as resolve_target};
use crate::lock::Reading;
use crate::requests::{self, digest_of, refuse_unless_prover, subject_summary};
use crate::server::{Shared, commit_framed, locked, refuse_if_traced};
use crate::state::vault_reason;

use super::{decode_fixed_bytes, hex_encode};

/// Client-role `reveal.request`: refuses agent, unknown or terminal-less
/// callers (`proof_refused`, audited) before filing (SPEC §6.7, §10b), resolves
/// the target secret item and field, and opens a 10-minute pending reveal
/// request under the pending caps.
pub(crate) fn request(
    shared: &Shared,
    peer: &PeerIdentity,
    p: RevealRequestParams,
) -> Result<RevealRequestedView, RpcError> {
    refuse_if_traced()?;
    let caller = requests::evidence(shared, peer, &p.claims)?;
    refuse_unless_prover(shared, peer, &caller, "reveal.request")?;

    let mut s = locked(&shared.state);
    let now = now_of(&shared.clocks);
    refuse_item_prover(&mut s, peer, &caller, &now, "reveal.request")?;
    let (vault_id, t, field_id, field_name, classification) = {
        let v = s.unlocked()?;
        if v.se_unlockers().next().is_none() {
            return Err(RpcError::new(ErrorKind::NoUnlocker));
        }
        let t = resolve_target(v, &p.slug, p.field.as_deref(), None)?;
        let (fid, fname) = t
            .field
            .clone()
            .ok_or_else(|| RpcError::with_reason(ErrorKind::NoSuchItem, "ambiguous_field"))?;
        let meta = v.item(t.item).ok_or(RpcError::new(ErrorKind::Internal))?;
        (v.vault_id(), t, fid, fname, meta.details.classification)
    };
    let id = s
        .grants()
        .open_reveal_request(
            RevealRequestSpec {
                requester: Some(caller),
                vault_id,
                item: t.item,
                slug: t.slug,
                field: field_id,
                field_name,
                classification,
            },
            &now,
        )
        .map_err(|cap| RpcError::with_reason(ErrorKind::TooManyPending, cap.token()))?;
    Ok(RevealRequestedView {
        request: id.to_string(),
    })
}

/// App-role `app.reveal.begin`: returns the [`RevealDescriptor`] for an
/// existing pending `reveal.request` (`request` set) or opens a 60-second
/// app-initiated reveal stage (`slug` and optional `field` set).
pub(crate) fn begin(
    shared: &Shared,
    peer: &PeerIdentity,
    p: AppRevealBeginParams,
) -> Result<RevealDescriptor, RpcError> {
    refuse_if_traced()?;
    let _caller = requests::evidence(shared, peer, &p.claims)?;

    match (p.request.as_deref(), p.slug.as_deref()) {
        (req_opt, None) => {
            if p.field.is_some() {
                return Err(RpcError::new(ErrorKind::InvalidParams));
            }
            let id_opt = match req_opt {
                Some(req_str) => {
                    Some(PendingId::parse(req_str).ok_or(RpcError::new(ErrorKind::InvalidParams))?)
                }
                None => None,
            };
            let mut s = locked(&shared.state);
            s.refuse_if_tampered()?;
            let now = now_of(&shared.clocks);
            let pending = match id_opt {
                Some(id) => s.grants().pending_reveal(&id, &now).cloned(),
                None => s.grants().oldest_pending_client_reveal(&now).cloned(),
            }
            .ok_or(RpcError::new(ErrorKind::NoSuchRequest))?;
            let v = s.unlocked()?;
            if v.vault_id() != pending.spec.vault_id {
                return Err(RpcError::new(ErrorKind::NoSuchRequest));
            }
            let t = resolve_target(
                v,
                pending.spec.slug.as_str(),
                Some(pending.spec.field_name.as_str()),
                Some(&pending.spec.item.to_string()),
            )?;
            if t.field.as_ref().map(|(fid, _)| *fid) != Some(pending.spec.field) {
                return Err(RpcError::with_reason(
                    ErrorKind::NoSuchItem,
                    "unknown_field",
                ));
            }
            pending
                .current(v.items())
                .ok_or(RpcError::new(ErrorKind::NoSuchItem))
        }
        (None, Some(slug)) => {
            let mut s = locked(&shared.state);
            s.refuse_if_tampered()?;
            let now = now_of(&shared.clocks);
            let (vault_id, t, field_id, field_name, classification) = {
                let v = s.unlocked()?;
                let t = resolve_target(v, slug, p.field.as_deref(), None)?;
                let (fid, fname) = t.field.clone().ok_or_else(|| {
                    RpcError::with_reason(ErrorKind::NoSuchItem, "ambiguous_field")
                })?;
                let meta = v.item(t.item).ok_or(RpcError::new(ErrorKind::Internal))?;
                (v.vault_id(), t, fid, fname, meta.details.classification)
            };
            let id = s.grants().open_app_reveal(
                RevealRequestSpec {
                    requester: None,
                    vault_id,
                    item: t.item,
                    slug: t.slug,
                    field: field_id,
                    field_name,
                    classification,
                },
                &now,
            );
            s.grants()
                .pending_reveal(&id, &now)
                .map(|r| r.descriptor.clone())
                .ok_or(RpcError::new(ErrorKind::Internal))
        }
        _ => Err(RpcError::new(ErrorKind::InvalidParams)),
    }
}

/// App-role `app.reveal`: verifies the `envcloak-reveal-statement/1` digest and
/// P-256 signature against an enrolled Secure Enclave `approve` key matching
/// `enrolled_under`, HPKE-seals the secret value to `app_eph_pub` with AAD
/// `request || nonce`, writes the durable `reveal_app` audit entry BEFORE
/// releasing (gate 33), and returns the framed ciphertext.
pub(crate) fn reveal(
    shared: &Shared,
    peer: &PeerIdentity,
    enrolled_under: &SeEnrolledUnder,
    id: u64,
    p: AppRevealParams,
) -> Result<Frame, RpcError> {
    refuse_if_traced()?;
    let req_id = PendingId::parse(&p.request).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let digest = digest_of(&p.digest).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let signature: [u8; P256_SIGNATURE_LEN] =
        decode_fixed_bytes(&p.signature).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let app_eph_pub: [u8; X25519_PUBLIC_KEY_LEN] =
        decode_fixed_bytes(&p.app_eph_pub).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let caller = requests::evidence(shared, peer, &p.claims)?;

    let mut s = locked(&shared.state);
    let _ = s.unlocked()?;
    let now = now_of(&shared.clocks);
    let pending = s
        .grants()
        .pending_reveal(&req_id, &now)
        .cloned()
        .ok_or(RpcError::new(ErrorKind::NoSuchRequest))?;

    let mut current_desc = {
        let v = s.unlocked()?;
        if v.vault_id() != pending.spec.vault_id {
            return Err(RpcError::new(ErrorKind::StatementMismatch));
        }
        let t = resolve_target(
            v,
            pending.spec.slug.as_str(),
            Some(pending.spec.field_name.as_str()),
            Some(&pending.spec.item.to_string()),
        )?;
        if t.field.as_ref().map(|(fid, _)| *fid) != Some(pending.spec.field) {
            return Err(RpcError::with_reason(
                ErrorKind::NoSuchItem,
                "unknown_field",
            ));
        }
        let meta = v
            .item(pending.spec.item)
            .ok_or(RpcError::new(ErrorKind::Internal))?;
        if meta.details.classification != pending.spec.classification {
            return Err(RpcError::new(ErrorKind::StatementMismatch));
        }
        pending
            .current(v.items())
            .ok_or(RpcError::new(ErrorKind::NoSuchItem))?
    };
    current_desc.app_eph_pub = hex_encode(&app_eph_pub);

    let expected = reveal_statement_digest(&current_desc);
    if expected != digest {
        return Err(RpcError::new(ErrorKind::StatementMismatch));
    }
    if s.unlocked()?
        .verify_se_approval(enrolled_under, &digest, &signature)
        .is_none()
    {
        s.audit(AuditEvent::ItemProofFailed {
            pid: peer.pid,
            write: AuditKind::RevealApp,
            item: pending.spec.item,
            slug: pending.spec.slug,
        });
        return Err(RpcError::new(ErrorKind::SignatureInvalid));
    }

    let value = s
        .unlocked()?
        .read_value(pending.spec.field)
        .map_err(|e| RpcError::with_reason(ErrorKind::VaultUnavailable, vault_reason(e.kind())))?;
    let aad = se_reveal_aad(&pending.id.to_string(), &pending.nonce, &app_eph_pub);
    let sealed = seal_secret_to_x25519(&app_eph_pub, &aad, &value)
        .map_err(|_| RpcError::new(ErrorKind::InvalidParams))?;
    drop(value);

    let out = AppRevealOutput {
        sealed_value: hex_encode(&sealed),
    };
    let frame = commit_framed::<AppReveal>(id, &out, || {
        if !s.audit_delivery(AuditEvent::RevealedApp {
            pid: peer.pid,
            subject: subject_summary(peer, &caller),
            request: pending.id.to_string(),
            item: pending.spec.item,
            slug: pending.spec.slug.clone(),
        }) {
            return Err(RpcError::new(ErrorKind::AuditFailed));
        }
        let _ = s.grants().take_pending_reveal(&req_id, &now);
        Ok(())
    })?;
    s.touch(Reading::now(&shared.clocks));
    Ok(frame)
}
