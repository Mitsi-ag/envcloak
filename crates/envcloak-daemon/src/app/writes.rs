//! App-role signed item writes (`app.items.target`, `app.items.rotate`,
//! `app.items.remove`; SPEC §10b, M3 plan M3-14).

use envcloak_core::audit::AuditKind;
use envcloak_core::crypto::{
    P256_SIGNATURE_LEN, SE_SEALED_SECRET_OVERHEAD, SeEnrolledUnder, SeEphemeralKey,
    generate_se_challenge, se_reseal_aad, secret_sha256,
};
use envcloak_core::vault::{ItemDetails, MAX_FIELD};
use envcloak_ipc::RpcError;
use envcloak_ipc::app::{
    AppItemsRemoveParams, AppItemsRotateParams, AppItemsTargetOutput, AppItemsTargetParams,
};
use envcloak_ipc::proto::ErrorKind;
use envcloak_ipc::view::{ClassificationView, LengthClass, RemovedView, RotatedView};
use envcloak_policy::{PendingId, WriteAction, WriteStatement, write_statement_digest};
use envcloak_sys::PeerIdentity;

use crate::audit::AuditEvent;
use crate::clock::now_of;
use crate::items::{check_value, detected_class, target as resolve_target, write_error};
use crate::lock::Reading;
use crate::requests::{self, digest_of, subject_summary};
use crate::server::{Shared, locked, refuse_if_traced};
use crate::state::{WRITE_TARGET_TTL, WriteTarget, backup_reason};

use super::{decode_bytes, decode_fixed_bytes, hex_encode};

/// `app.items.target`: resolves the target item (and field) in the unlocked
/// vault, records a 60-second single-use write target with a 32-byte nonce and
/// X25519 ephemeral keypair, and returns the statement inputs.
pub(crate) fn target(
    shared: &Shared,
    peer: &PeerIdentity,
    p: AppItemsTargetParams,
) -> Result<AppItemsTargetOutput, RpcError> {
    refuse_if_traced()?;
    let _caller = requests::evidence(shared, peer, &p.claims)?;
    let mut s = locked(&shared.state);
    s.refuse_if_tampered()?;
    let now = now_of(&shared.clocks);
    let (vault_id, t, classification, prior_count) = {
        let v = s.unlocked()?;
        let t = resolve_target(v, &p.slug, p.field.as_deref(), None)?;
        let meta = v.item(t.item).ok_or(RpcError::new(ErrorKind::Internal))?;
        let prior_count = match &t.field {
            Some((fid, _)) => meta
                .fields
                .iter()
                .find(|f| f.id == *fid)
                .map(|f| f.prior_count)
                .ok_or(RpcError::new(ErrorKind::Internal))?,
            None => 0,
        };
        (v.vault_id(), t, meta.details.classification, prior_count)
    };
    let grants = u64::try_from(s.grants().binding_item(t.item)).unwrap_or(u64::MAX);
    let target_id = s.fresh_write_target_id();
    let nonce = generate_se_challenge().map_err(|_| RpcError::new(ErrorKind::Internal))?;
    let ephemeral = SeEphemeralKey::generate().map_err(|_| RpcError::new(ErrorKind::Internal))?;
    let daemon_eph_pub = *ephemeral.public_key();
    let created_secs = now
        .wall
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let (field_id_str, field_name_str) = match &t.field {
        Some((fid, fname)) => (Some(fid.to_string()), Some(fname.as_str().to_owned())),
        None => (None, None),
    };
    s.open_write_target(
        WriteTarget {
            target: target_id,
            nonce,
            ephemeral,
            vault_id,
            item: t.item,
            slug: t.slug.clone(),
            field: t.field,
            classification,
            prior_count,
            grants,
            opened_awake: now.awake,
        },
        now.awake,
    );
    Ok(AppItemsTargetOutput {
        target: target_id.to_string(),
        nonce: hex_encode(&nonce),
        daemon_eph_pub: hex_encode(&daemon_eph_pub),
        vault_id: hex_encode(&vault_id.0),
        item: t.item.to_string(),
        slug: t.slug.as_str().to_owned(),
        field: field_id_str,
        field_name: field_name_str,
        classification: ClassificationView::from(classification),
        prior_count,
        grants,
        created_secs,
        expires_in_secs: WRITE_TARGET_TTL.as_secs(),
    })
}

/// `app.items.rotate`: opens the HPKE-sealed value (`target || nonce` AAD),
/// rebuilds the `envcloak-write-statement/1` `rotate` statement, verifies the
/// digest and P-256 signature against an enrolled Secure Enclave `approve` key
/// matching `enrolled_under`, rotates the field keeping prior values, updates
/// classification on single-field secret items (ending bound grants on change,
/// F-47), clears exposure if replaced, and audits `rotate`.
pub(crate) fn rotate(
    shared: &Shared,
    peer: &PeerIdentity,
    enrolled_under: &SeEnrolledUnder,
    p: AppItemsRotateParams,
) -> Result<RotatedView, RpcError> {
    refuse_if_traced()?;
    let target_id = PendingId::parse(&p.target).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let sealed = decode_bytes(&p.sealed_value, MAX_FIELD + SE_SEALED_SECRET_OVERHEAD)
        .ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let digest = digest_of(&p.digest).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let signature: [u8; P256_SIGNATURE_LEN] =
        decode_fixed_bytes(&p.signature).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let caller = requests::evidence(shared, peer, &p.claims)?;

    let mut s = locked(&shared.state);
    let _ = s.unlocked()?;
    let now = now_of(&shared.clocks);
    let wt = s
        .take_write_target(target_id, now.awake)
        .ok_or(RpcError::new(ErrorKind::NoSuchRequest))?;
    let (field_id, field_name) = wt
        .field
        .clone()
        .ok_or_else(|| RpcError::with_reason(ErrorKind::NoSuchItem, "ambiguous_field"))?;

    let aad = se_reseal_aad(&wt.target.to_string(), &wt.nonce);
    let value = wt
        .ephemeral
        .open_secret(&aad, &sealed)
        .map_err(|_| RpcError::new(ErrorKind::InvalidParams))?;
    check_value(&value)?;
    let new_value_sha256 = secret_sha256(&value);

    {
        let current_grants = u64::try_from(s.grants().binding_item(wt.item)).unwrap_or(u64::MAX);
        let v = s.unlocked()?;
        if v.vault_id() != wt.vault_id || current_grants != wt.grants {
            return Err(RpcError::new(ErrorKind::StatementMismatch));
        }
        let current_t = resolve_target(
            v,
            wt.slug.as_str(),
            Some(field_name.as_str()),
            Some(&wt.item.to_string()),
        )?;
        if current_t.field.as_ref().map(|(fid, _)| *fid) != Some(field_id) {
            return Err(RpcError::with_reason(
                ErrorKind::NoSuchItem,
                "unknown_field",
            ));
        }
        let meta = v.item(wt.item).ok_or(RpcError::new(ErrorKind::Internal))?;
        let current_prior = meta
            .fields
            .iter()
            .find(|f| f.id == field_id)
            .map(|f| f.prior_count)
            .ok_or(RpcError::new(ErrorKind::Internal))?;
        if meta.details.classification != wt.classification || current_prior != wt.prior_count {
            return Err(RpcError::new(ErrorKind::StatementMismatch));
        }
    }

    let stmt = WriteStatement {
        target: wt.target.to_string(),
        nonce: hex_encode(&wt.nonce),
        vault_id: hex_encode(&wt.vault_id.0),
        action: WriteAction::Rotate {
            item: wt.item.to_string(),
            slug: wt.slug.as_str().to_owned(),
            field: field_id.to_string(),
            field_name: field_name.as_str().to_owned(),
            classification: ClassificationView::from(wt.classification)
                .as_str()
                .to_owned(),
            prior_count: wt.prior_count,
            grants: wt.grants,
            new_value_sha256: hex_encode(&new_value_sha256),
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
        s.audit(AuditEvent::ItemProofFailed {
            pid: peer.pid,
            write: AuditKind::Rotate,
            item: wt.item,
            slug: wt.slug,
        });
        return Err(RpcError::new(ErrorKind::SignatureInvalid));
    }

    let length = LengthClass::of(value.len());
    let written: Result<_, RpcError> = (|| {
        let v = s.unlocked_mut()?;
        let meta = v.item(wt.item).ok_or(RpcError::new(ErrorKind::Internal))?;
        let before = meta.details.classification;
        let after = match meta.fields.as_slice() {
            [_] => detected_class(shared, &meta.details, &value).unwrap_or(before),
            _ => before,
        };
        let details = (after != before).then(|| ItemDetails {
            classification: after,
            ..meta.details.clone()
        });
        v.transact(|txn| {
            txn.set_value(field_id, value)?;
            if let Some(details) = details {
                txn.update_item(wt.item, details)?;
            }
            txn.clear_exposure_if_replaced(wt.item)?;
            Ok(())
        })
        .map_err(|e| write_error(&e))?;
        let prior_count = v
            .item(wt.item)
            .and_then(|m| m.fields.iter().find(|f| f.id == field_id))
            .map(|f| f.prior_count)
            .ok_or(RpcError::new(ErrorKind::Internal))?;
        Ok((prior_count, before, after))
    })();
    let (prior_count, before, after) = match written {
        Ok(w) => w,
        Err(e) => {
            s.audit(AuditEvent::ItemWriteFailed {
                pid: peer.pid,
                subject: subject_summary(peer, &caller),
                write: AuditKind::Rotate,
                item: wt.item,
                slug: wt.slug,
                reason: e.reason.unwrap_or_else(|| e.kind.token()),
            });
            return Err(e);
        }
    };

    let reclassified = after != before;
    let grants = if reclassified {
        s.grants().on_item_reclassified(wt.item)
    } else {
        0
    };
    let class_str = |c| ClassificationView::from(c).as_str();
    s.audit(AuditEvent::Rotated {
        pid: peer.pid,
        subject: subject_summary(peer, &caller),
        item: wt.item,
        slug: wt.slug.clone(),
        prior_count,
        reclassified: reclassified.then(|| (class_str(before), class_str(after))),
        grants,
    });
    s.touch(Reading::now(&shared.clocks));
    Ok(RotatedView {
        slug: wt.slug.as_str().to_owned(),
        field: field_name.as_str().to_owned(),
        prior_count,
        length,
        classification: ClassificationView::from(after),
        reclassified_from: reclassified.then(|| ClassificationView::from(before)),
        grants_ended: u64::try_from(grants).unwrap_or(u64::MAX),
    })
}

/// `app.items.remove`: rebuilds the `envcloak-write-statement/1` `remove`
/// statement, verifies the digest and P-256 signature against an enrolled
/// Secure Enclave `approve` key matching `enrolled_under`, writes the encrypted
/// vault backup first (`backup_failed` if it fails, removing nothing), deletes
/// the item, ends bound grants and pending requests, and audits `remove`.
pub(crate) fn remove(
    shared: &Shared,
    peer: &PeerIdentity,
    enrolled_under: &SeEnrolledUnder,
    p: AppItemsRemoveParams,
) -> Result<RemovedView, RpcError> {
    refuse_if_traced()?;
    let target_id = PendingId::parse(&p.target).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let digest = digest_of(&p.digest).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let signature: [u8; P256_SIGNATURE_LEN] =
        decode_fixed_bytes(&p.signature).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let caller = requests::evidence(shared, peer, &p.claims)?;

    let mut s = locked(&shared.state);
    let _ = s.unlocked()?;
    let now = now_of(&shared.clocks);
    let wt = s
        .take_write_target(target_id, now.awake)
        .ok_or(RpcError::new(ErrorKind::NoSuchRequest))?;

    {
        let current_grants = u64::try_from(s.grants().binding_item(wt.item)).unwrap_or(u64::MAX);
        let v = s.unlocked()?;
        if v.vault_id() != wt.vault_id || current_grants != wt.grants {
            return Err(RpcError::new(ErrorKind::StatementMismatch));
        }
        let _ = resolve_target(v, wt.slug.as_str(), None, Some(&wt.item.to_string()))?;
        let meta = v.item(wt.item).ok_or(RpcError::new(ErrorKind::Internal))?;
        if meta.details.classification != wt.classification {
            return Err(RpcError::new(ErrorKind::StatementMismatch));
        }
    }

    let stmt = WriteStatement {
        target: wt.target.to_string(),
        nonce: hex_encode(&wt.nonce),
        vault_id: hex_encode(&wt.vault_id.0),
        action: WriteAction::Remove {
            item: wt.item.to_string(),
            slug: wt.slug.as_str().to_owned(),
            grants: wt.grants,
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
        s.audit(AuditEvent::ItemProofFailed {
            pid: peer.pid,
            write: AuditKind::Remove,
            item: wt.item,
            slug: wt.slug,
        });
        return Err(RpcError::new(ErrorKind::SignatureInvalid));
    }

    let written: Result<_, RpcError> = (|| {
        let v = s.unlocked_mut()?;
        let backup = v.create_backup().map_err(|e| {
            log_line!(
                "envcloakd: the backup before a removal could not be written ({}); nothing was \
                 removed",
                backup_reason(e.kind())
            );
            RpcError::new(ErrorKind::BackupFailed)
        })?;
        v.transact(|txn| txn.delete_item(wt.item))
            .map_err(|e| write_error(&e))?;
        Ok(backup)
    })();
    let backup = match written {
        Ok(b) => b,
        Err(e) => {
            s.audit(AuditEvent::ItemWriteFailed {
                pid: peer.pid,
                subject: subject_summary(peer, &caller),
                write: AuditKind::Remove,
                item: wt.item,
                slug: wt.slug,
                reason: e.reason.unwrap_or_else(|| e.kind.token()),
            });
            return Err(e);
        }
    };

    let grants = s.grants().on_item_removed(wt.item);
    s.audit(AuditEvent::Removed {
        pid: peer.pid,
        subject: subject_summary(peer, &caller),
        item: wt.item,
        slug: wt.slug.clone(),
        grants,
    });
    s.touch(Reading::now(&shared.clocks));
    Ok(RemovedView {
        slug: wt.slug.as_str().to_owned(),
        grants_ended: u64::try_from(grants).unwrap_or(u64::MAX),
        backup: backup
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
    })
}
