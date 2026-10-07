//! Linux terminal reveal: fresh proof, fresh evidence and target, then a
//! durable audit entry before the framed value can leave (SPEC §6.7).

use envcloak_ipc::proto::{ErrorKind, RevealOutput, RevealParams};
use envcloak_ipc::{Frame, RpcError, WireSecret};
use envcloak_sys::PeerIdentity;

use crate::audit::AuditEvent;
use crate::clock::now_of;
use crate::items::{Write, prove, refuse_item_prover, target};
use crate::requests::{evidence, subject_summary};
use crate::server::{Shared, result_framed};
use crate::state::vault_reason;

pub fn reveal(
    shared: &Shared,
    peer: &PeerIdentity,
    id: u64,
    p: RevealParams,
) -> Result<Frame, RpcError> {
    let resolve = |v: &envcloak_core::vault::Vault| {
        let t = target(v, &p.slug, p.field.as_deref(), None)?;
        if t.field.is_none() {
            return Err(RpcError::with_reason(
                ErrorKind::NoSuchItem,
                "ambiguous_field",
            ));
        }
        Ok(t)
    };
    let mut proven = prove(
        shared,
        peer,
        Write::Reveal,
        &p.claims,
        p.passphrase.into_inner(),
        &resolve,
    )?;
    let result = (|| {
        // Argon2id ran without the state lock. Recompute the caller, its
        // origin boundary and the target before the first value read.
        let caller = evidence(shared, peer, &p.claims)?;
        refuse_item_prover(
            &mut proven.s,
            peer,
            &caller,
            &now_of(&shared.clocks),
            "items.reveal",
        )?;
        let t = target(
            proven.s.unlocked()?,
            &p.slug,
            p.field.as_deref(),
            Some(&proven.target.item.to_string()),
        )?;
        let (field, _) = t.field.ok_or(RpcError::with_reason(
            ErrorKind::NoSuchItem,
            "ambiguous_field",
        ))?;
        let value = proven.s.unlocked()?.read_value(field).map_err(|e| {
            RpcError::with_reason(ErrorKind::VaultUnavailable, vault_reason(e.kind()))
        })?;
        // Frame first. A value that cannot be sent is not a successful
        // reveal; a failed audit drops and wipes this private frame.
        let answer = result_framed::<envcloak_ipc::proto::ItemsReveal>(
            id,
            &RevealOutput {
                value: WireSecret::new(value),
            },
        )?;
        if !proven.s.audit_delivery(AuditEvent::Revealed {
            pid: peer.pid,
            subject: subject_summary(peer, &caller),
            item: t.item,
            slug: t.slug,
        }) {
            return Err(RpcError::new(ErrorKind::AuditFailed));
        }
        Ok(answer)
    })();
    result.map_err(|e| proven.aborted(peer, Write::Reveal, e))
}
