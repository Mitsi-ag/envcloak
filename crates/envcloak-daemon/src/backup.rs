//! Encrypted vault backups and restore (SPEC §5, §15.1 step 11; the file
//! format is in docs/VAULT.md "Backups"): `backup.create` and
//! `vault.recover`.
//!
//! - `backup.create` writes a backup of the unlocked, verified vault to
//!   its `backups` directory ([`envcloak_core::vault::Vault::create_backup`]).
//!   It needs no proof: no value crosses the socket, and nothing in the
//!   file opens without the Recovery Kit. It is audited (kind `backup`).
//! - `vault.recover` replaces the vault with the one a backup holds
//!   ([`envcloak_core::restore_backup`]), opened with the Recovery Kit and
//!   put under a new passphrase, and leaves it unlocked. It is a proof,
//!   like `unlock`, with the kit in place of the passphrase: the caller
//!   must be a terminal subject with no agent by any evidence, and the
//!   attempt limiter must admit the attempt. Everything that needs no key
//!   is checked first: the kit's shape, the new passphrase's rules, and
//!   that the backup is a regular file at an absolute path whose last
//!   component is not a symlink. Then the vault file is closed so the
//!   restore can take its lock; a vault that was unlocked is locked first,
//!   which ends every grant and pending request and saves the audit log's
//!   head. The restore runs outside the state lock, under the proof gate
//!   (Argon2id runs twice: for the kit, and for the new passphrase). It
//!   leaves the old vault or the restored one in place, never neither, and
//!   refuses a backup of another vault than the one in place
//!   (`backup_unusable`) before it moves anything. A wrong kit is counted
//!   and audited as a failed proof (kind `recover`); whatever the outcome,
//!   the slot then holds what is on disk.

use std::path::Path;

use envcloak_core::audit::AuditKind;
use envcloak_core::crypto::CryptoErrorKind;
use envcloak_core::vault::VaultErrorKind;
use envcloak_core::{RecoveryKit, check_passphrase, restore_backup};
use envcloak_ipc::RpcError;
use envcloak_ipc::proto::{ErrorKind, NoParams, RecoverParams};
use envcloak_ipc::view::{BackupView, LockReason, RecoveredView};
use envcloak_sys::PeerIdentity;

use crate::audit::AuditEvent;
use crate::clock::now_of;
use crate::lock::Reading;
use crate::requests::{evidence, refuse_unless_prover, subject_summary};
use crate::server::{Shared, locked, refuse_if_traced};
use crate::state::{passphrase_error, vault_reason};

/// `backup.create`. See the module documentation.
pub fn create(shared: &Shared, peer: &PeerIdentity, _p: NoParams) -> Result<BackupView, RpcError> {
    let mut s = locked(&shared.state);
    let info = s.unlocked()?.create_backup().map_err(|e| {
        log_line!(
            "envcloakd: a vault backup could not be written ({})",
            vault_reason(e.kind())
        );
        match e.kind() {
            VaultErrorKind::Tampered | VaultErrorKind::ReadOnly => {
                RpcError::new(ErrorKind::VaultTampered)
            }
            _ => RpcError::new(ErrorKind::BackupFailed),
        }
    })?;
    let file_name = info
        .path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    s.audit(AuditEvent::BackedUp {
        pid: peer.pid,
        backup: hex(&info.backup_id),
        items: info.items,
    });
    Ok(BackupView {
        path: info.path.to_string_lossy().into_owned(),
        file_name,
        items: u64::try_from(info.items).unwrap_or(u64::MAX),
        bytes: info.bytes,
        created_secs: info.created_at,
    })
}

/// `vault.recover`. See the module documentation.
pub fn recover(
    shared: &Shared,
    peer: &PeerIdentity,
    p: RecoverParams,
) -> Result<RecoveredView, RpcError> {
    let text = p.recovery_kit.into_inner();
    let new_pass = p.new_passphrase.into_inner();
    let kit = RecoveryKit::parse(&text).map_err(|_| RpcError::new(ErrorKind::WrongPassphrase))?;
    drop(text);
    check_passphrase(&new_pass).map_err(passphrase_error)?;
    let backup = Path::new(&p.backup);
    if !backup.is_absolute() {
        return Err(RpcError::new(ErrorKind::InvalidParams));
    }
    refuse_if_traced()?;
    let caller = evidence(shared, peer, &p.claims)?;
    refuse_unless_prover(shared, peer, &caller, "vault.recover")?;
    // Checked before the vault is touched: the last component only. The
    // restore opens the file again without following a symlink there, and
    // refuses anything but a regular file, so a swap after this check
    // gains nothing.
    if !std::fs::symlink_metadata(backup).is_ok_and(|m| m.file_type().is_file()) {
        return Err(RpcError::new(ErrorKind::BackupUnusable));
    }
    let _gate = locked(&shared.proof_gate);
    let (generation, paths) = {
        let mut s = locked(&shared.state);
        let at = now_of(&shared.clocks);
        s.limiter()
            .check(&at)
            .map_err(|_| RpcError::new(ErrorKind::TooManyAttempts))?;
        let (generation, was_unlocked) = s.begin_recover()?;
        if was_unlocked {
            log_line!(
                "envcloakd: vault locked (reason: {})",
                LockReason::Restore.as_str()
            );
        }
        (generation, s.paths().clone())
    };
    // As every lock: no restore chunk checked before it is still going out.
    crate::backups::wait_for_deliveries(shared);
    let result = restore_backup(&paths, backup, &kit, &new_pass);
    drop((kit, new_pass));
    let wrong_kit = matches!(
        &result,
        Err(e) if e.kind() == VaultErrorKind::Crypto(CryptoErrorKind::Unlock)
    );
    let backup_id = result.as_ref().ok().map(|(_, r)| hex(&r.backup_id));
    let now = Reading::now(&shared.clocks);
    let at = now_of(&shared.clocks);
    let mut s = locked(&shared.state);
    let r = s.finish_recover(generation, now, result);
    match &r {
        Ok(view) => {
            s.limiter().succeeded();
            log_line!(
                "envcloakd: vault restored from a backup{}",
                if view.locked {
                    ", then locked (a lock arrived while it was restored)"
                } else {
                    " and unlocked"
                }
            );
            s.audit(AuditEvent::Recovered {
                pid: peer.pid,
                subject: subject_summary(peer, &caller),
                backup: backup_id.unwrap_or_default(),
                items: usize::try_from(view.items).unwrap_or(usize::MAX),
            });
        }
        Err(_) if wrong_kit => {
            s.limiter().failed(&at);
            s.audit(AuditEvent::ProofFailed {
                pid: peer.pid,
                kind: AuditKind::Recover,
            });
        }
        Err(e) => log_line!("envcloakd: a restore failed ({})", e.kind.token()),
    }
    r
}

/// A restore's failure as the protocol reports it.
pub fn recover_error(k: VaultErrorKind) -> RpcError {
    match k {
        VaultErrorKind::Crypto(CryptoErrorKind::Unlock) => {
            RpcError::new(ErrorKind::WrongPassphrase)
        }
        VaultErrorKind::Passphrase(r) => passphrase_error(r),
        VaultErrorKind::BackupDamaged
        | VaultErrorKind::BackupOfAnotherVault
        | VaultErrorKind::Tampered
        | VaultErrorKind::NotFound => RpcError::new(ErrorKind::BackupUnusable),
        VaultErrorKind::Busy => RpcError::new(ErrorKind::Busy),
        k => RpcError::with_reason(ErrorKind::VaultUnavailable, vault_reason(k)),
    }
}

/// Lower-case hex of a backup's id, as its audit entry names it.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(2 * bytes.len()), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_failures_map_to_fixed_kinds() {
        let kind = |k| recover_error(k).kind;
        assert_eq!(
            kind(VaultErrorKind::Crypto(CryptoErrorKind::Unlock)),
            ErrorKind::WrongPassphrase
        );
        assert_eq!(
            kind(VaultErrorKind::BackupDamaged),
            ErrorKind::BackupUnusable
        );
        assert_eq!(kind(VaultErrorKind::Tampered), ErrorKind::BackupUnusable);
        assert_eq!(
            kind(VaultErrorKind::BackupOfAnotherVault),
            ErrorKind::BackupUnusable
        );
        assert_eq!(kind(VaultErrorKind::NotFound), ErrorKind::BackupUnusable);
        assert_eq!(kind(VaultErrorKind::Busy), ErrorKind::Busy);
        assert_eq!(
            kind(VaultErrorKind::Passphrase(
                envcloak_core::PassphraseRejected::TooShort
            )),
            ErrorKind::PassphraseRejected
        );
        assert_eq!(
            kind(VaultErrorKind::RestoreUnverified),
            ErrorKind::VaultUnavailable
        );
        assert_eq!(hex(&[0, 0xab, 0x10]), "00ab10");
    }
}
