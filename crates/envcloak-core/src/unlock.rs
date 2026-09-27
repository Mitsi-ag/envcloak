//! Creating a vault and unlocking it with a passphrase or the Recovery Kit
//! (SPEC §5 "Unlockers" and "Unlock flow").
//!
//! - [`create_vault`] checks the passphrase against the rules, generates
//!   the VMK, the vault id and the Recovery Kit, wraps the VMK under both
//!   (each envelope with its own salt), and creates the vault.
//! - [`LockedVault::unlock_with_passphrase`] and
//!   [`LockedVault::unlock_with_kit`] try each envelope of that kind. A
//!   wrong secret gives one error, [`CryptoErrorKind::Unlock`], whether the
//!   secret was wrong or the envelope damaged.
//! - [`Vault::change_passphrase`] wraps the VMK under a new passphrase with
//!   the current default parameters and a fresh salt, never the stored
//!   ones, and replaces the passphrase envelope in one transaction.
//! - [`Vault::confirm_recovery_kit`] proves the user holds the kit: it must
//!   unwrap this vault's VMK. The header then records it (SPEC §6.4: plain
//!   files are deleted after import only once the kit is confirmed).
//!
//! Argon2id runs for every wrap and unwrap: most of a second at the
//! defaults. The daemon calls these on a blocking thread. Each proof-taking
//! call here trusts its caller to have checked who is asking (SPEC §10b).

use crate::crypto::{
    Argon2id, CryptoErrorKind, Envelope, EnvelopeCtx, Kdf, KdfParams, UnlockerId, UnlockerKind,
    VaultId, Vmk, unwrap_vmk_with, wrap_vmk_with,
};
use crate::passphrase::check_passphrase;
use crate::recovery::RecoveryKit;
use crate::secret::SecretBytes;
use crate::vault::{INITIAL_EPOCH, LockedVault, Vault, VaultError, VaultErrorKind, VaultPaths};

/// Creates a vault at `p` with a passphrase unlocker and a new Recovery
/// Kit, and returns it unlocked with the kit. Both envelopes use `kdf`'s
/// Argon2id parameters, each with a salt of its own (`kdf`'s salt is not
/// used); pass [`KdfParams::current_defaults`], or lower memory for a small
/// machine, down to the 64 MiB bound.
///
/// Fails, before any key derivation, when the passphrase breaks the rules
/// ([`VaultErrorKind::Passphrase`]), the parameters are out of bounds, or a
/// vault already exists.
pub fn create_vault(
    p: &VaultPaths,
    pass: &SecretBytes,
    kdf: KdfParams,
) -> Result<(Vault, RecoveryKit), VaultError> {
    check_passphrase(pass)?;
    kdf.check_bounds()?;
    if std::fs::symlink_metadata(&p.db).is_ok() {
        return Err(VaultErrorKind::AlreadyExists.into());
    }
    let vault_id = VaultId::generate();
    let vmk = Vmk::generate();
    let kit = RecoveryKit::generate();
    let wrap = |secret: &SecretBytes, kind| {
        let ctx = EnvelopeCtx {
            vault_id,
            unlocker_id: UnlockerId::generate(),
            epoch: INITIAL_EPOCH,
        };
        wrap_vmk_with(&vmk, secret, kind, &ctx, &kdf.with_fresh_salt(), &Argon2id)
    };
    let envelopes = vec![
        wrap(pass, UnlockerKind::Passphrase)?,
        wrap(kit.secret(), UnlockerKind::RecoveryKit)?,
    ];
    let vault = Vault::create(p, vault_id, vmk, envelopes)?;
    Ok((vault, kit))
}

impl LockedVault {
    /// Unlocks with the passphrase. On failure the locked vault comes back
    /// with the error: [`CryptoErrorKind::Unlock`] for a wrong passphrase
    /// or a damaged envelope, [`VaultErrorKind::NoPassphrase`] when the
    /// vault has no passphrase envelope.
    pub fn unlock_with_passphrase(self, s: &SecretBytes) -> Result<Vault, (Self, VaultError)> {
        self.unlock_with_secret(UnlockerKind::Passphrase, s, &Argon2id)
    }

    /// Unlocks with the Recovery Kit, as
    /// [`LockedVault::unlock_with_passphrase`] does with a passphrase.
    pub fn unlock_with_kit(self, k: &RecoveryKit) -> Result<Vault, (Self, VaultError)> {
        self.unlock_with_secret(UnlockerKind::RecoveryKit, k.secret(), &Argon2id)
    }

    fn unlock_with_secret<K: Kdf + ?Sized>(
        self,
        kind: UnlockerKind,
        secret: &SecretBytes,
        kdf: &K,
    ) -> Result<Vault, (Self, VaultError)> {
        let envelopes = match self.unlockers() {
            Ok(e) => e,
            Err(e) => return Err((self, e)),
        };
        let ctx = |env: &Envelope| EnvelopeCtx {
            vault_id: self.vault_id(),
            unlocker_id: env.unlocker_id(),
            epoch: self.epoch(),
        };
        match unwrap_first(&envelopes, kind, secret, ctx, kdf) {
            Ok(vmk) => self.unlock(vmk),
            Err(e) => Err((self, e)),
        }
    }
}

/// Unwraps the VMK from the first envelope of `kind` that `secret` opens.
fn unwrap_first<'e, K: Kdf + ?Sized>(
    envelopes: impl IntoIterator<Item = &'e Envelope>,
    kind: UnlockerKind,
    secret: &SecretBytes,
    ctx: impl Fn(&Envelope) -> EnvelopeCtx,
    kdf: &K,
) -> Result<Vmk, VaultError> {
    let mut any = false;
    for env in envelopes.into_iter().filter(|e| e.kind() == kind) {
        any = true;
        match unwrap_vmk_with(env, secret, &ctx(env), kdf) {
            Ok(vmk) => return Ok(vmk),
            Err(e) if e.kind() == CryptoErrorKind::Unlock => {}
            Err(e) => return Err(e.into()),
        }
    }
    if !any {
        return Err(missing(kind));
    }
    Err(VaultErrorKind::Crypto(CryptoErrorKind::Unlock).into())
}

fn missing(kind: UnlockerKind) -> VaultError {
    match kind {
        UnlockerKind::Passphrase => VaultErrorKind::NoPassphrase.into(),
        UnlockerKind::RecoveryKit => VaultErrorKind::NoRecoveryKit.into(),
    }
}

/// Unwraps the VMK of `vault` from one of its envelopes of `kind` with
/// `secret`. Fails with [`CryptoErrorKind::Unlock`] unless one opens and
/// holds this vault's VMK.
pub(crate) fn prove_secret(
    vault: &Vault,
    kind: UnlockerKind,
    secret: &SecretBytes,
) -> Result<(), VaultError> {
    let ctx = |env: &Envelope| EnvelopeCtx {
        vault_id: vault.vault_id(),
        unlocker_id: env.unlocker_id(),
        epoch: vault.epoch(),
    };
    let vmk = unwrap_first(vault.unlockers(), kind, secret, ctx, &Argon2id)?;
    if vmk.ct_eq(vault.vmk()) {
        Ok(())
    } else {
        Err(VaultErrorKind::Crypto(CryptoErrorKind::Unlock).into())
    }
}

/// The envelope that makes `new` the passphrase of `vault`: wrapped with
/// `params` and a fresh salt, under the id of the passphrase unlocker it
/// replaces (the first of `existing`), or a new id when there is none.
pub(crate) fn passphrase_envelope(
    vault: &Vault,
    new: &SecretBytes,
    existing: &[UnlockerId],
    params: &KdfParams,
) -> Result<Envelope, VaultError> {
    let ctx = EnvelopeCtx {
        vault_id: vault.vault_id(),
        unlocker_id: existing
            .first()
            .copied()
            .unwrap_or_else(UnlockerId::generate),
        epoch: vault.epoch(),
    };
    Ok(wrap_vmk_with(
        vault.vmk(),
        new,
        UnlockerKind::Passphrase,
        &ctx,
        &params.with_fresh_salt(),
        &Argon2id,
    )?)
}

/// Makes `env` the vault's only passphrase envelope, in the transaction
/// `t`: it replaces the envelope with its id, or is added, and any other
/// passphrase envelope is removed.
pub(crate) fn install_passphrase(
    t: &mut crate::vault::Txn<'_>,
    env: Envelope,
    existing: &[UnlockerId],
) -> Result<(), VaultError> {
    let id = env.unlocker_id();
    if existing.contains(&id) {
        t.replace_unlocker(env)?;
    } else {
        t.add_unlocker(env)?;
    }
    for other in existing.iter().filter(|o| **o != id) {
        t.remove_unlocker(*other)?;
    }
    Ok(())
}

/// The ids of a vault's passphrase unlockers, in id order.
pub(crate) fn passphrase_unlockers(vault: &Vault) -> Vec<UnlockerId> {
    vault
        .unlockers()
        .filter(|e| e.kind() == UnlockerKind::Passphrase)
        .map(Envelope::unlocker_id)
        .collect()
}

impl Vault {
    /// Makes `new` the vault's passphrase. The VMK is wrapped with
    /// [`KdfParams::current_defaults`] and a fresh salt, whatever the old
    /// envelope used, and the envelope replaces the old one in one
    /// transaction; the Recovery Kit is unchanged. The caller must have
    /// checked a proof (the old passphrase or the kit) first.
    ///
    /// Fails before any key derivation when `new` breaks the passphrase
    /// rules, and with [`VaultErrorKind::ReadOnly`] when the vault failed
    /// its integrity check.
    pub fn change_passphrase(&mut self, new: &SecretBytes) -> Result<(), VaultError> {
        self.change_passphrase_with(new, &KdfParams::current_defaults())
    }

    /// Test support only (feature `testing`): [`Vault::change_passphrase`]
    /// with other Argon2id parameters, so tests that watch every
    /// allocation need not fill 256 MiB.
    #[cfg(feature = "testing")]
    pub fn change_passphrase_for_testing(
        &mut self,
        new: &SecretBytes,
        params: &KdfParams,
    ) -> Result<(), VaultError> {
        self.change_passphrase_with(new, params)
    }

    fn change_passphrase_with(
        &mut self,
        new: &SecretBytes,
        params: &KdfParams,
    ) -> Result<(), VaultError> {
        check_passphrase(new)?;
        params.check_bounds()?;
        self.writable()?;
        let existing = passphrase_unlockers(self);
        let env = passphrase_envelope(self, new, &existing, params)?;
        self.transact(|t| install_passphrase(t, env, &existing))
    }

    /// Records that the user holds the Recovery Kit, after checking that
    /// `k` unwraps this vault's VMK. A wrong kit gives
    /// [`CryptoErrorKind::Unlock`], like a wrong passphrase.
    pub fn confirm_recovery_kit(&mut self, k: &RecoveryKit) -> Result<(), VaultError> {
        self.writable()?;
        prove_secret(self, UnlockerKind::RecoveryKit, k.secret())?;
        if self.header()?.recovery_confirmed {
            return Ok(());
        }
        self.transact(|t| {
            t.set_recovery_confirmed(true);
            Ok(())
        })
    }

    /// Whether the user has confirmed the Recovery Kit. Fails with
    /// [`VaultErrorKind::Tampered`] unless the vault verified.
    pub fn recovery_confirmed(&self) -> Result<bool, VaultError> {
        Ok(self.header()?.recovery_confirmed)
    }

    /// Fails, before any key derivation, where `transact` would.
    fn writable(&self) -> Result<(), VaultError> {
        if self.integrity() != crate::vault::Integrity::Ok {
            return Err(VaultErrorKind::ReadOnly.into());
        }
        if self.migration_error().is_some() {
            return Err(VaultErrorKind::Migration.into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    use crate::crypto::{CryptoError, Kek};

    struct Spy(Cell<usize>);

    impl Kdf for Spy {
        fn derive(&self, secret: &SecretBytes, params: &KdfParams) -> Result<Kek, CryptoError> {
            self.0.set(self.0.get() + 1);
            Argon2id.derive(secret, params)
        }
    }

    /// Each envelope of the kind is tried until one opens; envelopes of
    /// the other kind are never derived.
    #[test]
    fn unwrap_first_tries_each_envelope_of_its_kind_only() {
        let vault_id = VaultId::generate();
        let vmk = Vmk::generate();
        let wrap = |s: &[u8], kind| {
            wrap_vmk_with(
                &vmk,
                &SecretBytes::copy_from(s),
                kind,
                &EnvelopeCtx {
                    vault_id,
                    unlocker_id: UnlockerId::generate(),
                    epoch: 1,
                },
                &KdfParams::minimum(),
                &Argon2id,
            )
            .unwrap()
        };
        let envs = [
            wrap(b"first passphrase one", UnlockerKind::Passphrase),
            wrap(b"a recovery kit secret", UnlockerKind::RecoveryKit),
            wrap(b"second passphrase two", UnlockerKind::Passphrase),
        ];
        let ctx = |e: &Envelope| EnvelopeCtx {
            vault_id,
            unlocker_id: e.unlocker_id(),
            epoch: 1,
        };
        let spy = Spy(Cell::new(0));
        let pass = SecretBytes::copy_from(b"second passphrase two");
        let got = unwrap_first(&envs, UnlockerKind::Passphrase, &pass, ctx, &spy).unwrap();
        assert!(got.ct_eq(&vmk));
        assert_eq!(spy.0.get(), 2);

        let spy = Spy(Cell::new(0));
        let wrong = SecretBytes::copy_from(b"not any of them at all");
        let e = unwrap_first(&envs, UnlockerKind::Passphrase, &wrong, ctx, &spy).unwrap_err();
        assert_eq!(e.kind(), VaultErrorKind::Crypto(CryptoErrorKind::Unlock));
        assert_eq!(spy.0.get(), 2);

        let spy = Spy(Cell::new(0));
        let e = unwrap_first(&envs[..1], UnlockerKind::RecoveryKit, &wrong, ctx, &spy).unwrap_err();
        assert_eq!(e.kind(), VaultErrorKind::NoRecoveryKit);
        assert_eq!(spy.0.get(), 0);
    }
}
