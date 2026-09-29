//! Unlocker envelopes: the VMK wrapped under a passphrase or Recovery Kit
//! (SPEC §5 "Key hierarchy"; byte layout in docs/CRYPTO.md).
//!
//! - KEK = Argon2id(secret, salt, params), through [`derive_kek`], which
//!   checks the stored parameters against the bounds first. A wrap takes
//!   its parameters as a [`KdfParams`] and draws the salt itself; an
//!   envelope's stored parameters and salt are a [`StoredKdfParams`], which
//!   only unwrapping reads, so no re-wrap can reuse them.
//! - `wrap = HKDF-SHA256(KEK, "envcloak/v1/wrap")` and
//!   `commit = HKDF-SHA256(KEK, "envcloak/v1/commit")`, with no salt.
//! - The authenticated header is the envelope's bytes up to and including
//!   the nonce, followed by the vault id. The commitment is keyed BLAKE3
//!   of it under `commit`; the VMK is sealed with XChaCha20-Poly1305 under
//!   `wrap` with it as associated data.
//!
//! XChaCha20-Poly1305 does not commit to its key: a ciphertext can be built
//! that opens under several keys, which turns an unlock oracle into a
//! partitioning oracle over guessed passphrases. So [`unwrap_vmk`] compares
//! the commitment in constant time before it tries to decrypt, and a wrong
//! KEK fails there. Every failure after the parameter and identity checks
//! gives the one generic [`CryptoErrorKind::Unlock`] error.

use hkdf::Hkdf;
use secrecy::{ExposeSecret, SecretBox};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use super::aead::{open_into, seal_with_nonce};
use super::kdf::{Argon2id, Kdf, KdfParams, Kek, StoredKdfParams, derive_kek};
use super::keys::{UnlockerId, VaultId, Vmk, blake3_keyed, hkdf_expand};
use super::{CryptoError, CryptoErrorKind, fill_random};
use crate::secret::SecretBytes;

/// What secret an envelope is wrapped under. Part of the envelope format:
/// never renumber.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum UnlockerKind {
    Passphrase = 1,
    RecoveryKit = 2,
}

impl UnlockerKind {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(UnlockerKind::Passphrase),
            2 => Some(UnlockerKind::RecoveryKit),
            _ => None,
        }
    }
}

/// Who an envelope belongs to: the caller's own record of the vault, the
/// unlocker row and the current key epoch, never the envelope's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvelopeCtx {
    pub vault_id: VaultId,
    pub unlocker_id: UnlockerId,
    pub epoch: u32,
}

/// A wrapped VMK. Holds no plaintext secret.
#[derive(Clone, PartialEq, Eq)]
pub struct Envelope {
    kind: UnlockerKind,
    unlocker_id: UnlockerId,
    epoch: u32,
    kdf: StoredKdfParams,
    nonce: [u8; 24],
    commitment: [u8; 32],
    ciphertext: [u8; 48],
}

const MAGIC: [u8; 4] = *b"ECEV";
const KDF_ARGON2ID: u8 = 1;
/// Magic through nonce: the part of the envelope the commitment covers.
const HEADER_LEN: usize = 79;
const AUTH_LEN: usize = HEADER_LEN + 16;

impl Envelope {
    /// Length of [`Envelope::to_bytes`]'s output.
    pub const LEN: usize = HEADER_LEN + 32 + 48;
    /// The only format version this build reads and writes.
    pub const FORMAT_VERSION: u8 = 1;

    pub fn version(&self) -> u8 {
        Self::FORMAT_VERSION
    }

    pub fn kind(&self) -> UnlockerKind {
        self.kind
    }

    pub fn unlocker_id(&self) -> UnlockerId {
        self.unlocker_id
    }

    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// The parameters and salt this envelope was wrapped with. Unwrapping
    /// uses them; no wrap accepts them.
    pub fn kdf(&self) -> &StoredKdfParams {
        &self.kdf
    }

    /// `magic(4) version(1) kind(1) unlocker_id(16) epoch(4) kdf(1) m_kib(4)
    /// t(4) p(4) salt(16) nonce(24)`, integers big-endian.
    fn header(&self) -> [u8; HEADER_LEN] {
        let mut h = [0u8; HEADER_LEN];
        let mut w = Cursor { buf: &mut h, at: 0 };
        w.put(&MAGIC);
        w.put(&[Self::FORMAT_VERSION, self.kind as u8]);
        w.put(&self.unlocker_id.0);
        w.put(&self.epoch.to_be_bytes());
        w.put(&[KDF_ARGON2ID]);
        w.put(&self.kdf.m_kib().to_be_bytes());
        w.put(&self.kdf.t().to_be_bytes());
        w.put(&self.kdf.p().to_be_bytes());
        w.put(self.kdf.salt());
        w.put(&self.nonce);
        debug_assert_eq!(w.at, HEADER_LEN);
        h
    }

    /// The header followed by the vault id: what the commitment and the
    /// AEAD authenticate.
    fn authenticated(&self, vault_id: &VaultId) -> [u8; AUTH_LEN] {
        let mut a = [0u8; AUTH_LEN];
        a[..HEADER_LEN].copy_from_slice(&self.header());
        a[HEADER_LEN..].copy_from_slice(&vault_id.0);
        a
    }

    /// The stored form: header, commitment, then the sealed VMK and its tag.
    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[..HEADER_LEN].copy_from_slice(&self.header());
        out[HEADER_LEN..HEADER_LEN + 32].copy_from_slice(&self.commitment);
        out[HEADER_LEN + 32..].copy_from_slice(&self.ciphertext);
        out
    }

    /// Parses [`Envelope::to_bytes`]'s output. Rejects a wrong length,
    /// magic, version, kind or KDF with [`CryptoErrorKind::EnvelopeFormat`],
    /// and Argon2id parameters outside the bounds with
    /// [`CryptoErrorKind::KdfParams`].
    pub fn from_bytes(b: &[u8]) -> Result<Self, CryptoError> {
        let format = || CryptoError::new(CryptoErrorKind::EnvelopeFormat);
        let b: &[u8; Self::LEN] = b.try_into().map_err(|_| format())?;
        let mut r = Reader { buf: b, at: 0 };
        if r.take::<4>() != MAGIC || r.take::<1>() != [Self::FORMAT_VERSION] {
            return Err(format());
        }
        let [kind] = r.take::<1>();
        let kind = UnlockerKind::from_byte(kind).ok_or_else(format)?;
        let unlocker_id = UnlockerId(r.take());
        let epoch = u32::from_be_bytes(r.take());
        if r.take::<1>() != [KDF_ARGON2ID] {
            return Err(format());
        }
        let m_kib = u32::from_be_bytes(r.take());
        let t = u32::from_be_bytes(r.take());
        let p = u32::from_be_bytes(r.take());
        let kdf = StoredKdfParams::parsed(m_kib, t, p, r.take());
        let env = Envelope {
            kind,
            unlocker_id,
            epoch,
            kdf,
            nonce: r.take(),
            commitment: r.take(),
            ciphertext: r.take(),
        };
        debug_assert_eq!(r.at, Self::LEN);
        env.kdf.check_bounds()?;
        Ok(env)
    }
}

impl core::fmt::Debug for Envelope {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Envelope")
            .field("kind", &self.kind)
            .field("unlocker_id", &self.unlocker_id)
            .field("epoch", &self.epoch)
            .field("kdf", &self.kdf)
            .finish_non_exhaustive()
    }
}

/// Wraps `vmk` under `secret` with [`KdfParams::current_defaults`].
pub fn wrap_vmk(
    vmk: &Vmk,
    secret: &SecretBytes,
    kind: UnlockerKind,
    ctx: &EnvelopeCtx,
) -> Result<Envelope, CryptoError> {
    wrap_vmk_with(
        vmk,
        secret,
        kind,
        ctx,
        &KdfParams::current_defaults(),
        &Argon2id,
    )
}

/// Wraps `vmk` under `secret` with explicit parameters, which must be in
/// bounds, and an explicit KDF backend. The salt is drawn here from the OS
/// CSPRNG, fresh for every envelope, so two wraps with the same `params`
/// never share one. `params` is a [`KdfParams`], made only by its
/// constructors; an envelope's stored parameters ([`Envelope::kdf`]) are
/// another type, which this does not accept.
#[allow(clippy::disallowed_methods)] // Encrypts the VMK under keys from the KEK.
pub fn wrap_vmk_with<K: Kdf + ?Sized>(
    vmk: &Vmk,
    secret: &SecretBytes,
    kind: UnlockerKind,
    ctx: &EnvelopeCtx,
    params: &KdfParams,
    kdf: &K,
) -> Result<Envelope, CryptoError> {
    params.check_bounds()?;
    let mut salt = [0u8; 16];
    fill_random(&mut salt)?;
    let stored = params.stored_with(salt);
    let kek = derive_kek(kdf, secret, &stored)?;
    let mut env = Envelope {
        kind,
        unlocker_id: ctx.unlocker_id,
        epoch: ctx.epoch,
        kdf: stored,
        nonce: [0; 24],
        commitment: [0; 32],
        ciphertext: [0; 48],
    };
    fill_random(&mut env.nonce)?;
    let auth = env.authenticated(&ctx.vault_id);
    let keys = EnvelopeKeys::derive(&kek);
    env.commitment = blake3_keyed(keys.commit.expose_secret(), &[&auth]);
    let ct = seal_with_nonce(
        keys.wrap.expose_secret(),
        &env.nonce,
        &auth,
        vmk.0.expose_secret(),
    )?;
    env.ciphertext.copy_from_slice(&ct);
    Ok(env)
}

/// Unwraps the VMK with [`Argon2id`].
pub fn unwrap_vmk(
    env: &Envelope,
    secret: &SecretBytes,
    ctx: &EnvelopeCtx,
) -> Result<Vmk, CryptoError> {
    unwrap_vmk_with(env, secret, ctx, &Argon2id)
}

/// Unwraps the VMK with an explicit KDF backend. In order:
/// 1. parameters outside the bounds fail with [`CryptoErrorKind::KdfParams`],
///    before any key derivation;
/// 2. an envelope for another unlocker or epoch than `ctx` fails with
///    [`CryptoErrorKind::EnvelopeMismatch`], also before derivation;
/// 3. the KEK is derived and the commitment compared in constant time;
/// 4. only then is the VMK decrypted.
///
/// Failures in 3 and 4 are the same [`CryptoErrorKind::Unlock`] error.
#[allow(clippy::disallowed_methods)] // Decrypts the VMK under keys from the KEK.
pub fn unwrap_vmk_with<K: Kdf + ?Sized>(
    env: &Envelope,
    secret: &SecretBytes,
    ctx: &EnvelopeCtx,
    kdf: &K,
) -> Result<Vmk, CryptoError> {
    env.kdf.check_bounds()?;
    if env.unlocker_id != ctx.unlocker_id || env.epoch != ctx.epoch {
        return Err(CryptoErrorKind::EnvelopeMismatch.into());
    }
    let kek = derive_kek(kdf, secret, &env.kdf)?;
    let auth = env.authenticated(&ctx.vault_id);
    let keys = EnvelopeKeys::derive(&kek);
    let unlock = || CryptoError::new(CryptoErrorKind::Unlock);
    let tag = blake3_keyed(keys.commit.expose_secret(), &[&auth]);
    if !bool::from(tag.ct_eq(&env.commitment)) {
        return Err(unlock());
    }
    let mut result = Ok(());
    let vmk = SecretBox::init_with_mut(|k: &mut [u8; 32]| {
        result = open_into(
            keys.wrap.expose_secret(),
            &env.nonce,
            &auth,
            &env.ciphertext,
            k,
        );
    });
    result.map_err(|_| unlock())?;
    Ok(Vmk(vmk))
}

/// Re-wraps an envelope's VMK under `new_secret`, keeping its kind and
/// unlocker. Always uses [`KdfParams::current_defaults`] with a fresh salt,
/// never the envelope's stored parameters.
pub fn rewrap_vmk(
    env: &Envelope,
    secret: &SecretBytes,
    new_secret: &SecretBytes,
    ctx: &EnvelopeCtx,
) -> Result<Envelope, CryptoError> {
    let vmk = unwrap_vmk(env, secret, ctx)?;
    wrap_vmk(&vmk, new_secret, env.kind, ctx)
}

/// The two keys derived from a KEK.
struct EnvelopeKeys {
    wrap: SecretBox<[u8; 32]>,
    commit: SecretBox<[u8; 32]>,
}

impl EnvelopeKeys {
    #[allow(clippy::disallowed_methods)] // Reads the KEK to derive its keys.
    fn derive(kek: &Kek) -> Self {
        let hk = Hkdf::<Sha256>::new(None, kek.0.expose_secret());
        let key = |label: &[u8]| {
            SecretBox::init_with_mut(|k: &mut [u8; 32]| hkdf_expand(&hk, &[label], k))
        };
        EnvelopeKeys {
            wrap: key(b"envcloak/v1/wrap"),
            commit: key(b"envcloak/v1/commit"),
        }
    }
}

struct Cursor<'a> {
    buf: &'a mut [u8],
    at: usize,
}

impl Cursor<'_> {
    fn put(&mut self, b: &[u8]) {
        self.buf[self.at..self.at + b.len()].copy_from_slice(b);
        self.at += b.len();
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        out.copy_from_slice(&self.buf[self.at..self.at + N]);
        self.at += N;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::super::aead::OPEN_ATTEMPTS;
    use super::super::keys::{Keyring, Purpose, keyed_hash};
    use super::*;
    use core::cell::Cell;

    struct Spy(Cell<usize>);

    impl Kdf for Spy {
        fn derive(
            &self,
            secret: &SecretBytes,
            params: &StoredKdfParams,
        ) -> Result<Kek, CryptoError> {
            self.0.set(self.0.get() + 1);
            Argon2id.derive(secret, params)
        }
    }

    fn ctx() -> EnvelopeCtx {
        EnvelopeCtx {
            vault_id: VaultId::generate(),
            unlocker_id: UnlockerId::generate(),
            epoch: 4,
        }
    }

    fn opens() -> usize {
        OPEN_ATTEMPTS.with(Cell::get)
    }

    fn fingerprint(vmk: &Vmk) -> [u8; 32] {
        let kr = Keyring::derive(vmk, &VaultId([0; 16]), 0);
        keyed_hash(kr.key(Purpose::Index), "envcloak/v1/test", b"")
    }

    #[test]
    fn the_commitment_is_checked_before_any_decryption() {
        let c = ctx();
        let vmk = Vmk::generate();
        let pass = SecretBytes::copy_from(b"the right passphrase here");
        let env = wrap_vmk_with(
            &vmk,
            &pass,
            UnlockerKind::Passphrase,
            &c,
            &KdfParams::minimum(),
            &Argon2id,
        )
        .unwrap();

        let before = opens();
        let wrong = SecretBytes::copy_from(b"the wrong passphrase here");
        let e = unwrap_vmk(&env, &wrong, &c).unwrap_err();
        assert_eq!(e.kind(), CryptoErrorKind::Unlock);
        assert_eq!(opens(), before, "a wrong KEK reached the AEAD");

        let got = unwrap_vmk(&env, &pass, &c).unwrap();
        assert_eq!(opens(), before + 1);
        assert_eq!(fingerprint(&got), fingerprint(&vmk));
    }

    /// A multi-key ciphertext: the VMK is sealed under B's wrap key, while
    /// the commitment is A's. The AEAD alone would accept secret B; the
    /// commitment refuses it before decryption, and secret A passes the
    /// commitment but fails the AEAD.
    #[test]
    #[allow(clippy::disallowed_methods)] // Builds the forged envelope by hand.
    fn the_commitment_binds_the_kek() {
        let c = ctx();
        let vmk = Vmk::generate();
        let params = KdfParams::minimum().stored_with([5; 16]);
        let pass_a = SecretBytes::copy_from(b"passphrase number one A");
        let pass_b = SecretBytes::copy_from(b"passphrase number two B");
        let keys_a = EnvelopeKeys::derive(&Argon2id.derive(&pass_a, &params).unwrap());
        let keys_b = EnvelopeKeys::derive(&Argon2id.derive(&pass_b, &params).unwrap());

        let mut env = Envelope {
            kind: UnlockerKind::Passphrase,
            unlocker_id: c.unlocker_id,
            epoch: c.epoch,
            kdf: params,
            nonce: [9; 24],
            commitment: [0; 32],
            ciphertext: [0; 48],
        };
        let auth = env.authenticated(&c.vault_id);
        env.commitment = blake3_keyed(keys_a.commit.expose_secret(), &[&auth]);
        let ct = seal_with_nonce(
            keys_b.wrap.expose_secret(),
            &env.nonce,
            &auth,
            vmk.0.expose_secret(),
        )
        .unwrap();
        env.ciphertext.copy_from_slice(&ct);

        // Control: B's wrap key does open the ciphertext.
        let mut out = [0u8; 32];
        open_into(
            keys_b.wrap.expose_secret(),
            &env.nonce,
            &auth,
            &env.ciphertext,
            &mut out,
        )
        .unwrap();
        assert_eq!(&out, vmk.0.expose_secret());

        let before = opens();
        let e = unwrap_vmk(&env, &pass_b, &c).unwrap_err();
        assert_eq!(e.kind(), CryptoErrorKind::Unlock);
        assert_eq!(opens(), before, "the commitment did not stop key B");
        let e = unwrap_vmk(&env, &pass_a, &c).unwrap_err();
        assert_eq!(e.kind(), CryptoErrorKind::Unlock);
        assert_eq!(opens(), before + 1);
    }

    /// Parsing rejects out-of-bounds parameters, so this builds the
    /// envelope directly to reach unwrap's own check.
    #[test]
    fn unwrap_rejects_out_of_bounds_params_before_derivation() {
        let c = ctx();
        let pass = SecretBytes::copy_from(b"a passphrase for the spy");
        let good = wrap_vmk_with(
            &Vmk::generate(),
            &pass,
            UnlockerKind::Passphrase,
            &c,
            &KdfParams::minimum(),
            &Argon2id,
        )
        .unwrap();
        let spy = Spy(Cell::new(0));
        for (m_kib, t, p) in [
            (1024, 2, 1),
            (65536, 1, 1),
            (65536, 2, 0),
            (u32::MAX, 16, 16),
        ] {
            let mut env = good.clone();
            env.kdf = StoredKdfParams::parsed(m_kib, t, p, *env.kdf.salt());
            let e = unwrap_vmk_with(&env, &pass, &c, &spy).unwrap_err();
            assert_eq!(e.kind(), CryptoErrorKind::KdfParams);
        }
        assert_eq!(spy.0.get(), 0);
        unwrap_vmk_with(&good, &pass, &c, &spy).unwrap();
        assert_eq!(spy.0.get(), 1);
    }

    #[test]
    fn layout_offsets() {
        assert_eq!(HEADER_LEN, 4 + 1 + 1 + 16 + 4 + 1 + 12 + 16 + 24);
        assert_eq!(Envelope::LEN, 159);
    }
}
