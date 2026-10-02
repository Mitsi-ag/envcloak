//! Argon2id key derivation for unlockers (SPEC §5 "Envelope parameters").
//!
//! KEK = Argon2id (version 0x13) of the passphrase or Recovery Kit, with a
//! 16-byte salt and a 32-byte output. Two types carry the parameters:
//!
//! - [`KdfParams`] is what a new envelope is wrapped with: memory, passes
//!   and lanes, and no salt. Only its constructors make one (the current
//!   defaults, the minimum, or the defaults at a chosen memory), and
//!   [`crate::crypto::wrap_vmk_with`] draws a fresh salt for every
//!   envelope it wraps.
//! - [`StoredKdfParams`] is what an envelope holds: the parameters and the
//!   salt it was wrapped with. Only parsing an envelope and wrapping make
//!   one, only unwrapping reads it, and no wrap accepts it, so a re-wrap
//!   can never reuse an envelope's stored parameters or salt (gate 3).
//!
//! Stored parameters are untrusted when read back:
//! [`StoredKdfParams::check_bounds`] rejects anything outside 64 MiB to
//! 4 GiB of memory, 2 to 16 passes and 1 to 16 lanes, and [`derive_kek`]
//! runs it before any key derivation work, so a doctored envelope can
//! neither weaken the KDF nor make it exhaust memory.
//!
//! Argon2id's working memory, 64 MiB to 4 GiB, holds the last block of
//! each lane, from which the KEK follows at once: it is as secret as the
//! KEK. argon2 frees the memory it allocates itself unwiped, whatever its
//! `zeroize` feature (that wipes only its small buffers), and only a
//! wiping global allocator would clear it. So [`argon2id`] allocates the
//! memory here, in a [`Zeroizing`] vector, and hands it to argon2: it is
//! wiped when dropped in every program that embeds this crate, tests
//! included.
//!
//! Argon2id takes most of a second at the defaults. The daemon must run it
//! on a blocking thread.

use argon2::{Algorithm, Argon2, Block, Params, Version};
use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroizing;

use super::{CryptoError, CryptoErrorKind};
use crate::secret::SecretBytes;

/// The Argon2id cost a new envelope is wrapped with. Not secret.
///
/// It holds no salt: [`crate::crypto::wrap_vmk_with`] draws a fresh one for
/// every envelope, so two wraps with the same parameters never share a
/// salt. The fields are private and nothing converts an envelope's
/// [`StoredKdfParams`] into this type: a wrap takes its parameters from
/// the constructors below and never from an envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    m_kib: u32,
    t: u32,
    p: u32,
}

impl KdfParams {
    /// 64 MiB.
    pub const MIN_M_KIB: u32 = 64 * 1024;
    /// 4 GiB.
    pub const MAX_M_KIB: u32 = 4 * 1024 * 1024;
    pub const MIN_T: u32 = 2;
    pub const MAX_T: u32 = 16;
    pub const MIN_P: u32 = 1;
    pub const MAX_P: u32 = 16;

    /// 256 MiB.
    pub const DEFAULT_M_KIB: u32 = 256 * 1024;
    pub const DEFAULT_T: u32 = 3;
    pub const DEFAULT_P: u32 = 4;

    /// The parameters every new envelope and every re-wrap uses: 256 MiB,
    /// 3 passes, 4 lanes.
    pub const fn current_defaults() -> Self {
        Self::with_memory(Self::DEFAULT_M_KIB)
    }

    /// The current defaults with `m_kib` KiB of memory: `vault create` on a
    /// machine that cannot spare 256 MiB. Not checked here; a wrap refuses
    /// memory outside the bounds, as [`KdfParams::check_bounds`] does.
    pub const fn with_memory(m_kib: u32) -> Self {
        KdfParams {
            m_kib,
            t: Self::DEFAULT_T,
            p: Self::DEFAULT_P,
        }
    }

    /// The cheapest parameters the bounds allow (64 MiB, 2 passes, 1 lane):
    /// for tests.
    pub const fn minimum() -> Self {
        KdfParams {
            m_kib: Self::MIN_M_KIB,
            t: Self::MIN_T,
            p: Self::MIN_P,
        }
    }

    /// Memory in KiB.
    pub const fn m_kib(&self) -> u32 {
        self.m_kib
    }

    /// Passes.
    pub const fn t(&self) -> u32 {
        self.t
    }

    /// Lanes.
    pub const fn p(&self) -> u32 {
        self.p
    }

    /// Fails unless every parameter is within the bounds. Cheap; runs
    /// before any Argon2 work.
    pub fn check_bounds(&self) -> Result<(), CryptoError> {
        check_bounds(self.m_kib, self.t, self.p)
    }

    /// The stored form of these parameters with `salt`: only a wrap, which
    /// has just drawn the salt, calls this.
    pub(crate) const fn stored_with(&self, salt: [u8; 16]) -> StoredKdfParams {
        StoredKdfParams {
            m_kib: self.m_kib,
            t: self.t,
            p: self.p,
            salt,
        }
    }
}

/// The Argon2id parameters and salt an envelope was wrapped with, as
/// stored in it and returned by [`crate::crypto::Envelope::kdf`]. Not
/// secret, and untrusted when parsed: see [`StoredKdfParams::check_bounds`].
///
/// Unwrapping derives the KEK with these. No wrap accepts them, and the
/// fields are private: only parsing an envelope and wrapping make one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredKdfParams {
    m_kib: u32,
    t: u32,
    p: u32,
    salt: [u8; 16],
}

impl StoredKdfParams {
    /// Parameters as read from an envelope's bytes, not yet checked.
    pub(crate) const fn parsed(m_kib: u32, t: u32, p: u32, salt: [u8; 16]) -> Self {
        StoredKdfParams { m_kib, t, p, salt }
    }

    /// Memory in KiB.
    pub const fn m_kib(&self) -> u32 {
        self.m_kib
    }

    /// Passes.
    pub const fn t(&self) -> u32 {
        self.t
    }

    /// Lanes.
    pub const fn p(&self) -> u32 {
        self.p
    }

    /// The envelope's salt.
    pub const fn salt(&self) -> &[u8; 16] {
        &self.salt
    }

    /// Fails unless every parameter is within the bounds in [`KdfParams`].
    /// Cheap; runs before any Argon2 work.
    pub fn check_bounds(&self) -> Result<(), CryptoError> {
        check_bounds(self.m_kib, self.t, self.p)
    }
}

fn check_bounds(m_kib: u32, t: u32, p: u32) -> Result<(), CryptoError> {
    let ok = (KdfParams::MIN_M_KIB..=KdfParams::MAX_M_KIB).contains(&m_kib)
        && (KdfParams::MIN_T..=KdfParams::MAX_T).contains(&t)
        && (KdfParams::MIN_P..=KdfParams::MAX_P).contains(&p);
    if ok {
        Ok(())
    } else {
        Err(CryptoErrorKind::KdfParams.into())
    }
}

/// A 256-bit key-encryption key. Only a [`Kdf`] makes one, and only the
/// envelope code reads it.
pub struct Kek(pub(crate) SecretBox<[u8; 32]>);

impl core::fmt::Debug for Kek {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Kek(..)")
    }
}

/// A key derivation backend. [`Argon2id`] is the only production one; the
/// trait exists so tests can observe whether, and how often, derivation
/// runs. [`derive_kek`] checks the parameters before calling it.
pub trait Kdf {
    /// Derives a KEK from `secret` under `params`, which are within bounds.
    fn derive(&self, secret: &SecretBytes, params: &StoredKdfParams) -> Result<Kek, CryptoError>;
}

/// Argon2id, version 0x13, 32-byte output, no secret key or associated
/// data.
#[derive(Debug, Clone, Copy, Default)]
pub struct Argon2id;

impl Kdf for Argon2id {
    #[allow(clippy::disallowed_methods)] // Hashes the passphrase or kit.
    fn derive(&self, secret: &SecretBytes, params: &StoredKdfParams) -> Result<Kek, CryptoError> {
        params.check_bounds()?;
        // A test build with its trace on counts the runs (gate: one
        // Argon2id run per proof).
        envcloak_sys::test_event("argon2id run");
        let mut result = Ok(());
        let kek = SecretBox::init_with_mut(|out: &mut [u8; 32]| {
            result = argon2id(
                secret.expose_secret(),
                &params.salt,
                params.m_kib,
                params.t,
                params.p,
                out,
            );
        });
        result.map(|()| Kek(kek))
    }
}

/// Checks `params` against the bounds, then derives. The only way the
/// envelope code derives a KEK.
pub(crate) fn derive_kek<K: Kdf + ?Sized>(
    kdf: &K,
    secret: &SecretBytes,
    params: &StoredKdfParams,
) -> Result<Kek, CryptoError> {
    params.check_bounds()?;
    kdf.derive(secret, params)
}

/// Raw Argon2id into `out`, in working memory from [`argon2_memory`],
/// which is wiped when this returns. The salt is a slice so the reference
/// vectors, whose salts are not 16 bytes, can run through it.
fn argon2id(
    pwd: &[u8],
    salt: &[u8],
    m_kib: u32,
    t: u32,
    p: u32,
    out: &mut [u8; 32],
) -> Result<(), CryptoError> {
    let kdf_err = |_| CryptoError::new(CryptoErrorKind::Kdf);
    let params = Params::new(m_kib, t, p, Some(out.len())).map_err(kdf_err)?;
    let mut memory = argon2_memory(params.block_count())?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(pwd, salt, out, memory.as_mut_slice())
        .map_err(kdf_err)
}

/// Argon2id's working memory: `blocks` zeroed 1 KiB blocks, wiped when
/// dropped. A failed allocation is [`CryptoErrorKind::Kdf`], as argon2's
/// own would be, never an abort.
fn argon2_memory(blocks: usize) -> Result<Zeroizing<Vec<Block>>, CryptoError> {
    let mut memory = Zeroizing::new(Vec::new());
    memory
        .try_reserve_exact(blocks)
        .map_err(|_| CryptoError::new(CryptoErrorKind::Kdf))?;
    memory.resize(blocks, Block::default());
    Ok(memory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    /// The reference implementation's test for Argon2id version 0x13 at
    /// m = 64 MiB, t = 2, p = 1 (phc-winner-argon2 src/test.c), which are
    /// EnvCloak's minimum bounds: password "password", salt "somesalt".
    #[test]
    fn argon2id_matches_the_reference_at_the_minimum_bounds() {
        let mut out = [0u8; 32];
        argon2id(b"password", b"somesalt", 65536, 2, 1, &mut out).unwrap();
        // $argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc
        let want = [
            0x09, 0x31, 0x61, 0x15, 0xd5, 0xcf, 0x24, 0xed, 0x5a, 0x15, 0xa3, 0x1a, 0x3b, 0xa3,
            0x26, 0xe5, 0xcf, 0x32, 0xed, 0xc2, 0x47, 0x02, 0x98, 0x7c, 0x02, 0xb6, 0x56, 0x6f,
            0x61, 0x91, 0x3c, 0xf7,
        ];
        assert_eq!(out, want);
    }

    #[test]
    fn bounds_are_inclusive_and_enforced() {
        KdfParams::minimum().check_bounds().unwrap();
        KdfParams::current_defaults().check_bounds().unwrap();
        let edges_ok = [
            (KdfParams::MIN_M_KIB, KdfParams::MIN_T, KdfParams::MIN_P),
            (KdfParams::MAX_M_KIB, KdfParams::MAX_T, KdfParams::MAX_P),
        ];
        for (m_kib, t, p) in edges_ok {
            StoredKdfParams::parsed(m_kib, t, p, [0; 16])
                .check_bounds()
                .unwrap();
        }
        let bad = [
            (KdfParams::MIN_M_KIB - 1, 2, 1),
            (KdfParams::MAX_M_KIB + 1, 2, 1),
            (0, 2, 1),
            (u32::MAX, 2, 1),
            (KdfParams::MIN_M_KIB, 1, 1),
            (KdfParams::MIN_M_KIB, 17, 1),
            (KdfParams::MIN_M_KIB, 0, 1),
            (KdfParams::MIN_M_KIB, 2, 0),
            (KdfParams::MIN_M_KIB, 2, 17),
        ];
        for (m_kib, t, p) in bad {
            let e = StoredKdfParams::parsed(m_kib, t, p, [0; 16])
                .check_bounds()
                .unwrap_err();
            assert_eq!(e.kind(), CryptoErrorKind::KdfParams);
        }
        for m_kib in [KdfParams::MIN_M_KIB - 1, KdfParams::MAX_M_KIB + 1] {
            let e = KdfParams::with_memory(m_kib).check_bounds().unwrap_err();
            assert_eq!(e.kind(), CryptoErrorKind::KdfParams);
        }
    }

    #[test]
    fn the_constructors_give_the_spec_parameters() {
        let d = KdfParams::current_defaults();
        assert_eq!(
            (d.m_kib(), d.t(), d.p()),
            (256 * 1024, 3, 4),
            "SPEC §5 defaults"
        );
        let m = KdfParams::minimum();
        assert_eq!((m.m_kib(), m.t(), m.p()), (64 * 1024, 2, 1));
        let w = KdfParams::with_memory(100 * 1024);
        assert_eq!((w.m_kib(), w.t(), w.p()), (100 * 1024, 3, 4));
        let s = m.stored_with([7; 16]);
        assert_eq!(
            (s.m_kib(), s.t(), s.p(), *s.salt()),
            (64 * 1024, 2, 1, [7; 16])
        );
    }

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

    #[test]
    fn derive_kek_checks_bounds_before_the_backend() {
        let spy = Spy(Cell::new(0));
        let pass = SecretBytes::copy_from(b"a passphrase for the spy test");
        let bad = StoredKdfParams::parsed(KdfParams::MIN_M_KIB, 1, 1, [3; 16]);
        let e = derive_kek(&spy, &pass, &bad).unwrap_err();
        assert_eq!(e.kind(), CryptoErrorKind::KdfParams);
        assert_eq!(spy.0.get(), 0);
        derive_kek(&spy, &pass, &KdfParams::minimum().stored_with([3; 16])).unwrap();
        assert_eq!(spy.0.get(), 1);
    }

    #[test]
    #[allow(clippy::disallowed_methods)] // Compares derived keys.
    fn argon2id_backend_depends_on_every_input() {
        let pass = SecretBytes::copy_from(b"correct horse battery staple");
        let salt = [0x42; 16];
        let p = KdfParams::minimum().stored_with(salt);
        let k = |s: &SecretBytes, p: &StoredKdfParams| {
            *Argon2id.derive(s, p).unwrap().0.expose_secret()
        };
        let base = k(&pass, &p);
        assert_eq!(base, k(&pass, &p));
        let other = SecretBytes::copy_from(b"correct horse battery stapla");
        assert_ne!(base, k(&other, &p));
        let mut salted = salt;
        salted[0] ^= 1;
        assert_ne!(base, k(&pass, &KdfParams::minimum().stored_with(salted)));
        let more_passes = StoredKdfParams::parsed(KdfParams::MIN_M_KIB, 3, 1, salt);
        assert_ne!(base, k(&pass, &more_passes));
        assert_eq!(
            format!("{:?}", Argon2id.derive(&pass, &p).unwrap()),
            "Kek(..)"
        );
    }
}
