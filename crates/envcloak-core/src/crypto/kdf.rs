//! Argon2id key derivation for unlockers (SPEC §5 "Envelope parameters").
//!
//! KEK = Argon2id (version 0x13) of the passphrase or Recovery Kit, with a
//! 16-byte salt and a 32-byte output. Parameters are stored with each
//! envelope and are untrusted when read back: [`KdfParams::check_bounds`]
//! rejects anything outside 64 MiB to 4 GiB of memory, 2 to 16 passes and 1
//! to 16 lanes, and [`derive_kek`] runs it before any key derivation work,
//! so a doctored envelope can neither weaken the KDF nor make it exhaust
//! memory.
//!
//! Argon2id takes most of a second at the defaults. The daemon must run it
//! on a blocking thread.

use argon2::{Algorithm, Argon2, Params, Version};
use secrecy::{ExposeSecret, SecretBox};

use super::{CryptoError, CryptoErrorKind, fill_random_or_panic};
use crate::secret::SecretBytes;

/// Argon2id parameters and salt, as stored in an envelope. Not secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_kib: u32,
    /// Passes.
    pub t: u32,
    /// Lanes.
    pub p: u32,
    pub salt: [u8; 16],
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
    /// 3 passes, 4 lanes, and a fresh random salt.
    ///
    /// # Panics
    /// When the OS random number generator fails.
    pub fn current_defaults() -> Self {
        Self::fresh(Self::DEFAULT_M_KIB, Self::DEFAULT_T, Self::DEFAULT_P)
    }

    /// The cheapest parameters the bounds allow (64 MiB, 2 passes, 1 lane),
    /// with a fresh random salt: for machines that cannot spare 256 MiB,
    /// and for tests.
    ///
    /// # Panics
    /// When the OS random number generator fails.
    pub fn minimum() -> Self {
        Self::fresh(Self::MIN_M_KIB, Self::MIN_T, Self::MIN_P)
    }

    /// The same parameters with a fresh random salt: each envelope draws
    /// its own.
    ///
    /// # Panics
    /// When the OS random number generator fails.
    pub fn with_fresh_salt(&self) -> Self {
        Self::fresh(self.m_kib, self.t, self.p)
    }

    fn fresh(m_kib: u32, t: u32, p: u32) -> Self {
        let mut salt = [0u8; 16];
        fill_random_or_panic(&mut salt);
        KdfParams { m_kib, t, p, salt }
    }

    /// Fails unless every parameter is within the bounds. Cheap; runs
    /// before any Argon2 work.
    pub fn check_bounds(&self) -> Result<(), CryptoError> {
        let ok = (Self::MIN_M_KIB..=Self::MAX_M_KIB).contains(&self.m_kib)
            && (Self::MIN_T..=Self::MAX_T).contains(&self.t)
            && (Self::MIN_P..=Self::MAX_P).contains(&self.p);
        if ok {
            Ok(())
        } else {
            Err(CryptoErrorKind::KdfParams.into())
        }
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
    fn derive(&self, secret: &SecretBytes, params: &KdfParams) -> Result<Kek, CryptoError>;
}

/// Argon2id, version 0x13, 32-byte output, no secret key or associated
/// data.
#[derive(Debug, Clone, Copy, Default)]
pub struct Argon2id;

impl Kdf for Argon2id {
    #[allow(clippy::disallowed_methods)] // Hashes the passphrase or kit.
    fn derive(&self, secret: &SecretBytes, params: &KdfParams) -> Result<Kek, CryptoError> {
        params.check_bounds()?;
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
    params: &KdfParams,
) -> Result<Kek, CryptoError> {
    params.check_bounds()?;
    kdf.derive(secret, params)
}

/// Raw Argon2id into `out`. The salt is a slice so the reference vectors,
/// whose salts are not 16 bytes, can run through it.
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
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(pwd, salt, out)
        .map_err(kdf_err)
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
        let base = KdfParams::minimum();
        base.check_bounds().unwrap();
        KdfParams::current_defaults().check_bounds().unwrap();
        let edges_ok = [
            (KdfParams::MIN_M_KIB, KdfParams::MIN_T, KdfParams::MIN_P),
            (KdfParams::MAX_M_KIB, KdfParams::MAX_T, KdfParams::MAX_P),
        ];
        for (m_kib, t, p) in edges_ok {
            KdfParams {
                m_kib,
                t,
                p,
                ..base
            }
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
            let e = KdfParams {
                m_kib,
                t,
                p,
                ..base
            }
            .check_bounds()
            .unwrap_err();
            assert_eq!(e.kind(), CryptoErrorKind::KdfParams);
        }
    }

    #[test]
    fn fresh_params_get_fresh_salts() {
        let a = KdfParams::current_defaults();
        let b = KdfParams::current_defaults();
        assert_ne!(a.salt, b.salt);
        assert_eq!((a.m_kib, a.t, a.p), (256 * 1024, 3, 4), "SPEC §5 defaults");
        let m = KdfParams::minimum();
        assert_eq!((m.m_kib, m.t, m.p), (64 * 1024, 2, 1));
    }

    struct Spy(Cell<usize>);

    impl Kdf for Spy {
        fn derive(&self, secret: &SecretBytes, params: &KdfParams) -> Result<Kek, CryptoError> {
            self.0.set(self.0.get() + 1);
            Argon2id.derive(secret, params)
        }
    }

    #[test]
    fn derive_kek_checks_bounds_before_the_backend() {
        let spy = Spy(Cell::new(0));
        let pass = SecretBytes::copy_from(b"a passphrase for the spy test");
        let bad = KdfParams {
            t: 1,
            ..KdfParams::minimum()
        };
        let e = derive_kek(&spy, &pass, &bad).unwrap_err();
        assert_eq!(e.kind(), CryptoErrorKind::KdfParams);
        assert_eq!(spy.0.get(), 0);
        derive_kek(&spy, &pass, &KdfParams::minimum()).unwrap();
        assert_eq!(spy.0.get(), 1);
    }

    #[test]
    #[allow(clippy::disallowed_methods)] // Compares derived keys.
    fn argon2id_backend_depends_on_every_input() {
        let pass = SecretBytes::copy_from(b"correct horse battery staple");
        let p = KdfParams::minimum();
        let k = |s: &SecretBytes, p: &KdfParams| *Argon2id.derive(s, p).unwrap().0.expose_secret();
        let base = k(&pass, &p);
        assert_eq!(base, k(&pass, &p));
        let other = SecretBytes::copy_from(b"correct horse battery stapla");
        assert_ne!(base, k(&other, &p));
        let mut salted = p;
        salted.salt[0] ^= 1;
        assert_ne!(base, k(&pass, &salted));
        assert_ne!(base, k(&pass, &KdfParams { t: 3, ..p }));
        assert_eq!(
            format!("{:?}", Argon2id.derive(&pass, &p).unwrap()),
            "Kek(..)"
        );
    }
}
