//! Crypto primitives for the vault (SPEC §5 "Vault", §11; the byte formats
//! are in docs/CRYPTO.md).
//!
//! - [`seal`] and [`open`]: XChaCha20-Poly1305 under a [`SubKey`], with a
//!   fresh 192-bit nonce from the OS CSPRNG per seal and the canonical
//!   associated data [`Aad`] of the row and field being sealed.
//! - [`Keyring`]: the eight purpose subkeys of one VMK epoch,
//!   HKDF-SHA256(ikm = VMK, salt = vault_id, info =
//!   `envcloak/v1/<purpose>/e<epoch>`). [`keyed_hash`] is keyed BLAKE3 under
//!   a subkey.
//! - [`KdfParams`], [`StoredKdfParams`] and [`Kdf`]: Argon2id. A wrap
//!   takes a [`KdfParams`] (no salt: it draws a fresh one per envelope);
//!   an envelope's stored parameters and salt are a [`StoredKdfParams`],
//!   which only unwrapping reads, checked against fixed bounds before any
//!   key derivation work.
//! - [`Envelope`]: the VMK wrapped under a passphrase or Recovery Kit. The
//!   key-encryption key comes from Argon2id; a key-commitment tag over the
//!   envelope header is checked in constant time before decryption.
//!
//! Errors are [`CryptoError`]s, whose `Display` comes from a fixed set of
//! strings and whose `Debug` names the kind only. Upstream error text is
//! never forwarded. A wrong passphrase or Recovery Kit, a damaged
//! envelope and an envelope from another vault all give the same error.

mod aad;
mod aead;
mod envelope;
mod kdf;
mod keys;

pub use aad::{Aad, FieldTag, ItemClass, TableTag};
#[cfg(test)]
pub(crate) use aead::OPEN_ATTEMPTS;
pub use aead::{Sealed, open, seal};
pub use envelope::{
    Envelope, EnvelopeCtx, UnlockerKind, rewrap_vmk, unwrap_vmk, unwrap_vmk_with, wrap_vmk,
    wrap_vmk_with,
};
pub use kdf::{Argon2id, Kdf, KdfParams, Kek, StoredKdfParams};
pub use keys::{Keyring, Purpose, SubKey, UnlockerId, VaultId, Vmk, keyed_hash};
pub(crate) use keys::{keyed_hash_parts, keyed_hash_prefixes, open_subkey, seal_subkey};

/// A crypto failure. Carries its kind only: no values, sizes of secrets or
/// upstream error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoError {
    kind: CryptoErrorKind,
}

/// What went wrong. Each kind has one fixed message, its `Display`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CryptoErrorKind {
    /// The AEAD refused to encrypt (a message beyond its length limit).
    Seal,
    /// Authentication failed: the data was altered, or it is opened with
    /// another key or other associated data than it was sealed with.
    Open,
    /// Sealed bytes too short to hold a nonce and a tag.
    Malformed,
    /// The OS random number generator failed.
    Random,
    /// Argon2id parameters outside the bounds in [`KdfParams`].
    KdfParams,
    /// Argon2id failed (out of memory, say).
    Kdf,
    /// Envelope bytes of the wrong length, magic, version, kind or KDF.
    EnvelopeFormat,
    /// The envelope names another unlocker or key epoch than the caller
    /// expects.
    EnvelopeMismatch,
    /// The one error for a wrong passphrase or Recovery Kit, a damaged
    /// envelope, or an envelope from another vault.
    Unlock,
}

impl CryptoErrorKind {
    /// Every kind, in declaration order.
    pub const ALL: [CryptoErrorKind; 9] = [
        CryptoErrorKind::Seal,
        CryptoErrorKind::Open,
        CryptoErrorKind::Malformed,
        CryptoErrorKind::Random,
        CryptoErrorKind::KdfParams,
        CryptoErrorKind::Kdf,
        CryptoErrorKind::EnvelopeFormat,
        CryptoErrorKind::EnvelopeMismatch,
        CryptoErrorKind::Unlock,
    ];

    /// The fixed message for this kind.
    pub const fn message(self) -> &'static str {
        match self {
            CryptoErrorKind::Seal => "encryption failed",
            CryptoErrorKind::Open => "decryption failed: the data is damaged or belongs elsewhere",
            CryptoErrorKind::Malformed => "sealed data is malformed",
            CryptoErrorKind::Random => "the system random number generator failed",
            CryptoErrorKind::KdfParams => "key derivation parameters are out of bounds",
            CryptoErrorKind::Kdf => "key derivation failed",
            CryptoErrorKind::EnvelopeFormat => {
                "unlocker envelope is malformed or has an unsupported format"
            }
            CryptoErrorKind::EnvelopeMismatch => {
                "unlocker envelope belongs to another unlocker or key epoch"
            }
            CryptoErrorKind::Unlock => {
                "wrong passphrase or Recovery Kit, or the unlocker envelope is damaged"
            }
        }
    }
}

impl CryptoError {
    pub(crate) const fn new(kind: CryptoErrorKind) -> Self {
        CryptoError { kind }
    }

    pub fn kind(&self) -> CryptoErrorKind {
        self.kind
    }
}

impl From<CryptoErrorKind> for CryptoError {
    fn from(kind: CryptoErrorKind) -> Self {
        CryptoError::new(kind)
    }
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.kind.message())
    }
}

impl std::error::Error for CryptoError {}

/// Fills `buf` from the OS CSPRNG.
pub(crate) fn fill_random(buf: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::fill(buf).map_err(|_| CryptoError::new(CryptoErrorKind::Random))
}

/// Fills `buf` from the OS CSPRNG, for the constructors that cannot fail.
///
/// # Panics
/// When the OS random number generator fails. Nothing safe can be done
/// without it, and release builds abort on panic.
pub(crate) fn fill_random_or_panic(buf: &mut [u8]) {
    if fill_random(buf).is_err() {
        panic!("{}", CryptoErrorKind::Random.message());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exhaustive without a wildcard, so a new kind fails to compile here
    /// until it is added to `ALL`.
    fn position(k: CryptoErrorKind) -> usize {
        match k {
            CryptoErrorKind::Seal => 0,
            CryptoErrorKind::Open => 1,
            CryptoErrorKind::Malformed => 2,
            CryptoErrorKind::Random => 3,
            CryptoErrorKind::KdfParams => 4,
            CryptoErrorKind::Kdf => 5,
            CryptoErrorKind::EnvelopeFormat => 6,
            CryptoErrorKind::EnvelopeMismatch => 7,
            CryptoErrorKind::Unlock => 8,
        }
    }

    #[test]
    fn all_lists_every_kind_once() {
        for (i, k) in CryptoErrorKind::ALL.iter().enumerate() {
            assert_eq!(position(*k), i);
        }
    }

    #[test]
    fn display_is_the_fixed_message_and_debug_names_the_kind() {
        for k in CryptoErrorKind::ALL {
            let e = CryptoError::from(k);
            assert_eq!(e.to_string(), k.message());
            assert_eq!(format!("{e:?}"), format!("CryptoError {{ kind: {k:?} }}"));
            assert!(std::error::Error::source(&e).is_none());
        }
    }
}
