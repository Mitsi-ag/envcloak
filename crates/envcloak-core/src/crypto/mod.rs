//! Crypto primitives for the vault (SPEC §5 "Vault", §11).
//!
//! - [`seal`] and [`open`]: XChaCha20-Poly1305 under a [`SubKey`], with a
//!   fresh 192-bit nonce from the OS CSPRNG per seal and the canonical
//!   associated data [`Aad`] of the row and field being sealed.
//! - [`Keyring`]: the eight purpose subkeys of one VMK epoch,
//!   HKDF-SHA256(ikm = VMK, salt = vault_id, info =
//!   `envcloak/v1/<purpose>/e<epoch>`). [`keyed_hash`] is keyed BLAKE3 under
//!   a subkey.
//!
//! Errors are [`CryptoError`]s, whose `Display` comes from a fixed set of
//! strings and whose `Debug` names the kind only. Upstream error text is
//! never forwarded.

mod aad;
mod aead;
mod keys;

pub use aad::{Aad, FieldTag, ItemClass, TableTag};
pub use aead::{Sealed, open, seal};
pub use keys::{Keyring, Purpose, SubKey, UnlockerId, VaultId, Vmk, keyed_hash};

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
}

impl CryptoErrorKind {
    /// Every kind, in declaration order.
    pub const ALL: [CryptoErrorKind; 4] = [
        CryptoErrorKind::Seal,
        CryptoErrorKind::Open,
        CryptoErrorKind::Malformed,
        CryptoErrorKind::Random,
    ];

    /// The fixed message for this kind.
    pub const fn message(self) -> &'static str {
        match self {
            CryptoErrorKind::Seal => "encryption failed",
            CryptoErrorKind::Open => "decryption failed: the data is damaged or belongs elsewhere",
            CryptoErrorKind::Malformed => "sealed data is malformed",
            CryptoErrorKind::Random => "the system random number generator failed",
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
