//! The vault's plaintext boundary: the one vault file allowed to open a
//! secret (security/expose-allowlist.txt).
//!
//! - Field values are sealed from and opened into [`SecretBytes`], and
//!   hashed under the `index` subkey for duplicate detection.
//! - Prior values are packed into one buffer of exact size, sealed, and
//!   wiped; opening one unpacks it into separate [`SecretBytes`].
//! - Other sealed records (metadata, the header) are opened here and their
//!   plaintext is handed to a decoder as a slice, so decoders never call
//!   `expose_secret` themselves.
//!
//! Only sealed bytes leave this file for SQLite.

use secrecy::ExposeSecret;
use zeroize::Zeroizing;

use crate::crypto::{Aad, CryptoError, Sealed, SubKey, keyed_hash, open, seal};
use crate::secret::SecretBytes;

use super::error::{VaultError, VaultErrorKind};
use super::items::{MAX_FIELD, MAX_PRIOR};

/// The keyed-hash domain of `fields.value_hash`.
pub(crate) const VALUE_DOMAIN: &str = "envcloak/v1/value";
const PRIOR_RECORD: u8 = 1;

/// Seals a non-secret record (metadata, the header).
pub(crate) fn seal_record(k: &SubKey, aad: &Aad, record: &[u8]) -> Result<Vec<u8>, VaultError> {
    Ok(seal(k, aad, record)?.to_bytes())
}

/// Opens a sealed record and hands its plaintext to `decode`. The
/// plaintext is wiped when this returns.
#[allow(clippy::disallowed_methods)] // Hands decrypted metadata to its decoder.
pub(crate) fn open_record<T>(
    k: &SubKey,
    aad: &Aad,
    stored: &[u8],
    decode: impl FnOnce(&[u8]) -> Result<T, VaultError>,
) -> Result<T, CryptoOrRecord> {
    let pt = open_stored(k, aad, stored).map_err(|_| CryptoOrRecord::Crypto)?;
    decode(pt.expose_secret()).map_err(|_| CryptoOrRecord::Record)
}

/// Why [`open_record`] failed: the sealed bytes did not open, or the
/// plaintext did not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CryptoOrRecord {
    Crypto,
    Record,
}

/// Fails unless `v` is a storable value: 1 byte to [`MAX_FIELD`].
pub(crate) fn check_value(v: &SecretBytes) -> Result<(), VaultError> {
    if v.is_empty() {
        return Err(VaultErrorKind::InvalidValue.into());
    }
    if v.len() > MAX_FIELD {
        return Err(VaultErrorKind::TooLarge.into());
    }
    Ok(())
}

/// Seals a value.
#[allow(clippy::disallowed_methods)] // Encrypts the value.
pub(crate) fn seal_value(k: &SubKey, aad: &Aad, v: &SecretBytes) -> Result<Vec<u8>, VaultError> {
    Ok(seal(k, aad, v.expose_secret())?.to_bytes())
}

/// Opens a sealed value.
pub(crate) fn open_value(k: &SubKey, aad: &Aad, stored: &[u8]) -> Result<SecretBytes, CryptoError> {
    open_stored(k, aad, stored)
}

/// Keyed BLAKE3 of a value under the `index` subkey.
#[allow(clippy::disallowed_methods)] // Hashes the value for lookups.
pub(crate) fn value_hash(index: &SubKey, v: &SecretBytes) -> [u8; 32] {
    keyed_hash(index, VALUE_DOMAIN, v.expose_secret())
}

/// Seals prior values, newest first: `version(1) count(1)` then `len(4)
/// bytes` for each. `None` when there are none.
#[allow(clippy::disallowed_methods)] // Packs prior values to encrypt them.
pub(crate) fn seal_priors(
    k: &SubKey,
    aad: &Aad,
    priors: &[SecretBytes],
) -> Result<Option<Vec<u8>>, VaultError> {
    if priors.is_empty() {
        return Ok(None);
    }
    if priors.len() > MAX_PRIOR {
        return Err(VaultErrorKind::Corrupt.into());
    }
    let total = 2 + priors.iter().map(|p| 4 + p.len()).sum::<usize>();
    // Exact capacity: the pushes below never reallocate, so no unwiped copy
    // is freed, and `Zeroizing` wipes the buffer when it drops.
    let mut buf = Zeroizing::new(Vec::with_capacity(total));
    buf.push(PRIOR_RECORD);
    buf.push(u8::try_from(priors.len()).map_err(|_| VaultError::from(VaultErrorKind::Corrupt))?);
    for p in priors {
        let len = u32::try_from(p.len()).map_err(|_| VaultError::from(VaultErrorKind::TooLarge))?;
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(p.expose_secret());
    }
    debug_assert_eq!(buf.len(), total);
    Ok(Some(seal(k, aad, &buf)?.to_bytes()))
}

/// Opens [`seal_priors`]'s output, which must hold `count` values: the
/// authenticated `prior_count` of the field's record. `None` stored is no
/// priors, and is accepted only when `count` is 0, so a list removed from
/// the row (a NULL has no seal to fail) is caught like an altered one.
#[allow(clippy::disallowed_methods)] // Unpacks prior values.
pub(crate) fn open_priors(
    k: &SubKey,
    aad: &Aad,
    stored: Option<&[u8]>,
    count: u8,
) -> Result<Vec<SecretBytes>, CryptoOrRecord> {
    let Some(stored) = stored else {
        return if count == 0 {
            Ok(Vec::new())
        } else {
            Err(CryptoOrRecord::Record)
        };
    };
    let packed = open_stored(k, aad, stored).map_err(|_| CryptoOrRecord::Crypto)?;
    let priors = unpack_priors(packed.expose_secret()).map_err(|_| CryptoOrRecord::Record)?;
    if priors.len() != usize::from(count) {
        return Err(CryptoOrRecord::Record);
    }
    Ok(priors)
}

fn unpack_priors(b: &[u8]) -> Result<Vec<SecretBytes>, VaultError> {
    let corrupt = || VaultError::from(VaultErrorKind::Corrupt);
    let (&version, rest) = b.split_first().ok_or_else(corrupt)?;
    let (&count, mut rest) = rest.split_first().ok_or_else(corrupt)?;
    if version != PRIOR_RECORD || count == 0 || usize::from(count) > MAX_PRIOR {
        return Err(corrupt());
    }
    let mut out = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let (len, tail) = rest.split_first_chunk::<4>().ok_or_else(corrupt)?;
        let len = usize::try_from(u32::from_be_bytes(*len)).map_err(|_| corrupt())?;
        let value = tail.get(..len).ok_or_else(corrupt)?;
        out.push(SecretBytes::copy_from(value));
        rest = &tail[len..];
    }
    if !rest.is_empty() {
        return Err(corrupt());
    }
    Ok(out)
}

/// Re-seals a stored record under new associated data (a schema
/// migration). The plaintext is wiped when this returns.
#[allow(clippy::disallowed_methods)] // Moves plaintext from one seal to another.
pub(crate) fn reseal(
    k: &SubKey,
    from: &Aad,
    to: &Aad,
    stored: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let pt = open_stored(k, from, stored)?;
    Ok(seal(k, to, pt.expose_secret())?.to_bytes())
}

fn open_stored(k: &SubKey, aad: &Aad, stored: &[u8]) -> Result<SecretBytes, CryptoError> {
    let sealed = Sealed::from_bytes(stored)?;
    open(k, aad, &sealed)
}

/// Maps a failure to open a stored row to the error a reader sees.
pub(crate) fn tampered(_: CryptoError) -> VaultError {
    VaultErrorKind::Tampered.into()
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // Tests read values back.
mod tests {
    use super::*;
    use crate::crypto::{FieldTag, ItemClass, Keyring, Purpose, TableTag, VaultId, Vmk};

    fn aad(rv: u64) -> Aad {
        Aad {
            vault_id: VaultId([1; 16]),
            schema_version: 1,
            key_epoch: 1,
            table: TableTag::Fields,
            row_id: [2; 16],
            field: FieldTag::FieldPrior,
            item_class: ItemClass::Secret,
            row_version: rv,
        }
    }

    #[test]
    fn priors_round_trip_and_bind_to_their_row() {
        let kr = Keyring::derive(&Vmk::generate(), &VaultId([1; 16]), 1);
        let k = kr.key(Purpose::Data);
        let priors = vec![
            SecretBytes::copy_from(b"newest"),
            SecretBytes::copy_from(&[0u8; 300]),
            SecretBytes::copy_from(b"x"),
        ];
        let stored = seal_priors(k, &aad(4), &priors).unwrap().unwrap();
        let back = open_priors(k, &aad(4), Some(&stored), 3).unwrap();
        assert_eq!(back.len(), 3);
        for (a, b) in priors.iter().zip(&back) {
            assert_eq!(a.expose_secret(), b.expose_secret());
        }
        assert!(matches!(
            open_priors(k, &aad(5), Some(&stored), 3),
            Err(CryptoOrRecord::Crypto)
        ));
        assert!(seal_priors(k, &aad(4), &[]).unwrap().is_none());
        assert!(open_priors(k, &aad(4), None, 0).unwrap().is_empty());
        let four: Vec<_> = (0..4).map(|_| SecretBytes::copy_from(b"v")).collect();
        assert!(seal_priors(k, &aad(4), &four).is_err());
    }

    /// Codex F-21: the stored list must agree with the authenticated count.
    /// A removed list (NULL) where the record counts priors, or a list of
    /// another length, is refused.
    #[test]
    fn priors_must_match_the_authenticated_count() {
        let kr = Keyring::derive(&Vmk::generate(), &VaultId([1; 16]), 1);
        let k = kr.key(Purpose::Data);
        let two = [SecretBytes::copy_from(b"b"), SecretBytes::copy_from(b"a")];
        let stored = seal_priors(k, &aad(4), &two).unwrap().unwrap();
        assert_eq!(open_priors(k, &aad(4), Some(&stored), 2).unwrap().len(), 2);
        for count in [0, 1, 3] {
            assert!(matches!(
                open_priors(k, &aad(4), Some(&stored), count),
                Err(CryptoOrRecord::Record)
            ));
        }
        for count in 1..=3 {
            assert!(matches!(
                open_priors(k, &aad(4), None, count),
                Err(CryptoOrRecord::Record)
            ));
        }
    }

    #[test]
    fn malformed_prior_packs_are_corrupt() {
        for bad in [
            &[][..],
            &[1][..],
            &[2, 1, 0, 0, 0, 0][..],
            &[1, 0][..],
            &[1, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0][..],
            &[1, 1, 0, 0, 0, 2, b'a'][..],
            &[1, 1, 0, 0, 0, 1, b'a', b'b'][..],
        ] {
            assert_eq!(
                unpack_priors(bad).unwrap_err().kind(),
                VaultErrorKind::Corrupt,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn values_are_checked_for_size() {
        assert_eq!(
            check_value(&SecretBytes::copy_from(b""))
                .unwrap_err()
                .kind(),
            VaultErrorKind::InvalidValue
        );
        check_value(&SecretBytes::copy_from(&vec![1u8; MAX_FIELD])).unwrap();
        assert_eq!(
            check_value(&SecretBytes::copy_from(&vec![1u8; MAX_FIELD + 1]))
                .unwrap_err()
                .kind(),
            VaultErrorKind::TooLarge
        );
    }
}
