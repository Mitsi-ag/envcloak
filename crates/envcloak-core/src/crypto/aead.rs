//! XChaCha20-Poly1305 sealing (SPEC §5 "Vault").
//!
//! [`seal`] draws a fresh 192-bit nonce from the OS CSPRNG for every call;
//! counters are never used. Encryption writes ciphertext straight into its
//! output buffer, so no buffer the sealer allocates ever holds plaintext.
//! [`open`] checks the tag before decrypting and decrypts into one
//! exact-size buffer that becomes the returned [`SecretBytes`] without
//! moving.

use chacha20poly1305::aead::inout::InOutBuf;
use chacha20poly1305::{AeadInOut, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use secrecy::ExposeSecret;
use zeroize::Zeroizing;

use super::aad::Aad;
use super::keys::SubKey;
use super::{CryptoError, CryptoErrorKind, fill_random};
use crate::secret::SecretBytes;

/// A sealed value: the nonce, then the ciphertext with its 16-byte tag
/// appended.
#[derive(Clone, PartialEq, Eq)]
pub struct Sealed {
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

impl Sealed {
    pub const NONCE_LEN: usize = 24;
    pub const TAG_LEN: usize = 16;
    /// Bytes [`Sealed::to_bytes`] adds to the plaintext length.
    pub const OVERHEAD: usize = Self::NONCE_LEN + Self::TAG_LEN;

    /// `nonce || ciphertext || tag`, the stored form.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::NONCE_LEN + self.ciphertext.len());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Parses [`Sealed::to_bytes`]'s output. Fails when `b` is too short to
    /// hold a nonce and a tag.
    pub fn from_bytes(b: &[u8]) -> Result<Self, CryptoError> {
        if b.len() < Self::OVERHEAD {
            return Err(CryptoErrorKind::Malformed.into());
        }
        let (nonce, ciphertext) = b.split_at(Self::NONCE_LEN);
        let mut n = [0u8; Self::NONCE_LEN];
        n.copy_from_slice(nonce);
        Ok(Sealed {
            nonce: n,
            ciphertext: ciphertext.to_vec(),
        })
    }
}

impl core::fmt::Debug for Sealed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sealed")
            .field("ciphertext_len", &self.ciphertext.len())
            .finish_non_exhaustive()
    }
}

/// Seals `pt` under `k`, bound to `aad`, with a fresh random nonce.
#[allow(clippy::disallowed_methods)] // Reads the subkey to encrypt.
pub fn seal(k: &SubKey, aad: &Aad, pt: &[u8]) -> Result<Sealed, CryptoError> {
    let mut nonce = [0u8; Sealed::NONCE_LEN];
    fill_random(&mut nonce)?;
    let ciphertext = seal_with_nonce(k.key.expose_secret(), &nonce, &aad.encode(), pt)?;
    Ok(Sealed { nonce, ciphertext })
}

/// Opens `s` under `k` and `aad`. Any change to the nonce, ciphertext, tag,
/// key or associated data fails with [`CryptoErrorKind::Open`].
#[allow(clippy::disallowed_methods)] // Reads the subkey to decrypt.
pub fn open(k: &SubKey, aad: &Aad, s: &Sealed) -> Result<SecretBytes, CryptoError> {
    let Some(len) = s.ciphertext.len().checked_sub(Sealed::TAG_LEN) else {
        return Err(CryptoErrorKind::Malformed.into());
    };
    // `vec![0; n]` allocates exactly n bytes, so `from_vec` keeps this
    // allocation; nothing holding plaintext is ever copied or freed.
    let mut out = Zeroizing::new(vec![0u8; len]);
    open_into(
        k.key.expose_secret(),
        &s.nonce,
        &aad.encode(),
        &s.ciphertext,
        &mut out,
    )?;
    Ok(SecretBytes::from_vec(core::mem::take(&mut *out)))
}

/// XChaCha20-Poly1305 encryption of `pt`: returns `ciphertext || tag`.
pub(crate) fn seal_with_nonce(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    pt: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let seal_err = || CryptoError::new(CryptoErrorKind::Seal);
    let total = pt.len().checked_add(Sealed::TAG_LEN).ok_or_else(seal_err)?;
    let mut out = vec![0u8; total];
    let (body, tag_out) = out.split_at_mut(pt.len());
    let buf = InOutBuf::new(pt, body).map_err(|_| seal_err())?;
    let tag = XChaCha20Poly1305::new(key.into())
        .encrypt_inout_detached(&XNonce::from(*nonce), aad, buf)
        .map_err(|_| seal_err())?;
    tag_out.copy_from_slice(&tag);
    Ok(out)
}

/// XChaCha20-Poly1305 decryption of `ct_and_tag` into `out`, which must be
/// exactly the ciphertext's length. The tag is checked first; on failure
/// nothing is written to `out`.
pub(crate) fn open_into(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    ct_and_tag: &[u8],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    #[cfg(test)]
    OPEN_ATTEMPTS.with(|n| n.set(n.get() + 1));
    let open_err = || CryptoError::new(CryptoErrorKind::Open);
    let Some(len) = ct_and_tag.len().checked_sub(Sealed::TAG_LEN) else {
        return Err(CryptoErrorKind::Malformed.into());
    };
    let (body, tag) = ct_and_tag.split_at(len);
    let tag = Tag::try_from(tag).map_err(|_| open_err())?;
    let buf = InOutBuf::new(body, out).map_err(|_| open_err())?;
    XChaCha20Poly1305::new(key.into())
        .decrypt_inout_detached(&XNonce::from(*nonce), aad, buf, &tag)
        .map_err(|_| open_err())
}

#[cfg(test)]
thread_local! {
    /// Calls to [`open_into`] on this thread, so tests can show that a
    /// check ran before any decryption was attempted.
    pub(crate) static OPEN_ATTEMPTS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // draft-irtf-cfrg-xchacha-03, appendix A.3.1.
    const KEY: &str = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
    const NONCE: &str = "404142434445464748494a4b4c4d4e4f5051525354555657";
    const AAD: &str = "50515253c0c1c2c3c4c5c6c7";
    const PT: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you \
only one tip for the future, sunscreen would be it.";
    const CT: &str = "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb\
731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452\
2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9\
21f9664c97637da9768812f615c68b13b52e";
    const TAG: &str = "c0875924c1c7987947deafd8780acf49";

    fn arr<const N: usize>(hex: &str) -> [u8; N] {
        unhex(hex).try_into().unwrap()
    }

    #[test]
    fn seal_with_nonce_matches_the_xchacha_draft() {
        let ct = seal_with_nonce(&arr(KEY), &arr(NONCE), &unhex(AAD), PT).unwrap();
        let mut want = unhex(CT);
        want.extend(unhex(TAG));
        assert_eq!(ct, want);
    }

    #[test]
    fn open_into_matches_the_xchacha_draft() {
        let mut ct = unhex(CT);
        ct.extend(unhex(TAG));
        let mut out = vec![0u8; PT.len()];
        open_into(&arr(KEY), &arr(NONCE), &unhex(AAD), &ct, &mut out).unwrap();
        assert_eq!(out, PT);

        // A flipped tag bit fails, and nothing is written.
        let last = ct.len() - 1;
        ct[last] ^= 1;
        let mut out = vec![0u8; PT.len()];
        let e = open_into(&arr(KEY), &arr(NONCE), &unhex(AAD), &ct, &mut out).unwrap_err();
        assert_eq!(e.kind(), CryptoErrorKind::Open);
        assert!(out.iter().all(|b| *b == 0));
    }

    #[test]
    fn short_input_is_malformed() {
        let mut out = [0u8; 0];
        let e = open_into(&[0; 32], &[0; 24], &[], &[0; 15], &mut out).unwrap_err();
        assert_eq!(e.kind(), CryptoErrorKind::Malformed);
        assert_eq!(
            Sealed::from_bytes(&[0; 39]).unwrap_err().kind(),
            CryptoErrorKind::Malformed
        );
        let s = Sealed::from_bytes(&[7; 40]).unwrap();
        assert_eq!(s.nonce, [7; 24]);
        assert_eq!(s.ciphertext, vec![7; 16]);
        assert_eq!(s.to_bytes(), vec![7; 40]);
        assert_eq!(format!("{s:?}"), "Sealed { ciphertext_len: 16, .. }");
    }
}
