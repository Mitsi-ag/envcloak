//! XChaCha20-Poly1305 sealing (SPEC §5 "Vault").
//!
//! [`seal`] draws a fresh 192-bit nonce from the OS CSPRNG for every call;
//! counters are never used. Encryption writes ciphertext straight into its
//! output buffer, so no buffer the sealer allocates ever holds plaintext.
//! [`open`] checks the tag before decrypting and decrypts into one
//! exact-size buffer that becomes the returned [`SecretBytes`] without
//! moving.

use chacha20::XChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20poly1305::aead::inout::InOutBuf;
use chacha20poly1305::{AeadInOut, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use poly1305::Poly1305;
use poly1305::universal_hash::UniversalHash;
use secrecy::ExposeSecret;
use zeroize::{Zeroize, Zeroizing};

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

/// Whether `body`, read as `nonce || ciphertext || tag` (the stored form
/// of a [`Sealed`]), authenticates under `k` and `aad` when cut to some
/// length in `lens`: for each length `n` in order, whether its first `n`
/// bytes would open. `take(n)` is asked about each length that does, and
/// the search ends when it answers `true`.
///
/// One pass, as XChaCha20-Poly1305 checks a tag (the `chacha20poly1305`
/// crate's construction): the one-time Poly1305 key is the first 32 bytes
/// of the keystream under the nonce, and the tag covers the associated
/// data and the ciphertext, each padded to 16 bytes, then both lengths.
/// The hash of the whole 16-byte blocks is carried from one length to the
/// next, and only the last partial block and the lengths are hashed for
/// each, so every length a stored entry can have is checked in time
/// linear in `body` where opening each would take the square (the audit
/// log's torn-tail check, review F-46). Nothing is decrypted; the
/// one-time key and the hash states are wiped.
#[allow(clippy::disallowed_methods)] // Reads the subkey to derive the one-time key.
pub(crate) fn authenticates_at(
    k: &SubKey,
    aad: &Aad,
    body: &[u8],
    lens: core::ops::RangeInclusive<usize>,
    take: impl FnMut(usize) -> bool,
) -> bool {
    authenticates_at_with(k.key.expose_secret(), &aad.encode(), body, lens, take)
}

/// [`authenticates_at`] with the key and the associated data as bytes.
fn authenticates_at_with(
    key: &[u8; 32],
    aad: &[u8],
    body: &[u8],
    lens: core::ops::RangeInclusive<usize>,
    mut take: impl FnMut(usize) -> bool,
) -> bool {
    let first = (*lens.start()).max(Sealed::OVERHEAD);
    let last = (*lens.end()).min(body.len());
    if first > last {
        return false;
    }
    let mut nonce = [0u8; Sealed::NONCE_LEN];
    nonce.copy_from_slice(&body[..Sealed::NONCE_LEN]);
    let mut cipher = XChaCha20::new(key.into(), &XNonce::from(nonce));
    let mut mac_key = poly1305::Key::default();
    cipher.apply_keystream(&mut mac_key);
    let mut mac = Poly1305::new(&mac_key);
    mac_key.as_mut_slice().zeroize();
    mac.update_padded(aad);
    let aad_len = u64::try_from(aad.len()).unwrap_or(u64::MAX).to_le_bytes();
    let ciphertext = &body[Sealed::NONCE_LEN..];
    // The whole 16-byte blocks of the ciphertext hashed into `mac`.
    let mut hashed = 0;
    for n in first..=last {
        let len = n - Sealed::OVERHEAD;
        while (hashed + 1) * 16 <= len {
            let mut block = poly1305::Block::default();
            block.copy_from_slice(&ciphertext[hashed * 16..(hashed + 1) * 16]);
            mac.update(&[block]);
            hashed += 1;
        }
        let mut at = mac.clone();
        at.update_padded(&ciphertext[hashed * 16..len]);
        let mut lengths = poly1305::Block::default();
        lengths[..8].copy_from_slice(&aad_len);
        lengths[8..].copy_from_slice(&u64::try_from(len).unwrap_or(u64::MAX).to_le_bytes());
        at.update(&[lengths]);
        let mut tag = poly1305::Block::default();
        tag.copy_from_slice(&body[n - Sealed::TAG_LEN..n]);
        #[cfg(feature = "testing")]
        LENGTHS_TRIED.with(|t| t.set(t.get() + 1));
        if at.verify(&tag).is_ok() && take(n) {
            return true;
        }
    }
    false
}

#[cfg(test)]
thread_local! {
    /// Calls to [`open_into`] on this thread, so tests can show that a
    /// check ran before any decryption was attempted.
    pub(crate) static OPEN_ATTEMPTS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

#[cfg(feature = "testing")]
thread_local! {
    /// Test support only: the lengths [`authenticates_at`] and
    /// [`super::keyed_hash_prefixes`] have tried on this thread, each one
    /// tag or hash computed to its end, so a test can see the audit log's
    /// torn-tail check stay within its budget (review R-17).
    pub(crate) static LENGTHS_TRIED: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// Test support only: [`LENGTHS_TRIED`] on this thread so far.
#[cfg(feature = "testing")]
pub(crate) fn lengths_tried() -> usize {
    LENGTHS_TRIED.with(core::cell::Cell::get)
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

    /// Every length at which `body` opens, by opening each alone.
    fn opening_each(key: &[u8; 32], aad: &[u8], body: &[u8]) -> Vec<usize> {
        (Sealed::OVERHEAD..=body.len())
            .filter(|&n| {
                let mut nonce = [0u8; Sealed::NONCE_LEN];
                nonce.copy_from_slice(&body[..Sealed::NONCE_LEN]);
                let ct = &body[Sealed::NONCE_LEN..n];
                let mut out = vec![0u8; ct.len() - Sealed::TAG_LEN];
                open_into(key, &nonce, aad, ct, &mut out).is_ok()
            })
            .collect()
    }

    /// Every length at which `body` opens, in one pass.
    fn in_one_pass(key: &[u8; 32], aad: &[u8], body: &[u8]) -> Vec<usize> {
        let mut found = Vec::new();
        assert!(!authenticates_at_with(
            key,
            aad,
            body,
            0..=usize::MAX,
            |n| {
                found.push(n);
                false
            }
        ));
        found
    }

    /// Review F-46: the one-pass check agrees with the crate's own open at
    /// every length: the draft's vector with bytes after its tag, and
    /// entries sealed here of every length up to three blocks and beyond,
    /// before bytes that are no entry, with the associated data empty or
    /// not a multiple of 16. `take` ends the search where it says.
    #[test]
    fn every_length_that_opens_is_found_in_one_pass() {
        let (key, aad) = (arr::<32>(KEY), unhex(AAD));
        let mut body = unhex(NONCE);
        body.extend(unhex(CT));
        body.extend(unhex(TAG));
        let whole = body.len();
        body.extend([0x5a; 37]);
        assert_eq!(in_one_pass(&key, &aad, &body), [whole]);
        assert_eq!(opening_each(&key, &aad, &body), [whole]);
        // One byte of the tag or the ciphertext changed: no length.
        for at in [whole - 1, Sealed::NONCE_LEN + 3] {
            let mut changed = body.clone();
            changed[at] ^= 0x01;
            assert!(in_one_pass(&key, &aad, &changed).is_empty(), "{at}");
        }

        let mut x: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for aad_len in [0usize, 12, 16, 61] {
            let aad: Vec<u8> = (0..aad_len).map(|_| next() as u8).collect();
            for pt_len in (0..=50).chain([63, 64, 65, 200]) {
                let mut key = [0u8; 32];
                key.iter_mut().for_each(|b| *b = next() as u8);
                let mut nonce = [0u8; Sealed::NONCE_LEN];
                nonce.iter_mut().for_each(|b| *b = next() as u8);
                let pt: Vec<u8> = (0..pt_len).map(|_| next() as u8).collect();
                let mut body = nonce.to_vec();
                body.extend(seal_with_nonce(&key, &nonce, &aad, &pt).unwrap());
                let end = body.len();
                let tail = usize::try_from(next() % 50).unwrap();
                body.extend((0..tail).map(|_| next() as u8));
                let found = in_one_pass(&key, &aad, &body);
                assert_eq!(found, [end], "{aad_len} {pt_len}");
                assert_eq!(found, opening_each(&key, &aad, &body), "{aad_len} {pt_len}");
                // Each length alone, and a range that leaves it out.
                assert!(authenticates_at_with(&key, &aad, &body, end..=end, |_| {
                    true
                }));
                assert!(!authenticates_at_with(
                    &key,
                    &aad,
                    &body,
                    0..=end - 1,
                    |_| true
                ));
                assert!(!authenticates_at_with(
                    &key,
                    &aad,
                    &body,
                    end + 1..=usize::MAX,
                    |_| true
                ));
                // The wrong key, or other associated data: none.
                key[0] ^= 1;
                assert!(in_one_pass(&key, &aad, &body).is_empty());
            }
        }
        // Too short to hold a nonce and a tag: nothing is read.
        assert!(!authenticates_at_with(
            &key,
            &aad,
            &body[..39],
            0..=usize::MAX,
            |_| true
        ));
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
