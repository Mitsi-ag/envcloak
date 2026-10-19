//! macOS Secure Enclave unlocker envelopes and HPKE unlock (SPEC §5 "Key
//! hierarchy" and "Unlock flow"; byte layout in docs/CRYPTO.md).
//!
//! - [`SeUnlockerRecord`]: the public record of an enrolled Secure Enclave
//!   unlocker: its id, its 65-byte uncompressed SEC1 P-256 `unlock` and
//!   `approve` public keys, its label, its creation time, and the macOS Team
//!   ID and signing identifier the app was verified under when it enrolled.
//!   Only public keys are ever stored in the vault.
//! - [`SeUnlockerEnvelope`]: the record together with the VMK sealed to
//!   `unlock_pub` with HPKE (RFC 9180 base mode, DHKEM(P-256, HKDF-SHA256),
//!   HKDF-SHA256, AES-256-GCM) and `info = "envcloak/v1/unlocker/se" ||
//!   vault_id || unlocker_id || epoch` (empty associated data).
//!   [`seal_se_unlocker`] creates the envelope and [`recreate_se_unlocker`]
//!   re-creates it for a new epoch without user presence.
//! - [`SeEphemeralKey`]: the fresh, single-use X25519 keypair the daemon
//!   generates at `app.unlock.begin` and keeps at most 60 seconds. The app
//!   opens [`SeHpkeEnvelope`] with its Secure Enclave `unlock` key and
//!   reseals the 32-byte VMK to [`SeEphemeralKey::public_key`] with HPKE
//!   (base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
//!   ChaCha20-Poly1305, empty `info`, associated data `request_id ||
//!   challenge`). [`SeEphemeralKey::open_vmk`] consumes the ephemeral secret
//!   key, opens the resealed VMK into a wiping buffer, and wipes the
//!   ephemeral key on drop.

use hpke::aead::{AesGcm256, ChaCha20Poly1305};
use hpke::kdf::HkdfSha256;
use hpke::kem::{DhP256HkdfSha256, X25519HkdfSha256};
use hpke::{Deserializable as _, Kem as _, OpModeR, OpModeS, Serializable as _};
use p256::ecdsa::signature::hazmat::{PrehashSigner as _, PrehashVerifier as _};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use secrecy::{ExposeSecret, SecretBox};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use super::envelope::UnlockerKind;
use super::keys::{UnlockerId, VaultId, Vmk};
use super::{CryptoError, CryptoErrorKind, fill_random};
use crate::SecretBytes;

/// The HPKE `info` prefix for a Secure Enclave VMK envelope (SPEC §5).
pub const SE_HPKE_INFO_PREFIX: &[u8] = b"envcloak/v1/unlocker/se";
/// Length of an uncompressed SEC1 P-256 public key (`0x04 || X || Y`).
pub const P256_PUBLIC_KEY_LEN: usize = 65;
/// Length of a raw P-256 ECDSA signature (`r (32) || s (32)`).
pub const P256_SIGNATURE_LEN: usize = 64;
/// Length of the DHKEM(P-256, HKDF-SHA256) encapsulated key.
pub const SE_HPKE_ENC_LEN: usize = 65;
/// Length of the AES-256-GCM or ChaCha20-Poly1305 sealed 32-byte VMK (32 + 16).
pub const SE_HPKE_CIPHERTEXT_LEN: usize = 48;
/// Length of an X25519 public key or DHKEM(X25519, HKDF-SHA256) encapsulated key.
pub const X25519_PUBLIC_KEY_LEN: usize = 32;
/// Length of the app's resealed VMK (`enc(32) || ciphertext(48)`).
pub const SE_RESEAL_LEN: usize = X25519_PUBLIC_KEY_LEN + SE_HPKE_CIPHERTEXT_LEN;
/// Length of the random unlock challenge.
pub const SE_CHALLENGE_LEN: usize = 32;

/// Maximum UTF-8 byte length of an unlocker label.
pub const MAX_SE_LABEL_LEN: usize = 128;
/// Maximum UTF-8 byte length of an Apple Developer Team ID.
pub const MAX_SE_TEAM_ID_LEN: usize = 64;
/// Maximum UTF-8 byte length of a macOS code-signing identifier.
pub const MAX_SE_SIGNING_ID_LEN: usize = 256;

const MAGIC: [u8; 4] = *b"ECSE";
const FORMAT_VERSION: u8 = 1;
const INFO_LEN: usize = SE_HPKE_INFO_PREFIX.len() + 16 + 16 + 4;

/// The verified code-signing identity of the app that enrolled a Secure
/// Enclave unlocker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeEnrolledUnder {
    pub team_id: String,
    pub signing_id: String,
}

/// The public metadata and keys of an enrolled Secure Enclave unlocker.
/// Holds public keys only, never a private key or keychain blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeUnlockerRecord {
    pub unlocker_id: UnlockerId,
    pub unlock_pub: [u8; P256_PUBLIC_KEY_LEN],
    pub approve_pub: [u8; P256_PUBLIC_KEY_LEN],
    pub label: String,
    pub created_secs: u64,
    pub enrolled_under: SeEnrolledUnder,
}

impl SeUnlockerRecord {
    /// SHA-256 fingerprint of `unlock_pub`.
    pub fn unlock_fingerprint(&self) -> [u8; 32] {
        p256_fingerprint(&self.unlock_pub)
    }

    /// SHA-256 fingerprint of `approve_pub`.
    pub fn approve_fingerprint(&self) -> [u8; 32] {
        p256_fingerprint(&self.approve_pub)
    }

    /// Checks that both keys are distinct, valid uncompressed P-256 points
    /// and that the label and code-signing strings are within bounds and free
    /// of control characters.
    pub fn check(&self) -> Result<(), CryptoError> {
        let _ = check_p256_public_key(&self.unlock_pub)?;
        let _ = check_p256_public_key(&self.approve_pub)?;
        if self.unlock_pub == self.approve_pub {
            return Err(CryptoErrorKind::EnvelopeFormat.into());
        }
        check_se_label(&self.label)?;
        check_text(&self.enrolled_under.team_id, MAX_SE_TEAM_ID_LEN)?;
        check_text(&self.enrolled_under.signing_id, MAX_SE_SIGNING_ID_LEN)?;
        Ok(())
    }
}

/// The HPKE-sealed VMK portion of a Secure Enclave unlocker (`enc` and
/// `ciphertext`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeHpkeEnvelope {
    pub enc: [u8; SE_HPKE_ENC_LEN],
    pub ciphertext: [u8; SE_HPKE_CIPHERTEXT_LEN],
}

/// A stored Secure Enclave unlocker row: [`SeUnlockerRecord`] plus the
/// [`SeHpkeEnvelope`] for a specific `vault_id` and `epoch`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeUnlockerEnvelope {
    record: SeUnlockerRecord,
    vault_id: VaultId,
    epoch: u32,
    envelope: SeHpkeEnvelope,
}

impl SeUnlockerEnvelope {
    pub fn record(&self) -> &SeUnlockerRecord {
        &self.record
    }

    pub fn unlocker_id(&self) -> UnlockerId {
        self.record.unlocker_id
    }

    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    pub fn hpke(&self) -> &SeHpkeEnvelope {
        &self.envelope
    }

    /// Encodes the stored bytes for `unlockers.envelope` (`kind = 3`).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(320);
        out.extend_from_slice(&MAGIC);
        out.push(FORMAT_VERSION);
        out.push(UnlockerKind::SecureEnclave as u8);
        out.extend_from_slice(&self.vault_id.0);
        out.extend_from_slice(&self.record.unlocker_id.0);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.record.created_secs.to_be_bytes());
        out.extend_from_slice(&self.record.unlock_pub);
        out.extend_from_slice(&self.record.approve_pub);
        out.extend_from_slice(&self.envelope.enc);
        out.extend_from_slice(&self.envelope.ciphertext);
        put_str(&mut out, &self.record.label);
        put_str(&mut out, &self.record.enrolled_under.team_id);
        put_str(&mut out, &self.record.enrolled_under.signing_id);
        out
    }

    /// Parses [`SeUnlockerEnvelope::to_bytes`]'s output, validating the magic,
    /// version, kind, P-256 keys, encapsulated key and text bounds.
    pub fn from_bytes(b: &[u8]) -> Result<Self, CryptoError> {
        let format = || CryptoError::new(CryptoErrorKind::EnvelopeFormat);
        let mut r = SliceReader { buf: b, at: 0 };
        if r.array::<4>()? != MAGIC || r.array::<1>()? != [FORMAT_VERSION] {
            return Err(format());
        }
        let [kind] = r.array::<1>()?;
        if UnlockerKind::from_byte(kind) != Some(UnlockerKind::SecureEnclave) {
            return Err(format());
        }
        let vault_id = VaultId(r.array::<16>()?);
        let unlocker_id = UnlockerId(r.array::<16>()?);
        let epoch = u32::from_be_bytes(r.array::<4>()?);
        let created_secs = u64::from_be_bytes(r.array::<8>()?);
        let unlock_pub = check_p256_public_key(&r.array::<P256_PUBLIC_KEY_LEN>()?)?;
        let approve_pub = check_p256_public_key(&r.array::<P256_PUBLIC_KEY_LEN>()?)?;
        let enc = r.array::<SE_HPKE_ENC_LEN>()?;
        let _ = check_p256_public_key(&enc)?;
        let _ =
            <DhP256HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(&enc).map_err(|_| format())?;
        let ciphertext = r.array::<SE_HPKE_CIPHERTEXT_LEN>()?;
        let label = r.string(MAX_SE_LABEL_LEN)?;
        let team_id = r.string(MAX_SE_TEAM_ID_LEN)?;
        let signing_id = r.string(MAX_SE_SIGNING_ID_LEN)?;
        if r.at != r.buf.len() {
            return Err(format());
        }
        let record = SeUnlockerRecord {
            unlocker_id,
            unlock_pub,
            approve_pub,
            label,
            created_secs,
            enrolled_under: SeEnrolledUnder {
                team_id,
                signing_id,
            },
        };
        record.check()?;
        Ok(SeUnlockerEnvelope {
            record,
            vault_id,
            epoch,
            envelope: SeHpkeEnvelope { enc, ciphertext },
        })
    }
}

/// Validates an uncompressed 65-byte SEC1 P-256 public key (`0x04 || X || Y`)
/// on the NIST P-256 curve.
pub fn check_p256_public_key(sec1: &[u8]) -> Result<[u8; P256_PUBLIC_KEY_LEN], CryptoError> {
    let format = || CryptoError::new(CryptoErrorKind::EnvelopeFormat);
    let key: [u8; P256_PUBLIC_KEY_LEN] = sec1.try_into().map_err(|_| format())?;
    if key[0] != 0x04 {
        return Err(format());
    }
    let _ = VerifyingKey::from_sec1_bytes(&key).map_err(|_| format())?;
    let _ = <DhP256HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(&key).map_err(|_| format())?;
    Ok(key)
}

/// Validates a Secure Enclave unlocker label: 1 to [`MAX_SE_LABEL_LEN`] UTF-8
/// bytes, not blank, and containing no control characters.
pub fn check_se_label(label: &str) -> Result<(), CryptoError> {
    check_text(label, MAX_SE_LABEL_LEN)
}

fn check_text(s: &str, max_len: usize) -> Result<(), CryptoError> {
    if s.is_empty() || s.len() > max_len || s.trim().is_empty() || s.chars().any(char::is_control) {
        return Err(CryptoErrorKind::EnvelopeFormat.into());
    }
    Ok(())
}

/// SHA-256 fingerprint of a 65-byte SEC1 P-256 public key.
pub fn p256_fingerprint(pub_sec1: &[u8; P256_PUBLIC_KEY_LEN]) -> [u8; 32] {
    Sha256::digest(pub_sec1).into()
}

/// Builds the 59-byte HPKE `info` string:
/// `"envcloak/v1/unlocker/se" || vault_id || unlocker_id || epoch`.
pub fn se_hpke_info(vault_id: VaultId, unlocker_id: UnlockerId, epoch: u32) -> [u8; INFO_LEN] {
    let mut info = [0u8; INFO_LEN];
    let p = SE_HPKE_INFO_PREFIX.len();
    info[..p].copy_from_slice(SE_HPKE_INFO_PREFIX);
    info[p..p + 16].copy_from_slice(&vault_id.0);
    info[p + 16..p + 32].copy_from_slice(&unlocker_id.0);
    info[p + 32..].copy_from_slice(&epoch.to_be_bytes());
    info
}

/// Seals `vmk` to `record.unlock_pub` with HPKE base mode
/// (`DHKEM(P-256, HKDF-SHA256)`, `HKDF-SHA256`, `AES-256-GCM`) and returns the
/// complete [`SeUnlockerEnvelope`]. Needs no user presence.
pub fn seal_se_unlocker(
    vmk: &Vmk,
    vault_id: VaultId,
    epoch: u32,
    record: SeUnlockerRecord,
) -> Result<SeUnlockerEnvelope, CryptoError> {
    record.check()?;
    let envelope = seal_vmk_to_se(vmk, &record.unlock_pub, vault_id, record.unlocker_id, epoch)?;
    Ok(SeUnlockerEnvelope {
        record,
        vault_id,
        epoch,
        envelope,
    })
}

/// Re-creates a [`SeUnlockerEnvelope`] for `new_epoch` and `vmk` using the
/// stored `unlock_pub`, without user presence (SPEC §5).
pub fn recreate_se_unlocker(
    existing: &SeUnlockerEnvelope,
    vmk: &Vmk,
    new_epoch: u32,
) -> Result<SeUnlockerEnvelope, CryptoError> {
    seal_se_unlocker(vmk, existing.vault_id, new_epoch, existing.record.clone())
}

/// Seals `vmk` to `unlock_pub` with HPKE (`DHKEM(P-256, HKDF-SHA256)`,
/// `HKDF-SHA256`, `AES-256-GCM`).
#[allow(clippy::disallowed_methods)] // Seals the VMK to the Secure Enclave P-256 public key.
pub fn seal_vmk_to_se(
    vmk: &Vmk,
    unlock_pub: &[u8; P256_PUBLIC_KEY_LEN],
    vault_id: VaultId,
    unlocker_id: UnlockerId,
    epoch: u32,
) -> Result<SeHpkeEnvelope, CryptoError> {
    let _ = check_p256_public_key(unlock_pub)?;
    let pk = <DhP256HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(unlock_pub)
        .map_err(|_| CryptoError::new(CryptoErrorKind::EnvelopeFormat))?;
    let info = se_hpke_info(vault_id, unlocker_id, epoch);
    let (encapped, ct) = hpke::single_shot_seal::<AesGcm256, HkdfSha256, DhP256HkdfSha256>(
        &OpModeS::Base,
        &pk,
        &info,
        vmk.0.expose_secret(),
        b"",
    )
    .map_err(|_| CryptoError::new(CryptoErrorKind::Seal))?;
    let enc_bytes = encapped.to_bytes();
    let enc: [u8; SE_HPKE_ENC_LEN] = enc_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::new(CryptoErrorKind::Seal))?;
    let ciphertext: [u8; SE_HPKE_CIPHERTEXT_LEN] = ct
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::new(CryptoErrorKind::Seal))?;
    Ok(SeHpkeEnvelope { enc, ciphertext })
}

/// Opens a [`SeHpkeEnvelope`] with the raw 32-byte P-256 private scalar (used
/// by software stand-in tests and cross-implementation HPKE vector checks).
pub fn open_se_envelope(
    unlock_sk_raw: &[u8; 32],
    vault_id: VaultId,
    unlocker_id: UnlockerId,
    epoch: u32,
    envelope: &SeHpkeEnvelope,
) -> Result<Vmk, CryptoError> {
    let unlock = || CryptoError::new(CryptoErrorKind::Unlock);
    let _ = check_p256_public_key(&envelope.enc)?;
    let sk = <DhP256HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(unlock_sk_raw)
        .map_err(|_| unlock())?;
    let enc = <DhP256HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(&envelope.enc)
        .map_err(|_| unlock())?;
    let info = se_hpke_info(vault_id, unlocker_id, epoch);
    let mut pt = hpke::single_shot_open::<AesGcm256, HkdfSha256, DhP256HkdfSha256>(
        &OpModeR::Base,
        &sk,
        &enc,
        &info,
        &envelope.ciphertext,
        b"",
    )
    .map_err(|_| unlock())?;
    if pt.len() != 32 {
        pt.zeroize();
        return Err(unlock());
    }
    let vmk = SecretBox::init_with_mut(|k: &mut [u8; 32]| {
        k.copy_from_slice(&pt);
    });
    pt.zeroize();
    Ok(Vmk(vmk))
}

/// Builds the associated data for the app-to-daemon HPKE reseal:
/// `request_id || challenge`.
pub fn se_reseal_aad(request_id: &str, challenge: &[u8; SE_CHALLENGE_LEN]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(request_id.len() + SE_CHALLENGE_LEN);
    aad.extend_from_slice(request_id.as_bytes());
    aad.extend_from_slice(challenge);
    aad
}

/// Builds the associated data for the daemon-to-app HPKE reveal seal:
/// `request_id || challenge || app_eph_pub` (SPEC §6.3; M3-14).
pub fn se_reveal_aad(
    request_id: &str,
    challenge: &[u8; SE_CHALLENGE_LEN],
    app_eph_pub: &[u8; X25519_PUBLIC_KEY_LEN],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(request_id.len() + SE_CHALLENGE_LEN + X25519_PUBLIC_KEY_LEN);
    aad.extend_from_slice(request_id.as_bytes());
    aad.extend_from_slice(challenge);
    aad.extend_from_slice(app_eph_pub);
    aad
}

/// Generates a fresh 32-byte random challenge for `app.unlock.begin`.
pub fn generate_se_challenge() -> Result<[u8; SE_CHALLENGE_LEN], CryptoError> {
    let mut challenge = [0u8; SE_CHALLENGE_LEN];
    fill_random(&mut challenge)?;
    Ok(challenge)
}

/// A fresh, single-use X25519 keypair generated by the daemon for one
/// `app.unlock.begin` request. The private key is zeroized on drop.
pub struct SeEphemeralKey {
    sk: <X25519HkdfSha256 as hpke::Kem>::PrivateKey,
    pub_bytes: [u8; X25519_PUBLIC_KEY_LEN],
}

impl core::fmt::Debug for SeEphemeralKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SeEphemeralKey")
            .field("pub_bytes", &self.pub_bytes)
            .finish_non_exhaustive()
    }
}

impl SeEphemeralKey {
    /// Generates a fresh X25519 keypair from the OS CSPRNG.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut ikm = Zeroizing::new([0u8; 32]);
        fill_random(&mut *ikm)?;
        Self::from_ikm(&ikm)
    }

    /// Deterministically derives an X25519 keypair from `ikm` (for vector
    /// tests and key generation).
    pub fn from_ikm(ikm: &[u8; 32]) -> Result<Self, CryptoError> {
        let (sk, pk) = X25519HkdfSha256::derive_keypair(ikm);
        let pub_bytes: [u8; X25519_PUBLIC_KEY_LEN] = pk
            .to_bytes()
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::new(CryptoErrorKind::Seal))?;
        Ok(SeEphemeralKey { sk, pub_bytes })
    }

    /// Constructs an [`SeEphemeralKey`] from a raw 32-byte X25519 private scalar.
    pub fn from_raw_private(raw: &[u8; 32]) -> Result<Self, CryptoError> {
        let sk = <X25519HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(raw)
            .map_err(|_| CryptoError::new(CryptoErrorKind::EnvelopeFormat))?;
        let pk = X25519HkdfSha256::sk_to_pk(&sk);
        let pub_bytes: [u8; X25519_PUBLIC_KEY_LEN] = pk
            .to_bytes()
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::new(CryptoErrorKind::EnvelopeFormat))?;
        Ok(SeEphemeralKey { sk, pub_bytes })
    }

    /// The 32-byte X25519 public key (`daemon_eph_pub`).
    pub fn public_key(&self) -> &[u8; X25519_PUBLIC_KEY_LEN] {
        &self.pub_bytes
    }

    /// Consumes this single-use keypair and opens the app's HPKE-sealed VMK
    /// (`DHKEM(X25519, HKDF-SHA256)`, `HKDF-SHA256`, `ChaCha20-Poly1305`,
    /// empty `info`, associated data `request_id || challenge`).
    pub fn open_vmk(
        self,
        request_id: &str,
        challenge: &[u8; SE_CHALLENGE_LEN],
        sealed: &[u8],
    ) -> Result<Vmk, CryptoError> {
        let unlock = || CryptoError::new(CryptoErrorKind::Unlock);
        if sealed.len() != SE_RESEAL_LEN {
            return Err(unlock());
        }
        let enc = <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(
            &sealed[..X25519_PUBLIC_KEY_LEN],
        )
        .map_err(|_| unlock())?;
        let ct = &sealed[X25519_PUBLIC_KEY_LEN..];
        let aad = se_reseal_aad(request_id, challenge);
        let mut pt = hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &self.sk,
            &enc,
            b"",
            ct,
            &aad,
        )
        .map_err(|_| unlock())?;
        drop(self);
        if pt.len() != 32 {
            pt.zeroize();
            return Err(unlock());
        }
        let vmk = SecretBox::init_with_mut(|k: &mut [u8; 32]| {
            k.copy_from_slice(&pt);
        });
        pt.zeroize();
        Ok(Vmk(vmk))
    }

    /// Opens an HPKE-sealed secret value (`DHKEM(X25519, HKDF-SHA256)`,
    /// `HKDF-SHA256`, `ChaCha20-Poly1305`, empty `info`, associated data `aad`)
    /// into [`SecretBytes`], zeroizing intermediate buffers (SPEC §4.4, §6.7;
    /// M3-14).
    pub fn open_secret(&self, aad: &[u8], sealed: &[u8]) -> Result<SecretBytes, CryptoError> {
        let open_err = || CryptoError::new(CryptoErrorKind::Open);
        if sealed.len() <= SE_SEALED_SECRET_OVERHEAD {
            return Err(CryptoError::new(CryptoErrorKind::Malformed));
        }
        let enc = <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(
            &sealed[..X25519_PUBLIC_KEY_LEN],
        )
        .map_err(|_| open_err())?;
        let ct = &sealed[X25519_PUBLIC_KEY_LEN..];
        let mut pt = hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &self.sk,
            &enc,
            b"",
            ct,
            aad,
        )
        .map_err(|_| open_err())?;
        let out = SecretBytes::copy_from(&pt);
        pt.zeroize();
        Ok(out)
    }
}

/// Byte overhead of an HPKE-sealed secret (`enc(32)` + 16-byte Poly1305 tag).
pub const SE_SEALED_SECRET_OVERHEAD: usize = X25519_PUBLIC_KEY_LEN + 16;

/// Seals `secret` to `recipient_pub` with HPKE base mode
/// (`DHKEM(X25519, HKDF-SHA256)`, `HKDF-SHA256`, `ChaCha20-Poly1305`, empty
/// `info`, associated data `aad`), returning `enc(32) || ciphertext(len + 16)`
/// (SPEC §4.4, §6.7; M3-14).
#[allow(clippy::disallowed_methods)] // Seals a secret value to an ephemeral X25519 public key.
pub fn seal_secret_to_x25519(
    recipient_pub: &[u8; X25519_PUBLIC_KEY_LEN],
    aad: &[u8],
    secret: &SecretBytes,
) -> Result<Vec<u8>, CryptoError> {
    if recipient_pub.iter().all(|&b| b == 0) {
        return Err(CryptoError::new(CryptoErrorKind::EnvelopeFormat));
    }
    let pk = <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(recipient_pub)
        .map_err(|_| CryptoError::new(CryptoErrorKind::EnvelopeFormat))?;
    let (enc, ct) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeS::Base,
        &pk,
        b"",
        secret.expose_secret(),
        aad,
    )
    .map_err(|_| CryptoError::new(CryptoErrorKind::Seal))?;
    let mut out = Vec::with_capacity(X25519_PUBLIC_KEY_LEN + ct.len());
    out.extend_from_slice(enc.to_bytes().as_slice());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Opens an HPKE-sealed secret value using a raw 32-byte X25519 private key.
pub fn open_secret_from_x25519(
    sk_raw: &[u8; 32],
    aad: &[u8],
    sealed: &[u8],
) -> Result<SecretBytes, CryptoError> {
    let key = SeEphemeralKey::from_raw_private(sk_raw)?;
    key.open_secret(aad, sealed)
}

/// Computes the SHA-256 digest of `secret` for `envcloak-write-statement/1`
/// (`new_value_sha256`, SPEC §4.3; M3-14).
#[allow(clippy::disallowed_methods)] // Hashes secret bytes to bind replacement ciphertext to the signed statement.
pub fn secret_sha256(secret: &SecretBytes) -> [u8; 32] {
    Sha256::digest(secret.expose_secret()).into()
}

/// Seals `vmk` to `daemon_eph_pub` with HPKE base mode
/// (`DHKEM(X25519, HKDF-SHA256)`, `HKDF-SHA256`, `ChaCha20-Poly1305`, empty
/// `info`, associated data `request_id || challenge`), returning
/// `enc(32) || ciphertext(48)`.
#[allow(clippy::disallowed_methods)] // Seals the VMK to the daemon's ephemeral X25519 public key.
pub fn seal_vmk_to_daemon(
    daemon_eph_pub: &[u8; X25519_PUBLIC_KEY_LEN],
    request_id: &str,
    challenge: &[u8; SE_CHALLENGE_LEN],
    vmk: &Vmk,
) -> Result<[u8; SE_RESEAL_LEN], CryptoError> {
    let pk = <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(daemon_eph_pub)
        .map_err(|_| CryptoError::new(CryptoErrorKind::EnvelopeFormat))?;
    let aad = se_reseal_aad(request_id, challenge);
    let (enc, ct) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeS::Base,
        &pk,
        b"",
        vmk.0.expose_secret(),
        &aad,
    )
    .map_err(|_| CryptoError::new(CryptoErrorKind::Seal))?;
    let mut out = [0u8; SE_RESEAL_LEN];
    out[..X25519_PUBLIC_KEY_LEN].copy_from_slice(enc.to_bytes().as_slice());
    out[X25519_PUBLIC_KEY_LEN..].copy_from_slice(&ct);
    Ok(out)
}

/// Derives a deterministic P-256 keypair (`(secret_scalar_32, public_sec1_65)`)
/// from 32 bytes of keying material (for tests and vector tools).
pub fn derive_p256_keypair(ikm: &[u8; 32]) -> ([u8; 32], [u8; P256_PUBLIC_KEY_LEN]) {
    let (sk, pk) = DhP256HkdfSha256::derive_keypair(ikm);
    let mut sk_out = [0u8; 32];
    sk_out.copy_from_slice(sk.to_bytes().as_slice());
    let mut pk_out = [0u8; P256_PUBLIC_KEY_LEN];
    pk_out.copy_from_slice(pk.to_bytes().as_slice());
    (sk_out, pk_out)
}

/// Verifies a 64-byte raw P-256 ECDSA signature (`r || s`, low-S normalized)
/// over the 32-byte SHA-256 `digest` as a prehash using the 65-byte
/// uncompressed SEC1 public key `pub_sec1` (SPEC §10b, §11; M3-09).
pub fn verify_p256_prehash(
    pub_sec1: &[u8; P256_PUBLIC_KEY_LEN],
    digest: &[u8; 32],
    sig_raw: &[u8; P256_SIGNATURE_LEN],
) -> Result<(), CryptoError> {
    let _ = check_p256_public_key(pub_sec1)?;
    let vk = VerifyingKey::from_sec1_bytes(pub_sec1)
        .map_err(|_| CryptoError::new(CryptoErrorKind::Unlock))?;
    let sig = Signature::from_slice(sig_raw)
        .map_err(|_| CryptoError::new(CryptoErrorKind::Unlock))?
        .normalize_s();
    vk.verify_prehash(digest, &sig)
        .map_err(|_| CryptoError::new(CryptoErrorKind::Unlock))
}

/// Signs the 32-byte SHA-256 `digest` as a prehash with the raw 32-byte P-256
/// private scalar `sk_raw`, returning the 64-byte raw signature (`r || s`,
/// low-S normalized; used by software stand-in tests).
pub fn sign_p256_prehash(
    sk_raw: &[u8; 32],
    digest: &[u8; 32],
) -> Result<[u8; P256_SIGNATURE_LEN], CryptoError> {
    let sk = SigningKey::from_bytes(sk_raw.into())
        .map_err(|_| CryptoError::new(CryptoErrorKind::Seal))?;
    let sig: Signature = sk
        .sign_prehash(digest)
        .map_err(|_| CryptoError::new(CryptoErrorKind::Seal))?;
    let sig = sig.normalize_s();
    let mut out = [0u8; P256_SIGNATURE_LEN];
    out.copy_from_slice(sig.to_bytes().as_slice());
    Ok(out)
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    let len = u32::try_from(s.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

struct SliceReader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> SliceReader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CryptoError> {
        let format = || CryptoError::new(CryptoErrorKind::EnvelopeFormat);
        let end = self.at.checked_add(n).ok_or_else(format)?;
        let s = self.buf.get(self.at..end).ok_or_else(format)?;
        self.at = end;
        Ok(s)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], CryptoError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn string(&mut self, max_len: usize) -> Result<String, CryptoError> {
        let format = || CryptoError::new(CryptoErrorKind::EnvelopeFormat);
        let len = usize::try_from(u32::from_be_bytes(self.array::<4>()?)).map_err(|_| format())?;
        if len == 0 || len > max_len {
            return Err(format());
        }
        let b = self.take(len)?;
        let s = core::str::from_utf8(b).map_err(|_| format())?;
        check_text(s, max_len)?;
        Ok(s.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::{Keyring, Purpose, keyed_hash};

    fn vmk_fingerprint(vmk: &Vmk) -> [u8; 32] {
        let kr = Keyring::derive(vmk, &VaultId([0; 16]), 0);
        keyed_hash(kr.key(Purpose::Index), "envcloak/v1/test", b"")
    }

    fn sample_record() -> ([u8; 32], SeUnlockerRecord) {
        let (unlock_sk, unlock_pub) = derive_p256_keypair(&[11u8; 32]);
        let (_, approve_pub) = derive_p256_keypair(&[22u8; 32]);
        let rec = SeUnlockerRecord {
            unlocker_id: UnlockerId::generate(),
            unlock_pub,
            approve_pub,
            label: "MacBook Pro Touch ID".to_owned(),
            created_secs: 1_790_000_000,
            enrolled_under: SeEnrolledUnder {
                team_id: "TEAM123456".to_owned(),
                signing_id: "ai.envcloak.app".to_owned(),
            },
        };
        (unlock_sk, rec)
    }

    #[test]
    fn envelope_seals_round_trips_and_recreates_for_new_epoch() {
        let (unlock_sk, rec) = sample_record();
        let vault_id = VaultId::generate();
        let vmk1 = Vmk::generate();
        let env1 = seal_se_unlocker(&vmk1, vault_id, 1, rec.clone()).unwrap();
        let bytes = env1.to_bytes();
        let parsed = SeUnlockerEnvelope::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, env1);

        let opened1 =
            open_se_envelope(&unlock_sk, vault_id, rec.unlocker_id, 1, parsed.hpke()).unwrap();
        assert_eq!(vmk_fingerprint(&opened1), vmk_fingerprint(&vmk1));

        // Wrong epoch, vault_id or unlocker_id in HPKE info fails to open.
        assert!(open_se_envelope(&unlock_sk, vault_id, rec.unlocker_id, 2, parsed.hpke()).is_err());
        assert!(
            open_se_envelope(
                &unlock_sk,
                VaultId::generate(),
                rec.unlocker_id,
                1,
                parsed.hpke()
            )
            .is_err()
        );

        // Recreating for epoch 2 with a new VMK needs only the stored public record.
        let vmk2 = Vmk::generate();
        let env2 = recreate_se_unlocker(&parsed, &vmk2, 2).unwrap();
        assert_eq!(env2.epoch(), 2);
        assert_eq!(env2.record(), &rec);
        let opened2 =
            open_se_envelope(&unlock_sk, vault_id, rec.unlocker_id, 2, env2.hpke()).unwrap();
        assert_eq!(vmk_fingerprint(&opened2), vmk_fingerprint(&vmk2));
    }

    #[test]
    fn reseal_to_daemon_ephemeral_key_round_trips_and_binds_aad() {
        let vmk = Vmk::generate();
        let eph1 = SeEphemeralKey::generate().unwrap();
        let eph2 = SeEphemeralKey::generate().unwrap();
        assert_ne!(eph1.public_key(), eph2.public_key());

        let challenge = [0x42u8; SE_CHALLENGE_LEN];
        let sealed = seal_vmk_to_daemon(eph1.public_key(), "4KQ7M2XD", &challenge, &vmk).unwrap();
        let opened = eph1.open_vmk("4KQ7M2XD", &challenge, &sealed).unwrap();
        assert_eq!(vmk_fingerprint(&opened), vmk_fingerprint(&vmk));

        // Wrong request_id or challenge in AAD is refused.
        let eph_bad_req = SeEphemeralKey::generate().unwrap();
        let sealed_bad_req =
            seal_vmk_to_daemon(eph_bad_req.public_key(), "4KQ7M2XD", &challenge, &vmk).unwrap();
        assert!(
            eph_bad_req
                .open_vmk("OTHERREQ", &challenge, &sealed_bad_req)
                .is_err()
        );

        let eph_bad_chal = SeEphemeralKey::generate().unwrap();
        let sealed_bad_chal =
            seal_vmk_to_daemon(eph_bad_chal.public_key(), "4KQ7M2XD", &challenge, &vmk).unwrap();
        assert!(
            eph_bad_chal
                .open_vmk("4KQ7M2XD", &[0x99u8; SE_CHALLENGE_LEN], &sealed_bad_chal)
                .is_err()
        );
    }

    #[test]
    fn rejects_invalid_p256_keys_and_identical_unlock_and_approve_keys() {
        assert!(check_p256_public_key(&[0u8; 65]).is_err());
        assert!(check_p256_public_key(&[4u8; 65]).is_err());
        assert!(check_p256_public_key(&[4u8; 33]).is_err());

        let (_, mut rec) = sample_record();
        rec.approve_pub = rec.unlock_pub;
        assert!(rec.check().is_err());
    }

    #[test]
    fn p256_prehash_sign_and_verify_accepts_both_s_halves_and_rejects_bad_inputs() {
        let (sk1, pk1) = derive_p256_keypair(&[0x31u8; 32]);
        let (_, pk2) = derive_p256_keypair(&[0x32u8; 32]);
        let digest: [u8; 32] = Sha256::digest(b"envcloak-statement/2\ntest-statement").into();
        let other_digest: [u8; 32] =
            Sha256::digest(b"envcloak-statement/2\nother-statement").into();
        let double_hashed: [u8; 32] = Sha256::digest(digest).into();

        let sig = sign_p256_prehash(&sk1, &digest).unwrap();
        assert!(verify_p256_prehash(&pk1, &digest, &sig).is_ok());
        assert!(verify_p256_prehash(&pk2, &digest, &sig).is_err());
        assert!(verify_p256_prehash(&pk1, &other_digest, &sig).is_err());
        assert!(verify_p256_prehash(&[0u8; 65], &digest, &sig).is_err());
        assert!(verify_p256_prehash(&pk1, &digest, &[0u8; 64]).is_err());

        // Double-hashing the digest fails verification against the one-hash digest.
        let double_sig = sign_p256_prehash(&sk1, &double_hashed).unwrap();
        assert!(verify_p256_prehash(&pk1, &digest, &double_sig).is_err());

        // High-S representation (`s' = n - s` on P-256, as Apple Security / CryptoKit
        // may emit) is normalized and accepted for the exact digest, while a flipped
        // byte is rejected.
        let p256_order: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];
        let mut high_s_sig = sig;
        let mut borrow = 0u16;
        for i in (0..32).rev() {
            let diff = i32::from(p256_order[i]) - i32::from(sig[32 + i]) - i32::from(borrow);
            if diff < 0 {
                high_s_sig[32 + i] = (diff + 256) as u8;
                borrow = 1;
            } else {
                high_s_sig[32 + i] = diff as u8;
                borrow = 0;
            }
        }
        assert!(verify_p256_prehash(&pk1, &digest, &high_s_sig).is_ok());
        let mut flipped = sig;
        flipped[63] ^= 1;
        assert!(verify_p256_prehash(&pk1, &digest, &flipped).is_err());
    }

    #[test]
    fn seal_and_open_secret_to_x25519_binds_aad_and_rejects_tampering() {
        let eph = SeEphemeralKey::generate().unwrap();
        let secret = SecretBytes::copy_from(b"sk_test_synthetic_secret_value_0123456789");
        let aad = b"TARGET01\x11\x22\x33\x44";
        let sealed = seal_secret_to_x25519(eph.public_key(), aad, &secret).unwrap();
        assert_eq!(sealed.len(), SE_SEALED_SECRET_OVERHEAD + secret.len());
        let opened = eph.open_secret(aad, &sealed).unwrap();
        assert_eq!(secret_sha256(&opened), secret_sha256(&secret));
        assert!(eph.open_secret(b"WRONG_AAD", &sealed).is_err());
        assert!(
            eph.open_secret(aad, &sealed[..SE_SEALED_SECRET_OVERHEAD])
                .is_err()
        );
        assert!(seal_secret_to_x25519(&[0u8; 32], aad, &secret).is_err());
    }
}
