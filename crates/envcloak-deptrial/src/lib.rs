pub mod hpke {
//! M3-01 dependency trial (scratch, never merged): SPEC §5's two HPKE
//! suites compile with the chosen features and round-trip.
use hpke::aead::{AesGcm256, ChaCha20Poly1305};
use hpke::kdf::HkdfSha256;
use hpke::kem::{DhP256HkdfSha256, X25519HkdfSha256};
use hpke::{Kem as _, OpModeR, OpModeS};

/// The VMK envelope: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM.
pub fn envelope_round_trip(ikm: &[u8], info: &[u8], pt: &[u8]) -> bool {
    let (sk, pk) = DhP256HkdfSha256::derive_keypair(ikm);
    let Ok((enc, ct)) = hpke::single_shot_seal::<AesGcm256, HkdfSha256, DhP256HkdfSha256>(
        &OpModeS::Base,
        &pk,
        info,
        pt,
        b"",
    ) else {
        return false;
    };
    hpke::single_shot_open::<AesGcm256, HkdfSha256, DhP256HkdfSha256>(
        &OpModeR::Base,
        &sk,
        &enc,
        info,
        &ct,
        b"",
    )
    .is_ok_and(|p| p == pt)
}

/// The reseal to the daemon: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
/// ChaCha20-Poly1305, with AAD `request_id || challenge`.
pub fn reseal_round_trip(ikm: &[u8], aad: &[u8], pt: &[u8]) -> bool {
    let (sk, pk) = X25519HkdfSha256::derive_keypair(ikm);
    let Ok((enc, ct)) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeS::Base,
        &pk,
        b"",
        pt,
        aad,
    ) else {
        return false;
    };
    hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &sk,
        &enc,
        b"",
        &ct,
        aad,
    )
    .is_ok_and(|p| p == pt)
}

#[cfg(test)]
mod tests {
    #[test]
    fn both_suites_round_trip() {
        let ikm = [7u8; 32];
        assert!(super::envelope_round_trip(&ikm, b"info", b"vmk"));
        assert!(super::reseal_round_trip(&ikm, b"aad", b"vmk"));
        // A wrong AAD does not open.
        assert!(!super::reseal_round_trip_with(&ikm, b"aad", b"other", b"vmk"));
    }
}

/// Seals with `aad` and opens with `open_aad`.
pub fn reseal_round_trip_with(ikm: &[u8], aad: &[u8], open_aad: &[u8], pt: &[u8]) -> bool {
    let (sk, pk) = X25519HkdfSha256::derive_keypair(ikm);
    let Ok((enc, ct)) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeS::Base,
        &pk,
        b"",
        pt,
        aad,
    ) else {
        return false;
    };
    hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &sk,
        &enc,
        b"",
        &ct,
        open_aad,
    )
    .is_ok_and(|p| p == pt)
}
}
pub mod p256 {
//! M3-01 dependency trial (scratch, never merged): P-256 ECDSA
//! verification only, over a SHA-256 digest as a prehash, with the 64-byte
//! raw `r || s` signature (D3-10).
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};

pub fn verify(public_sec1: &[u8], digest: &[u8; 32], raw: &[u8; 64]) -> bool {
    let Ok(key) = VerifyingKey::from_sec1_bytes(public_sec1) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(raw) else {
        return false;
    };
    key.verify_prehash(digest, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_malformed_key_is_refused() {
        assert!(!super::verify(&[4u8; 65], &[0u8; 32], &[1u8; 64]));
    }
}
}
pub mod security_framework {
//! M3-01 dependency trial (scratch, never merged): what `security-framework`
//! 3.x covers of D3-06 and D3-12 without `unsafe`: a peer's code from its
//! audit token checked against a requirement, and a data protection
//! keychain item. SecCodeCopySigningInformation (the runtime flag and the
//! entitlements D3-06 also checks) is not wrapped; M3-07 calls it from
//! envcloak-sys.
#[cfg(target_os = "macos")]
mod mac {
    use core_foundation::base::TCFType;
    use core_foundation::data::CFData;
    use security_framework::os::macos::code_signing::{
        Flags, GuestAttributes, SecCode, SecRequirement,
    };
    use security_framework::passwords::{
        delete_generic_password_options, generic_password, set_generic_password_options,
    };
    use security_framework::passwords_options::PasswordOptions;

    /// The guest named by an audit token satisfies `requirement`.
    pub fn satisfies(audit_token: &[u8], requirement: &str) -> bool {
        let Ok(req) = requirement.parse::<SecRequirement>() else {
            return false;
        };
        let data = CFData::from_buffer(audit_token);
        let mut attrs = GuestAttributes::new();
        attrs.set_audit_token(data.as_concrete_TypeRef());
        let Ok(code) = SecCode::copy_guest_with_attribues(None, &attrs, Flags::NONE) else {
            return false;
        };
        code.check_validity(Flags::NONE, &req).is_ok()
    }

    /// An anchor item in the data protection keychain (D3-12).
    pub fn anchor_round_trip(service: &str, account: &str, group: &str, bytes: &[u8]) -> bool {
        let opts = || {
            let mut o = PasswordOptions::new_generic_password(service, account);
            o.set_access_group(group);
            o.use_protected_keychain();
            o
        };
        set_generic_password_options(bytes, opts()).is_ok()
            && generic_password(opts()).is_ok_and(|b| b == bytes)
            && delete_generic_password_options(opts()).is_ok()
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn a_malformed_requirement_or_token_is_refused() {
            assert!(!super::satisfies(&[0u8; 32], "identifier \"ai.envcloak.app\""));
            assert!(!super::satisfies(&[0u8; 32], "not a requirement ("));
        }
    }
}

#[cfg(target_os = "macos")]
pub use mac::*;
}
