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
