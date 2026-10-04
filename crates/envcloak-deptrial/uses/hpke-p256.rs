//! M3-01 dependency trial (scratch, never merged): the D3-15 fallback,
//! DHKEM(P-256) with AES-256-GCM for both the envelope and the reseal.
use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha256;
use hpke::kem::DhP256HkdfSha256;
use hpke::{Kem as _, OpModeR, OpModeS};

pub fn round_trip(ikm: &[u8], aad: &[u8], pt: &[u8]) -> bool {
    let (sk, pk) = DhP256HkdfSha256::derive_keypair(ikm);
    let Ok((enc, ct)) = hpke::single_shot_seal::<AesGcm256, HkdfSha256, DhP256HkdfSha256>(
        &OpModeS::Base,
        &pk,
        b"",
        pt,
        aad,
    ) else {
        return false;
    };
    hpke::single_shot_open::<AesGcm256, HkdfSha256, DhP256HkdfSha256>(
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
    fn round_trips() {
        assert!(super::round_trip(&[9u8; 32], b"aad", b"vmk"));
    }
}
