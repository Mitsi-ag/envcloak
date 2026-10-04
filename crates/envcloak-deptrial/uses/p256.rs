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
