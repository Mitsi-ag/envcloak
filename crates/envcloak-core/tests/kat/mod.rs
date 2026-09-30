//! The known-answer envelope, which scripts/crypto-kat-vectors.py builds
//! with implementations independent of the crates the vault uses. Shared
//! by crypto_kat.rs, which unwraps it and checks what comes out against
//! the vectors, and crypto_probe.rs, which watches its key material in
//! freed memory.
#![allow(dead_code, clippy::unwrap_used)]

use envcloak_core::crypto::{EnvelopeCtx, UnlockerId, VaultId};

pub fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    assert_eq!(s.len() % 2, 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// `start`, `start + 1`, ..., `N` bytes of the test pattern.
pub fn range<const N: usize>(start: u8) -> [u8; N] {
    core::array::from_fn(|i| start + i as u8)
}

pub const VAULT_ID: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
pub const EPOCH: u32 = 7;
pub const PASSPHRASE: &[u8] = b"envcloak envelope known answer";

/// The VMK [`ENVELOPE`] wraps.
pub fn vmk() -> [u8; 32] {
    range(0x20)
}

/// A passphrase envelope of the VMK 0x20..0x3f for unlocker 0x50..0x5f,
/// with m = 64 MiB, t = 2, p = 1, salt 0x60..0x6f and nonce 0x70..0x87.
pub const ENVELOPE: &str = "
    454345560101505152535455565758595a5b5c5d5e5f0000000701000100000000000200000001606162
    636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868763ac42c70c
    d503f7143f1e9be31decd03c3474a4710ae7eead62516b570e51c93c8850368b913e272860cbc632620a
    a71154c6cee7aaaec003d486265fc4b66963e53b8afa5c52d7e4b245ad22da0a84";

/// The caller's record of the envelope's vault, unlocker and epoch.
pub fn kat_ctx() -> EnvelopeCtx {
    EnvelopeCtx {
        vault_id: VaultId(VAULT_ID),
        unlocker_id: UnlockerId(range(0x50)),
        epoch: EPOCH,
    }
}
