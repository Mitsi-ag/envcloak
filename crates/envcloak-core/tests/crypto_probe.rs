//! Gate 11 for the crypto primitives: sealing, opening, wrapping and
//! unwrapping never free a block that still holds a fixture.
//!
//! `ProbeMode::Unwiped` turns the allocator's own wipe off, so it checks
//! that this code wipes every buffer it fills with a value. The
//! `ProbeMode::Wiping` runs are the gate as written: with the wiping
//! allocator, no freed block holds a fixture.
//!
//! Besides the canaries, the needles include key material: Argon2id's
//! working memory, computed here with the argon2 crate and checked against
//! the envelope it came from, and a Poly1305 state's key and pending block.
#![allow(clippy::unwrap_used)]

use std::mem::ManuallyDrop;

use argon2::{Algorithm, Argon2, Block, Params, Version};
use envcloak_core::SecretBytes;
use envcloak_core::crypto::{
    Aad, Argon2id, Envelope, EnvelopeCtx, FieldTag, ItemClass, Kdf, KdfParams, Keyring, Purpose,
    StoredKdfParams, TableTag, UnlockerId, UnlockerKind, VaultId, Vmk, open, seal, unwrap_vmk,
    wrap_vmk_with,
};
use envcloak_testkit::{
    Canary, ProbeAllocator, ProbeMode, ProbeSession, by_label, canaries, fresh_seed, labels,
    probe_canaries,
};
use hkdf::Hkdf;
use poly1305::Poly1305;
use poly1305::universal_hash::{KeyInit as _, UniversalHash as _};
use sha2::Sha256;

#[global_allocator]
static ALLOCATOR: ProbeAllocator = ProbeAllocator;

fn aad(kr: &Keyring) -> Aad {
    Aad {
        vault_id: kr.vault_id(),
        schema_version: 1,
        key_epoch: kr.epoch(),
        table: TableTag::Fields,
        row_id: [3; 16],
        field: FieldTag::FieldValue,
        item_class: ItemClass::Secret,
        row_version: 1,
    }
}

fn seal_and_open_every_fixture(cs: &[Canary], kr: &Keyring) {
    let k = kr.key(Purpose::Data);
    let a = aad(kr);
    for c in cs {
        let sealed = seal(k, &a, c.value()).unwrap();
        let opened = open(k, &a, &sealed).unwrap();
        assert!(opened.ct_eq(c.value()));
        drop(opened);
        // A failed open allocates its output buffer too.
        let moved = Aad {
            row_version: 2,
            ..a
        };
        assert!(open(k, &moved, &sealed).is_err());
    }
}

#[test]
fn the_probe_catches_an_unwiped_copy() {
    // Negative control: this binary's probe is armed and sees a plain copy.
    let cs = canaries(fresh_seed());
    let session = probe_canaries(&cs, ProbeMode::Unwiped);
    drop(std::hint::black_box(
        by_label(&cs, labels::GITHUB_TOKEN).value().to_vec(),
    ));
    let report = session.finish();
    assert!(report.released_with_needle >= 1, "{report:?}");
}

#[test]
fn seal_and_open_wipe_their_own_buffers() {
    let cs = canaries(fresh_seed());
    let kr = Keyring::derive(&Vmk::generate(), &VaultId::generate(), 1);
    let session = probe_canaries(&cs, ProbeMode::Unwiped);
    seal_and_open_every_fixture(&cs, &kr);
    let report = session.finish();
    assert!(report.freed > 0, "{report:?}");
    assert_eq!(report.released_with_needle, 0, "{report:?}");
}

#[test]
fn seal_and_open_leave_no_fixture_with_the_wiping_allocator() {
    let cs = canaries(fresh_seed());
    let kr = Keyring::derive(&Vmk::generate(), &VaultId::generate(), 1);
    let session = probe_canaries(&cs, ProbeMode::Wiping);
    seal_and_open_every_fixture(&cs, &kr);
    let report = session.finish();
    assert!(report.freed > 0, "{report:?}");
    assert_eq!(report.not_zeroed, 0, "{report:?}");
    assert_eq!(report.released_with_needle, 0, "{report:?}");
}

#[test]
fn wrap_and_unwrap_wipe_the_passphrase() {
    let cs = canaries(fresh_seed());
    let ctx = EnvelopeCtx {
        vault_id: VaultId::generate(),
        unlocker_id: UnlockerId::generate(),
        epoch: 1,
    };
    for mode in [ProbeMode::Unwiped, ProbeMode::Wiping] {
        let session = probe_canaries(&cs, mode);
        let pass = SecretBytes::copy_from(by_label(&cs, labels::VAULT_PASSPHRASE).value());
        let vmk = Vmk::generate();
        let env = wrap_vmk_with(
            &vmk,
            &pass,
            UnlockerKind::Passphrase,
            &ctx,
            &KdfParams::minimum(),
            &Argon2id,
        )
        .unwrap();
        drop(unwrap_vmk(&env, &pass, &ctx).unwrap());
        let wrong = SecretBytes::copy_from(by_label(&cs, labels::SHORT_TOKEN).value());
        assert!(unwrap_vmk(&env, &wrong, &ctx).is_err());
        drop((pass, wrong, vmk));
        let report = session.finish();
        assert!(report.freed > 0, "{mode:?} {report:?}");
        assert_eq!(report.not_zeroed, 0, "{mode:?} {report:?}");
        assert_eq!(report.released_with_needle, 0, "{mode:?} {report:?}");
    }
}

/// Argon2id of `pass` under `k`, with the argon2 crate, in `memory`, which
/// the caller supplies and keeps: returns the KEK and leaves the working
/// memory as a derivation ends it.
fn argon2_reference(pass: &[u8], k: &StoredKdfParams, memory: &mut [Block]) -> [u8; 32] {
    let params = Params::new(k.m_kib(), k.t(), k.p(), Some(32)).unwrap();
    let mut kek = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(pass, k.salt(), &mut kek, memory)
        .unwrap();
    kek
}

/// The number of 1 KiB blocks of Argon2id's working memory under `k`.
fn argon2_blocks(k: &StoredKdfParams) -> usize {
    Params::new(k.m_kib(), k.t(), k.p(), None)
        .unwrap()
        .block_count()
}

/// HKDF-SHA256 of `ikm`, 32 bytes.
fn hkdf32(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(salt, ikm)
        .expand(info, &mut out)
        .unwrap();
    out
}

/// Whether `kek` is the KEK `env` was wrapped under: its commit key
/// reproduces the envelope's commitment over its header and the vault id
/// (docs/CRYPTO.md).
fn is_the_kek(env: &Envelope, vault_id: &VaultId, kek: &[u8; 32]) -> bool {
    let bytes = env.to_bytes();
    let commit = hkdf32(kek, None, b"envcloak/v1/commit");
    let mut auth = bytes[..79].to_vec();
    auth.extend_from_slice(&vault_id.0);
    blake3::keyed_hash(&commit, &auth).as_bytes()[..] == bytes[79..111]
}

/// Argon2id's working memory holds the last block of each lane, from which
/// the KEK follows, so a derivation wipes it before it is freed, with or
/// without the wiping allocator. The needles are the first 64 bytes of the
/// first, middle and last block of each of the four lanes, from the same
/// derivation run here with the argon2 crate into memory the test keeps
/// (checked to give the envelope's KEK). The control frees that memory
/// unwiped, and the probe finds them.
#[test]
fn a_derivation_wipes_the_argon2_memory() {
    const PASS: &[u8] = b"a passphrase for the argon2 memory";
    let pass = SecretBytes::copy_from(PASS);
    let ctx = EnvelopeCtx {
        vault_id: VaultId::generate(),
        unlocker_id: UnlockerId::generate(),
        epoch: 1,
    };
    let env = wrap_vmk_with(
        &Vmk::generate(),
        &pass,
        UnlockerKind::Passphrase,
        &ctx,
        &KdfParams::with_memory(KdfParams::MIN_M_KIB),
        &Argon2id,
    )
    .unwrap();
    let k = *env.kdf();
    let blocks = argon2_blocks(&k);
    let lanes = usize::try_from(k.p()).unwrap();
    let lane_len = blocks / lanes;
    let mut needles = [[0u8; 64]; 12];
    assert_eq!(needles.len(), lanes * 3);
    let mut memory = vec![Block::default(); blocks];
    let kek = argon2_reference(PASS, &k, &mut memory);
    assert!(
        is_the_kek(&env, &ctx.vault_id, &kek),
        "the reference derivation is not the envelope's"
    );
    for (n, needle) in needles.iter_mut().enumerate() {
        let (lane, which) = (n / 3, n % 3);
        let at = lane * lane_len + [0, lane_len / 2, lane_len - 1][which];
        for (bytes, word) in needle.chunks_exact_mut(8).zip(memory[at].as_ref()) {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
    }
    drop(memory);
    let refs: Vec<&[u8]> = needles.iter().map(|n| &n[..]).collect();

    // Control: the same memory, freed unwiped, holds the needles.
    let session = ProbeSession::start(&refs, 32, ProbeMode::Unwiped);
    let mut memory = vec![Block::default(); blocks];
    argon2_reference(PASS, &k, &mut memory);
    drop(memory);
    let report = session.finish();
    assert!(report.released_with_needle >= 1, "{report:?}");

    let session = ProbeSession::start(&refs, 32, ProbeMode::Unwiped);
    drop(Argon2id.derive(&pass, &k).unwrap());
    drop(unwrap_vmk(&env, &pass, &ctx).unwrap());
    let report = session.finish();
    assert!(report.freed > 0, "{report:?}");
    assert_eq!(report.released_with_needle, 0, "{report:?}");
}

/// The Poly1305 state is wiped when it is dropped. It holds the one-time
/// key (r, and s as given in the portable backend) and, in the AVX2
/// backend, blocks not yet processed. chacha20poly1305's `zeroize` feature
/// does not reach poly1305, so the workspace turns poly1305's own on. The
/// needles are s and a block; the control frees a state without dropping
/// it, and the probe finds one of them.
#[test]
fn a_dropped_poly1305_state_is_wiped() {
    let key: [u8; 32] = core::array::from_fn(|i| 0x81 ^ (i as u8).wrapping_mul(29));
    let block: [u8; 16] = core::array::from_fn(|i| 0x5c ^ (i as u8).wrapping_mul(53));
    let needles: [&[u8]; 2] = [&key[16..], &block];

    let session = ProbeSession::start(&needles, 16, ProbeMode::Unwiped);
    let mut kept = Box::new(ManuallyDrop::new(Poly1305::new(&key.into())));
    kept.update(&[block.into()]);
    drop(kept);
    let report = session.finish();
    assert!(report.released_with_needle >= 1, "{report:?}");

    let session = ProbeSession::start(&needles, 16, ProbeMode::Unwiped);
    let mut mac = Box::new(Poly1305::new(&key.into()));
    mac.update(&[block.into()]);
    drop(mac);
    let report = session.finish();
    assert!(report.freed > 0, "{report:?}");
    assert_eq!(report.released_with_needle, 0, "{report:?}");
}
