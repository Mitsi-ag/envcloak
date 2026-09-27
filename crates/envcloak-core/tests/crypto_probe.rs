//! Gate 11 for the crypto primitives: sealing, opening, wrapping and
//! unwrapping never free a block that still holds a fixture.
//!
//! `ProbeMode::Unwiped` turns the allocator's own wipe off, so it checks
//! that this code wipes every buffer it fills with a value. The
//! `ProbeMode::Wiping` runs are the gate as written: with the wiping
//! allocator, no freed block holds a fixture.
#![allow(clippy::unwrap_used)]

use envcloak_core::SecretBytes;
use envcloak_core::crypto::{
    Aad, Argon2id, EnvelopeCtx, FieldTag, ItemClass, KdfParams, Keyring, Purpose, TableTag,
    UnlockerId, UnlockerKind, VaultId, Vmk, open, seal, unwrap_vmk, wrap_vmk_with,
};
use envcloak_testkit::{
    Canary, ProbeAllocator, ProbeMode, by_label, canaries, fresh_seed, labels, probe_canaries,
};

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
