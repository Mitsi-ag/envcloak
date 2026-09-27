//! Gate 11 on the unlocker paths: checking a passphrase, parsing and
//! showing the Recovery Kit, confirming the kit, changing the passphrase,
//! unlocking with the passphrase or the kit, and backing up and restoring
//! never free a block that still holds the passphrase, the new passphrase,
//! the kit's text or a stored fixture.
//!
//! The probe scans every freed block, and each Argon2id run frees 64 MiB
//! that never holds a secret (T2's crypto probe covers wrapping and
//! unwrapping), so the vault is created before the probe is armed, every
//! envelope uses the minimum parameters, and the wiping pass repeats only
//! the paths without Argon2id and one unlock.
//!
//! `ProbeMode::Unwiped` turns the allocator's own wipe off, so it checks
//! that this code wipes every buffer it fills with a secret; the
//! `ProbeMode::Wiping` pass is the gate as written. SQLite's memory (the
//! database image a backup copies) is C `malloc`, which the probe does not
//! see; it only ever holds sealed bytes. One test, so no other test's
//! allocations run while the probe is armed.
#![allow(clippy::unwrap_used)]

mod common;

use common::populate;
use envcloak_core::backup::restore_backup_observed;
use envcloak_core::crypto::KdfParams;
use envcloak_core::vault::{Integrity, LockedVault, VaultPaths};
use envcloak_core::{RecoveryKit, SecretBytes, check_passphrase, create_vault};
use envcloak_testkit::{
    Canary, ProbeAllocator, ProbeMode, ProbeReport, TestHome, by_label, canaries, fresh_seed,
    labels, probe_canaries,
};

#[global_allocator]
static ALLOCATOR: ProbeAllocator = ProbeAllocator;

fn secret(c: &[Canary], label: &str) -> SecretBytes {
    SecretBytes::copy_from(by_label(c, label).value())
}

fn assert_clean(report: &ProbeReport, mode: ProbeMode, what: &str) {
    assert!(report.freed > 0, "{what} {mode:?} {report:?}");
    assert_eq!(report.released_with_needle, 0, "{what} {mode:?} {report:?}");
    if mode == ProbeMode::Wiping {
        assert_eq!(report.not_zeroed, 0, "{what} {mode:?} {report:?}");
    }
}

/// Parses and shows the kit, and checks both passphrases: no Argon2id.
fn text_paths(all: &[Canary]) -> RecoveryKit {
    check_passphrase(&secret(all, labels::VAULT_PASSPHRASE)).unwrap();
    check_passphrase(&secret(all, "NEW_PASSPHRASE")).unwrap();
    let kit = RecoveryKit::parse(&secret(all, "RECOVERY_KIT")).unwrap();
    drop(kit.to_display());
    assert!(RecoveryKit::parse(&secret(all, labels::VAULT_PASSPHRASE)).is_err());
    kit
}

#[test]
fn unlocker_paths_leave_no_secret_in_freed_memory() {
    let cs = canaries(fresh_seed());

    // Negative control: this binary's probe is armed and sees a plain copy.
    let session = probe_canaries(&cs, ProbeMode::Unwiped);
    drop(std::hint::black_box(
        by_label(&cs, labels::GITHUB_TOKEN).value().to_vec(),
    ));
    assert!(session.finish().released_with_needle >= 1);

    // Created before the probe is armed; the kit then becomes a needle.
    let home = TestHome::new();
    let paths = VaultPaths::under(home.root().join("data"));
    let (mut v, kit) = create_vault(
        &paths,
        &secret(&cs, labels::VAULT_PASSPHRASE),
        KdfParams::minimum(),
    )
    .unwrap();
    populate(&mut v, &cs);
    let mut all = cs.clone();
    all.push(Canary::new("RECOVERY_KIT", kit.to_display().to_string()));
    all.push(Canary::new(
        "NEW_PASSPHRASE",
        format!("new passphrase {}", fresh_seed()),
    ));
    drop(kit);
    let min = KdfParams::minimum();

    let mode = ProbeMode::Unwiped;
    let session = probe_canaries(&all, mode);
    let kit = text_paths(&all);
    v.confirm_recovery_kit(&kit).unwrap();
    v.change_passphrase_for_testing(&secret(&all, "NEW_PASSPHRASE"), &min)
        .unwrap();
    let info = v.create_backup().unwrap();
    drop(v);
    let v = LockedVault::open(&paths)
        .unwrap()
        .unlock_with_passphrase(&secret(&all, "NEW_PASSPHRASE"))
        .map_err(|(_, e)| e)
        .unwrap();
    drop(v);
    let (v, _) = restore_backup_observed(
        &paths,
        &info.path,
        &kit,
        &secret(&all, labels::VAULT_PASSPHRASE),
        &min,
        &mut |_| {},
    )
    .unwrap();
    assert_eq!(v.integrity(), Integrity::Ok);
    common::assert_holds_canaries(&v, &cs);
    drop((v, kit));
    assert_clean(&session.finish(), mode, "every unlocker path");

    let mode = ProbeMode::Wiping;
    let session = probe_canaries(&all, mode);
    let kit = text_paths(&all);
    let v = LockedVault::open(&paths)
        .unwrap()
        .unlock_with_kit(&kit)
        .map_err(|(_, e)| e)
        .unwrap();
    v.create_backup().unwrap();
    drop((v, kit));
    assert_clean(&session.finish(), mode, "kit, unlock and backup");
    home.assert_clean(&all);
}
