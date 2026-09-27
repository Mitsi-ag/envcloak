//! Gate 4 (SPEC §15.2): after the primary unlocker is destroyed, restoring
//! from the Recovery Kit gives identical items; a wrong kit fails.
//!
//! Two ways the passphrase is lost:
//! - forgotten, with the vault file intact: the kit unlocks the vault and
//!   a new passphrase replaces the old envelope;
//! - destroyed with the vault (the acceptance story's S11: the `vault`
//!   directory is deleted, or the passphrase envelope is damaged on disk):
//!   an encrypted backup is restored with the kit and a new passphrase.
//!
//! In both, every item's metadata, value and prior value, and the project
//! record, are what they were, and the digest verifies.
#![allow(clippy::unwrap_used)]

mod common;

use common::{KitFixture, assert_holds_canaries, dir_names, other_passphrase};
use envcloak_core::crypto::{CryptoErrorKind, UnlockerKind};
use envcloak_core::vault::{Integrity, ItemMeta, LockedVault, VaultErrorKind};
use envcloak_core::{RecoveryKit, SecretBytes, restore_backup};
use envcloak_testkit::Detector;

#[test]
fn a_forgotten_passphrase_is_replaced_through_the_kit() {
    let (f, v) = KitFixture::create();
    let before: Vec<ItemMeta> = v.items().to_vec();
    drop(v);

    // The passphrase is gone: anything else fails.
    let (locked, e) = f
        .open()
        .unlock_with_passphrase(&other_passphrase(1))
        .unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::Crypto(CryptoErrorKind::Unlock));

    let mut v = locked
        .unlock_with_kit(&f.kit())
        .map_err(|(_, e)| e)
        .unwrap();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_eq!(v.items(), &before[..], "identical items");
    assert_holds_canaries(&v, &f.cs);
    let new = other_passphrase(2);
    v.change_passphrase(&new).unwrap();
    drop(v);

    let v = f
        .open()
        .unlock_with_passphrase(&new)
        .map_err(|(_, e)| e)
        .unwrap();
    assert_eq!(v.items(), &before[..]);
    assert_holds_canaries(&v, &f.cs);
    f.home.assert_clean(&f.cs);
}

#[test]
fn a_deleted_vault_is_restored_from_a_backup_with_the_kit() {
    let (f, mut v) = KitFixture::create();
    v.confirm_recovery_kit(&f.kit()).unwrap();
    let info = v.create_backup().unwrap();
    let before: Vec<ItemMeta> = v.items().to_vec();
    let before_header = v.header().unwrap();
    drop(v);

    // S11: stop, delete `vault/`, restore.
    std::fs::remove_dir_all(&f.paths.vault_dir).unwrap();
    assert_eq!(
        LockedVault::open(&f.paths).unwrap_err().kind(),
        VaultErrorKind::NotFound
    );
    let new = other_passphrase(3);
    let (v, report) = restore_backup(&f.paths, &info.path, &f.kit(), &new).unwrap();
    assert_eq!(v.integrity(), Integrity::Ok, "the restored digest verifies");
    assert_eq!(v.items(), &before[..], "identical items");
    assert_holds_canaries(&v, &f.cs);
    assert!(v.recovery_confirmed().unwrap());
    let header = v.header().unwrap();
    assert_eq!(header.write_counter, before_header.write_counter + 1);
    assert_eq!(report.vault_id, v.vault_id());
    assert_eq!(report.backup_id, info.backup_id);
    assert_eq!(report.backup_write_counter, before_header.write_counter);
    assert_eq!(report.backup_created_at, info.created_at);
    assert_eq!(report.items, before.len());
    assert_eq!(report.replaced, None);
    drop(v);

    // The new passphrase opens it; the old one no longer does.
    let (locked, e) = f.open().unlock_with_passphrase(&f.pass()).unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::Crypto(CryptoErrorKind::Unlock));
    let v = locked
        .unlock_with_passphrase(&new)
        .map_err(|(_, e)| e)
        .unwrap();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_eq!(v.items(), &before[..]);
    assert_eq!(
        v.unlockers()
            .filter(|e| e.kind() == UnlockerKind::Passphrase)
            .count(),
        1
    );
    drop(v);
    // The kit still opens it too.
    let v = f
        .open()
        .unlock_with_kit(&f.kit())
        .map_err(|(_, e)| e)
        .unwrap();
    assert_holds_canaries(&v, &f.cs);
    f.home.assert_clean(&f.cs);
}

/// The primary unlocker is destroyed in place: its envelope no longer
/// opens with the passphrase, and the vault fails its integrity check. The
/// restore replaces the file and keeps the damaged one aside.
#[test]
fn a_destroyed_passphrase_envelope_is_recovered_from_a_backup() {
    let (f, v) = KitFixture::create();
    let info = v.create_backup().unwrap();
    let before: Vec<ItemMeta> = v.items().to_vec();
    let pass_env = v
        .unlockers()
        .find(|e| e.kind() == UnlockerKind::Passphrase)
        .unwrap()
        .to_bytes();
    drop(v);

    let raw = rusqlite::Connection::open(f.db()).unwrap();
    let mut destroyed = pass_env.to_vec();
    for b in &mut destroyed[79..] {
        *b = 0;
    }
    let n = raw
        .execute(
            "UPDATE unlockers SET envelope = ?1 WHERE envelope = ?2",
            rusqlite::params![destroyed, &pass_env[..]],
        )
        .unwrap();
    assert_eq!(n, 1);
    drop(raw);
    let (_, e) = f.open().unlock_with_passphrase(&f.pass()).unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::Crypto(CryptoErrorKind::Unlock));
    let damaged = std::fs::read(f.db()).unwrap();

    let new = other_passphrase(4);
    let (v, report) = restore_backup(&f.paths, &info.path, &f.kit(), &new).unwrap();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_eq!(v.items(), &before[..]);
    assert_holds_canaries(&v, &f.cs);
    drop(v);
    let kept = report.replaced.expect("the replaced vault is kept");
    assert_eq!(kept.parent(), Some(f.db().parent().unwrap()));
    let name = kept.file_name().unwrap().to_str().unwrap().to_owned();
    assert!(
        name.starts_with("replaced-") && name.ends_with(".db"),
        "{name}"
    );
    assert_eq!(std::fs::read(&kept).unwrap(), damaged, "kept byte for byte");
    let mut names = dir_names(&f.paths.vault_dir);
    names.retain(|n| n != "vault.db-wal");
    assert_eq!(names, [name.as_str(), "vault.db"]);
    let v = f
        .open()
        .unlock_with_passphrase(&new)
        .map_err(|(_, e)| e)
        .unwrap();
    assert_eq!(v.items(), &before[..]);
    f.home.assert_clean(&f.cs);
}

/// A wrong kit fails with the generic error, whether it unlocks the vault
/// or restores a backup, and a failed restore changes nothing.
#[test]
fn a_wrong_kit_fails_and_changes_nothing() {
    let (f, v) = KitFixture::create();
    let info = v.create_backup().unwrap();
    drop(v);
    let det = Detector::new(&f.cs);
    let files_before = dir_names(&f.paths.vault_dir);
    let db_before = std::fs::read(f.db()).unwrap();

    let wrong = RecoveryKit::generate();
    let e = restore_backup(&f.paths, &info.path, &wrong, &other_passphrase(5)).unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::Crypto(CryptoErrorKind::Unlock));
    assert!(det.find(format!("{e} {e:?}").as_bytes()).is_empty());
    let (locked, e2) = f.open().unlock_with_kit(&wrong).unwrap_err();
    assert_eq!(e2.kind(), e.kind());
    assert_eq!(e2.to_string(), e.to_string());
    let (_, e3) = locked
        .unlock_with_passphrase(&other_passphrase(6))
        .unwrap_err();
    assert_eq!(
        e3.to_string(),
        e.to_string(),
        "the same as a wrong passphrase"
    );

    assert_eq!(dir_names(&f.paths.vault_dir), files_before);
    assert_eq!(std::fs::read(f.db()).unwrap(), db_before);
    let v = f.unlock();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_holds_canaries(&v, &f.cs);
    // A kit typed with a mistake never reaches key derivation.
    let mut typo = f.kit_text.as_bytes().to_vec();
    typo[0] = if typo[0] == b'A' { b'B' } else { b'A' };
    assert!(RecoveryKit::parse(&SecretBytes::copy_from(&typo)).is_err());
}
