//! Unlockers (SPEC §5 "Unlockers", "Unlock flow"): creating a vault with a
//! passphrase and a Recovery Kit, unlocking with either, confirming the
//! kit, and SPEC §15.2 gate 3 for the vault's own paths:
//! - a wrong passphrase, a wrong kit and a damaged envelope give one
//!   generic error;
//! - a re-wrap (a passphrase change) uses the current default parameters,
//!   never the stored ones.
#![allow(clippy::unwrap_used)]

mod common;

use common::{KitFixture, dir_names, later_wal, other_passphrase};
use envcloak_core::crypto::{CryptoErrorKind, Envelope, KdfParams, UnlockerKind};
use envcloak_core::vault::{Integrity, LockedVault, VaultErrorKind, VaultPaths};
use envcloak_core::{PassphraseRejected, RecoveryKit, SecretBytes, create_vault};
use envcloak_testkit::{Detector, TestHome, by_label, labels};

fn secret(s: &str) -> SecretBytes {
    SecretBytes::copy_from(s.as_bytes())
}

fn envelope(v: &envcloak_core::vault::Vault, kind: UnlockerKind) -> Envelope {
    let mut e = v.unlockers().filter(|e| e.kind() == kind);
    let env = e.next().unwrap().clone();
    assert!(e.next().is_none(), "one {kind:?} envelope");
    env
}

// ------------------------------------------------------ creating a vault

#[test]
fn create_vault_makes_a_passphrase_and_a_kit_envelope() {
    let (f, v) = KitFixture::create();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert!(!v.recovery_confirmed().unwrap());
    let pass = envelope(&v, UnlockerKind::Passphrase);
    let kit = envelope(&v, UnlockerKind::RecoveryKit);
    assert_eq!(v.unlockers().count(), 2);
    for e in [&pass, &kit] {
        let k = e.kdf();
        assert_eq!(
            (k.m_kib, k.t, k.p),
            (KdfParams::MIN_M_KIB, KdfParams::MIN_T, KdfParams::MIN_P)
        );
    }
    assert_ne!(
        pass.kdf().salt,
        kit.kdf().salt,
        "each envelope has its own salt"
    );
    assert_ne!(pass.unlocker_id(), kit.unlocker_id());
    common::assert_holds_canaries(&v, &f.cs);
    drop(v);

    let v = f
        .open()
        .unlock_with_passphrase(&f.pass())
        .map_err(|(_, e)| e)
        .unwrap();
    common::assert_holds_canaries(&v, &f.cs);
    drop(v);
    let v = f
        .open()
        .unlock_with_kit(&f.kit())
        .map_err(|(_, e)| e)
        .unwrap();
    assert_eq!(v.integrity(), Integrity::Ok);
    common::assert_holds_canaries(&v, &f.cs);
    drop(v);

    // A second vault in the same place is refused.
    let e = create_vault(&f.paths, &f.pass(), KdfParams::minimum()).unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::AlreadyExists);
    f.home.assert_clean(&f.cs);
}

#[test]
fn create_vault_refuses_a_weak_passphrase_or_bad_parameters_before_writing() {
    let home = TestHome::new();
    // TestHome makes `data/` itself.
    let paths = VaultPaths::under(home.root().join("data/envcloak"));
    for (pass, want) in [
        ("too short", PassphraseRejected::TooShort),
        ("passwordpassword", PassphraseRejected::Common),
        (
            "new\nline in passphrase",
            PassphraseRejected::ControlCharacter,
        ),
    ] {
        let e = create_vault(&paths, &secret(pass), KdfParams::minimum()).unwrap_err();
        assert_eq!(e.kind(), VaultErrorKind::Passphrase(want));
        assert!(!paths.data_dir.exists(), "nothing written");
    }
    let low = KdfParams {
        m_kib: KdfParams::MIN_M_KIB - 1,
        ..KdfParams::minimum()
    };
    let e = create_vault(&paths, &other_passphrase(1), low).unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::Crypto(CryptoErrorKind::KdfParams));
    assert!(!paths.data_dir.exists());
}

/// A WAL or journal left beside a missing `vault.db` is moved aside before
/// the new vault is linked into place, so SQLite never replays it onto the
/// new file, whether it was written for the vault that was there or for
/// another one.
#[test]
fn create_vault_moves_aside_side_files_left_without_a_vault() {
    let (f, mut v) = KitFixture::create();
    let same = later_wal(&mut v, &f.db());
    drop(v);
    let (g, mut w) = KitFixture::create();
    let other = later_wal(&mut w, &g.db());
    drop(w);

    let db = f.db();
    for (n, (what, wal)) in [("same vault", &same), ("another vault", &other)]
        .into_iter()
        .enumerate()
    {
        std::fs::remove_file(&db).unwrap();
        std::fs::write(db.with_file_name("vault.db-wal"), wal).unwrap();
        std::fs::write(db.with_file_name("vault.db-journal"), b"stale journal").unwrap();
        let pass = other_passphrase(10 + n as u64);
        let (v, _kit) = create_vault(&f.paths, &pass, KdfParams::minimum()).unwrap();
        assert_eq!(v.integrity(), Integrity::Ok, "{what}");
        assert!(v.items().is_empty(), "{what}: a new vault is empty");
        drop(v);

        let names = dir_names(&f.paths.vault_dir);
        let kept: Vec<&String> = names
            .iter()
            .filter(|n| n.starts_with("replaced-"))
            .collect();
        assert_eq!(kept.len(), 2 * (n + 1), "{what}: {names:?}");
        let wal_kept = kept
            .iter()
            .filter(|k| k.ends_with(".db-wal"))
            .map(|k| std::fs::read(f.paths.vault_dir.join(k)).unwrap())
            .any(|b| b == *wal);
        assert!(wal_kept, "{what}: the WAL is kept byte for byte");
        assert!(names.contains(&"vault.db".to_owned()));

        let v = f
            .open()
            .unlock_with_passphrase(&pass)
            .map_err(|(_, e)| e)
            .unwrap();
        assert_eq!(v.integrity(), Integrity::Ok, "{what}: reopened");
        assert!(v.items().is_empty(), "{what}: reopened");
    }
    f.home.assert_clean(&f.cs);
}

// ------------------------------------------------------ gate 3

/// A wrong passphrase, a wrong kit, and a passphrase or kit envelope whose
/// commitment or ciphertext was damaged all give the same error, and the
/// locked vault comes back for another try.
#[test]
fn every_wrong_secret_or_damaged_envelope_gives_one_generic_error() {
    let (f, v) = KitFixture::create();
    drop(v);
    let det = Detector::new(&f.cs);
    let generic = VaultErrorKind::Crypto(CryptoErrorKind::Unlock);
    let check = |e: envcloak_core::vault::VaultError, what: &str| {
        assert_eq!(e.kind(), generic, "{what}");
        assert_eq!(e.to_string(), generic.message(), "{what}");
        assert!(
            det.find(format!("{e} {e:?}").as_bytes()).is_empty(),
            "{what}"
        );
    };

    let (locked, e) = f
        .open()
        .unlock_with_passphrase(&other_passphrase(2))
        .unwrap_err();
    check(e, "wrong passphrase");
    // The kit's text is not the passphrase.
    let (locked, e) = locked
        .unlock_with_passphrase(&SecretBytes::copy_from(f.kit_text.as_bytes()))
        .unwrap_err();
    check(e, "kit text as passphrase");
    let (locked, e) = locked
        .unlock_with_kit(&RecoveryKit::generate())
        .unwrap_err();
    check(e, "wrong kit");
    // The same handle still unlocks with the right one.
    let v = locked
        .unlock_with_passphrase(&f.pass())
        .map_err(|(_, e)| e)
        .unwrap();
    let envelopes: Vec<(UnlockerKind, [u8; Envelope::LEN])> =
        v.unlockers().map(|e| (e.kind(), e.to_bytes())).collect();
    drop(v);

    // Damage each envelope's commitment, then its sealed VMK, on disk.
    for (kind, bytes) in &envelopes {
        for at in [79 + 5, 111 + 3, Envelope::LEN - 1] {
            let raw = rusqlite::Connection::open(f.db()).unwrap();
            let mut damaged = bytes.to_vec();
            damaged[at] ^= 0x01;
            raw.execute(
                "UPDATE unlockers SET envelope = ?1 WHERE envelope = ?2",
                rusqlite::params![damaged, &bytes[..]],
            )
            .unwrap();
            drop(raw);
            let e = match kind {
                UnlockerKind::Passphrase => f.open().unlock_with_passphrase(&f.pass()),
                UnlockerKind::RecoveryKit => f.open().unlock_with_kit(&f.kit()),
            }
            .unwrap_err()
            .1;
            check(e, &format!("{kind:?} envelope byte {at}"));
            let raw = rusqlite::Connection::open(f.db()).unwrap();
            raw.execute(
                "UPDATE unlockers SET envelope = ?1 WHERE envelope = ?2",
                rusqlite::params![&bytes[..], damaged],
            )
            .unwrap();
        }
    }
    let v = f
        .open()
        .unlock_with_kit(&f.kit())
        .map_err(|(_, e)| e)
        .unwrap();
    assert_eq!(v.integrity(), Integrity::Ok, "every change was undone");
}

/// Gate 3: a re-wrap uses the current defaults. The vault was created at
/// the minimum parameters; the new passphrase envelope has the defaults
/// and a fresh salt, keeps its unlocker id, and the kit envelope is
/// unchanged.
#[test]
fn a_passphrase_change_rewraps_with_the_current_defaults() {
    let (f, mut v) = KitFixture::create();
    let old = envelope(&v, UnlockerKind::Passphrase);
    let kit = envelope(&v, UnlockerKind::RecoveryKit);
    let counter = v.header().unwrap().write_counter;

    // A weak new passphrase is refused before any work, and changes
    // nothing.
    let e = v.change_passphrase(&secret("short")).unwrap_err();
    assert_eq!(
        e.kind(),
        VaultErrorKind::Passphrase(PassphraseRejected::TooShort)
    );
    assert_eq!(v.header().unwrap().write_counter, counter);

    let new = other_passphrase(3);
    v.change_passphrase(&new).unwrap();
    let got = envelope(&v, UnlockerKind::Passphrase);
    let d = KdfParams::current_defaults();
    assert_eq!(
        (got.kdf().m_kib, got.kdf().t, got.kdf().p),
        (d.m_kib, d.t, d.p)
    );
    assert_eq!(
        (d.m_kib, d.t, d.p),
        (
            KdfParams::DEFAULT_M_KIB,
            KdfParams::DEFAULT_T,
            KdfParams::DEFAULT_P
        )
    );
    assert_ne!(got.kdf().salt, old.kdf().salt);
    assert_eq!(got.unlocker_id(), old.unlocker_id());
    assert!(
        envelope(&v, UnlockerKind::RecoveryKit) == kit,
        "the kit envelope is unchanged"
    );
    assert_eq!(v.header().unwrap().write_counter, counter + 1);
    drop(v);

    let (locked, e) = f.open().unlock_with_passphrase(&f.pass()).unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::Crypto(CryptoErrorKind::Unlock));
    let v = locked
        .unlock_with_passphrase(&new)
        .map_err(|(_, e)| e)
        .unwrap();
    assert_eq!(v.integrity(), Integrity::Ok);
    common::assert_holds_canaries(&v, &f.cs);
    drop(v);
    let v = f
        .open()
        .unlock_with_kit(&f.kit())
        .map_err(|(_, e)| e)
        .unwrap();
    assert_eq!(v.integrity(), Integrity::Ok);
    f.home.assert_clean(&f.cs);
}

#[test]
fn confirming_the_kit_needs_the_right_kit() {
    let (f, mut v) = KitFixture::create();
    assert!(!v.recovery_confirmed().unwrap());
    let e = v
        .confirm_recovery_kit(&RecoveryKit::generate())
        .unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::Crypto(CryptoErrorKind::Unlock));
    assert!(!v.recovery_confirmed().unwrap());
    let counter = v.header().unwrap().write_counter;
    v.confirm_recovery_kit(&f.kit()).unwrap();
    assert!(v.recovery_confirmed().unwrap());
    assert_eq!(v.header().unwrap().write_counter, counter + 1);
    // Again: checked, not written.
    v.confirm_recovery_kit(&f.kit()).unwrap();
    assert_eq!(v.header().unwrap().write_counter, counter + 1);
    drop(v);
    let v = f.unlock();
    assert!(v.recovery_confirmed().unwrap(), "kept in the sealed header");
}

/// A vault that failed its integrity check refuses a passphrase change and
/// a kit confirmation before any key derivation.
#[test]
fn a_tampered_vault_refuses_passphrase_and_kit_writes() {
    let (f, v) = KitFixture::create();
    let project = v.projects().unwrap().next().unwrap().0;
    drop(v);
    let raw = rusqlite::Connection::open(f.db()).unwrap();
    raw.execute(
        "DELETE FROM projects WHERE id = ?1",
        [&project.as_bytes()[..]],
    )
    .unwrap();
    drop(raw);
    let mut v = f
        .open()
        .unlock_with_kit(&f.kit())
        .map_err(|(_, e)| e)
        .unwrap();
    assert!(matches!(v.integrity(), Integrity::Tampered(_)));
    let pass = by_label(&f.cs, labels::VAULT_PASSPHRASE);
    let e = v
        .change_passphrase(&SecretBytes::copy_from(pass.value()))
        .unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::ReadOnly);
    let e = v.confirm_recovery_kit(&f.kit()).unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::ReadOnly);
    assert_eq!(
        v.recovery_confirmed().unwrap_err().kind(),
        VaultErrorKind::Tampered
    );
}

/// Unlocking a vault without the kind of envelope asked for says so.
#[test]
fn a_missing_unlocker_kind_is_named() {
    let (f, v) = common::Fixture::create();
    drop(v);
    let locked = LockedVault::open(&f.paths).unwrap();
    let (_, e) = locked
        .unlock_with_kit(&RecoveryKit::generate())
        .unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::NoRecoveryKit);
}
