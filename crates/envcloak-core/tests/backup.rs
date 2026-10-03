//! Encrypted vault backups (SPEC §5, §6.4, §15.1 step 11; the format is in
//! docs/VAULT.md "Backups"):
//! - a backup is a private file in `backups/` that holds no fixture, no
//!   plaintext metadata and none of the vault file's own bytes, and carries
//!   only the Recovery Kit envelope, so it is unusable without the kit;
//! - any change to a backup (a flipped bit, a truncation, an extension, a
//!   reordered, dropped or foreign record) is refused, and a refused
//!   restore changes nothing;
//! - a vault changed on disk behind an open vault is never backed up;
//! - a restored vault's digest verifies, and its new passphrase envelope
//!   uses the current default parameters (gate 3);
//! - a restore hands back only the state it prepared: one that finds
//!   another state installed, valid or not, fails;
//! - a restore refuses an open vault, a weak new passphrase, a backup path
//!   that is a symlink, a FIFO or a directory, and a backup of another
//!   vault than the one in place, also one that opens as damaged; it moves
//!   aside a file that is not a vault or is a damaged one, and never a WAL
//!   away from the vault it belongs to.
#![allow(clippy::unwrap_used)]

mod common;

use std::path::{Path, PathBuf};

use common::{
    Fixture, KitFixture, Rng, assert_holds_canaries, canary_slug, dir_names, later_wal, name,
    other_passphrase, secret_item,
};
use envcloak_core::backup::{
    BACKUP_CHUNK, BACKUP_EXTENSION, RestoreStep, remove_replaced_files, replaced_files,
    restore_backup_observed, restore_backup_with_plan,
};
use envcloak_core::crypto::{CryptoErrorKind, Envelope, KdfParams, UnlockerKind};
use envcloak_core::vault::{
    Integrity, ItemMeta, LockedVault, Migration, MigrationPlan, MigrationTx, PathErrorKind,
    TamperKind, VaultError, VaultErrorKind, VaultPaths, skip_next_close_checkpoint_for_testing,
};
use envcloak_core::{PassphraseRejected, SecretBytes, restore_backup};
use envcloak_testkit::assert_no_canary;

const HEADER_FIXED: usize = 44;

/// Where each record of a backup starts and how long it is, `len` field
/// included.
fn records(b: &[u8]) -> (usize, Vec<(usize, usize)>) {
    let header = HEADER_FIXED + usize::from(b[43]) * Envelope::LEN;
    let mut at = header;
    let mut out = Vec::new();
    while at < b.len() {
        let len = u32::from_be_bytes(b[at..at + 4].try_into().unwrap()) as usize;
        out.push((at, 4 + len));
        at += 4 + len;
    }
    assert_eq!(at, b.len());
    (header, out)
}

/// The only file in the backups directory.
fn only_backup(f: &KitFixture) -> PathBuf {
    let names = dir_names(&f.paths.backups_dir);
    let [name] = &names[..] else {
        panic!("backups: {names:?}");
    };
    f.paths.backups_dir.join(name)
}

/// Every blob column of the closed vault file.
fn stored_blobs(f: &KitFixture) -> Vec<(String, Vec<u8>)> {
    let raw = rusqlite::Connection::open(f.db()).unwrap();
    let mut out = Vec::new();
    for (table, cols) in [
        ("items", "slug_hash, sealed_meta"),
        ("fields", "value_hash, sealed_value"),
        ("projects", "dir_hash, sealed"),
        ("header", "sealed, sealed"),
        ("unlockers", "envelope, envelope"),
    ] {
        let mut st = raw.prepare(&format!("SELECT {cols} FROM {table}")).unwrap();
        let rows = st
            .query_map([], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .unwrap();
        for row in rows {
            let (a, b) = row.unwrap();
            out.push((format!("{table} first"), a));
            out.push((format!("{table} second"), b));
        }
    }
    out
}

#[test]
fn a_backup_is_a_private_file_holding_ciphertext_only() {
    let (f, v) = KitFixture::create();
    // What an interrupted backup left is removed.
    std::fs::write(f.paths.backups_dir.join(".vault-x.ecbackup.tmp"), b"x").unwrap();
    let info = v.create_backup().unwrap();
    let kit_env = v
        .unlockers()
        .find(|e| e.kind() == UnlockerKind::RecoveryKit)
        .unwrap()
        .to_bytes();
    drop(v);

    assert_eq!(only_backup(&f).file_name(), info.path.file_name());
    let name = info.path.file_name().unwrap().to_str().unwrap();
    assert!(name.starts_with("vault-") && name.ends_with(&format!(".{BACKUP_EXTENSION}")));
    // vault-YYYYMMDDTHHMMSSZ-xxxxxxxx.ecbackup
    assert_eq!(
        name.len(),
        "vault-".len() + 16 + 1 + 8 + 1 + BACKUP_EXTENSION.len()
    );
    let meta = std::fs::metadata(&info.path).unwrap();
    assert_eq!(
        std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o777,
        0o600
    );
    assert_eq!(info.bytes, meta.len());
    assert_eq!(info.items, 5, "one item per stored canary");

    let bytes = std::fs::read(&info.path).unwrap();
    assert_no_canary(&bytes, &f.cs);
    // Only the kit envelope is readable, byte for byte; the passphrase
    // envelope, the database's magic, slugs and every stored column are
    // not there.
    assert_eq!(&bytes[..4], b"ECBK");
    assert_eq!(bytes[43], 1, "one envelope");
    assert_eq!(
        &bytes[HEADER_FIXED..HEADER_FIXED + Envelope::LEN],
        &kit_env[..]
    );
    let contains = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
    assert!(!contains(b"SQLite format 3"));
    // No slug, title, env hint or project path. Each needle is 10 bytes or
    // more: in about 60 KB of ciphertext a chance match of one is out of
    // reach, where a 3-byte needle would match about once in 270 backups.
    let mut needles: Vec<Vec<u8>> = vec![b"t4-project".to_vec(), b"/src/acme-web".to_vec()];
    for c in &f.cs {
        needles.push(canary_slug(&c.label).as_str().as_bytes().to_vec());
        needles.push(format!("fixture {}", c.label).into_bytes());
        needles.push(c.label.as_bytes().to_vec());
    }
    for needle in &needles {
        assert!(needle.len() >= 10, "{}", String::from_utf8_lossy(needle));
        assert!(
            !contains(needle),
            "{} is in the backup",
            String::from_utf8_lossy(needle)
        );
    }
    for (what, blob) in stored_blobs(&f) {
        if blob[..] == kit_env[..] || blob.len() < 16 {
            continue;
        }
        assert!(!contains(&blob), "{what} is in the backup");
    }
    f.home.assert_clean(&f.cs);
}

/// A vault large enough for several chunks: `n` items with a 60 KB value
/// each, besides the canaries.
fn big_vault() -> (KitFixture, envcloak_core::vault::Vault) {
    let (f, mut v) = KitFixture::create();
    let mut rng = Rng(f.seed);
    v.transact(|t| {
        for i in 0..45 {
            let item = t.create_item(secret_item(&format!("bulk/item-{i}")))?;
            t.add_field(
                item,
                name("blob"),
                SecretBytes::copy_from(&rng.text(60_000)),
            )?;
        }
        Ok(())
    })
    .unwrap();
    (f, v)
}

/// Every change to a backup is refused: nothing is restored, the current
/// vault is untouched, and no temporary file is left.
#[test]
fn every_change_to_a_backup_is_refused_and_changes_nothing() {
    let (f, v) = big_vault();
    let a = v.create_backup().unwrap();
    let b = v.create_backup().unwrap();
    let items: Vec<ItemMeta> = v.items().to_vec();
    drop(v);
    let good = std::fs::read(&a.path).unwrap();
    let other = std::fs::read(&b.path).unwrap();
    let (header, recs) = records(&good);
    assert!(recs.len() >= 4, "a manifest and at least three chunks");
    assert_eq!(recs[1].1, 4 + BACKUP_CHUNK + 40, "full chunks");
    let (_, other_recs) = records(&other);
    let db_before = std::fs::read(f.db()).unwrap();
    let files_before = dir_names(&f.paths.vault_dir);

    let rec = |i: usize| &good[recs[i].0..recs[i].0 + recs[i].1];
    let mut cases: Vec<(String, Vec<u8>)> = Vec::new();
    let flips = [
        ("magic", 0),
        ("format version", 4),
        ("vault id", 5),
        ("schema version", 21),
        ("epoch", 25),
        ("backup id", 27),
        ("envelope count", 43),
        ("envelope memory", HEADER_FIXED + 29),
        ("envelope salt", HEADER_FIXED + 40),
        ("envelope commitment", HEADER_FIXED + 90),
        ("envelope sealed key", HEADER_FIXED + 120),
        ("manifest length", recs[0].0 + 3),
        ("manifest nonce", recs[0].0 + 4),
        ("manifest body", recs[0].0 + 60),
        ("manifest tag", recs[0].0 + recs[0].1 - 1),
        ("chunk length", recs[1].0 + 2),
        ("chunk nonce", recs[2].0 + 10),
        ("chunk body", recs[2].0 + 5000),
        ("last chunk tag", good.len() - 1),
    ];
    for (what, at) in flips {
        let mut m = good.clone();
        m[at] ^= 0x04;
        cases.push((format!("flip {what}"), m));
    }
    for (what, len) in [
        ("empty", 0),
        ("magic only", 4),
        ("header only", header),
        ("mid manifest", recs[0].0 + 50),
        ("manifest only", recs[1].0),
        ("mid chunk", recs[2].0 + 1000),
        ("last chunk dropped", recs[recs.len() - 1].0),
        ("last byte dropped", good.len() - 1),
    ] {
        cases.push((format!("truncated: {what}"), good[..len].to_vec()));
    }
    cases.push(("one byte appended".into(), [&good[..], &[0]].concat()));
    cases.push((
        "last record repeated".into(),
        [&good[..], rec(recs.len() - 1)].concat(),
    ));
    let mut swapped = good[..recs[1].0].to_vec();
    swapped.extend_from_slice(rec(2));
    swapped.extend_from_slice(rec(1));
    swapped.extend_from_slice(&good[recs[3].0..]);
    cases.push(("chunks 1 and 2 swapped".into(), swapped));
    let mut dropped = good[..recs[2].0].to_vec();
    dropped.extend_from_slice(&good[recs[3].0..]);
    cases.push(("middle chunk dropped".into(), dropped));
    let mut foreign = good[..recs[2].0].to_vec();
    foreign.extend_from_slice(&other[other_recs[2].0..other_recs[2].0 + other_recs[2].1]);
    foreign.extend_from_slice(&good[recs[3].0..]);
    cases.push(("chunk from another backup".into(), foreign));
    let mut foreign_manifest = good[..recs[0].0].to_vec();
    foreign_manifest.extend_from_slice(&other[other_recs[0].0..other_recs[1].0]);
    foreign_manifest.extend_from_slice(&good[recs[1].0..]);
    cases.push(("manifest from another backup".into(), foreign_manifest));
    let mut other_header = other[..header].to_vec();
    other_header.extend_from_slice(&good[header..]);
    cases.push(("header from another backup".into(), other_header));

    let bad = f.home.root().join("bad.ecbackup");
    for (what, bytes) in &cases {
        std::fs::write(&bad, bytes).unwrap();
        let e = restore_backup(&f.paths, &bad, &f.kit(), &other_passphrase(1)).unwrap_err();
        assert!(
            matches!(
                e.kind(),
                VaultErrorKind::BackupDamaged
                    | VaultErrorKind::UnsupportedVersion
                    | VaultErrorKind::Crypto(CryptoErrorKind::Unlock)
            ),
            "{what}: {:?}",
            e.kind()
        );
        assert_eq!(std::fs::read(f.db()).unwrap(), db_before, "{what}");
        assert_eq!(dir_names(&f.paths.vault_dir), files_before, "{what}");
    }

    // Control: the untouched copy restores.
    std::fs::write(&bad, &good).unwrap();
    let (v, _) = restore_backup(&f.paths, &bad, &f.kit(), &other_passphrase(1)).unwrap();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_eq!(v.items(), &items[..]);
    assert_holds_canaries(&v, &f.cs);
    drop(v);
    f.home.assert_clean(&f.cs);
}

/// A vault file changed behind the open vault is never backed up; the
/// vault turns read-only. A vault that failed its check at unlock is not
/// backed up either.
#[test]
fn a_changed_or_tampered_vault_is_not_backed_up() {
    let (f, v) = KitFixture::create();
    let field = v.items()[0].fields[0].id;
    drop(v);
    let raw = rusqlite::Connection::open(f.db()).unwrap();
    let sealed: Vec<u8> = raw
        .query_row(
            "SELECT sealed_value FROM fields WHERE id = ?1",
            [&field.as_bytes()[..]],
            |r| r.get(0),
        )
        .unwrap();
    drop(raw);

    let v = f.unlock();
    // Another program flips a byte of the file while the vault is open.
    {
        use std::os::unix::fs::FileExt;
        let bytes = std::fs::read(f.db()).unwrap();
        let at = bytes
            .windows(sealed.len())
            .position(|w| w == &sealed[..])
            .unwrap()
            + 30;
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(f.db())
            .unwrap();
        file.write_at(&[bytes[at] ^ 0x10], at as u64).unwrap();
        file.sync_all().unwrap();
    }
    let e = v.create_backup().unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::Tampered);
    assert_eq!(
        v.integrity(),
        Integrity::Tampered(TamperKind::ChangedWhileOpen)
    );
    assert!(dir_names(&f.paths.backups_dir).is_empty());
    drop(v);

    let v = f.unlock();
    assert!(matches!(v.integrity(), Integrity::Tampered(_)));
    assert_eq!(
        v.create_backup().unwrap_err().kind(),
        VaultErrorKind::Tampered
    );
    assert!(dir_names(&f.paths.backups_dir).is_empty());
}

/// A vault file whose structure is damaged behind the open vault (its
/// SQLite header overwritten) cannot be read into a verified image: the
/// backup is refused, and the vault turns read-only as for any other
/// change found while open, instead of staying trusted (F-23).
#[test]
fn a_structurally_damaged_vault_is_not_backed_up() {
    let (f, v) = KitFixture::create();
    drop(v);
    let v = f.unlock();
    assert_eq!(v.integrity(), Integrity::Ok);
    {
        use std::os::unix::fs::FileExt;
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(f.db())
            .unwrap();
        file.write_all_at(&[0u8; 16], 0).unwrap();
        file.sync_all().unwrap();
    }
    let e = v.create_backup().unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::Tampered);
    assert_eq!(
        v.integrity(),
        Integrity::Tampered(TamperKind::ChangedWhileOpen)
    );
    assert_eq!(v.header().unwrap_err().kind(), VaultErrorKind::Tampered);
    assert!(v.policies().is_err() && v.projects().is_err());
    assert!(dir_names(&f.paths.backups_dir).is_empty());
}

#[test]
fn a_vault_without_a_kit_is_not_backed_up() {
    let (f, v) = Fixture::create();
    assert_eq!(
        v.create_backup().unwrap_err().kind(),
        VaultErrorKind::NoRecoveryKit
    );
    assert!(dir_names(&f.paths.backups_dir).is_empty());
}

/// Gate 3 for restore: the new passphrase envelope has the current
/// defaults and a fresh salt, although the backed-up vault's envelopes had
/// the minimum; the kit envelope is carried over unchanged.
#[test]
fn a_restore_wraps_the_new_passphrase_with_the_current_defaults() {
    let (f, v) = KitFixture::create();
    let info = v.create_backup().unwrap();
    let old_pass = v
        .unlockers()
        .find(|e| e.kind() == UnlockerKind::Passphrase)
        .unwrap()
        .clone();
    let kit = v
        .unlockers()
        .find(|e| e.kind() == UnlockerKind::RecoveryKit)
        .unwrap()
        .clone();
    drop(v);
    let (v, _) = restore_backup(&f.paths, &info.path, &f.kit(), &other_passphrase(2)).unwrap();
    let pass: Vec<&Envelope> = v
        .unlockers()
        .filter(|e| e.kind() == UnlockerKind::Passphrase)
        .collect();
    let [pass] = &pass[..] else {
        panic!("one passphrase envelope");
    };
    let k = pass.kdf();
    assert_eq!(
        (k.m_kib(), k.t(), k.p()),
        (
            KdfParams::DEFAULT_M_KIB,
            KdfParams::DEFAULT_T,
            KdfParams::DEFAULT_P
        )
    );
    assert_eq!(old_pass.kdf().m_kib(), KdfParams::MIN_M_KIB);
    assert_ne!(k.salt(), old_pass.kdf().salt());
    assert_eq!(pass.unlocker_id(), old_pass.unlocker_id());
    let kits: Vec<&Envelope> = v
        .unlockers()
        .filter(|e| e.kind() == UnlockerKind::RecoveryKit)
        .collect();
    assert!(kits.len() == 1 && *kits[0] == kit);
}

#[test]
fn a_restore_refuses_an_open_vault_or_a_weak_passphrase_first() {
    let (f, v) = KitFixture::create();
    let info = v.create_backup().unwrap();
    drop(v);
    let db_before = std::fs::read(f.db()).unwrap();

    let held = f.open();
    let e = restore_backup(&f.paths, &info.path, &f.kit(), &other_passphrase(3)).unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::Busy);
    drop(held);

    let e = restore_backup(
        &f.paths,
        &info.path,
        &f.kit(),
        &SecretBytes::copy_from(b"too short"),
    )
    .unwrap_err();
    assert_eq!(
        e.kind(),
        VaultErrorKind::Passphrase(PassphraseRejected::TooShort)
    );
    assert_eq!(std::fs::read(f.db()).unwrap(), db_before);
    assert_eq!(dir_names(&f.paths.vault_dir), ["vault.db"]);
}

/// The backup path is opened without following a symlink or blocking on a
/// FIFO; only a regular file is read.
#[test]
fn a_restore_reads_only_a_regular_backup_file() {
    let (f, v) = KitFixture::create();
    let info = v.create_backup().unwrap();
    drop(v);
    let root = f.home.root();
    let link = root.join("link.ecbackup");
    std::os::unix::fs::symlink(&info.path, &link).unwrap();
    let fifo = root.join("fifo.ecbackup");
    let made = std::process::Command::new("/usr/bin/mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(made.success());
    let cases: [(&Path, VaultErrorKind); 4] = [
        (&link, VaultErrorKind::Path(PathErrorKind::Symlink)),
        (&fifo, VaultErrorKind::Path(PathErrorKind::NotFile)),
        (root, VaultErrorKind::Path(PathErrorKind::NotFile)),
        (
            &root.join("missing"),
            VaultErrorKind::Io(std::io::ErrorKind::NotFound),
        ),
    ];
    for (path, want) in cases {
        let e = restore_backup(&f.paths, path, &f.kit(), &other_passphrase(4)).unwrap_err();
        assert_eq!(e.kind(), want, "{}", path.display());
    }
    assert_eq!(dir_names(&f.paths.vault_dir), ["vault.db"]);
}

/// A file at `vault.db` that is not a vault, with a side file, is moved
/// aside whole, and the restore proceeds.
#[test]
fn a_restore_moves_aside_a_file_that_is_not_a_vault() {
    let (f, v) = KitFixture::create();
    let info = v.create_backup().unwrap();
    let items: Vec<ItemMeta> = v.items().to_vec();
    drop(v);
    std::fs::write(f.db(), b"not a database at all").unwrap();
    let wal = f.db().with_file_name("vault.db-wal");
    std::fs::write(&wal, b"not a wal").unwrap();

    let (v, report) = restore_backup(&f.paths, &info.path, &f.kit(), &other_passphrase(5)).unwrap();
    assert_eq!(v.items(), &items[..]);
    drop(v);
    let [kept, kept_wal] = &report.replaced[..] else {
        panic!("{:?}", report.replaced);
    };
    assert_eq!(std::fs::read(kept).unwrap(), b"not a database at all");
    assert_eq!(kept_wal.as_os_str(), &*format!("{}-wal", kept.display()));
    assert_eq!(std::fs::read(kept_wal).unwrap(), b"not a wal");
    let kept_name = kept.file_name().unwrap().to_str().unwrap().to_owned();
    assert_eq!(
        dir_names(&f.paths.vault_dir),
        [
            kept_name.clone(),
            format!("{kept_name}-wal"),
            "vault.db".into()
        ]
    );
}

/// A WAL, shared-memory file or journal left beside a missing `vault.db`
/// (a daemon killed before a checkpoint, then `vault.db` deleted) is moved
/// aside and kept, never replayed onto the restored vault, whether it was
/// written for the same vault or for another one.
#[test]
fn a_restore_moves_aside_side_files_left_without_a_vault() {
    let (f, mut v) = KitFixture::create();
    let info = v.create_backup().unwrap();
    let items: Vec<ItemMeta> = v.items().to_vec();
    let same = later_wal(&mut v, &f.db());
    drop(v);
    let (g, mut w) = KitFixture::create();
    let other = later_wal(&mut w, &g.db());
    drop(w);

    let db = f.db();
    let side = |suffix: &str| db.with_file_name(format!("vault.db{suffix}"));
    for (what, wal) in [("same vault", &same), ("another vault", &other)] {
        std::fs::remove_file(&db).unwrap();
        std::fs::write(side("-wal"), wal).unwrap();
        std::fs::write(side("-shm"), b"stale shared memory").unwrap();
        std::fs::write(side("-journal"), b"stale journal").unwrap();
        let mut before = dir_names(&f.paths.vault_dir);
        before.retain(|n| !n.starts_with("vault.db"));

        let (v, report) =
            restore_backup(&f.paths, &info.path, &f.kit(), &other_passphrase(1)).unwrap();
        assert_eq!(v.integrity(), Integrity::Ok, "{what}");
        assert_eq!(v.items(), &items[..], "{what}");
        assert_holds_canaries(&v, &f.cs);
        drop(v);

        let [wal_kept, shm_kept, journal_kept] = &report.replaced[..] else {
            panic!("{what}: {:?}", report.replaced);
        };
        let kept = |p: &Path, suffix: &str| {
            let n = p.file_name().unwrap().to_str().unwrap().to_owned();
            assert!(
                n.starts_with("replaced-") && n.ends_with(suffix),
                "{what}: {n}"
            );
            assert_eq!(p.parent(), db.parent(), "{what}");
            n
        };
        let mut want = before.clone();
        want.push(kept(wal_kept, ".db-wal"));
        want.push(kept(shm_kept, ".db-shm"));
        want.push(kept(journal_kept, ".db-journal"));
        want.push("vault.db".into());
        want.sort();
        assert_eq!(dir_names(&f.paths.vault_dir), want, "{what}");
        assert_eq!(std::fs::read(wal_kept).unwrap(), *wal, "{what}");
        assert_eq!(std::fs::read(shm_kept).unwrap(), b"stale shared memory");
        assert_eq!(std::fs::read(journal_kept).unwrap(), b"stale journal");

        let v = f.unlock();
        assert_eq!(v.integrity(), Integrity::Ok, "{what}: reopened");
        assert_eq!(v.items(), &items[..], "{what}: reopened");
    }
    f.home.assert_clean(&f.cs);
}

/// Should something put a WAL beside `vault.db` after the restore cleared
/// the way, the installed vault no longer verifies. The restore then says
/// so rather than hand back a vault it did not check, the replaced vault is
/// still kept aside, and a second restore puts a verified vault in place.
#[test]
fn a_restore_fails_when_the_installed_vault_does_not_verify() {
    let (f, mut v) = KitFixture::create();
    let info = v.create_backup().unwrap();
    let items: Vec<ItemMeta> = v.items().to_vec();
    let wal = later_wal(&mut v, &f.db());
    drop(v);
    let old = std::fs::read(f.db()).unwrap();
    let wal_path = f.db().with_file_name("vault.db-wal");

    let e = restore_backup_observed(
        &f.paths,
        &info.path,
        &f.kit(),
        &other_passphrase(2),
        &KdfParams::minimum(),
        &mut |s| {
            if s == RestoreStep::OldVaultKept {
                std::fs::write(&wal_path, &wal).unwrap();
            }
        },
    )
    .unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::RestoreUnverified);
    let kept: Vec<String> = dir_names(&f.paths.vault_dir)
        .into_iter()
        .filter(|n| n.starts_with("replaced-"))
        .collect();
    let [kept] = &kept[..] else {
        panic!("{kept:?}");
    };
    assert_eq!(
        std::fs::read(f.paths.vault_dir.join(kept)).unwrap(),
        old,
        "the replaced vault is kept"
    );
    // What is in place now does not verify (or does not open at all).
    if let Ok(Ok(v)) = LockedVault::open(&f.paths).map(|l| l.unlock(f.vmk())) {
        assert_ne!(v.integrity(), Integrity::Ok);
    }

    let (v, report) = restore_backup(&f.paths, &info.path, &f.kit(), &other_passphrase(3)).unwrap();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_eq!(v.items(), &items[..]);
    assert_eq!(report.replaced.len(), 1, "{:?}", report.replaced);
    drop(v);
    assert_eq!(f.unlock().integrity(), Integrity::Ok);
}

/// Review T4 open 1: a restore closes the vault it replaces with that
/// vault's WAL folded in, and checks it. The vault here is what a daemon
/// killed before a checkpoint leaves: `vault.db` and a WAL whose frames
/// hold its newest items. When the close leaves that WAL beside
/// `vault.db` (its checkpoint skipped, as when SQLite's own fails), the
/// restore stops before anything is moved: set aside, the WAL would leave
/// `vault.db` without those items until the new file is in place, and a
/// crash in between would leave an older state that still verifies. The
/// vault is then as it was, WAL and all. Without the fault, the replaced
/// vault is folded in before it is kept aside, whole, with no WAL beside
/// it.
#[test]
fn a_restore_never_sets_a_wal_aside_from_its_vault() {
    let (f, mut v) = KitFixture::create();
    let info = v.create_backup().unwrap();
    let wal = later_wal(&mut v, &f.db());
    let db = std::fs::read(f.db()).unwrap();
    let latest: Vec<ItemMeta> = v.items().to_vec();
    drop(v);
    let wal_path = f.db().with_file_name("vault.db-wal");
    let crashed = || {
        std::fs::write(f.db(), &db).unwrap();
        std::fs::write(&wal_path, &wal).unwrap();
    };

    crashed();
    skip_next_close_checkpoint_for_testing();
    let e = restore_backup(&f.paths, &info.path, &f.kit(), &other_passphrase(6)).unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::Storage(5), "SQLITE_BUSY");
    assert_eq!(
        dir_names(&f.paths.vault_dir),
        ["vault.db", "vault.db-wal"],
        "nothing moved"
    );
    let v = f.unlock();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_eq!(v.items(), &latest[..], "the newest items are there");
    drop(v);

    crashed();
    let (v, report) = restore_backup(&f.paths, &info.path, &f.kit(), &other_passphrase(7)).unwrap();
    assert_eq!(v.integrity(), Integrity::Ok);
    drop(v);
    let [kept] = &report.replaced[..] else {
        panic!("{:?}", report.replaced);
    };
    let aside = VaultPaths::under(f.home.root().join("aside"));
    aside.ensure_dirs().unwrap();
    std::fs::copy(kept, aside.vault_dir.join("vault.db")).unwrap();
    let v = LockedVault::open(&aside)
        .unwrap()
        .unlock(f.vmk())
        .map_err(|(_, e)| e)
        .unwrap();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_eq!(v.items(), &latest[..], "the kept file alone holds them");
    drop(v);
    f.home.assert_clean(&f.cs);
}

/// Review T14 open 1: a backup restores only its own vault. Over a vault
/// with another id, a valid backup that opens with its own kit is refused
/// before anything is written or moved, and the vault in place is as it
/// was. Where no vault exists (story S11) the same backup restores.
#[test]
fn a_backup_of_another_vault_is_refused_over_a_vault() {
    let (f, v) = KitFixture::create();
    let items: Vec<ItemMeta> = v.items().to_vec();
    drop(v);
    let (g, w) = KitFixture::create();
    let other = w.create_backup().unwrap();
    let other_id = w.vault_id();
    drop(w);
    let before = std::fs::read(f.db()).unwrap();

    let e = restore_backup(&f.paths, &other.path, &g.kit(), &other_passphrase(8)).unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::BackupOfAnotherVault);
    assert_eq!(dir_names(&f.paths.vault_dir), ["vault.db"]);
    assert_eq!(std::fs::read(f.db()).unwrap(), before);
    let v = f.unlock();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_eq!(v.items(), &items[..]);
    assert_holds_canaries(&v, &f.cs);
    drop(v);

    std::fs::remove_file(f.db()).unwrap();
    let (v, report) =
        restore_backup(&f.paths, &other.path, &g.kit(), &other_passphrase(8)).unwrap();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_eq!(v.vault_id(), other_id);
    assert!(report.replaced.is_empty());
}

/// Verification of 5ff68c7: a vault in place that opens as damaged is
/// compared by the vault ids its `meta`, `header` and `unlockers` rows
/// still hold. With any one of those tables gone, the others name the
/// vault, and another vault's valid backup is refused before anything is
/// moved, the file byte for byte as it was. A file whose rows hold no id
/// (all three tables gone) names no vault: it is moved aside byte for byte,
/// as a file that is not a vault is, and the backup restores. The vault's
/// own backup over it restores in `a_restore_moves_aside_a_vault_missing_a_table`.
#[test]
fn a_backup_of_another_vault_is_refused_over_a_damaged_vault() {
    let (f, v) = KitFixture::create();
    drop(v);
    let (g, w) = KitFixture::create();
    let other = w.create_backup().unwrap();
    let other_id = w.vault_id();
    drop(w);
    let intact = std::fs::read(f.db()).unwrap();
    assert_eq!(dir_names(&f.paths.vault_dir), ["vault.db"]);
    let without = |tables: &[&str]| {
        std::fs::write(f.db(), &intact).unwrap();
        let raw = rusqlite::Connection::open(f.db()).unwrap();
        for table in tables {
            raw.execute_batch(&format!("DROP TABLE {table}")).unwrap();
        }
        raw.close().unwrap();
        assert_eq!(
            LockedVault::open(&f.paths).unwrap_err().kind(),
            VaultErrorKind::Damaged,
            "{tables:?}"
        );
        std::fs::read(f.db()).unwrap()
    };
    let restore = || {
        restore_backup_observed(
            &f.paths,
            &other.path,
            &g.kit(),
            &other_passphrase(8),
            &KdfParams::minimum(),
            &mut |_| {},
        )
    };

    for table in ["meta", "header", "unlockers"] {
        let damaged = without(&[table]);
        let e = restore().unwrap_err();
        assert_eq!(e.kind(), VaultErrorKind::BackupOfAnotherVault, "{table}");
        assert_eq!(dir_names(&f.paths.vault_dir), ["vault.db"], "{table}");
        assert_eq!(std::fs::read(f.db()).unwrap(), damaged, "{table}");
    }

    let nameless = without(&["meta", "header", "unlockers"]);
    let (v, report) = restore().unwrap();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_eq!(v.vault_id(), other_id);
    drop(v);
    let [kept] = &report.replaced[..] else {
        panic!("{:?}", report.replaced);
    };
    assert_eq!(std::fs::read(kept).unwrap(), nameless);
    remove_replaced_files(&f.paths).unwrap();
}

/// Opens the vault with `pass`: Ok, or the generic unlock error.
fn opens_with(f: &KitFixture, pass: &SecretBytes) -> bool {
    match f.open().unlock_with_passphrase(pass) {
        Ok(v) => v.integrity() == Integrity::Ok,
        Err((_, e)) => {
            assert_eq!(e.kind(), VaultErrorKind::Crypto(CryptoErrorKind::Unlock));
            false
        }
    }
}

/// The installed vault must be the state the restore prepared, not merely
/// one that verifies (F-24). A WAL the same vault wrote after a passphrase
/// change is coherent: replayed onto the installed file, it gives a vault
/// that verifies under the VMK but holds another passphrase envelope, and
/// in the second case other items. Planted after the way was cleared, it
/// makes the restore fail with `RestoreUnverified`, where it used to report
/// the backup's items and a passphrase that no longer opens the vault. A
/// second restore then installs the backup, and its report counts the
/// items the installed vault holds.
#[test]
fn a_restore_fails_when_another_valid_state_is_installed() {
    let (f, mut v) = KitFixture::create();
    let info = v.create_backup().unwrap();
    let items: Vec<ItemMeta> = v.items().to_vec();
    let later_pass = other_passphrase(77);
    v.change_passphrase_for_testing(&later_pass, &KdfParams::minimum())
        .unwrap();
    let pass_only = std::fs::read(f.db().with_file_name("vault.db-wal")).unwrap();
    let pass_and_items = later_wal(&mut v, &f.db());
    let later_items: Vec<ItemMeta> = v.items().to_vec();
    assert_eq!(later_items.len(), items.len() + 20);
    drop(v);
    let wal_path = f.db().with_file_name("vault.db-wal");

    let cases = [
        ("a passphrase change", &pass_only, &items),
        (
            "a passphrase change and more items",
            &pass_and_items,
            &later_items,
        ),
    ];
    for (n, (what, wal, planted_items)) in (10u64..).zip(cases) {
        let requested = other_passphrase(n);
        let e = restore_backup_observed(
            &f.paths,
            &info.path,
            &f.kit(),
            &requested,
            &KdfParams::minimum(),
            &mut |s| {
                if s == RestoreStep::OldVaultKept {
                    std::fs::write(&wal_path, wal).unwrap();
                }
            },
        )
        .unwrap_err();
        assert_eq!(e.kind(), VaultErrorKind::RestoreUnverified, "{what}");

        // What is in place verifies: only the comparison with the prepared
        // state can have caught it.
        let v = f.unlock();
        assert_eq!(v.integrity(), Integrity::Ok, "{what}");
        assert_eq!(v.items(), &planted_items[..], "{what}");
        drop(v);
        assert!(!opens_with(&f, &requested), "{what}");
        assert!(opens_with(&f, &later_pass), "{what}");
    }

    let requested = other_passphrase(3);
    let (v, report) = restore_backup_observed(
        &f.paths,
        &info.path,
        &f.kit(),
        &requested,
        &KdfParams::minimum(),
        &mut |_| {},
    )
    .unwrap();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_eq!(v.items(), &items[..]);
    assert_eq!(report.items, items.len());
    assert_holds_canaries(&v, &f.cs);
    drop(v);
    assert!(opens_with(&f, &requested));
    assert!(!opens_with(&f, &later_pass));
    f.home.assert_clean(&f.cs);
}

/// A file with the vault's magic and application id that is missing a
/// table SQLite reads before unlock is damaged, not a storage failure: it
/// opens with `Damaged`, and a restore moves it aside, byte for byte, and
/// installs the backup.
#[test]
fn a_restore_moves_aside_a_vault_missing_a_table() {
    let (f, v) = KitFixture::create();
    let info = v.create_backup().unwrap();
    let items: Vec<ItemMeta> = v.items().to_vec();
    drop(v);
    for (n, table) in (20u64..).zip(["meta", "header", "unlockers"]) {
        let raw = rusqlite::Connection::open(f.db()).unwrap();
        raw.execute_batch(&format!("DROP TABLE {table}")).unwrap();
        raw.close().unwrap();
        let damaged = std::fs::read(f.db()).unwrap();
        assert_eq!(
            LockedVault::open(&f.paths).unwrap_err().kind(),
            VaultErrorKind::Damaged,
            "{table}"
        );

        let (v, report) = restore_backup_observed(
            &f.paths,
            &info.path,
            &f.kit(),
            &other_passphrase(n),
            &KdfParams::minimum(),
            &mut |_| {},
        )
        .unwrap();
        assert_eq!(v.integrity(), Integrity::Ok, "{table}");
        assert_eq!(v.items(), &items[..], "{table}");
        drop(v);
        let [kept] = &report.replaced[..] else {
            panic!("{table}: {:?}", report.replaced);
        };
        assert_eq!(std::fs::read(kept).unwrap(), damaged, "{table}");
        assert_eq!(f.unlock().integrity(), Integrity::Ok, "{table}");
        remove_replaced_files(&f.paths).unwrap();
    }
    f.home.assert_clean(&f.cs);
}

fn no_change(_: &MigrationTx<'_>) -> Result<(), VaultError> {
    Ok(())
}

/// The shipped plan and a step to schema version 3 that only adds a
/// table.
fn to_v3() -> MigrationPlan {
    MigrationPlan::new(vec![Migration {
        from: 2,
        ddl: "CREATE TABLE notes (id BLOB PRIMARY KEY NOT NULL) STRICT;",
        transform: no_change,
    }])
    .unwrap()
}

/// A backup of an older format restores with a build that migrates it
/// (F-22): the image is checked against its manifest as it was backed up,
/// then migrated, and the restored vault verifies at the new version.
#[test]
fn an_older_format_backup_restores_and_is_migrated() {
    let (f, v) = KitFixture::create();
    let info = v.create_backup().unwrap();
    let items: Vec<ItemMeta> = v.items().to_vec();
    assert_eq!(v.schema_version(), 2);
    drop(v);

    let new = other_passphrase(8);
    let (v, report) = restore_backup_with_plan(
        &f.paths,
        &info.path,
        &f.kit(),
        &new,
        &KdfParams::minimum(),
        to_v3(),
    )
    .unwrap();
    assert_eq!(v.schema_version(), 3);
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_eq!(v.items(), &items[..]);
    assert_holds_canaries(&v, &f.cs);
    assert_eq!(report.backup_write_counter, info.write_counter);
    drop(v);

    let v = LockedVault::open_with_plan(&f.paths, to_v3())
        .unwrap()
        .unlock_with_passphrase(&new)
        .map_err(|(_, e)| e)
        .unwrap();
    assert_eq!(v.schema_version(), 3);
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_holds_canaries(&v, &f.cs);
    drop(v);
    // This build, which knows version 2 at most, refuses the newer file.
    assert_eq!(
        LockedVault::open(&f.paths).unwrap_err().kind(),
        VaultErrorKind::UnsupportedVersion
    );
    f.home.assert_clean(&f.cs);
}

/// The replaced vault is kept whole until it is deleted: it still opens
/// with the old passphrase and, being the same vault, gives the restored
/// vault's key, which is why callers offer to delete it. `replaced_files`
/// lists what a restore kept (regular files only) and
/// `remove_replaced_files` deletes it, leaving the restored vault.
#[test]
fn a_replaced_vault_is_kept_until_removed() {
    let (f, v) = KitFixture::create();
    let info = v.create_backup().unwrap();
    drop(v);
    assert!(replaced_files(&f.paths).unwrap().is_empty());
    std::fs::create_dir(f.paths.vault_dir.join("replaced-not-a-file")).unwrap();
    let new = other_passphrase(4);
    let (v, report) = restore_backup(&f.paths, &info.path, &f.kit(), &new).unwrap();
    let restored_key = v.vmk().export_for_testing();
    drop(v);
    let [kept] = &report.replaced[..] else {
        panic!("{:?}", report.replaced);
    };
    assert_eq!(replaced_files(&f.paths).unwrap(), report.replaced);

    // A copy of the kept file opens with the old passphrase and holds the
    // restored vault's key.
    let elsewhere = VaultPaths::under(f.home.root().join("elsewhere"));
    elsewhere.ensure_dirs().unwrap();
    let copy = std::fs::canonicalize(&elsewhere.vault_dir)
        .unwrap()
        .join("vault.db");
    std::fs::copy(kept, copy).unwrap();
    let old = LockedVault::open(&elsewhere)
        .unwrap()
        .unlock_with_passphrase(&f.pass())
        .map_err(|(_, e)| e)
        .unwrap();
    assert_eq!(old.integrity(), Integrity::Ok);
    assert!(old.vmk().export_for_testing() == restored_key);
    drop(old);

    assert_eq!(remove_replaced_files(&f.paths).unwrap(), report.replaced);
    assert!(replaced_files(&f.paths).unwrap().is_empty());
    assert_eq!(
        dir_names(&f.paths.vault_dir),
        ["replaced-not-a-file", "vault.db"]
    );
    let v = f
        .open()
        .unlock_with_passphrase(&new)
        .map_err(|(_, e)| e)
        .unwrap();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_holds_canaries(&v, &f.cs);
    drop(v);
    f.home.assert_clean(&f.cs);
}

/// A restored vault can be backed up and restored again.
#[test]
fn a_restored_vault_backs_up_and_restores_again() {
    let (f, v) = KitFixture::create();
    let first = v.create_backup().unwrap();
    let items: Vec<ItemMeta> = v.items().to_vec();
    drop(v);
    let (v, _) = restore_backup(&f.paths, &first.path, &f.kit(), &other_passphrase(6)).unwrap();
    let second = v.create_backup().unwrap();
    assert_ne!(second.backup_id, first.backup_id);
    drop(v);
    let (v, report) =
        restore_backup(&f.paths, &second.path, &f.kit(), &other_passphrase(7)).unwrap();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_eq!(v.items(), &items[..]);
    assert_eq!(report.backup_write_counter, first.write_counter + 1);
    drop(v);
    let v = LockedVault::open(&f.paths)
        .unwrap()
        .unlock_with_passphrase(&other_passphrase(7))
        .map_err(|(_, e)| e)
        .unwrap();
    assert_holds_canaries(&v, &f.cs);
    f.home.assert_clean(&f.cs);
}

/// A vault backup is made durable through `envcloak_sys::sync_file`
/// (`F_FULLFSYNC` on macOS), in order, and a flush that fails fails the
/// backup (verifier, M2-05 round 9: with the error of the last flush
/// ignored, every test still passed, and `envcloak rm` removes an item on
/// the strength of the answer): a backup flushes the data directory's
/// parent and the data directory (the directories the vault's paths make
/// sure of), its file, then `backups/` once the file is linked to its
/// name (the counting shim records each by device and inode). With the
/// file's flush failing, the backup fails; with the last one, `backups/`,
/// failing, it fails too, the backup linked by then.
#[test]
fn a_vault_backup_is_flushed_in_order_and_a_failed_flush_fails_it() {
    use envcloak_sys::testing::{fail_sync_after, record_syncs, take_synced};
    use std::os::unix::fs::MetadataExt;
    let id_of = |p: &Path| {
        let m = std::fs::metadata(p).unwrap();
        (m.dev(), m.ino())
    };
    let (f, v) = KitFixture::create();
    let backups = f.paths.backups_dir.clone();
    record_syncs();
    let info = v.create_backup().unwrap();
    assert_eq!(
        take_synced(),
        [
            id_of(f.paths.data_dir.parent().unwrap()),
            id_of(&f.paths.data_dir),
            id_of(&info.path),
            id_of(&backups)
        ],
        "a backup's flushes: the data directory's parent and itself, the file, then backups/"
    );
    let before = dir_names(&backups).len();

    fail_sync_after(2);
    assert!(
        v.create_backup().is_err(),
        "the failed flush of a backup's file was unreported"
    );
    fail_sync_after(3);
    assert!(
        v.create_backup().is_err(),
        "the failed flush of backups/ was unreported"
    );
    assert_eq!(
        dir_names(&backups).len(),
        before + 1,
        "the backup whose last flush failed is linked, the other is not: {:?}",
        dir_names(&backups)
    );
    drop(v);
    f.home.assert_clean(&f.cs);
}
