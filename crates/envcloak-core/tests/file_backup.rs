//! Encrypted backups of deleted files (SPEC §6.4 "Backups"; the format is
//! in docs/VAULT.md "File backups"): a backup holds ciphertext only and
//! gives the files back byte for byte; any change to it is refused, as is
//! a backup of another vault; it is purged after 7 days, and so is what an
//! interrupted backup left under its staging name. Also the vault
//! pieces import rests on: checking the Recovery Kit without a write, and
//! the keys that compare values without holding them.
#![allow(clippy::unwrap_used)]

mod common;

use common::{KitFixture, dir_names};
use envcloak_core::crypto::CryptoErrorKind;
use envcloak_core::file_backup::{
    BackupFile, FILE_BACKUP_RETENTION, FileBackupCreator, FileBackupId, FileLeft, MAX_BACKUP_BYTES,
    MAX_BACKUP_FILES, STAGING_GRACE, age_file_backup_for_testing, purge_file_backups,
};
use envcloak_core::file_backup_v2::CreatorKind;
use envcloak_core::vault::VaultErrorKind;
use envcloak_core::{RecoveryKit, SecretBytes};
use envcloak_testkit::{assert_no_canary, by_label, labels};

/// Two files with the fixture values in them: what `init` backs up.
fn files(f: &KitFixture) -> (Vec<Vec<u8>>, Vec<BackupFile>) {
    let key = by_label(&f.cs, labels::OPENAI_API_KEY).as_str();
    let url = by_label(&f.cs, labels::DATABASE_URL).as_str();
    let short = by_label(&f.cs, labels::SHORT_TOKEN).as_str();
    let raw = vec![
        format!("OPENAI_API_KEY={key}\nDATABASE_URL='{url}'\nPORT=8080\n").into_bytes(),
        // Not UTF-8, CRLF, no final newline: bytes are bytes.
        [
            b"SHORT_TOKEN=".as_slice(),
            short.as_bytes(),
            b"\r\n\xff\xfe",
        ]
        .concat(),
    ];
    let backup = vec![
        BackupFile {
            path: "/p/acme-web/.env".into(),
            mode: 0o600,
            content: SecretBytes::copy_from(&raw[0]),
            left: Some(FileLeft::Rewritten([0x5a; 32])),
        },
        BackupFile {
            path: "/p/acme-web/.env.short".into(),
            mode: 0o644,
            content: SecretBytes::copy_from(&raw[1]),
            left: Some(FileLeft::Removed),
        },
    ];
    (raw, backup)
}

/// Who the daemon says made a backup: an agent, so a test sees that it
/// comes back.
fn creator() -> FileBackupCreator {
    FileBackupCreator {
        kind: CreatorKind::Agent,
        agent: Some("Codex".to_owned()),
    }
}

fn only_file(dir: &std::path::Path) -> std::path::PathBuf {
    let names: Vec<String> = dir_names(dir)
        .into_iter()
        .filter(|n| n.starts_with("files-"))
        .collect();
    let [n] = &names[..] else { panic!("{names:?}") };
    dir.join(n)
}

#[test]
fn a_backup_gives_the_files_back_byte_for_byte_and_holds_ciphertext_only() {
    let (f, v) = KitFixture::create();
    let (raw, backup) = files(&f);
    let info = v.backup_files(&backup, &creator()).unwrap();
    assert_eq!(info.files, 2);
    let path = only_file(&f.paths.backups_dir);
    assert_eq!(path.file_name(), info.path.file_name());
    let name = path.file_name().unwrap().to_str().unwrap();
    assert!(name.ends_with(&format!("-{}.ecfiles", info.id)), "{name}");
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(bytes.len() as u64, info.bytes);
    // No fixture and no path: the file is ciphertext but for its header.
    assert_no_canary(&bytes, &f.cs);
    assert!(
        !bytes.windows(8).any(|w| w == b"acme-web"),
        "a path is in plaintext"
    );
    let mode = std::os::unix::fs::MetadataExt::mode(&std::fs::metadata(&path).unwrap());
    assert_eq!(mode & 0o777, 0o600);
    // No temporary file is left.
    assert_eq!(dir_names(&f.paths.backups_dir).len(), 1);

    let back = v.open_file_backup(&info.id).unwrap();
    assert_eq!(back.creator, Some(creator()));
    assert_eq!(v.file_backup_creator(&info.id).unwrap(), Some(creator()));
    let back = back.files;
    assert_eq!(back.len(), 2);
    for (b, (want, orig)) in back.iter().zip(raw.iter().zip(&backup)) {
        assert!(b.content.ct_eq(want));
        assert_eq!(b.path, orig.path);
        assert_eq!(b.mode, orig.mode);
        assert_eq!(b.left, orig.left);
    }
    // After the vault locks and unlocks, with the id as text.
    drop(v);
    let v = f.unlock();
    let id = FileBackupId::parse(&info.id.to_string()).unwrap();
    assert!(
        v.open_file_backup(&id).unwrap().files[1]
            .content
            .ct_eq(&raw[1])
    );
}

#[test]
fn any_change_to_a_backup_is_refused() {
    let (f, v) = KitFixture::create();
    let (_, backup) = files(&f);
    let info = v.backup_files(&backup, &creator()).unwrap();
    let good = std::fs::read(&info.path).unwrap();
    let damaged = |bytes: &[u8]| {
        std::fs::write(&info.path, bytes).unwrap();
        let e = v.open_file_backup(&info.id).unwrap_err();
        std::fs::write(&info.path, &good).unwrap();
        e.kind()
    };
    // Every byte, flipped: the header's id is part of the file's name and
    // of every record's associated data, so a flip anywhere fails.
    for i in 0..good.len() {
        let mut b = good.clone();
        b[i] ^= 0x01;
        let k = damaged(&b);
        assert!(
            matches!(k, VaultErrorKind::BackupDamaged),
            "byte {i}: {k:?}"
        );
    }
    for cut in [0, 1, 50, good.len() / 2, good.len() - 1] {
        assert_eq!(
            damaged(&good[..cut]),
            VaultErrorKind::BackupDamaged,
            "{cut}"
        );
    }
    let mut longer = good.clone();
    longer.push(0);
    assert_eq!(damaged(&longer), VaultErrorKind::BackupDamaged);
    assert_eq!(v.open_file_backup(&info.id).unwrap().files.len(), 2);
}

#[test]
fn another_vault_cannot_open_a_backup_and_an_unknown_id_is_not_found() {
    let (f, v) = KitFixture::create();
    let (_, backup) = files(&f);
    let info = v.backup_files(&backup, &creator()).unwrap();
    let (g, w) = KitFixture::create();
    let copy = g.paths.backups_dir.join(info.path.file_name().unwrap());
    std::fs::create_dir_all(&g.paths.backups_dir).unwrap();
    std::fs::copy(&info.path, &copy).unwrap();
    let e = w.open_file_backup(&info.id).unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::BackupDamaged);
    let e = v.open_file_backup(&FileBackupId([9; 16])).unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::NotFound);
}

#[test]
fn backups_are_purged_after_seven_days() {
    let (f, v) = KitFixture::create();
    let (_, backup) = files(&f);
    let old = v.backup_files(&backup, &creator()).unwrap();
    let new = v.backup_files(&backup, &creator()).unwrap();
    let now = old.created_at;
    assert_eq!(purge_file_backups(&f.paths, now).unwrap(), 0);
    let week = FILE_BACKUP_RETENTION.as_secs();
    age_file_backup_for_testing(&old.path, now - week - 1).unwrap();
    // At exactly seven days it stays; a second later it goes.
    assert_eq!(purge_file_backups(&f.paths, now - 1).unwrap(), 0);
    assert_eq!(purge_file_backups(&f.paths, now).unwrap(), 1);
    assert!(!old.path.exists());
    assert!(new.path.exists());
    assert_eq!(v.open_file_backup(&new.id).unwrap().files.len(), 2);
    assert_eq!(
        v.open_file_backup(&old.id).unwrap_err().kind(),
        VaultErrorKind::NotFound
    );
    // Vault backups are not file backups, and stay.
    let vault_backup = v.create_backup().unwrap();
    assert_eq!(purge_file_backups(&f.paths, u64::MAX).unwrap(), 1);
    assert!(vault_backup.path.exists());
}

#[test]
fn a_backup_has_limits() {
    let (_f, v) = KitFixture::create();
    let one = |path: &str, len: usize| BackupFile {
        path: path.into(),
        mode: 0o600,
        content: SecretBytes::copy_from(&vec![b'x'; len]),
        left: None,
    };
    let kind = |files: &[BackupFile]| v.backup_files(files, &creator()).unwrap_err().kind();
    assert_eq!(kind(&[]), VaultErrorKind::InvalidRecord);
    assert_eq!(kind(&[one("", 1)]), VaultErrorKind::InvalidRecord);
    assert_eq!(
        kind(&[one(&"p".repeat(4097), 1)]),
        VaultErrorKind::InvalidRecord
    );
    let many: Vec<BackupFile> = (0..=MAX_BACKUP_FILES)
        .map(|i| one(&format!("/p/{i}"), 1))
        .collect();
    assert_eq!(kind(&many), VaultErrorKind::TooLarge);
    assert_eq!(
        kind(&[one("/a", MAX_BACKUP_BYTES), one("/b", 1)]),
        VaultErrorKind::TooLarge
    );
    // At the limits it is written; an empty file is kept too.
    v.backup_files(&[one("/a", MAX_BACKUP_BYTES)], &creator())
        .unwrap();
    let back = v.backup_files(&[one("/empty", 0)], &creator()).unwrap();
    assert!(
        v.open_file_backup(&back.id).unwrap().files[0]
            .content
            .is_empty()
    );
}

#[test]
fn the_recovery_kit_is_checked_without_a_write() {
    let (f, v) = KitFixture::create();
    v.verify_recovery_kit(&f.kit()).unwrap();
    assert!(!v.recovery_confirmed().unwrap());
    let wrong = RecoveryKit::generate();
    let e = v.verify_recovery_kit(&wrong).unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::Crypto(CryptoErrorKind::Unlock));
}

#[test]
fn value_keys_compare_values_without_holding_them() {
    let (f, v) = KitFixture::create();
    let a = SecretBytes::copy_from(by_label(&f.cs, labels::OPENAI_API_KEY).value());
    let b = SecretBytes::copy_from(by_label(&f.cs, labels::OPENAI_API_KEY).value());
    let c = SecretBytes::copy_from(by_label(&f.cs, labels::GITHUB_TOKEN).value());
    assert_eq!(v.value_key(&a), v.value_key(&b));
    assert_ne!(v.value_key(&a), v.value_key(&c));
    assert_eq!(format!("{:?}", v.value_key(&a)), "ValueKey(..)");
    // Keyed: another vault's key for the same value differs.
    let (_g, w) = KitFixture::create();
    assert_ne!(v.value_key(&a), w.value_key(&a));
}

/// Review finding F-52 (Codex): an interrupted backup leaves its staging
/// file, `.files-<time>-<id>.ecfiles.tmp`, complete or partial. A purge
/// removes one unchanged for an hour, keeps a fresh one (a backup being
/// written) and never follows a symlink of that name; published backups
/// keep their own rule.
#[test]
fn staging_files_an_interrupted_backup_left_are_purged() {
    let (f, v) = KitFixture::create();
    let (_, backup) = files(&f);
    let kept = v.backup_files(&backup, &creator()).unwrap();
    let dir = kept.path.parent().unwrap().to_owned();
    let bytes = std::fs::read(&kept.path).unwrap();
    let now = std::time::SystemTime::now();
    let secs = now.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let stage = |name: &str, body: &[u8], ago: std::time::Duration| {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&p)
            .unwrap()
            .set_modified(now - ago)
            .unwrap();
        p
    };
    let hour = STAGING_GRACE + std::time::Duration::from_secs(60);
    // Complete (a whole backup, never linked into place) and partial.
    let complete = stage(".files-20260901T000000Z-A.ecfiles.tmp", &bytes, hour);
    let partial = stage(".files-20260901T000000Z-B.ecfiles.tmp", &bytes[..40], hour);
    let fresh = stage(
        ".files-20260901T000000Z-C.ecfiles.tmp",
        &bytes[..40],
        std::time::Duration::from_secs(5),
    );
    let target = stage("elsewhere", b"not a backup", hour);
    let link = dir.join(".files-20260901T000000Z-D.ecfiles.tmp");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert_eq!(purge_file_backups(&f.paths, secs).unwrap(), 2);
    assert!(!complete.exists() && !partial.exists());
    assert!(fresh.exists());
    assert!(link.symlink_metadata().is_ok() && target.exists());
    assert!(kept.path.exists());
    assert_eq!(v.open_file_backup(&kept.id).unwrap().files.len(), 2);
    // A week on, the published backup goes too, and the fresh staging
    // file is old by then.
    let week = FILE_BACKUP_RETENTION.as_secs() + 2 * STAGING_GRACE.as_secs();
    assert_eq!(purge_file_backups(&f.paths, secs + week).unwrap(), 2);
    assert!(!kept.path.exists() && !fresh.exists());
}

/// Nothing outside the vault's own `backups/` is listed, read, written or
/// removed when `backups/` itself, or the data directory that holds it,
/// is replaced by a symlink to a private directory of this user's
/// elsewhere holding backup-shaped files (L-11; the class of the backups
/// v2 finding of the M2-05 review): `backups/` is opened through the data
/// directory, never through a symlink in place of either, and every file
/// is listed, opened, linked and removed through that handle. With the
/// real `backups/` (an expired backup, a fresh one, a stale staging file)
/// moved away and a symlink to it in its place, a purge, an open and a
/// new backup each fail (`Path(Symlink)`) and every file in the moved
/// directory stays as it was; the same with the data directory replaced.
/// Once both are back, the purge removes the expired backup and the
/// staging file, and the fresh backup opens.
#[test]
fn a_symlink_in_place_of_backups_or_the_data_directory_is_never_followed() {
    use envcloak_core::vault::{PathErrorKind, Vault, VaultError};
    let (f, v) = KitFixture::create();
    let (_, backup) = files(&f);
    let old = v.backup_files(&backup, &creator()).unwrap();
    let fresh = v.backup_files(&backup, &creator()).unwrap();
    let now = fresh.created_at;
    let week = FILE_BACKUP_RETENTION.as_secs();
    age_file_backup_for_testing(&old.path, now - week - 1).unwrap();
    let backups = f.paths.backups_dir.clone();
    let stale = backups.join(".files-20260901T000000Z-A.ecfiles.tmp");
    std::fs::write(&stale, b"sealed bytes only").unwrap();
    std::fs::File::options()
        .write(true)
        .open(&stale)
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(now - week))
        .unwrap();
    // Each call's error kind, or `None` when it went through.
    let every_call = |v: &Vault| {
        let kind = |r: Result<(), VaultError>| r.err().map(|e| e.kind());
        vec![
            ("purge", kind(purge_file_backups(&f.paths, now).map(drop))),
            ("open", kind(v.open_file_backup(&fresh.id).map(drop))),
            (
                "backup",
                kind(v.backup_files(&backup, &creator()).map(drop)),
            ),
        ]
    };
    let refused = |got: Vec<(&str, Option<VaultErrorKind>)>| {
        for (call, kind) in got {
            assert_eq!(
                kind,
                Some(VaultErrorKind::Path(PathErrorKind::Symlink)),
                "{call} through a symlink"
            );
        }
    };

    let before = common::tree(&backups);
    let elsewhere = f.home.root().join("elsewhere");
    std::fs::rename(&backups, &elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &backups).unwrap();
    let got = every_call(&v);
    assert_eq!(
        common::tree(&elsewhere),
        before,
        "a call through a symlink in place of backups/ changed what it points at"
    );
    refused(got);
    std::fs::remove_file(&backups).unwrap();
    std::fs::rename(&elsewhere, &backups).unwrap();

    let data_elsewhere = f.home.root().join("data-elsewhere");
    std::fs::rename(&f.paths.data_dir, &data_elsewhere).unwrap();
    std::os::unix::fs::symlink(&data_elsewhere, &f.paths.data_dir).unwrap();
    let got = every_call(&v);
    assert_eq!(
        common::tree(&data_elsewhere.join("backups")),
        before,
        "a call through a symlink in place of the data directory changed what it points at"
    );
    refused(got);
    std::fs::remove_file(&f.paths.data_dir).unwrap();
    std::fs::rename(&data_elsewhere, &f.paths.data_dir).unwrap();

    assert_eq!(purge_file_backups(&f.paths, now).unwrap(), 2);
    assert!(!old.path.exists() && !stale.exists());
    assert_eq!(dir_names(&backups).len(), 1);
    assert_eq!(v.open_file_backup(&fresh.id).unwrap().files.len(), 2);
}

/// A file backup is made durable through `envcloak_sys::sync_file`
/// (`F_FULLFSYNC` on macOS), in order, and a flush that fails fails its
/// step (the class of the backups v2 flush findings of the M2-05 review):
/// a backup flushes, after the directories the vault's paths make sure of
/// (the data directory's parent and the data directory), its file, then
/// `backups/` once it is linked to its name (the counting shim records
/// each by device and inode); with the
/// file's flush failing, the backup fails and nothing is left in
/// `backups/`; with the directory's failing, it fails with the backup in
/// place. A purge flushes `backups/` once its files went, and a failed
/// flush fails it.
#[test]
fn a_file_backup_is_flushed_in_order_and_a_failed_flush_fails_its_step() {
    use envcloak_sys::testing::{fail_sync_after, record_syncs, take_synced};
    use std::os::unix::fs::MetadataExt;
    let id_of = |p: &std::path::Path| {
        let m = std::fs::metadata(p).unwrap();
        (m.dev(), m.ino())
    };
    let (f, v) = KitFixture::create();
    let (_, backup) = files(&f);
    let backups = f.paths.backups_dir.clone();
    record_syncs();
    let info = v.backup_files(&backup, &creator()).unwrap();
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

    fail_sync_after(2);
    assert!(
        v.backup_files(&backup, &creator()).is_err(),
        "the failed flush of a backup's file was unreported"
    );
    assert_eq!(dir_names(&backups).len(), 1, "{:?}", dir_names(&backups));
    fail_sync_after(3);
    assert!(
        v.backup_files(&backup, &creator()).is_err(),
        "the failed flush of backups/ was unreported"
    );
    assert_eq!(dir_names(&backups).len(), 2, "the backup linked before");

    let later = info.created_at + FILE_BACKUP_RETENTION.as_secs() + 60;
    fail_sync_after(0);
    assert!(
        purge_file_backups(&f.paths, later).is_err(),
        "the failed flush of a purge's removals was unreported"
    );
    assert!(dir_names(&backups).is_empty());
}
