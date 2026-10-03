//! Gate 6 (SPEC §15.2): deleting a row, or restoring one row from an older
//! copy, makes unlock report tampering and open read-only. Every table is
//! covered, `meta` and the header included, on a fresh open and on the
//! handle `lock` keeps, also with a session's pages in the WAL. Also:
//! altered plaintext columns, moved ciphertext, an altered schema, an
//! empty vault without its header, a row or prior list changed in the file
//! while the vault is open, the documented whole-file rollback limit, file
//! modes, and the digest's cost at 10,000 rows.
#![allow(clippy::unwrap_used)]

mod common;

use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::{PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Instant;

use common::{Fixture, copy_dir, name, secret_item, slug};
use envcloak_core::SecretBytes;
use envcloak_core::crypto::{
    Argon2id, EnvelopeCtx, KdfParams, UnlockerId, UnlockerKind, Vmk, wrap_vmk_with,
};
use envcloak_core::vault::{
    FieldId, INITIAL_EPOCH, Integrity, ItemDetails, LockedVault, PolicyId, ProjectKey,
    ProjectRecord, TamperKind, Vault, VaultErrorKind,
};

/// This build's SQLite keeps one page cache for every connection in the
/// process (`SQLITE_ENABLE_MEMORY_MANAGEMENT`), so one test's connections,
/// unlocks and writes can drop the pages another test's vault has cached.
/// The tests that change the file behind an open or locked vault check
/// what happens while those pages are still cached, so each runs
/// [`alone`]; every other test runs [`beside`] the others.
static SERIAL: RwLock<()> = RwLock::new(());

fn alone() -> RwLockWriteGuard<'static, ()> {
    SERIAL.write().unwrap_or_else(PoisonError::into_inner)
}

fn beside() -> RwLockReadGuard<'static, ()> {
    SERIAL.read().unwrap_or_else(PoisonError::into_inner)
}

/// A closed vault with two items (three fields), a project, a policy and
/// two unlockers, and a copy of its directory to restore between cases.
struct Pristine {
    f: Fixture,
    snapshot: std::path::PathBuf,
    keep: FieldId,
    other: FieldId,
}

const KEEP: &[u8] = b"value that stays readable";

fn pristine() -> Pristine {
    let (f, mut v) = Fixture::create();
    let vmk = f.vmk();
    let kit = wrap_vmk_with(
        &vmk,
        &SecretBytes::copy_from(b"kit stand-in"),
        UnlockerKind::RecoveryKit,
        &EnvelopeCtx {
            vault_id: f.vault_id,
            unlocker_id: UnlockerId::generate(),
            epoch: INITIAL_EPOCH,
        },
        &KdfParams::minimum(),
        &Argon2id,
    )
    .unwrap();
    let (keep, other) = v
        .transact(|t| {
            let a = t.create_item(secret_item("a/keep"))?;
            let keep = t.add_field(a, name("value"), SecretBytes::copy_from(KEEP))?;
            let b = t.create_item(secret_item("b/other"))?;
            let other = t.add_field(b, name("value"), SecretBytes::copy_from(b"other value"))?;
            t.add_field(b, name("second"), SecretBytes::copy_from(b"second value"))?;
            t.upsert_project(project(1))?;
            t.put_policy(PolicyId::generate(), &common::standing_record(1))?;
            t.add_unlocker(kit)?;
            Ok((keep, other))
        })
        .unwrap();
    drop(v);
    let snapshot = f.home.root().join("pristine");
    assert_closed(&f);
    copy_dir(&f.paths.vault_dir, &snapshot);
    Pristine {
        f,
        snapshot,
        keep,
        other,
    }
}

fn project(last_seen: u64) -> ProjectRecord {
    ProjectRecord {
        key: ProjectKey::new(b"dev-and-inode").unwrap(),
        display_path: "/src/acme-web".into(),
        manifest_sha256: [3; 32],
        bindings: Vec::new(),
        last_seen,
    }
}

/// A closed vault is one file: the WAL was checkpointed and removed.
fn assert_closed(f: &Fixture) {
    let names: Vec<String> = std::fs::read_dir(&f.paths.vault_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["vault.db"]);
}

impl Pristine {
    fn restore(&self) {
        std::fs::copy(self.snapshot.join("vault.db"), self.f.db()).unwrap();
    }

    /// Restores the pristine vault, runs `sql` on it through a plain
    /// SQLite connection, and unlocks it.
    fn tampered(&self, sql: &str) -> Vault {
        self.tampered_by(|raw| raw.execute_batch(sql).unwrap())
    }

    fn tampered_by(&self, f: impl FnOnce(&rusqlite::Connection)) -> Vault {
        self.restore();
        let raw = self.f.raw();
        f(&raw);
        drop(raw);
        self.f.unlock()
    }
}

/// Flips one bit of byte `at` of a blob column (`select` names the one
/// row's column; `update` writes `?1` back to it).
fn flip_bit(raw: &rusqlite::Connection, select: &str, update: &str, at: usize) {
    let mut b: Vec<u8> = raw.query_row(select, [], |r| r.get(0)).unwrap();
    b[at] ^= 0x10;
    assert_eq!(raw.execute(update, [b]).unwrap(), 1);
}

/// Swaps a blob column between the rows with ids `a` and `b`. Both
/// originals are read first and written back crosswise as bound
/// parameters (a correlated UPDATE would see its own first write), through
/// a placeholder so a UNIQUE column never holds a duplicate. Then checks
/// that each row holds the other's original.
fn swap_blobs(raw: &rusqlite::Connection, table: &str, col: &str, a: &[u8], b: &[u8]) {
    let get = |id: &[u8]| -> Vec<u8> {
        raw.query_row(
            &format!("SELECT {col} FROM {table} WHERE id = ?1"),
            [id],
            |r| r.get(0),
        )
        .unwrap()
    };
    let set = |id: &[u8], v: &[u8]| {
        let sql = format!("UPDATE {table} SET {col} = ?1 WHERE id = ?2");
        assert_eq!(raw.execute(&sql, rusqlite::params![v, id]).unwrap(), 1);
    };
    let (va, vb) = (get(a), get(b));
    assert_ne!(va, vb);
    set(a, b"swap placeholder, never a real value");
    set(b, &va);
    set(a, &vb);
    assert_eq!((get(a), get(b)), (vb, va), "{table}.{col} was not swapped");
}

/// The vault opened read-only with `want` (or any kind when `None`), still
/// serves the untouched value, refuses writes, and serves nothing a grant
/// or policy decision could rest on: no policies, project records or
/// header.
fn assert_read_only(mut v: Vault, want: Option<TamperKind>, keep: Option<FieldId>, case: &str) {
    match (v.integrity(), want) {
        (Integrity::Tampered(got), Some(want)) => assert_eq!(got, want, "{case}"),
        (Integrity::Tampered(_), None) => {}
        (Integrity::Ok, _) => panic!("{case}: tampering was not detected"),
    }
    if let Some(keep) = keep {
        assert!(v.read_value(keep).unwrap().ct_eq(KEEP), "{case}");
    }
    let untrusted = |r: Result<(), envcloak_core::vault::VaultError>| {
        assert_eq!(r.unwrap_err().kind(), VaultErrorKind::Tampered, "{case}");
    };
    untrusted(v.policies().map(drop));
    untrusted(v.projects().map(drop));
    untrusted(v.find_project(&project(1).key).map(drop));
    untrusted(v.header().map(drop));
    let e = v
        .transact(|t| t.create_item(secret_item("new/item")))
        .unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::ReadOnly, "{case}");
}

fn hex(id: &[u8]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn deleting_any_row_opens_read_only() {
    let _serial = beside();
    let p = pristine();
    // The pristine copy itself verifies.
    p.restore();
    assert_eq!(p.f.unlock().integrity(), Integrity::Ok);

    let other_item = {
        p.restore();
        let v = p.f.unlock();
        hex(v.find(&slug("b/other")).unwrap().id.as_bytes())
    };
    let cases = [
        (
            "an item row and its fields",
            format!(
                "DELETE FROM fields WHERE item_id = x'{other_item}'; DELETE FROM items WHERE id = x'{other_item}';"
            ),
        ),
        (
            "an item row alone",
            format!("DELETE FROM items WHERE id = x'{other_item}';"),
        ),
        (
            "a field row",
            format!(
                "DELETE FROM fields WHERE id = x'{}';",
                hex(p.other.as_bytes())
            ),
        ),
        ("the project row", "DELETE FROM projects;".to_owned()),
        ("the policy row", "DELETE FROM policies;".to_owned()),
        (
            "an unlocker row",
            "DELETE FROM unlockers WHERE rowid = (SELECT max(rowid) FROM unlockers);".to_owned(),
        ),
    ];
    for (case, sql) in cases {
        let v = p.tampered(&sql);
        assert_read_only(v, None, Some(p.keep), case);
    }
    // The deleted field is gone from the read-only view; the vault did not
    // invent it back.
    let v = p.tampered(&format!(
        "DELETE FROM fields WHERE id = x'{}';",
        hex(p.other.as_bytes())
    ));
    assert_eq!(
        v.integrity(),
        Integrity::Tampered(TamperKind::DigestMismatch)
    );
    assert_eq!(
        v.read_value(p.other).unwrap_err().kind(),
        VaultErrorKind::UnknownField
    );
}

#[test]
fn restoring_one_row_from_an_older_copy_opens_read_only() {
    let _serial = beside();
    let p = pristine();
    let old = p.snapshot.join("vault.db");
    // Move every kind of row one version on, then close.
    p.restore();
    let mut v = p.f.unlock();
    let vmk = p.f.vmk();
    let first_unlocker = v.unlockers().next().unwrap().unlocker_id();
    let replaced = wrap_vmk_with(
        &vmk,
        &SecretBytes::copy_from(b"a new passphrase"),
        UnlockerKind::Passphrase,
        &EnvelopeCtx {
            vault_id: p.f.vault_id,
            unlocker_id: first_unlocker,
            epoch: INITIAL_EPOCH,
        },
        &KdfParams::minimum(),
        &Argon2id,
    )
    .unwrap();
    let item = v.find(&slug("b/other")).unwrap().id;
    let policy = v.policies().unwrap().next().unwrap().0;
    v.transact(|t| {
        t.set_value(p.other, SecretBytes::copy_from(b"rotated value"))?;
        t.update_item(
            item,
            ItemDetails {
                title: "renamed".into(),
                ..ItemDetails::default()
            },
        )?;
        t.upsert_project(project(2))?;
        t.put_policy(policy, &common::standing_record(2))?;
        t.replace_unlocker(replaced)
    })
    .unwrap();
    drop(v);
    assert_eq!(p.f.unlock().integrity(), Integrity::Ok);
    let current = p.f.home.root().join("current.db");
    std::fs::copy(p.f.db(), &current).unwrap();

    let cases: [(&str, &str, &str); 6] = [
        (
            "a field row",
            "fields",
            "id, item_id, row_version, sealed_name, sealed_value, value_hash, sealed_prior",
        ),
        (
            "an item row",
            "items",
            "id, row_version, class, slug_hash, sealed_meta, updated_at",
        ),
        (
            "the project row",
            "projects",
            "id, row_version, dir_hash, sealed",
        ),
        ("the policy row", "policies", "id, row_version, sealed"),
        (
            "an unlocker row",
            "unlockers",
            "id, vault_id, kind, envelope, created_at",
        ),
        (
            "the header row alone",
            "header",
            "epoch, vault_id, schema_version, sealed",
        ),
    ];
    for (case, table, cols) in cases {
        // Start from the current file and put back one table's older rows
        // (each table here has exactly the rows that changed, plus rows
        // that did not, which are identical in both copies).
        std::fs::copy(&current, p.f.db()).unwrap();
        let raw = p.f.raw();
        raw.execute("ATTACH DATABASE ?1 AS old", [old.to_str().unwrap()])
            .unwrap();
        raw.execute_batch(&format!(
            "DELETE FROM main.{table}; INSERT INTO main.{table} ({cols}) SELECT {cols} FROM old.{table};"
        ))
        .unwrap();
        raw.execute("DETACH DATABASE old", []).unwrap();
        drop(raw);
        let v = p.f.unlock();
        if table == "fields" {
            // The rolled-back row is internally consistent and opens: only
            // the digest catches it.
            assert!(v.read_value(p.other).unwrap().ct_eq(b"other value"));
        }
        assert_read_only(v, Some(TamperKind::DigestMismatch), Some(p.keep), case);
    }
}

#[test]
fn altered_plaintext_columns_or_moved_ciphertext_open_read_only() {
    let _serial = beside();
    let p = pristine();
    let (a, b) = {
        p.restore();
        let v = p.f.unlock();
        (
            hex(v.find(&slug("a/keep")).unwrap().id.as_bytes()),
            hex(v.find(&slug("b/other")).unwrap().id.as_bytes()),
        )
    };
    let other = hex(p.other.as_bytes());
    // (case, SQL, the finding expected first, whether `a/keep`'s value
    // stays readable)
    let cases = [
        (
            "items.updated_at",
            "UPDATE items SET updated_at = updated_at + 1;".to_owned(),
            Some(TamperKind::DigestMismatch),
            true,
        ),
        (
            "items.class",
            format!("UPDATE items SET class = 3 WHERE id = x'{b}';"),
            Some(TamperKind::RowUnreadable),
            true,
        ),
        (
            "fields.value_hash",
            format!("UPDATE fields SET value_hash = zeroblob(32) WHERE id = x'{other}';"),
            Some(TamperKind::DigestMismatch),
            true,
        ),
        (
            "fields.item_id moved to another item",
            format!("UPDATE fields SET item_id = x'{a}' WHERE item_id = x'{b}' AND id != x'{other}';"),
            Some(TamperKind::DigestMismatch),
            true,
        ),
        (
            "fields.item_id moved onto a field of the same name",
            format!("UPDATE fields SET item_id = x'{a}' WHERE id = x'{other}';"),
            Some(TamperKind::RowInconsistent),
            true,
        ),
        (
            "unlockers.created_at",
            "UPDATE unlockers SET created_at = created_at + 1;".to_owned(),
            Some(TamperKind::DigestMismatch),
            true,
        ),
        (
            "projects.dir_hash",
            "UPDATE projects SET dir_hash = zeroblob(32);".to_owned(),
            Some(TamperKind::RowInconsistent),
            true,
        ),
        (
            "a row copied under a new id",
            "INSERT INTO policies SELECT x'00112233445566778899aabbccddeeff', row_version, sealed FROM policies;"
                .to_owned(),
            Some(TamperKind::RowUnreadable),
            true,
        ),
    ];
    for (case, sql, want, keep_readable) in cases {
        let v = p.tampered(&sql);
        assert_read_only(v, want, keep_readable.then_some(p.keep), case);
    }

    // Columns swapped between two rows (review finding F-20: read both originals
    // first, never a correlated UPDATE).
    let (a_id, b_id) = (unhex(&a), unhex(&b));
    let (keep_id, other_id) = (p.keep.as_bytes().to_vec(), p.other.as_bytes().to_vec());
    let v = p.tampered_by(|raw| swap_blobs(raw, "items", "slug_hash", &a_id, &b_id));
    assert_read_only(
        v,
        Some(TamperKind::RowInconsistent),
        None,
        "slug_hash swapped",
    );
    let v = p.tampered_by(|raw| swap_blobs(raw, "items", "sealed_meta", &a_id, &b_id));
    assert_read_only(
        v,
        Some(TamperKind::RowUnreadable),
        None,
        "item metadata swapped",
    );
    let v = p.tampered_by(|raw| swap_blobs(raw, "fields", "sealed_value", &keep_id, &other_id));
    // A value moved to another row does not open there, in either row.
    for id in [p.keep, p.other] {
        assert_eq!(
            v.read_value(id).unwrap_err().kind(),
            VaultErrorKind::Tampered
        );
    }
    assert_read_only(
        v,
        Some(TamperKind::DigestMismatch),
        None,
        "sealed values swapped",
    );

    // One flipped bit in a nonce, the ciphertext or the tag of a field
    // name, which unlock opens.
    for at in [3, 30, 60] {
        let v = p.tampered_by(|raw| {
            flip_bit(
                raw,
                &format!("SELECT sealed_name FROM fields WHERE id = x'{other}'"),
                &format!("UPDATE fields SET sealed_name = ?1 WHERE id = x'{other}'"),
                at,
            );
        });
        assert_read_only(
            v,
            Some(TamperKind::RowUnreadable),
            Some(p.keep),
            "a flipped bit",
        );
    }
}

#[test]
fn an_altered_schema_or_header_opens_read_only() {
    let _serial = beside();
    let p = pristine();
    for (case, sql, want) in [
        (
            "a trigger",
            "CREATE TRIGGER t AFTER INSERT ON items BEGIN SELECT 1; END;",
            TamperKind::SchemaAltered,
        ),
        (
            "a view",
            "CREATE VIEW v AS SELECT id FROM items;",
            TamperKind::SchemaAltered,
        ),
        (
            "a table",
            "CREATE TABLE extra (x BLOB);",
            TamperKind::SchemaAltered,
        ),
        (
            "an index",
            "CREATE INDEX extra_idx ON fields (value_hash);",
            TamperKind::SchemaAltered,
        ),
        (
            "a deleted header",
            "DELETE FROM header;",
            TamperKind::HeaderUnreadable,
        ),
        (
            "a second header",
            "INSERT INTO header SELECT * FROM header;",
            TamperKind::HeaderUnreadable,
        ),
    ] {
        let v = p.tampered(sql);
        assert_read_only(v, Some(want), Some(p.keep), case);
    }
    let v = p.tampered_by(|raw| {
        flip_bit(
            raw,
            "SELECT sealed FROM header",
            "UPDATE header SET sealed = ?1",
            40,
        );
    });
    assert_read_only(
        v,
        Some(TamperKind::HeaderUnreadable),
        Some(p.keep),
        "a damaged header",
    );
}

/// Gate 6 for the rows that name the vault: `meta` (its id and schema
/// version), the header's plaintext columns, and an unlocker's copy of the
/// vault id. Deleting, doubling or altering one of them opens read-only
/// like any other row. The passphrase still unlocks it: before unlock the
/// file reports the vault id, epoch and envelopes that the other rows agree
/// on (docs/VAULT.md "Unlock").
#[test]
fn the_rows_that_name_the_vault_are_covered_too() {
    let _serial = beside();
    let p = pristine();
    let cases = [
        (
            "the meta row deleted",
            "DELETE FROM meta;",
            TamperKind::MetaAltered,
        ),
        (
            "the meta row doubled",
            "INSERT INTO meta SELECT * FROM meta;",
            TamperKind::MetaAltered,
        ),
        (
            "meta.vault_id",
            "UPDATE meta SET vault_id = zeroblob(16);",
            TamperKind::MetaAltered,
        ),
        (
            "meta.schema_version newer than this build",
            "UPDATE meta SET schema_version = 7;",
            TamperKind::MetaAltered,
        ),
        (
            "meta.schema_version invalid",
            "UPDATE meta SET schema_version = 0;",
            TamperKind::MetaAltered,
        ),
        (
            "header.epoch",
            "UPDATE header SET epoch = epoch + 1;",
            TamperKind::RowInconsistent,
        ),
        (
            "header.vault_id",
            "UPDATE header SET vault_id = zeroblob(16);",
            TamperKind::RowInconsistent,
        ),
        (
            "header.schema_version",
            "UPDATE header SET schema_version = 7;",
            TamperKind::RowInconsistent,
        ),
        (
            "an unlocker's vault_id",
            "UPDATE unlockers SET vault_id = zeroblob(16) \
             WHERE rowid = (SELECT max(rowid) FROM unlockers);",
            TamperKind::RowInconsistent,
        ),
        (
            "the header deleted",
            "DELETE FROM header;",
            TamperKind::HeaderUnreadable,
        ),
        (
            "the header and the meta row deleted",
            "DELETE FROM header; DELETE FROM meta;",
            TamperKind::HeaderUnreadable,
        ),
    ];
    for (case, sql, want) in cases {
        p.restore();
        p.f.raw().execute_batch(sql).unwrap();
        let locked = LockedVault::open(&p.f.paths).unwrap();
        assert_eq!(locked.vault_id(), p.f.vault_id, "{case}");
        assert_eq!(locked.epoch(), INITIAL_EPOCH, "{case}");
        assert_eq!(locked.unlockers().unwrap().len(), 2, "{case}");
        drop(locked);
        let v = p.f.unlock_with_passphrase();
        assert_eq!(v.vault_id(), p.f.vault_id, "{case}");
        assert_eq!(v.schema_version(), 2, "{case}");
        assert_read_only(v, Some(want), Some(p.keep), case);
    }
}

/// An empty vault's only sealed row is its header. Deleting or doubling it
/// still opens read-only instead of passing for a wrong key, and a wrong key
/// is still refused whenever a header row is there.
#[test]
fn an_empty_vault_without_its_header_opens_read_only() {
    let _serial = beside();
    let (f, v) = Fixture::create();
    drop(v);
    let snapshot = f.home.root().join("empty");
    copy_dir(&f.paths.vault_dir, &snapshot);
    let tamper = |sql: &str| {
        std::fs::copy(snapshot.join("vault.db"), f.db()).unwrap();
        f.raw().execute_batch(sql).unwrap();
    };
    for (case, sql) in [
        ("header deleted", "DELETE FROM header;"),
        ("header doubled", "INSERT INTO header SELECT * FROM header;"),
    ] {
        tamper(sql);
        let v = f.unlock_with_passphrase();
        assert!(v.items().is_empty(), "{case}");
        assert_read_only(v, Some(TamperKind::HeaderUnreadable), None, case);
    }
    for sql in [
        "",
        "INSERT INTO header SELECT * FROM header;",
        "UPDATE header SET epoch = epoch + 1;",
    ] {
        tamper(sql);
        let (_, e) = LockedVault::open(&f.paths)
            .unwrap()
            .unlock(Vmk::generate())
            .unwrap_err();
        assert_eq!(e.kind(), VaultErrorKind::KeyMismatch, "{sql}");
    }
}

/// The stored `sealed_value` of `field`, read through a plain connection
/// while the vault is closed.
fn sealed_value_of(f: &Fixture, field: FieldId) -> Vec<u8> {
    f.raw()
        .query_row(
            "SELECT sealed_value FROM fields WHERE id = ?1",
            [&field.as_bytes()[..]],
            |r| r.get(0),
        )
        .unwrap()
}

/// Flips one bit inside the ciphertext of `sealed`, a column stored once in
/// the database file, with a plain write to the file. The vault's lock is
/// advisory, so another program can do this while the vault is open.
fn flip_on_disk(f: &Fixture, sealed: &[u8]) {
    use std::os::unix::fs::FileExt;
    let db = f.db();
    let bytes = std::fs::read(&db).unwrap();
    let hits: Vec<usize> = bytes
        .windows(sealed.len())
        .enumerate()
        .filter(|(_, w)| *w == sealed)
        .map(|(i, _)| i)
        .collect();
    let [at] = hits[..] else {
        panic!("the column is stored {} times in the file", hits.len());
    };
    // Past the 24-byte nonce: a ciphertext byte.
    let at = at + 30;
    let file = std::fs::OpenOptions::new().write(true).open(&db).unwrap();
    file.write_at(&[bytes[at] ^ 0x10], at as u64).unwrap();
    file.sync_all().unwrap();
}

/// The number of the database page that holds `sealed`, a column stored
/// once in the closed file.
fn page_of(f: &Fixture, sealed: &[u8]) -> usize {
    let bytes = std::fs::read(f.db()).unwrap();
    let page_size = usize::from(u16::from_be_bytes([bytes[16], bytes[17]]));
    let at = bytes
        .windows(sealed.len())
        .position(|w| w == sealed)
        .unwrap();
    at / page_size
}

/// Writes `sql`'s changes over `vault.db` while a vault holds it: copies
/// the file, runs `sql` on the copy through a plain connection, and writes
/// the result back into the same file, as another program can (the vault's
/// lock is advisory). Only `vault.db` is copied and rewritten: a page whose
/// newer copy is in the WAL is read from there, so a change shows only on
/// a page with no copy in the WAL (every page, when the vault has not
/// written since it was opened).
fn rewrite_on_disk(f: &Fixture, sql: &str) {
    let copy = f.home.root().join("rewrite.db");
    std::fs::copy(f.db(), &copy).unwrap();
    let raw = rusqlite::Connection::open(&copy).unwrap();
    raw.execute_batch(sql).unwrap();
    drop(raw);
    let bytes = std::fs::read(&copy).unwrap();
    std::fs::remove_file(&copy).unwrap();
    assert_ne!(bytes, std::fs::read(f.db()).unwrap(), "no change: {sql}");
    std::fs::write(f.db(), bytes).unwrap();
}

/// Gate 6 on the daemon's path (SPEC stories S9 and S10): `lock` keeps the
/// file open and locked, and the next unlock goes through the handle it
/// kept. A row deleted, restored from an older copy, or altered while the
/// vault was locked is reported at that unlock, as on a fresh open. SQLite
/// in exclusive locking mode never checks the file for such changes, so
/// this fails if unlock checks the pages it cached before the lock.
#[test]
fn unlocking_the_handle_kept_by_lock_reads_the_file_again() {
    let _serial = alone();
    let p = pristine();
    let unlock = |locked: LockedVault| locked.unlock(p.f.vmk()).map_err(|(_, e)| e).unwrap();
    // Opened and not written since, so the WAL is empty; then locked.
    let open_and_lock = || {
        let v = p.f.unlock();
        assert_eq!(v.integrity(), Integrity::Ok);
        v.policies().unwrap().for_each(drop);
        v.lock()
    };

    // Untouched, after a session's writes (the WAL holds pages), the kept
    // handle unlocks as before.
    p.restore();
    let mut v = p.f.unlock();
    v.transact(|t| t.set_value(p.other, SecretBytes::copy_from(b"rotated in session")))
        .unwrap();
    let v = unlock(v.lock());
    assert_eq!(v.integrity(), Integrity::Ok);
    assert!(v.read_value(p.other).unwrap().ct_eq(b"rotated in session"));
    assert_eq!(v.policies().unwrap().count(), 1);
    drop(v);

    // A deleted row.
    p.restore();
    let locked = open_and_lock();
    rewrite_on_disk(&p.f, "DELETE FROM policies;");
    assert_read_only(
        unlock(locked),
        Some(TamperKind::DigestMismatch),
        Some(p.keep),
        "a row deleted while locked",
    );

    // One row restored from an older copy: the snapshot holds the policy
    // at version 1, the file at version 2.
    p.restore();
    let mut v = p.f.unlock();
    let policy = v.policies().unwrap().next().unwrap().0;
    v.transact(|t| t.put_policy(policy, &common::standing_record(2)))
        .unwrap();
    drop(v);
    let locked = open_and_lock();
    rewrite_on_disk(
        &p.f,
        &format!(
            "ATTACH DATABASE '{}' AS old; DELETE FROM main.policies; \
             INSERT INTO main.policies SELECT * FROM old.policies; DETACH DATABASE old;",
            p.snapshot.join("vault.db").display()
        ),
    );
    assert_read_only(
        unlock(locked),
        Some(TamperKind::DigestMismatch),
        Some(p.keep),
        "a row restored while locked",
    );

    // A sealed column altered in place.
    p.restore();
    let sealed = sealed_value_of(&p.f, p.other);
    let locked = open_and_lock();
    flip_on_disk(&p.f, &sealed);
    let v = unlock(locked);
    assert_eq!(
        v.read_value(p.other).unwrap_err().kind(),
        VaultErrorKind::Tampered
    );
    assert_read_only(
        v,
        Some(TamperKind::DigestMismatch),
        Some(p.keep),
        "a column altered while locked",
    );
}

/// The database pages (numbered from 0, as [`page_of`] gives them) whose
/// newer copies are in the WAL beside `vault.db`: after its 32-byte header
/// come frames of a 24-byte header, starting with the page's number
/// (counted from 1), and the page.
fn wal_pages(f: &Fixture) -> Vec<usize> {
    let wal = std::fs::read(f.db().with_file_name("vault.db-wal")).unwrap();
    let page_size = u32::from_be_bytes(wal[8..12].try_into().unwrap()) as usize;
    wal[32..]
        .chunks_exact(24 + page_size)
        .map(|frame| u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize - 1)
        .collect()
}

/// Review T3 open 3: the gate 6 case above on the daemon's own path, where
/// the WAL is never empty at unlock (SPEC stories S7 to S10). The vault has
/// enough items to span pages; a session rotates a value, which puts that
/// field's page and the header's in the WAL, and is locked, unlocked with
/// no write between (so the kept handle has every page cached) and locked
/// again. Then a policy row, on a page with no copy in the WAL, is deleted
/// or restored from an older copy in `vault.db`. The next unlock through
/// the kept handle reads some pages from the WAL and that one from
/// `vault.db`, and reports the change.
#[test]
fn the_kept_handle_reads_the_file_again_with_session_frames_in_the_wal() {
    let _serial = alone();
    let p = pristine();
    let unlock = |locked: LockedVault| locked.unlock(p.f.vmk()).map_err(|(_, e)| e).unwrap();
    let older_copy = format!(
        "ATTACH DATABASE '{}' AS old; DELETE FROM main.policies; \
         INSERT INTO main.policies SELECT * FROM old.policies; DETACH DATABASE old;",
        p.snapshot.join("vault.db").display()
    );
    for (case, sql) in [
        ("a policy row deleted", "DELETE FROM policies;"),
        (
            "a policy row restored from an older copy",
            older_copy.as_str(),
        ),
    ] {
        // Items spanning pages and the policy at version 2 (the snapshot
        // holds version 1), all in `vault.db`.
        p.restore();
        let mut v = p.f.unlock();
        let policy = v.policies().unwrap().next().unwrap().0;
        v.transact(|t| {
            for i in 0..60 {
                let item = t.create_item(secret_item(&format!("span/item-{i:02}")))?;
                let value = SecretBytes::copy_from(b"a value that fills the pages");
                t.add_field(item, name("value"), value)?;
            }
            t.put_policy(policy, &common::standing_record(2))
        })
        .unwrap();
        drop(v);
        assert_closed(&p.f);
        let sealed_policy: Vec<u8> =
            p.f.raw()
                .query_row("SELECT sealed FROM policies", [], |r| r.get(0))
                .unwrap();
        let policy_page = page_of(&p.f, &sealed_policy);
        let field_page = page_of(&p.f, &sealed_value_of(&p.f, p.other));

        // The session.
        let mut v = p.f.unlock();
        v.transact(|t| t.set_value(p.other, SecretBytes::copy_from(b"rotated in session")))
            .unwrap();
        let v = unlock(v.lock());
        assert_eq!(v.integrity(), Integrity::Ok, "{case}");
        let locked = v.lock();
        let in_wal = wal_pages(&p.f);
        assert!(in_wal.contains(&field_page), "{case}: {in_wal:?}");
        assert!(
            !in_wal.contains(&policy_page),
            "{case}: the policy's page {policy_page} is in the WAL: {in_wal:?}"
        );

        rewrite_on_disk(&p.f, sql);
        let v = unlock(locked);
        assert!(
            v.read_value(p.other).unwrap().ct_eq(b"rotated in session"),
            "{case}: the session's write, read from the WAL"
        );
        assert_read_only(v, Some(TamperKind::DigestMismatch), Some(p.keep), case);
    }
}

/// Review finding F-21: a field's prior list removed on disk while the vault is
/// open. The authenticated prior count held since unlock says the list is
/// there, so its absence is tampering whether a read or a rotation meets it
/// first. The rotation is refused, so no digest vouches for the lost
/// history, and the next unlock reports it.
#[test]
fn a_prior_list_removed_while_open_is_tampering() {
    let _serial = alone();
    let p = pristine();
    p.restore();
    let mut v = p.f.unlock();
    for n in 0..2 {
        let value = SecretBytes::copy_from(format!("rotation {n}").as_bytes());
        v.transact(|t| t.set_value(p.other, value)).unwrap();
    }
    drop(v);
    let rotated = p.f.home.root().join("rotated.db");
    std::fs::copy(p.f.db(), &rotated).unwrap();
    // Only `other` has a prior list.
    let remove = "UPDATE fields SET sealed_prior = NULL WHERE sealed_prior IS NOT NULL;";

    // Met by a read.
    std::fs::copy(&rotated, p.f.db()).unwrap();
    let v = p.f.unlock();
    assert!(v.read_prior(p.other, 1).unwrap().ct_eq(b"other value"));
    rewrite_on_disk(&p.f, remove);
    v.evict_page_cache_for_testing().unwrap();
    assert_eq!(
        v.read_prior(p.other, 0).unwrap_err().kind(),
        VaultErrorKind::Tampered
    );
    assert_read_only(
        v,
        Some(TamperKind::ChangedWhileOpen),
        Some(p.keep),
        "met by a read",
    );
    // Unlock's own check: the record counts priors, the row holds none.
    assert_read_only(
        p.f.unlock(),
        Some(TamperKind::RowInconsistent),
        Some(p.keep),
        "reopened after a read",
    );

    // Met by a rotation, with no read first.
    std::fs::copy(&rotated, p.f.db()).unwrap();
    let before = sealed_value_of(&p.f, p.other);
    let mut v = p.f.unlock();
    rewrite_on_disk(&p.f, remove);
    let e = v
        .transact(|t| t.set_value(p.other, SecretBytes::copy_from(b"a third rotation")))
        .unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::Tampered);
    assert_read_only(
        v,
        Some(TamperKind::ChangedWhileOpen),
        Some(p.keep),
        "met by a rotation",
    );
    // Nothing was committed: the row still holds the value it had.
    assert_eq!(sealed_value_of(&p.f, p.other), before);
    assert_read_only(
        p.f.unlock(),
        Some(TamperKind::RowInconsistent),
        Some(p.keep),
        "reopened after a rotation",
    );
}

/// A row changed in the file while the vault is open turns it read-only
/// at the first read or write that meets the row, and the next unlock
/// reports it. A read may be served from the page SQLite cached at unlock,
/// so the read case drops that page on purpose; a write transaction reads
/// the file as it is, so the write case does not.
#[test]
fn a_row_changed_on_disk_while_open_turns_the_vault_read_only() {
    let _serial = alone();
    let p = pristine();

    // Met by a read.
    p.restore();
    let sealed = sealed_value_of(&p.f, p.other);
    let v = p.f.unlock();
    flip_on_disk(&p.f, &sealed);
    v.evict_page_cache_for_testing().unwrap();
    assert!(v.read_value(p.keep).unwrap().ct_eq(KEEP));
    assert_eq!(v.integrity(), Integrity::Ok, "an untouched row still reads");
    assert_eq!(
        v.read_value(p.other).unwrap_err().kind(),
        VaultErrorKind::Tampered
    );
    assert_read_only(
        v,
        Some(TamperKind::ChangedWhileOpen),
        Some(p.keep),
        "met by a read",
    );
    assert_read_only(
        p.f.unlock(),
        Some(TamperKind::DigestMismatch),
        Some(p.keep),
        "reopened after a read",
    );

    // Met by a write, with every page still cached.
    p.restore();
    let mut v = p.f.unlock();
    flip_on_disk(&p.f, &sealed);
    let e = v
        .transact(|t| t.set_value(p.other, SecretBytes::copy_from(b"a new value")))
        .unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::Tampered);
    assert_read_only(
        v,
        Some(TamperKind::ChangedWhileOpen),
        Some(p.keep),
        "met by a write",
    );
    assert_read_only(
        p.f.unlock(),
        Some(TamperKind::DigestMismatch),
        Some(p.keep),
        "reopened after a write",
    );
}

/// A commit's digest comes from the rows this process wrote, never from the
/// file: a row changed behind its back and not touched by the write is not
/// folded into a fresh digest, and the next unlock still reports it. Nor
/// does the commit write back a copy of that row's page cached before the
/// change, which would erase the change unreported (the two fields share a
/// page, and nothing drops the cache here but the write itself).
#[test]
fn a_commit_never_vouches_for_a_row_changed_on_disk() {
    let _serial = alone();
    let p = pristine();
    p.restore();
    let sealed = sealed_value_of(&p.f, p.other);
    assert_eq!(
        page_of(&p.f, &sealed),
        page_of(&p.f, &sealed_value_of(&p.f, p.keep))
    );
    let mut v = p.f.unlock();
    assert!(v.read_value(p.other).unwrap().ct_eq(b"other value"));
    flip_on_disk(&p.f, &sealed);
    v.transact(|t| t.set_value(p.keep, SecretBytes::copy_from(b"a later value")))
        .unwrap();
    assert_eq!(v.integrity(), Integrity::Ok);
    drop(v);
    let v = p.f.unlock();
    assert!(v.read_value(p.keep).unwrap().ct_eq(b"a later value"));
    assert_read_only(
        v,
        Some(TamperKind::DigestMismatch),
        None,
        "a commit after the change",
    );
}

/// SPEC §5 "Integrity": without an anchor (Linux, and macOS before M3),
/// restoring the whole file together with its header is not detected
/// locally. This test pins that documented limit, so a change in it is a
/// deliberate spec change.
#[test]
fn restoring_the_whole_file_is_not_detected_locally() {
    let _serial = beside();
    let p = pristine();
    p.restore();
    let mut v = p.f.unlock();
    let before = v.header().unwrap().write_counter;
    v.transact(|t| t.set_value(p.other, SecretBytes::copy_from(b"newer value")))
        .unwrap();
    drop(v);
    p.restore();
    let v = p.f.unlock();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_eq!(v.header().unwrap().write_counter, before);
    assert!(v.read_value(p.other).unwrap().ct_eq(b"other value"));
}

const MODES_CHILD: &str = "ENVCLOAK_VAULT_MODES_CHILD";

/// Runs only as the child of the test below, under umask 000.
#[test]
fn file_modes_child() {
    let Some(dir) = std::env::var_os(MODES_CHILD) else {
        return;
    };
    let data = Path::new(&dir).join("data");
    // Before the vault code runs, this process creates world-writable
    // files: the umask really is 000.
    let probe = Path::new(&dir).join("probe");
    std::fs::write(&probe, b"").unwrap();
    assert_eq!(std::fs::metadata(&probe).unwrap().mode() & 0o777, 0o666);

    let paths = envcloak_core::vault::VaultPaths::under(&data);
    let vmk = envcloak_core::crypto::Vmk::generate();
    let vault_id = envcloak_core::crypto::VaultId::generate();
    let env = wrap_vmk_with(
        &vmk,
        &SecretBytes::copy_from(b"modes passphrase"),
        UnlockerKind::Passphrase,
        &EnvelopeCtx {
            vault_id,
            unlocker_id: UnlockerId::generate(),
            epoch: INITIAL_EPOCH,
        },
        &KdfParams::minimum(),
        &Argon2id,
    )
    .unwrap();
    let mut v = Vault::create(&paths, vault_id, vmk, vec![env]).unwrap();
    v.transact(|t| {
        let i = t.create_item(secret_item("m/one"))?;
        t.add_field(i, name("value"), SecretBytes::copy_from(b"mode test value"))
    })
    .unwrap();
    // While the vault is open its WAL exists; every file is 0600 and every
    // directory 0700.
    let mode = |p: &Path| std::fs::symlink_metadata(p).unwrap().mode() & 0o777;
    for d in [
        &paths.data_dir,
        &paths.vault_dir,
        &paths.audit_dir,
        &paths.backups_dir,
    ] {
        assert_eq!(mode(d), 0o700, "{}", d.display());
    }
    let mut files = 0;
    for e in std::fs::read_dir(&paths.vault_dir).unwrap() {
        let e = e.unwrap();
        assert_eq!(mode(&e.path()), 0o600, "{:?}", e.file_name());
        files += 1;
    }
    assert!(files >= 2, "the database and its WAL");
    println!("modes: checked");
}

#[test]
fn files_are_private_even_under_a_permissive_umask() {
    let _serial = beside();
    let home = envcloak_testkit::TestHome::new();
    let exe = std::env::current_exe().unwrap();
    let out = home
        .apply(&mut std::process::Command::new("/bin/sh"))
        .args([
            "-c",
            "umask 000; exec \"$0\" --exact file_modes_child --nocapture --test-threads=1",
        ])
        .arg(&exe)
        .env(MODES_CHILD, home.root())
        .output()
        .unwrap();
    assert!(out.status.success(), "child failed: {out:?}");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("modes: checked"),
        "the child did not run the check: {out:?}"
    );
}

/// SPEC T3 pitfall: the digest is recomputed on every commit; benchmark it
/// at 10,000 rows. The bounds are loose so a slow CI runner passes; the
/// timings are printed.
#[test]
fn the_digest_stays_cheap_at_ten_thousand_rows() {
    let _serial = beside();
    let (f, mut v) = Fixture::create();
    let start = Instant::now();
    let first = v
        .transact(|t| {
            let mut first = None;
            for n in 0..5_000u32 {
                let i = t.create_item(secret_item(&format!("bulk/item-{n:05}")))?;
                let fid = t.add_field(
                    i,
                    name("value"),
                    SecretBytes::copy_from(format!("bulk value number {n:05}").as_bytes()),
                )?;
                first.get_or_insert(fid);
            }
            Ok(first.unwrap())
        })
        .unwrap();
    let fill = start.elapsed();

    let start = Instant::now();
    v.transact(|t| t.set_value(first, SecretBytes::copy_from(b"one small change")))
        .unwrap();
    let commit = start.elapsed();
    drop(v);

    let start = Instant::now();
    let v = f.unlock();
    let unlock = start.elapsed();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_eq!(v.items().len(), 5_000);
    println!("10k rows: fill {fill:?}, one-row commit {commit:?}, unlock {unlock:?}");
    assert!(commit.as_secs_f64() < 2.0, "one-row commit took {commit:?}");
    assert!(unlock.as_secs_f64() < 10.0, "unlock took {unlock:?}");
}
