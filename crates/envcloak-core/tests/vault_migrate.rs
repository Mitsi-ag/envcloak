//! Gate 7 (SPEC §15.2), for the migration engine: a failure mid-migration
//! leaves the old vault intact and openable, by the old build and,
//! read-only, by the build whose migration failed. Also: a migration that
//! succeeds re-seals every sealed column under the new schema version and
//! verifies; an older build refuses the newer file; `kill -9` during a
//! migration leaves the old or the new vault, never a mix: the old one when
//! the child is held inside the migration's transaction, the new one when
//! it is held after the commit; a row changed between unlock's check and
//! the migration is tampering, never migrated.
//!
//! These tests take a vault this build writes (schema version 2) through
//! test-only steps to version 3. The shipped step, from the format M1
//! wrote to version 2, is tested on files the M1 build wrote, in
//! `tests/m1_format.rs`.
#![allow(clippy::unwrap_used)]

mod common;

use std::io::BufReader;
use std::time::{Duration, Instant};

use common::{
    Fixture, Rng, kill_child, name, read_stdin, secret_item, spawn_self, standing_record, wait_for,
};
use envcloak_core::SecretBytes;
use envcloak_core::crypto::Vmk;
use envcloak_core::vault::{
    FieldId, Integrity, LockedVault, Migration, MigrationPlan, MigrationTx, PolicyId, ProjectKey,
    ProjectRecord, TamperKind, Vault, VaultError, VaultErrorKind, VaultPaths,
};
use envcloak_testkit::fresh_seed;
use rusqlite::types::Value;

const V2_DDL: &str = "ALTER TABLE items ADD COLUMN tier INTEGER NOT NULL DEFAULT 0;
CREATE TABLE notes (id BLOB PRIMARY KEY NOT NULL, row_version INTEGER NOT NULL) STRICT;";

fn set_tier(tx: &MigrationTx<'_>) -> Result<(), VaultError> {
    assert_eq!(tx.version(), 3);
    tx.execute("UPDATE items SET tier = 1")?;
    Ok(())
}

fn set_tier_then_fail(tx: &MigrationTx<'_>) -> Result<(), VaultError> {
    tx.execute("UPDATE items SET tier = 1")?;
    Err(VaultErrorKind::Migration.into())
}

fn nothing(_: &MigrationTx<'_>) -> Result<(), VaultError> {
    Ok(())
}

/// The shipped plan and one test-only step, from 2 to 3.
fn to_v3(transform: fn(&MigrationTx<'_>) -> Result<(), VaultError>) -> MigrationPlan {
    MigrationPlan::new(vec![Migration {
        from: 2,
        ddl: V2_DDL,
        transform,
    }])
    .unwrap()
}

/// A vault with items, fields with prior values, a project and a policy.
fn populated(items: u32) -> (Fixture, Vec<(FieldId, Vec<u8>)>) {
    let (f, mut v) = Fixture::create();
    let mut values = Vec::new();
    v.transact(|t| {
        for n in 0..items {
            let i = t.create_item(secret_item(&format!("m/item-{n:04}")))?;
            let a = t.add_field(i, name("value"), SecretBytes::copy_from(b"first"))?;
            let now = format!("value {n} after rotation");
            t.set_value(a, SecretBytes::copy_from(now.as_bytes()))?;
            values.push((a, now.into_bytes()));
            let b = t.add_field(i, name("other"), SecretBytes::copy_from(b"other"))?;
            values.push((b, b"other".to_vec()));
        }
        t.upsert_project(ProjectRecord {
            key: ProjectKey::new(b"proj").unwrap(),
            display_path: "/src/p".into(),
            manifest_sha256: [1; 32],
            bindings: Vec::new(),
            last_seen: 1,
        })?;
        t.put_policy(PolicyId::generate(), &standing_record(1))
    })
    .unwrap();
    (f, values)
}

fn assert_values(v: &Vault, values: &[(FieldId, Vec<u8>)]) {
    for (id, want) in values {
        assert!(v.read_value(*id).unwrap().ct_eq(want));
    }
    // The rotated fields kept their prior value.
    assert!(v.read_prior(values[0].0, 0).unwrap().ct_eq(b"first"));
}

/// Every row of every vault table, and the schema, through a plain SQLite
/// connection. Ciphertext only.
fn dump(f: &Fixture) -> Vec<(String, Vec<Vec<Value>>)> {
    let raw = f.raw();
    let mut out = Vec::new();
    for table in [
        "sqlite_schema",
        "meta",
        "header",
        "unlockers",
        "items",
        "fields",
        "projects",
        "policies",
    ] {
        let mut st = raw
            .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
            .unwrap();
        let cols = st.column_count();
        let rows = st
            .query_map([], |r| (0..cols).map(|i| r.get::<_, Value>(i)).collect())
            .unwrap()
            .collect::<Result<Vec<Vec<Value>>, _>>()
            .unwrap();
        out.push((table.to_owned(), rows));
    }
    out
}

fn open_with(f: &Fixture, plan: MigrationPlan) -> Result<Vault, (LockedVault, VaultError)> {
    LockedVault::open_with_plan(&f.paths, plan)
        .unwrap()
        .unlock(f.vmk())
}

/// The build whose migration failed opens the vault too: read-only, at
/// its old version, every value readable, so the owner can back it up.
fn assert_opens_unmigrated(f: &Fixture, plan: MigrationPlan, values: &[(FieldId, Vec<u8>)]) {
    let mut v = open_with(f, plan).map_err(|(_, e)| e).unwrap();
    assert_eq!(v.migration_error(), Some(VaultErrorKind::Migration));
    assert_eq!(v.integrity(), Integrity::Ok, "the vault itself verified");
    assert_eq!(v.schema_version(), 2);
    assert_values(&v, values);
    let e = v
        .transact(|t| t.set_value(values[1].0, SecretBytes::copy_from(b"refused")))
        .unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::Migration);
}

#[test]
fn a_failing_transform_leaves_the_old_vault_intact_and_openable() {
    let (f, values) = populated(20);
    let before = dump(&f);
    assert_opens_unmigrated(&f, to_v3(set_tier_then_fail), &values);
    // Byte for byte the same rows and schema: no new table, no new column.
    assert_eq!(dump(&f), before);
    // Every open retries the migration, and changes nothing when it fails.
    assert_opens_unmigrated(&f, to_v3(set_tier_then_fail), &values);
    assert_eq!(dump(&f), before);
    // A build without the migration opens it as it was.
    let v = f.unlock();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_eq!(v.migration_error(), None);
    assert_eq!(v.schema_version(), 2);
    assert_values(&v, &values);
    drop(v);
    // And a build whose migration works migrates it.
    let v = open_with(&f, to_v3(set_tier)).map_err(|(_, e)| e).unwrap();
    assert_eq!(v.migration_error(), None);
    assert_eq!(v.schema_version(), 3);
    assert_values(&v, &values);
}

static FAILED_ONCE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Fails the first time it runs in this process, then works.
fn fail_once(tx: &MigrationTx<'_>) -> Result<(), VaultError> {
    if !FAILED_ONCE.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return Err(VaultErrorKind::Migration.into());
    }
    set_tier(tx)
}

#[test]
fn locking_and_unlocking_again_retries_a_failed_migration() {
    let (f, values) = populated(4);
    let v = open_with(&f, to_v3(fail_once)).map_err(|(_, e)| e).unwrap();
    assert_eq!(v.migration_error(), Some(VaultErrorKind::Migration));
    let v = v.lock().unlock(f.vmk()).map_err(|(_, e)| e).unwrap();
    assert_eq!(v.migration_error(), None);
    assert_eq!(v.schema_version(), 3);
    assert_values(&v, &values);
}

#[test]
fn a_failing_step_later_in_the_plan_rolls_back_every_step() {
    let (f, values) = populated(5);
    let before = dump(&f);
    let plan = MigrationPlan::new(vec![
        Migration {
            from: 2,
            ddl: V2_DDL,
            transform: set_tier,
        },
        Migration {
            from: 3,
            // The first statement succeeds, the second does not parse.
            ddl: "CREATE TABLE fine (x INTEGER) STRICT; CREATE TABLE broken (;",
            transform: nothing,
        },
    ])
    .unwrap();
    assert_opens_unmigrated(&f, plan, &values);
    assert_eq!(dump(&f), before);
    let v = f.unlock();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_values(&v, &values);
}

#[test]
fn a_migration_reseals_everything_and_verifies() {
    let (f, values) = populated(10);
    let before = dump(&f);
    let counter = f.unlock().header().unwrap().write_counter;

    let v = open_with(&f, to_v3(set_tier)).map_err(|(_, e)| e).unwrap();
    assert_eq!(v.schema_version(), 3);
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_eq!(v.header().unwrap().write_counter, counter + 1);
    assert_values(&v, &values);
    drop(v);

    // Every sealed blob changed: the schema version is in the associated
    // data, so nothing sealed under version 1 would open.
    let after = dump(&f);
    let blobs = |d: &[(String, Vec<Vec<Value>>)], table: &str, col: usize| -> Vec<Value> {
        d.iter()
            .find(|(t, _)| t == table)
            .unwrap()
            .1
            .iter()
            .map(|r| r[col].clone())
            .collect()
    };
    for (table, col) in [
        ("items", 4),
        ("fields", 3),
        ("fields", 4),
        ("fields", 6),
        ("projects", 3),
        ("policies", 2),
        ("header", 3),
    ] {
        let old = blobs(&before, table, col);
        let new = blobs(&after, table, col);
        assert_eq!(old.len(), new.len());
        let mut sealed = 0;
        for (o, n) in old.iter().zip(&new) {
            // Fields without prior values have none to re-seal.
            if *o == Value::Null {
                assert_eq!(*n, Value::Null);
                continue;
            }
            assert_ne!(o, n, "{table} column {col} was not re-sealed");
            sealed += 1;
        }
        assert!(sealed > 0, "{table} column {col}");
    }
    let raw = f.raw();
    let tiers: i64 = raw
        .query_row("SELECT count(*) FROM items WHERE tier = 1", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(tiers, 10);
    // Both rows that name the version say 3.
    let versions: (i64, i64) = raw
        .query_row(
            "SELECT (SELECT schema_version FROM meta), (SELECT schema_version FROM header)",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(versions, (3, 3));
    drop(raw);

    // Reopened with the same plan: nothing left to migrate, and writes
    // work at the new version.
    let mut v = open_with(&f, to_v3(set_tier)).map_err(|(_, e)| e).unwrap();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_eq!(v.header().unwrap().write_counter, counter + 1);
    v.transact(|t| t.set_value(values[1].0, SecretBytes::copy_from(b"at v2")))
        .unwrap();
    drop(v);
    let v = open_with(&f, to_v3(set_tier)).map_err(|(_, e)| e).unwrap();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert!(v.read_value(values[1].0).unwrap().ct_eq(b"at v2"));
    drop(v);
    // A build that knows version 2 at most refuses the file, and leaves
    // it alone.
    let snapshot = dump(&f);
    assert_eq!(
        LockedVault::open(&f.paths).unwrap_err().kind(),
        VaultErrorKind::UnsupportedVersion
    );
    assert_eq!(dump(&f), snapshot);
}

#[test]
fn a_tampered_vault_is_not_migrated() {
    let (f, values) = populated(3);
    let raw = f.raw();
    raw.execute("UPDATE items SET updated_at = updated_at + 1", [])
        .unwrap();
    drop(raw);
    let before = dump(&f);
    let v = open_with(&f, to_v3(set_tier)).map_err(|(_, e)| e).unwrap();
    assert!(matches!(v.integrity(), Integrity::Tampered(_)));
    assert_eq!(v.schema_version(), 2, "read-only at the old version");
    assert!(v.read_value(values[0].0).unwrap().ct_eq(&values[0].1));
    drop(v);
    assert_eq!(dump(&f), before);
}

/// Runs `sql` on `vault.db` behind the open vault, as another program can
/// (the vault's lock is advisory): on a copy, through a plain connection,
/// whose bytes then replace the file's. The vault has not written, so
/// every page it reads comes from `vault.db`.
fn rewrite_behind(p: &VaultPaths, sql: &str) {
    let db = std::fs::canonicalize(&p.vault_dir)
        .unwrap()
        .join("vault.db");
    let copy = p.data_dir.join("rewrite.db");
    std::fs::copy(&db, &copy).unwrap();
    let raw = rusqlite::Connection::open(&copy).unwrap();
    raw.execute_batch(sql).unwrap();
    drop(raw);
    let bytes = std::fs::read(&copy).unwrap();
    std::fs::remove_file(&copy).unwrap();
    assert_ne!(bytes, std::fs::read(&db).unwrap(), "no change: {sql}");
    std::fs::write(&db, bytes).unwrap();
}

fn delete_a_policy_behind(p: &VaultPaths) {
    rewrite_behind(p, "DELETE FROM policies;");
}

fn add_a_policy_behind(p: &VaultPaths) {
    rewrite_behind(
        p,
        "INSERT INTO policies SELECT randomblob(16), row_version, sealed FROM policies;",
    );
}

/// Review T3 open 2: unlock's check and the migration are separate
/// transactions. A row deleted or added between them (here through the
/// test-only hook between the two) is not re-sealed into a state the new
/// header vouches for: the vault opens read-only at version 1, "changed
/// while open", nothing is migrated, and a build without the migration
/// then reports the change too.
#[test]
fn a_row_changed_between_the_check_and_the_migration_is_tampering() {
    for (case, hook, later) in [
        (
            "a policy deleted",
            delete_a_policy_behind as fn(&VaultPaths),
            TamperKind::DigestMismatch,
        ),
        // Sealed for the row it was copied from, it does not open.
        (
            "a policy added",
            add_a_policy_behind,
            TamperKind::RowUnreadable,
        ),
    ] {
        let (f, values) = populated(3);
        let plan = to_v3(set_tier).with_hook_before_migration(hook);
        let mut v = open_with(&f, plan).map_err(|(_, e)| e).unwrap();
        assert_eq!(
            v.integrity(),
            Integrity::Tampered(TamperKind::ChangedWhileOpen),
            "{case}"
        );
        assert_eq!(v.schema_version(), 2, "{case}: not migrated");
        assert_values(&v, &values);
        let e = v
            .transact(|t| t.set_value(values[1].0, SecretBytes::copy_from(b"refused")))
            .unwrap_err();
        assert_eq!(e.kind(), VaultErrorKind::ReadOnly, "{case}");
        drop(v);
        let raw = f.raw();
        let versions: (i64, i64) = raw
            .query_row(
                "SELECT (SELECT schema_version FROM meta), (SELECT schema_version FROM header)",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(versions, (2, 2), "{case}");
        drop(raw);
        let v = f.unlock();
        assert_eq!(v.integrity(), Integrity::Tampered(later), "{case}");
    }
}

/// Gate 6 across a migration: `meta` restored from the copy taken before
/// the vault moved to version 3, or the header's copy of the version
/// lowered, opens read-only at the version the header and rows were sealed
/// under. Nothing is migrated or written. A build that reads version 2 at
/// most reports a newer vault instead of a wrong key.
#[test]
fn a_meta_row_from_before_a_migration_opens_read_only() {
    let (f, values) = populated(3);
    let v2 = f.home.root().join("v2.db");
    std::fs::copy(f.db(), &v2).unwrap();
    drop(open_with(&f, to_v3(set_tier)).map_err(|(_, e)| e).unwrap());
    let v3 = f.home.root().join("v3.db");
    std::fs::copy(f.db(), &v3).unwrap();

    for (case, want) in [
        ("meta restored from version 2", TamperKind::MetaAltered),
        ("the header's version lowered", TamperKind::RowInconsistent),
    ] {
        std::fs::copy(&v3, f.db()).unwrap();
        let raw = f.raw();
        if want == TamperKind::MetaAltered {
            raw.execute("ATTACH DATABASE ?1 AS old", [v2.to_str().unwrap()])
                .unwrap();
            raw.execute_batch(
                "DELETE FROM main.meta; INSERT INTO main.meta SELECT * FROM old.meta; \
                 DETACH DATABASE old;",
            )
            .unwrap();
        } else {
            raw.execute_batch("UPDATE header SET schema_version = 2;")
                .unwrap();
        }
        drop(raw);
        let before = dump(&f);

        let mut v = open_with(&f, to_v3(set_tier)).map_err(|(_, e)| e).unwrap();
        assert_eq!(v.integrity(), Integrity::Tampered(want), "{case}");
        assert_eq!(v.schema_version(), 3, "{case}");
        assert_values(&v, &values);
        let e = v
            .transact(|t| t.set_value(values[1].0, SecretBytes::copy_from(b"no")))
            .unwrap_err();
        assert_eq!(e.kind(), VaultErrorKind::ReadOnly, "{case}");
        drop(v);
        assert_eq!(dump(&f), before, "{case}: the file changed");

        let (_, e) = LockedVault::open(&f.paths)
            .unwrap()
            .unlock(f.vmk())
            .unwrap_err();
        assert_eq!(e.kind(), VaultErrorKind::UnsupportedVersion, "{case}");
    }
}

const MIGRATOR: &str = "ENVCLOAK_VAULT_MIGRATOR";
/// Set for the child: its migration stops inside the migration
/// transaction, after every row was re-sealed and the transform ran and
/// before the commit, prints `@@in-migration` and waits to be killed.
const HOLD: &str = "ENVCLOAK_VAULT_MIGRATOR_HOLD";

/// The child's transform: [`set_tier`], then, when [`HOLD`] is set, the
/// stop inside the transaction.
fn set_tier_or_hold(tx: &MigrationTx<'_>) -> Result<(), VaultError> {
    set_tier(tx)?;
    if std::env::var_os(HOLD).is_some() {
        println!("@@in-migration");
        std::thread::sleep(Duration::from_secs(60));
    }
    Ok(())
}

/// Runs only as the child of the test below: opens with the v2 plan, which
/// migrates.
#[test]
fn migration_child() {
    let Some(dir) = std::env::var_os(MIGRATOR) else {
        return;
    };
    let vmk = Vmk::import_for_testing(&read_stdin()).unwrap();
    println!("@@start");
    let v = LockedVault::open_with_plan(&VaultPaths::under(dir), to_v3(set_tier_or_hold))
        .unwrap()
        .unlock(vmk)
        .map_err(|(_, e)| e)
        .unwrap();
    assert_eq!(v.schema_version(), 3);
    println!("@@migrated");
    std::thread::sleep(Duration::from_secs(60));
}

/// Which vault a killed migration left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Left {
    Old,
    New,
}

/// Opens the vault a killed migration left and checks that it is exactly
/// the old vault, byte for byte, or the migrated one, whole.
fn left_by_kill(
    f: &Fixture,
    values: &[(FieldId, Vec<u8>)],
    before: &[(String, Vec<Vec<Value>>)],
    ctx: &str,
) -> Left {
    match LockedVault::open(&f.paths) {
        Ok(locked) => {
            let v = locked.unlock(f.vmk()).map_err(|(_, e)| e).unwrap();
            assert_eq!(v.integrity(), Integrity::Ok, "{ctx}");
            assert_eq!(v.schema_version(), 2, "{ctx}");
            assert_values(&v, values);
            drop(v);
            assert_eq!(dump(f), before, "{ctx}: the old vault changed");
            Left::Old
        }
        Err(e) => {
            assert_eq!(e.kind(), VaultErrorKind::UnsupportedVersion, "{ctx}");
            let v = open_with(f, to_v3(set_tier)).map_err(|(_, e)| e).unwrap();
            assert_eq!(v.integrity(), Integrity::Ok, "{ctx}");
            assert_eq!(v.schema_version(), 3, "{ctx}");
            assert_values(&v, values);
            Left::New
        }
    }
}

/// Gate 7's crash half (Codex F-25): the child is held inside the
/// migration transaction, after the rows were re-sealed and before the
/// commit, and killed there: the old vault is left. Held after the commit
/// and killed: the migrated one. Neither depends on when the kill lands.
/// Then kills at random moments within a measured migration add coverage,
/// each leaving one vault or the other, however they fall.
#[test]
fn kill_9_during_a_migration_leaves_the_old_or_the_new_vault() {
    let seed = fresh_seed();
    let mut rng = Rng(seed);
    let (f, values) = populated(150);
    let v2 = f.home.root().join("v2.db");
    std::fs::copy(f.db(), &v2).unwrap();
    let before = dump(&f);
    let start = |hold: bool| {
        std::fs::copy(&v2, f.db()).unwrap();
        let data = f.data();
        let mut env = vec![(MIGRATOR, data.as_str())];
        if hold {
            env.push((HOLD, "1"));
        }
        let mut child = spawn_self(&f.home, "migration_child", &env, &f.vmk);
        let out = BufReader::new(child.stdout.take().unwrap());
        (child, out)
    };

    // Held before the commit.
    for round in 0..3 {
        let (mut child, mut out) = start(true);
        assert!(
            wait_for(&mut out, "@@in-migration").is_some(),
            "held round {round}: the child did not reach the migration"
        );
        kill_child(&mut child, "migration");
        let ctx = format!("killed inside the migration, round {round}");
        assert_eq!(left_by_kill(&f, &values, &before, &ctx), Left::Old, "{ctx}");
    }

    // Held after the commit; this also measures a whole migration.
    let (mut child, mut out) = start(false);
    assert!(wait_for(&mut out, "@@start").is_some());
    let started = Instant::now();
    assert!(
        wait_for(&mut out, "@@migrated").is_some(),
        "the migration did not finish"
    );
    let window = started.elapsed();
    kill_child(&mut child, "migration");
    let ctx = "killed after the commit";
    assert_eq!(left_by_kill(&f, &values, &before, ctx), Left::New, "{ctx}");

    // Random moments: either vault, never a mix.
    let (mut old, mut new) = (0, 0);
    for round in 0..20 {
        let (mut child, mut out) = start(false);
        assert!(wait_for(&mut out, "@@start").is_some(), "round {round}");
        let us = rng.below(window.as_micros() as u64 * 5 / 4 + 1);
        std::thread::sleep(Duration::from_micros(us));
        kill_child(&mut child, "migration");
        match left_by_kill(&f, &values, &before, &format!("seed {seed}: round {round}")) {
            Left::Old => old += 1,
            Left::New => new += 1,
        }
    }
    println!("random migration kills (seed {seed}): {old} left version 2, {new} left version 3");
}

#[test]
fn plans_must_be_contiguous() {
    for from in [1, 3] {
        let e = MigrationPlan::new(vec![Migration {
            from,
            ddl: "",
            transform: nothing,
        }])
        .unwrap_err();
        assert_eq!(e.kind(), VaultErrorKind::Migration);
    }
    // The shipped plan: the one step from M1's format to version 2.
    let plan = MigrationPlan::current();
    assert_eq!(plan.target(), 2);
    assert_eq!(plan.steps().iter().map(|s| s.from).collect::<Vec<_>>(), [1]);
    // A test plan keeps it, and goes on from there.
    let plan = to_v3(nothing);
    assert_eq!(plan.target(), 3);
    assert_eq!(
        plan.steps().iter().map(|s| s.from).collect::<Vec<_>>(),
        [1, 2]
    );
}
