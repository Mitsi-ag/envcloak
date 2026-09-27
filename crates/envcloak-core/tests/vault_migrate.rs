//! Gate 7 (SPEC §15.2): a failure mid-migration leaves the old vault
//! intact and openable. Also: a migration that succeeds re-seals every
//! sealed column under the new schema version and verifies; an older build
//! refuses the newer file; `kill -9` during a migration leaves the old or
//! the new vault, never a mix.
#![allow(clippy::unwrap_used)]

mod common;

use std::io::BufReader;
use std::time::{Duration, Instant};

use common::{Fixture, Rng, kill_child, name, read_stdin, secret_item, spawn_self, wait_for};
use envcloak_core::SecretBytes;
use envcloak_core::crypto::Vmk;
use envcloak_core::vault::{
    FieldId, Integrity, LockedVault, Migration, MigrationPlan, MigrationTx, PolicyId, ProjectKey,
    ProjectRecord, Vault, VaultError, VaultErrorKind, VaultPaths,
};
use envcloak_testkit::fresh_seed;
use rusqlite::types::Value;

const V2_DDL: &str = "ALTER TABLE items ADD COLUMN tier INTEGER NOT NULL DEFAULT 0;
CREATE TABLE notes (id BLOB PRIMARY KEY NOT NULL, row_version INTEGER NOT NULL) STRICT;";

fn set_tier(tx: &MigrationTx<'_>) -> Result<(), VaultError> {
    assert_eq!(tx.version(), 2);
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

fn to_v2(transform: fn(&MigrationTx<'_>) -> Result<(), VaultError>) -> MigrationPlan {
    MigrationPlan::new(vec![Migration {
        from: 1,
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
        t.put_policy(PolicyId::generate(), b"policy")
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

#[test]
fn a_failing_transform_leaves_the_old_vault_intact_and_openable() {
    let (f, values) = populated(20);
    let before = dump(&f);
    let (locked, e) = open_with(&f, to_v2(set_tier_then_fail)).unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::Migration);
    assert_eq!(locked.schema_version(), 1);
    drop(locked);
    // Byte for byte the same rows and schema: no new table, no new column.
    assert_eq!(dump(&f), before);
    let v = f.unlock();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_eq!(v.schema_version(), 1);
    assert_values(&v, &values);
}

#[test]
fn a_failing_step_later_in_the_plan_rolls_back_every_step() {
    let (f, values) = populated(5);
    let before = dump(&f);
    let plan = MigrationPlan::new(vec![
        Migration {
            from: 1,
            ddl: V2_DDL,
            transform: set_tier,
        },
        Migration {
            from: 2,
            // The first statement succeeds, the second does not parse.
            ddl: "CREATE TABLE fine (x INTEGER) STRICT; CREATE TABLE broken (;",
            transform: nothing,
        },
    ])
    .unwrap();
    let (_, e) = open_with(&f, plan).unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::Migration);
    assert_eq!(dump(&f), before);
    let v = f.unlock();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_values(&v, &values);
}

#[test]
fn a_migration_reseals_everything_and_verifies() {
    let (f, values) = populated(10);
    let before = dump(&f);
    let counter = f.unlock().header().write_counter;

    let v = open_with(&f, to_v2(set_tier)).map_err(|(_, e)| e).unwrap();
    assert_eq!(v.schema_version(), 2);
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_eq!(v.header().write_counter, counter + 1);
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
        ("header", 1),
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
    drop(raw);

    // Reopened with the same plan: nothing left to migrate, and writes
    // work at the new version.
    let mut v = open_with(&f, to_v2(set_tier)).map_err(|(_, e)| e).unwrap();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_eq!(v.header().write_counter, counter + 1);
    v.transact(|t| t.set_value(values[1].0, SecretBytes::copy_from(b"at v2")))
        .unwrap();
    drop(v);
    let v = open_with(&f, to_v2(set_tier)).map_err(|(_, e)| e).unwrap();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert!(v.read_value(values[1].0).unwrap().ct_eq(b"at v2"));
    drop(v);
    // A build that only knows version 1 refuses the file, and leaves it
    // alone.
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
    let v = open_with(&f, to_v2(set_tier)).map_err(|(_, e)| e).unwrap();
    assert!(matches!(v.integrity(), Integrity::Tampered(_)));
    assert_eq!(v.schema_version(), 1, "read-only at the old version");
    assert!(v.read_value(values[0].0).unwrap().ct_eq(&values[0].1));
    drop(v);
    assert_eq!(dump(&f), before);
}

const MIGRATOR: &str = "ENVCLOAK_VAULT_MIGRATOR";

/// Runs only as the child of the test below: opens with the v2 plan, which
/// migrates.
#[test]
fn migration_child() {
    let Some(dir) = std::env::var_os(MIGRATOR) else {
        return;
    };
    let vmk = Vmk::import_for_testing(&read_stdin()).unwrap();
    println!("@@start");
    let v = LockedVault::open_with_plan(&VaultPaths::under(dir), to_v2(set_tier))
        .unwrap()
        .unlock(vmk)
        .map_err(|(_, e)| e)
        .unwrap();
    assert_eq!(v.schema_version(), 2);
    println!("@@migrated");
    std::thread::sleep(Duration::from_secs(60));
}

#[test]
fn kill_9_during_a_migration_leaves_the_old_or_the_new_vault() {
    let seed = fresh_seed();
    let mut rng = Rng(seed);
    let (f, values) = populated(150);
    let v1 = f.home.root().join("v1.db");
    std::fs::copy(f.db(), &v1).unwrap();
    let before = dump(&f);

    let mut window = Duration::from_millis(50);
    let (mut old, mut new) = (0, 0);
    for round in 0..30 {
        std::fs::copy(&v1, f.db()).unwrap();
        let mut child = spawn_self(&f.home, "migration_child", &[(MIGRATOR, &f.data())], &f.vmk);
        let mut out = BufReader::new(child.stdout.take().unwrap());
        assert!(wait_for(&mut out, "@@start").is_some(), "round {round}");
        let started = Instant::now();
        if round == 0 {
            assert!(
                wait_for(&mut out, "@@migrated").is_some(),
                "the migration did not finish"
            );
            window = started.elapsed();
        } else {
            let us = rng.below(window.as_micros() as u64 * 5 / 4 + 1);
            std::thread::sleep(Duration::from_micros(us));
        }
        kill_child(&mut child, "migration");

        let ctx = format!("seed {seed}: round {round}");
        match LockedVault::open(&f.paths) {
            Ok(locked) => {
                old += 1;
                let v = locked.unlock(f.vmk()).map_err(|(_, e)| e).unwrap();
                assert_eq!(v.integrity(), Integrity::Ok, "{ctx}");
                assert_eq!(v.schema_version(), 1, "{ctx}");
                assert_values(&v, &values);
                drop(v);
                assert_eq!(dump(&f), before, "{ctx}: the old vault changed");
            }
            Err(e) => {
                assert_eq!(e.kind(), VaultErrorKind::UnsupportedVersion, "{ctx}");
                new += 1;
                let v = open_with(&f, to_v2(set_tier)).map_err(|(_, e)| e).unwrap();
                assert_eq!(v.integrity(), Integrity::Ok, "{ctx}");
                assert_eq!(v.schema_version(), 2, "{ctx}");
                assert_values(&v, &values);
            }
        }
    }
    println!("migration kills (seed {seed}): {old} left version 1, {new} left version 2");
    assert!(old > 0, "no kill landed before the migration committed");
    assert!(new > 0);
}

#[test]
fn plans_must_be_contiguous() {
    let e = MigrationPlan::new(vec![Migration {
        from: 2,
        ddl: "",
        transform: nothing,
    }])
    .unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::Migration);
    assert_eq!(MigrationPlan::current().target(), 1);
    assert!(MigrationPlan::current().steps().is_empty());
}
