//! The one schema migration of M2 and M2b (plan task M2-07, decision D-08,
//! risk K-12), on files the M1 build wrote: `tests/fixtures/m1-vault`,
//! written by M1's code with `generate.rs` beside them (L-02: the format
//! as the real old code wrote it, loaded as bytes).
//!
//! - The shipped step from schema version 1 to 2 turns every item and
//!   field record into version 2, keeps every value, prior value, class,
//!   detail, project and header field, starts the standing set, re-seals
//!   every sealed column, and verifies.
//! - Gate 7 on that step: a failure inside it (a test-only hook in the
//!   migration's transaction, after every row was rewritten and before the
//!   commit) and a version 1 policy row, which has no type to give it, each
//!   leave the M1 vault exactly as it was, open read-only at version 1
//!   with every value readable; `kill -9` while the migration's
//!   transaction is held open (a deterministic barrier, F-25) leaves the M1
//!   vault, and after the commit the migrated one.
//! - F-22 and K-12: a Recovery Kit backup M1 wrote restores with this
//!   build, checked against its manifest as it was backed up and migrated
//!   after; and an `init` file backup M1 wrote opens once the vault has
//!   moved to version 2.
#![allow(clippy::unwrap_used)]

mod common;

use std::io::BufReader;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use common::{Rng, kill_child, read_stdin, spawn_self, standing_record, wait_for};
use envcloak_core::crypto::{ItemClass, KdfParams, Vmk};
use envcloak_core::file_backup::{FileBackupId, FileLeft};
use envcloak_core::file_backup_v2::CreatorKind;
use envcloak_core::vault::{
    Account, AuditHead, Classification, ExposureSource, FieldKind, Integrity, ItemDetails, Links,
    LockedVault, LoginMeta, LoginTier, MigrationPlan, MigrationTx, NewLogin, PolicyId,
    ProjectBinding, ProjectKey, ProjectRecord, Slug, Vault, VaultError, VaultErrorKind, VaultPaths,
};
use envcloak_core::{RecoveryKit, SecretBytes};
use envcloak_testkit::{TestHome, fresh_seed};
use rusqlite::types::Value;
use sha2::{Digest, Sha256};

// What generate.rs derived and wrote, derived here again.

const SECRETS: usize = 40;
const FILE_BACKUP: &str = "files-20261003T154737Z-2P951CNXX7XE19N012X0GZV7WH.ecfiles";
const FILE_BACKUP_ID: &str = "2P951CNXX7XE19N012X0GZV7WH";

fn derived(label: &str) -> [u8; 32] {
    Sha256::digest(format!("envcloak/test/m2-07/m1-fixture/{label}").as_bytes()).into()
}

fn vmk() -> Vmk {
    Vmk::import_for_testing(&derived("vmk")).unwrap()
}

fn kit() -> RecoveryKit {
    RecoveryKit::from_bytes_for_testing(&derived("kit")[..16]).unwrap()
}

fn value(n: usize, version: usize) -> String {
    format!("m1 fixture value {n:02} version {version}")
}

fn other(n: usize) -> String {
    format!("m1 fixture other {n:02}")
}

fn file_content(n: usize) -> String {
    format!("M1_FIXTURE_FILE_{n}=m1 fixture file contents {n}\n")
}

fn details(n: usize) -> ItemDetails {
    let pick = |m: usize| n % m == 0;
    ItemDetails {
        title: format!("M1 item {n:02}"),
        provider: pick(2).then(|| "openai".to_owned()),
        account: Account {
            email: pick(3).then(|| format!("dev{n}@example.com")),
            label: pick(4).then(|| format!("label {n}")),
            org_id: pick(5).then(|| format!("org-{n}")),
        },
        env_hint: pick(2).then(|| format!("M1_VAR_{n:02}")),
        classification: match n % 3 {
            0 => Classification::Unknown,
            1 => Classification::Test,
            _ => Classification::Live,
        },
        allowed_hosts: if pick(2) {
            vec!["api.example.com".to_owned(), format!("h{n}.example.com")]
        } else {
            Vec::new()
        },
        allow_short: pick(7),
        tags: (0..n % 3).map(|t| format!("tag-{t}")).collect(),
        links: Links {
            docs: pick(2).then(|| "https://example.com/docs".to_owned()),
            billing: pick(3).then(|| "https://example.com/billing".to_owned()),
            keys_page: pick(4).then(|| "https://example.com/keys".to_owned()),
            dashboard: pick(5).then(|| "https://example.com/dash".to_owned()),
        },
        expires_at: pick(2).then_some(1_900_000_000 + n as u64),
        rotated_at: pick(3).then_some(1_700_000_000 + n as u64),
        last_used_at: pick(4).then_some(1_800_000_000 + n as u64),
        notes: format!("notes for item {n:02}"),
    }
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/m1-vault")
        .join(name)
}

/// An M1 file installed in a test home of its own.
struct M1 {
    home: TestHome,
    paths: VaultPaths,
}

impl M1 {
    /// A test home whose vault is the fixture `name` (`vault.db` or
    /// `vault-policy.db`), with the file backup M1 wrote in `backups/`.
    fn install(name: &str) -> M1 {
        let home = TestHome::new();
        let paths = VaultPaths::under(home.root().join("data"));
        paths.ensure_dirs().unwrap();
        let m = M1 { home, paths };
        m.put_back(name);
        std::fs::create_dir_all(&m.paths.backups_dir).unwrap();
        std::fs::set_permissions(&m.paths.backups_dir, PermissionsExt::from_mode(0o700)).unwrap();
        let backup = m.paths.backups_dir.join(FILE_BACKUP);
        std::fs::copy(fixture(FILE_BACKUP), &backup).unwrap();
        std::fs::set_permissions(&backup, PermissionsExt::from_mode(0o600)).unwrap();
        m
    }

    fn db(&self) -> PathBuf {
        std::fs::canonicalize(&self.paths.vault_dir)
            .unwrap()
            .join("vault.db")
    }

    /// Puts the fixture `name` back as `vault.db`, with no side file.
    fn put_back(&self, name: &str) {
        let db = self.db();
        for side in ["-wal", "-shm", "-journal"] {
            let mut p = db.clone().into_os_string();
            p.push(side);
            let _ = std::fs::remove_file(p);
        }
        std::fs::copy(fixture(name), &db).unwrap();
        std::fs::set_permissions(&db, PermissionsExt::from_mode(0o600)).unwrap();
    }

    fn open(&self, plan: MigrationPlan) -> Result<Vault, (LockedVault, VaultError)> {
        LockedVault::open_with_plan(&self.paths, plan)
            .unwrap()
            .unlock(vmk())
    }

    fn data(&self) -> String {
        self.paths.data_dir.to_str().unwrap().to_owned()
    }

    /// Every row of every vault table, and the schema, through a plain
    /// SQLite connection. Ciphertext only.
    fn dump(&self) -> Vec<(String, Vec<Vec<Value>>)> {
        let raw = rusqlite::Connection::open(self.db()).unwrap();
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

    /// `meta`'s and the header's copies of the schema version.
    fn versions(&self) -> (i64, i64) {
        let raw = rusqlite::Connection::open(self.db()).unwrap();
        raw.query_row(
            "SELECT (SELECT schema_version FROM meta), (SELECT schema_version FROM header)",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
    }
}

/// Every item, value and prior value M1 wrote, and the project, read back
/// from `v`; the version 2 additions read as M1 left them: none.
fn assert_holds_m1(v: &Vault) {
    assert_eq!(v.items().len(), SECRETS + 2);
    for n in 0..SECRETS {
        let m = v
            .find(&Slug::new(&format!("m1/item-{n:02}")).unwrap())
            .unwrap();
        assert_eq!(m.class, ItemClass::Secret);
        assert_eq!(m.details, details(n), "item {n}");
        assert_eq!(m.classification_changed_at, None, "not recorded by M1");
        assert_eq!(m.exposure, None);
        assert!(!m.rotate_recommended);
        assert_eq!(m.login, None);
        let names: Vec<&str> = m.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["other", "value"]);
        for f in &m.fields {
            assert_eq!(f.kind, FieldKind::Value);
            let got = v.read_value(f.id).unwrap();
            if f.name.as_str() == "value" {
                assert!(got.ct_eq(value(n, 1).as_bytes()));
                assert_eq!(f.prior_count, 1);
                assert!(v.read_prior(f.id, 0).unwrap().ct_eq(value(n, 0).as_bytes()));
            } else {
                assert!(got.ct_eq(other(n).as_bytes()));
                assert_eq!(f.prior_count, 0);
            }
        }
    }
    for (class, slug) in [
        (ItemClass::Card, "m1/card"),
        (ItemClass::IssuerCredential, "m1/issuer"),
    ] {
        let m = v.find(&Slug::new(slug).unwrap()).unwrap();
        assert_eq!(m.class, class);
        let got = v.read_value(m.fields[0].id).unwrap();
        assert!(got.ct_eq(format!("m1 fixture {slug}").as_bytes()));
    }
}

fn assert_m1_header_and_project(v: &Vault) {
    let h = v.header().unwrap();
    assert_eq!(h.policy_epoch, 2);
    assert!(h.recovery_confirmed);
    assert_eq!(
        h.audit_head,
        Some(AuditHead {
            seq: 42,
            mac: derived("audit-mac"),
        })
    );
    let key = ProjectKey::new(b"m1 fixture project key").unwrap();
    let (_, p) = v.find_project(&key).unwrap().unwrap();
    assert_eq!(
        *p,
        ProjectRecord {
            key,
            display_path: "/src/m1-fixture".to_owned(),
            manifest_sha256: derived("manifest"),
            bindings: vec![
                ProjectBinding {
                    env_name: "M1_VAR_00".to_owned(),
                    reference: "m1/item-00".to_owned(),
                },
                ProjectBinding {
                    env_name: "M1_OTHER".to_owned(),
                    reference: "m1/item-01#other".to_owned(),
                },
            ],
            last_seen: 1_750_000_000,
        }
    );
}

fn fail_before_commit(_: &MigrationTx<'_>) -> Result<(), VaultError> {
    Err(VaultErrorKind::Migration.into())
}

/// The vault M1 wrote, as a build whose migration failed opens it:
/// read-only at version 1, verified, every value readable, nothing a
/// decision rests on that it cannot type.
fn assert_opens_at_version_1(m: &M1, plan: MigrationPlan) {
    let mut v = m.open(plan).map_err(|(_, e)| e).unwrap();
    assert_eq!(v.migration_error(), Some(VaultErrorKind::Migration));
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_eq!(v.schema_version(), 1);
    assert_holds_m1(&v);
    assert_m1_header_and_project(&v);
    assert_eq!(
        v.policies().err().unwrap().kind(),
        VaultErrorKind::Migration
    );
    let any = v.items()[0].fields[0].id;
    let e = v
        .transact(|t| t.set_value(any, SecretBytes::copy_from(b"refused")))
        .unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::Migration);
}

/// The shipped migration takes M1's vault whole to version 2.
#[test]
fn the_vault_m1_wrote_migrates_whole() {
    let m = M1::install("vault.db");
    let before = m.dump();
    assert_eq!(m.versions(), (1, 1));
    let locked = LockedVault::open(&m.paths).unwrap();
    assert_eq!(locked.schema_version(), 1);
    // The header's write counter as M1 left it, read by a build whose
    // migration fails (which changes nothing; see below).
    drop(locked);
    let counter = {
        let v = m
            .open(MigrationPlan::current().with_hook_before_commit(fail_before_commit))
            .map_err(|(_, e)| e)
            .unwrap();
        v.header().unwrap().write_counter
    };
    assert_eq!(m.dump(), before);

    let v = LockedVault::open(&m.paths)
        .unwrap()
        .unlock(vmk())
        .map_err(|(_, e)| e)
        .unwrap();
    assert_eq!(v.migration_error(), None);
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_eq!(v.schema_version(), 2);
    assert_eq!(v.header().unwrap().write_counter, counter + 1);
    assert_holds_m1(&v);
    assert_m1_header_and_project(&v);
    assert_eq!(v.policies().unwrap().count(), 0);
    let set = v.standing_set().unwrap();
    assert_eq!(set.generation, 0);
    drop(v);
    assert_eq!(m.versions(), (2, 2));

    // Every sealed column was re-sealed: nothing sealed under version 1
    // is left. The plaintext columns are as they were.
    let after = m.dump();
    let table = |d: &[(String, Vec<Vec<Value>>)], t: &str| -> Vec<Vec<Value>> {
        d.iter().find(|(n, _)| n == t).unwrap().1.clone()
    };
    for (t, sealed) in [
        ("header", &[3usize][..]),
        ("items", &[4][..]),
        ("fields", &[3, 4, 6][..]),
        ("projects", &[3][..]),
    ] {
        let (old, new) = (table(&before, t), table(&after, t));
        assert_eq!(old.len(), new.len(), "{t}");
        for (o, n) in old.iter().zip(&new) {
            for (col, (a, b)) in o.iter().zip(n).enumerate() {
                if sealed.contains(&col) && *a != Value::Null {
                    assert_ne!(a, b, "{t} column {col} was not re-sealed");
                } else if !(t == "header" && col == 2) {
                    assert_eq!(a, b, "{t} column {col} changed");
                }
            }
        }
    }
    assert_eq!(table(&before, "unlockers"), table(&after, "unlockers"));
    assert_eq!(
        table(&before, "sqlite_schema"),
        table(&after, "sqlite_schema"),
        "version 2 adds no table or column"
    );

    // Opened again: nothing left to migrate, and the passphrase M1 wrapped
    // still opens it.
    let mut v = LockedVault::open(&m.paths)
        .unwrap()
        .unlock_with_passphrase(&SecretBytes::copy_from(common::PASSPHRASE))
        .map_err(|(_, e)| e)
        .unwrap();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_eq!(v.header().unwrap().write_counter, counter + 1);
    assert_holds_m1(&v);

    // And it is written at version 2 like any vault this build made: a
    // login, a standing approval, an exposure, and a classification
    // changed, which is recorded from then on (M1 recorded none); an edit
    // that keeps the classification records nothing.
    let first = v.items()[0].id;
    let (second, third) = (v.items()[1].clone(), v.items()[2].clone());
    let login = v
        .transact(|t| {
            t.put_policy(PolicyId::generate(), &standing_record(1))?;
            t.mark_exposed(first, &[ExposureSource::GitHistory], 2)?;
            let other = match second.details.classification {
                Classification::Live => Classification::Test,
                _ => Classification::Live,
            };
            t.update_item(
                second.id,
                ItemDetails {
                    classification: other,
                    ..second.details.clone()
                },
            )?;
            t.update_item(
                third.id,
                ItemDetails {
                    title: "renamed".into(),
                    ..third.details.clone()
                },
            )?;
            t.create_login(NewLogin {
                slug: Slug::new("m1/login").unwrap(),
                details: ItemDetails {
                    classification: Classification::Test,
                    ..ItemDetails::default()
                },
                meta: LoginMeta {
                    tier: LoginTier::Dev,
                    session_lifetime: 600,
                },
                username: SecretBytes::copy_from(b"editor"),
                password: SecretBytes::copy_from(b"m1 fixture login password"),
                totp: None,
                adapter_key: None,
            })
        })
        .unwrap();
    assert_eq!(v.standing_set().unwrap().generation, 1);
    drop(v);
    let v = LockedVault::open(&m.paths)
        .unwrap()
        .unlock(vmk())
        .map_err(|(_, e)| e)
        .unwrap();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_eq!(v.item(login).unwrap().class, ItemClass::Login);
    assert_eq!(v.policies().unwrap().count(), 1);
    assert_eq!(v.standing_set().unwrap().generation, 1);
    assert!(v.item(first).unwrap().rotate_recommended);
    let changed = v.item(second.id).unwrap();
    assert_eq!(changed.classification_changed_at, Some(changed.updated_at));
    assert_eq!(v.item(third.id).unwrap().classification_changed_at, None);
}

/// Gate 7 on the shipped migration: a failure inside its transaction,
/// after every row was rewritten and the header written, leaves the vault
/// M1 wrote exactly as it was, and openable, by this build too (read-only,
/// at version 1). Every open tries again, and a build whose migration
/// works then migrates it.
#[test]
fn a_failure_inside_the_migration_leaves_the_m1_vault_intact() {
    let m = M1::install("vault.db");
    let before = m.dump();
    for _ in 0..2 {
        assert_opens_at_version_1(
            &m,
            MigrationPlan::current().with_hook_before_commit(fail_before_commit),
        );
        assert_eq!(m.dump(), before, "the failed migration changed the file");
        assert_eq!(m.versions(), (1, 1));
    }
    let v = m
        .open(MigrationPlan::current())
        .map_err(|(_, e)| e)
        .unwrap();
    assert_eq!(v.migration_error(), None);
    assert_eq!(v.schema_version(), 2);
    assert_holds_m1(&v);
}

/// A policy row M1's format holds has no type to give it: the migration
/// refuses it rather than drop it or read it as some record. The vault
/// stays M1's, read-only at version 1, every value readable, and no policy
/// served.
#[test]
fn an_m1_policy_row_fails_the_migration_and_changes_nothing() {
    let m = M1::install("vault-policy.db");
    let before = m.dump();
    assert_opens_at_version_1(&m, MigrationPlan::current());
    assert_eq!(m.dump(), before);
    assert_eq!(m.versions(), (1, 1));
}

const MIGRATOR: &str = "ENVCLOAK_M1_MIGRATOR";
/// Set for the child: the migration stops inside its transaction, prints
/// `@@in-migration` and waits to be killed.
const HOLD: &str = "ENVCLOAK_M1_MIGRATOR_HOLD";

fn hold_before_commit(_: &MigrationTx<'_>) -> Result<(), VaultError> {
    if std::env::var_os(HOLD).is_some() {
        println!("@@in-migration");
        std::thread::sleep(Duration::from_secs(60));
    }
    Ok(())
}

/// Runs only as the child of the test below: opens the vault with the
/// shipped plan, which migrates it.
#[test]
fn m1_migration_child() {
    let Some(dir) = std::env::var_os(MIGRATOR) else {
        return;
    };
    let vmk = Vmk::import_for_testing(&read_stdin()).unwrap();
    println!("@@start");
    let v = LockedVault::open_with_plan(
        &VaultPaths::under(dir),
        MigrationPlan::current().with_hook_before_commit(hold_before_commit),
    )
    .unwrap()
    .unlock(vmk)
    .map_err(|(_, e)| e)
    .unwrap();
    assert_eq!(v.schema_version(), 2);
    println!("@@migrated");
    std::thread::sleep(Duration::from_secs(60));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Left {
    Old,
    New,
}

/// Which vault a killed migration left: exactly M1's, row for row, or the
/// migrated one, whole.
fn left_by_kill(m: &M1, before: &[(String, Vec<Vec<Value>>)], ctx: &str) -> Left {
    // Opened by a build whose migration fails: a vault still at version 1
    // stays as it is, and one at version 2 has nothing to migrate.
    let v = m
        .open(MigrationPlan::current().with_hook_before_commit(fail_before_commit))
        .map_err(|(_, e)| e)
        .unwrap();
    assert_eq!(v.integrity(), Integrity::Ok, "{ctx}");
    let left = match v.schema_version() {
        1 => Left::Old,
        2 => Left::New,
        other => panic!("{ctx}: schema version {other}"),
    };
    assert_holds_m1(&v);
    drop(v);
    if left == Left::Old {
        assert_eq!(m.dump(), before, "{ctx}: the M1 vault changed");
    }
    left
}

/// Gate 7's crash half on the shipped migration (F-25): the child is held
/// inside the migration's transaction, after every row was re-sealed and
/// the header written, and killed there: M1's vault is left, row for row.
/// Held after the commit and killed: the migrated one. Neither depends on
/// when the kill lands. Kills at random moments within a measured
/// migration add coverage, each leaving one vault or the other.
#[test]
fn kill_9_during_the_migration_leaves_the_m1_vault_or_the_migrated_one() {
    let seed = fresh_seed();
    let mut rng = Rng(seed);
    let m = M1::install("vault.db");
    let before = m.dump();
    let start = |hold: bool| {
        m.put_back("vault.db");
        let data = m.data();
        let mut env = vec![(MIGRATOR, data.as_str())];
        if hold {
            env.push((HOLD, "1"));
        }
        let mut child = spawn_self(&m.home, "m1_migration_child", &env, &derived("vmk"));
        let out = BufReader::new(child.stdout.take().unwrap());
        (child, out)
    };

    for round in 0..3 {
        let (mut child, mut out) = start(true);
        assert!(
            wait_for(&mut out, "@@in-migration").is_some(),
            "held round {round}: the child did not reach the migration"
        );
        kill_child(&mut child, "migration");
        let ctx = format!("killed inside the migration, round {round}");
        assert_eq!(left_by_kill(&m, &before, &ctx), Left::Old, "{ctx}");
    }

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
    assert_eq!(left_by_kill(&m, &before, ctx), Left::New, "{ctx}");

    let (mut old, mut new) = (0, 0);
    for round in 0..10 {
        let (mut child, mut out) = start(false);
        assert!(wait_for(&mut out, "@@start").is_some(), "round {round}");
        let us = rng.below(window.as_micros() as u64 * 5 / 4 + 1);
        std::thread::sleep(Duration::from_micros(us));
        kill_child(&mut child, "migration");
        match left_by_kill(&m, &before, &format!("seed {seed}: round {round}")) {
            Left::Old => old += 1,
            Left::New => new += 1,
        }
    }
    println!("random kills (seed {seed}): {old} left the M1 vault, {new} the migrated one");
}

/// K-12's kill criterion, F-22: a Recovery Kit backup M1 wrote restores
/// with this build, where no vault is and over the vault in place (the
/// same vault, already migrated). The image is checked against its
/// manifest as it was backed up (version 1), then migrated, and the
/// restored vault verifies at version 2 under the new passphrase.
#[test]
fn a_backup_m1_wrote_restores_with_this_build() {
    let new_pass = SecretBytes::copy_from(b"a new passphrase for the m1 restore");
    // No vault in place.
    let home = TestHome::new();
    let paths = VaultPaths::under(home.root().join("data"));
    let (v, report) = envcloak_core::backup::restore_backup_observed(
        &paths,
        &fixture("backup.ecbackup"),
        &kit(),
        &new_pass,
        &KdfParams::minimum(),
        &mut |_| {},
    )
    .unwrap();
    assert_eq!(v.schema_version(), 2);
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_eq!(report.items, SECRETS + 2);
    assert_holds_m1(&v);
    assert_m1_header_and_project(&v);
    drop(v);
    let v = LockedVault::open(&paths)
        .unwrap()
        .unlock_with_passphrase(&new_pass)
        .map_err(|(_, e)| e)
        .unwrap();
    assert_eq!(v.schema_version(), 2);
    assert_holds_m1(&v);
    drop(v);

    // Over the same vault, which this build has migrated meanwhile.
    let m = M1::install("vault.db");
    drop(
        m.open(MigrationPlan::current())
            .map_err(|(_, e)| e)
            .unwrap(),
    );
    assert_eq!(m.versions(), (2, 2));
    let (v, report) = envcloak_core::backup::restore_backup_observed(
        &m.paths,
        &fixture("backup.ecbackup"),
        &kit(),
        &new_pass,
        &KdfParams::minimum(),
        &mut |_| {},
    )
    .unwrap();
    assert_eq!(v.schema_version(), 2);
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_holds_m1(&v);
    assert!(
        !report.replaced.is_empty(),
        "the migrated vault was kept aside"
    );
}

/// `init --undo` across the migration: the file backup M1's `init` wrote
/// still opens once the vault is at version 2, whole, with who made it and
/// what the deletion left of each file.
#[test]
fn an_init_file_backup_m1_wrote_opens_after_the_migration() {
    let m = M1::install("vault.db");
    let v = m
        .open(MigrationPlan::current())
        .map_err(|(_, e)| e)
        .unwrap();
    assert_eq!(v.schema_version(), 2);
    let id = FileBackupId::parse(FILE_BACKUP_ID).unwrap();
    let opened = v.open_file_backup(&id).unwrap();
    let creator = opened.creator.unwrap();
    assert_eq!((creator.kind, creator.agent), (CreatorKind::Terminal, None));
    assert_eq!(opened.files.len(), 2);
    let want = [
        ("/src/m1-fixture/.env", 0o600, FileLeft::Removed),
        (
            "/src/m1-fixture/.env.local",
            0o640,
            FileLeft::Rewritten(derived("rewritten")),
        ),
    ];
    for (n, (f, (path, mode, left))) in opened.files.iter().zip(want).enumerate() {
        assert_eq!(f.path, path);
        assert_eq!(f.mode, mode);
        assert_eq!(f.left, Some(left));
        assert!(f.content.ct_eq(file_content(n).as_bytes()));
    }
}
