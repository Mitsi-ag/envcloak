//! Schema migrations (SPEC §15.2 gate 7).
//!
//! The associated data of every sealed value includes the schema version,
//! so a migration re-seals every sealed column under the new version. It
//! runs at unlock, when the key is available, and only on a vault that
//! passed its integrity check. All of it, from the first step's DDL to the
//! rewritten header, is one SQLite transaction: a failure at any point, or
//! a crash, leaves the vault at its old version, intact and openable. After
//! a failure the unlock still succeeds, read-only at the old version
//! ([`Vault::migration_error`](super::Vault::migration_error)).
//!
//! Each step moves the vault from `from` to `from + 1`:
//! 1. its DDL runs;
//! 2. every sealed column (header, items, fields, projects, policies) is
//!    re-sealed from the old version to the new one;
//! 3. its `transform` rewrites data as the new version needs.
//!
//! Then `meta.schema_version` is set, the schema is compared with the
//! expected one, the state digest is recomputed from the migrated rows and
//! the header, with its copy of the schema version, is written, and the
//! transaction commits.
//!
//! A step whose target version reads other record layouts than its source
//! rewrites them while it re-seals them: the step from 1 to 2 turns every
//! item record and field record into version 2 (docs/VAULT.md "Schema
//! version 2"), and writes the header as version 2 with an empty standing
//! set. Version 1 policy rows have no type, so that step refuses a vault
//! that holds one: the migration fails, nothing is written, and the vault
//! opens read-only at version 1, as any failed migration leaves it.
//!
//! Unlock's check and the migration are separate transactions, and another
//! program can write the file between them. So the page cache is dropped
//! before the migration's transaction begins, and inside it, before
//! anything is written, every row's stamp is read again and must equal the
//! stamps unlock verified. A row deleted, added or changed in between is
//! never re-sealed into a state the new header vouches for: the migration
//! stops with [`VaultErrorKind::Tampered`], nothing is written, and the
//! vault opens read-only at its old version, reporting
//! [`TamperKind::ChangedWhileOpen`](super::TamperKind::ChangedWhileOpen).
//!
//! The shipped plan has one step, from 1 to 2 (plan decision D-08: the one
//! migration of M2 and M2b); later record changes are record versions.

use std::collections::BTreeMap;

use rusqlite::{Connection, Transaction, TransactionBehavior, params};

use crate::crypto::{FieldTag, ItemClass, Keyring, Purpose, TableTag};

use super::error::{VaultError, VaultErrorKind};
use super::integrity::{HeaderState, RowKey, Stamp};
use super::items::{
    FieldRecord, ItemExtra, RECORDS_V2_FROM, decode_field, decode_item, encode_field, encode_item,
};
use super::policies::{StandingSetHeader, standing_set_digest};
use super::schema::{CURRENT_SCHEMA, drop_page_cache, verify_schema};
use super::state::{VaultCtx, item_class_from, item_key, scan_stamps};
use super::values::{reseal, reseal_record, seal_record};

/// The schema version the first format had.
const FIRST_SCHEMA: u16 = 1;

/// The step from schema version 1 to 2. It adds no table or column: the
/// records' new layouts are written by the re-sealing (see the module
/// documentation), so its own transform has nothing left to do.
const TO_V2: Migration = Migration {
    from: FIRST_SCHEMA,
    ddl: "",
    transform: no_transform,
};

fn no_transform(_: &MigrationTx<'_>) -> Result<(), VaultError> {
    Ok(())
}

/// One step, from schema version `from` to `from + 1`.
#[derive(Clone, Copy)]
pub struct Migration {
    pub from: u16,
    /// Run first, in the migration transaction.
    pub ddl: &'static str,
    /// Run after every sealed column has been re-sealed under `from + 1`.
    pub transform: fn(&MigrationTx<'_>) -> Result<(), VaultError>,
}

impl core::fmt::Debug for Migration {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Migration")
            .field("from", &self.from)
            .finish_non_exhaustive()
    }
}

/// The steps that bring a vault to `target`.
#[derive(Debug, Clone)]
pub struct MigrationPlan {
    target: u16,
    steps: Vec<Migration>,
    /// Test support only: called with the vault's paths after unlock
    /// verified the vault and before its migration begins.
    #[cfg(feature = "testing")]
    before_migration: Option<fn(&super::VaultPaths)>,
    /// Test support only: called inside the migration's transaction after
    /// every step ran and the header was written, before the commit.
    #[cfg(feature = "testing")]
    before_commit: Option<BeforeCommit>,
}

/// Test support only: what [`MigrationPlan::with_hook_before_commit`]
/// calls.
#[cfg(feature = "testing")]
pub type BeforeCommit = fn(&MigrationTx<'_>) -> Result<(), VaultError>;

impl MigrationPlan {
    /// The plan this build ships: to [`CURRENT_SCHEMA`].
    pub fn current() -> Self {
        MigrationPlan {
            target: CURRENT_SCHEMA,
            steps: vec![TO_V2],
            #[cfg(feature = "testing")]
            before_migration: None,
            #[cfg(feature = "testing")]
            before_commit: None,
        }
    }

    /// The shipped plan, then `steps`: a plan to `CURRENT_SCHEMA +
    /// steps.len()`. Step `i` must migrate from `CURRENT_SCHEMA + i`.
    pub fn new(steps: Vec<Migration>) -> Result<Self, VaultError> {
        let mut plan = MigrationPlan::current();
        for s in steps {
            if s.from != plan.target {
                return Err(VaultErrorKind::Migration.into());
            }
            plan.target = plan
                .target
                .checked_add(1)
                .ok_or(VaultErrorKind::Migration)?;
            plan.steps.push(s);
        }
        Ok(plan)
    }

    /// Test support only: calls `f` inside the migration's transaction
    /// once every step ran and the header was written, before the commit:
    /// an error it returns fails the migration there, and a test can stop
    /// the process at that point (gate 7, F-25).
    #[cfg(feature = "testing")]
    pub fn with_hook_before_commit(mut self, f: BeforeCommit) -> Self {
        self.before_commit = Some(f);
        self
    }

    /// Test support only: calls `f` with the vault's paths after unlock
    /// has verified the vault and before the migration begins, as another
    /// program writing the file between the two would.
    #[cfg(feature = "testing")]
    pub fn with_hook_before_migration(mut self, f: fn(&super::VaultPaths)) -> Self {
        self.before_migration = Some(f);
        self
    }

    /// The hook [`MigrationPlan::with_hook_before_migration`] set.
    #[cfg(feature = "testing")]
    pub(crate) fn before_migration(&self) -> Option<fn(&super::VaultPaths)> {
        self.before_migration
    }

    pub fn target(&self) -> u16 {
        self.target
    }

    pub fn steps(&self) -> &[Migration] {
        &self.steps
    }
}

/// What a step's `transform` can do: run SQL without bound parameters in
/// the migration transaction.
pub struct MigrationTx<'a> {
    tx: &'a Transaction<'a>,
    version: u16,
}

impl MigrationTx<'_> {
    /// The version the vault is being migrated to.
    pub fn version(&self) -> u16 {
        self.version
    }

    /// Runs `sql`; returns the number of rows changed. Errors carry their
    /// kind only.
    pub fn execute(&self, sql: &str) -> Result<usize, VaultError> {
        Ok(self.tx.execute(sql, [])?)
    }
}

impl core::fmt::Debug for MigrationTx<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MigrationTx")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

/// Migrates the vault at `ctx` (its on-disk version, integrity verified,
/// `header` its opened header, `verified` the stamps of the rows unlock
/// verified) to `plan.target()`. Every failure rolls back and becomes
/// [`VaultErrorKind::Migration`], except a busy or full disk, which keep
/// their kinds, and rows that are no longer the ones verified
/// ([`VaultErrorKind::Tampered`]; see the module documentation).
pub(crate) fn run(
    conn: &mut Connection,
    keys: &Keyring,
    ctx: &VaultCtx,
    header: &HeaderState,
    verified: &BTreeMap<RowKey, Stamp>,
    plan: &MigrationPlan,
) -> Result<(), VaultError> {
    let as_migration = |e: VaultError| match e.kind() {
        VaultErrorKind::Busy | VaultErrorKind::DiskFull | VaultErrorKind::Tampered => e,
        _ => VaultErrorKind::Migration.into(),
    };
    // Read the file as it is now, not pages cached while unlock read it.
    drop_page_cache(conn).map_err(as_migration)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(VaultError::from)
        .map_err(as_migration)?;
    migrate_in(&tx, keys, ctx, header, verified, plan).map_err(as_migration)?;
    tx.commit().map_err(VaultError::from).map_err(as_migration)
}

fn migrate_in(
    tx: &Transaction<'_>,
    keys: &Keyring,
    ctx: &VaultCtx,
    header: &HeaderState,
    verified: &BTreeMap<RowKey, Stamp>,
    plan: &MigrationPlan,
) -> Result<(), VaultError> {
    // Nothing is re-sealed unless every row is the one unlock verified. A
    // malformed row cannot have verified either.
    let now = scan_stamps(tx).map_err(|e| match e.kind() {
        VaultErrorKind::Damaged => VaultErrorKind::Tampered.into(),
        _ => e,
    })?;
    if now != *verified {
        return Err(VaultErrorKind::Tampered.into());
    }
    let mut version = ctx.schema_version;
    for step in plan.steps.iter().filter(|s| s.from >= ctx.schema_version) {
        if step.from != version {
            return Err(VaultErrorKind::Migration.into());
        }
        tx.execute_batch(step.ddl)?;
        let from = VaultCtx {
            schema_version: version,
            ..*ctx
        };
        version += 1;
        let to = VaultCtx {
            schema_version: version,
            ..from
        };
        reseal_rows(tx, keys, &from, &to)?;
        (step.transform)(&MigrationTx { tx, version })?;
    }
    if version != plan.target {
        return Err(VaultErrorKind::Migration.into());
    }
    tx.execute("UPDATE meta SET schema_version = ?1", params![version])?;
    if !verify_schema(tx, version, plan)? {
        return Err(VaultErrorKind::Migration.into());
    }
    let to = VaultCtx {
        schema_version: version,
        ..*ctx
    };
    let stamps = scan_stamps(tx)?;
    // A vault that comes from version 1 has no standing set yet: its header
    // starts one, at generation 0, over the empty set. A later step keeps
    // the set it has (re-sealing changes no record).
    let standing_set = if ctx.schema_version < RECORDS_V2_FROM {
        StandingSetHeader {
            generation: 0,
            set_digest: standing_set_digest(keys, core::iter::empty()),
        }
    } else {
        header.standing_set
    };
    let next = HeaderState {
        write_counter: header.write_counter + 1,
        state_digest: super::integrity::state_digest(keys, &stamps),
        standing_set,
        ..*header
    };
    let sealed = seal_record(keys.key(Purpose::Header), &to.header_aad(), &next.encode())?;
    let n = tx.execute(
        "UPDATE header SET sealed = ?1, schema_version = ?2 WHERE epoch = ?3",
        params![sealed, version, ctx.epoch],
    )?;
    if n != 1 {
        return Err(VaultErrorKind::Migration.into());
    }
    #[cfg(feature = "testing")]
    if let Some(f) = plan.before_commit {
        f(&MigrationTx { tx, version })?;
    }
    Ok(())
}

/// Re-seals every sealed row column (items, fields, projects, policies)
/// from `from`'s schema version to `to`'s, rewriting the item and field
/// records into the layout `to` reads when it is another than `from`'s.
/// The header is sealed afresh, at the target version, once every step has
/// run.
fn reseal_rows(
    tx: &Transaction<'_>,
    keys: &Keyring,
    from: &VaultCtx,
    to: &VaultCtx,
) -> Result<(), VaultError> {
    let fail = |_| VaultError::from(VaultErrorKind::Migration);
    let upgrade = from.schema_version < RECORDS_V2_FROM && to.schema_version >= RECORDS_V2_FROM;
    let migration = |_| VaultError::from(VaultErrorKind::Migration);

    // Version 1 policy rows have no type to give them (module
    // documentation): refused, never dropped and never typed by guess.
    if upgrade {
        let policies: i64 = tx.query_row("SELECT count(*) FROM policies", [], |r| r.get(0))?;
        if policies != 0 {
            return Err(VaultErrorKind::Migration.into());
        }
    }

    // Items, and each item's class for its fields.
    let mut classes = std::collections::BTreeMap::new();
    let items: Vec<(Vec<u8>, i64, i64, Vec<u8>)> = collect(
        tx,
        "SELECT id, row_version, class, sealed_meta FROM items",
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    for (id, rv, class, sealed) in items {
        let (id16, rv) = (id16(&id)?, rv_u64(rv)?);
        let class = item_class_from(class, from.schema_version).ok_or(VaultErrorKind::Migration)?;
        classes.insert(id16, class);
        let k = item_key(keys, class);
        let a = |c: &VaultCtx| c.aad(TableTag::Items, &id16, FieldTag::ItemMeta, class, rv);
        let new = if upgrade {
            // Version 1 to 2: what version 1 does not record starts empty;
            // in particular the classification's last change is not known.
            reseal_record(k, &a(from), &a(to), &sealed, |b| {
                let (slug, created_at, details, _) =
                    decode_item(b, from.schema_version, class).map_err(migration)?;
                Ok(encode_item(
                    &slug,
                    created_at,
                    &details,
                    &ItemExtra::default(),
                ))
            })?
        } else {
            reseal(k, &a(from), &a(to), &sealed).map_err(fail)?
        };
        tx.execute(
            "UPDATE items SET sealed_meta = ?1 WHERE id = ?2",
            params![new, id],
        )?;
    }

    type FieldRow = (Vec<u8>, Vec<u8>, i64, Vec<u8>, Vec<u8>, Option<Vec<u8>>);
    let fields: Vec<FieldRow> = collect(
        tx,
        "SELECT id, item_id, row_version, sealed_name, sealed_value, sealed_prior FROM fields",
        |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
            ))
        },
    )?;
    for (id, item_id, rv, name, value, prior) in fields {
        let item = id16(&item_id)?;
        let (id16, rv) = (id16(&id)?, rv_u64(rv)?);
        let class = *classes.get(&item).ok_or(VaultErrorKind::Migration)?;
        let k = item_key(keys, class);
        let a = |c: &VaultCtx, f| c.aad(TableTag::Fields, &id16, f, class, rv);
        let name = if upgrade {
            // Version 1 to 2: every field of version 1 holds a value.
            reseal_record(
                k,
                &a(from, FieldTag::FieldName),
                &a(to, FieldTag::FieldName),
                &name,
                |b| {
                    let r: FieldRecord = decode_field(b, from.schema_version).map_err(migration)?;
                    Ok(encode_field(&r))
                },
            )?
        } else {
            reseal(
                k,
                &a(from, FieldTag::FieldName),
                &a(to, FieldTag::FieldName),
                &name,
            )
            .map_err(fail)?
        };
        let value = reseal(
            k,
            &a(from, FieldTag::FieldValue),
            &a(to, FieldTag::FieldValue),
            &value,
        )
        .map_err(fail)?;
        let prior = match prior {
            None => None,
            Some(p) => Some(
                reseal(
                    k,
                    &a(from, FieldTag::FieldPrior),
                    &a(to, FieldTag::FieldPrior),
                    &p,
                )
                .map_err(fail)?,
            ),
        };
        tx.execute(
            "UPDATE fields SET sealed_name = ?1, sealed_value = ?2, sealed_prior = ?3 WHERE id = ?4",
            params![name, value, prior, id],
        )?;
    }

    for (tag, field, sql_get, sql_set) in [
        (
            TableTag::Projects,
            FieldTag::Project,
            "SELECT id, row_version, sealed FROM projects",
            "UPDATE projects SET sealed = ?1 WHERE id = ?2",
        ),
        (
            TableTag::Policies,
            FieldTag::Policy,
            "SELECT id, row_version, sealed FROM policies",
            "UPDATE policies SET sealed = ?1 WHERE id = ?2",
        ),
    ] {
        let rows: Vec<(Vec<u8>, i64, Vec<u8>)> =
            collect(tx, sql_get, |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        let k = keys.key(Purpose::Data);
        for (id, rv, sealed) in rows {
            let (id16, rv) = (id16(&id)?, rv_u64(rv)?);
            let a = |c: &VaultCtx| c.aad(tag, &id16, field, ItemClass::None, rv);
            let new = reseal(k, &a(from), &a(to), &sealed).map_err(fail)?;
            tx.execute(sql_set, params![new, id])?;
        }
    }
    Ok(())
}

fn collect<T>(
    tx: &Transaction<'_>,
    sql: &str,
    f: impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
) -> Result<Vec<T>, VaultError> {
    let mut st = tx.prepare(sql)?;
    let rows = st.query_map([], f)?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

fn id16(b: &[u8]) -> Result<[u8; 16], VaultError> {
    b.try_into()
        .map_err(|_| VaultError::from(VaultErrorKind::Migration))
}

fn rv_u64(v: i64) -> Result<u64, VaultError> {
    u64::try_from(v).map_err(|_| VaultError::from(VaultErrorKind::Migration))
}
