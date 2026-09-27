//! The SQLite schema and connection settings (SPEC §5 "Vault"; see
//! docs/VAULT.md).
//!
//! Every connection EnvCloak opens on a vault file:
//! - refuses a symlinked database path (`SQLITE_OPEN_NOFOLLOW`);
//! - runs with the defensive flag on, triggers and views disabled, the
//!   schema untrusted, and `ATTACH` unable to create or write files, so a
//!   vault file altered by another program cannot make EnvCloak's own
//!   statements do anything else;
//! - holds an exclusive lock for as long as it is open
//!   (`locking_mode=EXCLUSIVE`): a second EnvCloak process, or any other
//!   SQLite client, gets "busy" instead of reading or writing, and SQLite
//!   keeps its WAL index in process memory, so there is no `-shm` file;
//! - uses WAL with `synchronous=FULL`, `secure_delete=ON`,
//!   `temp_store=MEMORY` and, on macOS, `fullfsync=ON` and
//!   `checkpoint_fullfsync=ON`, because a plain `fsync` there does not flush
//!   the drive's cache.
//!
//! [`verify_schema`] compares the file's `sqlite_schema` with the schema
//! this build expects, so an added trigger, view, table or index shows up
//! as tampering.

use std::path::Path;
use std::time::Duration;

use rusqlite::config::DbConfig;
use rusqlite::{Connection, OpenFlags};

use super::error::{VaultError, VaultErrorKind};
use super::migrate::MigrationPlan;

/// The schema version this build writes.
pub const CURRENT_SCHEMA: u16 = 1;

/// `PRAGMA application_id` of a vault file: "ECV1".
pub(crate) const APPLICATION_ID: i32 = 0x4543_5631;

/// Schema version 1 (SPEC §5; docs/VAULT.md). Plaintext columns hold only
/// opaque ids, row versions, timestamps, kinds and keyed hashes; `sealed*`
/// columns hold XChaCha20-Poly1305 output. The vault id is kept in `meta`,
/// the header and every unlocker, and the schema version in `meta` and the
/// header, so one deleted or altered row does not stop the vault opening.
pub(crate) const SCHEMA_V1: &str = "\
CREATE TABLE meta (
  vault_id BLOB NOT NULL,
  schema_version INTEGER NOT NULL,
  created_at INTEGER NOT NULL
) STRICT;
CREATE TABLE header (
  epoch INTEGER NOT NULL,
  vault_id BLOB NOT NULL,
  schema_version INTEGER NOT NULL,
  sealed BLOB NOT NULL
) STRICT;
CREATE TABLE unlockers (
  id BLOB PRIMARY KEY NOT NULL,
  vault_id BLOB NOT NULL,
  kind INTEGER NOT NULL,
  envelope BLOB NOT NULL,
  created_at INTEGER NOT NULL
) STRICT;
CREATE TABLE items (
  id BLOB PRIMARY KEY NOT NULL,
  row_version INTEGER NOT NULL,
  class INTEGER NOT NULL,
  slug_hash BLOB NOT NULL UNIQUE,
  sealed_meta BLOB NOT NULL,
  updated_at INTEGER NOT NULL
) STRICT;
CREATE TABLE fields (
  id BLOB PRIMARY KEY NOT NULL,
  item_id BLOB NOT NULL,
  row_version INTEGER NOT NULL,
  sealed_name BLOB NOT NULL,
  sealed_value BLOB NOT NULL,
  value_hash BLOB NOT NULL,
  sealed_prior BLOB
) STRICT;
CREATE TABLE projects (
  id BLOB PRIMARY KEY NOT NULL,
  row_version INTEGER NOT NULL,
  dir_hash BLOB NOT NULL UNIQUE,
  sealed BLOB NOT NULL
) STRICT;
CREATE TABLE policies (
  id BLOB PRIMARY KEY NOT NULL,
  row_version INTEGER NOT NULL,
  sealed BLOB NOT NULL
) STRICT;
";

/// Opens a vault database file and applies [`configure`]. `create` allows
/// SQLite to create the file (used only for the temporary file `create`
/// builds before linking it into place).
pub(crate) fn open_db(path: &Path, create: bool) -> Result<Connection, VaultError> {
    let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW
        | OpenFlags::SQLITE_OPEN_EXRESCODE;
    if create {
        flags |= OpenFlags::SQLITE_OPEN_CREATE;
    }
    let conn = Connection::open_with_flags(path, flags)?;
    harden_connection(&conn)?;
    Ok(conn)
}

/// The per-connection flags that keep an altered file from steering
/// EnvCloak's statements.
fn harden_connection(conn: &Connection) -> Result<(), VaultError> {
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_VIEW, false)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DQS_DML, false)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DQS_DDL, false)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_ATTACH_CREATE, false)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_ATTACH_WRITE, false)?;
    conn.busy_timeout(Duration::ZERO)?;
    Ok(())
}

/// Takes the exclusive lock and applies the durability settings. `wal`
/// selects WAL; `create` builds its temporary file in rollback-journal
/// mode, so the finished file needs no side files when it is linked into
/// place.
pub(crate) fn configure(conn: &Connection, wal: bool) -> Result<(), VaultError> {
    conn.pragma_update(None, "locking_mode", "EXCLUSIVE")?;
    let mode = if wal { "wal" } else { "delete" };
    let got: String = conn.pragma_update_and_check(None, "journal_mode", mode, |r| r.get(0))?;
    if !got.eq_ignore_ascii_case(mode) {
        return Err(VaultErrorKind::Storage(-1).into());
    }
    conn.pragma_update(None, "synchronous", "FULL")?;
    conn.pragma_update(None, "secure_delete", "ON")?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    conn.pragma_update(None, "cell_size_check", "ON")?;
    conn.pragma_update(None, "foreign_keys", "OFF")?;
    if cfg!(target_os = "macos") {
        conn.pragma_update(None, "fullfsync", "ON")?;
        conn.pragma_update(None, "checkpoint_fullfsync", "ON")?;
    }
    Ok(())
}

/// Drops every page SQLite has cached for `conn`, so the next read comes
/// from the file (or from the WAL this connection wrote). Fails inside a
/// transaction, where pages in use would stay cached.
///
/// Under `locking_mode=EXCLUSIVE` SQLite never checks the file for a change
/// another program made, and the lock does not stop a program that writes
/// the file directly. A page cached before such a change would hide it
/// from unlock, and a commit to another row on that page would write the
/// cached copy back over it, erasing the change unreported. Every unlock
/// and every write transaction therefore starts here.
///
/// The bundled SQLite keeps one page cache for all connections in the
/// process (`SQLITE_ENABLE_MEMORY_MANAGEMENT`), so this also drops other
/// connections' unused pages: a cost for them, never a change in what they
/// read.
pub(crate) fn drop_page_cache(conn: &Connection) -> Result<(), VaultError> {
    if !conn.is_autocommit() {
        return Err(VaultErrorKind::Storage(-1).into());
    }
    conn.execute_batch("PRAGMA shrink_memory")?;
    Ok(())
}

/// The settings in effect on a vault connection, read back from SQLite.
/// Value-free; for `status` and tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageReport {
    pub journal_mode: String,
    pub locking_mode: String,
    /// 2 is FULL.
    pub synchronous: i64,
    pub secure_delete: bool,
    /// 2 is MEMORY.
    pub temp_store: i64,
    pub fullfsync: bool,
    pub checkpoint_fullfsync: bool,
    pub defensive: bool,
    pub trusted_schema: bool,
    pub triggers_enabled: bool,
    pub views_enabled: bool,
}

pub(crate) fn storage_report(conn: &Connection) -> Result<StorageReport, VaultError> {
    let text = |name: &str| -> Result<String, VaultError> {
        Ok(conn.pragma_query_value(None, name, |r| r.get::<_, String>(0))?)
    };
    let int = |name: &str| -> Result<i64, VaultError> {
        Ok(conn.pragma_query_value(None, name, |r| r.get::<_, i64>(0))?)
    };
    Ok(StorageReport {
        journal_mode: text("journal_mode")?,
        locking_mode: text("locking_mode")?,
        synchronous: int("synchronous")?,
        secure_delete: int("secure_delete")? == 1,
        temp_store: int("temp_store")?,
        fullfsync: int("fullfsync")? == 1,
        checkpoint_fullfsync: int("checkpoint_fullfsync")? == 1,
        defensive: conn.db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE)?,
        trusted_schema: conn.db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA)?,
        triggers_enabled: conn.db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER)?,
        views_enabled: conn.db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_VIEW)?,
    })
}

/// One row of `sqlite_schema`, without its root page.
pub(crate) type SchemaObject = (String, String, String, Option<String>);

fn read_schema(conn: &Connection) -> Result<Vec<SchemaObject>, VaultError> {
    let mut st = conn.prepare(
        "SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name, tbl_name",
    )?;
    let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

/// The objects a vault at `version` must hold: version 1's schema, then the
/// DDL of every step of `plan` below `version`, run on an empty in-memory
/// database.
pub(crate) fn expected_schema(
    version: u16,
    plan: &MigrationPlan,
) -> Result<Vec<SchemaObject>, VaultError> {
    let mem = Connection::open_in_memory()?;
    harden_connection(&mem)?;
    mem.execute_batch(SCHEMA_V1)?;
    for step in plan.steps() {
        if step.from < version {
            mem.execute_batch(step.ddl)?;
        }
    }
    read_schema(&mem)
}

/// Whether the file's schema is exactly [`expected_schema`].
pub(crate) fn verify_schema(
    conn: &Connection,
    version: u16,
    plan: &MigrationPlan,
) -> Result<bool, VaultError> {
    Ok(read_schema(conn)? == expected_schema(version, plan)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_v1_is_strict_and_has_no_secondary_objects_beyond_its_keys() {
        let objects = expected_schema(1, &MigrationPlan::current()).unwrap();
        let tables: Vec<&str> = objects
            .iter()
            .filter(|o| o.0 == "table")
            .map(|o| o.1.as_str())
            .collect();
        assert_eq!(
            tables,
            [
                "fields",
                "header",
                "items",
                "meta",
                "policies",
                "projects",
                "unlockers"
            ]
        );
        for o in objects.iter().filter(|o| o.0 == "table") {
            assert!(o.3.as_deref().unwrap().ends_with("STRICT"), "{}", o.1);
        }
        // Indexes exist only for primary keys and the UNIQUE keyed hashes.
        for o in objects.iter().filter(|o| o.0 == "index") {
            assert!(o.1.starts_with("sqlite_autoindex_"), "{}", o.1);
        }
        assert!(objects.iter().all(|o| o.0 == "table" || o.0 == "index"));
    }

    #[test]
    fn an_added_trigger_is_seen_and_cannot_fire() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::fs::canonicalize(dir.path()).unwrap().join("v.db");
        let conn = open_db(&path, true).unwrap();
        configure(&conn, true).unwrap();
        conn.execute_batch(SCHEMA_V1).unwrap();
        let plan = MigrationPlan::current();
        assert!(verify_schema(&conn, 1, &plan).unwrap());
        drop(conn);

        // Another program adds a trigger through a connection of its own.
        let other = Connection::open(&path).unwrap();
        other
            .execute_batch(
                "CREATE TABLE leak (x BLOB);
                 CREATE TRIGGER t AFTER INSERT ON policies BEGIN
                   INSERT INTO leak VALUES (new.sealed);
                 END;",
            )
            .unwrap();
        drop(other);

        let conn = open_db(&path, false).unwrap();
        configure(&conn, true).unwrap();
        assert!(!verify_schema(&conn, 1, &plan).unwrap());
        conn.execute("INSERT INTO policies VALUES (x'00', 1, x'01')", [])
            .unwrap();
        let leaked: i64 = conn
            .query_row("SELECT count(*) FROM leak", [], |r| r.get(0))
            .unwrap();
        assert_eq!(leaked, 0, "triggers are disabled on vault connections");
        let report = storage_report(&conn).unwrap();
        assert!(!report.triggers_enabled && !report.views_enabled);
    }
}
