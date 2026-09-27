//! Vault storage (SPEC §5 "Vault", "Integrity" and "Items"; the file format
//! is in docs/VAULT.md).
//!
//! One SQLite file per user, `vault/vault.db` under the data directory
//! ([`VaultPaths`]).
//! - Every sensitive column is sealed with XChaCha20-Poly1305 before it is
//!   bound to a statement, so plaintext never enters SQLite's pages, WAL or
//!   journal. Plaintext columns hold opaque ids, row versions, timestamps,
//!   kinds and keyed hashes.
//! - The sealed header carries a write counter and the state digest over
//!   every row; it is rewritten in the same transaction as each write.
//! - [`LockedVault`] is an open file without a key: it can list unlocker
//!   envelopes. [`LockedVault::unlock`] with the VMK checks the digest,
//!   decrypts item metadata into memory and gives a [`Vault`]. Values stay
//!   sealed until [`Vault::read_value`] opens one.
//! - A vault that fails its integrity check opens read-only
//!   ([`Integrity::Tampered`]).
//! - Writes go through [`Vault::transact`] and a [`Txn`].
//!
//! Errors are [`VaultError`]s with fixed messages and no values.

mod codec;
mod error;
mod integrity;
mod items;
mod migrate;
mod paths;
mod schema;
mod state;
mod txn;
mod values;

use std::cell::Cell;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::crypto::{
    Envelope, FieldTag, Keyring, Purpose, TableTag, UnlockerId, VaultId, Vmk, fill_random_or_panic,
};
use crate::secret::SecretBytes;

pub use error::{VaultError, VaultErrorKind};
pub use integrity::{AuditHead, HeaderState, Integrity, TamperKind};
pub use items::{
    Account, Classification, FieldId, FieldMeta, FieldName, ItemDetails, ItemId, ItemMeta, Links,
    MAX_FIELD, MAX_PRIOR, MAX_ROW, NewItem, PolicyId, ProjectBinding, ProjectId, ProjectKey,
    ProjectRecord, Slug,
};
pub use migrate::{Migration, MigrationPlan, MigrationTx};
pub use paths::{PathError, PathErrorKind, Platform, VaultPaths, data_dir_for};
pub use schema::{CURRENT_SCHEMA, StorageReport};
pub use txn::Txn;

use integrity::{state_digest, unlocker_body};
use paths::{check_private_dir, check_private_file};
use state::{State, VaultCtx, item_key};
use values::{open_priors, open_value, seal_record};

/// The key epoch of a new vault.
pub const INITIAL_EPOCH: u32 = 1;

/// The database's file name inside the vault directory.
const DB_NAME: &str = "vault.db";
/// `create` builds the database under this prefix, then links it into
/// place, so a crash never leaves a half-built `vault.db`.
const TEMP_PREFIX: &str = ".vault.db.new-";

/// An open vault file without its key.
pub struct LockedVault {
    conn: Connection,
    vault_id: VaultId,
    schema_version: u16,
    epoch: u32,
    created_at: u64,
    plan: MigrationPlan,
}

impl core::fmt::Debug for LockedVault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LockedVault")
            .field("vault_id", &self.vault_id)
            .field("schema_version", &self.schema_version)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl LockedVault {
    /// Opens the vault at `p` and takes its exclusive lock, which it holds
    /// until dropped. Does not create anything: a missing vault is
    /// [`VaultErrorKind::NotFound`]. Removes what an interrupted
    /// [`Vault::create`] left. Sets the process umask to 077 first, as
    /// [`VaultPaths::ensure_dirs`] does.
    pub fn open(p: &VaultPaths) -> Result<Self, VaultError> {
        Self::open_with(p, MigrationPlan::current())
    }

    /// Test support only: opens with a migration plan other than the
    /// shipped one (SPEC §15.2 gate 7).
    #[cfg(feature = "testing")]
    pub fn open_with_plan(p: &VaultPaths, plan: MigrationPlan) -> Result<Self, VaultError> {
        Self::open_with(p, plan)
    }

    fn open_with(p: &VaultPaths, plan: MigrationPlan) -> Result<Self, VaultError> {
        envcloak_sys::restrict_umask();
        check_private_dir(&p.data_dir)?;
        check_private_dir(&p.vault_dir)?;
        // SQLite's NOFOLLOW refuses any symlink on the path, and the data
        // directory's own ancestors (macOS `/tmp`, say) may be symlinks.
        let dir = std::fs::canonicalize(&p.vault_dir)?;
        let db = dir.join(DB_NAME);
        check_private_file(&db)?;
        for side in ["-wal", "-shm", "-journal"] {
            let mut name = db.clone().into_os_string();
            name.push(side);
            match std::fs::symlink_metadata(&name) {
                Ok(_) => check_private_file(Path::new(&name))?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        let conn = schema::open_db(&db, false)?;
        schema::configure(&conn, true)?;
        let app_id: i32 = conn.pragma_query_value(None, "application_id", |r| r.get(0))?;
        if app_id != schema::APPLICATION_ID {
            return Err(VaultErrorKind::Damaged.into());
        }
        // This handle now holds the vault's lock. A `create` killed after
        // linking its file into place left the temporary name as a second
        // link to this vault; nothing else uses these names once `vault.db`
        // exists.
        remove_stale_temps(&dir)?;
        let id = read_identity(&conn, plan.target())?;
        Ok(LockedVault {
            vault_id: id.vault_id,
            schema_version: *id.versions.first().ok_or(VaultErrorKind::Damaged)?,
            epoch: id.epoch,
            created_at: id.created_at,
            conn,
            plan,
        })
    }

    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// The schema version the file names (before unlock), or the one it
    /// verified under (after an unlock).
    pub fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Unix seconds, as recorded in the file. Not authenticated.
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// The well-formed unlocker envelopes of the current epoch. Envelopes
    /// authenticate themselves when opened; the rest of the file is
    /// verified only at unlock.
    pub fn unlockers(&self) -> Result<Vec<Envelope>, VaultError> {
        let mut st = self.conn.prepare("SELECT envelope FROM unlockers")?;
        let rows = st.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for bytes in rows {
            if let Ok(env) = Envelope::from_bytes(&bytes?) {
                if env.epoch() == self.epoch {
                    out.push(env);
                }
            }
        }
        Ok(out)
    }

    /// The SQLite settings in effect.
    pub fn storage_report(&self) -> Result<StorageReport, VaultError> {
        schema::storage_report(&self.conn)
    }

    /// Unlocks with the VMK: derives the subkeys, verifies the header and
    /// the state digest, decrypts item metadata (never a value), and
    /// migrates an older format when the vault verified. On failure the
    /// locked vault comes back with the error.
    ///
    /// A migration that fails is rolled back and does not fail the unlock:
    /// the vault opens read-only at its old version, with
    /// [`Vault::migration_error`] set, so its owner can still read and back
    /// up what it holds (SPEC §15.2 gate 7). The next unlock tries again.
    ///
    /// When the file names more than one schema version (an altered or
    /// restored `meta` or header row), the vault opens under the first one
    /// its header or rows open under, and reports the row read-only.
    pub fn unlock(mut self, vmk: Vmk) -> Result<Vault, (Self, VaultError)> {
        // A vault locked after opening read-only is judged afresh.
        if let Err(e) = self.conn.pragma_update(None, "query_only", "OFF") {
            return Err((self, e.into()));
        }
        let keys = Keyring::derive(&vmk, &self.vault_id, self.epoch);
        // The file cannot have changed since `open`: this handle holds the
        // exclusive lock.
        let id = match read_identity(&self.conn, self.plan.target()) {
            Ok(id) => id,
            Err(e) => return Err((self, e)),
        };
        let others = id.versions.iter().filter(|v| **v != self.schema_version);
        let versions: Vec<u16> = core::iter::once(self.schema_version)
            .chain(others.copied())
            .collect();
        let mut opened = None;
        for schema_version in versions {
            let ctx = VaultCtx {
                vault_id: self.vault_id,
                schema_version,
                epoch: self.epoch,
            };
            match load_verified(&self.conn, &keys, &ctx, &self.plan) {
                Ok(l) => {
                    opened = Some((ctx, l));
                    break;
                }
                Err(e) if e.kind() == VaultErrorKind::KeyMismatch => {}
                Err(e) => return Err((self, e)),
            }
        }
        let Some((mut ctx, mut loaded)) = opened else {
            // Nothing opened under a version this build reads: the file is
            // newer, when it says so, or the key is wrong.
            let kind = if id.newer {
                VaultErrorKind::UnsupportedVersion
            } else {
                VaultErrorKind::KeyMismatch
            };
            return Err((self, kind.into()));
        };
        self.schema_version = ctx.schema_version;
        let mut migration_error = None;
        if loaded.integrity == Integrity::Ok && ctx.schema_version < self.plan.target() {
            let header = loaded.state.header;
            match migrate::run(&mut self.conn, &keys, &ctx, &header, &self.plan) {
                Ok(()) => {
                    self.schema_version = self.plan.target();
                    ctx.schema_version = self.schema_version;
                    loaded = match load_verified(&self.conn, &keys, &ctx, &self.plan) {
                        Ok(l) => l,
                        Err(e) => return Err((self, e)),
                    };
                }
                // Rolled back: the file, and so `loaded`, are as they were.
                Err(e) => migration_error = Some(e.kind()),
            }
        }
        if loaded.integrity != Integrity::Ok || migration_error.is_some() {
            // Belt and braces: `transact` refuses writes already.
            if let Err(e) = self.conn.pragma_update(None, "query_only", "ON") {
                return Err((self, e.into()));
            }
        }
        let view = loaded.state.item_list();
        Ok(Vault {
            file: self,
            ctx,
            vmk,
            keys,
            state: loaded.state,
            view,
            integrity: Cell::new(loaded.integrity),
            migration_error,
        })
    }
}

fn load_verified(
    conn: &Connection,
    keys: &Keyring,
    ctx: &VaultCtx,
    plan: &MigrationPlan,
) -> Result<state::Loaded, VaultError> {
    let schema_ok = schema::verify_schema(conn, ctx.schema_version, plan)?;
    state::load(conn, keys, ctx, schema_ok)
}

/// What the file's plaintext says about the vault before it is unlocked.
struct Identity {
    vault_id: VaultId,
    /// The schema versions named that this build reads, the header's
    /// first. Never empty.
    versions: Vec<u16>,
    /// Some row names a version newer than this build reads.
    newer: bool,
    epoch: u32,
    created_at: u64,
}

/// Reads the vault id, schema version and epoch from the rows that hold
/// them in plaintext: `meta`, the header, and the unlockers (each holds the
/// vault id, and its envelope the epoch). None of them is trusted alone, so
/// one deleted, doubled or altered row among them still lets the vault open;
/// unlock then reports it and opens read-only (SPEC §15.2 gate 6).
/// - The vault id is the one most of these rows hold. A tie is
///   [`VaultErrorKind::Damaged`].
/// - The epoch is the header's when an envelope carries it, otherwise the
///   one every envelope carries.
/// - The schema versions are the header's, then `meta`'s, keeping those
///   this build reads; unlock uses the first that the header or rows open
///   under. When no row names one, every version this build reads is
///   tried. When every row names a newer one, the vault is refused with
///   [`VaultErrorKind::UnsupportedVersion`].
fn read_identity(conn: &Connection, target: u16) -> Result<Identity, VaultError> {
    let metas = state::query(
        conn,
        "SELECT vault_id, schema_version, created_at FROM meta",
        |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
            ))
        },
    )?;
    let headers = state::query(
        conn,
        "SELECT epoch, vault_id, schema_version FROM header",
        |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, i64>(2)?,
            ))
        },
    )?;
    let unlockers = state::query(conn, "SELECT vault_id, envelope FROM unlockers", |r| {
        Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
    })?;

    let mut votes = std::collections::BTreeMap::<[u8; 16], usize>::new();
    let ids = metas
        .iter()
        .map(|m| &m.0)
        .chain(headers.iter().map(|h| &h.1))
        .chain(unlockers.iter().map(|u| &u.0));
    for id in ids {
        if let Ok(id) = <[u8; 16]>::try_from(id.as_slice()) {
            *votes.entry(id).or_default() += 1;
        }
    }
    let most = votes
        .values()
        .copied()
        .max()
        .ok_or(VaultErrorKind::Damaged)?;
    let mut leaders = votes.iter().filter(|(_, n)| **n == most).map(|(id, _)| *id);
    let (Some(vault_id), None) = (leaders.next(), leaders.next()) else {
        return Err(VaultErrorKind::Damaged.into());
    };

    let envelope_epochs: std::collections::BTreeSet<u32> = unlockers
        .iter()
        .filter_map(|u| Envelope::from_bytes(&u.1).ok())
        .map(|e| e.epoch())
        .collect();
    let header_epoch = match headers.as_slice() {
        [h] => u32::try_from(h.0).ok(),
        _ => None,
    };
    let epoch = match (header_epoch, envelope_epochs.first()) {
        (Some(e), _) if envelope_epochs.contains(&e) => e,
        (_, Some(e)) if envelope_epochs.len() == 1 => *e,
        (Some(e), None) => e,
        _ => return Err(VaultErrorKind::Damaged.into()),
    };

    let mut versions = Vec::new();
    let mut newer = false;
    for v in headers.iter().map(|h| h.2).chain(metas.iter().map(|m| m.1)) {
        match u16::try_from(v) {
            Ok(v) if v > target => newer = true,
            Ok(v) if v >= 1 && !versions.contains(&v) => versions.push(v),
            _ => {}
        }
    }
    if versions.is_empty() {
        if newer {
            return Err(VaultErrorKind::UnsupportedVersion.into());
        }
        versions = (1..=target).rev().collect();
    }
    let created_at = match metas.as_slice() {
        [m] => u64::try_from(m.2).unwrap_or(0),
        _ => 0,
    };
    Ok(Identity {
        vault_id: VaultId(vault_id),
        versions,
        newer,
        epoch,
        created_at,
    })
}

/// An unlocked vault: the file, the VMK and its subkeys, and the verified
/// metadata.
pub struct Vault {
    file: LockedVault,
    ctx: VaultCtx,
    vmk: Vmk,
    keys: Keyring,
    state: State,
    /// `state`'s items sorted by slug, rebuilt after every commit.
    view: Vec<ItemMeta>,
    integrity: Cell<Integrity>,
    migration_error: Option<VaultErrorKind>,
}

impl core::fmt::Debug for Vault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Vault")
            .field("vault_id", &self.ctx.vault_id)
            .field("epoch", &self.ctx.epoch)
            .field("integrity", &self.integrity.get())
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Creates a vault at `p` with the VMK and at least one unlocker
    /// envelope, each wrapped for `vault_id`, [`INITIAL_EPOCH`] and its own
    /// unlocker id. The database is built under a temporary name, synced,
    /// and linked into place, so `vault.db` either does not exist or is
    /// complete. Fails with [`VaultErrorKind::AlreadyExists`] if a vault is
    /// there.
    pub fn create(
        p: &VaultPaths,
        vault_id: VaultId,
        vmk: Vmk,
        unlockers: Vec<Envelope>,
    ) -> Result<Vault, VaultError> {
        if unlockers.is_empty() || unlockers.iter().any(|e| e.epoch() != INITIAL_EPOCH) {
            return Err(VaultErrorKind::InvalidRecord.into());
        }
        let ids: std::collections::BTreeSet<[u8; 16]> =
            unlockers.iter().map(|e| e.unlocker_id().0).collect();
        if ids.len() != unlockers.len() {
            return Err(VaultErrorKind::DuplicateUnlocker.into());
        }
        p.ensure_dirs()?;
        let dir = std::fs::canonicalize(&p.vault_dir)?;
        let db = dir.join(DB_NAME);
        if std::fs::symlink_metadata(&db).is_ok() {
            return Err(VaultErrorKind::AlreadyExists.into());
        }
        remove_stale_temps(&dir)?;
        let mut suffix = [0u8; 8];
        fill_random_or_panic(&mut suffix);
        let tmp = dir.join(format!(
            "{TEMP_PREFIX}{}",
            suffix
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        let built = build_new(&tmp, vault_id, &vmk, &unlockers)
            .and_then(|()| Ok(std::fs::File::open(&tmp)?.sync_all()?));
        let linked = built.and_then(|()| match std::fs::hard_link(&tmp, &db) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(VaultErrorKind::AlreadyExists.into())
            }
            Err(e) => Err(e.into()),
        });
        let removed = remove_temp(&tmp);
        linked?;
        removed?;
        sync_dir(&dir)?;
        LockedVault::open(p)?.unlock(vmk).map_err(|(_, e)| e)
    }

    pub fn vault_id(&self) -> VaultId {
        self.ctx.vault_id
    }

    pub fn epoch(&self) -> u32 {
        self.ctx.epoch
    }

    pub fn schema_version(&self) -> u16 {
        self.ctx.schema_version
    }

    /// The result of the integrity check at unlock, or
    /// [`TamperKind::ChangedWhileOpen`] once a read found a row that no
    /// longer matches.
    pub fn integrity(&self) -> Integrity {
        self.integrity.get()
    }

    /// Why this build could not migrate the vault to its schema version,
    /// or `None`. When set, the vault verified but is open read-only at its
    /// on-disk version ([`Vault::schema_version`]): values and metadata
    /// read as usual, and writes fail with [`VaultErrorKind::Migration`].
    pub fn migration_error(&self) -> Option<VaultErrorKind> {
        self.migration_error
    }

    /// The header as of the last commit.
    pub fn header(&self) -> HeaderState {
        self.state.header
    }

    /// The VMK, for wrapping new unlocker envelopes. Its bytes cannot be
    /// read outside the crypto module.
    pub fn vmk(&self) -> &Vmk {
        &self.vmk
    }

    /// Every item, sorted by slug. Metadata only.
    pub fn items(&self) -> &[ItemMeta] {
        &self.view
    }

    pub fn find(&self, slug: &Slug) -> Option<&ItemMeta> {
        self.view
            .binary_search_by(|m| m.slug.cmp(slug))
            .ok()
            .map(|i| &self.view[i])
    }

    pub fn item(&self, id: ItemId) -> Option<&ItemMeta> {
        self.state.items.get(&id).and_then(|r| self.find(&r.slug))
    }

    /// Decrypts a field's current value.
    pub fn read_value(&self, field: FieldId) -> Result<SecretBytes, VaultError> {
        let (class, rv) = self.field_context(field)?;
        let stored: Option<Vec<u8>> = self
            .file
            .conn
            .query_row(
                "SELECT sealed_value FROM fields WHERE id = ?1",
                params![&field.as_bytes()[..]],
                |r| r.get(0),
            )
            .optional()?;
        // The associated data carries the row version held in memory, so a
        // row replaced on disk since unlock does not open.
        let aad = self.ctx.aad(
            TableTag::Fields,
            field.as_bytes(),
            FieldTag::FieldValue,
            class,
            rv,
        );
        let opened = stored.ok_or(VaultErrorKind::Tampered).and_then(|s| {
            open_value(item_key(&self.keys, class), &aad, &s).map_err(|_| VaultErrorKind::Tampered)
        });
        opened.map_err(|k| self.changed_while_open(k))
    }

    /// Decrypts one of a field's prior values, 0 being the newest.
    pub fn read_prior(&self, field: FieldId, index: usize) -> Result<SecretBytes, VaultError> {
        let (class, rv) = self.field_context(field)?;
        let stored: Option<Option<Vec<u8>>> = self
            .file
            .conn
            .query_row(
                "SELECT sealed_prior FROM fields WHERE id = ?1",
                params![&field.as_bytes()[..]],
                |r| r.get(0),
            )
            .optional()?;
        let Some(stored) = stored else {
            return Err(self.changed_while_open(VaultErrorKind::Tampered));
        };
        let aad = self.ctx.aad(
            TableTag::Fields,
            field.as_bytes(),
            FieldTag::FieldPrior,
            class,
            rv,
        );
        let priors = open_priors(item_key(&self.keys, class), &aad, stored.as_deref())
            .map_err(|_| self.changed_while_open(VaultErrorKind::Tampered))?;
        priors
            .into_iter()
            .nth(index)
            .ok_or_else(|| VaultErrorKind::UnknownField.into())
    }

    fn field_context(&self, field: FieldId) -> Result<(crate::crypto::ItemClass, u64), VaultError> {
        let f = self
            .state
            .fields
            .get(&field)
            .ok_or(VaultErrorKind::UnknownField)?;
        let item = self
            .state
            .items
            .get(&f.item)
            .ok_or(VaultErrorKind::UnknownItem)?;
        Ok((item.class, f.row_version))
    }

    fn changed_while_open(&self, k: VaultErrorKind) -> VaultError {
        if self.integrity.get() == Integrity::Ok {
            self.integrity
                .set(Integrity::Tampered(TamperKind::ChangedWhileOpen));
        }
        k.into()
    }

    /// The fields whose current value equals `v`, by keyed hash (gate 10's
    /// duplicate-owner report). Prior values are not searched.
    pub fn find_by_value(&self, v: &SecretBytes) -> Vec<FieldId> {
        txn::find_by_value(&self.keys, &self.state, v)
    }

    /// Every project record.
    pub fn projects(&self) -> impl Iterator<Item = (ProjectId, &ProjectRecord)> {
        self.state.projects.iter().map(|(id, r)| (*id, &r.record))
    }

    pub fn find_project(&self, key: &ProjectKey) -> Option<(ProjectId, &ProjectRecord)> {
        let h = state::dir_hash(&self.keys, key.as_bytes());
        let id = *self.state.project_keys.get(&h)?;
        self.state.projects.get(&id).map(|r| (id, &r.record))
    }

    /// Every policy record.
    pub fn policies(&self) -> impl Iterator<Item = (PolicyId, &[u8])> {
        self.state
            .policies
            .iter()
            .map(|(id, p)| (*id, p.body.as_slice()))
    }

    /// The unlocker envelopes that verified at unlock.
    pub fn unlockers(&self) -> impl Iterator<Item = &Envelope> {
        self.state.unlockers.values()
    }

    pub fn unlocker(&self, id: UnlockerId) -> Option<&Envelope> {
        self.state.unlockers.get(&id)
    }

    /// Runs `f` in one write transaction. Its writes, and the header that
    /// vouches for them, commit together when `f` returns `Ok`, and not at
    /// all when it returns an error or panics. Refused with
    /// [`VaultErrorKind::ReadOnly`] when the vault failed its integrity
    /// check, and with [`VaultErrorKind::Migration`] when it could not be
    /// migrated.
    pub fn transact<T>(
        &mut self,
        f: impl FnOnce(&mut Txn<'_>) -> Result<T, VaultError>,
    ) -> Result<T, VaultError> {
        if self.integrity.get() != Integrity::Ok {
            return Err(VaultErrorKind::ReadOnly.into());
        }
        if self.migration_error.is_some() {
            return Err(VaultErrorKind::Migration.into());
        }
        let run = || -> Result<(T, State), VaultError> {
            let mut txn = Txn::begin(
                &mut self.file.conn,
                &self.keys,
                self.ctx,
                self.state.clone(),
            )?;
            let out = f(&mut txn)?;
            Ok((out, txn.commit()?))
        };
        // A row that is not where this process left it means the file was
        // changed behind its back: the vault goes read-only.
        let (out, state) = run().inspect_err(|e| {
            if e.kind() == VaultErrorKind::Tampered {
                self.integrity
                    .set(Integrity::Tampered(TamperKind::ChangedWhileOpen));
            }
        })?;
        self.state = state;
        self.view = self.state.item_list();
        Ok(out)
    }

    /// The SQLite settings in effect.
    pub fn storage_report(&self) -> Result<StorageReport, VaultError> {
        self.file.storage_report()
    }

    /// Test support only: drops the pages SQLite has cached, so the next
    /// read of a row comes from the file, as it does once the cache evicts
    /// the page. Lets a test see a change another program made to the file
    /// while the vault is open.
    #[cfg(feature = "testing")]
    pub fn evict_page_cache_for_testing(&self) -> Result<(), VaultError> {
        self.file.conn.execute_batch("PRAGMA shrink_memory")?;
        Ok(())
    }

    /// Locks: drops the VMK, the subkeys and the decrypted metadata, which
    /// are wiped as they are freed, and keeps the file open and locked.
    pub fn lock(self) -> LockedVault {
        let Vault { file, .. } = self;
        file
    }
}

/// Builds a complete vault in the empty file `tmp`, in rollback-journal
/// mode, and closes it.
fn build_new(
    tmp: &Path,
    vault_id: VaultId,
    vmk: &Vmk,
    unlockers: &[Envelope],
) -> Result<(), VaultError> {
    let mut conn = schema::open_db(tmp, true)?;
    schema::configure(&conn, false)?;
    conn.pragma_update(None, "application_id", schema::APPLICATION_ID)?;
    let keys = Keyring::derive(vmk, &vault_id, INITIAL_EPOCH);
    let ctx = VaultCtx {
        vault_id,
        schema_version: CURRENT_SCHEMA,
        epoch: INITIAL_EPOCH,
    };
    let now = i64::try_from(txn::now_secs()).unwrap_or(0);
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute_batch(schema::SCHEMA_V1)?;
    tx.execute(
        "INSERT INTO meta (vault_id, schema_version, created_at) VALUES (?1, ?2, ?3)",
        params![&vault_id.0[..], CURRENT_SCHEMA, now],
    )?;
    let mut stamps = std::collections::BTreeMap::new();
    for env in unlockers {
        let id = env.unlocker_id();
        let kind = i64::from(env.kind() as u8);
        let bytes = env.to_bytes();
        tx.execute(
            "INSERT INTO unlockers (id, vault_id, kind, envelope, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![&id.0[..], &vault_id.0[..], kind, &bytes[..], now],
        )?;
        stamps.insert(
            integrity::row_key(TableTag::Unlockers, &id.0),
            integrity::Stamp {
                row_version: 0,
                body: unlocker_body(&vault_id.0, kind, now, &bytes),
            },
        );
    }
    let header = HeaderState {
        write_counter: 1,
        state_digest: state_digest(&keys, &stamps),
        ..HeaderState::default()
    };
    let sealed = seal_record(
        keys.key(Purpose::Header),
        &ctx.header_aad(),
        &header.encode(),
    )?;
    tx.execute(
        "INSERT INTO header (epoch, vault_id, schema_version, sealed) VALUES (?1, ?2, ?3, ?4)",
        params![INITIAL_EPOCH, &vault_id.0[..], CURRENT_SCHEMA, sealed],
    )?;
    tx.commit()?;
    conn.close().map_err(|(_, e)| VaultError::from(e))
}

/// Removes what an interrupted `create` left: temporary databases (possibly
/// a second link to a finished vault) and their journals.
fn remove_stale_temps(dir: &Path) -> Result<(), VaultError> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if name.to_string_lossy().starts_with(TEMP_PREFIX) {
            remove_temp(&entry.path())?;
        }
    }
    Ok(())
}

fn remove_temp(p: &Path) -> Result<(), VaultError> {
    for side in ["", "-journal"] {
        let mut name = p.as_os_str().to_owned();
        name.push(side);
        match std::fs::remove_file(&name) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Makes a directory's entries durable. On macOS `sync_all` is
/// `F_FULLFSYNC`.
fn sync_dir(dir: &Path) -> Result<(), VaultError> {
    Ok(std::fs::File::open(dir)?.sync_all()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        Argon2id, EnvelopeCtx, ItemClass, KdfParams, OPEN_ATTEMPTS, UnlockerKind, wrap_vmk_with,
    };

    fn opens() -> usize {
        OPEN_ATTEMPTS.with(Cell::get)
    }

    /// SPEC T3 acceptance: at unlock, item metadata is decrypted into
    /// memory; values are decrypted on demand only.
    #[test]
    fn unlock_decrypts_metadata_and_never_a_value() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::under(dir.path().join("data"));
        let vault_id = VaultId::generate();
        let vmk = Vmk::generate();
        let raw = vmk.export_for_testing();
        let env = wrap_vmk_with(
            &vmk,
            &SecretBytes::copy_from(b"unit test passphrase"),
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
        let field = v
            .transact(|t| {
                let mut last = None;
                for n in 0..3 {
                    let item = t.create_item(NewItem {
                        class: ItemClass::Secret,
                        slug: Slug::new(&format!("unit/item-{n}")).unwrap(),
                        details: ItemDetails::default(),
                    })?;
                    for name in ["a", "b"] {
                        let value = SecretBytes::copy_from(format!("value {n} {name}").as_bytes());
                        last = Some(t.add_field(item, FieldName::new(name).unwrap(), value)?);
                    }
                    // A prior value too, which unlock must not open either.
                    t.set_value(last.unwrap(), SecretBytes::copy_from(b"rotated"))?;
                }
                Ok(last.unwrap())
            })
            .unwrap();
        let locked = v.lock();

        let before = opens();
        let v = locked
            .unlock(Vmk::import_for_testing(&raw).unwrap())
            .map_err(|(_, e)| e)
            .unwrap();
        // The header, three item records and six field records: nothing
        // from `sealed_value` or `sealed_prior`.
        assert_eq!(opens() - before, 1 + 3 + 6);
        assert_eq!(v.integrity(), Integrity::Ok);

        let before = opens();
        assert!(v.read_value(field).unwrap().ct_eq(b"rotated"));
        assert_eq!(opens() - before, 1, "one value, on demand");
        assert!(v.read_prior(field, 0).unwrap().ct_eq(b"value 2 b"));
        assert_eq!(opens() - before, 2);
    }
}
