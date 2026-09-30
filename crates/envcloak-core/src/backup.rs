//! Encrypted vault backups and restore (SPEC §5, §6.4 and §15.1 step 11;
//! the file format is in docs/VAULT.md "Backups").
//!
//! [`Vault::create_backup`] writes the whole vault to
//! `backups/vault-<UTC time>-<id>.ecbackup`:
//! - a plaintext header: the vault id, schema version and key epoch, the
//!   backup's random id, and the vault's Recovery Kit envelopes, which
//!   authenticate themselves. The passphrase envelope is not there, so a
//!   copied backup offers nothing to guess but the 128-bit kit;
//! - a sealed manifest: the SHA-256 of that header, the time, the write
//!   counter and state digest the vault had, and the image's length;
//! - the database image, a verified snapshot of the vault file
//!   (`Vault::snapshot`), in sealed chunks of 1 MiB.
//!
//! Every record is XChaCha20-Poly1305 under the `backup` subkey, bound to
//! the backup's id and the record's index, so nothing can be altered,
//! reordered, dropped, added or moved between backups unnoticed. Nothing
//! in the file opens without the VMK, which only the kit unwraps.
//!
//! [`restore_backup`] unwraps the VMK with the kit, decrypts the image
//! into a temporary file next to `vault.db`, opens it at the version it
//! was backed up at, and requires its digest to verify and its header to
//! match the manifest. It then migrates an older format, as any unlock
//! does, verifies it again, wraps the VMK under the new passphrase
//! (current default parameters), makes that the only passphrase envelope,
//! records the kit as confirmed (it was just used), and closes the file.
//! Only then does it touch the current vault: it folds the vault's WAL in
//! and closes it, checking both (a WAL still beside it stops the restore
//! there, with nothing moved), keeps it as `vault/replaced-<UTC time>.db`
//! (a hard link, so `vault.db` never goes missing), moves aside any side
//! file beside `vault.db` (also one left without a database, which SQLite
//! would otherwise replay onto the new file), renames the new file over
//! `vault.db`, and syncs the directory. A crash at any point leaves the
//! old vault or the new one in place, never neither; leftovers are removed
//! by the next open. The installed vault is then opened again: it must
//! verify, and be the state the restore prepared, with the vault id, epoch,
//! schema version and sealed header it committed. The header's state
//! digest covers every row, the new passphrase envelope included, so
//! another valid state of the same vault (a WAL it wrote, replayed onto the
//! installed file) is refused too.
//!
//! A backup restores only its own vault: a vault in place whose id is not
//! the backup's is refused before anything is written.
//!
//! Restore takes the vault's lock through [`LockedVault::open`], so it
//! fails with [`VaultErrorKind::Busy`] while the vault is open. It takes no
//! lock when there is no vault, and it releases the old vault's lock before
//! the files are swapped; [`Vault::create`] takes none either. The caller
//! must keep every other EnvCloak process away from the vault directory
//! for the whole call: the daemon runs both under its instance lock, after
//! locking and closing its own handle.

use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::crypto::{
    Aad, Argon2id, CryptoErrorKind, Envelope, EnvelopeCtx, FieldTag, ItemClass, KdfParams, Keyring,
    Purpose, Sealed, SubKey, TableTag, UnlockerKind, VaultId, Vmk, fill_random_or_panic,
    unwrap_vmk_with,
};
use crate::passphrase::check_passphrase;
use crate::recovery::RecoveryKit;
use crate::secret::SecretBytes;
use crate::unlock::{install_passphrase, passphrase_envelope, passphrase_unlockers};
use crate::vault::{
    DB_NAME, HeaderState, Integrity, LockedVault, MigrationPlan, REPLACED_PREFIX, TEMP_PREFIX,
    Vault, VaultError, VaultErrorKind, VaultPaths, check_private_dir, open_record, remove_temp,
    seal_record, set_aside, sync_dir, utc_stamp, with_suffix,
};

/// The extension of backup files.
pub const BACKUP_EXTENSION: &str = "ecbackup";
/// Bytes of database image per sealed chunk.
pub const BACKUP_CHUNK: usize = 1 << 20;

const MAGIC: [u8; 4] = *b"ECBK";
/// The only backup format version this build reads and writes.
const FORMAT_VERSION: u8 = 1;
const MANIFEST_VERSION: u8 = 1;
/// `magic(4) version(1) vault_id(16) schema_version(2) epoch(4)
/// backup_id(16) envelope_count(1)`.
const HEADER_FIXED: usize = 44;
/// `version(1) header_sha256(32) created_at(8) write_counter(8)
/// state_digest(32) image_len(8) chunk_count(4)`.
const MANIFEST_LEN: usize = 93;
/// At most this many Recovery Kit envelopes are carried.
const MAX_ENVELOPES: usize = 8;
const BACKUP_PREFIX: &str = "vault-";

/// A backup [`Vault::create_backup`] wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupInfo {
    pub path: PathBuf,
    pub backup_id: [u8; 16],
    /// Unix seconds.
    pub created_at: u64,
    /// The vault's write counter when it was backed up.
    pub write_counter: u64,
    pub items: usize,
    /// The file's size.
    pub bytes: u64,
}

/// What [`restore_backup`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreReport {
    pub vault_id: VaultId,
    pub backup_id: [u8; 16],
    /// When the backup was made, Unix seconds, from its sealed manifest.
    pub backup_created_at: u64,
    /// The vault's write counter when it was backed up.
    pub backup_write_counter: u64,
    /// The number of items the installed vault holds.
    pub items: usize,
    /// Every file moved out of the new vault's way: the file that was
    /// `vault.db`, now `vault/replaced-<UTC time>.db`, first, then its
    /// side files under the same name with SQLite's suffixes (or only side
    /// files, when they were left without a database). Empty when there
    /// was nothing. They stay until deleted: see [`replaced_files`].
    pub replaced: Vec<PathBuf>,
}

/// The points a restore passes, in order. Tests stop a restore at each
/// one; the vault on disk is the old one up to [`RestoreStep::Installed`]
/// and the new one from then on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RestoreStep {
    /// The kit unwrapped the VMK and the manifest opened.
    KitAccepted,
    /// The current vault, if any, is open and locked.
    OldVaultOpened,
    /// The decrypted image is in the temporary file and synced.
    StagingWritten,
    /// The staged vault verified, holds the new passphrase envelope, and
    /// is closed and synced.
    StagingReady,
    /// The current vault is closed.
    OldVaultClosed,
    /// The current vault is also linked as `replaced-<time>.db`, and any
    /// side file beside `vault.db` is moved aside.
    OldVaultKept,
    /// The new vault is `vault.db`, and the directory is synced.
    Installed,
}

impl Vault {
    /// Writes an encrypted backup of the vault to its `backups` directory.
    ///
    /// Refused with [`VaultErrorKind::Tampered`] unless the vault verified
    /// and still holds what this process committed (the vault then turns
    /// read-only), and with [`VaultErrorKind::NoRecoveryKit`] when it has
    /// no Recovery Kit envelope, which a restore needs. A vault that could
    /// not be migrated is backed up at its on-disk version.
    pub fn create_backup(&self) -> Result<BackupInfo, VaultError> {
        let header = self.header()?;
        let envelopes: Vec<&Envelope> = self
            .unlockers()
            .filter(|e| e.kind() == UnlockerKind::RecoveryKit)
            .take(MAX_ENVELOPES)
            .collect();
        if envelopes.is_empty() {
            return Err(VaultErrorKind::NoRecoveryKit.into());
        }
        let image = self.snapshot()?;

        let paths = self.paths();
        paths.ensure_dirs()?;
        let dir = std::fs::canonicalize(&paths.backups_dir)?;
        remove_stale_backup_temps(&dir)?;
        let created_at = now_secs();
        let mut backup_id = [0u8; 16];
        fill_random_or_panic(&mut backup_id);
        let name = format!(
            "{BACKUP_PREFIX}{}-{}.{BACKUP_EXTENSION}",
            utc_stamp(created_at),
            hex(&backup_id[..4])
        );
        let path = dir.join(&name);
        let tmp = dir.join(format!(".{name}.tmp"));

        let ctx = BackupCtx {
            vault_id: self.vault_id(),
            schema_version: self.schema_version(),
            epoch: self.epoch(),
            backup_id,
        };
        let head = ctx.header(&envelopes);
        let chunk_count = u32::try_from(image.len().div_ceil(BACKUP_CHUNK))
            .map_err(|_| VaultError::from(VaultErrorKind::TooLarge))?;
        let manifest = Manifest {
            header_sha256: Sha256::digest(&head).into(),
            created_at,
            write_counter: header.write_counter,
            state_digest: header.state_digest,
            image_len: image.len() as u64,
            chunk_count,
        };
        let k = self.keys().key(Purpose::Backup);
        let written = write_backup(&tmp, &head, &manifest, &image, k, &ctx);
        let linked = written.and_then(|()| Ok(std::fs::hard_link(&tmp, &path)?));
        let removed = remove_file_if_present(&tmp);
        linked?;
        removed?;
        sync_dir(&dir)?;
        Ok(BackupInfo {
            bytes: std::fs::metadata(&path)?.len(),
            path,
            backup_id,
            created_at,
            write_counter: header.write_counter,
            items: self.items().len(),
        })
    }
}

/// Restores the vault at `p` from `backup`, unlocked with `kit`, and makes
/// `new_pass` its passphrase. Returns the restored vault, unlocked.
///
/// Fails, and leaves the current vault as it was, when:
/// - `new_pass` breaks the passphrase rules ([`VaultErrorKind::Passphrase`],
///   checked before any key derivation);
/// - the kit does not open the backup (the generic
///   [`CryptoErrorKind::Unlock`], as for a wrong passphrase);
/// - the file is not a backup, or was altered, truncated or extended
///   ([`VaultErrorKind::BackupDamaged`]), or its vault does not verify
///   ([`VaultErrorKind::Tampered`]);
/// - a vault is in place and the backup is of another vault
///   ([`VaultErrorKind::BackupOfAnotherVault`]);
/// - the current vault is open ([`VaultErrorKind::Busy`]);
/// - the current vault's WAL could not be folded into it as it closed
///   ([`VaultErrorKind::Storage`]): moving that WAL aside would separate
///   transactions from their database.
///
/// A current file that is not an EnvCloak vault at all, or opens as
/// [`VaultErrorKind::Damaged`] (its plaintext tables altered, say), is
/// moved aside too. See the module documentation for the order of the
/// steps.
///
/// Fails with [`VaultErrorKind::RestoreUnverified`] when the backup was
/// installed but the installed vault does not open or verify, or verifies
/// as another state than the one prepared (something else changed the
/// vault directory meanwhile): the vault is then not the restored one, and
/// the replaced one is kept aside.
pub fn restore_backup(
    p: &VaultPaths,
    backup: &Path,
    kit: &RecoveryKit,
    new_pass: &SecretBytes,
) -> Result<(Vault, RestoreReport), VaultError> {
    restore(
        p,
        backup,
        kit,
        new_pass,
        &KdfParams::current_defaults(),
        MigrationPlan::current(),
        &mut |_| {},
    )
}

/// Test support only (feature `testing`): [`restore_backup`], wrapping the
/// new passphrase with `pass_kdf` instead of the current defaults, and
/// calling `observe` at each [`RestoreStep`].
#[cfg(feature = "testing")]
pub fn restore_backup_observed(
    p: &VaultPaths,
    backup: &Path,
    kit: &RecoveryKit,
    new_pass: &SecretBytes,
    pass_kdf: &KdfParams,
    observe: &mut dyn FnMut(RestoreStep),
) -> Result<(Vault, RestoreReport), VaultError> {
    restore(
        p,
        backup,
        kit,
        new_pass,
        pass_kdf,
        MigrationPlan::current(),
        observe,
    )
}

/// Test support only (feature `testing`): [`restore_backup`] by a build
/// whose migration plan is `plan`, wrapping the new passphrase with
/// `pass_kdf`: restores a backup of an older format.
#[cfg(feature = "testing")]
pub fn restore_backup_with_plan(
    p: &VaultPaths,
    backup: &Path,
    kit: &RecoveryKit,
    new_pass: &SecretBytes,
    pass_kdf: &KdfParams,
    plan: MigrationPlan,
) -> Result<(Vault, RestoreReport), VaultError> {
    restore(p, backup, kit, new_pass, pass_kdf, plan, &mut |_| {})
}

fn restore(
    p: &VaultPaths,
    backup: &Path,
    kit: &RecoveryKit,
    new_pass: &SecretBytes,
    pass_kdf: &KdfParams,
    plan: MigrationPlan,
    observe: &mut dyn FnMut(RestoreStep),
) -> Result<(Vault, RestoreReport), VaultError> {
    check_passphrase(new_pass)?;
    pass_kdf.check_bounds()?;
    let mut reader = open_backup(backup)?;
    let head = read_header(&mut reader)?;
    let vmk = unwrap_with_kit(&head, kit)?;
    let keys = Keyring::derive(&vmk, &head.ctx.vault_id, head.ctx.epoch);
    let k = keys.key(Purpose::Backup);
    let manifest = read_manifest(&mut reader, k, &head)?;
    observe(RestoreStep::KitAccepted);

    p.ensure_dirs()?;
    // A vault is opened, which takes its lock and folds in its WAL. A file
    // that is not one is left to be moved aside with its side files as
    // they are: SQLite would delete a WAL next to a file it cannot read.
    // So is one that opens as damaged; a busy vault, a path or permission
    // failure, or a newer format stops the restore.
    let old = if looks_like_a_vault(&p.db)? {
        match LockedVault::open(p) {
            Ok(v) => Some(v),
            Err(e) if e.kind() == VaultErrorKind::Damaged => None,
            Err(e) => return Err(e),
        }
    } else {
        None
    };
    // A backup restores its own vault only: another vault in place is
    // left as it is (its audit log beside it names it, too).
    if old
        .as_ref()
        .is_some_and(|o| o.vault_id() != head.ctx.vault_id)
    {
        return Err(VaultErrorKind::BackupOfAnotherVault.into());
    }
    observe(RestoreStep::OldVaultOpened);

    let dir = std::fs::canonicalize(&p.vault_dir)?;
    let mut staging = Staging::create(&dir)?;
    write_image(&mut reader, &mut staging.file, k, &head, &manifest)?;
    staging.file.sync_all()?;
    observe(RestoreStep::StagingWritten);

    let staged = Staged {
        head: &head,
        manifest: &manifest,
        plan: &plan,
    };
    let prepared = staged.prepare(&staging.path, p, vmk, new_pass, pass_kdf)?;
    staging.finish()?;
    observe(RestoreStep::StagingReady);

    let opened = old.is_some();
    if let Some(old) = old {
        old.close()?;
    }
    observe(RestoreStep::OldVaultClosed);
    // Closing a vault that opened folded its WAL into `vault.db` and
    // removed it. A WAL with frames still beside it holds transactions
    // `vault.db` lacks: set aside, it would leave `vault.db` without them
    // until the new file is renamed over it, and a crash in between would
    // leave the old vault at an older state that still verifies. Nothing
    // has been moved yet. Side files beside anything else go aside with it.
    if opened && holds_frames(&with_suffix(&dir.join(DB_NAME), "-wal"))? {
        return Err(VaultErrorKind::Storage(rusqlite::ffi::SQLITE_BUSY).into());
    }
    let replaced = set_aside(&dir)?;
    observe(RestoreStep::OldVaultKept);
    std::fs::rename(&staging.path, dir.join(DB_NAME))?;
    staging.disarm();
    sync_dir(&dir)?;
    observe(RestoreStep::Installed);

    // The file verified under its temporary name; under its own it must
    // verify again and be what was prepared there, not merely a state that
    // verifies. A restore never hands back a vault it did not check.
    let Prepared { vmk, committed } = prepared;
    let vault = LockedVault::open_with(p, plan)
        .and_then(|l| l.unlock(vmk).map_err(|(_, e)| e))
        .ok()
        .filter(|v| committed.is(v))
        .ok_or(VaultErrorKind::RestoreUnverified)?;
    let items = vault.items().len();
    Ok((
        vault,
        RestoreReport {
            vault_id: head.ctx.vault_id,
            backup_id: head.ctx.backup_id,
            backup_created_at: manifest.created_at,
            backup_write_counter: manifest.write_counter,
            items,
            replaced,
        },
    ))
}

/// What [`Staged::prepare`] left in the staged file.
struct Prepared {
    vmk: Vmk,
    committed: Committed,
}

/// The state a restore committed to the staged file: after any migration,
/// the new passphrase envelope and the kit's confirmation.
struct Committed {
    vault_id: VaultId,
    epoch: u32,
    schema_version: u16,
    header: HeaderState,
}

impl Committed {
    fn of(v: &Vault) -> Result<Self, VaultError> {
        Ok(Committed {
            vault_id: v.vault_id(),
            epoch: v.epoch(),
            schema_version: v.schema_version(),
            header: v.header()?,
        })
    }

    /// Whether `v` verified, writable, as exactly this state. Its header
    /// holds the write counter and the digest over every row, and is
    /// compared whole, in constant time.
    fn is(&self, v: &Vault) -> bool {
        let Ok(header) = v.header() else {
            return false;
        };
        v.integrity() == Integrity::Ok
            && v.migration_error().is_none()
            && v.vault_id() == self.vault_id
            && v.epoch() == self.epoch
            && v.schema_version() == self.schema_version
            && bool::from(header.encode().ct_eq(&self.header.encode()))
    }
}

/// What the staged database must be.
struct Staged<'a> {
    head: &'a Header,
    manifest: &'a Manifest,
    plan: &'a MigrationPlan,
}

impl Staged<'_> {
    /// Opens the staged database and requires it to be the backed-up vault,
    /// as it was backed up, with a verified digest; migrates it if it is of
    /// an older format, and requires it to verify again; installs the new
    /// passphrase envelope, and closes it. Returns the VMK and the state it
    /// committed.
    fn prepare(
        &self,
        staged: &Path,
        p: &VaultPaths,
        vmk: Vmk,
        new_pass: &SecretBytes,
        pass_kdf: &KdfParams,
    ) -> Result<Prepared, VaultError> {
        let (head, manifest) = (self.head, self.manifest);
        // The image opened under the backup key, so a file that is not a
        // vault or does not open under the VMK is a backup made wrongly or
        // forged with the key.
        let vault = LockedVault::open_staged(staged, p, self.plan.clone())
            .and_then(|l| l.unlock_as_stored(vmk).map_err(|(_, e)| e))
            .map_err(|e| match e.kind() {
                VaultErrorKind::KeyMismatch | VaultErrorKind::Damaged => {
                    VaultErrorKind::BackupDamaged.into()
                }
                _ => e,
            })?;
        if vault.integrity() != Integrity::Ok {
            return Err(VaultErrorKind::Tampered.into());
        }
        // Before any migration rewrites it, the header must be the one the
        // backup recorded.
        let header = vault.header()?;
        let matches = vault.vault_id() == head.ctx.vault_id
            && vault.epoch() == head.ctx.epoch
            && vault.schema_version() == head.ctx.schema_version
            && header.write_counter == manifest.write_counter
            && bool::from(header.state_digest.ct_eq(&manifest.state_digest));
        if !matches {
            return Err(VaultErrorKind::BackupDamaged.into());
        }
        // Unlocked again, it is verified afresh and migrated, as at any
        // unlock, when its format is older than this build's.
        let (locked, vmk) = vault.lock_keeping_key();
        let mut vault = locked.unlock(vmk).map_err(|(_, e)| e)?;
        if vault.integrity() != Integrity::Ok {
            return Err(VaultErrorKind::Tampered.into());
        }
        if vault.migration_error().is_some() {
            return Err(VaultErrorKind::Migration.into());
        }
        let existing = passphrase_unlockers(&vault);
        let env = passphrase_envelope(&vault, new_pass, &existing, pass_kdf)?;
        vault.transact(|t| {
            install_passphrase(t, env, &existing)?;
            // The kit was just used: the user holds it.
            t.set_recovery_confirmed(true);
            Ok(())
        })?;
        let committed = Committed::of(&vault)?;
        let (locked, vmk) = vault.lock_keeping_key();
        drop(locked);
        Ok(Prepared { vmk, committed })
    }
}

/// Whether a file is at `p` and is not empty.
fn holds_frames(p: &Path) -> Result<bool, VaultError> {
    match std::fs::symlink_metadata(p) {
        Ok(m) => Ok(m.len() > 0),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Whether `db` starts as an EnvCloak vault does: SQLite's magic and the
/// vault's application id. False when there is no file.
fn looks_like_a_vault(db: &Path) -> Result<bool, VaultError> {
    const MAGIC: &[u8; 16] = b"SQLite format 3\0";
    const APPLICATION_ID: [u8; 4] = *b"ECV1";
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(db)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return Err(VaultErrorKind::Path(crate::vault::PathErrorKind::Symlink).into());
        }
        Err(e) => return Err(e.into()),
    };
    if !file.metadata()?.is_file() {
        return Err(VaultErrorKind::Path(crate::vault::PathErrorKind::NotFile).into());
    }
    let mut head = [0u8; 72];
    match file.read_exact(&mut head) {
        Ok(()) => Ok(head[..16] == MAGIC[..] && head[68..72] == APPLICATION_ID),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// The temporary file a restore builds the new vault in. Removed, with its
/// side files, unless it was renamed into place.
struct Staging {
    path: PathBuf,
    file: File,
    armed: bool,
}

impl Staging {
    fn create(dir: &Path) -> Result<Self, VaultError> {
        let mut suffix = [0u8; 8];
        fill_random_or_panic(&mut suffix);
        let path = dir.join(format!("{TEMP_PREFIX}{}", hex(&suffix)));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)?;
        Ok(Staging {
            path,
            file,
            armed: true,
        })
    }

    /// After the staged vault is closed: removes the rollback journal
    /// SQLite keeps in exclusive mode, refuses any other side file, and
    /// syncs the database.
    fn finish(&self) -> Result<(), VaultError> {
        remove_file_if_present(&with_suffix(&self.path, "-journal"))?;
        for side in ["-wal", "-shm"] {
            if std::fs::symlink_metadata(with_suffix(&self.path, side)).is_ok() {
                return Err(VaultErrorKind::Storage(-1).into());
            }
        }
        Ok(File::open(&self.path)?.sync_all()?)
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        if self.armed {
            let _ = remove_temp(&self.path);
        }
    }
}

impl core::fmt::Debug for Staging {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Staging").finish_non_exhaustive()
    }
}

/// What every sealed record of one backup shares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BackupCtx {
    vault_id: VaultId,
    schema_version: u16,
    epoch: u32,
    backup_id: [u8; 16],
}

impl BackupCtx {
    /// Record 0 is the manifest; records 1 and up are the image's chunks.
    fn aad(&self, index: u64) -> Aad {
        Aad {
            vault_id: self.vault_id,
            schema_version: self.schema_version,
            key_epoch: self.epoch,
            table: TableTag::Backup,
            row_id: self.backup_id,
            field: if index == 0 {
                FieldTag::BackupManifest
            } else {
                FieldTag::BackupChunk
            },
            item_class: ItemClass::None,
            row_version: index,
        }
    }

    fn header(&self, envelopes: &[&Envelope]) -> Vec<u8> {
        let mut h = Vec::with_capacity(HEADER_FIXED + envelopes.len() * Envelope::LEN);
        h.extend_from_slice(&MAGIC);
        h.push(FORMAT_VERSION);
        h.extend_from_slice(&self.vault_id.0);
        h.extend_from_slice(&self.schema_version.to_be_bytes());
        h.extend_from_slice(&self.epoch.to_be_bytes());
        h.extend_from_slice(&self.backup_id);
        h.push(u8::try_from(envelopes.len()).unwrap_or(0));
        for e in envelopes {
            h.extend_from_slice(&e.to_bytes());
        }
        h
    }
}

/// The plaintext header as read.
struct Header {
    ctx: BackupCtx,
    envelopes: Vec<Envelope>,
    sha256: [u8; 32],
}

/// The sealed manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Manifest {
    header_sha256: [u8; 32],
    created_at: u64,
    write_counter: u64,
    state_digest: [u8; 32],
    image_len: u64,
    chunk_count: u32,
}

impl Manifest {
    fn encode(&self) -> Vec<u8> {
        let mut m = Vec::with_capacity(MANIFEST_LEN);
        m.push(MANIFEST_VERSION);
        m.extend_from_slice(&self.header_sha256);
        m.extend_from_slice(&self.created_at.to_be_bytes());
        m.extend_from_slice(&self.write_counter.to_be_bytes());
        m.extend_from_slice(&self.state_digest);
        m.extend_from_slice(&self.image_len.to_be_bytes());
        m.extend_from_slice(&self.chunk_count.to_be_bytes());
        m
    }

    fn decode(b: &[u8]) -> Result<Self, VaultError> {
        let damaged = || VaultError::from(VaultErrorKind::BackupDamaged);
        if b.len() != MANIFEST_LEN || b[0] != MANIFEST_VERSION {
            return Err(damaged());
        }
        let mut r = Cursor { buf: b, at: 1 };
        let m = Manifest {
            header_sha256: r.take()?,
            created_at: u64::from_be_bytes(r.take()?),
            write_counter: u64::from_be_bytes(r.take()?),
            state_digest: r.take()?,
            image_len: u64::from_be_bytes(r.take()?),
            chunk_count: u32::from_be_bytes(r.take()?),
        };
        // Every chunk but the last is full, and the last is not empty.
        let chunks = u64::from(m.chunk_count);
        let full = BACKUP_CHUNK as u64;
        if chunks == 0 || m.image_len <= (chunks - 1) * full || m.image_len > chunks * full {
            return Err(damaged());
        }
        Ok(m)
    }
}

struct Cursor<'a> {
    buf: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], VaultError> {
        let s = self
            .buf
            .get(self.at..self.at + N)
            .ok_or(VaultErrorKind::BackupDamaged)?;
        self.at += N;
        let mut out = [0u8; N];
        out.copy_from_slice(s);
        Ok(out)
    }
}

fn write_backup(
    tmp: &Path,
    head: &[u8],
    manifest: &Manifest,
    image: &[u8],
    k: &SubKey,
    ctx: &BackupCtx,
) -> Result<(), VaultError> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(tmp)?;
    let mut w = BufWriter::new(file);
    w.write_all(head)?;
    write_record(&mut w, &seal_record(k, &ctx.aad(0), &manifest.encode())?)?;
    for (i, chunk) in image.chunks(BACKUP_CHUNK).enumerate() {
        let sealed = seal_record(k, &ctx.aad(i as u64 + 1), chunk)?;
        write_record(&mut w, &sealed)?;
    }
    let file = w
        .into_inner()
        .map_err(|e| VaultError::from(e.into_error()))?;
    Ok(file.sync_all()?)
}

fn write_record(w: &mut impl Write, sealed: &[u8]) -> Result<(), VaultError> {
    let len =
        u32::try_from(sealed.len()).map_err(|_| VaultError::from(VaultErrorKind::TooLarge))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(sealed)?;
    Ok(())
}

/// The files a restore or [`Vault::create`] moved aside in the vault
/// directory, `vault/replaced-*`, sorted by name. Nothing removes them on
/// its own.
///
/// A replaced vault is a whole vault, and still opens with its own
/// passphrase envelope, which may use weaker Argon2id parameters than the
/// restored vault's. When it is the same vault as the backup, it wraps the
/// same VMK: until it is deleted, the old passphrase, or offline guessing
/// against that envelope, yields the restored vault's key. Callers report
/// these files (after a restore and in status) and offer to delete them,
/// with [`remove_replaced_files`], once the restored vault has verified.
pub fn replaced_files(p: &VaultPaths) -> Result<Vec<PathBuf>, VaultError> {
    check_private_dir(&p.vault_dir)?;
    let dir = std::fs::canonicalize(&p.vault_dir)?;
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let named = entry
            .file_name()
            .to_str()
            .is_some_and(|n| n.starts_with(REPLACED_PREFIX));
        if named && entry.file_type()?.is_file() {
            out.push(entry.path());
        }
    }
    out.sort();
    Ok(out)
}

/// Deletes every file [`replaced_files`] lists, syncs the vault directory,
/// and returns what it deleted.
pub fn remove_replaced_files(p: &VaultPaths) -> Result<Vec<PathBuf>, VaultError> {
    let files = replaced_files(p)?;
    for f in &files {
        remove_file_if_present(f)?;
    }
    sync_dir(&std::fs::canonicalize(&p.vault_dir)?)?;
    Ok(files)
}

/// Opens the backup without following a symlink, and without blocking on a
/// FIFO; anything but a regular file is refused.
fn open_backup(path: &Path) -> Result<BufReader<File>, VaultError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| match e.raw_os_error() {
            Some(libc::ELOOP) => VaultErrorKind::Path(crate::vault::PathErrorKind::Symlink).into(),
            _ => VaultError::from(e),
        })?;
    if !file.metadata()?.is_file() {
        return Err(VaultErrorKind::Path(crate::vault::PathErrorKind::NotFile).into());
    }
    Ok(BufReader::new(file))
}

/// Maps a short read to [`VaultErrorKind::BackupDamaged`].
fn read_exact(r: &mut impl Read, buf: &mut [u8]) -> Result<(), VaultError> {
    r.read_exact(buf).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            VaultErrorKind::BackupDamaged.into()
        } else {
            VaultError::from(e)
        }
    })
}

fn read_header(r: &mut impl Read) -> Result<Header, VaultError> {
    let damaged = || VaultError::from(VaultErrorKind::BackupDamaged);
    let mut fixed = [0u8; HEADER_FIXED];
    read_exact(r, &mut fixed)?;
    if fixed[..4] != MAGIC {
        return Err(damaged());
    }
    if fixed[4] != FORMAT_VERSION {
        return Err(VaultErrorKind::UnsupportedVersion.into());
    }
    let mut c = Cursor { buf: &fixed, at: 5 };
    let ctx = BackupCtx {
        vault_id: VaultId(c.take()?),
        schema_version: u16::from_be_bytes(c.take()?),
        epoch: u32::from_be_bytes(c.take()?),
        backup_id: c.take()?,
    };
    let [count] = c.take::<1>()?;
    let count = usize::from(count);
    if count == 0 || count > MAX_ENVELOPES {
        return Err(damaged());
    }
    let mut h = Sha256::new();
    h.update(fixed);
    let mut envelopes = Vec::with_capacity(count);
    for _ in 0..count {
        let mut b = [0u8; Envelope::LEN];
        read_exact(r, &mut b)?;
        h.update(b);
        // Out-of-bounds parameters are refused here, before any Argon2id.
        let env = Envelope::from_bytes(&b).map_err(|_| damaged())?;
        if env.kind() != UnlockerKind::RecoveryKit || env.epoch() != ctx.epoch {
            return Err(damaged());
        }
        envelopes.push(env);
    }
    Ok(Header {
        ctx,
        envelopes,
        sha256: h.finalize().into(),
    })
}

/// Unwraps the VMK from the first envelope the kit opens.
fn unwrap_with_kit(head: &Header, kit: &RecoveryKit) -> Result<Vmk, VaultError> {
    for env in &head.envelopes {
        let ctx = EnvelopeCtx {
            vault_id: head.ctx.vault_id,
            unlocker_id: env.unlocker_id(),
            epoch: head.ctx.epoch,
        };
        match unwrap_vmk_with(env, kit.secret(), &ctx, &Argon2id) {
            Ok(vmk) => return Ok(vmk),
            Err(e) if e.kind() == CryptoErrorKind::Unlock => {}
            Err(e) => return Err(e.into()),
        }
    }
    Err(VaultErrorKind::Crypto(CryptoErrorKind::Unlock).into())
}

/// Reads one record: `len(4)` then the sealed bytes, at most a full chunk
/// and the seal's overhead.
fn read_record(r: &mut impl Read) -> Result<Vec<u8>, VaultError> {
    let mut len = [0u8; 4];
    read_exact(r, &mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if !(Sealed::OVERHEAD..=BACKUP_CHUNK + Sealed::OVERHEAD).contains(&len) {
        return Err(VaultErrorKind::BackupDamaged.into());
    }
    let mut buf = vec![0u8; len];
    read_exact(r, &mut buf)?;
    Ok(buf)
}

fn read_manifest(r: &mut impl Read, k: &SubKey, head: &Header) -> Result<Manifest, VaultError> {
    let sealed = read_record(r)?;
    let m = open_record(k, &head.ctx.aad(0), &sealed, Manifest::decode)
        .map_err(|_| VaultError::from(VaultErrorKind::BackupDamaged))?;
    if !bool::from(m.header_sha256.ct_eq(&head.sha256)) {
        return Err(VaultErrorKind::BackupDamaged.into());
    }
    Ok(m)
}

/// Decrypts every chunk into `out`, then requires the end of the file.
fn write_image(
    r: &mut impl Read,
    out: &mut File,
    k: &SubKey,
    head: &Header,
    m: &Manifest,
) -> Result<(), VaultError> {
    let mut w = BufWriter::new(out);
    let mut total = 0u64;
    for i in 1..=u64::from(m.chunk_count) {
        let sealed = read_record(r)?;
        let mut io_error = None;
        let opened = open_record(k, &head.ctx.aad(i), &sealed, |pt| {
            // Every chunk but the last is full.
            if i < u64::from(m.chunk_count) && pt.len() != BACKUP_CHUNK {
                return Err(VaultErrorKind::BackupDamaged.into());
            }
            if let Err(e) = w.write_all(pt) {
                io_error = Some(e);
                return Err(VaultErrorKind::BackupDamaged.into());
            }
            Ok(pt.len() as u64)
        });
        if let Some(e) = io_error {
            return Err(e.into());
        }
        total += opened.map_err(|_| VaultError::from(VaultErrorKind::BackupDamaged))?;
    }
    if total != m.image_len {
        return Err(VaultErrorKind::BackupDamaged.into());
    }
    let mut extra = [0u8; 1];
    loop {
        match r.read(&mut extra) {
            Ok(0) => break,
            Ok(_) => return Err(VaultErrorKind::BackupDamaged.into()),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    w.flush()?;
    Ok(())
}

/// Removes what an interrupted `create_backup` left.
fn remove_stale_backup_temps(dir: &Path) -> Result<(), VaultError> {
    check_private_dir(dir)?;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(&format!(".{BACKUP_PREFIX}")) && name.ends_with(".tmp") {
            remove_file_if_present(&entry.path())?;
        }
    }
    Ok(())
}

fn remove_file_if_present(p: &Path) -> Result<(), VaultError> {
    match std::fs::remove_file(p) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_lengths() {
        assert_eq!(HEADER_FIXED, 4 + 1 + 16 + 2 + 4 + 16 + 1);
        let m = Manifest {
            header_sha256: [1; 32],
            created_at: 2,
            write_counter: 3,
            state_digest: [4; 32],
            image_len: 4096,
            chunk_count: 1,
        };
        let e = m.encode();
        assert_eq!(e.len(), MANIFEST_LEN);
        assert_eq!(Manifest::decode(&e).unwrap(), m);
    }

    #[test]
    fn manifests_with_impossible_chunking_are_refused() {
        let base = Manifest {
            header_sha256: [0; 32],
            created_at: 0,
            write_counter: 1,
            state_digest: [0; 32],
            image_len: 4096,
            chunk_count: 1,
        };
        let full = BACKUP_CHUNK as u64;
        for (image_len, chunk_count) in [(0, 1), (4096, 0), (4096, 2), (full + 1, 1), (full, 2)] {
            let m = Manifest {
                image_len,
                chunk_count,
                ..base
            };
            let e = Manifest::decode(&m.encode()).unwrap_err();
            assert_eq!(
                e.kind(),
                VaultErrorKind::BackupDamaged,
                "{image_len} {chunk_count}"
            );
        }
        let mut bad = base.encode();
        bad[0] = 2;
        assert!(Manifest::decode(&bad).is_err());
        assert!(Manifest::decode(&base.encode()[..MANIFEST_LEN - 1]).is_err());
    }

    fn no_change(_: &crate::vault::MigrationTx<'_>) -> Result<(), VaultError> {
        Ok(())
    }

    /// A plan to schema version 2 whose step changes nothing but adds a
    /// table.
    fn to_v2() -> MigrationPlan {
        MigrationPlan::new(vec![crate::vault::Migration {
            from: 1,
            ddl: "CREATE TABLE notes (id BLOB PRIMARY KEY NOT NULL) STRICT;",
            transform: no_change,
        }])
        .unwrap()
    }

    /// The staged image is checked against the manifest as it was backed
    /// up, before a migration rewrites its header (F-22): a backup whose
    /// manifest names another write counter or state digest than its image
    /// holds is refused, by this build and by one that migrates it. The
    /// forged manifests are sealed with the backup key, so only that check
    /// can catch them.
    #[test]
    fn the_image_must_match_its_manifest_before_any_migration() {
        use crate::crypto::{ItemClass, Purpose};
        use crate::vault::{ItemDetails, NewItem, Slug};

        let dir = tempfile::tempdir().unwrap();
        let p = VaultPaths::under(dir.path().join("data"));
        let pass = SecretBytes::copy_from(b"a unit test passphrase, not a secret");
        let (mut v, kit) = crate::unlock::create_vault(&p, &pass, KdfParams::minimum()).unwrap();
        v.transact(|t| {
            let item = t.create_item(NewItem {
                class: ItemClass::Secret,
                slug: Slug::new("unit/item").unwrap(),
                details: ItemDetails::default(),
            })?;
            t.add_field(
                item,
                crate::vault::FieldName::new("value").unwrap(),
                SecretBytes::copy_from(b"unit value"),
            )?;
            Ok(())
        })
        .unwrap();
        let info = v.create_backup().unwrap();
        let good = std::fs::read(&info.path).unwrap();

        // Re-seals the manifest, changed by `change`, with the backup key.
        let forge = |change: fn(&mut Manifest)| -> Vec<u8> {
            let mut r = &good[..];
            let head = read_header(&mut r).unwrap();
            let at = good.len() - r.len();
            let sealed = read_record(&mut r).unwrap();
            let k = v.keys().key(Purpose::Backup);
            let mut m = open_record(k, &head.ctx.aad(0), &sealed, Manifest::decode).unwrap();
            change(&mut m);
            let resealed = seal_record(k, &head.ctx.aad(0), &m.encode()).unwrap();
            assert_eq!(resealed.len(), sealed.len());
            let len = u32::try_from(resealed.len()).unwrap().to_be_bytes();
            [
                &good[..at],
                &len[..],
                &resealed,
                &good[at + 4 + sealed.len()..],
            ]
            .concat()
        };
        let forged = [
            ("an older write counter", forge(|m| m.write_counter -= 1)),
            ("a newer write counter", forge(|m| m.write_counter += 1)),
            ("another state digest", forge(|m| m.state_digest[7] ^= 1)),
        ];
        drop(v);
        let db = std::fs::read(&p.db).unwrap();

        let bad = dir.path().join("forged.ecbackup");
        let new_pass = SecretBytes::copy_from(b"another unit test passphrase");
        for (what, bytes) in &forged {
            std::fs::write(&bad, bytes).unwrap();
            for (build, plan) in [("this build", MigrationPlan::current()), ("v2", to_v2())] {
                let e = restore(
                    &p,
                    &bad,
                    &kit,
                    &new_pass,
                    &KdfParams::minimum(),
                    plan,
                    &mut |_| {},
                )
                .unwrap_err();
                assert_eq!(e.kind(), VaultErrorKind::BackupDamaged, "{what}, {build}");
                assert_eq!(std::fs::read(&p.db).unwrap(), db, "{what}, {build}");
            }
        }

        // Control: the backup as written restores and migrates.
        let (v, _) = restore(
            &p,
            &info.path,
            &kit,
            &new_pass,
            &KdfParams::minimum(),
            to_v2(),
            &mut |_| {},
        )
        .unwrap();
        assert_eq!(v.schema_version(), 2);
        assert_eq!(v.integrity(), Integrity::Ok);
        assert_eq!(v.items().len(), 1);
    }
}
