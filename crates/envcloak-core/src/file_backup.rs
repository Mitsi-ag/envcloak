//! Encrypted backups of files EnvCloak deletes (SPEC §6.4 "Backups"; the
//! file format is in docs/VAULT.md "File backups").
//!
//! Before `envcloak init` deletes a plaintext env file, the daemon writes
//! its bytes to `backups/files-<UTC time>-<id>.ecfiles` with
//! [`Vault::backup_files`]:
//! - a plaintext header: magic, format version, the vault id, schema
//!   version and key epoch, the backup's random id and its creation time;
//! - record 0: a fresh 256-bit key for this backup alone, sealed under
//!   the vault's `backup` subkey;
//! - record 1: a manifest sealed under that key: the SHA-256 of the
//!   header, and each file's path, mode and length;
//! - records 2 and up: each file's bytes, sealed under that key.
//!
//! Every record is XChaCha20-Poly1305, bound by its associated data to the
//! vault, the backup's id and the record's index, so nothing can be
//! altered, reordered, dropped, added or moved between backups unnoticed.
//! Nothing opens without the vault key, which the Recovery Kit also
//! unwraps. No plaintext copy or temporary file of the contents is ever
//! written: the backup is built in a new file (`O_EXCL`), flushed, and
//! linked into place.
//!
//! [`Vault::open_file_backup`] returns the files as they were, byte for
//! byte (`envcloak init --undo`). [`purge_file_backups`] removes backups
//! older than [`FILE_BACKUP_RETENTION`], by the time in their header, and
//! the staging files interrupted writes left
//! (`.files-<time>-<id>.ecfiles.tmp`, unchanged for [`STAGING_GRACE`]).

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use envcloak_sys::{
    DirEntryKind, DirEntryName, MAX_DIR_ENTRIES, create_beneath, kind_beneath, link_beneath,
    list_dir, open_beneath, sync_file, unlink_beneath,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::crypto::{
    Aad, FieldTag, ItemClass, Purpose, Sealed, SubKey, TableTag, fill_random_or_panic, open_subkey,
    seal_subkey,
};
use crate::secret::SecretBytes;
use crate::vault::{
    Vault, VaultError, VaultErrorKind, VaultPaths, open_private_child, open_record, open_value,
    seal_record, seal_value, utc_stamp,
};

/// The extension of file backups.
pub const FILE_BACKUP_EXTENSION: &str = "ecfiles";
/// How long a file backup is kept (SPEC §6.4: removed after 7 days).
pub const FILE_BACKUP_RETENTION: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// How long a file backup's staging file may stand unchanged before a
/// purge takes it for one an interrupted write left: a backup is written
/// in seconds.
pub const STAGING_GRACE: Duration = Duration::from_secs(60 * 60);
/// Files one backup holds at most.
pub const MAX_BACKUP_FILES: usize = 64;
/// Bytes of file contents one backup holds at most.
pub const MAX_BACKUP_BYTES: usize = 4 * 1024 * 1024;
/// The longest path a backup records, in bytes.
pub const MAX_BACKUP_PATH: usize = 4096;

const MAGIC: [u8; 4] = *b"ECFB";
const FORMAT_VERSION: u8 = 1;
const MANIFEST_VERSION: u8 = 1;
/// `magic(4) version(1) vault_id(16) schema_version(2) epoch(4)
/// backup_id(16) created_at(8)`.
const HEADER_LEN: usize = 51;
const PREFIX: &str = "files-";
/// The largest record read back: a file's sealed contents at most.
const MAX_RECORD: usize = MAX_BACKUP_BYTES + Sealed::OVERHEAD;

/// A file backup's id: 16 random bytes, shown as 26 Crockford base32
/// characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileBackupId(pub [u8; 16]);

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

impl FileBackupId {
    /// A fresh random id (the daemon also names restore leases with one).
    pub fn generate() -> Self {
        let mut id = [0u8; 16];
        fill_random_or_panic(&mut id);
        FileBackupId(id)
    }

    /// Parses the 26-character form, in either case. `None` for anything
    /// else.
    pub fn parse(s: &str) -> Option<Self> {
        if s.len() != 26 {
            return None;
        }
        let mut v: u128 = 0;
        for (i, c) in s.bytes().enumerate() {
            let d = CROCKFORD
                .iter()
                .position(|&x| x == c.to_ascii_uppercase())?;
            // The first character carries 3 bits (128 = 26 * 5 - 2).
            if i == 0 && d > 7 {
                return None;
            }
            v = (v << 5) | d as u128;
        }
        Some(FileBackupId(v.to_be_bytes()))
    }
}

impl core::fmt::Display for FileBackupId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let v = u128::from_be_bytes(self.0);
        for i in 0..26 {
            let shift = 5 * (25 - i);
            f.write_str(
                core::str::from_utf8(&[CROCKFORD[((v >> shift) & 0x1f) as usize]])
                    .map_err(|_| core::fmt::Error)?,
            )?;
        }
        Ok(())
    }
}

/// One file in a backup.
#[derive(Debug)]
pub struct BackupFile {
    /// Where it was: an absolute path, as the client gave it.
    pub path: String,
    /// Its permission bits.
    pub mode: u32,
    pub content: SecretBytes,
}

/// A backup [`Vault::backup_files`] wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileBackupInfo {
    pub id: FileBackupId,
    pub path: PathBuf,
    /// Unix seconds.
    pub created_at: u64,
    pub files: usize,
    /// The backup file's size.
    pub bytes: u64,
}

/// What every record of one backup shares.
#[derive(Debug, Clone, Copy)]
struct Ctx {
    vault_id: crate::crypto::VaultId,
    schema_version: u16,
    epoch: u32,
    id: FileBackupId,
    created_at: u64,
}

impl Ctx {
    fn of(v: &Vault, id: FileBackupId, created_at: u64) -> Self {
        Ctx {
            vault_id: v.vault_id(),
            schema_version: v.schema_version(),
            epoch: v.epoch(),
            id,
            created_at,
        }
    }

    /// Record 0 is the backup's key, 1 the manifest, 2 and up the files.
    fn aad(&self, index: u64) -> Aad {
        Aad {
            vault_id: self.vault_id,
            schema_version: self.schema_version,
            key_epoch: self.epoch,
            table: TableTag::FileBackup,
            row_id: self.id.0,
            field: match index {
                0 => FieldTag::FileBackupKey,
                1 => FieldTag::FileBackupManifest,
                _ => FieldTag::FileBackupContent,
            },
            item_class: ItemClass::None,
            row_version: index,
        }
    }

    fn header(&self) -> [u8; HEADER_LEN] {
        let mut h = [0u8; HEADER_LEN];
        let mut at = 0;
        for part in [
            &MAGIC[..],
            &[FORMAT_VERSION],
            &self.vault_id.0,
            &self.schema_version.to_be_bytes(),
            &self.epoch.to_be_bytes(),
            &self.id.0,
            &self.created_at.to_be_bytes(),
        ] {
            h[at..at + part.len()].copy_from_slice(part);
            at += part.len();
        }
        h
    }
}

/// The header's fields, as read.
struct Header {
    vault_id: [u8; 16],
    schema_version: u16,
    epoch: u32,
    id: FileBackupId,
    created_at: u64,
}

fn parse_header(h: &[u8; HEADER_LEN]) -> Result<Header, VaultError> {
    let damaged = || VaultError::from(VaultErrorKind::BackupDamaged);
    if h[..4] != MAGIC || h[4] != FORMAT_VERSION {
        return Err(damaged());
    }
    let take = |from: usize, to: usize| &h[from..to];
    let mut vault_id = [0u8; 16];
    vault_id.copy_from_slice(take(5, 21));
    let schema_version = u16::from_be_bytes([h[21], h[22]]);
    let epoch = u32::from_be_bytes([h[23], h[24], h[25], h[26]]);
    let mut id = [0u8; 16];
    id.copy_from_slice(take(27, 43));
    let mut created = [0u8; 8];
    created.copy_from_slice(take(43, 51));
    Ok(Header {
        vault_id,
        schema_version,
        epoch,
        id: FileBackupId(id),
        created_at: u64::from_be_bytes(created),
    })
}

/// The manifest: the header's hash and each file's path, mode and length.
fn encode_manifest(header: &[u8], files: &[BackupFile]) -> Result<Vec<u8>, VaultError> {
    let too_large = || VaultError::from(VaultErrorKind::TooLarge);
    let mut m = Vec::new();
    m.push(MANIFEST_VERSION);
    m.extend_from_slice(&Sha256::digest(header));
    m.extend_from_slice(
        &u32::try_from(files.len())
            .map_err(|_| too_large())?
            .to_be_bytes(),
    );
    for f in files {
        let len = u16::try_from(f.path.len()).map_err(|_| too_large())?;
        m.extend_from_slice(&len.to_be_bytes());
        m.extend_from_slice(f.path.as_bytes());
        m.extend_from_slice(&f.mode.to_be_bytes());
        let size = u32::try_from(f.content.len()).map_err(|_| too_large())?;
        m.extend_from_slice(&size.to_be_bytes());
    }
    Ok(m)
}

/// One manifest entry: path, mode and length.
type Entry = (String, u32, usize);

/// Reads fixed-size pieces off the front of a slice.
struct Take<'a>(&'a [u8]);

impl<'a> Take<'a> {
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], VaultError> {
        let (head, tail) = self
            .0
            .split_at_checked(n)
            .ok_or(VaultErrorKind::BackupDamaged)?;
        self.0 = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], VaultError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.bytes(N)?);
        Ok(out)
    }
}

fn decode_manifest(b: &[u8]) -> Result<([u8; 32], Vec<Entry>), VaultError> {
    let damaged = || VaultError::from(VaultErrorKind::BackupDamaged);
    let mut r = Take(b);
    if r.array::<1>()? != [MANIFEST_VERSION] {
        return Err(damaged());
    }
    let hash = r.array::<32>()?;
    let count = usize::try_from(u32::from_be_bytes(r.array()?)).map_err(|_| damaged())?;
    if count == 0 || count > MAX_BACKUP_FILES {
        return Err(damaged());
    }
    let mut out = Vec::with_capacity(count);
    let mut total = 0usize;
    for _ in 0..count {
        let len = u16::from_be_bytes(r.array()?);
        let path = std::str::from_utf8(r.bytes(usize::from(len))?)
            .map_err(|_| damaged())?
            .to_owned();
        let mode = u32::from_be_bytes(r.array()?);
        let size = usize::try_from(u32::from_be_bytes(r.array()?)).map_err(|_| damaged())?;
        total = total.checked_add(size).ok_or_else(damaged)?;
        if total > MAX_BACKUP_BYTES {
            return Err(damaged());
        }
        out.push((path, mode, size));
    }
    if !r.0.is_empty() {
        return Err(damaged());
    }
    Ok((hash, out))
}

fn write_record(w: &mut impl Write, sealed: &[u8]) -> Result<(), VaultError> {
    let len =
        u32::try_from(sealed.len()).map_err(|_| VaultError::from(VaultErrorKind::TooLarge))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(sealed)?;
    Ok(())
}

fn read_record(r: &mut impl Read) -> Result<Vec<u8>, VaultError> {
    let mut len = [0u8; 4];
    read_exact(r, &mut len)?;
    let len = usize::try_from(u32::from_be_bytes(len))
        .map_err(|_| VaultError::from(VaultErrorKind::BackupDamaged))?;
    if len > MAX_RECORD {
        return Err(VaultErrorKind::BackupDamaged.into());
    }
    let mut buf = vec![0u8; len];
    read_exact(r, &mut buf)?;
    Ok(buf)
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

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The file name of backup `id`, made at `created_at`.
fn file_name(id: &FileBackupId, created_at: u64) -> String {
    format!(
        "{PREFIX}{}-{id}.{FILE_BACKUP_EXTENSION}",
        utc_stamp(created_at)
    )
}

impl Vault {
    /// Writes an encrypted backup of `files` to the `backups` directory
    /// and returns it once it is on disk. See the module documentation.
    ///
    /// Refused with [`VaultErrorKind::Tampered`] unless the vault verified,
    /// with [`VaultErrorKind::InvalidRecord`] for no files or a path that
    /// is empty or over [`MAX_BACKUP_PATH`], and with
    /// [`VaultErrorKind::TooLarge`] beyond [`MAX_BACKUP_FILES`] or
    /// [`MAX_BACKUP_BYTES`].
    pub fn backup_files(&self, files: &[BackupFile]) -> Result<FileBackupInfo, VaultError> {
        self.backup_files_observed(files, &mut || {})
    }

    /// [`Vault::backup_files`], calling `written` once the new file is
    /// written and flushed, before it is linked to its name: a unit test
    /// puts another file under its temporary name there.
    ///
    /// A link takes whatever has the temporary name at that moment, so the
    /// backup's name is then opened (never through a symlink) and compared
    /// by device and inode with the file written: another file put under
    /// the temporary name fails the backup (`InvalidRecord`), never
    /// answered as written, so nothing is deleted on the strength of it.
    fn backup_files_observed(
        &self,
        files: &[BackupFile],
        written: &mut dyn FnMut(),
    ) -> Result<FileBackupInfo, VaultError> {
        self.header()?;
        if files.is_empty()
            || files
                .iter()
                .any(|f| f.path.is_empty() || f.path.len() > MAX_BACKUP_PATH)
        {
            return Err(VaultErrorKind::InvalidRecord.into());
        }
        let total: usize = files.iter().map(|f| f.content.len()).sum();
        if files.len() > MAX_BACKUP_FILES || total > MAX_BACKUP_BYTES {
            return Err(VaultErrorKind::TooLarge.into());
        }
        let paths = self.paths();
        paths.ensure_dirs()?;
        // `backups/` opened once, never through a symlink in its place, and
        // everything made, linked and removed through it.
        envcloak_sys::pause_point("backups.open");
        let dir = open_private_child(&paths.backups_dir)?.ok_or(VaultErrorKind::NotFound)?;
        let created_at = now_secs();
        let id = FileBackupId::generate();
        let ctx = Ctx::of(self, id, created_at);
        let head = ctx.header();
        let key = SubKey::random(Purpose::Backup);
        let name = file_name(&id, created_at);
        let tmp = format!(".{name}.tmp");
        let (name_os, tmp_os) = (OsStr::new(&name), OsStr::new(&tmp));
        let made = self.write_files(&dir, tmp_os, &head, &ctx, &key, files);
        let linked = made.and_then(|file| {
            written();
            link_beneath(&dir, tmp_os, name_os)?;
            let (ours, named) = (file.metadata()?, open_beneath(&dir, name_os)?.metadata()?);
            if (ours.dev(), ours.ino()) != (named.dev(), named.ino()) {
                return Err(VaultError::from(VaultErrorKind::InvalidRecord));
            }
            Ok(ours.len())
        });
        let removed = match unlink_beneath(&dir, tmp_os) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(VaultError::from(e)),
        };
        let bytes = linked?;
        removed?;
        sync_file(&dir)?;
        Ok(FileBackupInfo {
            id,
            bytes,
            path: paths.backups_dir.join(&name),
            created_at,
            files: files.len(),
        })
    }

    /// Writes the backup to the new file `tmp` in `dir` (`O_EXCL`, never
    /// through a symlink, 0600) and flushes it. Returns it, open.
    fn write_files(
        &self,
        dir: &File,
        tmp: &OsStr,
        head: &[u8],
        ctx: &Ctx,
        key: &SubKey,
        files: &[BackupFile],
    ) -> Result<File, VaultError> {
        let file = create_beneath(dir, tmp, 0o600)?;
        let mut w = BufWriter::new(file);
        w.write_all(head)?;
        let wrapped = seal_subkey(self.keys().key(Purpose::Backup), &ctx.aad(0), key)?;
        write_record(&mut w, &wrapped.to_bytes())?;
        let manifest = encode_manifest(head, files)?;
        write_record(&mut w, &seal_record(key, &ctx.aad(1), &manifest)?)?;
        for (i, f) in files.iter().enumerate() {
            let sealed = seal_value(key, &ctx.aad(i as u64 + 2), &f.content)?;
            write_record(&mut w, &sealed)?;
        }
        let file = w
            .into_inner()
            .map_err(|e| VaultError::from(e.into_error()))?;
        sync_file(&file)?;
        Ok(file)
    }

    /// The files of backup `id`, byte for byte, with their paths and
    /// modes. Fails with [`VaultErrorKind::NotFound`] when no backup has
    /// that id (or it was purged), and with
    /// [`VaultErrorKind::BackupDamaged`] when the file was altered,
    /// truncated or extended, or belongs to another vault.
    pub fn open_file_backup(&self, id: &FileBackupId) -> Result<Vec<BackupFile>, VaultError> {
        self.header()?;
        let dir = open_private_child(&self.paths().backups_dir)?.ok_or(VaultErrorKind::NotFound)?;
        let name =
            find_backup(&dir, &self.paths().backups_dir, id)?.ok_or(VaultErrorKind::NotFound)?;
        let file = open_beneath(&dir, &name)?;
        if !file.metadata()?.is_file() {
            return Err(VaultErrorKind::BackupDamaged.into());
        }
        let mut r = BufReader::new(file);
        let mut head = [0u8; HEADER_LEN];
        read_exact(&mut r, &mut head)?;
        let h = parse_header(&head)?;
        let damaged = || VaultError::from(VaultErrorKind::BackupDamaged);
        if h.id != *id
            || h.vault_id != self.vault_id().0
            || h.epoch != self.epoch()
            || h.schema_version != self.schema_version()
        {
            return Err(damaged());
        }
        let ctx = Ctx::of(self, h.id, h.created_at);
        let wrapped = Sealed::from_bytes(&read_record(&mut r)?).map_err(|_| damaged())?;
        let key = open_subkey(
            self.keys().key(Purpose::Backup),
            &ctx.aad(0),
            &wrapped,
            Purpose::Backup,
        )
        .map_err(|_| damaged())?;
        let manifest = read_record(&mut r)?;
        let (hash, entries) =
            open_record(&key, &ctx.aad(1), &manifest, decode_manifest).map_err(|_| damaged())?;
        let want: [u8; 32] = Sha256::digest(head).into();
        if !bool::from(hash.ct_eq(&want)) {
            return Err(damaged());
        }
        let mut out = Vec::with_capacity(entries.len());
        for (i, (path, mode, size)) in entries.into_iter().enumerate() {
            let sealed = read_record(&mut r)?;
            let content =
                open_value(&key, &ctx.aad(i as u64 + 2), &sealed).map_err(|_| damaged())?;
            if content.len() != size {
                return Err(damaged());
            }
            out.push(BackupFile {
                path,
                mode,
                content,
            });
        }
        // Nothing may follow the last record.
        let mut extra = [0u8; 1];
        if r.read(&mut extra)? != 0 {
            return Err(damaged());
        }
        Ok(out)
    }
}

/// The name in `dir` (`backups/`, opened) of the backup file of `id`, by
/// its name: a file whose header was damaged is still found, and then
/// refused as damaged rather than missing.
fn find_backup(dir: &File, path: &Path, id: &FileBackupId) -> Result<Option<OsString>, VaultError> {
    let suffix = format!("-{id}.{FILE_BACKUP_EXTENSION}");
    Ok(list_backups(dir, path)?.into_iter().find_map(|(name, _)| {
        name.to_str()
            .is_some_and(|n| n.ends_with(&suffix))
            .then_some(name)
    }))
}

/// Whether the entry `e` of `dir` is a regular file now (never a symlink):
/// as the listing read it, or, where it could not tell, as `fstatat(2)`
/// without following a symlink says.
fn is_file_entry(dir: &File, e: &DirEntryName) -> bool {
    match e.kind {
        DirEntryKind::File => true,
        DirEntryKind::Unknown => kind_beneath(dir, &e.name).is_ok_and(|k| k == DirEntryKind::File),
        _ => false,
    }
}

/// The modification time of the file `name` in `dir` (`backups/`, opened,
/// whose path is `path`), in Unix seconds: through the file opened (never
/// through a symlink, never waiting on a FIFO) when it opens, else as
/// `lstat` reads `name` under `path` (a file this user cannot read, say);
/// 0 when neither does. Only a time is read by the path: whatever a purge
/// then removes, it removes through `dir`.
fn modified_secs(dir: &File, path: &Path, name: &OsStr) -> u64 {
    open_beneath(dir, name)
        .and_then(|f| f.metadata())
        .or_else(|_| std::fs::symlink_metadata(path.join(name)))
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs())
}

/// Every file backup in `dir` (`backups/`, opened; `path` is its path, for
/// [`modified_secs`]), by name, with the creation time its header
/// records, or its modification time when the header does not read.
fn list_backups(dir: &File, path: &Path) -> Result<Vec<(OsString, u64)>, VaultError> {
    let mut out = Vec::new();
    for entry in list_dir(dir, MAX_DIR_ENTRIES)? {
        let named = entry.name.to_str().is_some_and(|n| {
            n.starts_with(PREFIX) && n.ends_with(&format!(".{FILE_BACKUP_EXTENSION}"))
        });
        if !named || !is_file_entry(dir, &entry) {
            continue;
        }
        let mut head = [0u8; HEADER_LEN];
        let created_at = open_beneath(dir, &entry.name)
            .ok()
            .filter(|f| f.metadata().is_ok_and(|m| m.is_file()))
            .filter(|f| read_exact(&mut &*f, &mut head).is_ok())
            .and_then(|_| parse_header(&head).ok())
            .map(|h| h.created_at);
        let created_at = match created_at {
            Some(t) => t,
            None => modified_secs(dir, path, &entry.name),
        };
        out.push((entry.name, created_at));
    }
    out.sort();
    Ok(out)
}

/// The staging files of file backups in `dir` (`backups/`, opened) that
/// interrupted writes left: regular files (a symlink is never one) named
/// `.files-*.ecfiles.tmp`, not modified for [`STAGING_GRACE`] before `now`
/// (Unix seconds). Complete or partial, they hold ciphertext only, and no
/// backup that is being written is this old.
fn stale_staging(dir: &File, path: &Path, now: u64) -> Result<Vec<OsString>, VaultError> {
    let mut out = Vec::new();
    for entry in list_dir(dir, MAX_DIR_ENTRIES)? {
        let named = entry.name.to_str().is_some_and(|n| {
            n.starts_with(&format!(".{PREFIX}"))
                && n.ends_with(&format!(".{FILE_BACKUP_EXTENSION}.tmp"))
        });
        if !named || !is_file_entry(dir, &entry) {
            continue;
        }
        let modified = modified_secs(dir, path, &entry.name);
        if now.saturating_sub(modified) > STAGING_GRACE.as_secs() {
            out.push(entry.name);
        }
    }
    Ok(out)
}

/// Removes the file backups in `p` made more than
/// [`FILE_BACKUP_RETENTION`] before `now` (Unix seconds), and the staging
/// files interrupted writes left, unchanged for [`STAGING_GRACE`]. Returns
/// how many files it removed. Needs no key: the time is in the header.
///
/// `backups/` is opened once, through the data directory that names it,
/// never through a symlink in place of either (one is refused, and
/// nothing is removed), and checked through the descriptor opened; each
/// file is removed through that handle (`unlinkat(2)`, which removes a
/// symlink put in a file's place itself, never what it points at), so
/// nothing outside the vault's `backups/` is removed. The removals are
/// flushed (`envcloak_sys::sync_file` on `backups/`), and a failed flush
/// fails the purge.
///
/// # Errors
/// When `backups/` cannot be opened, is not one this user alone may write
/// ([`VaultErrorKind::Path`]), or cannot be read, a file cannot be
/// removed, or the removals cannot be flushed.
pub fn purge_file_backups(p: &VaultPaths, now: u64) -> Result<usize, VaultError> {
    let Some(dir) = open_private_child(&p.backups_dir)? else {
        return Ok(0);
    };
    let mut removed = 0;
    let old = list_backups(&dir, &p.backups_dir)?
        .into_iter()
        .filter(|(_, created_at)| now.saturating_sub(*created_at) > FILE_BACKUP_RETENTION.as_secs())
        .map(|(name, _)| name);
    let stale = stale_staging(&dir, &p.backups_dir, now)?;
    for name in old.chain(stale) {
        match unlink_beneath(&dir, &name) {
            Ok(()) => removed += 1,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    if removed > 0 {
        sync_file(&dir)?;
    }
    Ok(removed)
}

/// Rewrites the creation time in a backup's header. Test support only
/// (feature `testing`): the header is authenticated through the manifest,
/// so the backup then no longer opens, but purging reads only the header.
#[cfg(feature = "testing")]
pub fn age_file_backup_for_testing(path: &Path, created_at: u64) -> Result<(), VaultError> {
    use std::io::{Seek, SeekFrom};
    let mut f = std::fs::File::options().read(true).write(true).open(path)?;
    f.seek(SeekFrom::Start(43))?;
    f.write_all(&created_at.to_be_bytes())?;
    Ok(f.sync_all()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_round_trip_and_reject_anything_else() {
        for _ in 0..100 {
            let id = FileBackupId::generate();
            let s = id.to_string();
            assert_eq!(s.len(), 26);
            assert_eq!(FileBackupId::parse(&s), Some(id));
            assert_eq!(FileBackupId::parse(&s.to_ascii_lowercase()), Some(id));
        }
        for bad in [
            "",
            "0",
            "8ZZZZZZZZZZZZZZZZZZZZZZZZZ",
            "0000000000000000000000000I",
            "00000000000000000000000000X",
            "000000000000000000000000U0",
        ] {
            assert_eq!(FileBackupId::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_header_layout_is_fixed() {
        assert_eq!(HEADER_LEN, 4 + 1 + 16 + 2 + 4 + 16 + 8);
        let ctx = Ctx {
            vault_id: crate::crypto::VaultId([7; 16]),
            schema_version: 3,
            epoch: 9,
            id: FileBackupId([5; 16]),
            created_at: 1_790_000_000,
        };
        let h = parse_header(&ctx.header()).unwrap();
        assert_eq!(h.vault_id, [7; 16]);
        assert_eq!((h.schema_version, h.epoch), (3, 9));
        assert_eq!(h.id, FileBackupId([5; 16]));
        assert_eq!(h.created_at, 1_790_000_000);
    }

    #[test]
    fn a_manifest_decodes_only_whole() {
        let files = [BackupFile {
            path: "/p/.env".into(),
            mode: 0o600,
            content: SecretBytes::copy_from(b"A=1\n"),
        }];
        let m = encode_manifest(b"header", &files).unwrap();
        let (hash, entries) = decode_manifest(&m).unwrap();
        assert_eq!(hash, <[u8; 32]>::from(Sha256::digest(b"header")));
        assert_eq!(entries, [("/p/.env".to_owned(), 0o600, 4)]);
        for cut in 0..m.len() {
            assert!(decode_manifest(&m[..cut]).is_err(), "{cut}");
        }
        let mut longer = m.clone();
        longer.push(0);
        assert!(decode_manifest(&longer).is_err());
    }

    /// A backup is answered as written only when its name holds the file
    /// written (a link takes whatever has the temporary name at that
    /// moment, and `init` deletes plaintext on the strength of the
    /// answer): once the new file is flushed, another file, or a symlink
    /// to a file elsewhere, is put under its temporary name. The backup
    /// fails, the symlink's target is as it was, and nothing named for
    /// the backup opens as one.
    #[test]
    fn a_backup_is_answered_only_for_the_file_written() {
        for symlink in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let paths = VaultPaths::under(dir.path().join("data"));
            let (v, _) = crate::create_vault(
                &paths,
                &SecretBytes::copy_from(b"a test passphrase, not a fixture"),
                crate::crypto::KdfParams::minimum(),
            )
            .unwrap();
            let outside = dir.path().join("outside");
            std::fs::write(&outside, b"not a backup").unwrap();
            let files = [BackupFile {
                path: "/p/.env".into(),
                mode: 0o600,
                content: SecretBytes::copy_from(b"A=1\n"),
            }];
            let backups = paths.backups_dir.clone();
            let mut did = 0;
            let e = v.backup_files_observed(&files, &mut || {
                let temp = std::fs::read_dir(&backups)
                    .unwrap()
                    .map(|e| e.unwrap().file_name().into_string().unwrap())
                    .find(|n| n.starts_with(".files-") && n.ends_with(".tmp"))
                    .unwrap();
                let other = backups.join("other");
                if symlink {
                    std::os::unix::fs::symlink(&outside, &other).unwrap();
                } else {
                    std::fs::write(&other, b"not a backup either").unwrap();
                }
                std::fs::rename(&other, backups.join(temp)).unwrap();
                did += 1;
            });
            assert_eq!(did, 1);
            assert!(
                e.is_err(),
                "symlink {symlink}: a backup answered as written for a file it did not write"
            );
            assert_eq!(std::fs::read(&outside).unwrap(), b"not a backup");
            let named: Vec<_> =
                list_backups(&open_private_child(&backups).unwrap().unwrap(), &backups).unwrap();
            for (name, _) in named {
                let id = name
                    .to_str()
                    .and_then(|n| n.strip_suffix(".ecfiles"))
                    .and_then(|n| n.rsplit('-').next())
                    .and_then(FileBackupId::parse)
                    .unwrap();
                assert!(v.open_file_backup(&id).is_err());
            }
        }
    }
}
