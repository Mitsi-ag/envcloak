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

use std::fs::OpenOptions;
use std::io::{BufReader, BufWriter, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::crypto::{
    Aad, FieldTag, ItemClass, Purpose, Sealed, SubKey, TableTag, fill_random_or_panic, open_subkey,
    seal_subkey,
};
use crate::secret::SecretBytes;
use crate::vault::{
    Vault, VaultError, VaultErrorKind, VaultPaths, check_private_dir, open_record, open_value,
    seal_record, seal_value, sync_dir, utc_stamp,
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
    fn generate() -> Self {
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
        let dir = std::fs::canonicalize(&paths.backups_dir)?;
        check_private_dir(&dir)?;
        let created_at = now_secs();
        let id = FileBackupId::generate();
        let ctx = Ctx::of(self, id, created_at);
        let head = ctx.header();
        let key = SubKey::random(Purpose::Backup);
        let name = file_name(&id, created_at);
        let path = dir.join(&name);
        let tmp = dir.join(format!(".{name}.tmp"));
        let written = self.write_files(&tmp, &head, &ctx, &key, files);
        let linked = written.and_then(|()| Ok(std::fs::hard_link(&tmp, &path)?));
        let removed = match std::fs::remove_file(&tmp) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(VaultError::from(e)),
        };
        linked?;
        removed?;
        sync_dir(&dir)?;
        Ok(FileBackupInfo {
            id,
            bytes: std::fs::metadata(&path)?.len(),
            path,
            created_at,
            files: files.len(),
        })
    }

    fn write_files(
        &self,
        tmp: &Path,
        head: &[u8],
        ctx: &Ctx,
        key: &SubKey,
        files: &[BackupFile],
    ) -> Result<(), VaultError> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(tmp)?;
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
        Ok(file.sync_all()?)
    }

    /// The files of backup `id`, byte for byte, with their paths and
    /// modes. Fails with [`VaultErrorKind::NotFound`] when no backup has
    /// that id (or it was purged), and with
    /// [`VaultErrorKind::BackupDamaged`] when the file was altered,
    /// truncated or extended, or belongs to another vault.
    pub fn open_file_backup(&self, id: &FileBackupId) -> Result<Vec<BackupFile>, VaultError> {
        self.header()?;
        let (path, _) = find_backup(self.paths(), id)?.ok_or(VaultErrorKind::NotFound)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)?;
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

/// The backup file of `id` in `p`'s backups directory, by its name: a
/// file whose header was damaged is still found, and then refused as
/// damaged rather than missing.
fn find_backup(p: &VaultPaths, id: &FileBackupId) -> Result<Option<(PathBuf, u64)>, VaultError> {
    let suffix = format!("-{id}.{FILE_BACKUP_EXTENSION}");
    Ok(list_backups(p)?.into_iter().find(|(path, _)| {
        path.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with(&suffix))
    }))
}

/// Every file backup in `p`'s backups directory, with the creation time
/// its header records, or its modification time when the header does not
/// read.
fn list_backups(p: &VaultPaths) -> Result<Vec<(PathBuf, u64)>, VaultError> {
    let dir = match std::fs::canonicalize(&p.backups_dir) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    check_private_dir(&dir)?;
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let named = name.to_str().is_some_and(|n| {
            n.starts_with(PREFIX) && n.ends_with(&format!(".{FILE_BACKUP_EXTENSION}"))
        });
        if !named || !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        let modified = entry
            .metadata()?
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs());
        let mut head = [0u8; HEADER_LEN];
        let created_at = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
            .ok()
            .filter(|f| read_exact(&mut &*f, &mut head).is_ok())
            .and_then(|_| parse_header(&head).ok())
            .map_or(modified, |h| h.created_at);
        out.push((path, created_at));
    }
    out.sort();
    Ok(out)
}

/// The staging files of file backups in `p`'s backups directory that
/// interrupted writes left: regular files (a symlink is never one) named
/// `.files-*.ecfiles.tmp`, not modified for [`STAGING_GRACE`] before
/// `now` (Unix seconds). Complete or partial, they hold ciphertext only,
/// and no backup that is being written is this old.
fn stale_staging(p: &VaultPaths, now: u64) -> Result<Vec<PathBuf>, VaultError> {
    let dir = match std::fs::canonicalize(&p.backups_dir) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    check_private_dir(&dir)?;
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let named = name.to_str().is_some_and(|n| {
            n.starts_with(&format!(".{PREFIX}"))
                && n.ends_with(&format!(".{FILE_BACKUP_EXTENSION}.tmp"))
        });
        // `DirEntry` reads the entry itself: a symlink is not followed.
        if !named || !entry.file_type()?.is_file() {
            continue;
        }
        let modified = entry
            .metadata()?
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs());
        if now.saturating_sub(modified) > STAGING_GRACE.as_secs() {
            out.push(entry.path());
        }
    }
    Ok(out)
}

/// Removes the file backups in `p` made more than
/// [`FILE_BACKUP_RETENTION`] before `now` (Unix seconds), and the staging
/// files interrupted writes left, unchanged for [`STAGING_GRACE`]. Returns
/// how many files it removed. Needs no key: the time is in the header.
pub fn purge_file_backups(p: &VaultPaths, now: u64) -> Result<usize, VaultError> {
    let mut removed = 0;
    let old = list_backups(p)?
        .into_iter()
        .filter(|(_, created_at)| now.saturating_sub(*created_at) > FILE_BACKUP_RETENTION.as_secs())
        .map(|(path, _)| path);
    for path in old.chain(stale_staging(p, now)?) {
        match std::fs::remove_file(&path) {
            Ok(()) => removed += 1,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    if removed > 0 {
        sync_dir(&std::fs::canonicalize(&p.backups_dir)?)?;
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
}
