//! File backups v2: chunked, encrypted backups of any file under an
//! allowed root, about to be modified or deleted (SPEC §6.4 "Backups", M2
//! plan D-07; the format is in docs/VAULT.md "File backups v2").
//!
//! A backup is built in steps, so no step holds more than one chunk of a
//! file in memory:
//! 1. [`Vault::begin_file_backup_v2`] checks the files' declared sizes
//!    against the caps (a file over [`MAX_FILE_V2`], a backup over
//!    [`MAX_BACKUP_V2`] or over [`MAX_FILES_V2`] files is refused
//!    [`VaultErrorKind::TooLarge`], never cut), makes a staging directory
//!    `.files2-<UTC time>-<id>.tmp/` in `backups/`, and starts its `data`
//!    file (`O_EXCL`, 0600) with a plaintext header and record 0: a fresh
//!    256-bit key for this backup alone, sealed under the vault's `backup`
//!    subkey.
//! 2. [`FileBackupV2Writer::put`] takes each chunk of each file in order:
//!    every chunk but a file's last holds exactly [`CHUNK_V2`] bytes, the
//!    last the rest (a file of 0 bytes has one empty chunk). Each is
//!    sealed under the backup's key, bound by its associated data to the
//!    backup's id, the file's index, the chunk's index and whether it is
//!    the file's last, and the SHA-256 of each file is computed from the
//!    chunks as they pass.
//! 3. [`FileBackupV2Writer::commit`] seals the metadata after the chunks:
//!    the header's SHA-256, the chunk size, the purpose, the creator (its
//!    subject kind, evidence digest, agent label and process instance, as
//!    the daemon read them; never anything the client said), and per file
//!    its display path, mode, size and SHA-256. It flushes the file and the
//!    staging directory, renames the directory to `files2-<UTC time>-<id>/`
//!    and flushes `backups/`. Only then is the backup listed: an
//!    interrupted backup is a staging directory, never listed, which a
//!    purge removes once it is [`STAGING_GRACE`] old.
//!
//! After the change, [`Vault::record_file_backup_v2_result`] records what
//! the change left in each file (its SHA-256), once per file, each in a
//! file of its own (`result-<index>`, `O_EXCL`), sealed under the
//! backup's key: the "restore only while the file is what the change
//! left" check compares against it.
//!
//! [`Vault::open_file_backup_v2`] opens a backup for reading: it checks
//! the header, the key, the metadata and the layout every chunk must have,
//! so a backup missing a chunk (its final one included) or with one too
//! many never opens. [`FileBackupV2Reader::verify`] opens every chunk and
//! compares each file's SHA-256, and [`FileBackupV2Reader::chunk`] reads
//! one chunk, opened with the associated data of the place it is read
//! for: a chunk swapped, moved, duplicated or cut does not open there.
//! Every failure is [`VaultErrorKind::BackupDamaged`], which says nothing
//! of the contents.
//!
//! No plaintext copy or temporary file of the contents is ever written:
//! the staging file holds only the header and sealed records.
//! [`purge_file_backups_v2`] removes backups older than
//! [`FILE_BACKUP_RETENTION`] (7 days) by the time in their header, and
//! staging directories interrupted backups left.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::os::unix::fs::{DirBuilderExt, FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::crypto::{
    Aad, FieldTag, ItemClass, Purpose, Sealed, SubKey, TableTag, VaultId, open_subkey, seal_subkey,
};
use crate::file_backup::{FILE_BACKUP_RETENTION, FileBackupId, STAGING_GRACE};
use crate::secret::SecretBytes;
use crate::vault::codec::{Dec, Enc};
use crate::vault::{
    Vault, VaultError, VaultErrorKind, VaultPaths, check_private_dir, open_record, open_value,
    seal_record, seal_value, sha256_update, sync_dir, utc_stamp,
};

/// The bytes of a file each chunk holds, but a file's last: 512 KiB. A
/// chunk crosses the socket base64-encoded in one frame, which is at most
/// 1 MiB (gate 32), so a chunk record holds well under 1 MiB.
pub const CHUNK_V2: usize = 512 * 1024;
/// The largest file a backup holds: 256 MiB.
pub const MAX_FILE_V2: u64 = 256 * 1024 * 1024;
/// The most bytes of files one backup holds: 1 GiB.
pub const MAX_BACKUP_V2: u64 = 1024 * 1024 * 1024;
/// The most files one backup holds.
pub const MAX_FILES_V2: usize = 4096;
/// The longest display path a backup records, in bytes.
pub const MAX_PATH_V2: usize = 4096;
/// The longest agent label a backup records, in bytes.
pub const MAX_LABEL_V2: usize = 256;

const MAGIC: [u8; 4] = *b"ECF2";
const FORMAT_VERSION: u8 = 2;
const METADATA_VERSION: u8 = 1;
const RESULT_VERSION: u8 = 1;
/// `magic(4) version(1) vault_id(16) schema_version(2) epoch(4)
/// backup_id(16) created_at(8)`.
pub const HEADER_LEN_V2: usize = 51;
const TRAILER_LEN: usize = 8;
const PREFIX: &str = "files2-";
const STAGING_SUFFIX: &str = ".tmp";
/// The file in a backup's directory that holds its records.
const DATA: &str = "data";
/// Each result's file name: `result-<file index>`.
const RESULT: &str = "result-";
/// The row version of a result: this bit, with the file's index.
const RESULT_BIT: u64 = 1 << 63;
/// The largest chunk record: a full chunk, sealed.
const MAX_CHUNK_RECORD: usize = CHUNK_V2 + Sealed::OVERHEAD;
/// The largest metadata record: every file at the longest path.
const MAX_METADATA: usize = 256 + MAX_LABEL_V2 + MAX_FILES_V2 * (2 + MAX_PATH_V2 + 4 + 8 + 32);

/// What a backup is for: the change it was made before.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BackupPurpose {
    /// `envcloak init` deleting plaintext.
    Init = 1,
    /// `envcloak scrub` rewriting transcripts.
    Scrub = 2,
    /// `envcloak agents install` editing an agent's config.
    Agents = 3,
    /// `envcloak agents migrate-mcp` rewriting an MCP config.
    Migrate = 4,
}

impl BackupPurpose {
    pub const ALL: [BackupPurpose; 4] = [
        BackupPurpose::Init,
        BackupPurpose::Scrub,
        BackupPurpose::Agents,
        BackupPurpose::Migrate,
    ];

    /// The purpose's stable name: `init`, `scrub`, `agents` or `migrate`.
    pub const fn as_str(self) -> &'static str {
        match self {
            BackupPurpose::Init => "init",
            BackupPurpose::Scrub => "scrub",
            BackupPurpose::Agents => "agents",
            BackupPurpose::Migrate => "migrate",
        }
    }

    /// The purpose with this token.
    pub fn from_token(t: &str) -> Option<BackupPurpose> {
        BackupPurpose::ALL.into_iter().find(|p| p.as_str() == t)
    }

    fn from_u8(v: u8) -> Option<BackupPurpose> {
        BackupPurpose::ALL.into_iter().find(|p| *p as u8 == v)
    }
}

/// Who made a backup, as the daemon's evidence classed the subject that
/// began it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CreatorKind {
    Terminal = 1,
    Agent = 2,
    Unknown = 3,
}

impl CreatorKind {
    pub const ALL: [CreatorKind; 3] = [
        CreatorKind::Terminal,
        CreatorKind::Agent,
        CreatorKind::Unknown,
    ];

    /// `terminal`, `agent` or `unknown`.
    pub const fn as_str(self) -> &'static str {
        match self {
            CreatorKind::Terminal => "terminal",
            CreatorKind::Agent => "agent",
            CreatorKind::Unknown => "unknown",
        }
    }

    fn from_u8(v: u8) -> Option<CreatorKind> {
        CreatorKind::ALL.into_iter().find(|k| *k as u8 == v)
    }
}

/// The process instance that began a backup: only it may add chunks,
/// commit and record results (M2 plan D-07). An instance identity, not a
/// code identity: the pid with its start time as the kernel records it,
/// and on macOS the audit token's pid version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BackupOwner {
    pub pid: i32,
    /// The kernel's start time (`envcloak_sys::StartTime::raw`).
    pub start_time: u64,
    /// macOS: the pid version from the audit token. `None` on Linux.
    pub token: Option<i32>,
}

/// What the daemon seals into a backup about who made it. Never taken from
/// the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupCreator {
    pub kind: CreatorKind,
    /// SHA-256 of the creator's evidence as the daemon read it.
    pub evidence_digest: [u8; 32],
    /// The agent's display name, when one is involved.
    pub agent: Option<String>,
    pub owner: BackupOwner,
}

/// One file a backup will hold, as declared at its start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedFile {
    /// Where it is: an absolute path, as the client gave it. Display only.
    pub path: String,
    /// Its permission bits.
    pub mode: u32,
    pub size: u64,
}

/// One file a committed backup holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMetaV2 {
    pub path: String,
    pub mode: u32,
    pub size: u64,
    /// SHA-256 of the contents, computed from the chunks as they passed.
    pub sha256: [u8; 32],
}

/// A committed backup's sealed metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupMetaV2 {
    pub id: FileBackupId,
    /// Unix seconds, from the header.
    pub created_at: u64,
    pub purpose: BackupPurpose,
    pub creator: BackupCreator,
    pub files: Vec<FileMetaV2>,
}

/// A backup [`FileBackupV2Writer::commit`] put in place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedV2 {
    pub id: FileBackupId,
    /// Its directory in `backups/`.
    pub dir: PathBuf,
    pub created_at: u64,
    pub files: usize,
    /// The size of its `data` file.
    pub bytes: u64,
}

/// A point a backup's writer passes, for the crash tests (feature
/// `testing`): each is reported after the step is done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepV2 {
    /// The staging directory and its `data` file exist.
    Staged,
    /// The header and the sealed key are written.
    Started,
    /// A chunk is written.
    Chunk,
    /// The metadata and the trailer are written.
    MetadataWritten,
    /// The `data` file and the staging directory are flushed.
    Synced,
    /// The staging directory has its final name.
    Installed,
    /// `backups/` is flushed: the backup is durable.
    Done,
}

/// How many chunks a file of `size` bytes has: one at least.
pub fn chunks_of(size: u64) -> u64 {
    size.div_ceil(CHUNK_V2 as u64).max(1)
}

/// The bytes chunk `chunk` of a file of `size` bytes holds, or `None`
/// beyond its last.
pub fn chunk_len(size: u64, chunk: u64) -> Option<usize> {
    let n = chunks_of(size);
    if chunk >= n {
        return None;
    }
    let start = chunk * CHUNK_V2 as u64;
    usize::try_from((size - start).min(CHUNK_V2 as u64)).ok()
}

/// Fails unless `files` is a backup this build takes: 1 to
/// [`MAX_FILES_V2`] files, each at most [`MAX_FILE_V2`] bytes, at most
/// [`MAX_BACKUP_V2`] in all ([`VaultErrorKind::TooLarge`]), each path 1 to
/// [`MAX_PATH_V2`] bytes without a NUL byte
/// ([`VaultErrorKind::InvalidRecord`]).
pub fn check_plan(files: &[PlannedFile]) -> Result<(), VaultError> {
    if files.is_empty() {
        return Err(VaultErrorKind::InvalidRecord.into());
    }
    if files.len() > MAX_FILES_V2 {
        return Err(VaultErrorKind::TooLarge.into());
    }
    let mut total: u64 = 0;
    for f in files {
        if f.path.is_empty() || f.path.len() > MAX_PATH_V2 || f.path.contains('\0') {
            return Err(VaultErrorKind::InvalidRecord.into());
        }
        if f.size > MAX_FILE_V2 {
            return Err(VaultErrorKind::TooLarge.into());
        }
        total = total.saturating_add(f.size);
    }
    if total > MAX_BACKUP_V2 {
        return Err(VaultErrorKind::TooLarge.into());
    }
    Ok(())
}

/// What every record of one backup shares.
#[derive(Debug, Clone, Copy)]
struct Ctx {
    vault_id: VaultId,
    schema_version: u16,
    epoch: u32,
    id: FileBackupId,
    created_at: u64,
}

/// Which record an associated data is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rec {
    Key,
    Metadata,
    Result(u32),
    Chunk { file: u32, chunk: u32, last: bool },
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

    /// The associated data of record `r`: the backup's id is the row id,
    /// and the row version says which record. A chunk's is its file index
    /// (high 32 bits), its chunk index (the next 31) and whether it is its
    /// file's last (the lowest bit).
    fn aad(&self, r: Rec) -> Aad {
        let (field, row_version) = match r {
            Rec::Key => (FieldTag::FileBackupV2Key, 0),
            Rec::Metadata => (FieldTag::FileBackupV2Metadata, 0),
            Rec::Result(file) => (FieldTag::FileBackupV2Metadata, RESULT_BIT | u64::from(file)),
            Rec::Chunk { file, chunk, last } => (
                FieldTag::FileBackupV2Chunk,
                (u64::from(file) << 32) | (u64::from(chunk) << 1) | u64::from(last),
            ),
        };
        Aad {
            vault_id: self.vault_id,
            schema_version: self.schema_version,
            key_epoch: self.epoch,
            table: TableTag::FileBackupV2,
            row_id: self.id.0,
            field,
            item_class: ItemClass::None,
            row_version,
        }
    }

    fn header(&self) -> [u8; HEADER_LEN_V2] {
        let mut h = [0u8; HEADER_LEN_V2];
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

/// A header's fields, as read.
#[derive(Debug, Clone, Copy)]
struct Header {
    vault_id: [u8; 16],
    schema_version: u16,
    epoch: u32,
    id: FileBackupId,
    created_at: u64,
}

fn damaged() -> VaultError {
    VaultErrorKind::BackupDamaged.into()
}

fn parse_header(h: &[u8; HEADER_LEN_V2]) -> Result<Header, VaultError> {
    if h[..4] != MAGIC || h[4] != FORMAT_VERSION {
        return Err(damaged());
    }
    let mut vault_id = [0u8; 16];
    vault_id.copy_from_slice(&h[5..21]);
    let mut id = [0u8; 16];
    id.copy_from_slice(&h[27..43]);
    let mut created = [0u8; 8];
    created.copy_from_slice(&h[43..51]);
    Ok(Header {
        vault_id,
        schema_version: u16::from_be_bytes([h[21], h[22]]),
        epoch: u32::from_be_bytes([h[23], h[24], h[25], h[26]]),
        id: FileBackupId(id),
        created_at: u64::from_be_bytes(created),
    })
}

fn encode_metadata(
    header: &[u8],
    purpose: BackupPurpose,
    creator: &BackupCreator,
    files: &[FileMetaV2],
) -> Vec<u8> {
    let mut e = Enc::new();
    e.u8(METADATA_VERSION)
        .raw(&Sha256::digest(header))
        .raw(&u32::try_from(CHUNK_V2).unwrap_or(u32::MAX).to_be_bytes())
        .u8(purpose as u8)
        .u8(creator.kind as u8)
        .raw(&creator.evidence_digest)
        .opt_str(creator.agent.as_deref())
        .raw(&creator.owner.pid.to_be_bytes())
        .u64(creator.owner.start_time);
    match creator.owner.token {
        None => e.u8(0),
        Some(t) => e.u8(1).raw(&t.to_be_bytes()),
    };
    e.raw(&u32::try_from(files.len()).unwrap_or(u32::MAX).to_be_bytes());
    for f in files {
        e.str(&f.path)
            .raw(&f.mode.to_be_bytes())
            .u64(f.size)
            .raw(&f.sha256);
    }
    e.finish()
}

/// The metadata as decoded: the header's hash, and the rest.
struct Decoded {
    header_hash: [u8; 32],
    purpose: BackupPurpose,
    creator: BackupCreator,
    files: Vec<FileMetaV2>,
}

fn decode_metadata(b: &[u8]) -> Result<Decoded, VaultError> {
    let mut d = Dec::new(b);
    if d.u8()? != METADATA_VERSION {
        return Err(damaged());
    }
    let header_hash = d.array()?;
    if usize::try_from(d.u32()?).ok() != Some(CHUNK_V2) {
        return Err(damaged());
    }
    let purpose = BackupPurpose::from_u8(d.u8()?).ok_or_else(damaged)?;
    let kind = CreatorKind::from_u8(d.u8()?).ok_or_else(damaged)?;
    let evidence_digest = d.array()?;
    let agent = d.opt_string()?;
    if agent.as_ref().is_some_and(|a| a.len() > MAX_LABEL_V2) {
        return Err(damaged());
    }
    let pid = i32::from_be_bytes(d.array()?);
    let start_time = d.u64()?;
    let token = if d.bool()? {
        Some(i32::from_be_bytes(d.array()?))
    } else {
        None
    };
    let count = usize::try_from(d.u32()?).map_err(|_| damaged())?;
    if count == 0 || count > MAX_FILES_V2 {
        return Err(damaged());
    }
    let mut files = Vec::with_capacity(count);
    let mut total: u64 = 0;
    for _ in 0..count {
        let path = d.string()?;
        let mode = u32::from_be_bytes(d.array()?);
        let size = d.u64()?;
        let sha256 = d.array()?;
        total = total.saturating_add(size);
        if path.is_empty() || path.len() > MAX_PATH_V2 || size > MAX_FILE_V2 {
            return Err(damaged());
        }
        files.push(FileMetaV2 {
            path,
            mode,
            size,
            sha256,
        });
    }
    if total > MAX_BACKUP_V2 {
        return Err(damaged());
    }
    d.end()?;
    Ok(Decoded {
        header_hash,
        purpose,
        creator: BackupCreator {
            kind,
            evidence_digest,
            agent,
            owner: BackupOwner {
                pid,
                start_time,
                token,
            },
        },
        files,
    })
}

fn write_record(w: &mut impl Write, sealed: &[u8]) -> Result<u64, VaultError> {
    let len =
        u32::try_from(sealed.len()).map_err(|_| VaultError::from(VaultErrorKind::TooLarge))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(sealed)?;
    Ok(4 + u64::from(len))
}

/// Reads exactly `buf.len()` bytes at `at`; a short read is damage.
fn read_at(f: &File, buf: &mut [u8], at: u64) -> Result<(), VaultError> {
    f.read_exact_at(buf, at).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            damaged()
        } else {
            VaultError::from(e)
        }
    })
}

/// The record at `at`: its length, which must be `want` when given and at
/// most `max`, then its bytes. Returns the bytes and where the next record
/// starts.
fn read_record_at(
    f: &File,
    at: u64,
    max: usize,
    want: Option<usize>,
) -> Result<(Vec<u8>, u64), VaultError> {
    let mut len = [0u8; 4];
    read_at(f, &mut len, at)?;
    let len = usize::try_from(u32::from_be_bytes(len)).map_err(|_| damaged())?;
    if len > max || want.is_some_and(|w| w != len) {
        return Err(damaged());
    }
    let mut buf = vec![0u8; len];
    read_at(f, &mut buf, at + 4)?;
    Ok((buf, at + 4 + len as u64))
}

/// The name of a backup's directory.
fn dir_name(id: &FileBackupId, created_at: u64) -> String {
    format!("{PREFIX}{}-{id}", utc_stamp(created_at))
}

/// The backups directory, made if missing and checked.
fn backups_dir(p: &VaultPaths) -> Result<PathBuf, VaultError> {
    p.ensure_dirs()?;
    let dir = std::fs::canonicalize(&p.backups_dir)?;
    check_private_dir(&dir)?;
    Ok(dir)
}

/// Builds a backup (see the module documentation). Dropped before
/// [`FileBackupV2Writer::commit`], it removes its staging directory. Its
/// `Debug` shows the id and where it is, never a key or a byte of a file.
pub struct FileBackupV2Writer {
    ctx: Ctx,
    key: SubKey,
    backups: PathBuf,
    staging: PathBuf,
    final_dir: PathBuf,
    out: Option<BufWriter<File>>,
    /// Bytes written to `data` so far.
    offset: u64,
    header_hash: [u8; 32],
    purpose: BackupPurpose,
    creator: BackupCreator,
    plan: Vec<PlannedFile>,
    next_file: usize,
    next_chunk: u64,
    hasher: Sha256,
    digests: Vec<[u8; 32]>,
    done: bool,
    observe: Option<Observer>,
}

/// What a test build's writer reports its steps to.
type Observer = Box<dyn FnMut(StepV2) + Send>;

impl core::fmt::Debug for FileBackupV2Writer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FileBackupV2Writer")
            .field("id", &self.ctx.id)
            .field("next_file", &self.next_file)
            .field("next_chunk", &self.next_chunk)
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Starts a backup of `files` for `purpose`, made by `creator`, at
    /// `created_at` (Unix seconds). See the module documentation.
    ///
    /// # Errors
    /// [`VaultErrorKind::Tampered`] unless the vault verified; as
    /// [`check_plan`]; an I/O or path error when the staging directory
    /// cannot be made.
    pub fn begin_file_backup_v2(
        &self,
        purpose: BackupPurpose,
        creator: BackupCreator,
        files: Vec<PlannedFile>,
        created_at: u64,
    ) -> Result<FileBackupV2Writer, VaultError> {
        self.begin_v2(purpose, creator, files, created_at, None)
    }

    /// [`Vault::begin_file_backup_v2`], reporting each step to `observe`
    /// as it is done, the first ones included. Test support only (feature
    /// `testing`): the crash tests stop the writer there.
    #[cfg(feature = "testing")]
    pub fn begin_file_backup_v2_observed(
        &self,
        purpose: BackupPurpose,
        creator: BackupCreator,
        files: Vec<PlannedFile>,
        created_at: u64,
        observe: impl FnMut(StepV2) + Send + 'static,
    ) -> Result<FileBackupV2Writer, VaultError> {
        self.begin_v2(purpose, creator, files, created_at, Some(Box::new(observe)))
    }

    fn begin_v2(
        &self,
        purpose: BackupPurpose,
        creator: BackupCreator,
        files: Vec<PlannedFile>,
        created_at: u64,
        observe: Option<Observer>,
    ) -> Result<FileBackupV2Writer, VaultError> {
        self.header()?;
        check_plan(&files)?;
        if creator
            .agent
            .as_ref()
            .is_some_and(|a| a.len() > MAX_LABEL_V2)
        {
            return Err(VaultErrorKind::InvalidRecord.into());
        }
        let backups = backups_dir(self.paths())?;
        let id = FileBackupId::generate();
        let ctx = Ctx::of(self, id, created_at);
        let name = dir_name(&id, created_at);
        let staging = backups.join(format!(".{name}{STAGING_SUFFIX}"));
        let final_dir = backups.join(&name);
        std::fs::DirBuilder::new().mode(0o700).create(&staging)?;
        let mut w = FileBackupV2Writer {
            ctx,
            key: SubKey::random(Purpose::Backup),
            backups,
            staging,
            final_dir,
            out: None,
            offset: 0,
            header_hash: [0; 32],
            purpose,
            creator,
            plan: files,
            next_file: 0,
            next_chunk: 0,
            hasher: Sha256::new(),
            digests: Vec::new(),
            done: false,
            observe,
        };
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(w.staging.join(DATA))?;
        w.out = Some(BufWriter::with_capacity(64 * 1024, file));
        w.start(self)?;
        Ok(w)
    }
}

impl FileBackupV2Writer {
    /// The backup's id.
    pub fn id(&self) -> FileBackupId {
        self.ctx.id
    }

    /// The files it will hold, as declared.
    pub fn plan(&self) -> &[PlannedFile] {
        &self.plan
    }

    /// The chunk [`FileBackupV2Writer::put`] takes next: `(file, chunk)`,
    /// or `None` once every chunk is in.
    pub fn next(&self) -> Option<(usize, u64)> {
        (self.next_file < self.plan.len()).then_some((self.next_file, self.next_chunk))
    }

    fn step(&mut self, s: StepV2) {
        if let Some(f) = self.observe.as_mut() {
            f(s);
        }
    }

    fn out(&mut self) -> Result<&mut BufWriter<File>, VaultError> {
        self.out
            .as_mut()
            .ok_or_else(|| VaultError::from(VaultErrorKind::InvalidRecord))
    }

    fn start(&mut self, v: &Vault) -> Result<(), VaultError> {
        self.step(StepV2::Staged);
        let head = self.ctx.header();
        self.header_hash = Sha256::digest(head).into();
        let wrapped = seal_subkey(
            v.keys().key(Purpose::Backup),
            &self.ctx.aad(Rec::Key),
            &self.key,
        )?
        .to_bytes();
        let out = self.out()?;
        out.write_all(&head)?;
        let n = write_record(out, &wrapped)?;
        self.offset = HEADER_LEN_V2 as u64 + n;
        self.step(StepV2::Started);
        Ok(())
    }

    /// Adds chunk `chunk` of file `file`, which must be the next one
    /// ([`FileBackupV2Writer::next`]) and hold exactly the bytes its place
    /// does ([`chunk_len`]). Returns whether it was its file's last.
    ///
    /// # Errors
    /// [`VaultErrorKind::InvalidRecord`] for another chunk than the next,
    /// or another length (nothing is written then); an I/O error when the
    /// record cannot be written, after which the backup cannot be
    /// committed.
    pub fn put(&mut self, file: usize, chunk: u64, data: &SecretBytes) -> Result<bool, VaultError> {
        if self.next() != Some((file, chunk)) {
            return Err(VaultErrorKind::InvalidRecord.into());
        }
        let size = self.plan[file].size;
        if chunk_len(size, chunk) != Some(data.len()) {
            return Err(VaultErrorKind::InvalidRecord.into());
        }
        let last = chunk + 1 == chunks_of(size);
        let rec = Rec::Chunk {
            file: u32::try_from(file).map_err(|_| damaged())?,
            chunk: u32::try_from(chunk).map_err(|_| damaged())?,
            last,
        };
        let sealed = seal_value(&self.key, &self.ctx.aad(rec), data)?;
        // Nothing is counted until the record is written: a failed write
        // leaves `next` where it was, and `data` may hold a partial record,
        // so the backup is never committed.
        let written = write_record(self.out()?, &sealed);
        let n = match written {
            Ok(n) => n,
            Err(e) => {
                self.out = None;
                return Err(e);
            }
        };
        self.offset += n;
        sha256_update(&mut self.hasher, data);
        if last {
            let digest: [u8; 32] = self.hasher.finalize_reset().into();
            self.digests.push(digest);
            self.next_file += 1;
            self.next_chunk = 0;
        } else {
            self.next_chunk += 1;
        }
        self.step(StepV2::Chunk);
        Ok(last)
    }

    /// Seals the metadata after the chunks and puts the backup in place:
    /// from then on it is listed, and its contents never change.
    ///
    /// # Errors
    /// [`VaultErrorKind::InvalidRecord`] while a chunk is missing (the
    /// writer is kept; nothing is written); an I/O error when the backup
    /// could not be put in place, in which case nothing is listed.
    pub fn commit(&mut self) -> Result<CommittedV2, VaultError> {
        if self.next().is_some() || self.digests.len() != self.plan.len() || self.done {
            return Err(VaultErrorKind::InvalidRecord.into());
        }
        let files: Vec<FileMetaV2> = self
            .plan
            .iter()
            .zip(&self.digests)
            .map(|(p, d)| FileMetaV2 {
                path: p.path.clone(),
                mode: p.mode,
                size: p.size,
                sha256: *d,
            })
            .collect();
        let meta = encode_metadata(&self.ctx.header(), self.purpose, &self.creator, &files);
        let sealed = seal_record(&self.key, &self.ctx.aad(Rec::Metadata), &meta)?;
        let at = self.offset;
        let mut out = self
            .out
            .take()
            .ok_or_else(|| VaultError::from(VaultErrorKind::InvalidRecord))?;
        let n = write_record(&mut out, &sealed)?;
        out.write_all(&at.to_be_bytes())?;
        self.step(StepV2::MetadataWritten);
        let file = out
            .into_inner()
            .map_err(|e| VaultError::from(e.into_error()))?;
        file.sync_all()?;
        drop(file);
        sync_dir(&self.staging)?;
        self.step(StepV2::Synced);
        std::fs::rename(&self.staging, &self.final_dir)?;
        self.done = true;
        self.step(StepV2::Installed);
        sync_dir(&self.backups)?;
        self.step(StepV2::Done);
        Ok(CommittedV2 {
            id: self.ctx.id,
            dir: self.final_dir.clone(),
            created_at: self.ctx.created_at,
            files: self.plan.len(),
            bytes: at + n + TRAILER_LEN as u64,
        })
    }
}

impl Drop for FileBackupV2Writer {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        // Not committed: the staging directory goes, with its `data`. It
        // holds sealed records only, and a purge removes what is left.
        drop(self.out.take());
        let _ = std::fs::remove_file(self.staging.join(DATA));
        let _ = std::fs::remove_dir(&self.staging);
    }
}

/// Where a file's chunks are: the offset of its first record and how many
/// it has.
#[derive(Debug, Clone, Copy)]
struct FileLayout {
    first: u64,
    chunks: u64,
}

/// A committed backup, opened for reading (see the module documentation).
/// It holds the backup's own key, never the vault's. Its `Debug` shows the
/// id only.
pub struct FileBackupV2Reader {
    ctx: Ctx,
    key: SubKey,
    file: File,
    dir: PathBuf,
    meta: BackupMetaV2,
    layout: Vec<FileLayout>,
}

impl core::fmt::Debug for FileBackupV2Reader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FileBackupV2Reader")
            .field("id", &self.ctx.id)
            .finish_non_exhaustive()
    }
}

/// The size of a chunk's record: its length, then its sealed bytes.
fn chunk_record_len(size: u64, chunk: u64) -> u64 {
    4 + chunk_len(size, chunk).map_or(0, |n| n as u64) + Sealed::OVERHEAD as u64
}

impl Vault {
    /// Opens backup `id` for reading. See the module documentation.
    ///
    /// # Errors
    /// [`VaultErrorKind::NotFound`] when no backup has that id (or it was
    /// purged), [`VaultErrorKind::BackupDamaged`] when its header, key,
    /// metadata or layout is not the one a whole backup of this vault has.
    pub fn open_file_backup_v2(&self, id: &FileBackupId) -> Result<FileBackupV2Reader, VaultError> {
        self.header()?;
        let dir = find_backup_v2(self.paths(), id)?.ok_or(VaultErrorKind::NotFound)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(dir.join(DATA))
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    damaged()
                } else {
                    VaultError::from(e)
                }
            })?;
        let len = {
            let m = file.metadata()?;
            if !m.is_file() {
                return Err(damaged());
            }
            m.len()
        };
        let mut head = [0u8; HEADER_LEN_V2];
        read_at(&file, &mut head, 0)?;
        let h = parse_header(&head)?;
        if h.id != *id
            || h.vault_id != self.vault_id().0
            || h.epoch != self.epoch()
            || h.schema_version != self.schema_version()
        {
            return Err(damaged());
        }
        let ctx = Ctx::of(self, h.id, h.created_at);
        let (wrapped, chunks_at) = read_record_at(
            &file,
            HEADER_LEN_V2 as u64,
            256,
            Some(32 + Sealed::OVERHEAD),
        )?;
        let wrapped = Sealed::from_bytes(&wrapped).map_err(|_| damaged())?;
        let key = open_subkey(
            self.keys().key(Purpose::Backup),
            &ctx.aad(Rec::Key),
            &wrapped,
            Purpose::Backup,
        )
        .map_err(|_| damaged())?;
        if len < chunks_at + TRAILER_LEN as u64 {
            return Err(damaged());
        }
        let mut trailer = [0u8; TRAILER_LEN];
        read_at(&file, &mut trailer, len - TRAILER_LEN as u64)?;
        let meta_at = u64::from_be_bytes(trailer);
        if meta_at < chunks_at || meta_at > len - TRAILER_LEN as u64 {
            return Err(damaged());
        }
        let (sealed, end) = read_record_at(&file, meta_at, MAX_METADATA + Sealed::OVERHEAD, None)?;
        if end != len - TRAILER_LEN as u64 {
            return Err(damaged());
        }
        let decoded = open_record(&key, &ctx.aad(Rec::Metadata), &sealed, decode_metadata)
            .map_err(|_| damaged())?;
        if !bool::from(decoded.header_hash.ct_eq(&Sha256::digest(head))) {
            return Err(damaged());
        }
        // Every chunk record has the length its place says: the chunks fill
        // the space between the key and the metadata exactly, or a chunk is
        // missing, cut or one too many.
        let mut layout = Vec::with_capacity(decoded.files.len());
        let mut at = chunks_at;
        for f in &decoded.files {
            let chunks = chunks_of(f.size);
            layout.push(FileLayout { first: at, chunks });
            for c in 0..chunks {
                at += chunk_record_len(f.size, c);
            }
        }
        if at != meta_at {
            return Err(damaged());
        }
        Ok(FileBackupV2Reader {
            ctx,
            key,
            file,
            dir,
            meta: BackupMetaV2 {
                id: h.id,
                created_at: h.created_at,
                purpose: decoded.purpose,
                creator: decoded.creator,
                files: decoded.files,
            },
            layout,
        })
    }

    /// Records what the change left in file `file` of backup `id`: its
    /// SHA-256, sealed under the backup's key in a file of its own,
    /// written once (`O_EXCL`) and flushed with its directory.
    ///
    /// # Errors
    /// As [`Vault::open_file_backup_v2`]; [`VaultErrorKind::InvalidRecord`]
    /// for a file index the backup does not have;
    /// [`VaultErrorKind::AlreadyExists`] when the file's result is
    /// recorded already.
    pub fn record_file_backup_v2_result(
        &self,
        id: &FileBackupId,
        file: usize,
        sha256_after: &[u8; 32],
    ) -> Result<(), VaultError> {
        let r = self.open_file_backup_v2(id)?;
        r.record_result(file, sha256_after)
    }
}

impl FileBackupV2Reader {
    /// The backup's metadata.
    pub fn meta(&self) -> &BackupMetaV2 {
        &self.meta
    }

    /// Chunk `chunk` of file `file`, and whether it is the file's last.
    ///
    /// # Errors
    /// [`VaultErrorKind::InvalidRecord`] for a file or chunk the backup
    /// does not have; [`VaultErrorKind::BackupDamaged`] when the record at
    /// its place does not open as that chunk.
    pub fn chunk(&self, file: usize, chunk: u64) -> Result<(SecretBytes, bool), VaultError> {
        let (Some(l), Some(f)) = (self.layout.get(file), self.meta.files.get(file)) else {
            return Err(VaultErrorKind::InvalidRecord.into());
        };
        let Some(want) = chunk_len(f.size, chunk) else {
            return Err(VaultErrorKind::InvalidRecord.into());
        };
        // Every chunk before the last is full.
        let at = l.first + chunk * (4 + MAX_CHUNK_RECORD as u64);
        let (sealed, _) = read_record_at(
            &self.file,
            at,
            MAX_CHUNK_RECORD,
            Some(want + Sealed::OVERHEAD),
        )?;
        let last = chunk + 1 == l.chunks;
        let rec = Rec::Chunk {
            file: u32::try_from(file).map_err(|_| damaged())?,
            chunk: u32::try_from(chunk).map_err(|_| damaged())?,
            last,
        };
        let data = open_value(&self.key, &self.ctx.aad(rec), &sealed).map_err(|_| damaged())?;
        if data.len() != want {
            return Err(damaged());
        }
        Ok((data, last))
    }

    /// Opens every chunk and compares each file's SHA-256 with the one the
    /// metadata holds.
    ///
    /// # Errors
    /// [`VaultErrorKind::BackupDamaged`] at the first chunk that does not
    /// open, or file whose contents are not the ones backed up.
    pub fn verify(&self) -> Result<(), VaultError> {
        for (i, (l, f)) in self.layout.iter().zip(&self.meta.files).enumerate() {
            let mut h = Sha256::new();
            for c in 0..l.chunks {
                let (data, _) = self.chunk(i, c)?;
                sha256_update(&mut h, &data);
            }
            let got: [u8; 32] = h.finalize().into();
            if !bool::from(got.ct_eq(&f.sha256)) {
                return Err(damaged());
            }
        }
        Ok(())
    }

    /// What the change left in each file, as recorded: one entry per file,
    /// `None` where no result is recorded.
    ///
    /// # Errors
    /// [`VaultErrorKind::BackupDamaged`] when a result's file does not
    /// open as that file's result.
    pub fn results(&self) -> Result<Vec<Option<[u8; 32]>>, VaultError> {
        let mut out = vec![None; self.meta.files.len()];
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(index) = name
                .to_str()
                .and_then(|n| n.strip_prefix(RESULT))
                .filter(|n| !n.is_empty() && n.len() <= 4 && n.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|n| n.parse::<usize>().ok())
            else {
                continue;
            };
            if index >= out.len() || !entry.file_type()?.is_file() {
                return Err(damaged());
            }
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(entry.path())?;
            let mut sealed = Vec::new();
            file.take(256).read_to_end(&mut sealed)?;
            let rec = Rec::Result(u32::try_from(index).map_err(|_| damaged())?);
            let digest = open_record(&self.key, &self.ctx.aad(rec), &sealed, |b| {
                let mut d = Dec::new(b);
                if d.u8()? != RESULT_VERSION || usize::try_from(d.u32()?).ok() != Some(index) {
                    return Err(damaged());
                }
                let h: [u8; 32] = d.array()?;
                d.end()?;
                Ok(h)
            })
            .map_err(|_| damaged())?;
            out[index] = Some(digest);
        }
        Ok(out)
    }

    /// See [`Vault::record_file_backup_v2_result`].
    ///
    /// # Errors
    /// As [`Vault::record_file_backup_v2_result`].
    pub fn record_result(&self, file: usize, sha256_after: &[u8; 32]) -> Result<(), VaultError> {
        if file >= self.meta.files.len() {
            return Err(VaultErrorKind::InvalidRecord.into());
        }
        let index = u32::try_from(file).map_err(|_| damaged())?;
        let mut e = Enc::new();
        e.u8(RESULT_VERSION)
            .raw(&index.to_be_bytes())
            .raw(sha256_after);
        let sealed = seal_record(&self.key, &self.ctx.aad(Rec::Result(index)), &e.finish())?;
        let path = self.dir.join(format!("{RESULT}{file}"));
        let mut out = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(VaultErrorKind::AlreadyExists.into());
            }
            Err(e) => return Err(e.into()),
        };
        let written = out.write_all(&sealed).and_then(|()| out.sync_all());
        if let Err(e) = written {
            // A result that is not whole is no result: it goes, so the
            // file reads as unrecorded, never as damaged.
            drop(out);
            let _ = std::fs::remove_file(&path);
            return Err(e.into());
        }
        sync_dir(&self.dir)
    }
}

/// The directory of backup `id` in `p`'s backups directory, by its name.
fn find_backup_v2(p: &VaultPaths, id: &FileBackupId) -> Result<Option<PathBuf>, VaultError> {
    let suffix = format!("-{id}");
    Ok(list_file_backups_v2(p)?
        .into_iter()
        .find(|e| {
            e.dir
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(&suffix))
        })
        .map(|e| e.dir))
}

/// A backup's directory, as a listing finds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedV2 {
    /// Its id, from its name.
    pub id: FileBackupId,
    pub dir: PathBuf,
    /// Unix seconds: the time its header records, or its directory's
    /// modification time when the header does not read.
    pub created_at: u64,
}

fn modified_secs(m: &std::fs::Metadata) -> u64 {
    m.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs())
}

/// Every committed backup in `p`'s backups directory: directories (never
/// a symlink) named `files2-<time>-<id>`. Staging directories are never
/// listed. Sorted by name, so oldest first.
///
/// # Errors
/// When the directory cannot be read.
pub fn list_file_backups_v2(p: &VaultPaths) -> Result<Vec<ListedV2>, VaultError> {
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
        let Some(id) = name
            .to_str()
            .filter(|n| n.starts_with(PREFIX))
            .and_then(|n| n.rsplit('-').next())
            .and_then(FileBackupId::parse)
        else {
            continue;
        };
        // `DirEntry` reads the entry itself: a symlink is not followed.
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let path = entry.path();
        let mut head = [0u8; HEADER_LEN_V2];
        let created_at = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path.join(DATA))
            .ok()
            .filter(|f| read_at(f, &mut head, 0).is_ok())
            .and_then(|_| parse_header(&head).ok())
            .map_or_else(
                || entry.metadata().map_or(0, |m| modified_secs(&m)),
                |h| h.created_at,
            );
        out.push(ListedV2 {
            id,
            dir: path,
            created_at,
        });
    }
    out.sort_by(|a, b| a.dir.cmp(&b.dir));
    Ok(out)
}

/// Removes a backup's directory: its `data` and result files, then the
/// directory. Anything else in it stays, and so does the directory.
fn remove_backup_dir(dir: &Path) -> Result<bool, VaultError> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let ours = entry.file_name().to_str().is_some_and(|n| {
            n == DATA
                || n.strip_prefix(RESULT)
                    .is_some_and(|i| !i.is_empty() && i.bytes().all(|b| b.is_ascii_digit()))
        });
        if ours && entry.file_type()?.is_file() {
            match std::fs::remove_file(entry.path()) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
    }
    match std::fs::remove_dir(dir) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Removes the backups in `p` made more than [`FILE_BACKUP_RETENTION`]
/// before `now` (Unix seconds), and the staging directories interrupted
/// backups left, unchanged for [`STAGING_GRACE`]. Returns how many
/// directories it removed. Needs no key: the time is in the header.
///
/// # Errors
/// When the directory cannot be read, or a backup cannot be removed.
pub fn purge_file_backups_v2(p: &VaultPaths, now: u64) -> Result<usize, VaultError> {
    let mut removed = 0;
    for b in list_file_backups_v2(p)? {
        if now.saturating_sub(b.created_at) > FILE_BACKUP_RETENTION.as_secs()
            && remove_backup_dir(&b.dir)?
        {
            removed += 1;
        }
    }
    let dir = match std::fs::canonicalize(&p.backups_dir) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(removed),
        Err(e) => return Err(e.into()),
    };
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let staging = entry
            .file_name()
            .to_str()
            .is_some_and(|n| n.starts_with(&format!(".{PREFIX}")) && n.ends_with(STAGING_SUFFIX));
        if !staging || !entry.file_type()?.is_dir() {
            continue;
        }
        let modified = entry.metadata().map_or(0, |m| modified_secs(&m));
        if now.saturating_sub(modified) > STAGING_GRACE.as_secs()
            && remove_backup_dir(&entry.path())?
        {
            removed += 1;
        }
    }
    if removed > 0 {
        sync_dir(&dir)?;
    }
    Ok(removed)
}

/// Rewrites the creation time in a backup's header. Test support only
/// (feature `testing`): the header is authenticated through the metadata,
/// so the backup then no longer opens, but purging reads only the header.
#[cfg(feature = "testing")]
pub fn age_file_backup_v2_for_testing(dir: &Path, created_at: u64) -> Result<(), VaultError> {
    use std::io::{Seek, SeekFrom};
    let mut f = std::fs::File::options()
        .read(true)
        .write(true)
        .open(dir.join(DATA))?;
    f.seek(SeekFrom::Start(43))?;
    f.write_all(&created_at.to_be_bytes())?;
    Ok(f.sync_all()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_counts_and_lengths_cover_every_size() {
        let c = CHUNK_V2 as u64;
        assert_eq!(chunks_of(0), 1);
        assert_eq!(chunk_len(0, 0), Some(0));
        assert_eq!(chunk_len(0, 1), None);
        assert_eq!(chunks_of(1), 1);
        assert_eq!(chunks_of(c), 1);
        assert_eq!(chunk_len(c, 0), Some(CHUNK_V2));
        assert_eq!(chunks_of(c + 1), 2);
        assert_eq!(chunk_len(c + 1, 1), Some(1));
        assert_eq!(chunks_of(MAX_FILE_V2), 512);
        assert_eq!(chunk_len(MAX_FILE_V2, 511), Some(CHUNK_V2));
        // A chunk record, sealed and framed, is well under 1 MiB.
        const { assert!(MAX_CHUNK_RECORD + 4 < 1 << 20) };
    }

    #[test]
    fn the_header_layout_is_fixed() {
        assert_eq!(HEADER_LEN_V2, 4 + 1 + 16 + 2 + 4 + 16 + 8);
        let ctx = Ctx {
            vault_id: VaultId([7; 16]),
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

    /// Every record of a backup has associated data of its own: no two
    /// places share one, so a record moved to another place does not open.
    #[test]
    fn every_place_has_its_own_associated_data() {
        let ctx = Ctx {
            vault_id: VaultId([1; 16]),
            schema_version: 1,
            epoch: 1,
            id: FileBackupId([2; 16]),
            created_at: 0,
        };
        let mut seen = std::collections::HashSet::new();
        assert!(seen.insert(ctx.aad(Rec::Key).encode()));
        assert!(seen.insert(ctx.aad(Rec::Metadata).encode()));
        for file in [0u32, 1, 4095] {
            assert!(seen.insert(ctx.aad(Rec::Result(file)).encode()));
            for chunk in [0u32, 1, 511] {
                for last in [false, true] {
                    assert!(seen.insert(ctx.aad(Rec::Chunk { file, chunk, last }).encode()));
                }
            }
        }
    }

    #[test]
    fn metadata_decodes_only_whole() {
        let creator = BackupCreator {
            kind: CreatorKind::Agent,
            evidence_digest: [3; 32],
            agent: Some("Claude Code".into()),
            owner: BackupOwner {
                pid: 42,
                start_time: 7,
                token: Some(9),
            },
        };
        let files = [FileMetaV2 {
            path: "/h/.claude/settings.json".into(),
            mode: 0o600,
            size: 5,
            sha256: [4; 32],
        }];
        let m = encode_metadata(b"header", BackupPurpose::Scrub, &creator, &files);
        let d = decode_metadata(&m).unwrap();
        assert_eq!(d.header_hash, <[u8; 32]>::from(Sha256::digest(b"header")));
        assert_eq!(d.purpose, BackupPurpose::Scrub);
        assert_eq!(d.creator, creator);
        assert_eq!(d.files, files);
        for cut in 0..m.len() {
            assert!(decode_metadata(&m[..cut]).is_err(), "{cut}");
        }
        let mut longer = m.clone();
        longer.push(0);
        assert!(decode_metadata(&longer).is_err());
    }

    #[test]
    fn plans_over_a_cap_are_too_large_and_never_cut() {
        let f = |size| PlannedFile {
            path: "/p/.env".into(),
            mode: 0o600,
            size,
        };
        assert!(check_plan(&[f(0)]).is_ok());
        assert!(check_plan(&[f(MAX_FILE_V2)]).is_ok());
        let kind = |files: &[PlannedFile]| check_plan(files).unwrap_err().kind();
        assert_eq!(kind(&[f(MAX_FILE_V2 + 1)]), VaultErrorKind::TooLarge);
        assert_eq!(kind(&[f(300 << 20)]), VaultErrorKind::TooLarge);
        assert_eq!(kind(&vec![f(MAX_FILE_V2); 5]), VaultErrorKind::TooLarge);
        assert!(check_plan(&vec![f(MAX_FILE_V2); 4]).is_ok());
        assert_eq!(
            kind(&vec![f(0); MAX_FILES_V2 + 1]),
            VaultErrorKind::TooLarge
        );
        assert!(check_plan(&vec![f(0); MAX_FILES_V2]).is_ok());
        assert_eq!(kind(&[]), VaultErrorKind::InvalidRecord);
        let named = |p: String| PlannedFile { path: p, ..f(1) };
        assert_eq!(
            kind(&[named("/p/\0".into())]),
            VaultErrorKind::InvalidRecord
        );
        assert_eq!(
            kind(&[named(format!("/{}", "a".repeat(MAX_PATH_V2)))]),
            VaultErrorKind::InvalidRecord
        );
    }
}
