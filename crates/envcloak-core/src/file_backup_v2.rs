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
//!    `.files2-<UTC time>-<id>.tmp/` in `backups/` (through the directory
//!    it opened, never by its path again), and starts its `data` file
//!    (`O_EXCL`, 0600) with a plaintext header and record 0: a fresh
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
//!    subject kind, evidence digest, agent label, process instance and boot,
//!    and the processes of its chain with their sessions and terminals, as
//!    the daemon read them; never anything the client said), and per file
//!    its display path, mode, size and SHA-256. It flushes the file and the
//!    staging directory, renames the directory to `files2-<UTC time>-<id>/`
//!    and flushes `backups/`, each with [`envcloak_sys::sync_file`]
//!    (`F_FULLFSYNC` on macOS, and a flush that fails fails the step), and
//!    answers only once the backup's name opens as the directory it sealed.
//!    Only then is the backup listed: an interrupted backup is a staging
//!    directory, never listed, which a purge removes once it is
//!    [`STAGING_GRACE`] old.
//!
//! After the change, [`Vault::record_file_backup_v2_result`] records what
//! the change left in each file (its SHA-256), once per file, each in a
//! file of its own (`result-<index>`), sealed under the backup's key: the
//! "restore only while the file is what the change left" check compares
//! against it. A result is written and flushed under a temporary name,
//! then linked to its own, which fails when that exists: a reader, or a
//! restart after a crash, finds it absent or whole, never in part.
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
//! staging directories interrupted backups left;
//! [`purge_file_backups_v2_except`] keeps those of backups still being
//! written, however old.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::os::unix::fs::FileExt;
use std::path::PathBuf;

use envcloak_sys::{
    DirEntryKind, MAX_DIR_ENTRIES, create_beneath, create_dir_beneath, kind_beneath, link_beneath,
    list_dir, open_beneath, open_dir_beneath, remove_dir_beneath, rename_beneath, sync_file,
    unlink_beneath,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::crypto::{
    Aad, FieldTag, ItemClass, Purpose, Sealed, SubKey, TableTag, VaultId, open_subkey, seal_subkey,
};
use crate::file_backup::{FILE_BACKUP_RETENTION, FileBackupId, STAGING_GRACE};
use crate::secret::SecretBytes;
use crate::vault::codec::{Dec, Enc};
use crate::vault::{
    Vault, VaultError, VaultErrorKind, VaultPaths, open_private_child, open_record, open_value,
    seal_record, seal_value, sha256_update, utc_stamp,
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
/// The most processes of its creator's chain a backup records: the
/// daemon reads at most this many (`envcloak_sys::MAX_ANCESTRY`).
pub const MAX_CHAIN_V2: usize = 64;

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
/// The suffix of a backup's directory being purged:
/// `.files2-<time>-<id>.purge`, never listed.
const PURGE_SUFFIX: &str = ".purge";
/// The file in a backup's directory that holds its records.
const DATA: &str = "data";
/// Each result's file name: `result-<file index>`.
const RESULT: &str = "result-";
/// A result's temporary name before it is published:
/// `.result-<file index>-<random id>.tmp`.
const RESULT_TEMP: &str = ".result-";
/// The row version of a result: this bit, with the file's index.
const RESULT_BIT: u64 = 1 << 63;
/// The largest chunk record: a full chunk, sealed.
const MAX_CHUNK_RECORD: usize = CHUNK_V2 + Sealed::OVERHEAD;
/// The metadata's bytes besides its files, each field at its longest, as
/// [`encode_metadata`] writes them: version(1) header_sha256(32)
/// chunk_size(4) purpose(1) creator_kind(1) evidence_digest(32) agent(1 +
/// 4 + [`MAX_LABEL_V2`]) owner_pid(4) owner_start_time(8) owner_token(1 +
/// 4) owner_boot(1 + 16) chain_count(4), [`MAX_CHAIN_V2`] processes of
/// [`META_PROCESS`] bytes, count(4).
const META_FIXED: usize = 1
    + 32
    + 4
    + 1
    + 1
    + 32
    + (1 + 4 + MAX_LABEL_V2)
    + 4
    + 8
    + (1 + 4)
    + (1 + 16)
    + 4
    + MAX_CHAIN_V2 * META_PROCESS
    + 4;
/// One process of the creator's chain at its longest: pid(4)
/// start_time(8) token(1 + 4) sid(1 + 4) terminal(1 + 8).
const META_PROCESS: usize = 4 + 8 + (1 + 4) + (1 + 4) + (1 + 8);
/// One file's entry at its longest: path(4 + [`MAX_PATH_V2`]) mode(4)
/// size(8) sha256(32).
const META_FILE: usize = 4 + MAX_PATH_V2 + 4 + 8 + 32;
/// The largest metadata record: every file at the longest path. A backup
/// [`check_plan`] takes always fits it, so it always opens again.
const MAX_METADATA: usize = META_FIXED + MAX_FILES_V2 * META_FILE;

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
/// and on macOS the audit token's pid version, in the boot it ran in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BackupOwner {
    pub pid: i32,
    /// The kernel's start time (`envcloak_sys::StartTime::raw`).
    pub start_time: u64,
    /// macOS: the pid version from the audit token. `None` on Linux.
    pub token: Option<i32>,
    /// The boot it ran in (`envcloak_sys::boot_id`): on Linux a start time
    /// counts from boot, so a process of a later boot can have this pid
    /// and start time again, and is not this one. `None` on macOS, whose
    /// start times are wall-clock time. The processes of
    /// [`BackupCreator::chain`] ran in this boot too.
    pub boot: Option<[u8; 16]>,
}

/// One process of the chain the daemon read for a backup's creator: what
/// the restore's session and terminal check (T9-3, F-70) needs, sealed so
/// that it holds after a restart of the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CreatorProcess {
    pub pid: i32,
    /// The kernel's start time (`envcloak_sys::StartTime::raw`).
    pub start_time: u64,
    /// macOS: the pid version from the audit token, when known.
    pub token: Option<i32>,
    /// Its session id.
    pub sid: Option<i32>,
    /// Its controlling terminal's device.
    pub terminal: Option<u64>,
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
    /// The creator's chain, the caller first, up to its root or up to its
    /// nearest agent, whichever is further: at most [`MAX_CHAIN_V2`].
    pub chain: Vec<CreatorProcess>,
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
    /// Its directory: `backups/`'s path in the vault's paths, joined with
    /// its name. For display and tests: nothing in this module opens it by
    /// this path.
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
    /// `backups/` is opened; nothing is made in it yet.
    Opened,
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
    opt_raw(&mut e, creator.owner.token.map(i32::to_be_bytes).as_ref());
    opt_raw(&mut e, creator.owner.boot.as_ref());
    e.raw(
        &u32::try_from(creator.chain.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for p in &creator.chain {
        e.raw(&p.pid.to_be_bytes()).u64(p.start_time);
        opt_raw(&mut e, p.token.map(i32::to_be_bytes).as_ref());
        opt_raw(&mut e, p.sid.map(i32::to_be_bytes).as_ref());
        opt_raw(&mut e, p.terminal.map(u64::to_be_bytes).as_ref());
    }
    e.raw(&u32::try_from(files.len()).unwrap_or(u32::MAX).to_be_bytes());
    for f in files {
        e.str(&f.path)
            .raw(&f.mode.to_be_bytes())
            .u64(f.size)
            .raw(&f.sha256);
    }
    e.finish()
}

/// An optional fixed-size value: a `0` byte, or a `1` byte and the value.
fn opt_raw<const N: usize>(e: &mut Enc, v: Option<&[u8; N]>) {
    match v {
        None => e.u8(0),
        Some(b) => e.u8(1).raw(b),
    };
}

fn opt_array<const N: usize>(d: &mut Dec<'_>) -> Result<Option<[u8; N]>, VaultError> {
    Ok(if d.bool()? { Some(d.array()?) } else { None })
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
    let token = opt_array(&mut d)?.map(i32::from_be_bytes);
    let boot = opt_array(&mut d)?;
    let processes = usize::try_from(d.u32()?).map_err(|_| damaged())?;
    if processes > MAX_CHAIN_V2 {
        return Err(damaged());
    }
    let mut chain = Vec::with_capacity(processes);
    for _ in 0..processes {
        chain.push(CreatorProcess {
            pid: i32::from_be_bytes(d.array()?),
            start_time: d.u64()?,
            token: opt_array(&mut d)?.map(i32::from_be_bytes),
            sid: opt_array(&mut d)?.map(i32::from_be_bytes),
            terminal: opt_array(&mut d)?.map(u64::from_be_bytes),
        });
    }
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
                boot,
            },
            chain,
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

/// `backups/`, opened through the data directory that names it, never
/// through a symlink in place of either, and checked through the
/// descriptor opened (a directory of this user's, writable by no one else:
/// `vault::open_private_child`). Every backup v2 is made, found, read and
/// removed through this handle, never by `backups/`'s path again, so
/// nothing outside the vault's own `backups/` is ever written, read or
/// removed, whatever takes its name: its path is never resolved first
/// (no `canonicalize`), which would follow a symlink put in its place.
/// `None` when there is none.
fn open_backups(p: &VaultPaths) -> Result<Option<File>, VaultError> {
    Ok(open_private_child(&p.backups_dir)?)
}

/// Builds a backup (see the module documentation). Dropped before
/// [`FileBackupV2Writer::commit`], it removes its staging directory. Its
/// `Debug` shows the id and where it is, never a key or a byte of a file.
pub struct FileBackupV2Writer {
    ctx: Ctx,
    key: SubKey,
    /// `backups/`, opened: the staging directory is renamed and removed
    /// through it.
    backups: File,
    /// The staging directory, opened when it was made: `data` is made and
    /// removed through it, never by a path someone could swap meanwhile.
    staging: File,
    /// Its name in `backups/`, and the backup's name there once committed.
    staging_name: String,
    final_name: String,
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
    /// The size of `data` once [`FileBackupV2Writer::seal`] wrote it all.
    sealed_len: Option<u64>,
    /// Whether the staging directory's name was renamed to the backup's:
    /// from then on, whatever the checks after it found, the writer
    /// neither installs again nor removes anything when dropped.
    installed: bool,
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
        self.begin_v2(
            purpose,
            creator,
            files,
            created_at,
            self.schema_version(),
            None,
        )
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
        self.begin_v2(
            purpose,
            creator,
            files,
            created_at,
            self.schema_version(),
            Some(Box::new(observe)),
        )
    }

    /// `schema_version` is the vault's own but in the tests of a backup a
    /// vault of an older schema made.
    fn begin_v2(
        &self,
        purpose: BackupPurpose,
        creator: BackupCreator,
        files: Vec<PlannedFile>,
        created_at: u64,
        schema_version: u16,
        observe: Option<Observer>,
    ) -> Result<FileBackupV2Writer, VaultError> {
        self.header()?;
        check_plan(&files)?;
        if creator
            .agent
            .as_ref()
            .is_some_and(|a| a.len() > MAX_LABEL_V2)
            || creator.chain.len() > MAX_CHAIN_V2
        {
            return Err(VaultErrorKind::InvalidRecord.into());
        }
        self.paths().ensure_dirs()?;
        let backups = open_backups(self.paths())?.ok_or(VaultErrorKind::NotFound)?;
        let mut observe = observe;
        if let Some(f) = observe.as_mut() {
            f(StepV2::Opened);
        }
        let id = FileBackupId::generate();
        let ctx = Ctx {
            schema_version,
            ..Ctx::of(self, id, created_at)
        };
        let final_name = dir_name(&id, created_at);
        let staging_name = format!(".{final_name}{STAGING_SUFFIX}");
        // Made through `backups/` as opened, never by its path again: a
        // directory put in its place meanwhile gets nothing.
        create_dir_beneath(&backups, OsStr::new(&staging_name), 0o700)?;
        let staging = match open_dir_beneath(&backups, OsStr::new(&staging_name)) {
            Ok(d) => d,
            Err(e) => {
                let _ = remove_dir_beneath(&backups, OsStr::new(&staging_name));
                return Err(e.into());
            }
        };
        let mut w = FileBackupV2Writer {
            ctx,
            key: SubKey::random(Purpose::Backup),
            backups,
            staging,
            staging_name,
            final_dir: self.paths().backups_dir.join(&final_name),
            final_name,
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
            sealed_len: None,
            installed: false,
            observe,
        };
        let file = create_beneath(&w.staging, OsStr::new(DATA), 0o600)?;
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
    /// [`FileBackupV2Writer::seal`], then [`FileBackupV2Writer::install`].
    ///
    /// # Errors
    /// [`VaultErrorKind::InvalidRecord`] while a chunk is missing (the
    /// writer is kept; nothing is written); an I/O error when the backup
    /// could not be put in place, in which case nothing is listed.
    pub fn commit(&mut self) -> Result<CommittedV2, VaultError> {
        self.seal()?;
        self.install()
    }

    /// The first half of [`FileBackupV2Writer::commit`]: writes the sealed
    /// metadata and the trailer, and flushes `data` and the staging
    /// directory. Nothing is listed yet, and a writer dropped now still
    /// removes its staging directory: whoever puts the backup in place
    /// ([`FileBackupV2Writer::install`]) can check first that it still
    /// may.
    ///
    /// # Errors
    /// [`VaultErrorKind::InvalidRecord`] while a chunk is missing, or once
    /// sealed (nothing is written then); an I/O error, after which the
    /// backup cannot be put in place.
    pub fn seal(&mut self) -> Result<(), VaultError> {
        if self.next().is_some()
            || self.digests.len() != self.plan.len()
            || self.installed
            || self.sealed_len.is_some()
        {
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
        sync_file(&file)?;
        drop(file);
        sync_file(&self.staging)?;
        self.sealed_len = Some(at + n + TRAILER_LEN as u64);
        self.step(StepV2::Synced);
        Ok(())
    }

    /// The second half of [`FileBackupV2Writer::commit`], after
    /// [`FileBackupV2Writer::seal`]: renames the staging directory to the
    /// backup's name and flushes `backups/`. From the rename on the backup
    /// is listed.
    ///
    /// A rename moves whatever has the staging directory's name at that
    /// moment, which need not be the directory this writer made and
    /// sealed (another directory, or a symlink, put in its place). So the
    /// backup's name is opened again through `backups/` (never through a
    /// symlink) once the rename is flushed, and its device and inode
    /// compared with the staging directory held open: a commit answers
    /// that the backup is in place only for the directory sealed, whatever
    /// took either name before that check. It cannot keep the name from
    /// being replaced later.
    ///
    /// # Errors
    /// [`VaultErrorKind::InvalidRecord`] unless sealed and not yet in
    /// place, and when the backup's name does not open as the directory
    /// sealed; an I/O error when the rename fails (nothing is listed),
    /// `backups/` cannot be flushed (the backup is in place, but may not
    /// last a crash), or a directory's metadata cannot be read. From the
    /// rename on a failure is final: the writer installs nothing again,
    /// and dropped, it keeps the sealed directory, wherever it is, and
    /// removes nothing that took its name.
    pub fn install(&mut self) -> Result<CommittedV2, VaultError> {
        let Some(bytes) = self.sealed_len.filter(|_| !self.installed) else {
            return Err(VaultErrorKind::InvalidRecord.into());
        };
        rename_beneath(
            &self.backups,
            OsStr::new(&self.staging_name),
            OsStr::new(&self.final_name),
        )?;
        self.installed = true;
        self.step(StepV2::Installed);
        sync_file(&self.backups)?;
        self.check_installed()?;
        self.step(StepV2::Done);
        Ok(CommittedV2 {
            id: self.ctx.id,
            dir: self.final_dir.clone(),
            created_at: self.ctx.created_at,
            files: self.plan.len(),
            bytes,
        })
    }
}

impl FileBackupV2Writer {
    /// Whether the backup's name in `backups/` opens (never through a
    /// symlink) as the staging directory this writer made and sealed:
    /// the same device and inode as the handle it holds on it.
    fn check_installed(&self) -> Result<(), VaultError> {
        use std::os::unix::fs::MetadataExt;
        let named = open_dir_beneath(&self.backups, OsStr::new(&self.final_name))
            .map_err(|_| VaultError::from(VaultErrorKind::InvalidRecord))?
            .metadata()?;
        let sealed = self.staging.metadata()?;
        if (named.dev(), named.ino()) != (sealed.dev(), sealed.ino()) {
            return Err(VaultErrorKind::InvalidRecord.into());
        }
        Ok(())
    }
}

impl Drop for FileBackupV2Writer {
    fn drop(&mut self) {
        if self.installed {
            return;
        }
        // Not committed: the staging directory goes, with its `data`, both
        // through the handles opened when it was made, its name only while
        // it still names that directory (an empty directory put in its
        // place stays). It holds sealed records only, and a purge removes
        // what is left.
        drop(self.out.take());
        let _ = unlink_beneath(&self.staging, OsStr::new(DATA));
        let name = OsStr::new(&self.staging_name);
        if still_named(&self.backups, name, &self.staging).unwrap_or(false) {
            let _ = remove_dir_beneath(&self.backups, name);
        }
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
    /// The backup's directory, opened with its `data`: its results are
    /// read and written through it.
    dir: File,
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

/// What opening this vault's backups v2 takes of it, held apart from it:
/// a copy of the `backup` subkey (wiped when this is dropped), the ids
/// the records are bound to and the paths. For a caller that opens
/// backups without holding the vault, as the daemon does outside its
/// state lock. Its `Debug` shows no key.
pub struct FileBackupsV2 {
    key: SubKey,
    vault_id: VaultId,
    schema_version: u16,
    epoch: u32,
    paths: VaultPaths,
}

impl core::fmt::Debug for FileBackupsV2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FileBackupsV2")
            .field("paths", &self.paths)
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// This vault's backups v2, to open apart from it.
    ///
    /// # Errors
    /// [`VaultErrorKind::Tampered`] unless the vault verified.
    pub fn file_backups_v2(&self) -> Result<FileBackupsV2, VaultError> {
        self.header()?;
        Ok(FileBackupsV2 {
            key: self.keys().key(Purpose::Backup).duplicate(),
            vault_id: self.vault_id(),
            schema_version: self.schema_version(),
            epoch: self.epoch(),
            paths: self.paths().clone(),
        })
    }

    /// Opens backup `id` for reading. See the module documentation.
    ///
    /// # Errors
    /// [`VaultErrorKind::NotFound`] when no backup has that id (or it was
    /// purged), [`VaultErrorKind::BackupDamaged`] when its header, key,
    /// metadata or layout is not the one a whole backup of this vault has.
    pub fn open_file_backup_v2(&self, id: &FileBackupId) -> Result<FileBackupV2Reader, VaultError> {
        self.file_backups_v2()?.open(id)
    }
}

impl FileBackupsV2 {
    /// The vault's paths.
    pub fn paths(&self) -> &VaultPaths {
        &self.paths
    }

    /// As [`Vault::open_file_backup_v2`].
    ///
    /// # Errors
    /// As [`Vault::open_file_backup_v2`].
    pub fn open(&self, id: &FileBackupId) -> Result<FileBackupV2Reader, VaultError> {
        let backups = open_backups(&self.paths)?.ok_or(VaultErrorKind::NotFound)?;
        let name = find_backup_v2(&backups, id)?.ok_or(VaultErrorKind::NotFound)?;
        self.open_in(&backups, &name, id)
    }

    /// Opens a backup [`list_file_backups_v2`] found, where it found it,
    /// as [`FileBackupsV2::open`] opens one by its id, without looking
    /// for it again: a listing then opens each backup once. Its directory
    /// must be one in this vault's backups directory, named for its id;
    /// the header in it must name that id too.
    ///
    /// # Errors
    /// [`VaultErrorKind::NotFound`] for a directory that is not one of
    /// this vault's backups; as [`FileBackupsV2::open`] otherwise.
    pub fn open_listed(&self, listed: &ListedV2) -> Result<FileBackupV2Reader, VaultError> {
        let name = listed
            .dir
            .file_name()
            .filter(|n| listed_id(n) == Some(listed.id));
        let Some(name) = name.filter(|_| listed.dir.parent() == Some(&*self.paths.backups_dir))
        else {
            return Err(VaultErrorKind::NotFound.into());
        };
        let backups = open_backups(&self.paths)?.ok_or(VaultErrorKind::NotFound)?;
        self.open_in(&backups, name, &listed.id)
    }

    /// Opens the backup whose directory is `name` in `backups`, which must
    /// be backup `id`'s: the directory through the handle on `backups/`,
    /// never through a symlink in its place, then its `data` in it.
    fn open_in(
        &self,
        backups: &File,
        name: &OsStr,
        id: &FileBackupId,
    ) -> Result<FileBackupV2Reader, VaultError> {
        let gone = |e: std::io::Error| {
            if not_a_dir(&e) {
                damaged()
            } else {
                VaultError::from(e)
            }
        };
        let dir = open_dir_beneath(backups, name).map_err(gone)?;
        let file = open_data_in(&dir).map_err(gone)?;
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
        // A backup a vault of an older schema made still opens, bound to
        // the schema it was made under (its header's, which the metadata
        // authenticates): a migration keeps the undo of the changes made
        // before it, for their 7 days. A newer schema's is not this
        // build's to read.
        if h.id != *id
            || h.vault_id != self.vault_id.0
            || h.epoch != self.epoch
            || h.schema_version > self.schema_version
        {
            return Err(damaged());
        }
        let ctx = Ctx {
            vault_id: self.vault_id,
            schema_version: h.schema_version,
            epoch: self.epoch,
            id: h.id,
            created_at: h.created_at,
        };
        let (wrapped, chunks_at) = read_record_at(
            &file,
            HEADER_LEN_V2 as u64,
            256,
            Some(32 + Sealed::OVERHEAD),
        )?;
        let wrapped = Sealed::from_bytes(&wrapped).map_err(|_| damaged())?;
        let key = open_subkey(&self.key, &ctx.aad(Rec::Key), &wrapped, Purpose::Backup)
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
}

impl Vault {
    /// Records what the change left in file `file` of backup `id`: its
    /// SHA-256, sealed under the backup's key in a file of its own,
    /// written and flushed under a temporary name, then published under
    /// its own once (a link that never replaces one), and flushed with its
    /// directory.
    ///
    /// # Errors
    /// As [`Vault::open_file_backup_v2`]; [`VaultErrorKind::InvalidRecord`]
    /// for a file index the backup does not have, and when the result's
    /// name, once linked, does not hold the file written (another file put
    /// under its temporary name meanwhile);
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
        self.verify_unless(&mut |_| false).map(drop)
    }

    /// [`FileBackupV2Reader::verify`], asking `stop` before each chunk,
    /// with the count of chunks opened so far, whether to go on: once it
    /// says stop, no other chunk is opened. Returns whether the whole
    /// backup was checked (`false` when `stop` stopped it). For a caller
    /// that must not go on decrypting once its reason to went away (the
    /// daemon, at a lock).
    ///
    /// # Errors
    /// As [`FileBackupV2Reader::verify`].
    pub fn verify_unless(&self, stop: &mut dyn FnMut(u64) -> bool) -> Result<bool, VaultError> {
        let mut opened = 0u64;
        for (i, (l, f)) in self.layout.iter().zip(&self.meta.files).enumerate() {
            let mut h = Sha256::new();
            for c in 0..l.chunks {
                if stop(opened) {
                    return Ok(false);
                }
                let (data, _) = self.chunk(i, c)?;
                envcloak_sys::test_event("file backup v2 chunk verified");
                opened += 1;
                sha256_update(&mut h, &data);
            }
            let got: [u8; 32] = h.finalize().into();
            if !bool::from(got.ct_eq(&f.sha256)) {
                return Err(damaged());
            }
        }
        Ok(true)
    }

    /// What the change left in each file, as recorded: one entry per file,
    /// `None` where no result is recorded.
    ///
    /// # Errors
    /// [`VaultErrorKind::BackupDamaged`] when a result's file does not
    /// open as that file's result.
    pub fn results(&self) -> Result<Vec<Option<[u8; 32]>>, VaultError> {
        let mut out = vec![None; self.meta.files.len()];
        for entry in list_dir(&self.dir, MAX_DIR_ENTRIES)? {
            let name = entry.name;
            let Some(index) = name
                .to_str()
                .and_then(|n| n.strip_prefix(RESULT))
                .filter(|n| !n.is_empty() && n.len() <= 4 && n.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|n| n.parse::<usize>().ok())
            else {
                continue;
            };
            let file = match entry.kind {
                DirEntryKind::File => true,
                DirEntryKind::Unknown => kind_beneath(&self.dir, &name)? == DirEntryKind::File,
                _ => false,
            };
            if index >= out.len() || !file {
                return Err(damaged());
            }
            let file = open_beneath(&self.dir, &name)?;
            if !file.metadata()?.is_file() {
                return Err(damaged());
            }
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
        self.record(file, sha256_after, &mut |_| {})
    }

    /// [`FileBackupV2Reader::record_result`], reporting each step to
    /// `observe` as it is done. Test support only (feature `testing`): the
    /// crash tests stop the writer there.
    ///
    /// # Errors
    /// As [`FileBackupV2Reader::record_result`].
    #[cfg(feature = "testing")]
    pub fn record_result_observed(
        &self,
        file: usize,
        sha256_after: &[u8; 32],
        mut observe: impl FnMut(ResultStepV2),
    ) -> Result<(), VaultError> {
        self.record(file, sha256_after, &mut observe)
    }

    /// The result is sealed into a file of its own under a name no reader
    /// takes (`.result-<index>-<random>.tmp`), flushed, and only then
    /// linked to its name `result-<index>`, which fails when that name
    /// exists: a reader sees a result absent or whole, never in part, and
    /// a crash at any step leaves the file unrecorded or recorded, never
    /// damaged. A link takes whatever has the temporary name at that
    /// moment, so the result's name is then opened (never through a
    /// symlink) and compared, by device and inode, with the file written:
    /// another file put under the temporary name meanwhile fails the call
    /// ([`VaultErrorKind::InvalidRecord`]), never answered as recorded.
    /// The temporary name then goes, and the directory is flushed.
    fn record(
        &self,
        file: usize,
        sha256_after: &[u8; 32],
        observe: &mut dyn FnMut(ResultStepV2),
    ) -> Result<(), VaultError> {
        if file >= self.meta.files.len() {
            return Err(VaultErrorKind::InvalidRecord.into());
        }
        let index = u32::try_from(file).map_err(|_| damaged())?;
        let mut e = Enc::new();
        e.u8(RESULT_VERSION)
            .raw(&index.to_be_bytes())
            .raw(sha256_after);
        let sealed = seal_record(&self.key, &self.ctx.aad(Rec::Result(index)), &e.finish())?;
        let path = format!("{RESULT}{file}");
        let temp = format!(
            "{RESULT_TEMP}{file}-{}{STAGING_SUFFIX}",
            FileBackupId::generate()
        );
        let (path, temp) = (OsStr::new(&path), OsStr::new(&temp));
        let mut out = create_beneath(&self.dir, temp, 0o600)?;
        observe(ResultStepV2::Created);
        let mut published = || -> Result<(), VaultError> {
            out.write_all(&sealed)?;
            observe(ResultStepV2::Written);
            sync_file(&out)?;
            observe(ResultStepV2::Synced);
            match link_beneath(&self.dir, temp, path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    return Err(VaultErrorKind::AlreadyExists.into());
                }
                Err(e) => return Err(e.into()),
            }
            // A link takes whatever has the temporary name then: the result
            // is recorded only if its name holds the file written.
            if !same_file(&open_beneath(&self.dir, path)?, &out)? {
                return Err(VaultErrorKind::InvalidRecord.into());
            }
            observe(ResultStepV2::Published);
            Ok(())
        };
        let published = published();
        drop(out);
        // The temporary name goes whatever happened. A failure to remove it
        // leaves a file no reader takes, which the purge removes with the
        // backup: the result itself is recorded or not as `published` says.
        let _ = unlink_beneath(&self.dir, temp);
        published?;
        observe(ResultStepV2::Unlinked);
        sync_file(&self.dir)?;
        observe(ResultStepV2::Done);
        Ok(())
    }
}

/// A point [`FileBackupV2Reader::record_result`] passes, for the crash
/// tests (feature `testing`): each is reported after the step is done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultStepV2 {
    /// The temporary file exists, empty.
    Created,
    /// The sealed result is written to it.
    Written,
    /// It is flushed.
    Synced,
    /// It is linked to the result's name: the result is recorded.
    Published,
    /// The temporary name is removed.
    Unlinked,
    /// The backup's directory is flushed.
    Done,
}

/// Whether `name` is a temporary name [`FileBackupV2Reader::record_result`]
/// uses: `.result-<index>-<id>.tmp`.
fn result_temp(name: &str) -> bool {
    name.strip_prefix(RESULT_TEMP)
        .and_then(|n| n.strip_suffix(STAGING_SUFFIX))
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
}

/// Opens the `data` file of the backup whose directory `dir` is open on,
/// read only, never through a symlink and never waiting on a FIFO
/// (`envcloak_sys::open_beneath`). Every open of one for a listing or a
/// reader goes through here: a test build's trace counts them (`file
/// backup v2 data opened`).
fn open_data_in(dir: &File) -> std::io::Result<File> {
    envcloak_sys::test_event("file backup v2 data opened");
    open_beneath(dir, OsStr::new(DATA))
}

/// The id a committed backup's directory is named for:
/// `files2-<time>-<id>`. `None` for any other name.
fn listed_id(name: &std::ffi::OsStr) -> Option<FileBackupId> {
    name.to_str()
        .filter(|n| n.starts_with(PREFIX))
        .and_then(|n| n.rsplit('-').next())
        .and_then(FileBackupId::parse)
}

/// Whether the entry `e` of `backups` is a directory now (never a
/// symlink): as the listing read it, or, where it could not tell, as
/// `fstatat(2)` without following a symlink says. It can change before it
/// is opened, so what is opened is opened with `O_NOFOLLOW` and checked.
fn is_dir_entry(backups: &File, e: &envcloak_sys::DirEntryName) -> bool {
    match e.kind {
        DirEntryKind::Dir => true,
        DirEntryKind::Unknown => {
            kind_beneath(backups, &e.name).is_ok_and(|k| k == DirEntryKind::Dir)
        }
        _ => false,
    }
}

/// The name in `backups` (the handle [`open_backups`] opened) of backup
/// `id`'s directory, by its name alone: no backup is opened to find it.
/// The first by name when two have the id.
fn find_backup_v2(backups: &File, id: &FileBackupId) -> Result<Option<OsString>, VaultError> {
    envcloak_sys::test_event("file backup v2 directory listed");
    let mut found: Option<OsString> = None;
    for entry in list_dir(backups, MAX_DIR_ENTRIES)? {
        if listed_id(&entry.name) != Some(*id) || !is_dir_entry(backups, &entry) {
            continue;
        }
        if found.as_ref().is_none_or(|f| entry.name < *f) {
            found = Some(entry.name);
        }
    }
    Ok(found)
}

/// A backup's directory, as a listing finds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedV2 {
    /// Its id, from its name.
    pub id: FileBackupId,
    /// Its directory: `backups/`'s path in the vault's paths, joined with
    /// its name. [`FileBackupsV2::open_listed`] takes the name from it and
    /// opens it through `backups/` opened again, never by this path.
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
/// a symlink) named `files2-<time>-<id>`, each one's header read once for
/// its time. Staging directories are never listed. Sorted by name, so
/// oldest first. [`FileBackupsV2::open_listed`] opens one where it was
/// found. `backups/` is opened as [`open_backups`] opens it, and each
/// backup's directory and `data` through it: a symlink in place of
/// `backups/` (or of the data directory) is refused, never listed
/// through.
///
/// # Errors
/// When the directory cannot be opened, is not one this user alone may
/// write ([`VaultErrorKind::Path`]), or cannot be read.
pub fn list_file_backups_v2(p: &VaultPaths) -> Result<Vec<ListedV2>, VaultError> {
    let Some(backups) = open_backups(p)? else {
        return Ok(Vec::new());
    };
    envcloak_sys::test_event("file backup v2 directory listed");
    let mut out = Vec::new();
    for entry in list_dir(&backups, MAX_DIR_ENTRIES)? {
        let Some(id) = listed_id(&entry.name) else {
            continue;
        };
        if !is_dir_entry(&backups, &entry) {
            continue;
        }
        // Gone, or no longer a directory, since it was listed: not listed.
        let dir = match open_dir_beneath(&backups, &entry.name) {
            Ok(d) => d,
            Err(e) if not_a_dir(&e) => continue,
            Err(e) => return Err(e.into()),
        };
        let mut head = [0u8; HEADER_LEN_V2];
        let created_at = open_data_in(&dir)
            .ok()
            .filter(|f| read_at(f, &mut head, 0).is_ok())
            .and_then(|_| parse_header(&head).ok())
            .map_or_else(
                || dir.metadata().map_or(0, |m| modified_secs(&m)),
                |h| h.created_at,
            );
        out.push(ListedV2 {
            id,
            dir: p.backups_dir.join(&entry.name),
            created_at,
        });
    }
    out.sort_by(|a, b| a.dir.cmp(&b.dir));
    Ok(out)
}

/// The id a staging directory is named for: `.files2-<time>-<id>.tmp`.
/// `None` for any other name.
fn staging_id(name: &str) -> Option<FileBackupId> {
    name.strip_prefix('.')
        .and_then(|n| n.strip_suffix(STAGING_SUFFIX))
        .and_then(|n| listed_id(std::ffi::OsStr::new(n)))
}

/// Whether `name` is a staging directory's: `.files2-<...>.tmp`.
fn staging_name(name: &str) -> bool {
    name.strip_prefix('.')
        .is_some_and(|n| n.starts_with(PREFIX) && n.ends_with(STAGING_SUFFIX))
}

/// Whether `name` is the name a purge gives a backup's directory before it
/// removes it: `.files2-<...>.purge`.
fn purged_name(name: &str) -> bool {
    name.strip_prefix('.')
        .is_some_and(|n| n.starts_with(PREFIX) && n.ends_with(PURGE_SUFFIX))
}

/// Whether removing a directory failed because something is left in it.
fn not_empty(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::DirectoryNotEmpty
        || e.raw_os_error()
            .is_some_and(|c| c == libc::ENOTEMPTY || c == libc::EEXIST)
}

/// Whether opening `name` as a directory failed because it is not one of
/// a backup's: gone, a symlink, or not a directory.
fn not_a_dir(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::NotFound
        || e.raw_os_error()
            .is_some_and(|c| c == libc::ELOOP || c == libc::ENOTDIR)
}

/// The directory `name` of `backups`, opened where it is now, never
/// through a symlink: `None` when it is gone, a symlink or not a
/// directory. Everything the purge removes in it, it removes through this
/// handle, so nothing outside it is touched, whatever takes its name.
fn open_member(backups: &File, name: &OsStr) -> Result<Option<File>, VaultError> {
    match open_dir_beneath(backups, name) {
        Ok(d) => Ok(Some(d)),
        Err(e) if not_a_dir(&e) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// When the backup in `dir` was made: its header's time, or its
/// directory's modification time when the header does not read.
fn made_at(dir: &File) -> u64 {
    let mut head = [0u8; HEADER_LEN_V2];
    open_beneath(dir, std::ffi::OsStr::new(DATA))
        .ok()
        .filter(|f| f.metadata().is_ok_and(|m| m.is_file()))
        .filter(|f| read_at(f, &mut head, 0).is_ok())
        .and_then(|_| parse_header(&head).ok())
        .map_or_else(
            || dir.metadata().map_or(0, |m| modified_secs(&m)),
            |h| h.created_at,
        )
}

/// Whether `a` and `b` are open on one file: the same device and inode.
fn same_file(a: &File, b: &File) -> Result<bool, VaultError> {
    use std::os::unix::fs::MetadataExt;
    let (a, b) = (a.metadata()?, b.metadata()?);
    Ok((a.dev(), a.ino()) == (b.dev(), b.ino()))
}

/// Whether `name` in `backups` still names the directory `dir` is.
fn still_named(backups: &File, name: &OsStr, dir: &File) -> Result<bool, VaultError> {
    use std::os::unix::fs::MetadataExt;
    let ours = dir.metadata()?;
    Ok(match open_dir_beneath(backups, name) {
        Ok(d) => d
            .metadata()
            .is_ok_and(|m| (m.dev(), m.ino()) == (ours.dev(), ours.ino())),
        Err(e) if not_a_dir(&e) => false,
        Err(e) => return Err(e.into()),
    })
}

/// Whether `name` is a file of a backup's own: `data`, a result, or a
/// temporary name a result left when its writer stopped.
fn backup_file(name: &str) -> bool {
    name == DATA
        || result_temp(name)
        || name
            .strip_prefix(RESULT)
            .is_some_and(|i| !i.is_empty() && i.bytes().all(|b| b.is_ascii_digit()))
}

/// Removes a backup's files from `dir`, the directory `name` of `backups`
/// opened ([`open_member`]): its `data` and result files and the temporary
/// names a result left, each through `dir`, then the directory by its
/// name. Anything else in it stays, and so does the directory. Returns
/// whether the directory went: `false` when it was gone already or
/// something else is left in it. When files went from a directory that
/// stays (something else is left in it, or a removal failed), `dir` is
/// flushed, so their removal is on disk too; a failed flush is the error
/// when nothing failed before it. A directory that went is flushed with
/// `backups/` ([`purge_v2`]).
fn empty_and_remove(backups: &File, name: &OsStr, dir: &File) -> Result<bool, VaultError> {
    let mut unlinked = false;
    let went = remove_backup_files(dir, &mut unlinked).and_then(|()| {
        match remove_dir_beneath(backups, name) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound || not_empty(&e) => Ok(false),
            Err(e) => Err(e.into()),
        }
    });
    if unlinked && !matches!(went, Ok(true)) {
        let flushed = sync_file(dir);
        if let (Ok(_), Err(e)) = (&went, flushed) {
            return Err(e.into());
        }
    }
    went
}

/// Unlinks a backup's own files from `dir` ([`backup_file`]), regular
/// files only, each through `dir`; sets `unlinked` once one went.
fn remove_backup_files(dir: &File, unlinked: &mut bool) -> Result<(), VaultError> {
    for entry in list_dir(dir, MAX_DIR_ENTRIES)? {
        if !entry.name.to_str().is_some_and(backup_file) {
            continue;
        }
        let file = match entry.kind {
            DirEntryKind::File => true,
            DirEntryKind::Unknown => {
                kind_beneath(dir, &entry.name).is_ok_and(|k| k == DirEntryKind::File)
            }
            _ => false,
        };
        if !file {
            continue;
        }
        match unlink_beneath(dir, &entry.name) {
            Ok(()) => *unlinked = true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// What a purge removed, whether it changed `backups/` since it last
/// flushed it, and the first thing it could not do.
#[derive(Default)]
struct Purged {
    removed: usize,
    unflushed: bool,
    failed: Option<VaultError>,
}

impl Purged {
    fn count(&mut self, r: Result<bool, VaultError>) {
        match r {
            Ok(true) => {
                self.removed += 1;
                self.unflushed = true;
            }
            Ok(false) => {}
            Err(e) => {
                self.failed.get_or_insert(e);
            }
        }
    }
}

/// Removes the backups in `p` made more than [`FILE_BACKUP_RETENTION`]
/// before `now` (Unix seconds), and the staging directories interrupted
/// backups left, unchanged for [`STAGING_GRACE`]. Returns how many
/// directories it removed. Needs no key: the time is in the header.
/// [`purge_file_backups_v2_except`] with no backup in progress.
///
/// # Errors
/// As [`purge_file_backups_v2_except`].
pub fn purge_file_backups_v2(p: &VaultPaths, now: u64) -> Result<usize, VaultError> {
    purge_file_backups_v2_except(p, now, |_| false)
}

/// [`purge_file_backups_v2`], keeping the staging directory of every
/// backup `in_progress` says is still being written, however long it has
/// been unchanged: a backup's chunks go to its `data` file, which leaves
/// the directory's time as it was, and a writer may buffer them. A
/// directory is asked about once it is due, just before it would go, so
/// a caller whose backups in progress are made and registered under one
/// lock, which `in_progress` takes, never loses one: a directory seen
/// before its backup was registered is asked about after.
///
/// Each directory is opened once, never through a symlink, its time read
/// through that handle, and every file removed from it removed through
/// that handle: whatever takes its name meanwhile (a symlink to another
/// directory, say), nothing outside `backups/` is removed. A committed
/// backup due to go first leaves the listing: its directory is renamed to
/// `.files2-<time>-<id>.purge` (only while its name still names the
/// directory opened), so no listing shows it half removed, and a
/// directory something else is left in stays under that name, never
/// listed, and is tried again by the next purge.
///
/// One backup it cannot remove does not stop it: a directory something
/// else is left in stays, deliberately (counted as not removed), and
/// after any other failure the others are still removed. A committed
/// backup's rename out of the listing is flushed before any of its files
/// goes, and none goes when that flush fails. Every change is flushed to
/// disk before it returns, also when no directory went and when it then
/// reports a failure: a rename and a removal in `backups/` by flushing
/// `backups/`, the files removed from a directory that stays by flushing
/// that directory.
///
/// # Errors
/// When the directory cannot be read or flushed, or the first backup or
/// staging directory that could not be removed or flushed, after the rest
/// went.
pub fn purge_file_backups_v2_except(
    p: &VaultPaths,
    now: u64,
    in_progress: impl FnMut(&FileBackupId) -> bool,
) -> Result<usize, VaultError> {
    purge_v2(p, now, in_progress, &mut |_| {})
}

/// Where a purge is with one directory, as
/// [`purge_file_backups_v2_observed`] reports it, by the directory's name
/// in `backups/` then.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurgeStepV2<'a> {
    /// A committed backup's directory is opened and found due; the purge
    /// has not yet checked that its name still names the directory opened,
    /// nor renamed it out of the listing.
    Due(&'a str),
    /// The files in it are about to be removed: once it is opened and
    /// found due and, for a committed backup's, renamed out of the
    /// listing.
    Removing(&'a str),
}

/// [`purge_file_backups_v2_except`], telling `observe` where it is with
/// each directory ([`PurgeStepV2`]). Test support only (feature
/// `testing`): a test replaces the directory there.
///
/// # Errors
/// As [`purge_file_backups_v2_except`].
#[cfg(feature = "testing")]
pub fn purge_file_backups_v2_observed(
    p: &VaultPaths,
    now: u64,
    in_progress: impl FnMut(&FileBackupId) -> bool,
    mut observe: impl FnMut(PurgeStepV2<'_>),
) -> Result<usize, VaultError> {
    purge_v2(p, now, in_progress, &mut observe)
}

fn purge_v2(
    p: &VaultPaths,
    now: u64,
    mut in_progress: impl FnMut(&FileBackupId) -> bool,
    observe: &mut dyn FnMut(PurgeStepV2<'_>),
) -> Result<usize, VaultError> {
    let Some(backups) = open_backups(p)? else {
        return Ok(0);
    };
    let mut entries = list_dir(&backups, MAX_DIR_ENTRIES)?;
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let mut purged = Purged::default();
    for entry in entries {
        let Some(name) = entry.name.to_str() else {
            continue;
        };
        let removed = if listed_id(&entry.name).is_some() {
            purge_committed(&backups, name, now, &mut purged.unflushed, observe)
        } else if staging_name(name) {
            purge_staging(&backups, name, now, &mut in_progress, observe)
        } else if purged_name(name) {
            open_member(&backups, &entry.name).and_then(|d| match d {
                Some(dir) => {
                    observe(PurgeStepV2::Removing(name));
                    empty_and_remove(&backups, &entry.name, &dir)
                }
                None => Ok(false),
            })
        } else {
            continue;
        };
        purged.count(removed);
    }
    // Whatever changed `backups/` since its last flush, also when no
    // directory went or something failed: renamed out of the listing,
    // removed.
    if purged.unflushed {
        if let Err(e) = sync_file(&backups) {
            purged.failed.get_or_insert(e.into());
        }
    }
    purged.failed.map_or(Ok(purged.removed), Err)
}

/// Removes the committed backup `name` of `backups` when it was made more
/// than [`FILE_BACKUP_RETENTION`] before `now`, first renaming it out of
/// the listing and flushing `backups/`, so no crash brings it back listed
/// with records missing: a failed flush removes none of them. Returns
/// whether its directory went; a directory whose name names another
/// meanwhile is left as it is, as one gone. Sets `unflushed` while
/// `backups/` holds a change not yet flushed.
fn purge_committed(
    backups: &File,
    name: &str,
    now: u64,
    unflushed: &mut bool,
    observe: &mut dyn FnMut(PurgeStepV2<'_>),
) -> Result<bool, VaultError> {
    let os = OsStr::new(name);
    let Some(dir) = open_member(backups, os)? else {
        return Ok(false);
    };
    if now.saturating_sub(made_at(&dir)) <= FILE_BACKUP_RETENTION.as_secs() {
        return Ok(false);
    }
    observe(PurgeStepV2::Due(name));
    if !still_named(backups, os, &dir)? {
        return Ok(false);
    }
    let hidden = format!(".{name}{PURGE_SUFFIX}");
    rename_beneath(backups, os, OsStr::new(&hidden))?;
    *unflushed = true;
    sync_file(backups)?;
    *unflushed = false;
    observe(PurgeStepV2::Removing(&hidden));
    empty_and_remove(backups, OsStr::new(&hidden), &dir)
}

/// Removes the staging directory `name` of `backups` if it was unchanged
/// for [`STAGING_GRACE`] before `now` and its backup is not in progress.
/// Returns whether it went.
fn purge_staging(
    backups: &File,
    name: &str,
    now: u64,
    in_progress: &mut impl FnMut(&FileBackupId) -> bool,
    observe: &mut dyn FnMut(PurgeStepV2<'_>),
) -> Result<bool, VaultError> {
    let os = OsStr::new(name);
    let Some(dir) = open_member(backups, os)? else {
        return Ok(false);
    };
    let modified = dir.metadata().map_or(0, |m| modified_secs(&m));
    if now.saturating_sub(modified) <= STAGING_GRACE.as_secs()
        || staging_id(name).is_some_and(|id| in_progress(&id))
    {
        return Ok(false);
    }
    observe(PurgeStepV2::Removing(name));
    empty_and_remove(backups, os, &dir)
}

/// Rewrites the creation time in a backup's header. Test support only
/// (feature `testing`): the header is authenticated through the metadata,
/// so the backup then no longer opens, but purging reads only the header.
#[cfg(feature = "testing")]
pub fn age_file_backup_v2_for_testing(
    dir: &std::path::Path,
    created_at: u64,
) -> Result<(), VaultError> {
    use std::io::{Seek, SeekFrom};
    let mut f = std::fs::File::options()
        .read(true)
        .write(true)
        .open(dir.join(DATA))?;
    f.seek(SeekFrom::Start(43))?;
    f.write_all(&created_at.to_be_bytes())?;
    sync_file(&f)?;
    Ok(())
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
                boot: Some([6; 16]),
            },
            chain: vec![
                CreatorProcess {
                    pid: 42,
                    start_time: 7,
                    token: Some(9),
                    sid: Some(40),
                    terminal: Some(0x1000_0003),
                },
                CreatorProcess {
                    pid: 40,
                    start_time: 5,
                    token: None,
                    sid: None,
                    terminal: None,
                },
            ],
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

    fn test_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::under(dir.path().join("data"));
        let (v, _) = crate::create_vault(
            &paths,
            &SecretBytes::copy_from(b"a test passphrase, not a fixture"),
            crate::crypto::KdfParams::minimum(),
        )
        .unwrap();
        (dir, v)
    }

    fn test_creator() -> BackupCreator {
        BackupCreator {
            kind: CreatorKind::Terminal,
            evidence_digest: [1; 32],
            agent: None,
            owner: BackupOwner {
                pid: 7,
                start_time: 8,
                token: None,
                boot: None,
            },
            chain: Vec::new(),
        }
    }

    /// The final flag in a chunk's associated data is what tells a file's
    /// last chunk from another: a file of two chunks whose metadata, sealed
    /// with the backup's own key, is replaced by one that says the file is
    /// one full chunk long, with its second chunk dropped. The layout, the
    /// chunk index and the length all agree with the metadata; only the
    /// flag the first chunk was sealed with (not the last) does not, and
    /// it does not open as the file's last.
    #[test]
    fn only_the_final_flag_tells_a_files_last_chunk_from_another() {
        let (_dir, v) = test_vault();
        let body: Vec<u8> = (0..=CHUNK_V2).map(|i| (i % 251) as u8).collect();
        let path = "/h/.claude/projects/p/f.jsonl".to_owned();
        let mut w = v
            .begin_file_backup_v2(
                BackupPurpose::Scrub,
                test_creator(),
                vec![PlannedFile {
                    path: path.clone(),
                    mode: 0o600,
                    size: body.len() as u64,
                }],
                1_790_000_000,
            )
            .unwrap();
        w.put(0, 0, &SecretBytes::copy_from(&body[..CHUNK_V2]))
            .unwrap();
        w.put(0, 1, &SecretBytes::copy_from(&body[CHUNK_V2..]))
            .unwrap();
        let done = w.commit().unwrap();
        let data = done.dir.join(DATA);
        let bytes = std::fs::read(&data).unwrap();
        let first_end = HEADER_LEN_V2 + 4 + 32 + Sealed::OVERHEAD + 4 + MAX_CHUNK_RECORD;
        let files = [FileMetaV2 {
            path,
            mode: 0o600,
            size: CHUNK_V2 as u64,
            sha256: Sha256::digest(&body[..CHUNK_V2]).into(),
        }];
        let meta = encode_metadata(&w.ctx.header(), BackupPurpose::Scrub, &w.creator, &files);
        let sealed = seal_record(&w.key, &w.ctx.aad(Rec::Metadata), &meta).unwrap();
        let mut forged = bytes[..first_end].to_vec();
        let at = forged.len() as u64;
        write_record(&mut forged, &sealed).unwrap();
        forged.extend_from_slice(&at.to_be_bytes());
        std::fs::write(&data, &forged).unwrap();
        let r = v.open_file_backup_v2(&done.id).unwrap();
        assert_eq!(r.meta().files[0].size, CHUNK_V2 as u64);
        assert_eq!(
            r.chunk(0, 0).unwrap_err().kind(),
            VaultErrorKind::BackupDamaged
        );
        assert_eq!(
            r.verify().unwrap_err().kind(),
            VaultErrorKind::BackupDamaged
        );
    }

    /// A backup made under an older schema (before a migration) opens and
    /// reads back, bound to its own schema; a header claiming another
    /// schema than the one its records were sealed under does not, nor one
    /// newer than the vault's.
    #[test]
    fn a_backup_of_an_older_schema_still_opens() {
        let (_dir, v) = test_vault();
        let body = b"KEY=not a secret, a test body\n";
        let creator = test_creator();
        let plan = || {
            vec![PlannedFile {
                path: "/h/.env".into(),
                mode: 0o600,
                size: body.len() as u64,
            }]
        };
        let now = v.schema_version();
        let make = |schema: u16| {
            let mut w = v
                .begin_v2(
                    BackupPurpose::Migrate,
                    creator.clone(),
                    plan(),
                    1_790_000_000,
                    schema,
                    None,
                )
                .unwrap();
            w.put(0, 0, &SecretBytes::copy_from(body)).unwrap();
            w.commit().unwrap()
        };
        let older = make(now - 1);
        let r = v.open_file_backup_v2(&older.id).unwrap();
        r.verify().unwrap();
        assert!(r.chunk(0, 0).unwrap().0.ct_eq(body));
        r.record_result(0, &[4; 32]).unwrap();
        assert_eq!(r.results().unwrap(), vec![Some([4; 32])]);
        // The header changed to the vault's schema: the records were sealed
        // under the older one.
        let data = older.dir.join(DATA);
        let mut bytes = std::fs::read(&data).unwrap();
        bytes[21..23].copy_from_slice(&now.to_be_bytes());
        std::fs::write(&data, &bytes).unwrap();
        assert_eq!(
            v.open_file_backup_v2(&older.id).unwrap_err().kind(),
            VaultErrorKind::BackupDamaged
        );
        let newer = make(now + 1);
        assert_eq!(
            v.open_file_backup_v2(&newer.id).unwrap_err().kind(),
            VaultErrorKind::BackupDamaged
        );
    }

    /// The bound the reader takes metadata up to is the encoding's own:
    /// metadata with every field at its longest (4,096 files, each at the
    /// longest path, the longest label) is exactly [`MAX_METADATA`].
    #[test]
    fn the_metadata_bound_is_the_encodings_longest() {
        let creator = BackupCreator {
            kind: CreatorKind::Unknown,
            evidence_digest: [3; 32],
            agent: Some("a".repeat(MAX_LABEL_V2)),
            owner: BackupOwner {
                pid: i32::MAX,
                start_time: u64::MAX,
                token: Some(i32::MAX),
                boot: Some([0xff; 16]),
            },
            chain: vec![
                CreatorProcess {
                    pid: i32::MAX,
                    start_time: u64::MAX,
                    token: Some(i32::MAX),
                    sid: Some(i32::MAX),
                    terminal: Some(u64::MAX),
                };
                MAX_CHAIN_V2
            ],
        };
        let file = FileMetaV2 {
            path: format!("/{}", "p".repeat(MAX_PATH_V2 - 1)),
            mode: 0o777,
            size: 0,
            sha256: [9; 32],
        };
        let files = vec![file; MAX_FILES_V2];
        let m = encode_metadata(
            &[0; HEADER_LEN_V2],
            BackupPurpose::Migrate,
            &creator,
            &files,
        );
        assert_eq!(m.len(), MAX_METADATA);
        assert_eq!(decode_metadata(&m).unwrap().creator, creator);
        // One process more than a backup records is refused.
        let mut longer = creator.clone();
        longer.chain.push(longer.chain[0]);
        let m = encode_metadata(
            &[0; HEADER_LEN_V2],
            BackupPurpose::Migrate,
            &longer,
            &files[..1],
        );
        assert!(decode_metadata(&m).is_err());
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
