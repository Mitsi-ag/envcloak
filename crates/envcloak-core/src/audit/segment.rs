//! The log's files and its writer (layout in docs/VAULT.md "Audit log").
//!
//! The log is a series of segment files in `<data>/audit/`, each named
//! after the sequence number of its first entry, `<20 digits>.seg`, 0600
//! in a 0700 directory. A segment starts with a header and holds entries
//! (frames) one after another:
//!
//! ```text
//! header = "ECAUDIT1" | version(1) = 1 | vault_id(16) | epoch(4) | first_seq(8)
//!          | prev_mac(32) | header_mac(32)
//! frame  = len(4) | seq(8) | sealed(len) | mac(32)
//! ```
//!
//! - `sealed` is the entry's record, XChaCha20-Poly1305 under the `audit`
//!   subkey, bound to the vault, the epoch and `seq` by its associated
//!   data. Nothing in a segment is plaintext but the header's fields, the
//!   lengths and the sequence numbers.
//! - `mac` chains the entries: keyed BLAKE3 under the `index` subkey of the
//!   previous entry's `mac`, `seq` and `sealed`, in the domain
//!   `envcloak/v1/audit-chain`. The first entry's predecessor is the
//!   genesis value, the keyed hash of the vault id in
//!   `envcloak/v1/audit-genesis`. A segment's `prev_mac` is the chain value
//!   before its first entry, and `header_mac` authenticates the header in
//!   `envcloak/v1/audit-segment`.
//! - The head is the last entry's (`seq`, `mac`). The daemon saves it in
//!   the vault's sealed header (the anchor): entries before it cannot be
//!   removed, changed or replaced without [`crate::audit::verify`]
//!   noticing; entries after it are the unanchored tail.
//!
//! [`AuditWriter::append`] writes one frame and flushes it with
//! [`envcloak_sys::sync_file`] (`F_FULLFSYNC` on macOS) before it returns:
//! the entry is durable, in a segment the log's directory still names,
//! when the call succeeds, and a failed call leaves the segment as it was,
//! so the caller can deny what the entry was for.

use std::ffi::OsStr;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::crypto::{
    Aad, FieldTag, ItemClass, Keyring, Purpose, Sealed, SubKey, TableTag, VaultId,
    authenticates_at, keyed_hash, keyed_hash_parts, keyed_hash_prefixes,
};
use crate::vault::{
    AuditHead, check_private_dir, check_private_file, now_secs, open_record, seal_record, utc_stamp,
};

use super::record::{AuditRecord, MAX_ENTRY};
use super::verify::{Walk, walk};
use super::{AuditError, AuditErrorKind};

pub(crate) const MAGIC: [u8; 8] = *b"ECAUDIT1";
pub(crate) const FORMAT_VERSION: u8 = 1;
/// The header's bytes before its MAC.
const HEADER_BODY: usize = 8 + 1 + 16 + 4 + 8 + 32;
/// A segment header's length.
pub const HEADER_LEN: usize = HEADER_BODY + 32;
/// A frame's length and sequence number.
pub(crate) const FRAME_HEAD: usize = 4 + 8;
pub(crate) const MAC_LEN: usize = 32;
/// The largest sealed entry.
pub(crate) const MAX_SEALED: usize = MAX_ENTRY + Sealed::OVERHEAD;
/// A segment this long or longer gets no more entries; the next one starts
/// a new segment.
pub const MAX_SEGMENT: u64 = 1 << 20;
/// A segment longer than this is not read: nothing EnvCloak writes grows
/// that large.
pub(crate) const MAX_SEGMENT_READ: u64 = 16 << 20;
/// The audit log's format version, in the associated data's
/// `schema_version` slot: the log outlives the vault's schema migrations.
pub(crate) const AAD_VERSION: u16 = 1;

const SEGMENT_DOMAIN: &str = "envcloak/v1/audit-segment";
const CHAIN_DOMAIN: &str = "envcloak/v1/audit-chain";
const GENESIS_DOMAIN: &str = "envcloak/v1/audit-genesis";

/// The keys and identity of one vault epoch's log: copies of the `audit`
/// and `index` subkeys, wiped on drop.
pub(crate) struct LogKeys {
    pub(crate) vault_id: VaultId,
    pub(crate) epoch: u32,
    seal: SubKey,
    mac: SubKey,
}

impl core::fmt::Debug for LogKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LogKeys")
            .field("vault_id", &self.vault_id)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl LogKeys {
    pub(crate) fn new(k: &Keyring) -> Self {
        LogKeys {
            vault_id: k.vault_id(),
            epoch: k.epoch(),
            seal: k.key(Purpose::Audit).duplicate(),
            mac: k.key(Purpose::Index).duplicate(),
        }
    }

    fn aad(&self, seq: u64) -> Aad {
        Aad {
            vault_id: self.vault_id,
            schema_version: AAD_VERSION,
            key_epoch: self.epoch,
            table: TableTag::Audit,
            row_id: [0; 16],
            field: FieldTag::AuditEntry,
            item_class: ItemClass::None,
            row_version: seq,
        }
    }

    /// The chain value before the first entry.
    pub(crate) fn genesis(&self) -> [u8; 32] {
        keyed_hash(&self.mac, GENESIS_DOMAIN, &self.vault_id.0)
    }

    /// The chain value after the entry `seq` sealed as `sealed`.
    pub(crate) fn chain(&self, prev: &[u8; 32], seq: u64, sealed: &[u8]) -> [u8; 32] {
        keyed_hash_parts(&self.mac, CHAIN_DOMAIN, &[prev, &seq.to_be_bytes(), sealed])
    }

    /// Whether an entry `seq` after the chain value `prev` ends in `body`
    /// at some sealed length in `lens`: whether, for such a length `n`,
    /// the chain value of the first `n` bytes is the 32 bytes after them.
    /// One pass over `body`: it is hashed once and the hash finalized at
    /// each length (at most the largest entry's bytes).
    pub(crate) fn chain_ends_in(
        &self,
        prev: &[u8; 32],
        seq: u64,
        body: &[u8],
        lens: core::ops::RangeInclusive<usize>,
    ) -> bool {
        keyed_hash_prefixes(
            &self.mac,
            CHAIN_DOMAIN,
            &[prev, &seq.to_be_bytes()],
            body,
            lens,
            |n, mac| {
                body.get(n..n + MAC_LEN).is_some_and(|stored| {
                    bool::from(subtle::ConstantTimeEq::ct_eq(stored, &mac[..]))
                })
            },
        )
    }

    /// Whether entry `seq`'s sealed bytes, starting `body`, open at some
    /// length in `lens`, whatever the frame says its length is: one pass
    /// ([`authenticates_at`]), where `take(n)` is asked about each length
    /// `n` that opens and ends the search with `true`. Nothing is
    /// decrypted.
    pub(crate) fn sealed_ends_in(
        &self,
        seq: u64,
        body: &[u8],
        lens: core::ops::RangeInclusive<usize>,
        take: impl FnMut(usize) -> bool,
    ) -> bool {
        authenticates_at(&self.seal, &self.aad(seq), body, lens, take)
    }

    fn header_mac(&self, body: &[u8]) -> [u8; 32] {
        keyed_hash(&self.mac, SEGMENT_DOMAIN, body)
    }

    fn seal(&self, seq: u64, record: &AuditRecord) -> Result<Vec<u8>, AuditError> {
        let pt = Zeroizing::new(record.encode());
        if pt.len() > MAX_ENTRY {
            return Err(AuditErrorKind::TooLarge.into());
        }
        seal_record(&self.seal, &self.aad(seq), &pt).map_err(|_| AuditErrorKind::Crypto.into())
    }

    /// Opens entry `seq`: `None` when it does not open under this log's key
    /// and sequence number, or does not decode.
    pub(crate) fn open(&self, seq: u64, sealed: &[u8]) -> Option<AuditRecord> {
        open_record(&self.seal, &self.aad(seq), sealed, AuditRecord::decode).ok()
    }

    /// A segment header for entries from `first_seq` on, after the chain
    /// value `prev_mac`.
    pub(crate) fn header(&self, first_seq: u64, prev_mac: &[u8; 32]) -> [u8; HEADER_LEN] {
        let mut h = [0u8; HEADER_LEN];
        let mut at = 0;
        for part in [
            &MAGIC[..],
            &[FORMAT_VERSION],
            &self.vault_id.0,
            &self.epoch.to_be_bytes(),
            &first_seq.to_be_bytes(),
            prev_mac,
        ] {
            h[at..at + part.len()].copy_from_slice(part);
            at += part.len();
        }
        let mac = self.header_mac(&h[..HEADER_BODY]);
        h[HEADER_BODY..].copy_from_slice(&mac);
        h
    }
}

/// A segment header as read from a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SegmentHeader {
    pub(crate) vault_id: [u8; 16],
    pub(crate) epoch: u32,
    pub(crate) first_seq: u64,
    pub(crate) prev_mac: [u8; 32],
}

/// Parses and authenticates a header. `None` when it is short, not a
/// header of this format, or its MAC is not this log's.
pub(crate) fn parse_header(b: &[u8], keys: &LogKeys) -> Option<SegmentHeader> {
    let b = b.get(..HEADER_LEN)?;
    if b[..8] != MAGIC || b[8] != FORMAT_VERSION {
        return None;
    }
    let want = keys.header_mac(&b[..HEADER_BODY]);
    if !bool::from(subtle::ConstantTimeEq::ct_eq(&want[..], &b[HEADER_BODY..])) {
        return None;
    }
    Some(SegmentHeader {
        vault_id: b[9..25].try_into().ok()?,
        epoch: u32::from_be_bytes(b[25..29].try_into().ok()?),
        first_seq: u64::from_be_bytes(b[29..37].try_into().ok()?),
        prev_mac: b[37..69].try_into().ok()?,
    })
}

/// One frame read from a segment.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Frame<'a> {
    pub(crate) seq: u64,
    pub(crate) sealed: &'a [u8],
    pub(crate) mac: [u8; 32],
    /// The offset just past the frame.
    pub(crate) end: usize,
}

/// What is at an offset of a segment.
#[derive(Debug)]
pub(crate) enum Next<'a> {
    Frame(Frame<'a>),
    /// Nothing: the segment ends here.
    End,
    /// Fewer bytes than the frame there says it has: a write cut short.
    Torn,
    /// A length no frame has: the bytes from here on cannot be framed.
    Unreadable,
}

pub(crate) fn next_frame(b: &[u8], at: usize) -> Next<'_> {
    let rest = &b[at.min(b.len())..];
    if rest.is_empty() {
        return Next::End;
    }
    if rest.len() < FRAME_HEAD {
        return Next::Torn;
    }
    let len = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
    if !(Sealed::OVERHEAD..=MAX_SEALED).contains(&len) {
        return Next::Unreadable;
    }
    let total = FRAME_HEAD + len + MAC_LEN;
    if rest.len() < total {
        return Next::Torn;
    }
    let mut seq = [0u8; 8];
    seq.copy_from_slice(&rest[4..12]);
    let mut mac = [0u8; 32];
    mac.copy_from_slice(&rest[FRAME_HEAD + len..total]);
    Next::Frame(Frame {
        seq: u64::from_be_bytes(seq),
        sealed: &rest[FRAME_HEAD..FRAME_HEAD + len],
        mac,
        end: at + total,
    })
}

fn encode_frame(seq: u64, sealed: &[u8], mac: &[u8; 32]) -> Vec<u8> {
    let len = u32::try_from(sealed.len()).unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(FRAME_HEAD + sealed.len() + MAC_LEN);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(sealed);
    out.extend_from_slice(mac);
    out
}

/// The name of the segment whose first entry is `first_seq`.
pub(crate) fn segment_name(first_seq: u64) -> String {
    format!("{first_seq:020}.seg")
}

/// The first sequence number a segment's name gives, or `None` when the
/// name is not a segment's.
pub(crate) fn parse_segment_name(name: &OsStr) -> Option<u64> {
    let s = name.to_str()?;
    let digits = s.strip_suffix(".seg")?;
    if digits.len() != 20 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// The segments in `dir`, by first sequence number. A missing directory
/// holds none.
pub(crate) fn list_segments(dir: &Path) -> Result<Vec<(u64, PathBuf)>, AuditError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry?;
        if let Some(seq) = parse_segment_name(&entry.file_name()) {
            out.push((seq, entry.path()));
        }
    }
    out.sort();
    Ok(out)
}

/// Reads a whole segment, refusing a symlink or anything over
/// [`MAX_SEGMENT_READ`] bytes.
pub(crate) fn read_segment(path: &Path) -> Result<Vec<u8>, AuditError> {
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = f.metadata()?;
    if !meta.is_file() || meta.len() > MAX_SEGMENT_READ {
        return Err(AuditErrorKind::Unreadable.into());
    }
    let mut buf = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
    Read::by_ref(&mut f)
        .take(MAX_SEGMENT_READ + 1)
        .read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_SEGMENT_READ {
        return Err(AuditErrorKind::Unreadable.into());
    }
    Ok(buf)
}

/// How the writer writes and flushes. The default writes to the file and
/// flushes with [`envcloak_sys::sync_file`]; tests put a shim in its place
/// to count the calls and to make one fail.
pub trait AuditIo: Send {
    /// Appends `bytes` to `f`, a segment opened for appending.
    fn write(&mut self, f: &File, bytes: &[u8]) -> io::Result<()>;
    /// Makes `f`, a segment or the log's directory, durable.
    fn sync(&mut self, f: &File) -> io::Result<()>;
}

/// The real thing.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsIo;

impl AuditIo for OsIo {
    fn write(&mut self, mut f: &File, bytes: &[u8]) -> io::Result<()> {
        f.write_all(bytes)
    }

    fn sync(&mut self, f: &File) -> io::Result<()> {
        envcloak_sys::sync_file(f).map(drop)
    }
}

/// What [`AuditWriter::open`] found in the log. The daemon records each
/// finding as a [`super::AuditKind::Log`] entry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpenReport {
    /// The last segment ended in what a crash in the middle of an append
    /// leaves (see [`super::VerifyReport::torn_tail`]), and those bytes
    /// were removed: part of one entry, or of a new segment's header. No
    /// whole entry was in them and the saved head did not cover them.
    pub torn_tail_removed: bool,
    /// How many bytes were removed.
    pub torn_bytes: u64,
    /// The log has damage (it fails [`super::verify`]); new entries go to
    /// a new segment and chain on from what is there.
    pub damaged: bool,
    /// The log ends at `.0` but the vault's saved head is at `.1`: entries
    /// were removed from its end, or the log was rolled back. New entries
    /// continue after the saved head, so the gap stays visible.
    pub behind_anchor: Option<(u64, u64)>,
    /// Every segment named another vault: the log of a vault this one
    /// replaced (created after the old vault was deleted). It was moved
    /// aside whole, to `audit.replaced-<UTC time>` beside the directory,
    /// and a new log started.
    pub other_vault_moved: bool,
}

/// The segment the writer appends to. Its length is read from the file
/// (`fstat`) before each append, never cached: another program running as
/// the user can change the file.
struct Current {
    file: File,
    path: PathBuf,
    /// A failed write could not be undone: start a new segment.
    broken: bool,
}

/// The log's only writer. Holds copies of the keys it needs, wiped when it
/// is dropped (the daemon drops it when the vault locks).
pub struct AuditWriter {
    dir: PathBuf,
    keys: LogKeys,
    next_seq: u64,
    head_mac: [u8; 32],
    current: Option<Current>,
    io: Box<dyn AuditIo>,
    max_segment: u64,
    /// The log's directory (device and inode) this writer last flushed the
    /// directory that names it for. Every writer starts with none and
    /// flushes that directory before its first append, whether or not it
    /// made the log's directory: `ensure_dirs` makes it for a new vault,
    /// and an earlier writer may have made it and failed, or crashed,
    /// before its flush (Codex F-64). It flushes it again before an append
    /// whenever the log's directory is another one than this: moved away
    /// and made anew, by this writer or by another program (Codex F-64
    /// follow-up). Set only when the flush succeeds.
    parent_synced: Option<(u64, u64)>,
}

impl core::fmt::Debug for AuditWriter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuditWriter")
            .field("dir", &self.dir)
            .field("segment", &self.current.as_ref().map(|c| &c.path))
            .field("next_seq", &self.next_seq)
            .finish_non_exhaustive()
    }
}

impl AuditWriter {
    /// Opens the log in `dir` for the vault epoch of `k`, after `anchor`,
    /// the head the vault's header saved (if any). Reads the log to find
    /// its head, removes a torn last entry, and notes damage and a log that
    /// ends before the anchor ([`OpenReport`]). Creates nothing until the
    /// first [`AuditWriter::append`].
    ///
    /// # Errors
    /// The directory is unsafe (not this user's, a symlink, writable by
    /// others) or cannot be read.
    pub fn open(
        dir: &Path,
        k: &Keyring,
        anchor: Option<AuditHead>,
    ) -> Result<(AuditWriter, OpenReport), AuditError> {
        Self::open_with(dir, k, anchor, Box::new(OsIo), MAX_SEGMENT)
    }

    /// Test support only: [`AuditWriter::open`] with another [`AuditIo`]
    /// and segment size.
    #[cfg(feature = "testing")]
    pub fn open_with_io(
        dir: &Path,
        k: &Keyring,
        anchor: Option<AuditHead>,
        io: Box<dyn AuditIo>,
        max_segment: u64,
    ) -> Result<(AuditWriter, OpenReport), AuditError> {
        Self::open_with(dir, k, anchor, io, max_segment)
    }

    fn open_with(
        dir: &Path,
        k: &Keyring,
        anchor: Option<AuditHead>,
        io: Box<dyn AuditIo>,
        max_segment: u64,
    ) -> Result<(AuditWriter, OpenReport), AuditError> {
        envcloak_sys::restrict_umask();
        if std::fs::symlink_metadata(dir).is_ok() {
            check_private_dir(dir)?;
        }
        let keys = LogKeys::new(k);
        let other_vault_moved = other_vaults_log(dir, &keys.vault_id)?;
        if other_vault_moved {
            move_aside(dir)?;
        }
        let w: Walk = walk(dir, &keys, anchor, false)?;
        let mut report = OpenReport {
            damaged: w.report.first_problem.is_some(),
            other_vault_moved,
            ..OpenReport::default()
        };
        let mut writer = AuditWriter {
            dir: dir.to_owned(),
            next_seq: w.next_seq,
            head_mac: w.end_mac,
            keys,
            current: None,
            io,
            max_segment,
            parent_synced: None,
        };
        if let Some(a) = anchor {
            if a.seq >= writer.next_seq {
                // The log ends before the saved head. Continue after the
                // head, so the verifier sees the gap and the chain from the
                // anchor on.
                report.behind_anchor = Some((writer.next_seq - 1, a.seq));
                writer.next_seq = a.seq.saturating_add(1);
                writer.head_mac = a.mac;
            }
        }
        if let Some(last) = w.last {
            if last.torn && last.good_len < HEADER_LEN as u64 {
                // A segment whose header a crash cut short: no entry was
                // ever in it. Remove it; the next append makes it again.
                std::fs::remove_file(&last.path)?;
                writer.io.sync(&File::open(dir)?)?;
                report.torn_tail_removed = true;
                report.torn_bytes = last.len;
            } else if last.torn && last.clean && last.good_len < last.len {
                // Part of one frame, as a crash in the middle of an append
                // leaves it (the walk checked that the segment is clean up
                // to it, that it carries the number the next entry takes,
                // that no whole entry is in it and that the saved head
                // does not cover it): remove it, whether or not the
                // writer continues this segment. Anything else is damage,
                // left as it is for the check to report.
                let f = open_append(&last.path)?;
                f.set_len(last.good_len)?;
                writer.io.sync(&f)?;
                report.torn_tail_removed = true;
                report.torn_bytes = last.len - last.good_len;
            }
            let reusable = last.clean
                && report.behind_anchor.is_none()
                && last.good_len < writer.max_segment
                && last.first_seq <= writer.next_seq;
            if reusable {
                writer.current = Some(Current {
                    file: open_append(&last.path)?,
                    path: last.path,
                    broken: false,
                });
            } else if segment_exists(dir, writer.next_seq) {
                // A damaged segment holds this name: skip its number, which
                // the verifier reports as missing along with the damage.
                writer.next_seq = writer.next_seq.saturating_add(1);
            }
        }
        Ok((writer, report))
    }

    /// Appends `r` as the next entry and returns its sequence number. The
    /// entry is durable when this returns: written and flushed with
    /// `F_FULLFSYNC` on macOS, `fsync` on Linux.
    ///
    /// # Errors
    /// Nothing was acknowledged: the segment is as it was (a failed write
    /// is cut back off), the head has not moved, and the next append tries
    /// the same sequence number again.
    pub fn append(&mut self, r: &AuditRecord) -> Result<u64, AuditError> {
        let seq = self.next_seq;
        let next = seq.checked_add(1).ok_or(AuditErrorKind::Full)?;
        let sealed = self.keys.seal(seq, r)?;
        let mac = self.keys.chain(&self.head_mac, seq, &sealed);
        let frame = encode_frame(seq, &sealed, &mac);
        let (mut cur, before) = self.segment()?;
        let written = self
            .io
            .write(&cur.file, &frame)
            .map_err(AuditError::from)
            .and_then(|()| {
                self.io
                    .sync(&cur.file)
                    .map_err(|_| AuditErrorKind::Sync.into())
            })
            .and_then(|()| {
                // The segment was moved out of the log while the entry was
                // written: the entry is not where the check reads.
                if in_log(&self.dir, &cur) {
                    Ok(())
                } else {
                    Err(io::Error::from(io::ErrorKind::NotFound).into())
                }
            });
        match written {
            Ok(()) => {
                self.current = Some(cur);
                self.next_seq = next;
                self.head_mac = mac;
                Ok(seq)
            }
            Err(e) => {
                // Cut the frame back off. If that fails too, the segment
                // may end in a frame nobody acknowledged: the next append
                // starts a new segment.
                let undone = cur
                    .file
                    .set_len(before)
                    .is_ok_and(|()| self.io.sync(&cur.file).is_ok());
                cur.broken = !undone;
                self.current = Some(cur);
                Err(e)
            }
        }
    }

    /// The head: the last entry's sequence number and chain value, or
    /// (0, genesis) for an empty log.
    pub fn head(&self) -> (u64, [u8; 32]) {
        (self.next_seq - 1, self.head_mac)
    }

    /// The head as the vault's header stores it.
    pub fn head_record(&self) -> AuditHead {
        let (seq, mac) = self.head();
        AuditHead { seq, mac }
    }

    /// The segment to append to, and its length now: the current one,
    /// unless it is full, broken or no longer in the log (removed or
    /// renamed by another program, or the directory itself moved: entries
    /// written to it would not be where the check reads), else a new one
    /// in the log's directory, which leaves the gap for the check to see.
    fn segment(&mut self) -> Result<(Current, u64), AuditError> {
        if let Some(cur) = self.current.take() {
            if let Ok(m) = cur.file.metadata() {
                if !cur.broken && m.len() < self.max_segment && in_log(&self.dir, &cur) {
                    if let Err(e) = self.sync_parent() {
                        self.current = Some(cur);
                        return Err(e);
                    }
                    return Ok((cur, m.len()));
                }
            }
        }
        Ok((self.new_segment()?, HEADER_LEN as u64))
    }

    /// Flushes the directory that names the log's directory, unless this
    /// writer already has for the directory there now (read each time,
    /// never trusted from before: it may have been moved away and made
    /// anew): the entry naming the log's directory is durable before any
    /// entry this writer appends is acknowledged. A failure fails the
    /// append, and the next one tries again.
    fn sync_parent(&mut self) -> Result<(), AuditError> {
        let m = std::fs::symlink_metadata(&self.dir)?;
        let now = (m.dev(), m.ino());
        if self.parent_synced != Some(now) {
            let parent = match self.dir.parent() {
                Some(p) if !p.as_os_str().is_empty() => p,
                _ => Path::new("."),
            };
            let parent = File::open(parent)?;
            self.io
                .sync(&parent)
                .map_err(|_| AuditError::from(AuditErrorKind::Sync))?;
            self.parent_synced = Some(now);
        }
        Ok(())
    }

    fn new_segment(&mut self) -> Result<Current, AuditError> {
        ensure_dir(&self.dir)?;
        // Before any segment is made in the directory.
        self.sync_parent()?;
        let path = self.dir.join(segment_name(self.next_seq));
        let file = OpenOptions::new()
            .append(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        let header = self.keys.header(self.next_seq, &self.head_mac);
        let made = self
            .io
            .write(&file, &header)
            .map_err(AuditError::from)
            .and_then(|()| {
                let dir = File::open(&self.dir)?;
                self.io
                    .sync(&file)
                    .and_then(|()| self.io.sync(&dir))
                    .map_err(|_| AuditErrorKind::Sync.into())
            });
        if let Err(e) = made {
            let _ = std::fs::remove_file(&path);
            return Err(e);
        }
        Ok(Current {
            file,
            path,
            broken: false,
        })
    }
}

/// Whether `cur` is still in the log: `dir` is still this user's private
/// directory (not a symlink), and the segment's name in it is not a symlink
/// and is the file the writer has open (same device and inode). A link
/// count above zero is not enough: a segment renamed out of the directory,
/// or a directory renamed away, keeps it.
fn in_log(dir: &Path, cur: &Current) -> bool {
    let Ok(open) = cur.file.metadata() else {
        return false;
    };
    check_private_dir(dir).is_ok()
        && std::fs::symlink_metadata(&cur.path)
            .is_ok_and(|m| m.is_file() && m.dev() == open.dev() && m.ino() == open.ino())
}

fn open_append(path: &Path) -> Result<File, AuditError> {
    check_private_file(path)?;
    Ok(OpenOptions::new()
        .append(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?)
}

/// Whether `dir` holds segments and every one of them names another vault
/// in its header. A segment that cannot be read, or is not a segment,
/// does not count: that is damage, which the check reports.
fn other_vaults_log(dir: &Path, ours: &VaultId) -> Result<bool, AuditError> {
    let segs = list_segments(dir)?;
    Ok(!segs.is_empty()
        && segs.iter().all(|(_, p)| {
            let mut b = [0u8; 25];
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(p)
                .and_then(|mut f| f.read_exact(&mut b))
                .is_ok_and(|()| b[..8] == MAGIC && b[9..25] != ours.0)
        }))
}

/// Renames the log's directory to `audit.replaced-<UTC time>` beside it
/// (`-1`, `-2` and so on when that is taken) and syncs the parent.
fn move_aside(dir: &Path) -> Result<(), AuditError> {
    let parent = dir.parent().ok_or(AuditErrorKind::Unsafe)?;
    let stamp = utc_stamp(now_secs());
    for n in 0..1000u32 {
        let name = if n == 0 {
            format!("audit.replaced-{stamp}")
        } else {
            format!("audit.replaced-{stamp}-{n}")
        };
        let to = parent.join(name);
        if std::fs::symlink_metadata(&to).is_ok() {
            continue;
        }
        std::fs::rename(dir, &to)?;
        envcloak_sys::sync_file(&File::open(parent)?)?;
        return Ok(());
    }
    Err(std::io::Error::from(io::ErrorKind::AlreadyExists).into())
}

fn segment_exists(dir: &Path, first_seq: u64) -> bool {
    std::fs::symlink_metadata(dir.join(segment_name(first_seq))).is_ok()
}

/// Creates the log's directory 0700 when it is missing, then checks it.
fn ensure_dir(dir: &Path) -> Result<(), AuditError> {
    match DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    check_private_dir(dir)?;
    Ok(())
}
