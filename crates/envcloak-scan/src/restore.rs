//! Writing an env file's bytes (SPEC §6.4): back from its encrypted backup
//! (`envcloak init --undo` restores the original byte for byte), and with
//! the entries the vault holds taken out (`envcloak init
//! --delete-plaintext`).
//!
//! The one place this crate writes a secret:
//! - [`restore_file`] creates the file as [`crate::create_atomically`] does
//!   (a new file beside it, flushed, linked into place only if the name is
//!   free), from the bytes the daemon handed back after a proof. It never
//!   replaces a file: one that exists stays as it is.
//! - [`restore_over`] puts the original back over the file a deletion
//!   rewrote, as [`crate::replace_atomically`] replaces one, only while it
//!   is still the file read (the caller checked it is that rewrite,
//!   [`crate::trimmed_from`]).
//! - [`rewrite_observed`] rewrites a file under the rules of a removal
//!   ([`crate::rewrite_checked`]) to hold what the vault does not.
//! - [`restore_over_left`] puts a file's contents back from a backup v2
//!   over the file a change left (SPEC §6.4, R-M2-73: "only while it is
//!   what the change left"), a chunk at a time, as
//!   [`crate::replace_atomically`] replaces one: only while that file's
//!   SHA-256 is the one the daemon recorded after the change
//!   (`backup.v2.record_result`), and only while it is still the file
//!   that was hashed when the new one takes its name; and only when the
//!   contents the chunks make up have the backed-up SHA-256. `scrub
//!   --undo`, `agents migrate-mcp --undo` and `init --undo` write back
//!   through it.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use envcloak_core::SecretBytes;
use envcloak_core::file_backup_v2::{MAX_FILE_V2, chunk_len, chunks_of};
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use std::time::SystemTime;

use crate::atomic::{
    Inside, ModifyError, ModifyErrorKind, create_atomically, io, replace_atomically,
    replace_in_with, rewrite_checked_observed,
};
use crate::root::{FileStamp, ScanRoot, open_file};

/// Creates the file at `rel` under `r` with `content` and `mode`, only if
/// no file has that name. Returns the new file's stamp.
///
/// # Errors
/// As [`create_atomically`]: [`crate::ModifyErrorKind::Exists`] when the
/// name is taken, a symlink in its place included.
pub fn restore_file(
    r: &ScanRoot,
    rel: &Path,
    content: &SecretBytes,
    mode: u32,
) -> Result<FileStamp, ModifyError> {
    #[allow(clippy::disallowed_methods)] // Writes the file back, as the person asked, with a proof.
    let bytes = content.expose_secret();
    create_atomically(r, rel, bytes, mode)
}

/// Replaces the file at `rel` under `r`, which must still be the one
/// `expect` stamps, with `content`, keeping its mode. Returns the new
/// file's stamp.
///
/// # Errors
/// As [`replace_atomically`].
pub fn restore_over(
    r: &ScanRoot,
    rel: &Path,
    content: &SecretBytes,
    expect: &FileStamp,
) -> Result<FileStamp, ModifyError> {
    #[allow(clippy::disallowed_methods)] // Writes the file back, as the person asked, with a proof.
    let bytes = content.expose_secret();
    replace_atomically(r, rel, bytes, expect)
}

/// Rewrites the file at `rel` under `r` to `content`, at the time `now`,
/// under the rules of a removal, telling `observe` when the new contents
/// are staged. Returns the new file's stamp.
///
/// # Errors
/// As [`crate::rewrite_checked`].
pub fn rewrite_observed(
    r: &ScanRoot,
    rel: &Path,
    content: &SecretBytes,
    expect: &FileStamp,
    now: SystemTime,
    observe: &mut dyn FnMut(Inside),
) -> Result<FileStamp, ModifyError> {
    #[allow(clippy::disallowed_methods)]
    // What the file keeps: the entries the vault does not hold.
    let bytes = content.expose_secret();
    rewrite_checked_observed(r, rel, bytes, expect, now, observe)
}

/// One file of a backup v2, as its restore statement names it
/// (`backup.v2.open_restore`): what [`restore_over_left`] checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackedUpFile {
    /// The size of the contents backed up.
    pub size: u64,
    /// Their SHA-256.
    pub sha256: [u8; 32],
    /// The SHA-256 of what the change left in the file, as the daemon
    /// recorded it (`sha256_after`).
    pub sha256_after: [u8; 32],
}

/// Puts the contents `file` describes back over the file at `rel` under
/// `r`, only while that file is what the change left: its SHA-256 is
/// `file.sha256_after` (else [`ModifyErrorKind::EditedSince`], and the
/// file stays as it is). `chunk(c)` gives chunk `c` of the contents (a
/// lease's `backup.v2.read`); the new file is written beside the old one a
/// chunk at a time, and takes its name only when the chunks came whole,
/// each at its length, and make up `file.sha256`
/// ([`ModifyErrorKind::BackupUnread`] otherwise, and nothing is written in
/// its place), and only while the file there is still the one hashed, as
/// [`crate::replace_atomically`] checks: a save meanwhile is kept
/// ([`ModifyErrorKind::Changed`]). The file keeps its mode. A file with
/// another hard link is never written over. Returns the new file's stamp.
///
/// # Errors
/// As above, and as [`crate::replace_atomically`].
pub fn restore_over_left(
    r: &ScanRoot,
    rel: &Path,
    file: &BackedUpFile,
    chunk: &mut dyn FnMut(u64) -> Option<SecretBytes>,
) -> Result<FileStamp, ModifyError> {
    restore_over_left_observed(r, rel, file, chunk, &mut |_| {})
}

/// [`restore_over_left`], telling `observe` when the file was hashed and
/// when the new contents are staged, checked and swapped in.
///
/// # Errors
/// As [`restore_over_left`].
pub fn restore_over_left_observed(
    r: &ScanRoot,
    rel: &Path,
    file: &BackedUpFile,
    chunk: &mut dyn FnMut(u64) -> Option<SecretBytes>,
    observe: &mut dyn FnMut(Inside),
) -> Result<FileStamp, ModifyError> {
    let fail = |kind| ModifyError {
        rel: rel.to_path_buf(),
        kind,
    };
    if file.size > MAX_FILE_V2 {
        return Err(fail(ModifyErrorKind::BackupUnread));
    }
    let (dir, name) = r
        .open_parent(rel)
        .map_err(|k| fail(ModifyErrorKind::Scan(k)))?;
    let (mut f, m) =
        open_file(&dir, &name, usize::MAX).map_err(|k| fail(ModifyErrorKind::Scan(k)))?;
    let stamp = FileStamp::of(&m);
    if stamp.nlink > 1 {
        return Err(fail(ModifyErrorKind::HardLinked));
    }
    let now = digest_of(&mut f, &stamp).map_err(fail)?;
    drop(f);
    if now != file.sha256_after {
        return Err(fail(ModifyErrorKind::EditedSince));
    }
    observe(Inside::Hashed);
    // The file must still be the one hashed when its replacement takes
    // its name: the stamp is the one it had before it was read.
    let mut fill = |out: &mut File| write_chunks(out, file, chunk);
    replace_in_with(&dir, rel, &name, &mut fill, &stamp, observe)
}

/// The SHA-256 of `f`, which must hold exactly the bytes `stamp` says and
/// still have that stamp once read (else [`ModifyErrorKind::Changed`]).
/// The bytes pass through a buffer wiped after.
fn digest_of(f: &mut File, stamp: &FileStamp) -> Result<[u8; 32], ModifyErrorKind> {
    let size = stamp.size;
    let mut buf = Zeroizing::new(vec![0u8; 64 * 1024]);
    let mut h = Sha256::new();
    let mut read: u64 = 0;
    loop {
        let n = f.read(&mut buf[..]).map_err(|e| io(&e))?;
        if n == 0 {
            break;
        }
        read += n as u64;
        if read > size {
            return Err(ModifyErrorKind::Changed);
        }
        h.update(&buf[..n]);
    }
    let after = f.metadata().map_err(|e| io(&e))?;
    if read != size || FileStamp::of(&after) != *stamp {
        return Err(ModifyErrorKind::Changed);
    }
    Ok(h.finalize().into())
}

/// Writes the chunks of `file` to `out`, in order, each at its length,
/// and checks that they make up `file.sha256`.
fn write_chunks(
    out: &mut File,
    file: &BackedUpFile,
    chunk: &mut dyn FnMut(u64) -> Option<SecretBytes>,
) -> Result<(), ModifyErrorKind> {
    let mut h = Sha256::new();
    for c in 0..chunks_of(file.size) {
        let want = chunk_len(file.size, c).ok_or(ModifyErrorKind::BackupUnread)?;
        let bytes = chunk(c).ok_or(ModifyErrorKind::BackupUnread)?;
        if bytes.len() != want {
            return Err(ModifyErrorKind::BackupUnread);
        }
        #[allow(clippy::disallowed_methods)]
        // Writes the file back, as the person asked, with a proof.
        let raw = bytes.expose_secret();
        out.write_all(raw).map_err(|e| io(&e))?;
        h.update(raw);
    }
    let whole: [u8; 32] = h.finalize().into();
    if whole != file.sha256 {
        return Err(ModifyErrorKind::BackupUnread);
    }
    Ok(())
}
