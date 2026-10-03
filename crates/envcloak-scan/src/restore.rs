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
//!   rewrote, only while that file is exactly what the deletion left, by
//!   the SHA-256 the backup recorded of it (F-78), checked as
//!   [`restore_over_left`] checks a backup v2's: hashed whole through the
//!   descriptor its stamp was read from, still that file holding those
//!   bytes when the original takes its name, and what the swap brought
//!   out read again whole; a file system that cannot swap two names
//!   writes nothing.
//! - [`rewrite_observed`] rewrites a file under the rules of a removal
//!   ([`crate::rewrite_checked`]) to hold what the vault does not.
//! - [`restore_over_left`] puts a file's contents back from a backup v2
//!   over the file a change left (SPEC §6.4, R-M2-73: "only while it is
//!   what the change left"), a chunk at a time, as
//!   [`crate::replace_atomically`] replaces one: only while that file's
//!   SHA-256 is the one the daemon recorded after the change
//!   (`backup.v2.record_result`), and only while it is still the file
//!   that was hashed, with those contents, when the new one takes its
//!   name; only when the contents the chunks make up have the backed-up
//!   SHA-256; and only while the new file holds exactly the bytes written
//!   to it. It is the write-back the backup v2 undo commands of M2-16,
//!   M2-20 and M2-22 are to call (docs/IPC.md "Backups v2", "Writing
//!   back"); `init --undo` restores its v1 backups through
//!   [`restore_over`], which shares its checks.

use std::io::Write;
use std::path::Path;

use envcloak_core::SecretBytes;
use envcloak_core::file_backup_v2::{MAX_FILE_V2, chunk_len, chunks_of};
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};

use std::time::SystemTime;

use crate::atomic::{
    Fill, Inside, ModifyError, ModifyErrorKind, Swap, create_atomically, digest_of, io,
    replace_in_using, rewrite_checked_observed,
};
use crate::root::{FileStamp, ScanRoot, open_file};
use envcloak_sys::exchange_beneath;

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

/// Puts `content`, a file's original from its backup, back over the file
/// at `rel` under `r`, only while that file is exactly what the deletion
/// left: its SHA-256 is `left`, the one the backup recorded of the
/// rewrite (else [`ModifyErrorKind::EditedSince`], and the file stays as
/// it is), F-78. It is checked as [`restore_over_left`] checks a backup
/// v2's file, with every guarantee written there: hashed whole through
/// the descriptor its stamp was read from, its stamp (the change time
/// included) unchanged by the read; still that file, with that stamp,
/// when the original takes its name, a save meanwhile kept
/// ([`ModifyErrorKind::Changed`]); and what the swap of the two names
/// brought out read again whole, the names swapped back unless it still
/// has `left` (an edit made in place after the last check, at the same
/// length with its modification time put back, is kept: `changed`). A
/// file system that cannot swap two names writes nothing
/// ([`ModifyErrorKind::SwapUnsupported`]), never renaming over a file it
/// could not check. The file keeps its mode; one with another hard link
/// is never written over. Returns the new file's stamp.
///
/// # Errors
/// As above, and as [`restore_over_left`].
pub fn restore_over(
    r: &ScanRoot,
    rel: &Path,
    content: &SecretBytes,
    left: &[u8; 32],
) -> Result<FileStamp, ModifyError> {
    restore_over_observed(r, rel, content, left, &mut |_| {})
}

/// [`restore_over`], telling `observe` what [`restore_over_left_observed`]
/// tells.
///
/// # Errors
/// As [`restore_over`].
pub fn restore_over_observed(
    r: &ScanRoot,
    rel: &Path,
    content: &SecretBytes,
    left: &[u8; 32],
    observe: &mut dyn FnMut(Inside),
) -> Result<FileStamp, ModifyError> {
    over_left(exchange_beneath, r, rel, content, left, observe)
}

/// [`restore_over_observed`], swapping names with `swap`.
fn over_left(
    swap: Swap,
    r: &ScanRoot,
    rel: &Path,
    content: &SecretBytes,
    left: &[u8; 32],
    observe: &mut dyn FnMut(Inside),
) -> Result<FileStamp, ModifyError> {
    let mut fill = |out: &mut dyn Write| {
        #[allow(clippy::disallowed_methods)]
        // Writes the file back, as the person asked, with a proof.
        let bytes = content.expose_secret();
        out.write_all(bytes).map_err(|e| io(&e))
    };
    replace_if_left(swap, r, rel, left, &mut fill, observe)
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
/// ([`ModifyErrorKind::Changed`]). The new file must hold exactly the
/// bytes written to it (their length and SHA-256, read back whole through
/// the descriptor it was written through, its stamp unchanged meanwhile)
/// before the swap and again once it has the file's name: a new file
/// written into in place, or another file put under its name, is never
/// left in the file's place nor answered as restored; it is kept, and
/// named ([`ModifyErrorKind::MovedAside`]). The two names are swapped in
/// one step, and what came out is read again whole: unless it still has
/// `file.sha256_after`, and what went in is the new file holding what was
/// written, the names are swapped back and the file is kept (`changed`,
/// or `moved_aside` naming where the other file is kept), so an edit made
/// in place after the last check, at the same length with its
/// modification time put back, is never deleted. Once the new file has
/// the file's name, the old file goes only while it is still the one
/// checked, moved to a fresh name and checked there first: a file another
/// program changed or put under its temporary name meanwhile is kept and
/// named for what it is ([`ModifyErrorKind::AsideChanged`]), never called
/// the old copy; one that cannot be removed is named
/// ([`ModifyErrorKind::NotRemoved`]); one another program moved or
/// removed from there is not named, and the file is answered as written
/// back. A file system that cannot swap names writes nothing
/// ([`ModifyErrorKind::SwapUnsupported`]). A write by a program that still
/// has the old file open, after that read, is not seen. The file keeps its
/// mode. A file with another hard link is never written over. Returns the
/// new file's stamp.
///
/// The new file is the write itself (SPEC §6.5 "Modifying a file",
/// R-M2-44: a new file in the same directory, `O_EXCL`, 0600 until it is
/// whole, flushed, then put in place): it holds only the bytes the person
/// asked to have written back at `rel`, never anywhere else. While it is
/// written it is under `.<name>.envcloak-new-<hex>.tmp` (0600); once
/// whole, it is moved, in one step that replaces nothing, to
/// `.<name>.envcloak-swap-<hex>.tmp`, which the swap takes it from and
/// leaves what came out under. A process killed while it writes leaves the
/// file at `rel` as it was, or the restored one, and may leave the new
/// file so far beside it under its `new` name, which nothing reads. Every
/// later restore of the same file that gets the contents whole beside it,
/// whether or not it then takes the file's place, removes each file of
/// that file's `new` names holding nothing but those contents' first
/// bytes (a regular file with one link, compared byte for byte), so
/// nothing is lost with it. A `new` name only ever holds a new file while
/// it is written; whatever a swap brings out (another program's save that
/// could not be put back, which [`ModifyErrorKind::MovedAside`] names, or
/// the file a restore stopped after its swap took out) is under a `swap`
/// name, which no restore removes, whatever it holds, since nothing shows
/// where it came from. So is the whole new file of a restore killed
/// between that move and the swap. A file it removes is first moved aside
/// to a fresh name of the same shape and checked there again, and only
/// that file is unlinked, while that name still holds it unchanged: a file
/// that takes the old name meanwhile keeps it, and one changed or replaced
/// while it is checked is put back (or, when its name was taken
/// meanwhile, kept under the fresh name). A restore that stops earlier
/// (`edited_since`, `backup_unread`) removes nothing. A restore of the
/// same file running in another process at that moment may then fail, and
/// reports it.
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

/// [`restore_over_left`], telling `observe` when the file is open and
/// about to be hashed, when it was hashed, when an earlier restore's
/// leftover is moved aside, when its bytes were compared there and when
/// one that failed is put back, and when the new contents are staged,
/// checked and swapped in.
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
    let mut fill = |out: &mut dyn Write| write_chunks(out, file, chunk);
    replace_if_left(
        exchange_beneath,
        r,
        rel,
        &file.sha256_after,
        &mut fill,
        observe,
    )
}

/// Replaces the file at `rel` under `r` with what `fill` writes, only
/// while it is what a change left (its SHA-256 is `left`), as
/// [`restore_over_left`] says, swapping names with `swap`: the one
/// write-back of [`restore_over_left`] and [`restore_over`].
fn replace_if_left(
    swap: Swap,
    r: &ScanRoot,
    rel: &Path,
    left: &[u8; 32],
    fill: Fill<'_>,
    observe: &mut dyn FnMut(Inside),
) -> Result<FileStamp, ModifyError> {
    let fail = |kind| ModifyError {
        rel: rel.to_path_buf(),
        kind,
    };
    let (dir, name) = r
        .open_parent(rel)
        .map_err(|k| fail(ModifyErrorKind::Scan(k)))?;
    let (mut f, m) =
        open_file(&dir, &name, usize::MAX).map_err(|k| fail(ModifyErrorKind::Scan(k)))?;
    let stamp = FileStamp::of(&m);
    if stamp.nlink > 1 {
        return Err(fail(ModifyErrorKind::HardLinked));
    }
    observe(Inside::Opened);
    let now = digest_of(&mut f, &stamp, &dir).map_err(fail)?;
    drop(f);
    if now != *left {
        return Err(fail(ModifyErrorKind::EditedSince));
    }
    observe(Inside::Hashed);
    // The file must still be the one hashed when its replacement takes
    // its name: the stamp is the one it had before it was read, and what
    // comes out of the swap must still hold what the change left.
    replace_in_using(swap, &dir, rel, &name, fill, &stamp, Some(left), observe)
}

/// Writes the chunks of `file` to `out`, in order, each at its length,
/// and checks that they make up `file.sha256`.
fn write_chunks(
    out: &mut dyn Write,
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::ffi::OsStr;
    use std::fs::File;

    /// A file system that cannot swap two names in one step.
    fn cannot_swap(_: &File, _: &OsStr, _: &OsStr) -> std::io::Result<()> {
        Err(std::io::ErrorKind::Unsupported.into())
    }

    /// F-78 (Codex's review): `init --undo`'s write-back, where two names
    /// cannot be swapped in one step, writes nothing (`swap_unsupported`):
    /// the file the deletion left stays as it is and no temporary file is
    /// left, since a rename over it could replace an edit made after the
    /// last check. Where they can, the same call writes the original back.
    ///
    /// Mutation: `restore_over` without the contents the file must still
    /// hold (the old `replace_atomically` path, which falls back to a
    /// rename): the file is replaced.
    #[test]
    fn an_undo_writes_nothing_where_names_cannot_be_swapped() {
        let d = tempfile::tempdir_in("/tmp").unwrap();
        let p = d.path().join(".env");
        let left: &[u8] = b"PORT=8080\n";
        std::fs::write(&p, left).unwrap();
        let r = crate::open_root(d.path()).unwrap();
        let original = SecretBytes::copy_from(b"TOKEN=from the backup\nPORT=8080\n");
        let sha: [u8; 32] = Sha256::digest(left).into();
        let e = over_left(
            cannot_swap,
            &r,
            Path::new(".env"),
            &original,
            &sha,
            &mut |_| {},
        )
        .unwrap_err();
        assert_eq!(e.kind, ModifyErrorKind::SwapUnsupported);
        assert_eq!(std::fs::read(&p).unwrap(), left, "written over");
        let names: Vec<_> = std::fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, [OsStr::new(".env")]);
        restore_over(&r, Path::new(".env"), &original, &sha).unwrap();
        assert!(original.ct_eq(&std::fs::read(&p).unwrap()));
    }
}
