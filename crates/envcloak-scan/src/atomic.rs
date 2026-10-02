//! Changing files under a [`ScanRoot`] (SPEC §6.4: `envcloak init` writes
//! `envcloak.toml` and `.gitignore` and removes plaintext env files).
//!
//! Each function takes the [`FileStamp`] the caller read the file with, or
//! creates a file that does not exist, and refuses when the file on disk
//! is not that one any more: nothing another program wrote meanwhile is
//! overwritten or removed. None follows a symlink, and none modifies or
//! removes a file with another hard link (SPEC §6.4: reported, never
//! modified), since the other name would keep the old contents.
//!
//! - [`replace_atomically`] writes the new contents to a new file beside
//!   the old one (`O_EXCL`, the old file's mode), flushes it, checks the
//!   old file again, swaps the two names in one step and checks that what
//!   came out is the file checked (swapping back when another program
//!   saved over the name meanwhile), then removes it and flushes the
//!   directory. A crash leaves the old file or the new one, never part of
//!   either; a leftover temporary file is never read by anyone. On a file
//!   system that cannot swap names (macOS HFS+, some network and FUSE
//!   ones), the new file is renamed over the old one right after the
//!   check, and a save landing between the two is replaced.
//! - [`create_atomically`] writes a new file the same way and links it
//!   into place only if the name is still free.
//! - [`remove_checked`] removes a file only when it is unchanged since it
//!   was read, not modified within [`MIN_AGE`], and not open in another
//!   process as far as the system can tell
//!   ([`envcloak_sys::open_elsewhere`], asked about the open file itself);
//!   a file found open is kept, and the whole stamp, change time
//!   included, is checked again after that question, right before the
//!   file moves. It first moves the file aside, checks that what moved is
//!   the file it checked, and only then unlinks it: a file saved over the
//!   name meanwhile (an editor's atomic save) is put back, never removed.
//! - [`rewrite_checked`] replaces a file as [`replace_atomically`] does,
//!   under [`remove_checked`]'s rules: `envcloak init --delete-plaintext`
//!   rewrites an env file to hold only the entries it did not import.
//!
//! A crash between the steps leaves the file, or its replacement, under a
//! temporary name `.<name>.envcloak-<new|del>-<hex>.tmp` ([`temp_name`]),
//! which a scan reports ([`ScanErrorKind::Leftover`]) and `envcloak init`
//! makes sure its project's `.gitignore` ignores.
//!
//! No temporary copy holds anything the caller did not write, and nothing
//! here writes a backup: plaintext is never copied (SPEC §6.4 "Backups").

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use envcloak_sys::{
    DirEntryKind, InUse, MAX_DIR_ENTRIES, create_beneath, exchange_beneath, kind_beneath,
    link_beneath, list_dir, open_elsewhere, rename_beneath, sync_file, unlink_beneath,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::root::{FileStamp, ScanErrorKind, ScanRoot, io_kind, open_file};

/// A file modified more recently than this is not removed: someone may be
/// editing it.
pub const MIN_AGE: Duration = Duration::from_secs(120);

/// Why a file was not changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ModifyErrorKind {
    /// Not the file that was read any more.
    Changed,
    /// It has another hard link.
    HardLinked,
    /// Modified within [`MIN_AGE`], or its time is in the future.
    RecentlyChanged,
    /// Another process has it open.
    OpenElsewhere,
    /// Whether another process has it open could not be asked about this
    /// file: its path names another file now ([`InUse::Unmatched`]).
    Unchecked,
    /// A file to create exists already.
    Exists,
    /// It could not be opened or checked, for this reason.
    Scan(ScanErrorKind),
    /// The file was moved aside and something else took its name before
    /// it could be put back: it was left under the name in
    /// [`ModifyError::rel`], and nothing was removed.
    MovedAside,
    /// The change was made (the new contents have the file's name, or the
    /// name is free), but the old file could not be unlinked: it is left
    /// under the temporary name in [`ModifyError::rel`].
    NotRemoved,
    /// A restore from a backup v2 found the file is not what the change
    /// the backup was made for left in it: its SHA-256 is not the one the
    /// daemon recorded ([`crate::restore_over_left`]).
    EditedSince,
    /// A restore from a backup v2 could not have the backed-up contents
    /// whole: a chunk did not come, had another length, or the whole did
    /// not have the backed-up SHA-256. Nothing was written in the file's
    /// place.
    BackupUnread,
    /// A restore from a backup v2 found a file system that cannot swap
    /// two names in one step: the file it writes over could not be
    /// checked once it moved out, so nothing was written in its place.
    SwapUnsupported,
}

impl ModifyErrorKind {
    /// A stable token for reports.
    pub fn token(self) -> &'static str {
        match self {
            ModifyErrorKind::Changed => "changed",
            ModifyErrorKind::HardLinked => "hard_linked",
            ModifyErrorKind::RecentlyChanged => "recently_changed",
            ModifyErrorKind::OpenElsewhere => "open_elsewhere",
            ModifyErrorKind::Unchecked => "unchecked",
            ModifyErrorKind::Exists => "exists",
            ModifyErrorKind::Scan(k) => k.token(),
            ModifyErrorKind::MovedAside => "moved_aside",
            ModifyErrorKind::NotRemoved => "not_removed",
            ModifyErrorKind::EditedSince => "edited_since",
            ModifyErrorKind::BackupUnread => "backup_unread",
            ModifyErrorKind::SwapUnsupported => "swap_unsupported",
        }
    }

    /// The fixed message.
    pub fn message(self) -> &'static str {
        match self {
            ModifyErrorKind::Changed => "it changed since it was read",
            ModifyErrorKind::HardLinked => {
                "it has another hard link, which would keep its contents, so it is never modified"
            }
            ModifyErrorKind::RecentlyChanged => {
                "it was modified in the last 2 minutes, so it may be in use"
            }
            ModifyErrorKind::OpenElsewhere => "another program has it open",
            ModifyErrorKind::Unchecked => {
                "whether another program has it open could not be checked (its path names \
                 another file now), so it was kept"
            }
            ModifyErrorKind::Exists => "a file of that name exists already",
            ModifyErrorKind::Scan(k) => k.message(),
            ModifyErrorKind::MovedAside => {
                "it was saved over while it was being removed; the checked file was kept under \
                 the name shown, and nothing was removed"
            }
            ModifyErrorKind::NotRemoved => {
                "the change was made, but the old file could not be removed and is left under \
                 the name shown: look at it, then delete it"
            }
            ModifyErrorKind::EditedSince => {
                "it changed after the change its backup was made for, so it was kept as it is"
            }
            ModifyErrorKind::BackupUnread => {
                "the backup's contents could not be read whole, so nothing was written"
            }
            ModifyErrorKind::SwapUnsupported => {
                "this file system cannot swap two names in one step, so the file could not be \
                 checked as it was replaced, and nothing was written"
            }
        }
    }
}

/// A path under the root, and why it was not changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModifyError {
    /// Relative to the root.
    pub rel: PathBuf,
    pub kind: ModifyErrorKind,
}

impl core::fmt::Display for ModifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {}", self.rel.display(), self.kind.message())
    }
}

impl std::error::Error for ModifyError {}

/// A new name beside `name`: `.<name>.envcloak-<what>-<hex>.tmp`, from a randomly
/// keyed hash of the time and this process. Not secret; a clash only makes
/// `O_EXCL` fail. Names too long for one leave the name out.
fn temp_name(name: &OsStr, what: &str) -> OsString {
    use std::hash::{BuildHasher, RandomState};
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let h = RandomState::new().hash_one((nanos, std::process::id()));
    let mut t = OsString::from(".");
    if name.as_bytes().len() <= 128 {
        t.push(name);
    }
    t.push(format!(".envcloak-{what}-{h:016x}.tmp"));
    t
}

/// Removes from `dir` the files a write of `name` left under its
/// temporary names (`.<name>.envcloak-<what>-<16 hex>.tmp`, [`temp_name`])
/// when it was stopped before it ended: regular files only, each by its
/// name, a symlink of such a name never followed. A name too long to be
/// carried in one ([`temp_name`] leaves it out) says nothing of whose it
/// is, so nothing is removed then. Best effort: returns how many went,
/// and flushes `dir` when any did. Nothing is read from them.
pub(crate) fn remove_leftovers(dir: &File, name: &OsStr, what: &str) -> usize {
    if name.as_bytes().len() > 128 {
        return 0;
    }
    let mut prefix = b".".to_vec();
    prefix.extend_from_slice(name.as_bytes());
    prefix.extend_from_slice(format!(".envcloak-{what}-").as_bytes());
    let Ok(entries) = list_dir(dir, MAX_DIR_ENTRIES) else {
        return 0;
    };
    let mut removed = 0;
    for e in entries {
        let ours = e
            .name
            .as_bytes()
            .strip_prefix(prefix.as_slice())
            .and_then(|rest| rest.strip_suffix(b".tmp"))
            .is_some_and(|h| {
                h.len() == 16
                    && h.iter()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
            });
        if ours
            && kind_beneath(dir, &e.name).is_ok_and(|k| k == DirEntryKind::File)
            && unlink_beneath(dir, &e.name).is_ok()
        {
            removed += 1;
        }
    }
    if removed > 0 {
        let _ = sync_file(dir);
    }
    removed
}

/// Writes `bytes` to a new file `temp` in `dir` with `mode`, flushed.
fn write_new(dir: &File, temp: &OsStr, bytes: &[u8], mode: u32) -> std::io::Result<File> {
    let mut f = create_beneath(dir, temp, 0o600)?;
    let written = f
        .write_all(bytes)
        .and_then(|()| f.set_permissions(std::fs::Permissions::from_mode(mode & 0o7777)))
        .and_then(|()| sync_file(&f).map(drop));
    if let Err(e) = written {
        let _ = unlink_beneath(dir, temp);
        return Err(e);
    }
    Ok(f)
}

/// What writes a new file's contents: called once with the new file, open
/// for writing and empty. A failure leaves no new file.
pub(crate) type Fill<'a> = &'a mut dyn FnMut(&mut File) -> Result<(), ModifyErrorKind>;

/// Writes what `fill` writes to a new file `temp` in `dir`, then gives it
/// `mode` and flushes it. On a failure the new file goes.
fn write_new_with(
    dir: &File,
    temp: &OsStr,
    mode: u32,
    fill: Fill<'_>,
) -> Result<File, ModifyErrorKind> {
    let mut f = create_beneath(dir, temp, 0o600).map_err(|e| io(&e))?;
    let written = fill(&mut f).and_then(|()| {
        f.set_permissions(std::fs::Permissions::from_mode(mode & 0o7777))
            .and_then(|()| sync_file(&f).map(drop))
            .map_err(|e| io(&e))
    });
    if let Err(k) = written {
        let _ = unlink_beneath(dir, temp);
        return Err(k);
    }
    Ok(f)
}

/// The file `name` in `dir` as it is now, checked to be the one `expect`
/// stamps, with no other hard link.
fn check_same(dir: &File, name: &OsStr, expect: &FileStamp) -> Result<File, ModifyErrorKind> {
    let (f, m) = open_file(dir, name, usize::MAX).map_err(|k| match k {
        ScanErrorKind::NotFound => ModifyErrorKind::Changed,
        k => ModifyErrorKind::Scan(k),
    })?;
    let now = FileStamp::of(&m);
    if now != *expect {
        return Err(ModifyErrorKind::Changed);
    }
    if now.nlink > 1 {
        return Err(ModifyErrorKind::HardLinked);
    }
    Ok(f)
}

pub(crate) fn io(e: &std::io::Error) -> ModifyErrorKind {
    ModifyErrorKind::Scan(io_kind(e))
}

/// Where [`remove_checked`] or [`rewrite_checked`] leaves a file under a
/// temporary name if the process ends there (gate 16's test stops it at
/// each), and where a test puts another program's save.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Inside {
    /// The file to remove was renamed aside, and is not unlinked yet.
    MovedAside,
    /// The new contents are written beside the file, and not in its place
    /// yet.
    Staged,
    /// The file was checked for the last time before the new contents take
    /// its name.
    Checked,
    /// The names are swapped: the new contents have the file's name, and
    /// what came out is under the temporary name, not checked yet.
    Exchanged,
    /// The names are swapped and what came out is the file checked (for a
    /// restore from a backup v2, with the contents the change left): the
    /// new contents have the file's name, and the old file is under the
    /// temporary name, not unlinked yet.
    Swapped,
    /// The file to write back over is open and its stamp read, and it is
    /// not read yet ([`crate::restore_over_left`]).
    Opened,
    /// The file to write back over was hashed and is what the change left
    /// ([`crate::restore_over_left`]); its replacement is not written yet.
    Hashed,
}

/// Whether `m` is the file `expect` stamps, as a rename leaves it: a
/// rename may update the change time, so the contents' identity is the
/// device, inode, size and modification time; and no other hard link.
fn is_checked(m: &std::fs::Metadata, expect: &FileStamp) -> bool {
    (m.dev(), m.ino(), m.size(), m.mtime(), m.mtime_nsec())
        == (
            expect.dev,
            expect.ino,
            expect.size,
            expect.mtime,
            expect.mtime_nsec,
        )
        && m.nlink() == 1
}

/// Writes `new` beside `name` in `dir`, checks the file there is still the
/// one `expect` stamps, and puts the new file in its place.
///
/// Where the file system can, the two names are swapped in one step
/// ([`exchange_beneath`]) and what came out is checked: when another
/// program saved over the name after the check (an editor's atomic save),
/// the names are swapped back, so its file is kept and nothing is
/// replaced (`changed`). Then the old file is unlinked; when it cannot be,
/// the change stands and the old file is named where it is left
/// (`not_removed`). Where the names cannot be swapped, the new file is
/// renamed over the name right after the check, and a save landing
/// between the two is replaced. `rel` is the file's path for errors.
fn replace_in(
    dir: &File,
    rel: &Path,
    name: &OsStr,
    new: &[u8],
    expect: &FileStamp,
    observe: &mut dyn FnMut(Inside),
) -> Result<FileStamp, ModifyError> {
    let mut fill = |f: &mut File| f.write_all(new).map_err(|e| io(&e));
    replace_in_with(dir, rel, name, &mut fill, expect, None, observe)
}

/// What swaps two names in a directory in one step: [`exchange_beneath`],
/// or a unit test's file system that cannot.
type Swap = fn(&File, &OsStr, &OsStr) -> std::io::Result<()>;

/// [`replace_in`], with the new contents written by `fill`, so they can
/// be written a part at a time; and, when `left` is given, only over a
/// file that still holds the contents of that SHA-256 when it moves out.
///
/// With `left`, the file that came out of the swap is read whole, its
/// stamp checked again after the read, and its SHA-256 compared with
/// `left`: an edit made in place after the last check (the same length,
/// its modification time put back, which the stamp alone does not tell)
/// swaps the names back and keeps the edit (`changed`). A file system
/// that cannot swap names then writes nothing (`swap_unsupported`), never
/// renaming over a file it could not check. What it cannot see is a write
/// to the old file, by a program that still has it open, after that read.
pub(crate) fn replace_in_with(
    dir: &File,
    rel: &Path,
    name: &OsStr,
    fill: Fill<'_>,
    expect: &FileStamp,
    left: Option<&[u8; 32]>,
    observe: &mut dyn FnMut(Inside),
) -> Result<FileStamp, ModifyError> {
    replace_in_using(
        exchange_beneath,
        dir,
        rel,
        name,
        fill,
        expect,
        left,
        observe,
    )
}

#[allow(clippy::too_many_arguments)] // replace_in_with's, and the swap.
fn replace_in_using(
    swap: Swap,
    dir: &File,
    rel: &Path,
    name: &OsStr,
    fill: Fill<'_>,
    expect: &FileStamp,
    left: Option<&[u8; 32]>,
    observe: &mut dyn FnMut(Inside),
) -> Result<FileStamp, ModifyError> {
    let fail = |kind| ModifyError {
        rel: rel.to_path_buf(),
        kind,
    };
    let temp = temp_name(name, "new");
    let f = write_new_with(dir, &temp, expect.mode, fill).map_err(fail)?;
    observe(Inside::Staged);
    // Another program may have written the file while this one wrote its
    // replacement: keep theirs.
    if let Err(k) = check_same(dir, name, expect) {
        let _ = unlink_beneath(dir, &temp);
        return Err(fail(k));
    }
    observe(Inside::Checked);
    match swap(dir, &temp, name) {
        Ok(()) => {
            observe(Inside::Exchanged);
            let checked = match open_file(dir, &temp, usize::MAX) {
                Ok((mut out, m)) if is_checked(&m, expect) => left.is_none_or(|want| {
                    digest_of(&mut out, &FileStamp::of(&m)).is_ok_and(|got| got == *want)
                }),
                _ => false,
            };
            if !checked {
                return Err(swap_back(swap, dir, rel, name, &temp, &f));
            }
            observe(Inside::Swapped);
            if unlink_beneath(dir, &temp).is_err() {
                let _ = sync_file(dir);
                return Err(ModifyError {
                    rel: rel.with_file_name(&temp),
                    kind: ModifyErrorKind::NotRemoved,
                });
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::Unsupported && left.is_some() => {
            let _ = unlink_beneath(dir, &temp);
            return Err(fail(ModifyErrorKind::SwapUnsupported));
        }
        Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
            if let Err(e) = rename_beneath(dir, &temp, name) {
                let _ = unlink_beneath(dir, &temp);
                return Err(fail(io(&e)));
            }
        }
        Err(e) => {
            let _ = unlink_beneath(dir, &temp);
            return Err(fail(io(&e)));
        }
    }
    sync_file(dir).map_err(|e| fail(io(&e)))?;
    let m = f.metadata().map_err(|e| fail(io(&e)))?;
    Ok(FileStamp::of(&m))
}

/// The SHA-256 of `f`, which must hold exactly the bytes `stamp` says and
/// still have that stamp once read, its change time included (else
/// [`ModifyErrorKind::Changed`]): a file written while it was hashed is
/// never taken for the one hashed. The bytes pass through a buffer wiped
/// after.
pub(crate) fn digest_of(f: &mut File, stamp: &FileStamp) -> Result<[u8; 32], ModifyErrorKind> {
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

/// After a swap brought out a file that is not the one checked: swaps the
/// names back, so `name` is that file again, and removes the new
/// contents, `staged`, from `temp`. Returns `changed`; or, when the names
/// could not be put back as they were, what is under `temp` is kept and
/// named (`moved_aside`), and nothing is removed.
fn swap_back(
    swap: Swap,
    dir: &File,
    rel: &Path,
    name: &OsStr,
    temp: &OsStr,
    staged: &File,
) -> ModifyError {
    let ours = staged.metadata().map(|m| (m.dev(), m.ino()));
    let back = swap(dir, temp, name).is_ok()
        && open_file(dir, temp, usize::MAX)
            .is_ok_and(|(_, m)| ours.as_ref().is_ok_and(|o| *o == (m.dev(), m.ino())));
    if back && unlink_beneath(dir, temp).is_ok() {
        let _ = sync_file(dir);
        return ModifyError {
            rel: rel.to_path_buf(),
            kind: ModifyErrorKind::Changed,
        };
    }
    let _ = sync_file(dir);
    ModifyError {
        rel: rel.with_file_name(temp),
        kind: ModifyErrorKind::MovedAside,
    }
}

/// Replaces the file at `rel`, which must still be the one `expect`
/// stamps, with `new`, keeping its mode. See the module documentation.
/// Returns the new file's stamp.
pub fn replace_atomically(
    r: &ScanRoot,
    rel: &Path,
    new: &[u8],
    expect: &FileStamp,
) -> Result<FileStamp, ModifyError> {
    let fail = |kind| ModifyError {
        rel: rel.to_path_buf(),
        kind,
    };
    let (dir, name) = r
        .open_parent(rel)
        .map_err(|k| fail(ModifyErrorKind::Scan(k)))?;
    drop(check_same(&dir, &name, expect).map_err(fail)?);
    replace_in(&dir, rel, &name, new, expect, &mut |_| {})
}

/// Creates the file at `rel` with `new` and `mode`, only if no file has
/// that name. See the module documentation. Returns the file's stamp.
pub fn create_atomically(
    r: &ScanRoot,
    rel: &Path,
    new: &[u8],
    mode: u32,
) -> Result<FileStamp, ModifyError> {
    let fail = |kind| ModifyError {
        rel: rel.to_path_buf(),
        kind,
    };
    let (dir, name) = r
        .open_parent(rel)
        .map_err(|k| fail(ModifyErrorKind::Scan(k)))?;
    let temp = temp_name(&name, "new");
    let f = write_new(&dir, &temp, new, mode).map_err(|e| fail(io(&e)))?;
    let linked = link_beneath(&dir, &temp, &name);
    let unlinked = unlink_beneath(&dir, &temp);
    match linked {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(fail(ModifyErrorKind::Exists));
        }
        Err(e) => return Err(fail(io(&e))),
    }
    unlinked.map_err(|e| fail(io(&e)))?;
    sync_file(&dir).map_err(|e| fail(io(&e)))?;
    let m = f.metadata().map_err(|e| fail(io(&e)))?;
    Ok(FileStamp::of(&m))
}

/// What must hold before plaintext is removed or rewritten: the file in
/// `dir` is still the one `expect` stamps, was not modified within
/// [`MIN_AGE`] of `now`, and is not open elsewhere; then the whole stamp
/// again, change time included, since another program may have written it
/// while that was asked.
fn check_removable(
    dir: &File,
    name: &OsStr,
    expect: &FileStamp,
    now: SystemTime,
) -> Result<(), ModifyErrorKind> {
    let f = check_same(dir, name, expect)?;
    if expect.age_at(now).is_none_or(|age| age < MIN_AGE.as_secs()) {
        return Err(ModifyErrorKind::RecentlyChanged);
    }
    match open_elsewhere(&f) {
        InUse::Yes => return Err(ModifyErrorKind::OpenElsewhere),
        InUse::Unmatched => return Err(ModifyErrorKind::Unchecked),
        InUse::No | InUse::Unknown => {}
    }
    drop(f);
    check_same(dir, name, expect).map(drop)
}

/// Removes the file at `rel` when it is still the one `expect` stamps, was
/// not modified within [`MIN_AGE`], and is not open elsewhere. See the
/// module documentation.
pub fn remove_checked(r: &ScanRoot, rel: &Path, expect: &FileStamp) -> Result<(), ModifyError> {
    remove_checked_at(r, rel, expect, SystemTime::now())
}

/// [`remove_checked`] at the time `now`.
pub fn remove_checked_at(
    r: &ScanRoot,
    rel: &Path,
    expect: &FileStamp,
    now: SystemTime,
) -> Result<(), ModifyError> {
    remove_checked_observed(r, rel, expect, now, &mut |_| {})
}

/// [`remove_checked_at`], telling `observe` when the file is aside.
pub fn remove_checked_observed(
    r: &ScanRoot,
    rel: &Path,
    expect: &FileStamp,
    now: SystemTime,
    observe: &mut dyn FnMut(Inside),
) -> Result<(), ModifyError> {
    let fail = |kind| ModifyError {
        rel: rel.to_path_buf(),
        kind,
    };
    let (dir, name) = r
        .open_parent(rel)
        .map_err(|k| fail(ModifyErrorKind::Scan(k)))?;
    check_removable(&dir, &name, expect, now).map_err(fail)?;
    // Move it aside, and remove it only if what moved is the file checked.
    let aside = temp_name(&name, "del");
    rename_beneath(&dir, &name, &aside).map_err(|e| fail(io(&e)))?;
    observe(Inside::MovedAside);
    let moved = open_file(&dir, &aside, usize::MAX).map(|(_, m)| m);
    if !moved.as_ref().is_ok_and(|m| is_checked(m, expect)) {
        return Err(match link_beneath(&dir, &aside, &name) {
            Ok(()) => {
                let _ = unlink_beneath(&dir, &aside);
                let _ = sync_file(&dir);
                fail(ModifyErrorKind::Changed)
            }
            Err(_) => ModifyError {
                rel: rel.with_file_name(&aside),
                kind: ModifyErrorKind::MovedAside,
            },
        });
    }
    if unlink_beneath(&dir, &aside).is_err() {
        let _ = sync_file(&dir);
        return Err(ModifyError {
            rel: rel.with_file_name(&aside),
            kind: ModifyErrorKind::NotRemoved,
        });
    }
    sync_file(&dir).map_err(|e| fail(io(&e)))?;
    Ok(())
}

/// Replaces the file at `rel` with `new`, as [`replace_atomically`] does,
/// only when [`remove_checked`] would remove it: still the one `expect`
/// stamps, not modified within [`MIN_AGE`], and not open elsewhere.
/// Returns the new file's stamp.
pub fn rewrite_checked(
    r: &ScanRoot,
    rel: &Path,
    new: &[u8],
    expect: &FileStamp,
) -> Result<FileStamp, ModifyError> {
    rewrite_checked_observed(r, rel, new, expect, SystemTime::now(), &mut |_| {})
}

/// [`rewrite_checked`] at the time `now`, telling `observe` when the new
/// contents are staged, checked and swapped in.
pub fn rewrite_checked_observed(
    r: &ScanRoot,
    rel: &Path,
    new: &[u8],
    expect: &FileStamp,
    now: SystemTime,
    observe: &mut dyn FnMut(Inside),
) -> Result<FileStamp, ModifyError> {
    let fail = |kind| ModifyError {
        rel: rel.to_path_buf(),
        kind,
    };
    let (dir, name) = r
        .open_parent(rel)
        .map_err(|k| fail(ModifyErrorKind::Scan(k)))?;
    check_removable(&dir, &name, expect, now).map_err(fail)?;
    replace_in(&dir, rel, &name, new, expect, observe)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// A file system that cannot swap two names in one step.
    fn cannot_swap(_: &File, _: &OsStr, _: &OsStr) -> std::io::Result<()> {
        Err(std::io::ErrorKind::Unsupported.into())
    }

    /// Where the names cannot be swapped, a restore from a backup v2 (a
    /// replacement given the contents the file must still hold) writes
    /// nothing (`swap_unsupported`): the file stays as it is and no
    /// temporary file is left, since a rename over it could replace a save
    /// made after the last check. A replacement without such contents
    /// (`init`'s rewrite) keeps the documented fallback and renames.
    #[test]
    fn a_restore_writes_nothing_where_names_cannot_be_swapped() {
        let d = tempfile::tempdir_in("/tmp").unwrap();
        let p = d.path().join("settings.json");
        std::fs::write(&p, b"what the change left").unwrap();
        let dir = File::open(d.path()).unwrap();
        let stamp = FileStamp::of(&std::fs::symlink_metadata(&p).unwrap());
        let left: [u8; 32] = Sha256::digest(b"what the change left").into();
        let name = OsStr::new("settings.json");
        let rel = Path::new("settings.json");
        let mut fill = |f: &mut File| f.write_all(b"backed up").map_err(|e| io(&e));
        let e = replace_in_using(
            cannot_swap,
            &dir,
            rel,
            name,
            &mut fill,
            &stamp,
            Some(&left),
            &mut |_| {},
        )
        .unwrap_err();
        assert_eq!(e.kind, ModifyErrorKind::SwapUnsupported);
        assert_eq!(e.kind.token(), "swap_unsupported");
        assert_eq!(std::fs::read(&p).unwrap(), b"what the change left");
        let names: Vec<_> = std::fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, [name]);
        let mut fill = |f: &mut File| f.write_all(b"rewritten").map_err(|e| io(&e));
        replace_in_using(
            cannot_swap,
            &dir,
            rel,
            name,
            &mut fill,
            &stamp,
            None,
            &mut |_| {},
        )
        .unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"rewritten");
    }
}
