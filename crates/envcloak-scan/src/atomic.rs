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
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use envcloak_sys::{
    InUse, create_beneath, exchange_beneath, link_beneath, open_elsewhere, rename_beneath,
    sync_file, unlink_beneath,
};

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

fn io(e: &std::io::Error) -> ModifyErrorKind {
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
/// replaced (`changed`). Where it cannot, the new file is renamed over
/// the name right after the check, and a save landing between the two is
/// replaced. `rel` is the file's path for errors.
fn replace_in(
    dir: &File,
    rel: &Path,
    name: &OsStr,
    new: &[u8],
    expect: &FileStamp,
    observe: &mut dyn FnMut(Inside),
) -> Result<FileStamp, ModifyError> {
    let fail = |kind| ModifyError {
        rel: rel.to_path_buf(),
        kind,
    };
    let temp = temp_name(name, "new");
    let f = write_new(dir, &temp, new, expect.mode).map_err(|e| fail(io(&e)))?;
    observe(Inside::Staged);
    // Another program may have written the file while this one wrote its
    // replacement: keep theirs.
    if let Err(k) = check_same(dir, name, expect) {
        let _ = unlink_beneath(dir, &temp);
        return Err(fail(k));
    }
    observe(Inside::Checked);
    match exchange_beneath(dir, &temp, name) {
        Ok(()) => {
            let out = open_file(dir, &temp, usize::MAX).map(|(_, m)| m);
            if !out.as_ref().is_ok_and(|m| is_checked(m, expect)) {
                return Err(swap_back(dir, rel, name, &temp, &f));
            }
            unlink_beneath(dir, &temp).map_err(|e| fail(io(&e)))?;
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

/// After a swap brought out a file that is not the one checked: swaps the
/// names back, so `name` is that file again, and removes the new
/// contents, `staged`, from `temp`. Returns `changed`; or, when the names
/// could not be put back as they were, what is under `temp` is kept and
/// named (`moved_aside`), and nothing is removed.
fn swap_back(dir: &File, rel: &Path, name: &OsStr, temp: &OsStr, staged: &File) -> ModifyError {
    let ours = staged.metadata().map(|m| (m.dev(), m.ino()));
    let back = exchange_beneath(dir, temp, name).is_ok()
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
    unlink_beneath(&dir, &aside).map_err(|e| fail(io(&e)))?;
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
/// contents are staged.
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
