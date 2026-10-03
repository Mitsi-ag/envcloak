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
//!   the old one (`O_EXCL`, the old file's mode), flushes it, moves it in
//!   one step that replaces nothing to the name it is swapped from,
//!   checks that this name holds the file written with exactly the bytes
//!   written, checks the old file again, swaps the two names in one step
//!   and checks that what came out is the file checked and what went in
//!   the file written, still holding those bytes (swapping back when
//!   another program saved over either name, or wrote into the new file,
//!   meanwhile), then removes the old file and flushes the directory. A
//!   crash leaves the old file or the new one, never part of either; a
//!   leftover temporary file is never read by anyone. On a file system
//!   that cannot swap names (macOS HFS+, some network and FUSE ones), the
//!   new file is renamed over the old one right after the check, and a
//!   save landing between the two is replaced.
//! - [`create_atomically`] writes a new file the same way and links it
//!   into place only if the name is still free, answering only once the
//!   name holds the file it wrote, with the bytes it wrote.
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
//! temporary name `.<name>.envcloak-<new|swap|del>-<hex>.tmp`
//! ([`temp_name`]), which a scan reports ([`ScanErrorKind::Leftover`]) and
//! `envcloak init` makes sure its project's `.gitignore` ignores. A name
//! of the shape `new` only ever holds a new file while it is written: a
//! swap takes the new file from a name of the shape `swap`, so whatever a
//! swap brings out (the old file, another program's save) never has a
//! name of the shape `new`, the one shape a later restore removes files
//! of ([`remove_leftovers`]). Nothing this module wrote is removed unless
//! it is shown to be the file written, holding what was written; anything
//! else under one of these names is kept, and named.
//!
//! Each removal of a temporary name checks the very file it unlinks: the
//! file is first moved, in one step that replaces nothing, to a fresh
//! name of the same shape, checked there, and unlinked there only while
//! that name still holds it unchanged ([`remove_if`]). What none of this
//! can exclude is a process that renames another file onto that fresh
//! name between the last check and the unlink: only one that reads the
//! directory for a name that did not exist a moment before.
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
    DirEntryKind, InUse, MAX_DIR_ENTRIES, create_rw_beneath, exchange_beneath, kind_beneath,
    link_beneath, list_dir, open_elsewhere, rename_beneath, rename_new_beneath, sync_file,
    unlink_beneath,
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
    /// Another program saved over a name, or wrote into a new file this
    /// one wrote, while it was being changed, so a file of unknown origin
    /// is under a temporary name: it was left there, under the name in
    /// [`ModifyError::rel`], and nothing was removed.
    MovedAside,
    /// The change was made (the new contents have the file's name, or the
    /// name is free), but the old file could not be unlinked: it is left
    /// under the temporary name in [`ModifyError::rel`].
    NotRemoved,
    /// The change was made (the new contents have the file's name), but
    /// the file under the temporary name in [`ModifyError::rel`] is not
    /// the old file as it was checked: another program wrote into it
    /// there, or put its own file under that name, after the names were
    /// swapped. It was kept as it is, and nothing shows whose it is.
    AsideChanged,
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
            ModifyErrorKind::AsideChanged => "aside_changed",
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
                "another program saved over it, or wrote into the new file beside it, while it was \
                 being changed; that file was kept under the name shown, and nothing was removed"
            }
            ModifyErrorKind::NotRemoved => {
                "the change was made, but the old file could not be removed and is left under \
                 the name shown: look at it, then delete it"
            }
            ModifyErrorKind::AsideChanged => {
                "the change was made, but another program changed the old file under the name \
                 shown, or put its own file there, meanwhile, so it was kept as it is"
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

/// A new name beside `name`: `.<name>.envcloak-<what>-<hex>.tmp`, from a
/// randomly keyed hash of the time and this process. Not secret; a clash
/// only makes `O_EXCL`, or a move that replaces nothing, fail. Names too
/// long for one leave the name out. `what` is `new` for a new file while
/// it is written, `swap` for the name a swap takes it from (and leaves
/// what it brings out under), and `del` for a file being removed.
fn temp_name(name: &OsStr, what: &str) -> OsString {
    use std::hash::{BuildHasher, RandomState};
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let h = RandomState::new().hash_one((nanos, std::process::id()));
    // A unit test names the next ones, to put a file there first.
    #[cfg(test)]
    let h = tests::NEXT_HEX
        .with(|q| q.borrow_mut().pop_front())
        .unwrap_or(h);
    let mut t = OsString::from(".");
    if name.as_bytes().len() <= 128 {
        t.push(name);
    }
    t.push(format!(".envcloak-{what}-{h:016x}.tmp"));
    t
}

/// Whether `n` is one of `name`'s temporary names for a new file while it
/// is written: `.<name>.envcloak-new-<16 lowercase hex>.tmp`
/// ([`temp_name`]).
fn new_name_of(name: &OsStr, n: &OsStr) -> bool {
    let mut prefix = b".".to_vec();
    prefix.extend_from_slice(name.as_bytes());
    prefix.extend_from_slice(b".envcloak-new-");
    n.as_bytes()
        .strip_prefix(prefix.as_slice())
        .and_then(|rest| rest.strip_suffix(b".tmp"))
        .is_some_and(|h| {
            h.len() == 16
                && h.iter()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
        })
}

/// Moves `from` to the fresh name `to` in `dir` without replacing what has
/// `to`: in one step ([`rename_new_beneath`]) where the file system can;
/// where it cannot, only after `to` was seen free, so there a file that
/// takes that unpredictable name in between is replaced.
fn move_aside(dir: &File, from: &OsStr, to: &OsStr) -> std::io::Result<()> {
    move_aside_using(rename_new_beneath, dir, from, to)
}

/// What moves a name to a free one in one step: [`rename_new_beneath`],
/// or a unit test's file system that cannot.
type RenameNew = fn(&File, &OsStr, &OsStr) -> std::io::Result<()>;

/// [`move_aside`] with `rename_new`.
fn move_aside_using(
    rename_new: RenameNew,
    dir: &File,
    from: &OsStr,
    to: &OsStr,
) -> std::io::Result<()> {
    match rename_new(dir, from, to) {
        Err(e) if e.kind() == std::io::ErrorKind::Unsupported => match kind_beneath(dir, to) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => rename_beneath(dir, from, to),
            Err(e) => Err(e),
            Ok(_) => Err(std::io::ErrorKind::AlreadyExists.into()),
        },
        moved => moved,
    }
}

/// What [`remove_if`] did with a file.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Removal {
    /// It was taken for the one to remove, and unlinked.
    Unlinked,
    /// Nothing had the name; or the file taken was gone from where it was
    /// moved before it was checked there (another program moved or
    /// removed it).
    Absent,
    /// It was taken for the one to remove, but could not be moved aside
    /// or unlinked: it is left, under this name.
    Left(OsString),
    /// It was not taken for the one to remove (another file, or the one
    /// expected changed): it was kept, under this name. Nothing shows
    /// whose it is.
    Kept(OsString),
}

/// The points [`remove_if`] passes, for the leftover cleanup's barriers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Removing {
    /// The file was moved to a fresh name and is not checked there yet.
    Moved,
    /// It was checked there, and its name there is not checked again yet.
    Read,
    /// It failed the check and was linked back under its name; the fresh
    /// name is not removed yet.
    PutBack,
}

/// Removes the file `at` in `dir` (one of `name`'s temporary names) only
/// when `is_it` takes it for the one to remove, and only the very file it
/// took. A first look opens it by its name (a regular file of this user,
/// never through a symlink) and asks `is_it`; a file that passes is moved,
/// in one step that replaces nothing ([`move_aside`]), to a fresh name of
/// the shape `what` (`.<name>.envcloak-<what>-<hex>.tmp`), opened and
/// asked again there, and unlinked there only while that name still holds
/// it with the stamp it had before it was asked, change time included. A
/// file that fails there is put back under `at` with a link that never
/// replaces a name, and the fresh name then goes only while it names that
/// same file ([`unlink_if_same`]); when `at` was taken meanwhile, the file
/// is left under the fresh name. `observe` hears each [`Removing`] point.
/// The one thing this cannot exclude is a process that renames another
/// file onto the fresh name between the last check and the unlink.
///
/// [`Removal::Left`] names a file taken for the one to remove that could
/// not be moved or unlinked; [`Removal::Kept`] one that was not taken
/// (put back, or left under the fresh name); [`Removal::Absent`] says
/// nothing had `at`, or the file moved aside was gone from the fresh name
/// before it was checked there.
fn remove_if(
    dir: &File,
    name: &OsStr,
    at: &OsStr,
    what: &str,
    is_it: &mut dyn FnMut(&mut File, &std::fs::Metadata) -> bool,
    observe: &mut dyn FnMut(Removing),
) -> Removal {
    let first = match open_file(dir, at, usize::MAX) {
        Err(ScanErrorKind::NotFound) => return Removal::Absent,
        Ok((mut f, m)) => is_it(&mut f, &m),
        Err(_) => false,
    };
    if !first {
        return Removal::Kept(at.to_os_string());
    }
    let aside = temp_name(name, what);
    match move_aside(dir, at, &aside) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Removal::Absent,
        Err(_) => return Removal::Left(at.to_os_string()),
    }
    observe(Removing::Moved);
    let taken = open_file(dir, &aside, usize::MAX).is_ok_and(|(mut f, m)| {
        let stamp = FileStamp::of(&m);
        let ok = is_it(&mut f, &m);
        observe(Removing::Read);
        ok && open_file(dir, &aside, usize::MAX).is_ok_and(|(_, now)| FileStamp::of(&now) == stamp)
    });
    if taken {
        return match unlink_beneath(dir, &aside) {
            Ok(()) => Removal::Unlinked,
            Err(_) => Removal::Left(aside),
        };
    }
    match link_beneath(dir, &aside, at) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Removal::Absent,
        Err(_) => return Removal::Kept(aside),
    }
    observe(Removing::PutBack);
    unlink_if_same(dir, &aside, at);
    Removal::Kept(at.to_os_string())
}

/// Unlinks `extra` in `dir` only while it and `name` are the same file
/// (device and inode, each opened never through a symlink): once a file
/// was linked back under `name`, the name it had been moved to goes, and
/// a file another program renamed onto that name meanwhile stays.
/// Returns whether it went.
fn unlink_if_same(dir: &File, extra: &OsStr, name: &OsStr) -> bool {
    let id = |n: &OsStr| open_file(dir, n, usize::MAX).map(|(_, m)| (m.dev(), m.ino()));
    id(extra).is_ok_and(|a| id(name).is_ok_and(|b| a == b)) && unlink_beneath(dir, extra).is_ok()
}

/// Removes from `dir` what earlier writes back of `name` left beside it
/// under the names a new file has while it is written
/// (`.<name>.envcloak-new-<16 hex>.tmp`, [`temp_name`]) when they were
/// stopped before they ended, once `staged`, the new file `ours` in `dir`,
/// holds the whole contents being written back. A file of such a name
/// goes only when it is shown to hold nothing but those contents' first
/// bytes: a regular file of this user with one link, no longer than
/// `staged`, every byte of it equal to the byte of `staged` at its place
/// ([`holds_first_bytes_of`]). Such a name is only ever given to a new
/// file while it is written: whatever a swap brings out, another
/// program's save included, is left under a name of the shape `swap`
/// ([`ModifyErrorKind::MovedAside`]), which is never removed here, since
/// nothing shows where it came from. A file of the shape `new` that holds
/// anything else stays too. A name too long to be carried in one
/// ([`temp_name`] leaves it out) says nothing of whose it is, so nothing
/// is removed then. Never through a symlink.
///
/// What each file is compared with is itself checked first: `staged` must
/// hold exactly the bytes written to it, read whole through its
/// descriptor, with the mode it was given ([`Staged::intact_stamp`]), or
/// nothing is removed; and its whole stamp, change time included, must be
/// the one that check read after every comparison, so a file compared
/// with bytes another program wrote into `staged` meanwhile (even put
/// back as they were) is never taken for a leftover.
///
/// Each file goes through [`remove_if`]: checked by its name, moved aside
/// to a fresh name of the same shape, checked there again, whole, and
/// unlinked there only while that name still holds it unchanged; put back
/// (or left under the fresh name) otherwise. A process killed between the
/// move and the end leaves the file under the fresh name, of the same
/// shape.
///
/// `observe` hears [`Inside::LeftoverMoved`] once a file is moved aside,
/// [`Inside::LeftoverRead`] once its bytes there are compared, before the
/// last check of its name, and [`Inside::LeftoverPutBack`] once a file
/// that failed is linked back under its name, before the fresh name goes.
/// Best effort: returns how many went, and flushes `dir` when any did. The
/// bytes read pass through buffers wiped after.
fn remove_leftovers(
    dir: &File,
    name: &OsStr,
    ours: &OsStr,
    staged: &Staged,
    observe: &mut dyn FnMut(Inside),
) -> usize {
    if name.as_bytes().len() > 128 {
        return 0;
    }
    // The bytes every leftover is compared with: the new file, holding
    // exactly what was written, and unchanged after each comparison.
    let Some(reference) = staged.intact_stamp() else {
        return 0;
    };
    let Ok(entries) = list_dir(dir, MAX_DIR_ENTRIES) else {
        return 0;
    };
    let mut removed = 0;
    for e in entries {
        // A file of another name or kind is never looked at.
        if !new_name_of(name, &e.name)
            || e.name == ours
            || !kind_beneath(dir, &e.name).is_ok_and(|k| k == DirEntryKind::File)
        {
            continue;
        }
        let gone = remove_if(
            dir,
            name,
            &e.name,
            "new",
            &mut |f, m| {
                holds_first_bytes_of(f, m, &staged.f, staged.len) && staged.stamped(&reference)
            },
            &mut |at| {
                observe(match at {
                    Removing::Moved => Inside::LeftoverMoved,
                    Removing::Read => Inside::LeftoverRead,
                    Removing::PutBack => Inside::LeftoverPutBack,
                });
            },
        );
        if gone == Removal::Unlinked {
            removed += 1;
        }
    }
    if removed > 0 {
        let _ = sync_file(dir);
    }
    removed
}

/// Whether `f`, opened with the metadata `m`, holds nothing but the first
/// bytes of `whole`, which is `len` bytes long: one link, no longer than
/// `whole`, each of its bytes the byte of `whole` at its place, and as
/// long as `m` says.
fn holds_first_bytes_of(f: &mut File, m: &std::fs::Metadata, whole: &File, len: u64) -> bool {
    use std::os::unix::fs::FileExt;
    if m.nlink() != 1 || m.len() > len {
        return false;
    }
    let mut theirs = Zeroizing::new(vec![0u8; 64 * 1024]);
    let mut ours = Zeroizing::new(vec![0u8; 64 * 1024]);
    let mut at: u64 = 0;
    loop {
        let n = match f.read(&mut theirs[..]) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => return false,
        };
        let end = at + n as u64;
        if end > m.len()
            || whole.read_exact_at(&mut ours[..n], at).is_err()
            || theirs[..n] != ours[..n]
        {
            return false;
        }
        at = end;
    }
    at == m.len()
}

/// A new file written beside the one it is to replace or create, open for
/// reading and writing, and what was written to it: the mode it was given,
/// and the length and SHA-256 of the bytes written. It is read back
/// through this descriptor only, never by a name.
struct Staged {
    f: File,
    mode: u32,
    len: u64,
    sha256: [u8; 32],
}

impl Staged {
    /// Whether the file holds exactly the bytes written: read whole
    /// through its descriptor, of the length and SHA-256 written, its
    /// whole stamp the same before and after that read, change time
    /// included. An edit in place, one at the same length that puts the
    /// modification time back included, and a write while it is read are
    /// each seen. The bytes pass through a buffer wiped after.
    fn holds_written(&self) -> bool {
        self.written_stamp().is_some()
    }

    /// The file's stamp when it holds exactly the bytes written
    /// ([`Staged::holds_written`]): the one it had both before and after
    /// it was read whole. `None` otherwise.
    fn written_stamp(&self) -> Option<FileStamp> {
        use std::os::unix::fs::FileExt;
        let before = FileStamp::of(&self.f.metadata().ok()?);
        if before.size != self.len {
            return None;
        }
        let mut buf = Zeroizing::new(vec![0u8; 64 * 1024]);
        let mut h = Sha256::new();
        let mut at: u64 = 0;
        loop {
            let n = match self.f.read_at(&mut buf[..], at) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return None,
            };
            at += n as u64;
            if at > self.len {
                return None;
            }
            h.update(&buf[..n]);
            #[cfg(test)]
            tests::during_read();
        }
        let digest: [u8; 32] = h.finalize().into();
        (at == self.len && digest == self.sha256 && self.stamped(&before)).then_some(before)
    }

    /// Whether the file's whole stamp, change time included, is `stamp`.
    fn stamped(&self, stamp: &FileStamp) -> bool {
        self.f.metadata().is_ok_and(|m| FileStamp::of(&m) == *stamp)
    }

    /// Whether the file is still as written: the bytes written
    /// ([`Staged::holds_written`]) and the mode it was given, so a file
    /// another program made readable to others is never put in place.
    fn intact(&self) -> bool {
        self.intact_stamp().is_some()
    }

    /// The file's stamp when it is still as written ([`Staged::intact`]):
    /// the one read before and after its bytes were. `None` otherwise.
    fn intact_stamp(&self) -> Option<FileStamp> {
        self.written_stamp().filter(|s| s.mode == self.mode)
    }

    /// Whether `at` in `dir` is this file (a regular file of this user,
    /// never through a symlink, with its device and inode), still as
    /// written ([`Staged::intact`]).
    fn named(&self, dir: &File, at: &OsStr) -> bool {
        holds(dir, at, &self.f) && self.intact()
    }

    /// Removes this file from `at` in `dir`, one of `name`'s temporary
    /// names of the shape `what`, only while `at` names it and it holds
    /// the bytes written ([`remove_if`], [`Staged::holds_written`]):
    /// anything else under that name, this file written into by another
    /// program included, is kept, and [`Removal::Kept`] says where. `dir`
    /// is flushed when anything went. `observe` hears
    /// [`Inside::NewMoved`] once the file is moved to a fresh name, and
    /// [`Inside::PutBack`] once a file that failed there is linked back.
    fn discard(
        &self,
        dir: &File,
        name: &OsStr,
        at: &OsStr,
        what: &str,
        observe: &mut dyn FnMut(Inside),
    ) -> Removal {
        let ours = self.f.metadata().map(|m| (m.dev(), m.ino())).ok();
        let r = remove_if(
            dir,
            name,
            at,
            what,
            &mut |_, m| ours == Some((m.dev(), m.ino())) && self.holds_written(),
            &mut removing(observe, Inside::NewMoved),
        );
        if r == Removal::Unlinked {
            let _ = sync_file(dir);
        }
        r
    }
}

/// What a removal of a temporary name ([`remove_if`]) tells `observe`:
/// `moved` once the file is moved to a fresh name, and [`Inside::PutBack`]
/// once a file that failed its check there is linked back under its name.
fn removing(observe: &mut dyn FnMut(Inside), moved: Inside) -> impl FnMut(Removing) + '_ {
    move |at| match at {
        Removing::Moved => observe(moved),
        Removing::PutBack => observe(Inside::PutBack),
        Removing::Read => {}
    }
}

/// What a new file's contents are written through: the file, and the
/// length and SHA-256 of every byte that reaches it.
struct Hashing<'a> {
    f: &'a mut File,
    h: Sha256,
    len: u64,
}

impl Write for Hashing<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.f.write(buf)?;
        let wrote = buf.get(..n).unwrap_or_default();
        self.h.update(wrote);
        self.len += wrote.len() as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.f.flush()
    }
}

/// What writes a new file's contents: called once with a writer to the
/// new file, which is empty. A failure leaves no new file.
pub(crate) type Fill<'a> = &'a mut dyn FnMut(&mut dyn Write) -> Result<(), ModifyErrorKind>;

/// Writes what `fill` writes to a new file `temp` in `dir` (one of
/// `name`'s temporary names of the shape `new`), counting and hashing
/// every byte that reaches it, then gives it `mode` and flushes it. On a
/// failure the new file goes, only while `temp` names it and it holds what
/// was written ([`Staged::discard`]); anything else there is kept and
/// named (`moved_aside`). `rel` is the file's path for errors.
fn write_new_with(
    dir: &File,
    rel: &Path,
    name: &OsStr,
    temp: &OsStr,
    mode: u32,
    fill: Fill<'_>,
) -> Result<Staged, ModifyError> {
    let fail = |kind| ModifyError {
        rel: rel.to_path_buf(),
        kind,
    };
    // Open for reading as well: what it holds is read back through this
    // descriptor, never by its name again.
    let mut f = create_rw_beneath(dir, temp, 0o600).map_err(|e| fail(io(&e)))?;
    let mut w = Hashing {
        f: &mut f,
        h: Sha256::new(),
        len: 0,
    };
    let filled = fill(&mut w);
    let (len, sha256): (u64, [u8; 32]) = (w.len, w.h.finalize().into());
    let written = filled.and_then(|()| {
        f.set_permissions(std::fs::Permissions::from_mode(mode & 0o7777))
            .and_then(|()| sync_file(&f).map(drop))
            .map_err(|e| io(&e))
    });
    // Without its mode nothing shows what the file is: it is kept, and
    // named.
    let Ok(mode) = f.metadata().map(|m| m.mode()) else {
        return Err(kept(rel, temp));
    };
    let staged = Staged {
        f,
        mode,
        len,
        sha256,
    };
    match written {
        Ok(()) => Ok(staged),
        Err(k) => Err(give_up(
            dir,
            rel,
            name,
            &staged,
            temp,
            "new",
            k,
            &mut |_| {},
        )),
    }
}

/// The error for a file of unknown origin left under the temporary name
/// `at` beside `rel`.
fn kept(rel: &Path, at: &OsStr) -> ModifyError {
    ModifyError {
        rel: rel.with_file_name(at),
        kind: ModifyErrorKind::MovedAside,
    }
}

/// A change that stops with `k`: the new file `staged` goes from `at` (a
/// temporary name of the shape `what`), only while `at` names it and it
/// holds what was written ([`Staged::discard`], which `observe` hears);
/// when anything else is there, or it could not be removed, it is kept,
/// and the error names it (`moved_aside`) instead.
#[allow(clippy::too_many_arguments)] // The change's place, and the barrier.
fn give_up(
    dir: &File,
    rel: &Path,
    name: &OsStr,
    staged: &Staged,
    at: &OsStr,
    what: &str,
    k: ModifyErrorKind,
    observe: &mut dyn FnMut(Inside),
) -> ModifyError {
    match staged.discard(dir, name, at, what, observe) {
        Removal::Kept(at) | Removal::Left(at) => {
            let _ = sync_file(dir);
            kept(rel, &at)
        }
        Removal::Unlinked | Removal::Absent => ModifyError {
            rel: rel.to_path_buf(),
            kind: k,
        },
    }
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
    /// The new contents are written and flushed beside the file, under
    /// the name the swap takes them from, and not checked there yet, nor
    /// in its place.
    Staged,
    /// The new file was checked under that name, and the file for the
    /// last time, before the new contents take its name.
    Checked,
    /// The names are swapped: the new contents have the file's name, and
    /// what came out is under the temporary name, not checked yet.
    Exchanged,
    /// The names are swapped, what came out is the file checked (for a
    /// restore from a backup v2, with the contents the change left), and
    /// what went in is the new file, holding what was written: the old
    /// file is under the temporary name, not removed yet.
    Swapped,
    /// The file to write back over is open and its stamp read, and it is
    /// not read yet ([`crate::restore_over_left`]).
    Opened,
    /// The file to write back over was hashed and is what the change left
    /// ([`crate::restore_over_left`]); its replacement is not written yet.
    Hashed,
    /// A file an earlier restore of the same file left beside it, which a
    /// first look took for its leftover, was moved aside to a fresh name
    /// of the same shape and is not checked there yet
    /// ([`crate::restore_over_left`]).
    LeftoverMoved,
    /// That file's bytes were compared where it was moved, and its name
    /// there is not checked again yet, nor the file unlinked.
    LeftoverRead,
    /// That file failed the check where it was moved and is linked back
    /// under its name; the fresh name is not removed yet.
    LeftoverPutBack,
    /// A file created is linked to its name, and its temporary name is not
    /// removed yet ([`crate::create_atomically`]).
    Linked,
    /// The old file, once the names are swapped and checked ([`Swapped`]),
    /// was moved from its temporary name to a fresh name of the same
    /// shape, and is not checked there yet.
    ///
    /// [`Swapped`]: Inside::Swapped
    OldMoved,
    /// The new file, being removed from its temporary name (the change
    /// stopped, or a create linked it to its name), was moved to a fresh
    /// name of the same shape, and is not checked there yet.
    NewMoved,
    /// A file a removal moved aside (the file [`crate::remove_checked`]
    /// removes, the old file or the new one) failed its check where it
    /// moved and is linked back under its name; the name it moved to is
    /// not removed yet.
    PutBack,
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
/// replaced (`changed`). Then the old file is removed, only while it is
/// still the file checked ([`remove_if`]); when it cannot be, the change
/// stands and the old file is named where it is left (`not_removed`); when
/// another program changed it, or put its own file under its temporary
/// name, meanwhile, the change stands and that file is kept and named for
/// what it is (`aside_changed`), never called the old copy; when another
/// program moved or removed it, nothing is named. Where the names cannot
/// be swapped, the new file is renamed over the name right after the
/// check, and a save landing between the two is replaced. `rel` is the
/// file's path for errors.
fn replace_in(
    dir: &File,
    rel: &Path,
    name: &OsStr,
    new: &[u8],
    expect: &FileStamp,
    observe: &mut dyn FnMut(Inside),
) -> Result<FileStamp, ModifyError> {
    let mut fill = |w: &mut dyn Write| w.write_all(new).map_err(|e| io(&e));
    replace_in_with(dir, rel, name, &mut fill, expect, None, observe)
}

/// What swaps two names in a directory in one step: [`exchange_beneath`],
/// or a unit test's file system that cannot.
type Swap = fn(&File, &OsStr, &OsStr) -> std::io::Result<()>;

/// [`replace_in`], with the new contents written by `fill`, so they can
/// be written a part at a time; and, when `left` is given, only over a
/// file that still holds the contents of that SHA-256 when it moves out.
///
/// The new file is written under a name of the shape `new`, then moved,
/// in one step that replaces nothing, to a name of the shape `swap`,
/// which the swap takes it from; there, and again once it has the file's
/// name, it must be the file written and hold exactly what was written
/// ([`Staged::named`]): another file put under either name, or this one
/// written into in place, is never left in the file's place. One found so
/// before the swap is kept where it is (`moved_aside`), and nothing is
/// swapped; one found so after it is swapped back out and kept the same
/// way. So nothing a swap brings out ever has a name of the shape `new`.
///
/// With `left`, the file that came out of the swap is read whole, its
/// stamp checked again after the read, and its SHA-256 compared with
/// `left`: an edit made in place after the last check (the same length,
/// its modification time put back, which the stamp alone does not tell)
/// swaps the names back and keeps the edit (`changed`). A file system
/// that cannot swap names then writes nothing (`swap_unsupported`), never
/// renaming over a file it could not check. What it cannot see is a write
/// to the old file, by a program that still has it open, after that read.
/// Also with `left`, once the new file is whole and before it moves, the
/// files earlier restores of `name` stopped while writing left beside it,
/// holding only its first bytes, go, each moved aside and checked where
/// it moved before it is unlinked there ([`remove_leftovers`]).
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
    let new = temp_name(name, "new");
    let staged = write_new_with(dir, rel, name, &new, expect.mode, fill)?;
    if left.is_some() {
        // A restore, its contents now whole beside the file: what earlier
        // restores of the file left of those contents goes, whatever this
        // one comes to (`remove_leftovers`).
        remove_leftovers(dir, name, &new, &staged, observe);
    }
    // A change that stops: the new file goes from `at` only while it is
    // the file written, holding what was written (`give_up`).
    let stop = |at: &OsStr, what: &str, k, observe: &mut dyn FnMut(Inside)| {
        give_up(dir, rel, name, &staged, at, what, k, observe)
    };
    // The swap takes the new file from a name of another shape, so what it
    // brings out never has the shape a later restore's cleanup reads.
    let temp = temp_name(name, "swap");
    if let Err(e) = move_aside(dir, &new, &temp) {
        return Err(stop(&new, "new", io(&e), observe));
    }
    observe(Inside::Staged);
    // What the swap takes must be the file written, holding what was
    // written: another file under that name, or this one written into, is
    // kept, and never swapped in.
    if !staged.named(dir, &temp) {
        return Err(stop(&temp, "swap", ModifyErrorKind::Changed, observe));
    }
    // Another program may have written the file while this one wrote its
    // replacement: keep theirs.
    if let Err(k) = check_same(dir, name, expect) {
        return Err(stop(&temp, "swap", k, observe));
    }
    observe(Inside::Checked);
    // What came out of a swap must be the file checked, holding (with
    // `left`) the contents the change left.
    let mut came_out = |out: &mut File, m: &std::fs::Metadata| {
        is_checked(m, expect)
            && left
                .is_none_or(|want| digest_of(out, &FileStamp::of(m)).is_ok_and(|got| got == *want))
    };
    match swap(dir, &temp, name) {
        Ok(()) => {
            observe(Inside::Exchanged);
            // A swap takes whatever has each name at that moment: what came
            // out must be the file checked, and what went in the file
            // written, still holding what was written (another file put
            // under the temporary name, or the new file written into
            // meanwhile, is never left in the file's place).
            let checked = open_file(dir, &temp, usize::MAX)
                .is_ok_and(|(mut out, m)| came_out(&mut out, &m))
                && staged.named(dir, name);
            if !checked {
                if swap(dir, &temp, name).is_ok() {
                    return Err(stop(&temp, "swap", ModifyErrorKind::Changed, observe));
                }
                // The names could not be swapped back: what came out is
                // kept where it is, and named.
                let _ = sync_file(dir);
                return Err(kept(rel, &temp));
            }
            observe(Inside::Swapped);
            // The old file goes only while it is still the file checked,
            // and the answer names only what was checked: a file another
            // program changed or put under the temporary name meanwhile is
            // kept, and never called the old file.
            let gone = remove_if(
                dir,
                name,
                &temp,
                "swap",
                &mut came_out,
                &mut removing(observe, Inside::OldMoved),
            );
            let left_aside = |at: OsString, kind| {
                let _ = sync_file(dir);
                Err(ModifyError {
                    rel: rel.with_file_name(at),
                    kind,
                })
            };
            match gone {
                // Gone from the temporary name before it was taken: nothing
                // this call left is under one.
                Removal::Unlinked | Removal::Absent => {}
                Removal::Left(at) => return left_aside(at, ModifyErrorKind::NotRemoved),
                Removal::Kept(at) => return left_aside(at, ModifyErrorKind::AsideChanged),
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::Unsupported && left.is_some() => {
            return Err(stop(
                &temp,
                "swap",
                ModifyErrorKind::SwapUnsupported,
                observe,
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
            if let Err(e) = rename_beneath(dir, &temp, name) {
                return Err(stop(&temp, "swap", io(&e), observe));
            }
            // A rename takes whatever has the temporary name at that
            // moment: another file put there, or the new file written into
            // meanwhile, is never answered as written.
            if !staged.named(dir, name) {
                let _ = sync_file(dir);
                return Err(fail(ModifyErrorKind::Changed));
            }
        }
        Err(e) => {
            return Err(stop(&temp, "swap", io(&e), observe));
        }
    }
    sync_file(dir).map_err(|e| fail(io(&e)))?;
    let m = staged.f.metadata().map_err(|e| fail(io(&e)))?;
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
    create_in(&dir, rel, &name, new, mode, &mut |_| {})
}

/// [`create_atomically`] in `dir`. The new file, once written and flushed
/// under its temporary name (`observe` hears [`Inside::Staged`]), must be
/// the file that name holds, as written ([`Staged::named`]), or nothing
/// is linked and what is there is kept and named (`moved_aside`); then
/// (`observe` hears [`Inside::Checked`]) it is linked to `name` only if no
/// file has that name. A link takes whatever has the temporary name at
/// that moment, so `name` is then checked the same way: another file put
/// under the temporary name, or the new file written into, is never
/// answered as created ([`ModifyErrorKind::Changed`]; what has `name`
/// keeps it, nothing is removed). Once linked (`observe` hears
/// [`Inside::Linked`]), the temporary name goes only while it names the
/// new file holding the bytes written ([`Staged::discard`], moved to a
/// fresh name and checked there first: `observe` hears
/// [`Inside::NewMoved`]); a file another program put under either name
/// meanwhile stays. When the new file keeps that name too, the file is
/// created but the call says so ([`ModifyErrorKind::NotRemoved`], naming
/// it).
fn create_in(
    dir: &File,
    rel: &Path,
    name: &OsStr,
    new: &[u8],
    mode: u32,
    observe: &mut dyn FnMut(Inside),
) -> Result<FileStamp, ModifyError> {
    let fail = |kind| ModifyError {
        rel: rel.to_path_buf(),
        kind,
    };
    let temp = temp_name(name, "new");
    let mut fill = |w: &mut dyn Write| w.write_all(new).map_err(|e| io(&e));
    let staged = write_new_with(dir, rel, name, &temp, mode, &mut fill)?;
    observe(Inside::Staged);
    if !staged.named(dir, &temp) {
        return Err(give_up(
            dir,
            rel,
            name,
            &staged,
            &temp,
            "new",
            ModifyErrorKind::Changed,
            observe,
        ));
    }
    observe(Inside::Checked);
    if let Err(e) = link_beneath(dir, &temp, name) {
        let k = if e.kind() == std::io::ErrorKind::AlreadyExists {
            ModifyErrorKind::Exists
        } else {
            io(&e)
        };
        return Err(give_up(dir, rel, name, &staged, &temp, "new", k, observe));
    }
    observe(Inside::Linked);
    let dropped = staged.discard(dir, name, &temp, "new", observe);
    sync_file(dir).map_err(|e| fail(io(&e)))?;
    if !staged.named(dir, name) {
        return Err(fail(ModifyErrorKind::Changed));
    }
    // Created; but the new file keeps its temporary name too when that
    // could not be removed.
    if let Removal::Kept(at) | Removal::Left(at) = dropped {
        if holds(dir, &at, &staged.f) {
            return Err(ModifyError {
                rel: rel.with_file_name(at),
                kind: ModifyErrorKind::NotRemoved,
            });
        }
    }
    let m = staged.f.metadata().map_err(|e| fail(io(&e)))?;
    Ok(FileStamp::of(&m))
}

/// Whether `name` in `dir` is the file `f` is open on: a regular file of
/// this user, never through a symlink, with `f`'s device and inode.
fn holds(dir: &File, name: &OsStr, f: &File) -> bool {
    let Ok(ours) = f.metadata() else {
        return false;
    };
    open_file(dir, name, usize::MAX)
        .is_ok_and(|(_, m)| (m.dev(), m.ino()) == (ours.dev(), ours.ino()))
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

/// [`remove_checked_at`], telling `observe` when the file is aside
/// ([`Inside::MovedAside`]) and, when what moved is not the file checked,
/// once it is linked back under its name ([`Inside::PutBack`]).
///
/// A file that is not the one checked once it moved is put back under its
/// name with a link that never replaces one, and the name it was moved to
/// goes only while it names that same file ([`unlink_if_same`]): a file
/// another program renamed onto that name meanwhile stays, and is named
/// (`moved_aside`). When the file is gone from where it moved (another
/// program moved or removed it), nothing is named: `changed`.
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
    // Move it aside, never over another file, and remove it only if what
    // moved is the file checked.
    let aside = temp_name(&name, "del");
    move_aside(&dir, &name, &aside).map_err(|e| fail(io(&e)))?;
    observe(Inside::MovedAside);
    let moved = open_file(&dir, &aside, usize::MAX).map(|(_, m)| m);
    if !moved.as_ref().is_ok_and(|m| is_checked(m, expect)) {
        let left_aside = ModifyError {
            rel: rel.with_file_name(&aside),
            kind: ModifyErrorKind::MovedAside,
        };
        return Err(match link_beneath(&dir, &aside, &name) {
            Ok(()) => {
                observe(Inside::PutBack);
                let gone = unlink_if_same(&dir, &aside, &name);
                let _ = sync_file(&dir);
                if gone {
                    fail(ModifyErrorKind::Changed)
                } else {
                    left_aside
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => fail(ModifyErrorKind::Changed),
            Err(_) => left_aside,
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

    thread_local! {
        /// The hex digits the next temporary names on this thread take,
        /// in order ([`temp_name`]), so a test can put a file there first.
        pub(super) static NEXT_HEX: core::cell::RefCell<std::collections::VecDeque<u64>> =
            const { core::cell::RefCell::new(std::collections::VecDeque::new()) };
    }

    /// Makes the next temporary names on this thread end in `hex`, in
    /// order.
    fn next_names(hex: &[u64]) {
        NEXT_HEX.with(|q| q.borrow_mut().extend(hex.iter().copied()));
    }

    thread_local! {
        /// What [`Staged::holds_written`] runs, once, after it read the
        /// first part of the file.
        static DURING_READ: core::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            const { core::cell::RefCell::new(None) };
    }

    /// Called by [`Staged::holds_written`] after each part it reads.
    pub(super) fn during_read() {
        if let Some(f) = DURING_READ.with(|d| d.borrow_mut().take()) {
            f();
        }
    }

    /// A file system that cannot swap two names in one step.
    fn cannot_swap(_: &File, _: &OsStr, _: &OsStr) -> std::io::Result<()> {
        Err(std::io::ErrorKind::Unsupported.into())
    }

    /// The names in `dir`, sorted.
    fn names_in(dir: &Path) -> Vec<OsString> {
        let mut v: Vec<OsString> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        v.sort();
        v
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
        let mut fill = |w: &mut dyn Write| w.write_all(b"backed up").map_err(|e| io(&e));
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
        assert_eq!(names_in(d.path()), [name]);
        let mut fill = |w: &mut dyn Write| w.write_all(b"rewritten").map_err(|e| io(&e));
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

    /// Puts a file of `bytes` under `temp` in `dir`, as another program
    /// renaming its own file there would.
    fn put_under(dir: &Path, temp: &OsStr, bytes: &[u8]) {
        let other = dir.join("another-programs-file");
        std::fs::write(&other, bytes).unwrap();
        std::fs::rename(&other, dir.join(temp)).unwrap();
    }

    /// Writes `bytes` into the file at `p` in place, at its start, and puts
    /// its modification time back, as a program holding it open could.
    fn write_into(p: &Path, bytes: &[u8]) {
        use std::os::unix::fs::FileExt;
        let w = std::fs::OpenOptions::new().write(true).open(p).unwrap();
        let modified = w.metadata().unwrap().modified().unwrap();
        w.write_all_at(bytes, 0).unwrap();
        w.set_modified(modified).unwrap();
    }

    /// The name of the one temporary file of the shape `what` in `dir`
    /// beside `name`.
    fn temp_of(dir: &Path, name: &str, what: &str) -> OsString {
        let prefix = format!(".{name}.envcloak-{what}-");
        let found: Vec<OsString> = names_in(dir)
            .into_iter()
            .filter(|n| n.to_string_lossy().starts_with(&prefix))
            .collect();
        assert_eq!(found.len(), 1, "{found:?}");
        found[0].clone()
    }

    /// A file created is answered as created only when its name holds the
    /// file written, holding exactly the bytes written. Once the new file
    /// is flushed under its temporary name (`Staged`), another file put
    /// under that name, or the new file written into in place, is never
    /// linked: the call fails (`moved_aside`, naming the temporary name,
    /// where that file is kept as it was), and the name stays free. Once
    /// that check passed (`Checked`), the link takes whatever has the
    /// temporary name: another file put there keeps the name, and the new
    /// file written into in place is never answered as created (`changed`
    /// both). Unchanged, the file is created, and no temporary file is
    /// left.
    #[test]
    fn a_create_answers_only_for_the_file_and_bytes_written() {
        for (at, how) in [
            (Inside::Staged, "replaced"),
            (Inside::Staged, "written into"),
            (Inside::Checked, "replaced"),
            (Inside::Checked, "written into"),
        ] {
            let d = tempfile::tempdir_in("/tmp").unwrap();
            let dir = File::open(d.path()).unwrap();
            let name = OsStr::new("envcloak.toml");
            let rel = Path::new("envcloak.toml");
            let mut did = 0;
            let e = create_in(&dir, rel, name, b"ours", 0o600, &mut |now| {
                if now != at {
                    return;
                }
                let temp = temp_of(d.path(), "envcloak.toml", "new");
                match how {
                    "replaced" => put_under(d.path(), &temp, b"theirs"),
                    _ => write_into(&d.path().join(&temp), b"THEM"),
                }
                did += 1;
            })
            .unwrap_err();
            assert_eq!(did, 1, "{at:?} {how}");
            let theirs: &[u8] = if how == "replaced" {
                b"theirs"
            } else {
                b"THEM"
            };
            if at == Inside::Staged {
                assert_eq!(e.kind, ModifyErrorKind::MovedAside, "{at:?} {how}");
                assert!(!d.path().join(name).exists(), "{at:?} {how}: linked");
                assert_eq!(
                    std::fs::read(d.path().join(&e.rel)).unwrap(),
                    theirs,
                    "{at:?} {how}"
                );
            } else {
                assert_eq!(e.kind, ModifyErrorKind::Changed, "{at:?} {how}");
                assert_eq!(
                    std::fs::read(d.path().join(name)).unwrap(),
                    theirs,
                    "{at:?} {how}"
                );
            }
        }
        let d = tempfile::tempdir_in("/tmp").unwrap();
        let dir = File::open(d.path()).unwrap();
        let name = OsStr::new("envcloak.toml");
        create_in(
            &dir,
            Path::new("envcloak.toml"),
            name,
            b"ours",
            0o600,
            &mut |_| {},
        )
        .unwrap();
        assert_eq!(std::fs::read(d.path().join(name)).unwrap(), b"ours");
        assert_eq!(names_in(d.path()), [name]);
    }

    /// Once a file created is linked to its name, its temporary name goes
    /// only while the check where it was moved still takes it (verifier,
    /// M2-05 round 11: the check at the fresh name had no test that could
    /// fail): right after the new file is moved from its temporary name to
    /// a fresh one (`NewMoved`), another program renames its own file onto
    /// that fresh name. That file is never removed: it is linked back under
    /// the temporary name, and the create, whose file has its name holding
    /// what was written, is answered as made.
    #[test]
    fn a_file_renamed_onto_a_creates_fresh_name_stays() {
        let d = tempfile::tempdir_in("/tmp").unwrap();
        let dir = File::open(d.path()).unwrap();
        let name = OsStr::new("envcloak.toml");
        let mut temp = None;
        let mut did = 0;
        create_in(
            &dir,
            Path::new("envcloak.toml"),
            name,
            b"ours",
            0o600,
            &mut |now| match now {
                Inside::Linked => temp = Some(temp_of(d.path(), "envcloak.toml", "new")),
                Inside::NewMoved => {
                    let fresh = temp_of(d.path(), "envcloak.toml", "new");
                    assert_ne!(Some(&fresh), temp.as_ref(), "not moved");
                    put_under(d.path(), &fresh, b"theirs");
                    did += 1;
                }
                _ => {}
            },
        )
        .unwrap();
        assert_eq!(did, 1);
        assert_eq!(std::fs::read(d.path().join(name)).unwrap(), b"ours");
        let temp = temp.unwrap();
        assert_eq!(temp_of(d.path(), "envcloak.toml", "new"), temp);
        assert_eq!(
            std::fs::read(d.path().join(&temp)).unwrap(),
            b"theirs",
            "the file renamed onto the fresh name was removed"
        );
    }

    /// Where names cannot be swapped, the new file renamed into place is
    /// answered as written only when the name then holds the file written,
    /// holding exactly the bytes written: once the last check passed
    /// (`Checked`), another file put under the temporary name, or the new
    /// file written into in place, makes the call fail (`changed`).
    #[test]
    fn a_rename_into_place_answers_only_for_the_file_and_bytes_written() {
        for how in ["replaced", "written into"] {
            let d = tempfile::tempdir_in("/tmp").unwrap();
            let dir = File::open(d.path()).unwrap();
            let p = d.path().join("settings.json");
            std::fs::write(&p, b"before").unwrap();
            let stamp = FileStamp::of(&std::fs::symlink_metadata(&p).unwrap());
            let mut fill = |w: &mut dyn Write| w.write_all(b"rewritten").map_err(|e| io(&e));
            let mut did = 0;
            let e = replace_in_using(
                cannot_swap,
                &dir,
                Path::new("settings.json"),
                OsStr::new("settings.json"),
                &mut fill,
                &stamp,
                None,
                &mut |at| {
                    if at != Inside::Checked {
                        return;
                    }
                    let temp = temp_of(d.path(), "settings.json", "swap");
                    match how {
                        "replaced" => put_under(d.path(), &temp, b"theirs"),
                        _ => write_into(&d.path().join(&temp), b"THEM"),
                    }
                    did += 1;
                },
            )
            .unwrap_err();
            assert_eq!(did, 1, "{how}");
            assert_eq!(e.kind, ModifyErrorKind::Changed, "{how}");
            let theirs: &[u8] = if how == "replaced" {
                b"theirs"
            } else {
                b"THEMitten"
            };
            assert_eq!(std::fs::read(&p).unwrap(), theirs, "{how}");
        }
    }

    /// A move to a fresh name never replaces a file that has that name: it
    /// fails, and both files stay as they were.
    #[test]
    fn a_move_aside_never_replaces_a_file() {
        let d = tempfile::tempdir_in("/tmp").unwrap();
        let dir = File::open(d.path()).unwrap();
        std::fs::write(d.path().join("a"), b"to move").unwrap();
        std::fs::write(d.path().join("b"), b"there first").unwrap();
        let e = move_aside(&dir, OsStr::new("a"), OsStr::new("b")).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(d.path().join("a")).unwrap(), b"to move");
        assert_eq!(std::fs::read(d.path().join("b")).unwrap(), b"there first");
        move_aside(&dir, OsStr::new("a"), OsStr::new("c")).unwrap();
        assert_eq!(std::fs::read(d.path().join("c")).unwrap(), b"to move");
    }

    /// Every move to a fresh temporary name replaces nothing that took the
    /// name first: a file put under the name a removal moves the file to
    /// (`del`), under the name a replacement hands its new file to the swap
    /// under (`swap`), and under the name a restore moves an earlier one's
    /// leftover to (`new`) stays as it was. The removal and the
    /// replacement fail and change nothing; the restore keeps the leftover
    /// under its name and still writes the file back.
    #[test]
    fn no_move_to_a_fresh_name_replaces_a_file_there() {
        let d = tempfile::tempdir_in("/tmp").unwrap();
        let dir = d.path();
        let r = crate::open_root(dir).unwrap();
        let p = dir.join(".env");
        std::fs::write(&p, b"A=1\n").unwrap();
        let stamp = FileStamp::of(&std::fs::symlink_metadata(&p).unwrap());
        let later = SystemTime::now() + Duration::from_secs(3600);
        let planted = dir.join("..env.envcloak-del-00000000000000d1.tmp");
        std::fs::write(&planted, b"there first").unwrap();
        next_names(&[0xd1]);
        remove_checked_at(&r, Path::new(".env"), &stamp, later).unwrap_err();
        assert_eq!(std::fs::read(&p).unwrap(), b"A=1\n", "removed");
        assert_eq!(std::fs::read(&planted).unwrap(), b"there first");
        std::fs::remove_file(&planted).unwrap();

        let planted = dir.join("..env.envcloak-swap-00000000000000e2.tmp");
        std::fs::write(&planted, b"there first").unwrap();
        next_names(&[0xe1, 0xe2]);
        let e = replace_atomically(&r, Path::new(".env"), b"B=2\n", &stamp).unwrap_err();
        assert_ne!(e.kind, ModifyErrorKind::MovedAside);
        assert_eq!(std::fs::read(&p).unwrap(), b"A=1\n", "replaced");
        assert_eq!(std::fs::read(&planted).unwrap(), b"there first");
        std::fs::remove_file(&planted).unwrap();
        assert_eq!(names_in(dir), [OsStr::new(".env")]);

        let body = b"the original, backed up".to_vec();
        let mcp = dir.join(".mcp.json");
        std::fs::write(&mcp, b"what the change left").unwrap();
        let leftover = dir.join("..mcp.json.envcloak-new-00000000000000f0.tmp");
        std::fs::write(&leftover, &body[..7]).unwrap();
        let planted = dir.join("..mcp.json.envcloak-new-00000000000000f2.tmp");
        std::fs::write(&planted, b"there first").unwrap();
        let file = crate::BackedUpFile {
            size: body.len() as u64,
            sha256: Sha256::digest(&body).into(),
            sha256_after: Sha256::digest(b"what the change left").into(),
        };
        next_names(&[0xf1, 0xf2, 0xf3]);
        crate::restore_over_left(&r, Path::new(".mcp.json"), &file, &mut |_| {
            Some(envcloak_core::SecretBytes::copy_from(&body))
        })
        .unwrap();
        assert_eq!(std::fs::read(&mcp).unwrap(), body);
        assert_eq!(std::fs::read(&planted).unwrap(), b"there first");
        assert_eq!(std::fs::read(&leftover).unwrap(), &body[..7]);
        NEXT_HEX.with(|q| assert!(q.borrow().is_empty()));
    }

    /// Where the file system cannot move a name to a free one in one step,
    /// a move to a fresh name still never replaces a file that has it: it
    /// looks first, and fails when the name is taken, both files as they
    /// were; a free name is moved to.
    #[test]
    fn a_move_aside_without_a_no_replace_rename_still_replaces_nothing() {
        fn cannot(_: &File, _: &OsStr, _: &OsStr) -> std::io::Result<()> {
            Err(std::io::ErrorKind::Unsupported.into())
        }
        let d = tempfile::tempdir_in("/tmp").unwrap();
        let dir = File::open(d.path()).unwrap();
        std::fs::write(d.path().join("a"), b"to move").unwrap();
        std::fs::write(d.path().join("b"), b"there first").unwrap();
        let e = move_aside_using(cannot, &dir, OsStr::new("a"), OsStr::new("b")).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(d.path().join("a")).unwrap(), b"to move");
        assert_eq!(std::fs::read(d.path().join("b")).unwrap(), b"there first");
        move_aside_using(cannot, &dir, OsStr::new("a"), OsStr::new("c")).unwrap();
        assert_eq!(std::fs::read(d.path().join("c")).unwrap(), b"to move");
    }

    /// A new file is taken for the one written only when it held the bytes
    /// written all the while it was read back: one written into, in a part
    /// already read and at its length, while it is read (a hook after the
    /// first part) is not, though the bytes read make up the SHA-256
    /// written. Read again, unchanged since, it is not either; and a file
    /// left alone is.
    #[test]
    fn a_new_file_written_into_while_it_is_read_back_is_not_taken_for_it() {
        let d = tempfile::tempdir_in("/tmp").unwrap();
        let dir = File::open(d.path()).unwrap();
        let body: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let mut fill = |w: &mut dyn Write| w.write_all(&body).map_err(|e| io(&e));
        let temp = OsString::from("..env.envcloak-new-00000000000000c1.tmp");
        let staged = write_new_with(
            &dir,
            Path::new(".env"),
            OsStr::new(".env"),
            &temp,
            0o600,
            &mut fill,
        )
        .unwrap();
        assert!(staged.holds_written());
        assert!(staged.intact());
        let path = d.path().join(&temp);
        DURING_READ.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                use std::os::unix::fs::FileExt;
                let w = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
                w.write_all_at(b"X", 10).unwrap();
            }));
        });
        assert!(
            !staged.holds_written(),
            "a file written into while it was read was taken for the one written"
        );
        assert!(!staged.holds_written());
        assert!(!staged.intact());
    }

    /// A created file that keeps its temporary name too, because that name
    /// could not be removed once it was linked (its directory made
    /// read-only then, a barrier at `Linked`), is created, and the call
    /// says so (`not_removed`, naming the temporary name), never answering
    /// as if nothing were left.
    #[test]
    fn a_create_whose_temporary_name_stays_says_so() {
        let d = tempfile::tempdir_in("/tmp").unwrap();
        let dir = File::open(d.path()).unwrap();
        let name = OsStr::new("envcloak.toml");
        let mut did = 0;
        let e = create_in(
            &dir,
            Path::new("envcloak.toml"),
            name,
            b"ours",
            0o600,
            &mut |at| {
                if at == Inside::Linked {
                    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o500))
                        .unwrap();
                    did += 1;
                }
            },
        );
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(did, 1);
        let e = e.unwrap_err();
        assert_eq!(e.kind, ModifyErrorKind::NotRemoved);
        assert_eq!(std::fs::read(d.path().join(name)).unwrap(), b"ours");
        assert_eq!(std::fs::read(d.path().join(&e.rel)).unwrap(), b"ours");
        assert!(
            e.rel
                .to_string_lossy()
                .starts_with(".envcloak.toml.envcloak-new-")
        );
    }
}
