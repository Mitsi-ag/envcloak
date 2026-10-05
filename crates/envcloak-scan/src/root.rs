//! The directory a scan starts from, and reading one file under it (SPEC
//! §6.4 "Filesystem safety").
//!
//! [`open_root`] opens the directory the person named (following a
//! symlink there, since they named it) and keeps its descriptor. Every
//! later step goes through that descriptor: each directory below it is
//! opened with `O_DIRECTORY | O_NOFOLLOW`, never through a symlink and
//! never onto another device (a mount point), and each file with
//! `O_NOFOLLOW | O_NONBLOCK`, so a symlink is never followed and a FIFO
//! never blocks. After a file is opened, `fstat` must show a regular file
//! owned by this user; FIFOs, sockets and devices are skipped.
//!
//! [`read_capped`] reads a file whole into a wiped buffer sized from
//! `fstat`, refuses one over the cap without reading it, and returns the
//! file's [`FileStamp`]: a file that changed while it was read is refused
//! too. The stamp is what a later replacement or removal checks against,
//! so it acts on the bytes that were read and nothing else.

use std::ffi::{OsStr, OsString};
use std::fs::{File, Metadata, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use envcloak_core::{SecretBuf, SecretBytes};
use envcloak_sys::{Volume, open_beneath, open_dir_beneath, volume_of};
use zeroize::Zeroize;

/// A directory a scan starts from.
#[derive(Debug)]
pub struct ScanRoot {
    dir: File,
    path: PathBuf,
    dev: u64,
    ino: u64,
    volume: Volume,
}

impl ScanRoot {
    /// The root's canonical path, for display and for the files written
    /// beside what was found. What is opened goes through the handle.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The open directory.
    pub fn dir(&self) -> &File {
        &self.dir
    }

    /// The device the root is on; a scan never leaves it.
    pub fn dev(&self) -> u64 {
        self.dev
    }

    /// The root's own device and inode.
    pub fn identity(&self) -> (u64, u64) {
        (self.dev, self.ino)
    }

    /// Whether the root is on a network volume. A root named explicitly is
    /// scanned wherever it is; a scan never crosses into another volume.
    pub fn volume(&self) -> Volume {
        self.volume
    }

    /// Opens the directory that holds `rel` (a relative path of plain
    /// components) and returns it with `rel`'s last component. Every
    /// directory on the way is opened beneath the one before, never
    /// through a symlink and never onto another device.
    pub fn open_parent(&self, rel: &Path) -> Result<(File, OsString), ScanErrorKind> {
        let mut parts = Vec::new();
        for c in rel.components() {
            match c {
                Component::Normal(p) => parts.push(p),
                _ => return Err(ScanErrorKind::InvalidPath),
            }
        }
        let Some((last, dirs)) = parts.split_last() else {
            return Err(ScanErrorKind::InvalidPath);
        };
        let mut dir = self.dir.try_clone().map_err(|e| io_kind(&e))?;
        for d in dirs {
            dir = self.open_subdir(&dir, d)?;
        }
        Ok((dir, (*last).to_owned()))
    }

    /// Opens the subdirectory `name` of `dir`, which is under this root:
    /// never through a symlink, and never onto another device.
    pub fn open_subdir(&self, dir: &File, name: &OsStr) -> Result<File, ScanErrorKind> {
        let sub = open_dir_beneath(dir, name).map_err(|e| match e.raw_os_error() {
            Some(libc::ELOOP) => ScanErrorKind::Symlink,
            // macOS says ENOTDIR for a symlink too: tell the two apart
            // without following it.
            Some(libc::ENOTDIR) => match open_beneath(dir, name) {
                Err(e) if e.raw_os_error() == Some(libc::ELOOP) => ScanErrorKind::Symlink,
                _ => ScanErrorKind::NotRegular,
            },
            _ => io_kind(&e),
        })?;
        let m = sub.metadata().map_err(|e| io_kind(&e))?;
        if m.dev() != self.dev {
            return Err(ScanErrorKind::MountPoint);
        }
        Ok(sub)
    }
}

/// Opens `p` as a scan root. `p` may be a symlink: the person named it.
///
/// # Errors
/// When `p` is not a directory that can be opened, or its canonical path
/// names another directory than the one opened.
pub fn open_root(p: &Path) -> std::io::Result<ScanRoot> {
    let path = std::fs::canonicalize(p)?;
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(&path)?;
    let m = dir.metadata()?;
    if !m.is_dir() {
        return Err(std::io::ErrorKind::NotADirectory.into());
    }
    // The path is for display and for writing beside what was found: it
    // must name the directory opened.
    let again = std::fs::metadata(&path)?;
    if (again.dev(), again.ino()) != (m.dev(), m.ino()) {
        return Err(std::io::ErrorKind::Other.into());
    }
    let volume = volume_of(&dir)?;
    Ok(ScanRoot {
        dir,
        path,
        dev: m.dev(),
        ino: m.ino(),
        volume,
    })
}

/// What identifies a file's contents on disk: when any of these changed,
/// someone wrote, replaced, linked or re-permissioned it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileStamp {
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub mtime: i64,
    pub mtime_nsec: i64,
    pub ctime: i64,
    pub ctime_nsec: i64,
    pub mode: u32,
    pub nlink: u64,
    pub uid: u32,
}

impl FileStamp {
    pub fn of(m: &Metadata) -> Self {
        FileStamp {
            dev: m.dev(),
            ino: m.ino(),
            size: m.size(),
            mtime: m.mtime(),
            mtime_nsec: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_nsec: m.ctime_nsec(),
            mode: m.mode(),
            nlink: m.nlink(),
            uid: m.uid(),
        }
    }

    /// Whole seconds since the contents last changed, at `now`; `None` when
    /// the modification time is in the future.
    pub fn age_at(&self, now: SystemTime) -> Option<u64> {
        let now = now.duration_since(UNIX_EPOCH).ok()?.as_secs();
        let now = i64::try_from(now).ok()?;
        u64::try_from(now.checked_sub(self.mtime)?).ok()
    }
}

/// Why a file or directory was skipped, or a change refused. Carries no
/// text from the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ScanErrorKind {
    /// A symlink: never followed.
    Symlink,
    /// A FIFO, socket, device or directory where a file was expected.
    NotRegular,
    /// Owned by another user.
    NotOwned,
    /// Over the size cap; not read.
    TooLarge,
    /// Permission denied.
    Unreadable,
    NotFound,
    /// It changed while it was read.
    Changed,
    /// Another device: a scan never crosses a mount point.
    MountPoint,
    /// A directory with more entries than a scan reads.
    TooManyEntries,
    /// Deeper than the scan goes.
    TooDeep,
    /// Not a relative path of plain components.
    InvalidPath,
    /// `.env.<suffix>` whose suffix makes no profile name.
    ProfileName,
    /// A file an interrupted change of an env file left under a temporary
    /// name (`..env.envcloak-del-<hex>.tmp`): it may hold plaintext.
    Leftover,
    /// Any other failure, by its kind.
    Io(std::io::ErrorKind),
}

impl ScanErrorKind {
    /// A stable token for reports.
    pub fn token(self) -> &'static str {
        match self {
            ScanErrorKind::Symlink => "symlink",
            ScanErrorKind::NotRegular => "not_regular",
            ScanErrorKind::NotOwned => "not_owned",
            ScanErrorKind::TooLarge => "too_large",
            ScanErrorKind::Unreadable => "unreadable",
            ScanErrorKind::NotFound => "not_found",
            ScanErrorKind::Changed => "changed",
            ScanErrorKind::MountPoint => "mount_point",
            ScanErrorKind::TooManyEntries => "too_many_entries",
            ScanErrorKind::TooDeep => "too_deep",
            ScanErrorKind::InvalidPath => "invalid_path",
            ScanErrorKind::ProfileName => "not_a_profile_name",
            ScanErrorKind::Leftover => "leftover",
            ScanErrorKind::Io(_) => "io",
        }
    }

    /// The fixed message.
    pub fn message(self) -> &'static str {
        match self {
            ScanErrorKind::Symlink => "a symlink, which is never followed",
            ScanErrorKind::NotRegular => "not a regular file (a FIFO, socket, device or directory)",
            ScanErrorKind::NotOwned => "owned by another user",
            ScanErrorKind::TooLarge => "larger than 1 MiB, so it was not read",
            ScanErrorKind::Unreadable => "permission denied",
            ScanErrorKind::NotFound => "not found",
            ScanErrorKind::Changed => "it changed while it was read",
            ScanErrorKind::MountPoint => "on another volume, which a scan never enters",
            ScanErrorKind::TooManyEntries => "a directory with too many entries to scan",
            ScanErrorKind::TooDeep => "deeper than a scan goes",
            ScanErrorKind::InvalidPath => "not a relative path of plain names",
            ScanErrorKind::ProfileName => {
                "the part after .env. makes no profile name (lowercase letters, digits, _, - or .)"
            }
            ScanErrorKind::Leftover => {
                "left by an interrupted change of an env file, and may hold plaintext: look at \
                 it, then delete it"
            }
            ScanErrorKind::Io(_) => "it could not be read",
        }
    }
}

/// A path under the root, and what went wrong there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanError {
    /// Relative to the root.
    pub rel: PathBuf,
    pub kind: ScanErrorKind,
}

impl core::fmt::Display for ScanError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {}", self.rel.display(), self.kind.message())
    }
}

impl std::error::Error for ScanError {}

pub(crate) fn io_kind(e: &std::io::Error) -> ScanErrorKind {
    match e.raw_os_error() {
        Some(libc::EACCES | libc::EPERM) => ScanErrorKind::Unreadable,
        Some(libc::ENOENT) => ScanErrorKind::NotFound,
        Some(libc::ELOOP) => ScanErrorKind::Symlink,
        _ => ScanErrorKind::Io(e.kind()),
    }
}

/// Opens the file `name` in `dir` as a scan does, and checks it is a
/// regular file of this user no larger than `cap`. Returns it with its
/// metadata.
pub(crate) fn open_file(
    dir: &File,
    name: &OsStr,
    cap: usize,
) -> Result<(File, Metadata), ScanErrorKind> {
    let f = open_beneath(dir, name).map_err(|e| io_kind(&e))?;
    let m = f.metadata().map_err(|e| io_kind(&e))?;
    if !m.file_type().is_file() {
        return Err(ScanErrorKind::NotRegular);
    }
    if m.uid() != envcloak_sys::effective_uid() {
        return Err(ScanErrorKind::NotOwned);
    }
    if m.len() > cap as u64 {
        return Err(ScanErrorKind::TooLarge);
    }
    Ok((f, m))
}

/// [`read_capped`] for a file that holds no secret (`.gitignore`,
/// `envcloak.toml`): the same checks, into an ordinary buffer the caller
/// can read.
pub fn read_plain(r: &ScanRoot, rel: &Path, cap: usize) -> Result<(Vec<u8>, FileStamp), ScanError> {
    let fail = |kind| ScanError {
        rel: rel.to_path_buf(),
        kind,
    };
    let (dir, name) = r.open_parent(rel).map_err(fail)?;
    let (f, m) = open_file(&dir, &name, cap).map_err(fail)?;
    let stamp = FileStamp::of(&m);
    let mut out = Vec::with_capacity(usize::try_from(m.len()).unwrap_or(0));
    (&f).take(cap as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| fail(io_kind(&e)))?;
    let after = f.metadata().map_err(|e| fail(io_kind(&e)))?;
    if out.len() as u64 != m.len() || FileStamp::of(&after) != stamp {
        return Err(fail(ScanErrorKind::Changed));
    }
    Ok((out, stamp))
}

/// Reads the file at `rel` under `r` whole, if it is a regular file of
/// this user of at most `cap` bytes, into a wiped buffer. Returns the
/// bytes and the file's stamp, which is the same before and after the
/// read, or the read is refused with [`ScanErrorKind::Changed`].
pub fn read_capped(
    r: &ScanRoot,
    rel: &Path,
    cap: usize,
) -> Result<(SecretBytes, FileStamp), ScanError> {
    let fail = |kind| ScanError {
        rel: rel.to_path_buf(),
        kind,
    };
    let (dir, name) = r.open_parent(rel).map_err(fail)?;
    let (mut f, m) = open_file(&dir, &name, cap).map_err(fail)?;
    if m.dev() != r.dev() {
        return Err(fail(ScanErrorKind::MountPoint));
    }
    let stamp = FileStamp::of(&m);
    let size = usize::try_from(m.len()).map_err(|_| fail(ScanErrorKind::TooLarge))?;
    let mut buf = SecretBuf::with_capacity(size);
    buf.read_exact_from(&mut f, size).map_err(|e| {
        fail(if e.kind() == std::io::ErrorKind::UnexpectedEof {
            ScanErrorKind::Changed
        } else {
            io_kind(&e)
        })
    })?;
    // One byte more means the file grew while it was read.
    let mut probe = [0u8; 1];
    let more = f.read(&mut probe);
    probe.zeroize();
    match more {
        Ok(0) => {}
        Ok(_) => return Err(fail(ScanErrorKind::Changed)),
        Err(e) => return Err(fail(io_kind(&e))),
    }
    let after = f.metadata().map_err(|e| fail(io_kind(&e)))?;
    if FileStamp::of(&after) != stamp {
        return Err(fail(ScanErrorKind::Changed));
    }
    Ok((buf.freeze(), stamp))
}

/// A directory already opened component by component by a catalog scan.
pub(crate) fn held_root(path: PathBuf, dir: File) -> std::io::Result<ScanRoot> {
    let m = dir.metadata()?;
    Ok(ScanRoot {
        volume: volume_of(&dir)?,
        dir,
        path,
        dev: m.dev(),
        ino: m.ino(),
    })
}

#[cfg(test)]
mod scanner_device_tests {
    use super::*;
    /// Recording model of a file mount: the opened leaf's device differs
    /// from the held root. No mounts or privileged host state are changed.
    #[test]
    fn leaf_mount_is_refused_before_reading() {
        let dir = tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).expect("temporary root")).expect("fixture");
        std::fs::write(dir.path().join("profile"), b"fixture-value").expect("write");
        let mut root = open_root(dir.path()).expect("root");
        assert!(read_capped(&root, Path::new("profile"), 64).is_ok());
        root.dev = root.dev.wrapping_add(1);
        assert_eq!(
            read_capped(&root, Path::new("profile"), 64)
                .expect_err("mount refused")
                .kind,
            ScanErrorKind::MountPoint
        );
    }
}
