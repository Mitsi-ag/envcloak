//! Names beneath a directory the caller holds open (SPEC §6.4 "Filesystem
//! safety": scans and the files `envcloak init` writes or removes go
//! through a directory handle, never through a symlink).
//!
//! A path is looked up again on every use, so a directory checked by path
//! can be swapped before a name in it is used. Every function here works
//! on one name inside a directory the caller already holds open
//! ([`crate::open_beneath`] opens a file there): [`list_dir`] reads its
//! entries, [`kind_beneath`] says what one is, [`read_link_beneath`] reads
//! a symlink's target, [`open_dir_beneath`] opens a subdirectory, and
//! [`create_beneath`], [`create_rw_beneath`], [`create_dir_beneath`],
//! [`link_beneath`], [`rename_beneath`], [`rename_new_beneath`],
//! [`exchange_beneath`], [`unlink_beneath`] and [`remove_dir_beneath`]
//! make, link, move, swap and remove names in it. None of them follows a
//! symlink in the name's place. [`volume_of`] says whether the directory
//! is on a network volume.
//!
//! Every name must be one path component: not empty, not `.` or `..`, and
//! without `/` or NUL, or the call fails with
//! [`io::ErrorKind::InvalidInput`].

use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};

/// The most entries [`list_dir`] is asked to read by the scanner. A
/// directory with more is refused, so one huge directory cannot hold the
/// scanner's memory.
pub const MAX_DIR_ENTRIES: usize = 100_000;

/// What `readdir(3)` says an entry is. A hint only: some file systems
/// report [`DirEntryKind::Unknown`], and the entry can change before it is
/// opened, so callers check what they open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DirEntryKind {
    File,
    Dir,
    Symlink,
    /// A FIFO, socket or device.
    Other,
    Unknown,
}

/// One entry of a directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntryName {
    pub name: OsString,
    pub kind: DirEntryKind,
}

/// The kind of volume a directory is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Volume {
    Local,
    /// A network or remote file system (NFS, SMB, AFP, WebDAV, and on
    /// Linux FUSE too, which cloud-storage mounts use).
    Network,
}

/// The name as a C string, after checking it is one plain component.
fn component(name: &OsStr) -> io::Result<CString> {
    let b = name.as_bytes();
    if b.is_empty() || b == b"." || b == b".." || b.contains(&b'/') {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    CString::new(b).map_err(|_| io::ErrorKind::InvalidInput.into())
}

/// A descriptor returned by a call that gives -1 on failure.
fn owned(fd: libc::c_int) -> io::Result<File> {
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by the kernel, is open, and nothing
    // else owns it.
    Ok(File::from(unsafe { OwnedFd::from_raw_fd(fd) }))
}

/// A call's result, retried on `EINTR`.
fn retry(mut f: impl FnMut() -> libc::c_int) -> io::Result<libc::c_int> {
    loop {
        let r = f();
        if r != -1 {
            return Ok(r);
        }
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EINTR) {
            return Err(e);
        }
    }
}

/// Opens the subdirectory `name` of `dir`, read-only, with `openat(2)` and
/// `O_DIRECTORY | O_NOFOLLOW`: a symlink in its place fails (`ELOOP`, or
/// `ENOTDIR` on some systems) and anything but a directory fails with
/// `ENOTDIR`.
pub fn open_dir_beneath(dir: &File, name: &OsStr) -> io::Result<File> {
    let c = component(name)?;
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // SAFETY: `dir` keeps its descriptor open for the call, and `c` is a
    // NUL-terminated string that outlives it.
    let fd = retry(|| unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), flags) })?;
    owned(fd)
}

/// What `name` in `dir` is now, from `fstatat(2)` with
/// `AT_SYMLINK_NOFOLLOW`: a symlink is [`DirEntryKind::Symlink`], never
/// what it points at. For an entry [`list_dir`] reported as
/// [`DirEntryKind::Unknown`]. It can change before it is opened, so
/// callers still check what they open.
pub fn kind_beneath(dir: &File, name: &OsStr) -> io::Result<DirEntryKind> {
    let c = component(name)?;
    // SAFETY: stat is plain data, for which all zeros is a valid value.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `dir` keeps its descriptor open for the call, `c` is a
    // NUL-terminated string that outlives it, and `st` is a writable stat.
    retry(|| unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            c.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    })?;
    Ok(match st.st_mode & libc::S_IFMT {
        libc::S_IFREG => DirEntryKind::File,
        libc::S_IFDIR => DirEntryKind::Dir,
        libc::S_IFLNK => DirEntryKind::Symlink,
        _ => DirEntryKind::Other,
    })
}

/// The longest symlink target [`read_link_beneath`] reads.
const MAX_LINK: usize = 1 << 16;

/// The target of the symlink `name` in `dir`, with `readlinkat(2)`: the
/// link itself is read, never followed. Fails with `EINVAL` when `name`
/// is not a symlink, and with [`io::ErrorKind::InvalidData`] when the
/// target is longer than 64 KiB.
pub fn read_link_beneath(dir: &File, name: &OsStr) -> io::Result<OsString> {
    let c = component(name)?;
    let mut cap = 256;
    loop {
        let mut buf = vec![0u8; cap];
        // SAFETY: `dir` keeps its descriptor open for the call, `c` is
        // NUL-terminated and outlives it, and `buf` is `cap` writable,
        // initialized bytes, of which readlinkat writes at most `cap`.
        let n =
            unsafe { libc::readlinkat(dir.as_raw_fd(), c.as_ptr(), buf.as_mut_ptr().cast(), cap) };
        let Ok(n) = usize::try_from(n) else {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        };
        // A target that fills the buffer may have been cut short.
        if n < cap {
            buf.truncate(n);
            return Ok(OsString::from_vec(buf));
        }
        if cap >= MAX_LINK {
            return Err(io::ErrorKind::InvalidData.into());
        }
        cap *= 4;
    }
}

/// Creates `name` in `dir` and opens it for writing, with `O_CREAT |
/// O_EXCL | O_NOFOLLOW`: an existing name, a symlink (even a dangling one)
/// included, fails with [`io::ErrorKind::AlreadyExists`] and is never
/// opened or truncated. The file gets `mode`, less the umask.
pub fn create_beneath(dir: &File, name: &OsStr, mode: u32) -> io::Result<File> {
    create_with(dir, name, mode, libc::O_WRONLY)
}

/// [`create_beneath`], with the new file open for reading as well: what
/// was written can be read back through this descriptor, never by the
/// file's name again (another file may have taken it meanwhile).
pub fn create_rw_beneath(dir: &File, name: &OsStr, mode: u32) -> io::Result<File> {
    create_with(dir, name, mode, libc::O_RDWR)
}

/// [`create_beneath`] with `access` (`O_WRONLY` or `O_RDWR`).
fn create_with(dir: &File, name: &OsStr, mode: u32, access: libc::c_int) -> io::Result<File> {
    let c = component(name)?;
    let flags =
        access | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_NOCTTY | libc::O_CLOEXEC;
    let mode = libc::c_uint::from(u16::try_from(mode & 0o7777).unwrap_or(0o600));
    // SAFETY: as in `open_dir_beneath`; the mode is passed as the variadic
    // argument openat reads when O_CREAT is set.
    let fd = retry(|| unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), flags, mode) })?;
    owned(fd)
}

/// Makes the directory `name` in `dir` with `mkdirat(2)`, with `mode`
/// less the umask. An existing name, a symlink (even a dangling one)
/// included, fails with [`io::ErrorKind::AlreadyExists`]: nothing is made
/// where it points. The new directory is in `dir` itself, whatever names
/// `dir`'s path by then.
pub fn create_dir_beneath(dir: &File, name: &OsStr, mode: u32) -> io::Result<()> {
    let c = component(name)?;
    let mode = libc::mode_t::from(u16::try_from(mode & 0o7777).unwrap_or(0o700));
    // SAFETY: `dir` keeps its descriptor open for the call, and `c` is a
    // NUL-terminated string that outlives it.
    retry(|| unsafe { libc::mkdirat(dir.as_raw_fd(), c.as_ptr(), mode) }).map(drop)
}

/// Removes the name `name` from `dir` with `unlinkat(2)`. A symlink is
/// removed itself, never its target. Directories are not removed.
pub fn unlink_beneath(dir: &File, name: &OsStr) -> io::Result<()> {
    let c = component(name)?;
    // SAFETY: `dir` keeps its descriptor open for the call, and `c`
    // outlives it.
    retry(|| unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), 0) }).map(drop)
}

/// Removes the empty directory `name` from `dir` with `unlinkat(2)` and
/// `AT_REMOVEDIR`. A symlink in its place is never followed: it fails
/// (`ENOTDIR`), and so does a directory with anything left in it
/// (`ENOTEMPTY`, or `EEXIST` on some systems).
pub fn remove_dir_beneath(dir: &File, name: &OsStr) -> io::Result<()> {
    let c = component(name)?;
    // SAFETY: `dir` keeps its descriptor open for the call, and `c`
    // outlives it.
    retry(|| unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), libc::AT_REMOVEDIR) }).map(drop)
}

/// Moves `from` to `to`, both in `dir`, with `renameat(2)`: `to` is
/// replaced atomically when it exists.
pub fn rename_beneath(dir: &File, from: &OsStr, to: &OsStr) -> io::Result<()> {
    let (a, b) = (component(from)?, component(to)?);
    let fd = dir.as_raw_fd();
    // SAFETY: `dir` keeps its descriptor open for the call; both names are
    // NUL-terminated and outlive it.
    retry(|| unsafe { libc::renameat(fd, a.as_ptr(), fd, b.as_ptr()) }).map(drop)
}

/// Moves `from` to `to`, both in `dir`, only while nothing has the name
/// `to`, in one step: Linux `renameat2(2)` with `RENAME_NOREPLACE`, macOS
/// `renameatx_np(2)` with `RENAME_EXCL`. Whatever takes `to` first, a
/// symlink (even a dangling one) included, keeps it, and the call fails
/// with [`io::ErrorKind::AlreadyExists`]. A file system that cannot (some
/// network and FUSE ones, a kernel before 3.15) fails with
/// [`io::ErrorKind::Unsupported`], having changed nothing.
pub fn rename_new_beneath(dir: &File, from: &OsStr, to: &OsStr) -> io::Result<()> {
    let (a, b) = (component(from)?, component(to)?);
    let fd = dir.as_raw_fd();
    // SAFETY: as in `rename_beneath`; the flags are the constant the
    // system defines for a rename that replaces nothing.
    #[cfg(target_os = "linux")]
    let moved = retry(|| unsafe {
        libc::renameat2(fd, a.as_ptr(), fd, b.as_ptr(), libc::RENAME_NOREPLACE)
    });
    // SAFETY: as above.
    #[cfg(target_os = "macos")]
    let moved =
        retry(|| unsafe { libc::renameatx_np(fd, a.as_ptr(), fd, b.as_ptr(), libc::RENAME_EXCL) });
    moved.map(drop).map_err(unsupported)
}

/// `e`, or [`io::ErrorKind::Unsupported`] for the codes a file system
/// gives for a rename flag it does not implement.
fn unsupported(e: io::Error) -> io::Error {
    let codes = [libc::EINVAL, libc::ENOSYS, libc::ENOTSUP, libc::EOPNOTSUPP];
    if e.raw_os_error().is_some_and(|c| codes.contains(&c)) {
        io::ErrorKind::Unsupported.into()
    } else {
        e
    }
}

/// Swaps the names `a` and `b` in `dir` in one step: each then names what
/// the other named, and no moment passes with either missing. Linux
/// `renameat2(2)` with `RENAME_EXCHANGE`, macOS `renameatx_np(2)` with
/// `RENAME_SWAP`. Both names must exist. A file system that cannot swap
/// (macOS HFS+, some network and FUSE ones, a kernel before 3.15) fails
/// with [`io::ErrorKind::Unsupported`], having changed nothing.
pub fn exchange_beneath(dir: &File, a: &OsStr, b: &OsStr) -> io::Result<()> {
    let (x, y) = (component(a)?, component(b)?);
    let fd = dir.as_raw_fd();
    // SAFETY: as in `rename_beneath`; the flags are the constant the
    // system defines for a swap.
    #[cfg(target_os = "linux")]
    let swapped =
        retry(|| unsafe { libc::renameat2(fd, x.as_ptr(), fd, y.as_ptr(), libc::RENAME_EXCHANGE) });
    // SAFETY: as above.
    #[cfg(target_os = "macos")]
    let swapped =
        retry(|| unsafe { libc::renameatx_np(fd, x.as_ptr(), fd, y.as_ptr(), libc::RENAME_SWAP) });
    swapped.map(drop).map_err(unsupported)
}

/// Gives the file `from` in `dir` a second name `to` there, with
/// `linkat(2)` without following a symlink at `from`. Fails with
/// [`io::ErrorKind::AlreadyExists`] when `to` exists, so it creates a file
/// with its whole content in one step or not at all.
pub fn link_beneath(dir: &File, from: &OsStr, to: &OsStr) -> io::Result<()> {
    let (a, b) = (component(from)?, component(to)?);
    let fd = dir.as_raw_fd();
    // SAFETY: as in `rename_beneath`.
    retry(|| unsafe { libc::linkat(fd, a.as_ptr(), fd, b.as_ptr(), 0) }).map(drop)
}

#[cfg(target_os = "macos")]
fn errno_location() -> *mut libc::c_int {
    // SAFETY: __error returns the calling thread's errno slot.
    unsafe { libc::__error() }
}

#[cfg(target_os = "linux")]
fn errno_location() -> *mut libc::c_int {
    // SAFETY: __errno_location returns the calling thread's errno slot.
    unsafe { libc::__errno_location() }
}

/// A `DIR` stream, closed on drop.
struct DirStream(*mut libc::DIR);

impl Drop for DirStream {
    fn drop(&mut self) {
        // SAFETY: the stream came from fdopendir, is not used after this,
        // and closedir also closes the descriptor it took.
        unsafe { libc::closedir(self.0) };
    }
}

/// The entries of `dir`, without `.` and `..`, in the order the file
/// system gives them. Reads through a duplicate of the descriptor, from
/// the start, so `dir` can be listed again.
///
/// # Errors
/// [`io::ErrorKind::OutOfMemory`] when the directory has more than `cap`
/// entries, and any failure of `readdir(3)`.
pub fn list_dir(dir: &File, cap: usize) -> io::Result<Vec<DirEntryName>> {
    // SAFETY: `dir` keeps its descriptor open for the call; F_DUPFD_CLOEXEC
    // returns a new descriptor or -1.
    let dup = retry(|| unsafe { libc::fcntl(dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) })?;
    // SAFETY: `dup` is a descriptor this function owns; fdopendir takes it
    // over on success.
    let stream = unsafe { libc::fdopendir(dup) };
    if stream.is_null() {
        let e = io::Error::last_os_error();
        // SAFETY: fdopendir failed, so `dup` is still ours to close.
        unsafe { libc::close(dup) };
        return Err(e);
    }
    let stream = DirStream(stream);
    // The duplicate shares its offset with `dir`: start from the top.
    // SAFETY: the stream is open.
    unsafe { libc::rewinddir(stream.0) };
    let mut out = Vec::new();
    loop {
        // SAFETY: errno_location points at this thread's errno; readdir
        // sets it only on failure, so it is cleared first.
        unsafe { *errno_location() = 0 };
        // SAFETY: the stream is open; the entry it returns stays valid
        // until the next readdir or closedir on it, and is copied first.
        let ent = unsafe { libc::readdir(stream.0) };
        if ent.is_null() {
            // SAFETY: as above.
            let errno = unsafe { *errno_location() };
            if errno != 0 {
                return Err(io::Error::from_raw_os_error(errno));
            }
            break;
        }
        // SAFETY: `ent` is a valid dirent whose d_name is NUL-terminated.
        let (name, d_type) = unsafe {
            (
                CStr::from_ptr((*ent).d_name.as_ptr()).to_bytes().to_vec(),
                (*ent).d_type,
            )
        };
        if name == b"." || name == b".." {
            continue;
        }
        if out.len() >= cap {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        let kind = match d_type {
            libc::DT_REG => DirEntryKind::File,
            libc::DT_DIR => DirEntryKind::Dir,
            libc::DT_LNK => DirEntryKind::Symlink,
            libc::DT_UNKNOWN => DirEntryKind::Unknown,
            _ => DirEntryKind::Other,
        };
        out.push(DirEntryName {
            name: OsString::from_vec(name),
            kind,
        });
    }
    Ok(out)
}

/// Whether `dir` is on a network volume ([`Volume::Network`]) or a local
/// one, from `fstatfs(2)`: on macOS the mount's `MNT_LOCAL` flag, on Linux
/// the file system's type.
pub fn volume_of(dir: &File) -> io::Result<Volume> {
    // SAFETY: statfs is plain data, for which all zeros is a valid value.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `dir` keeps its descriptor open for the call, and `st` is a
    // writable statfs.
    retry(|| unsafe { libc::fstatfs(dir.as_raw_fd(), &mut st) })?;
    Ok(if network(&st) {
        Volume::Network
    } else {
        Volume::Local
    })
}

#[cfg(target_os = "macos")]
fn network(st: &libc::statfs) -> bool {
    st.f_flags & (libc::MNT_LOCAL as u32) == 0
}

#[cfg(target_os = "linux")]
fn network(st: &libc::statfs) -> bool {
    // Magic numbers from linux/magic.h and the file systems' sources.
    const NETWORK: [u64; 10] = [
        0x6969,      // NFS
        0x517b,      // SMB
        0xff53_4d42, // CIFS
        0xfe53_4d42, // SMB2
        0x7375_7245, // CODA
        0x5346_414f, // AFS
        0x0102_1997, // 9P
        0x00c3_6400, // CEPH
        0x6573_5546, // FUSE: sshfs, rclone, cloud-storage clients
        0x564c,      // NCP
    ];
    #[allow(clippy::unnecessary_cast)] // f_type's width differs between targets.
    let t = (st.f_type as u64) & 0xffff_ffff;
    NETWORK.contains(&t)
}
