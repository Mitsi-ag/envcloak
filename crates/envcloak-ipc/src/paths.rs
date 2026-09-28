//! Where the daemon's socket lives, and the checks on its directory (SPEC
//! §4.2).
//!
//! - macOS: `~/Library/Application Support/EnvCloak/run/`.
//! - Linux: `$XDG_RUNTIME_DIR/envcloak/`. When `XDG_RUNTIME_DIR` is unset
//!   or not absolute, `$XDG_STATE_HOME/envcloak/run/` (default
//!   `~/.local/state/envcloak/run/`), and the daemon prints a warning.
//!
//! The directory holds `envcloakd.sock` and `envcloakd.lock`. It must be a
//! real directory (not a symlink), owned by the effective uid, and not
//! writable by group or others; the daemon also makes it mode 0700. Its
//! parent must belong to this uid or root and must not be writable by
//! others unless it is sticky (like `/tmp`), so no other user can rename
//! the directory away and put another in its place. A socket path longer
//! than `sun_path` allows (104 bytes on macOS, 108 on Linux, counting the
//! terminating NUL) is refused with a clear error rather than cut short.

use std::ffi::OsStr;
use std::fs::{DirBuilder, Permissions};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use envcloak_core::vault::{Platform, data_dir_for};

/// The socket's file name.
pub const SOCKET_NAME: &str = "envcloakd.sock";
/// The lock file's name. The running daemon holds an exclusive `flock` on
/// it.
pub const LOCK_NAME: &str = "envcloakd.lock";

/// The size of `sun_path` in `struct sockaddr_un`, including the
/// terminating NUL: 104 bytes on macOS, 108 on Linux.
pub const SUN_PATH_MAX: usize = if cfg!(target_os = "macos") { 104 } else { 108 };

/// The daemon's runtime directory and the files in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunPaths {
    /// The directory holding the socket and the lock.
    pub dir: PathBuf,
    /// `<dir>/envcloakd.sock`.
    pub socket: PathBuf,
    /// `<dir>/envcloakd.lock`.
    pub lock: PathBuf,
    /// Linux: `XDG_RUNTIME_DIR` was unset or relative, so the directory is
    /// under `XDG_STATE_HOME` instead. The daemon warns about it.
    pub fallback: bool,
}

impl RunPaths {
    /// The paths for the current user, from `HOME`, `XDG_RUNTIME_DIR` and
    /// `XDG_STATE_HOME`.
    ///
    /// # Errors
    /// When `HOME` is needed and not absolute, or the socket path is too
    /// long.
    pub fn for_user() -> Result<Self, RunPathError> {
        let home = std::env::var_os("HOME");
        let runtime = std::env::var_os("XDG_RUNTIME_DIR");
        let state = std::env::var_os("XDG_STATE_HOME");
        Self::resolve(
            Platform::current(),
            home.as_deref(),
            runtime.as_deref(),
            state.as_deref(),
        )
    }

    /// The paths for `platform`, given the values of `HOME`,
    /// `XDG_RUNTIME_DIR` and `XDG_STATE_HOME`. Relative values are ignored,
    /// as the XDG specification says.
    ///
    /// # Errors
    /// When `HOME` is needed and not absolute, or the socket path is too
    /// long.
    pub fn resolve(
        platform: Platform,
        home: Option<&OsStr>,
        xdg_runtime_dir: Option<&OsStr>,
        xdg_state_home: Option<&OsStr>,
    ) -> Result<Self, RunPathError> {
        fn absolute(v: Option<&OsStr>) -> Option<&Path> {
            v.map(Path::new).filter(|p| p.is_absolute())
        }
        let (dir, fallback) = match platform {
            Platform::MacOs => {
                let data = data_dir_for(platform, home, None)
                    .map_err(|_| RunPathError::new(RunPathErrorKind::NoHome))?;
                (data.join("run"), false)
            }
            Platform::Xdg => match absolute(xdg_runtime_dir) {
                Some(runtime) => (runtime.join("envcloak"), false),
                None => {
                    let state = match absolute(xdg_state_home) {
                        Some(s) => s.to_path_buf(),
                        None => absolute(home)
                            .ok_or(RunPathError::new(RunPathErrorKind::NoHome))?
                            .join(".local/state"),
                    };
                    (state.join("envcloak/run"), true)
                }
            },
        };
        let mut paths = Self::under(dir)?;
        paths.fallback = fallback;
        Ok(paths)
    }

    /// The paths in an explicit directory.
    ///
    /// # Errors
    /// [`RunPathErrorKind::SocketPathTooLong`] when the socket path would
    /// not fit in `sun_path`.
    pub fn under(dir: impl Into<PathBuf>) -> Result<Self, RunPathError> {
        let dir = dir.into();
        let socket = dir.join(SOCKET_NAME);
        if socket.as_os_str().as_bytes().len() + 1 > SUN_PATH_MAX {
            return Err(RunPathErrorKind::SocketPathTooLong.into());
        }
        Ok(RunPaths {
            lock: dir.join(LOCK_NAME),
            socket,
            dir,
            fallback: false,
        })
    }

    /// For the daemon: creates the directory (with missing ancestors) mode
    /// 0700, then checks it as [`RunPaths::check_dir`] does and tightens it
    /// to 0700 when group or others can read or search it. Call it with
    /// the umask at 077.
    ///
    /// # Errors
    /// When the directory or its parent fails the checks.
    pub fn prepare_dir(&self) -> Result<(), RunPathError> {
        match std::fs::symlink_metadata(&self.dir) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(&self.dir)?;
            }
            Err(e) => return Err(e.into()),
        }
        self.check_dir()?;
        let mode = std::fs::symlink_metadata(&self.dir)?.mode() & 0o7777;
        if mode != 0o700 {
            std::fs::set_permissions(&self.dir, Permissions::from_mode(0o700))?;
        }
        Ok(())
    }

    /// Checks, without changing anything, that the directory is one
    /// EnvCloak may trust: a real directory owned by the effective uid and
    /// not writable by group or others, in a parent that belongs to this
    /// uid or root and is not writable by others unless sticky.
    ///
    /// # Errors
    /// [`RunPathErrorKind::Missing`] when it does not exist, or the kind of
    /// check that failed.
    pub fn check_dir(&self) -> Result<(), RunPathError> {
        let uid = envcloak_sys::effective_uid();
        let m = std::fs::symlink_metadata(&self.dir)?;
        if m.file_type().is_symlink() {
            return Err(RunPathErrorKind::Symlink.into());
        }
        if !m.is_dir() {
            return Err(RunPathErrorKind::NotDirectory.into());
        }
        if m.uid() != uid {
            return Err(RunPathErrorKind::ForeignOwner.into());
        }
        if m.mode() & 0o022 != 0 {
            return Err(RunPathErrorKind::OpenPermissions.into());
        }
        let parent = self
            .dir
            .parent()
            .ok_or(RunPathError::new(RunPathErrorKind::OpenParent))?;
        let p = std::fs::metadata(parent)?;
        let sticky = p.mode() & 0o1000 != 0;
        if (p.uid() != uid && p.uid() != 0) || (p.mode() & 0o022 != 0 && !sticky) {
            return Err(RunPathErrorKind::OpenParent.into());
        }
        Ok(())
    }

    /// Checks that the socket file is a socket owned by the effective uid
    /// (a cheap first check; the peer's uid is what counts).
    ///
    /// # Errors
    /// [`RunPathErrorKind::Missing`] when there is no socket, or the kind
    /// of check that failed.
    pub fn check_socket(&self) -> Result<(), RunPathError> {
        let m = std::fs::symlink_metadata(&self.socket)?;
        if m.file_type().is_symlink() {
            return Err(RunPathErrorKind::Symlink.into());
        }
        if !m.file_type().is_socket() {
            return Err(RunPathErrorKind::NotSocket.into());
        }
        if m.uid() != envcloak_sys::effective_uid() {
            return Err(RunPathErrorKind::ForeignOwner.into());
        }
        Ok(())
    }
}

/// A refused runtime location. Carries its kind only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunPathError {
    kind: RunPathErrorKind,
}

/// Why a runtime location was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RunPathErrorKind {
    /// `HOME` is unset or not absolute, and the location needs it.
    NoHome,
    /// The socket path does not fit in `sun_path`.
    SocketPathTooLong,
    /// The directory or socket does not exist.
    Missing,
    Symlink,
    NotDirectory,
    NotSocket,
    /// Owned by another uid.
    ForeignOwner,
    /// The directory is writable by group or others.
    OpenPermissions,
    /// The parent directory belongs to another user, or others can write
    /// to it and it is not sticky.
    OpenParent,
    /// Another filesystem error.
    Io(io::ErrorKind),
}

impl RunPathErrorKind {
    /// The fixed message for this kind.
    pub fn message(self) -> &'static str {
        match self {
            RunPathErrorKind::NoHome => "HOME is not set to an absolute path",
            RunPathErrorKind::SocketPathTooLong => {
                "the daemon socket path is too long for a Unix socket (104 bytes on macOS, \
                 108 on Linux); use a shorter HOME or XDG_RUNTIME_DIR"
            }
            RunPathErrorKind::Missing => "the daemon's runtime directory or socket does not exist",
            RunPathErrorKind::Symlink => {
                "the daemon's runtime directory or socket is a symbolic link; EnvCloak does not \
                 follow them"
            }
            RunPathErrorKind::NotDirectory => "the daemon's runtime directory is not a directory",
            RunPathErrorKind::NotSocket => "the daemon socket path is not a socket",
            RunPathErrorKind::ForeignOwner => {
                "the daemon's runtime directory or socket belongs to another user"
            }
            RunPathErrorKind::OpenPermissions => {
                "the daemon's runtime directory is writable by other users; make it mode 0700"
            }
            RunPathErrorKind::OpenParent => {
                "the directory holding the daemon's runtime directory belongs to another user \
                 or is writable by other users"
            }
            RunPathErrorKind::Io(_) => "the daemon's runtime directory cannot be accessed",
        }
    }
}

impl RunPathError {
    const fn new(kind: RunPathErrorKind) -> Self {
        RunPathError { kind }
    }

    pub fn kind(&self) -> RunPathErrorKind {
        self.kind
    }
}

impl From<RunPathErrorKind> for RunPathError {
    fn from(kind: RunPathErrorKind) -> Self {
        RunPathError::new(kind)
    }
}

impl From<io::Error> for RunPathError {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::NotFound => RunPathErrorKind::Missing.into(),
            k => RunPathErrorKind::Io(k).into(),
        }
    }
}

impl core::fmt::Display for RunPathError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.kind.message())
    }
}

impl std::error::Error for RunPathError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(s: &str) -> Option<&OsStr> {
        Some(OsStr::new(s))
    }

    #[test]
    fn each_platform_has_its_location() {
        let mac = RunPaths::resolve(Platform::MacOs, os("/Users/u"), os("/r"), os("/s")).unwrap();
        assert_eq!(
            mac.dir,
            Path::new("/Users/u/Library/Application Support/EnvCloak/run")
        );
        assert_eq!(mac.socket, mac.dir.join("envcloakd.sock"));
        assert_eq!(mac.lock, mac.dir.join("envcloakd.lock"));
        assert!(!mac.fallback);

        let linux = RunPaths::resolve(Platform::Xdg, os("/home/u"), os("/run/user/1000"), None);
        let linux = linux.unwrap();
        assert_eq!(linux.dir, Path::new("/run/user/1000/envcloak"));
        assert!(!linux.fallback);
    }

    #[test]
    fn linux_without_a_runtime_dir_falls_back_to_the_state_dir() {
        for runtime in [None, os("relative/run"), os("")] {
            let p = RunPaths::resolve(Platform::Xdg, os("/home/u"), runtime, os("/state")).unwrap();
            assert_eq!(p.dir, Path::new("/state/envcloak/run"));
            assert!(p.fallback);
            let p = RunPaths::resolve(Platform::Xdg, os("/home/u"), runtime, None).unwrap();
            assert_eq!(p.dir, Path::new("/home/u/.local/state/envcloak/run"));
            assert!(p.fallback);
        }
        let e = RunPaths::resolve(Platform::Xdg, None, None, None).unwrap_err();
        assert_eq!(e.kind(), RunPathErrorKind::NoHome);
        let e = RunPaths::resolve(Platform::MacOs, os("relative"), None, None).unwrap_err();
        assert_eq!(e.kind(), RunPathErrorKind::NoHome);
    }

    #[test]
    fn socket_paths_that_do_not_fit_sun_path_are_refused() {
        // `<dir>/envcloakd.sock` plus the NUL: the longest directory that
        // fits leaves exactly SUN_PATH_MAX bytes.
        let name = SOCKET_NAME.len() + 1;
        let fits = format!("/{}", "d".repeat(SUN_PATH_MAX - name - 2));
        let p = RunPaths::under(&fits).unwrap();
        assert_eq!(p.socket.as_os_str().len() + 1, SUN_PATH_MAX);
        let too_long = format!("{fits}x");
        let e = RunPaths::under(&too_long).unwrap_err();
        assert_eq!(e.kind(), RunPathErrorKind::SocketPathTooLong);
        assert!(e.to_string().contains("too long"));
        if cfg!(target_os = "macos") {
            assert_eq!(SUN_PATH_MAX, 104);
        } else {
            assert_eq!(SUN_PATH_MAX, 108);
        }
    }
}
