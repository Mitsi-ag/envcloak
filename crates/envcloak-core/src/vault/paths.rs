//! Where the vault lives, and the checks on its directories (SPEC §5
//! "Vault").
//!
//! The data directory is `~/Library/Application Support/EnvCloak/` on macOS
//! and `$XDG_DATA_HOME/envcloak/` (default `~/.local/share/envcloak/`) on
//! Linux. It holds `vault/vault.db`, `audit/` and `backups/`. Every
//! directory is 0700 and every file 0600.
//!
//! A directory or file EnvCloak trusts must be a real directory or regular
//! file (not a symlink), owned by the effective uid, and not writable by
//! group or others. One that is merely readable by others is tightened; one
//! that fails the other checks is refused, because another user may already
//! have changed what is inside.

use std::ffi::OsStr;
use std::fs::{DirBuilder, Permissions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// The vault's locations under one data directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultPaths {
    /// `~/Library/Application Support/EnvCloak` or `$XDG_DATA_HOME/envcloak`.
    pub data_dir: PathBuf,
    /// `<data>/vault`, which holds the database and SQLite's own files.
    pub vault_dir: PathBuf,
    /// `<data>/vault/vault.db`.
    pub db: PathBuf,
    /// `<data>/audit`.
    pub audit_dir: PathBuf,
    /// `<data>/backups`.
    pub backups_dir: PathBuf,
}

/// The platform whose data directory convention applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    MacOs,
    /// Linux and other Unix systems: the XDG base directories.
    Xdg,
}

impl Platform {
    pub fn current() -> Self {
        if cfg!(target_os = "macos") {
            Platform::MacOs
        } else {
            Platform::Xdg
        }
    }
}

impl VaultPaths {
    /// The paths for the current user, from `HOME` and, off macOS,
    /// `XDG_DATA_HOME`.
    pub fn for_user() -> Result<Self, PathError> {
        let home = std::env::var_os("HOME");
        let xdg = std::env::var_os("XDG_DATA_HOME");
        data_dir_for(Platform::current(), home.as_deref(), xdg.as_deref()).map(Self::under)
    }

    /// The paths under an explicit data directory.
    pub fn under(data_dir: impl Into<PathBuf>) -> Self {
        let data_dir = data_dir.into();
        let vault_dir = data_dir.join("vault");
        VaultPaths {
            db: vault_dir.join("vault.db"),
            vault_dir,
            audit_dir: data_dir.join("audit"),
            backups_dir: data_dir.join("backups"),
            data_dir,
        }
    }

    /// Creates the data directory (and missing ancestors) and its `vault`,
    /// `audit` and `backups` directories with mode 0700, then checks each
    /// one. Sets the process umask to 077 first, so SQLite's side files and
    /// anything else created later start private too.
    ///
    /// Every directory it makes is durable when it returns: flushed into
    /// the directory that names it (`envcloak_sys::sync_file`), top down.
    /// A missing ancestor is flushed into its parent as it is made, and
    /// removed again when that flush fails, so the next call makes and
    /// flushes it again. The data directory's parent and the data
    /// directory, which names the other three, are flushed at every call,
    /// so what an earlier call made and could not flush, or a crash left
    /// unflushed, is flushed now.
    ///
    /// # Errors
    /// A directory cannot be made or flushed, or fails the checks.
    pub fn ensure_dirs(&self) -> Result<(), PathError> {
        envcloak_sys::restrict_umask();
        // The data directory's missing ancestors, nearest first.
        let mut missing = Vec::new();
        let mut up = self.data_dir.parent();
        while let Some(dir) = up.filter(|d| !d.as_os_str().is_empty()) {
            if exists_no_follow(dir)? {
                break;
            }
            missing.push(dir);
            up = dir.parent();
        }
        for dir in missing.iter().rev() {
            if make_dir(dir)? {
                if let Err(e) = sync_dir(parent_of(dir)) {
                    let _ = std::fs::remove_dir(dir);
                    return Err(e);
                }
            }
        }
        make_dir(&self.data_dir)?;
        check_private_dir(&self.data_dir)?;
        for dir in [&self.vault_dir, &self.audit_dir, &self.backups_dir] {
            make_dir(dir)?;
            check_private_dir(dir)?;
        }
        sync_dir(parent_of(&self.data_dir))?;
        sync_dir(&self.data_dir)
    }
}

/// Makes `dir` with mode 0700: whether this call made it (false when it
/// was there already).
fn make_dir(dir: &Path) -> Result<bool, PathError> {
    match DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// The directory that names `p`: its parent, or `.` for a bare name.
fn parent_of(p: &Path) -> &Path {
    match p.parent() {
        Some(up) if !up.as_os_str().is_empty() => up,
        _ => Path::new("."),
    }
}

/// Makes `dir`'s entries durable.
fn sync_dir(dir: &Path) -> Result<(), PathError> {
    envcloak_sys::sync_file(&std::fs::File::open(dir)?)?;
    Ok(())
}

/// The data directory for `platform`, given the values of `HOME` and
/// `XDG_DATA_HOME`. Relative values are ignored, as the XDG specification
/// says; a missing or relative `HOME` is an error.
pub fn data_dir_for(
    platform: Platform,
    home: Option<&OsStr>,
    xdg_data_home: Option<&OsStr>,
) -> Result<PathBuf, PathError> {
    fn absolute(v: Option<&OsStr>) -> Option<&Path> {
        v.map(Path::new).filter(|p| p.is_absolute())
    }
    if platform == Platform::Xdg {
        if let Some(xdg) = absolute(xdg_data_home) {
            return Ok(xdg.join("envcloak"));
        }
    }
    let home = absolute(home).ok_or(PathError::new(PathErrorKind::NoHome))?;
    Ok(match platform {
        Platform::MacOs => home.join("Library/Application Support/EnvCloak"),
        Platform::Xdg => home.join(".local/share/envcloak"),
    })
}

fn exists_no_follow(p: &Path) -> Result<bool, PathError> {
    match std::fs::symlink_metadata(p) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Checks that `p` is a directory EnvCloak may trust, and tightens it to
/// 0700 when group or others can read or search it.
pub(crate) fn check_private_dir(p: &Path) -> Result<(), PathError> {
    check_private(p, true)
}

/// Checks that `p` is a file EnvCloak may trust, and tightens it to 0600
/// when group or others can read it.
pub(crate) fn check_private_file(p: &Path) -> Result<(), PathError> {
    check_private(p, false)
}

fn check_private(p: &Path, dir: bool) -> Result<(), PathError> {
    let m = std::fs::symlink_metadata(p)?;
    let ft = m.file_type();
    if ft.is_symlink() {
        return Err(PathErrorKind::Symlink.into());
    }
    if dir && !ft.is_dir() {
        return Err(PathErrorKind::NotDirectory.into());
    }
    if !dir && !ft.is_file() {
        return Err(PathErrorKind::NotFile.into());
    }
    if m.uid() != envcloak_sys::effective_uid() {
        return Err(PathErrorKind::ForeignOwner.into());
    }
    let mode = m.mode() & 0o7777;
    if mode & 0o022 != 0 {
        return Err(PathErrorKind::OpenPermissions.into());
    }
    let want = if dir { 0o700 } else { 0o600 };
    if mode != want {
        std::fs::set_permissions(p, Permissions::from_mode(want))?;
    }
    Ok(())
}

/// A failed directory or file check. Carries its kind only, never the path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathError {
    kind: PathErrorKind,
}

/// Why a location was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PathErrorKind {
    /// `HOME` is unset or not an absolute path.
    NoHome,
    /// The directory or file does not exist.
    Missing,
    Symlink,
    NotDirectory,
    NotFile,
    /// Owned by another uid.
    ForeignOwner,
    /// Writable by group or others.
    OpenPermissions,
    /// Another filesystem error.
    Io(io::ErrorKind),
}

impl PathErrorKind {
    pub fn message(self) -> &'static str {
        match self {
            PathErrorKind::NoHome => "HOME is not set to an absolute path",
            PathErrorKind::Missing => "a vault directory or file is missing",
            PathErrorKind::Symlink => {
                "a vault directory or file is a symbolic link; EnvCloak does not follow them"
            }
            PathErrorKind::NotDirectory => "a vault directory is not a directory",
            PathErrorKind::NotFile => "a vault file is not a regular file",
            PathErrorKind::ForeignOwner => "a vault directory or file belongs to another user",
            PathErrorKind::OpenPermissions => {
                "a vault directory or file is writable by other users; make it mode 0700 \
                 (directories) or 0600 (files)"
            }
            PathErrorKind::Io(_) => "a vault directory or file cannot be accessed",
        }
    }
}

impl PathError {
    const fn new(kind: PathErrorKind) -> Self {
        PathError { kind }
    }

    pub fn kind(&self) -> PathErrorKind {
        self.kind
    }
}

impl From<PathErrorKind> for PathError {
    fn from(kind: PathErrorKind) -> Self {
        PathError::new(kind)
    }
}

impl From<io::Error> for PathError {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::NotFound => PathErrorKind::Missing.into(),
            k => PathErrorKind::Io(k).into(),
        }
    }
}

impl core::fmt::Display for PathError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.kind.message())
    }
}

impl std::error::Error for PathError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(s: &str) -> Option<&OsStr> {
        Some(OsStr::new(s))
    }

    #[test]
    fn data_dir_follows_each_platform_convention() {
        let mac = data_dir_for(Platform::MacOs, os("/Users/u"), os("/x")).unwrap();
        assert_eq!(
            mac,
            Path::new("/Users/u/Library/Application Support/EnvCloak")
        );
        let xdg = data_dir_for(Platform::Xdg, os("/home/u"), os("/data")).unwrap();
        assert_eq!(xdg, Path::new("/data/envcloak"));
        let default = data_dir_for(Platform::Xdg, os("/home/u"), None).unwrap();
        assert_eq!(default, Path::new("/home/u/.local/share/envcloak"));
        // A relative XDG_DATA_HOME is ignored.
        let relative = data_dir_for(Platform::Xdg, os("/home/u"), os("data")).unwrap();
        assert_eq!(relative, default);
        for p in [Platform::MacOs, Platform::Xdg] {
            for home in [None, os("relative/home"), os("")] {
                let e = data_dir_for(p, home, None).unwrap_err();
                assert_eq!(e.kind(), PathErrorKind::NoHome);
            }
        }
    }

    #[test]
    fn under_lays_out_the_vault() {
        let p = VaultPaths::under("/d");
        assert_eq!(p.vault_dir, Path::new("/d/vault"));
        assert_eq!(p.db, Path::new("/d/vault/vault.db"));
        assert_eq!(p.audit_dir, Path::new("/d/audit"));
        assert_eq!(p.backups_dir, Path::new("/d/backups"));
    }

    #[test]
    fn ensure_dirs_creates_private_dirs_and_refuses_unsafe_ones() {
        let t = tempfile::tempdir().unwrap();
        let mode = |p: &Path| std::fs::symlink_metadata(p).unwrap().mode() & 0o7777;

        // Missing ancestors are created 0700 as well.
        let p = VaultPaths::under(t.path().join("a/b/envcloak"));
        p.ensure_dirs().unwrap();
        for d in [
            t.path().join("a"),
            p.data_dir.clone(),
            p.vault_dir.clone(),
            p.audit_dir.clone(),
            p.backups_dir.clone(),
        ] {
            assert_eq!(mode(&d), 0o700, "{}", d.display());
        }
        // Idempotent.
        p.ensure_dirs().unwrap();

        // Readable by others: tightened.
        std::fs::set_permissions(&p.audit_dir, Permissions::from_mode(0o755)).unwrap();
        p.ensure_dirs().unwrap();
        assert_eq!(mode(&p.audit_dir), 0o700);

        // Writable by group: refused and left alone.
        std::fs::set_permissions(&p.backups_dir, Permissions::from_mode(0o770)).unwrap();
        let e = p.ensure_dirs().unwrap_err();
        assert_eq!(e.kind(), PathErrorKind::OpenPermissions);
        assert_eq!(mode(&p.backups_dir), 0o770);
        std::fs::set_permissions(&p.backups_dir, Permissions::from_mode(0o700)).unwrap();

        // A symlinked vault directory is refused, not followed.
        let elsewhere = t.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::remove_dir(&p.vault_dir).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &p.vault_dir).unwrap();
        assert_eq!(p.ensure_dirs().unwrap_err().kind(), PathErrorKind::Symlink);

        // A file where a directory belongs.
        std::fs::remove_file(&p.vault_dir).unwrap();
        std::fs::write(&p.vault_dir, b"").unwrap();
        assert_eq!(
            p.ensure_dirs().unwrap_err().kind(),
            PathErrorKind::NotDirectory
        );
    }

    /// Review T10 open 3 (verification): every directory `ensure_dirs`
    /// makes is flushed into the directory that names it before it
    /// returns, top down. Each missing ancestor is flushed into its parent
    /// as it is made, and removed again when that flush fails, so the next
    /// call makes and flushes it again. The data directory's parent and
    /// the data directory itself, which names `vault`, `audit` and
    /// `backups`, are flushed at every call, so what an earlier call made
    /// and could not flush, or a crash left unflushed, is flushed by the
    /// next one.
    #[test]
    fn ensure_dirs_flushes_every_directory_it_makes() {
        use envcloak_sys::testing::{fail_sync_after, record_syncs, take_synced};
        let t = tempfile::tempdir().unwrap();
        let id = |p: &Path| {
            let m = std::fs::metadata(p).unwrap();
            (m.dev(), m.ino())
        };

        // Missing ancestors: each flushed into its parent, then the data
        // directory's parent and the data directory.
        let p = VaultPaths::under(t.path().join("a/b/envcloak"));
        let (a, b) = (t.path().join("a"), t.path().join("a/b"));
        record_syncs();
        p.ensure_dirs().unwrap();
        assert_eq!(
            take_synced(),
            [id(t.path()), id(&a), id(&b), id(&p.data_dir)]
        );
        // All there: the two flushed at every call, and nothing else.
        record_syncs();
        p.ensure_dirs().unwrap();
        assert_eq!(take_synced(), [id(&b), id(&p.data_dir)]);
        // One of the three made again: the data directory names it.
        std::fs::remove_dir(&p.audit_dir).unwrap();
        record_syncs();
        p.ensure_dirs().unwrap();
        assert!(p.audit_dir.is_dir());
        assert_eq!(take_synced(), [id(&b), id(&p.data_dir)]);

        // A failed flush fails the call. An ancestor whose flush failed is
        // removed, so the next call makes it and flushes it again.
        let q = VaultPaths::under(t.path().join("c/d/envcloak"));
        let (c, d) = (t.path().join("c"), t.path().join("c/d"));
        fail_sync_after(0);
        assert!(q.ensure_dirs().is_err());
        assert!(!c.exists(), "c, whose flush failed, is removed");
        record_syncs();
        fail_sync_after(1);
        assert!(q.ensure_dirs().is_err());
        assert_eq!(take_synced(), [id(t.path())]);
        assert!(c.is_dir() && !d.exists(), "c kept, flushed; d removed");
        // The data directory's parent failing leaves every directory made;
        // the next call flushes it and the data directory.
        record_syncs();
        fail_sync_after(1);
        assert!(q.ensure_dirs().is_err());
        assert_eq!(take_synced(), [id(&c)]);
        for dir in [&q.data_dir, &q.vault_dir, &q.audit_dir, &q.backups_dir] {
            assert!(dir.is_dir(), "{}", dir.display());
        }
        record_syncs();
        q.ensure_dirs().unwrap();
        assert_eq!(take_synced(), [id(&d), id(&q.data_dir)]);
        // So does the data directory itself failing.
        record_syncs();
        fail_sync_after(1);
        assert!(q.ensure_dirs().is_err());
        assert_eq!(take_synced(), [id(&d)]);
        record_syncs();
        q.ensure_dirs().unwrap();
        assert_eq!(take_synced(), [id(&d), id(&q.data_dir)]);
    }

    #[test]
    fn private_files_are_tightened_or_refused() {
        let t = tempfile::tempdir().unwrap();
        let f = t.path().join("f");
        std::fs::write(&f, b"").unwrap();
        std::fs::set_permissions(&f, Permissions::from_mode(0o644)).unwrap();
        check_private_file(&f).unwrap();
        assert_eq!(std::fs::metadata(&f).unwrap().mode() & 0o777, 0o600);
        std::fs::set_permissions(&f, Permissions::from_mode(0o666)).unwrap();
        assert_eq!(
            check_private_file(&f).unwrap_err().kind(),
            PathErrorKind::OpenPermissions
        );
        let link = t.path().join("link");
        std::os::unix::fs::symlink(&f, &link).unwrap();
        assert_eq!(
            check_private_file(&link).unwrap_err().kind(),
            PathErrorKind::Symlink
        );
        assert_eq!(
            check_private_file(t.path()).unwrap_err().kind(),
            PathErrorKind::NotFile
        );
        assert_eq!(
            check_private_file(&t.path().join("missing"))
                .unwrap_err()
                .kind(),
            PathErrorKind::Missing
        );
    }
}
