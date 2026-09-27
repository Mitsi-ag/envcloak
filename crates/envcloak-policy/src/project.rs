//! Finding a project's manifest and computing the project's identity
//! (SPEC §6.1 steps 1 and 2, §10b "Match" rule 5, gate 28).
//!
//! The CLI finds the nearest `envcloak.toml` ([`find_manifest`]) and sends
//! its path. The daemon then opens the project itself ([`load_project`]):
//! 1. `realpath` of the manifest's directory gives the canonical path;
//! 2. that directory is opened (`O_DIRECTORY | O_NOFOLLOW`) and `fstat`ed:
//!    its device and inode come from the open descriptor;
//! 3. the manifest is opened through that descriptor (`openat` with
//!    `O_NOFOLLOW | O_NONBLOCK`, [`envcloak_sys::open_beneath`]), so a
//!    symlinked `envcloak.toml` is refused and the file read is the one in
//!    the directory identified, whatever happens to the path meanwhile;
//! 4. `fstat` of the manifest must show a regular file owned by this user;
//! 5. the canonical path is looked up again and must still be that
//!    directory, so the path and the device and inode agree.
//!
//! The identity is the canonical path together with the device and inode
//! ([`ProjectIdentity`]). Device and inode say which directory it is; a
//! path alone can alias (APFS folds case, and `realpath` returns the
//! stored spelling). The path makes a moved repo a new project, since a
//! rename keeps the inode; a copy has a new inode. A symlinked path to the
//! same directory resolves to the same canonical path and inode.

use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use envcloak_core::vault::ProjectKey;
use sha2::{Digest, Sha256};

use crate::manifest::{Manifest, ManifestError, ManifestErrorKind, parse_manifest};

/// The manifest's file name.
pub const MANIFEST_NAME: &str = Manifest::FILE_NAME;

/// Which project a manifest belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProjectIdentity {
    /// `realpath` of the manifest's directory.
    pub canonical_dir: PathBuf,
    /// Device and inode of the directory, from the opened descriptor.
    pub dev: u64,
    pub ino: u64,
    /// `canonical_dir` joined with [`MANIFEST_NAME`].
    pub manifest_path: PathBuf,
}

impl ProjectIdentity {
    /// The key of this project in the vault's project index
    /// (`envcloak_core::vault::ProjectRecord`): a format byte (1), the
    /// device and inode as big-endian u64s, and SHA-256 of the canonical
    /// path's bytes. 49 bytes; equal exactly when the identities are.
    pub fn vault_key(&self) -> ProjectKey {
        let mut b = Vec::with_capacity(49);
        b.push(1u8);
        b.extend_from_slice(&self.dev.to_be_bytes());
        b.extend_from_slice(&self.ino.to_be_bytes());
        b.extend_from_slice(&Sha256::digest(self.canonical_dir.as_os_str().as_bytes()));
        ProjectKey::new(&b).expect("a 49-byte key is within ProjectKey's bounds")
    }
}

/// A project as the daemon reads it: its identity and the manifest read
/// through the same directory descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    pub identity: ProjectIdentity,
    pub manifest: Manifest,
}

/// The nearest `envcloak.toml` at or above `start`: `start` is
/// canonicalized first, so the walk follows the directories the kernel
/// sees. Anything by that name counts, a symlink included, so that
/// [`load_project`] refuses it rather than a manifest further up being used
/// in its place. `Ok(None)` when there is none up to the root.
pub fn find_manifest(start: &Path) -> io::Result<Option<PathBuf>> {
    let start = std::fs::canonicalize(start)?;
    for dir in start.ancestors() {
        let candidate = dir.join(MANIFEST_NAME);
        match std::fs::symlink_metadata(&candidate) {
            Ok(_) => return Ok(Some(candidate)),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(None)
}

/// The identity of the project whose manifest is at `manifest`, an
/// absolute path to a file named `envcloak.toml`. Refuses a symlinked,
/// non-regular or foreign-owned manifest. See the module documentation.
pub fn project_identity(manifest: &Path) -> Result<ProjectIdentity, ManifestError> {
    open_project(manifest).map(|(id, _)| id)
}

/// Opens the project at `manifest` as [`project_identity`] does, then reads
/// and parses the manifest from the file it opened.
pub fn load_project(manifest: &Path) -> Result<Project, ManifestError> {
    let (identity, file) = open_project(manifest)?;
    let len = file.metadata().map_err(io_error)?.len();
    let cap = Manifest::MAX_LEN + 1;
    let mut bytes = Vec::with_capacity(usize::try_from(len).map_or(cap, |n| n.min(cap)));
    file.take(cap as u64)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() > Manifest::MAX_LEN {
        return Err(ManifestErrorKind::TooLarge.into());
    }
    Ok(Project {
        identity,
        manifest: parse_manifest(&bytes)?,
    })
}

fn io_error(e: io::Error) -> ManifestError {
    match e.kind() {
        io::ErrorKind::NotFound => ManifestErrorKind::NotFound.into(),
        k => ManifestErrorKind::Io(k).into(),
    }
}

fn open_project(manifest: &Path) -> Result<(ProjectIdentity, File), ManifestError> {
    let invalid = || ManifestError::from(ManifestErrorKind::InvalidPath);
    if !manifest.is_absolute() || manifest.file_name() != Some(OsStr::new(MANIFEST_NAME)) {
        return Err(invalid());
    }
    let parent = manifest.parent().ok_or_else(invalid)?;
    let canonical_dir = std::fs::canonicalize(parent).map_err(io_error)?;
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(&canonical_dir)
        .map_err(io_error)?;
    let dm = dir.metadata().map_err(io_error)?;
    let (dev, ino) = (dm.dev(), dm.ino());
    let file = envcloak_sys::open_beneath(&dir, OsStr::new(MANIFEST_NAME)).map_err(|e| {
        if e.raw_os_error() == Some(libc::ELOOP) {
            ManifestErrorKind::SymlinkedManifest.into()
        } else {
            io_error(e)
        }
    })?;
    let fm = file.metadata().map_err(io_error)?;
    check_manifest_file(
        fm.file_type().is_file(),
        fm.uid(),
        envcloak_sys::effective_uid(),
    )?;
    let again = std::fs::metadata(&canonical_dir).map_err(io_error)?;
    if (again.dev(), again.ino()) != (dev, ino) {
        return Err(ManifestErrorKind::DirectoryChanged.into());
    }
    let identity = ProjectIdentity {
        manifest_path: canonical_dir.join(MANIFEST_NAME),
        canonical_dir,
        dev,
        ino,
    };
    Ok((identity, file))
}

/// What `fstat` of the opened manifest must show: a regular file (not a
/// FIFO, device, socket or directory) owned by `euid`.
fn check_manifest_file(is_file: bool, uid: u32, euid: u32) -> Result<(), ManifestError> {
    if !is_file {
        return Err(ManifestErrorKind::NotRegularFile.into());
    }
    if uid != euid {
        return Err(ManifestErrorKind::NotOwned.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_manifest_must_be_a_regular_file_of_this_user() {
        assert!(check_manifest_file(true, 501, 501).is_ok());
        assert_eq!(
            check_manifest_file(true, 0, 501).unwrap_err().kind(),
            ManifestErrorKind::NotOwned
        );
        assert_eq!(
            check_manifest_file(false, 501, 501).unwrap_err().kind(),
            ManifestErrorKind::NotRegularFile
        );
    }

    #[test]
    fn vault_keys_follow_every_part_of_the_identity() {
        let id = ProjectIdentity {
            canonical_dir: PathBuf::from("/src/acme-web"),
            dev: 1,
            ino: 2,
            manifest_path: PathBuf::from("/src/acme-web/envcloak.toml"),
        };
        let k = id.vault_key();
        assert_eq!(k.as_bytes().len(), 49);
        assert_eq!(
            k.as_bytes()[..17],
            [1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2]
        );
        let moved = ProjectIdentity {
            canonical_dir: PathBuf::from("/src/acme-web-2"),
            ..id.clone()
        };
        let other_dev = ProjectIdentity {
            dev: 3,
            ..id.clone()
        };
        let other_ino = ProjectIdentity {
            ino: 3,
            ..id.clone()
        };
        for other in [moved, other_dev, other_ino] {
            assert_ne!(other.vault_key(), k);
        }
    }
}
