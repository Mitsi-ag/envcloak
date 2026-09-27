//! The private umask and the effective uid. The umask is process-wide, so
//! these tests live in their own binary.
#![allow(clippy::unwrap_used)]

use std::os::unix::fs::{MetadataExt, PermissionsExt};

use envcloak_sys::{PRIVATE_UMASK, effective_uid, restrict_umask};

#[test]
fn files_created_after_restrict_umask_are_private() {
    let dir = tempfile::tempdir().unwrap();
    restrict_umask();
    // A second call returns the mask the first one set.
    assert_eq!(restrict_umask(), PRIVATE_UMASK);

    // std creates files 0666 and directories 0777 before the umask applies.
    let file = dir.path().join("f");
    std::fs::write(&file, b"x").unwrap();
    let sub = dir.path().join("d");
    std::fs::create_dir(&sub).unwrap();
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&file), 0o600);
    assert_eq!(mode(&sub), 0o700);
}

#[test]
fn effective_uid_owns_what_this_process_creates() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("owned");
    std::fs::write(&file, b"x").unwrap();
    assert_eq!(std::fs::metadata(&file).unwrap().uid(), effective_uid());
}
