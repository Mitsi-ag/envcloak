//! `sync_file`: `F_FULLFSYNC` on macOS, `fsync` on Linux, counted by the
//! testing shim, and failures reported rather than taken for success.
#![allow(clippy::unwrap_used)]

use std::fs::File;
use std::io::Write;

use envcloak_sys::testing::sync_counts;
use envcloak_sys::{SyncMethod, sync_file};

#[test]
fn a_file_and_its_directory_are_flushed_with_the_platforms_strongest_call() {
    let tmp = tempfile::tempdir_in("/tmp").unwrap();
    let path = tmp.path().join("segment");
    let mut f = File::create(&path).unwrap();
    f.write_all(b"entry").unwrap();

    let before = sync_counts();
    let file_method = sync_file(&f).unwrap();
    let dir_method = sync_file(&File::open(tmp.path()).unwrap()).unwrap();
    let after = sync_counts();

    // /tmp is on the system volume (APFS on macOS), which supports
    // F_FULLFSYNC, so no fallback runs there.
    let want = if cfg!(target_os = "macos") {
        SyncMethod::FullFsync
    } else {
        SyncMethod::Fsync
    };
    assert_eq!((file_method, dir_method), (want, want));
    let (full, plain) = (
        after.full_fsync - before.full_fsync,
        after.fsync - before.fsync,
    );
    if cfg!(target_os = "macos") {
        assert_eq!((full, plain), (2, 0));
    } else {
        assert_eq!((full, plain), (0, 2));
    }
}

/// The counts are this thread's own: another thread's syncs do not show.
#[test]
fn counts_are_per_thread() {
    let tmp = tempfile::tempdir_in("/tmp").unwrap();
    let f = File::create(tmp.path().join("x")).unwrap();
    let before = sync_counts();
    std::thread::scope(|s| {
        s.spawn(|| {
            for _ in 0..3 {
                sync_file(&f).unwrap();
            }
        });
    });
    assert_eq!(sync_counts(), before);
}

/// A descriptor that cannot be flushed is an error, never a success: a
/// caller that promised durability must not go on.
#[test]
fn a_failure_is_reported() {
    let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
    let socket = File::from(std::os::fd::OwnedFd::from(a));
    let before = sync_counts();
    assert!(sync_file(&socket).is_err());
    assert_eq!(sync_counts(), before);
}
