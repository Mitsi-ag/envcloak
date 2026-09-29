//! Test support only (feature `testing`): [`crate::pause_point`] stops the
//! process at a named point until the test says go on, so gate 16's test
//! can kill `envcloak init` there.
//!
//! When [`PAUSE_DIR`] names a directory, the `n`th point (from 0) writes
//! this process's id to `<dir>/<n>.<name>` (three digits, written under
//! another name and renamed, so it is read whole) and waits until
//! `<dir>/<n>.go` exists.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// The environment variable naming the directory of the points.
pub const PAUSE_DIR: &str = "ENVCLOAK_TEST_PAUSE_DIR";

pub(crate) fn pause(name: &str) {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let Some(dir) = std::env::var_os(PAUSE_DIR).map(PathBuf::from) else {
        return;
    };
    let n = NEXT.fetch_add(1, Ordering::SeqCst);
    let staged = dir.join(format!(".{n:03}.tmp"));
    let written = std::fs::write(&staged, std::process::id().to_string())
        .and_then(|()| std::fs::rename(&staged, dir.join(format!("{n:03}.{name}"))));
    if written.is_err() {
        return;
    }
    let go = dir.join(format!("{n:03}.go"));
    while !go.exists() {
        std::thread::sleep(Duration::from_millis(5));
    }
}
