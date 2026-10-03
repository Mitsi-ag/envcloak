//! The file system's clock, as its change times show it.
//!
//! A file's stamp (device, inode, size, mode, modification and change
//! times) shows that nothing wrote into it, cut it, linked it or changed
//! its permissions between two looks only once the file system's clock
//! has moved past the file's last change: Linux stamps every change within
//! one tick of its clock (a millisecond or a few) with the same time, and
//! HFS+ every change within one second, so a write right after the file's
//! own last one leaves its stamp as it was. No program can set a change
//! time. [`wait_for_clock_past`] waits until a change made in the file's
//! directory is stamped later than the file's last one: from then on any
//! change to the file moves its change time.

use std::fs::File;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::time::{Duration, Instant};

/// Waits, up to `limit`, until a change to the directory `dir` is stamped
/// later than `after`, a change time (seconds, nanoseconds) read from a
/// file on its file system: the file system's clock has then moved past
/// it, and any change to that file from then on moves its change time.
/// Each probe gives `dir` the permissions it has (`fchmod`), which changes
/// nothing but its change time, set from the file system's clock, and
/// which only its owner may do. (Giving it the owner it has would not do:
/// a volume that ignores owners, as macOS mounts disk images and external
/// disks by default, takes that as no change and leaves the change time.)
/// macOS's APFS stamps each change apart, so there the first probe
/// passes; Linux takes at most a tick, HFS+ at most a second.
///
/// # Errors
/// When `dir`'s metadata cannot be read or its permissions set (it is not
/// this user's, or its file system keeps none), and `TimedOut` when the
/// clock is not past `after` within `limit` (it went back, or the file
/// system keeps no change times).
pub fn wait_for_clock_past(dir: &File, after: (i64, i64), limit: Duration) -> io::Result<()> {
    let deadline = Instant::now() + limit;
    loop {
        let mode = dir.metadata()?.mode() & 0o7777;
        dir.set_permissions(std::fs::Permissions::from_mode(mode))?;
        let m = dir.metadata()?;
        if (m.ctime(), m.ctime_nsec()) > after {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the file system's clock did not move past the file's last change",
            ));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::FileExt;

    fn changed(f: &File) -> (i64, i64) {
        let m = f.metadata().unwrap();
        (m.ctime(), m.ctime_nsec())
    }

    /// Once the wait is over, a write into a file just written (one byte
    /// in place, its modification time put back, its length kept), made
    /// as soon as a program can, moves its change time, every time. Linux
    /// stamps every change within one tick of its clock alike, so without
    /// the wait most such writes leave the change time as it was.
    #[test]
    fn a_write_after_the_wait_moves_the_change_time() {
        let d = tempfile::tempdir().unwrap();
        let dir = File::open(d.path()).unwrap();
        for i in 0..40 {
            let p = d.path().join(format!("f{i}"));
            let mut f = File::options()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&p)
                .unwrap();
            f.write_all(&[7; 4096]).unwrap();
            let before = changed(&f);
            wait_for_clock_past(&dir, before, Duration::from_secs(3)).unwrap();
            let modified = f.metadata().unwrap().modified().unwrap();
            f.write_all_at(&[8], 100).unwrap();
            f.set_modified(modified).unwrap();
            assert_ne!(
                changed(&f),
                before,
                "a write right after the wait (file {i}) left the change time as it was"
            );
        }
    }

    /// The probe changes nothing of the directory but its change time: its
    /// owner, group, mode and modification time stay.
    #[test]
    fn the_probe_changes_only_the_change_time() {
        let d = tempfile::tempdir().unwrap();
        let dir = File::open(d.path()).unwrap();
        let before = dir.metadata().unwrap();
        wait_for_clock_past(&dir, changed(&dir), Duration::from_secs(3)).unwrap();
        let after = dir.metadata().unwrap();
        assert!((after.ctime(), after.ctime_nsec()) > (before.ctime(), before.ctime_nsec()));
        assert_eq!(
            (after.uid(), after.gid(), after.mode()),
            (before.uid(), before.gid(), before.mode())
        );
        assert_eq!(after.modified().unwrap(), before.modified().unwrap());
    }

    /// A clock that does not move past the time given (here, one far in the
    /// future) fails the wait once its limit is up, never taken for one
    /// that did.
    #[test]
    fn a_clock_that_never_moves_past_fails_the_wait() {
        let d = tempfile::tempdir().unwrap();
        let dir = File::open(d.path()).unwrap();
        let started = Instant::now();
        let limit = Duration::from_millis(300);
        assert_eq!(
            wait_for_clock_past(&dir, (i64::MAX, 0), limit).map_err(|e| e.kind()),
            Err(io::ErrorKind::TimedOut)
        );
        assert!(started.elapsed() >= limit);
    }
}
