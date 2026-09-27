//! Moving files out of the way of a new `vault.db` (docs/VAULT.md "Create"
//! and "Restore").
//!
//! A restore keeps the vault it replaces, and both a restore and `create`
//! move aside any side file left beside `vault.db` without its database: a
//! daemon killed before a checkpoint leaves `vault.db-wal`, and SQLite
//! replays any WAL (or rolls back any hot journal) it finds beside a
//! database when it opens it. A WAL is not tied to the file it was written
//! for, so left in place it would be written into the new vault.

use std::path::{Path, PathBuf};

use super::txn::now_secs;
use super::{DB_NAME, SIDE_FILES, VaultError, sync_dir};

/// What files moved aside are named: `replaced-<UTC time>.db`, then
/// SQLite's suffixes.
pub(crate) const REPLACED_PREFIX: &str = "replaced-";

/// Moves whatever is at `vault.db` in `dir`, and its side files, out of
/// the way: to `replaced-<UTC time>.db` (with `-1`, `-2` and so on after
/// the time when that name, or one of its side files' names, is taken), the
/// side files keeping their suffixes. `vault.db` itself is hard-linked, not
/// moved: it stays until the caller renames the new file over it, so a
/// crash never leaves the directory without it. Side files are renamed.
/// Syncs the directory.
///
/// Returns the new names, `vault.db`'s first; empty when nothing was there.
pub(crate) fn set_aside(dir: &Path) -> Result<Vec<PathBuf>, VaultError> {
    let present = |p: &Path| std::fs::symlink_metadata(p).is_ok();
    let db = dir.join(DB_NAME);
    let has_db = present(&db);
    let sides: Vec<&str> = SIDE_FILES
        .into_iter()
        .filter(|s| present(&with_suffix(&db, s)))
        .collect();
    if !has_db && sides.is_empty() {
        return Ok(Vec::new());
    }
    let stamp = utc_stamp(now_secs());
    let mut n = 0u32;
    let base = loop {
        let name = if n == 0 {
            format!("{REPLACED_PREFIX}{stamp}.db")
        } else {
            format!("{REPLACED_PREFIX}{stamp}-{n}.db")
        };
        let base = dir.join(name);
        let taken = present(&base) || SIDE_FILES.iter().any(|s| present(&with_suffix(&base, s)));
        if !taken {
            if !has_db {
                break base;
            }
            match std::fs::hard_link(&db, &base) {
                Ok(()) => break base,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        if n == 1000 {
            return Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists).into());
        }
        n += 1;
    };
    let mut moved = Vec::with_capacity(1 + sides.len());
    if has_db {
        moved.push(base.clone());
    }
    for side in sides {
        let to = with_suffix(&base, side);
        std::fs::rename(with_suffix(&db, side), &to)?;
        moved.push(to);
    }
    sync_dir(dir)?;
    Ok(moved)
}

/// `p` with `suffix` appended to its last component.
pub(crate) fn with_suffix(p: &Path, suffix: &str) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

/// `YYYYMMDDTHHMMSSZ` for Unix seconds `secs`, in UTC.
pub(crate) fn utc_stamp(secs: u64) -> String {
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    let (hour, minute, second) = (rem / 3600, rem % 3600 / 60, rem % 60);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_stamps() {
        for (secs, want) in [
            (0, "19700101T000000Z"),
            (951_782_400, "20000229T000000Z"),
            (1_709_251_199, "20240229T235959Z"),
            (1_790_000_000, "20260921T141320Z"),
            (4_102_444_799, "20991231T235959Z"),
        ] {
            assert_eq!(utc_stamp(secs), want);
        }
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    /// The database is linked and its side files renamed; side files
    /// without a database are moved too; a taken name gets a suffix, and
    /// nothing is overwritten.
    #[test]
    fn everything_at_vault_db_is_moved_aside_under_a_free_name() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        assert!(set_aside(d).unwrap().is_empty());

        std::fs::write(d.join("vault.db"), b"db").unwrap();
        std::fs::write(d.join("vault.db-wal"), b"wal").unwrap();
        let moved = set_aside(d).unwrap();
        let [kept, wal] = &moved[..] else {
            panic!("{moved:?}");
        };
        assert_eq!(*wal, with_suffix(kept, "-wal"));
        assert_eq!(std::fs::read(kept).unwrap(), b"db");
        assert_eq!(std::fs::read(wal).unwrap(), b"wal");
        assert_eq!(std::fs::read(d.join("vault.db")).unwrap(), b"db");
        assert!(!d.join("vault.db-wal").exists());

        // Side files alone, possibly within the same second: a name whose
        // side files are taken is not reused.
        std::fs::remove_file(d.join("vault.db")).unwrap();
        std::fs::write(d.join("vault.db-wal"), b"wal 2").unwrap();
        std::fs::write(d.join("vault.db-journal"), b"journal 2").unwrap();
        let moved = set_aside(d).unwrap();
        let [wal2, journal2] = &moved[..] else {
            panic!("{moved:?}");
        };
        assert_eq!(std::fs::read(wal2).unwrap(), b"wal 2");
        assert_eq!(std::fs::read(journal2).unwrap(), b"journal 2");
        assert_eq!(std::fs::read(wal).unwrap(), b"wal", "not overwritten");
        let all = names(d);
        assert!(
            all.iter().all(|n| n.starts_with(REPLACED_PREFIX)),
            "{all:?}"
        );
        assert_eq!(all.len(), 4);
    }
}
