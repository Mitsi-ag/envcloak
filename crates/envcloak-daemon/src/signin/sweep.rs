//! Startup sweep and tombstone accounting for `<data>/signin/attempts/*`
//! (`SPEC.md` §6.8, M2 plan D-34, F-73, CR-3, L-08, task `M2b-09`).
//!
//! Invariants enforced:
//! 1. Startup sweep (`sweep::run`) never sends a signal to any stored PID.
//! 2. Only a valid on-disk `teardown.confirmed` record (verified via
//!    [`verify_teardown_record_at`]) counts as confirmed teardown; a free
//!    `reaper.lock` alone is never treated as proof that cleanup succeeded
//!    (`CR-3`).
//! 3. An unlocked attempt directory without `teardown.confirmed` has its
//!    `profile/` removed and is retained as an unconfirmed tombstone
//!    (`cleanup_unconfirmed`) until a later startup sweep observes a changed
//!    [`BootId`], which clears it and records `ended_by_reboot`.
//! 4. At most [`MAX_TOMBSTONES`] (`64`) unconfirmed tombstones may accumulate;
//!    at the cap, new sign-in attempts are refused with `cleanup_unconfirmed`.
#![allow(dead_code)]

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use envcloak_browser::REAPER_LOCK_FILE;
use envcloak_sys::{
    DirEntryKind, MAX_DIR_ENTRIES, create_beneath, create_dir_beneath, create_rw_beneath,
    kind_beneath, list_dir, open_beneath, open_dir_beneath, remove_tree_beneath_and_verify,
    sync_file, try_lock_exclusive, unlink_beneath,
};

use super::reaper::verify_teardown_record_at;

/// Maximum number of unconfirmed attempt tombstones before new sign-in
/// attempts are refused with `cleanup_unconfirmed` (`D-34`, `L-08`).
pub const MAX_TOMBSTONES: usize = 64;

/// Metadata written to `attempt.meta` when an attempt directory is created.
pub const ATTEMPT_META_FILE: &str = "attempt.meta";

/// Tombstone marker written to `tombstone.json` when an attempt's teardown is
/// unconfirmed.
pub const TOMBSTONE_FILE: &str = "tombstone.json";

/// Identifier of a kernel boot session, used by [`run`] to determine whether
/// an unconfirmed attempt from an earlier run has ended by reboot (`D-34`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BootId(pub String);

impl BootId {
    /// Creates a [`BootId`] if `raw` is non-empty after trimming whitespace.
    pub fn new(raw: impl Into<String>) -> Option<Self> {
        let trimmed = raw.into().trim().to_owned();
        if trimmed.is_empty() {
            None
        } else {
            Some(Self(trimmed))
        }
    }

    /// String slice of the boot identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Reads the current system boot identifier.
    ///
    /// - In test builds, honors `ENVCLOAK_TEST_BOOT_ID` from
    ///   [`envcloak_sys::test_hook_vars`] when set.
    /// - On Linux, reads `/proc/sys/kernel/random/boot_id` via
    ///   [`envcloak_sys::boot_id`].
    /// - On macOS, uses the kernel start time of PID 1 (`launchd`) via
    ///   [`envcloak_sys::process_start_time`].
    pub fn current() -> Option<Self> {
        for (k, v) in envcloak_sys::test_hook_vars() {
            if k == "ENVCLOAK_TEST_BOOT_ID"
                && let Some(s) = v.to_str()
                && let Some(id) = Self::new(s)
            {
                return Some(id);
            }
        }
        if let Ok(Some(bytes)) = envcloak_sys::boot_id() {
            let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            return Self::new(hex);
        }
        if let Ok(st) = envcloak_sys::process_start_time(1) {
            return Self::new(format!("pid1-start-{}", st.raw()));
        }
        None
    }
}

/// On-disk metadata recorded in `attempt.meta` at attempt creation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptMeta {
    pub attempt_id: String,
    pub started_wall_secs: u64,
    pub boot_id: Option<BootId>,
}

/// On-disk tombstone recorded in `tombstone.json` when cleanup is unconfirmed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TombstoneRecord {
    pub attempt_id: String,
    pub started_wall_secs: u64,
    pub boot_id: Option<BootId>,
}

/// Summary of a startup sweep over `<data>/signin/attempts/*`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Attempt IDs that had a valid `teardown.confirmed` record and were removed.
    pub confirmed: Vec<String>,
    /// Attempt IDs that lacked `teardown.confirmed` on the same (or unknown) boot
    /// and remain on disk as unconfirmed tombstones (`cleanup_unconfirmed`).
    pub unconfirmed: Vec<String>,
    /// Attempt IDs that lacked `teardown.confirmed` from a previous boot and were
    /// cleared after observing a changed [`BootId`] (`ended_by_reboot`).
    pub ended_by_reboot: Vec<String>,
}

impl SweepReport {
    /// Number of unconfirmed attempt directories remaining after the sweep.
    pub fn unconfirmed_count(&self) -> u32 {
        u32::try_from(self.unconfirmed.len()).unwrap_or(u32::MAX)
    }
}

fn lock_wait_timeout() -> Duration {
    for (k, v) in envcloak_sys::test_hook_vars() {
        if k == "ENVCLOAK_TEST_SWEEP_LOCK_WAIT_MS"
            && let Some(s) = v.to_str()
            && let Ok(ms) = s.parse::<u64>()
        {
            return Duration::from_millis(ms.min(5_000));
        }
    }
    Duration::from_millis(500)
}

fn ensure_attempts_root(data_dir: &Path) -> io::Result<(File, PathBuf)> {
    let signin_dir = data_dir.join("signin");
    let attempts_dir = signin_dir.join("attempts");
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    if !signin_dir.exists() {
        builder.create(&signin_dir)?;
    }
    if !attempts_dir.exists() {
        builder.create(&attempts_dir)?;
    }
    let signin_file = File::open(&signin_dir)?;
    let attempts_file = open_dir_beneath(&signin_file, OsStr::new("attempts"))?;
    Ok((attempts_file, attempts_dir))
}

fn open_attempts_root_if_present(data_dir: &Path) -> io::Result<Option<(File, PathBuf)>> {
    let signin_dir = data_dir.join("signin");
    let attempts_dir = signin_dir.join("attempts");
    let signin_file = match File::open(&signin_dir) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    match open_dir_beneath(&signin_file, OsStr::new("attempts")) {
        Ok(f) => Ok(Some((f, attempts_dir))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn read_json_beneath<T: for<'de> Deserialize<'de>>(dir: &File, name: &str) -> Option<T> {
    let mut file = open_beneath(dir, OsStr::new(name)).ok()?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_tombstone_beneath(dir: &File, record: &TombstoneRecord) -> io::Result<()> {
    if kind_beneath(dir, OsStr::new(TOMBSTONE_FILE)).is_ok() {
        let _ = unlink_beneath(dir, OsStr::new(TOMBSTONE_FILE));
    }
    let payload =
        serde_json::to_vec(record).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let mut file = create_beneath(dir, OsStr::new(TOMBSTONE_FILE), 0o600)?;
    file.write_all(&payload)?;
    sync_file(&file)?;
    drop(file);
    sync_file(dir).map(|_| ())
}

fn open_or_create_lock_beneath(dir: &File) -> io::Result<File> {
    match create_rw_beneath(dir, OsStr::new(REAPER_LOCK_FILE), 0o600) {
        Ok(f) => Ok(f),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            open_beneath(dir, OsStr::new(REAPER_LOCK_FILE))
        }
        Err(e) => Err(e),
    }
}

fn acquire_reaper_lock_with_wait(dir: &File, wait: Duration) -> io::Result<Option<File>> {
    let deadline = Instant::now() + wait;
    loop {
        let lock_file = open_or_create_lock_beneath(dir)?;
        if try_lock_exclusive(&lock_file)? {
            return Ok(Some(lock_file));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Sweeps `<data>/signin/attempts/*` at daemon startup (`SPEC.md` §6.8,
/// M2 plan D-34, F-73, CR-3).
///
/// Never signals any stored PID. Treats only a valid `teardown.confirmed`
/// record as confirmed cleanup; an unlocked attempt directory without that
/// record has its `profile/` removed and is retained as an unconfirmed
/// tombstone until a subsequent boot (`current_boot != recorded_boot`) clears
/// it with `ended_by_reboot`.
pub fn run(data_dir: &Path, current_boot: Option<BootId>) -> io::Result<SweepReport> {
    let Some((attempts_file, attempts_path)) = open_attempts_root_if_present(data_dir)? else {
        return Ok(SweepReport::default());
    };

    let mut entries = list_dir(&attempts_file, MAX_DIR_ENTRIES)?;
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    let mut report = SweepReport::default();
    let wait = lock_wait_timeout();

    for entry in entries {
        let Some(attempt_id) = entry.name.to_str().map(str::to_owned) else {
            continue;
        };
        let entry_kind = match kind_beneath(&attempts_file, &entry.name) {
            Ok(k) => k,
            Err(_) => continue,
        };
        if entry_kind != DirEntryKind::Dir {
            let _ = unlink_beneath(&attempts_file, &entry.name);
            continue;
        }

        let attempt_dir_file = match open_dir_beneath(&attempts_file, &entry.name) {
            Ok(f) => f,
            Err(_) => {
                report.unconfirmed.push(attempt_id);
                continue;
            }
        };

        let Some(_lock_guard) = acquire_reaper_lock_with_wait(&attempt_dir_file, wait)? else {
            // A reaper process still holds `reaper.lock`; leave the directory
            // untouched for a later sweep and count it as unconfirmed for now.
            report.unconfirmed.push(attempt_id);
            continue;
        };

        let attempt_path = attempts_path.join(&attempt_id);
        if verify_teardown_record_at(&attempt_path, &attempt_id).is_ok() {
            drop(_lock_guard);
            drop(attempt_dir_file);
            if remove_tree_beneath_and_verify(&attempts_file, &entry.name).is_ok() {
                let _ = sync_file(&attempts_file);
                report.confirmed.push(attempt_id);
            } else {
                report.unconfirmed.push(attempt_id);
            }
            continue;
        }

        // No valid `teardown.confirmed` record (`CR-3`: free lock alone is never confirmed).
        let _ = remove_tree_beneath_and_verify(&attempt_dir_file, OsStr::new("profile"));

        let meta: Option<AttemptMeta> = read_json_beneath(&attempt_dir_file, ATTEMPT_META_FILE);
        let prior_tomb: Option<TombstoneRecord> =
            read_json_beneath(&attempt_dir_file, TOMBSTONE_FILE);

        let recorded_boot = meta
            .as_ref()
            .and_then(|m| m.boot_id.clone())
            .or_else(|| prior_tomb.as_ref().and_then(|t| t.boot_id.clone()));
        let started_wall_secs = meta
            .as_ref()
            .map(|m| m.started_wall_secs)
            .or_else(|| prior_tomb.as_ref().map(|t| t.started_wall_secs))
            .unwrap_or(0);

        let rebooted = match (&recorded_boot, &current_boot) {
            (Some(recorded), Some(current)) => recorded != current,
            _ => false,
        };

        if rebooted {
            drop(_lock_guard);
            drop(attempt_dir_file);
            if remove_tree_beneath_and_verify(&attempts_file, &entry.name).is_ok() {
                let _ = sync_file(&attempts_file);
                report.ended_by_reboot.push(attempt_id);
            } else {
                report.unconfirmed.push(attempt_id);
            }
        } else {
            let tomb = TombstoneRecord {
                attempt_id: attempt_id.clone(),
                started_wall_secs,
                boot_id: recorded_boot,
            };
            let _ = write_tombstone_beneath(&attempt_dir_file, &tomb);
            report.unconfirmed.push(attempt_id);
        }
    }

    Ok(report)
}

/// Counts the number of unconfirmed attempt directories (tombstones or
/// unconfirmed directories lacking `teardown.confirmed`) beneath
/// `<data>/signin/attempts`.
pub fn unconfirmed_count(data_dir: &Path) -> io::Result<u32> {
    let Some((attempts_file, attempts_path)) = open_attempts_root_if_present(data_dir)? else {
        return Ok(0);
    };
    let entries = list_dir(&attempts_file, MAX_DIR_ENTRIES)?;
    let mut count = 0u32;
    for entry in entries {
        let Some(attempt_id) = entry.name.to_str() else {
            continue;
        };
        if kind_beneath(&attempts_file, &entry.name).ok() != Some(DirEntryKind::Dir) {
            continue;
        }
        if let Ok(attempt_dir_file) = open_dir_beneath(&attempts_file, &entry.name)
            && let Ok(lock_file) = open_beneath(&attempt_dir_file, OsStr::new(REAPER_LOCK_FILE))
            && matches!(try_lock_exclusive(&lock_file), Ok(false))
        {
            continue;
        }
        let attempt_path = attempts_path.join(attempt_id);
        if verify_teardown_record_at(&attempt_path, attempt_id).is_err() {
            count = count.saturating_add(1);
        }
    }
    Ok(count)
}

/// Prepares a fresh `0700` attempt directory `<data>/signin/attempts/<attempt_id>`
/// with a `0700` `profile/` subdirectory and a durable `attempt.meta` record.
///
/// # Errors
/// Returns an error with message `"cleanup_unconfirmed"` if the number of
/// unconfirmed tombstones in `<data>/signin/attempts` has reached
/// [`MAX_TOMBSTONES`] (`64`).
pub fn prepare_attempt_dir(
    data_dir: &Path,
    attempt_id: &str,
    started_wall_secs: u64,
    boot_id: Option<BootId>,
) -> io::Result<PathBuf> {
    let existing_unconfirmed = unconfirmed_count(data_dir)? as usize;
    if existing_unconfirmed >= MAX_TOMBSTONES {
        return Err(io::Error::other("cleanup_unconfirmed"));
    }

    let (attempts_file, attempts_path) = ensure_attempts_root(data_dir)?;
    create_dir_beneath(&attempts_file, OsStr::new(attempt_id), 0o700)?;
    let attempt_dir_file = open_dir_beneath(&attempts_file, OsStr::new(attempt_id))?;
    create_dir_beneath(&attempt_dir_file, OsStr::new("profile"), 0o700)?;

    let meta = AttemptMeta {
        attempt_id: attempt_id.to_owned(),
        started_wall_secs,
        boot_id,
    };
    let payload =
        serde_json::to_vec(&meta).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let mut meta_file = create_beneath(&attempt_dir_file, OsStr::new(ATTEMPT_META_FILE), 0o600)?;
    meta_file.write_all(&payload)?;
    sync_file(&meta_file)?;
    drop(meta_file);
    sync_file(&attempt_dir_file)?;
    sync_file(&attempts_file)?;

    Ok(attempts_path.join(attempt_id))
}

/// Finalizes an attempt directory after active teardown (`D-34`, `CR-3`).
///
/// - If `reaper_confirmed` is `true` AND `verify_teardown_record_at` confirms
///   the on-disk `teardown.confirmed` record, removes the attempt directory
///   and returns `true`.
/// - Otherwise removes `profile/` if possible, writes `tombstone.json` so the
///   attempt remains counted as `cleanup_unconfirmed`, and returns `false`.
pub fn finalize_active_attempt(
    data_dir: &Path,
    attempt_id: &str,
    reaper_confirmed: bool,
    started_wall_secs: u64,
    boot_id: Option<BootId>,
) -> bool {
    let Ok(Some((attempts_file, attempts_path))) = open_attempts_root_if_present(data_dir) else {
        return false;
    };
    let attempt_path = attempts_path.join(attempt_id);
    if reaper_confirmed
        && verify_teardown_record_at(&attempt_path, attempt_id).is_ok()
        && remove_tree_beneath_and_verify(&attempts_file, OsStr::new(attempt_id)).is_ok()
    {
        let _ = sync_file(&attempts_file);
        return true;
    }

    if let Ok(attempt_dir_file) = open_dir_beneath(&attempts_file, OsStr::new(attempt_id)) {
        let _ = remove_tree_beneath_and_verify(&attempt_dir_file, OsStr::new("profile"));
        let tomb = TombstoneRecord {
            attempt_id: attempt_id.to_owned(),
            started_wall_secs,
            boot_id,
        };
        let _ = write_tombstone_beneath(&attempt_dir_file, &tomb);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use envcloak_browser::{TEARDOWN_CONFIRMATION_FILE, TeardownRecord, TeardownStep};
    use tempfile::TempDir;

    fn write_confirmed_record(attempt_dir: &Path, attempt_id: &str) {
        let profile = attempt_dir.join("profile");
        if profile.exists() {
            std::fs::remove_dir_all(&profile).expect("remove profile");
        }
        let record = TeardownRecord {
            attempt_id: attempt_id.to_owned(),
            steps: vec![
                TeardownStep::ObserveExit,
                TeardownStep::SignalGroup,
                TeardownStep::ReapLeader,
                TeardownStep::RemoveProfile,
                TeardownStep::WriteConfirmation,
            ],
        };
        std::fs::write(
            attempt_dir.join(TEARDOWN_CONFIRMATION_FILE),
            serde_json::to_vec(&record).expect("json"),
        )
        .expect("write confirmed");
    }

    #[test]
    fn sweep_removes_confirmed_and_retains_unconfirmed_until_reboot() {
        let tmp = TempDir::new().expect("tempdir");
        let data_dir = tmp.path();
        let boot_1 = BootId::new("boot-session-1");
        let boot_2 = BootId::new("boot-session-2");

        let att_confirmed =
            prepare_attempt_dir(data_dir, "att-confirmed", 100, boot_1.clone()).expect("prep 1");
        write_confirmed_record(&att_confirmed, "att-confirmed");

        let att_unconfirmed =
            prepare_attempt_dir(data_dir, "att-unconfirmed", 101, boot_1.clone()).expect("prep 2");
        // Write a dummy file inside profile/ and leave reaper.lock unlocked without teardown.confirmed (CR-3).
        std::fs::write(att_unconfirmed.join("profile/Cookies"), b"cookie-bytes").expect("cookie");
        std::fs::write(att_unconfirmed.join(REAPER_LOCK_FILE), b"").expect("lock file");

        // Same boot: confirmed is removed, unconfirmed is retained as a tombstone with profile/ removed.
        let report_1 = run(data_dir, boot_1.clone()).expect("sweep 1");
        assert_eq!(report_1.confirmed, vec!["att-confirmed".to_owned()]);
        assert_eq!(report_1.unconfirmed, vec!["att-unconfirmed".to_owned()]);
        assert!(report_1.ended_by_reboot.is_empty());
        assert!(!att_confirmed.exists());
        assert!(att_unconfirmed.exists());
        assert!(!att_unconfirmed.join("profile").exists());
        assert!(att_unconfirmed.join(TOMBSTONE_FILE).exists());
        assert_eq!(unconfirmed_count(data_dir).expect("count"), 1);

        // Next sweep on the SAME boot still keeps the unconfirmed tombstone.
        let report_same = run(data_dir, boot_1).expect("sweep same boot");
        assert!(report_same.confirmed.is_empty());
        assert_eq!(report_same.unconfirmed, vec!["att-unconfirmed".to_owned()]);
        assert!(report_same.ended_by_reboot.is_empty());

        // Sweep after reboot (boot_2 != boot_1) clears the tombstone and reports ended_by_reboot.
        let report_reboot = run(data_dir, boot_2).expect("sweep reboot");
        assert!(report_reboot.confirmed.is_empty());
        assert!(report_reboot.unconfirmed.is_empty());
        assert_eq!(
            report_reboot.ended_by_reboot,
            vec!["att-unconfirmed".to_owned()]
        );
        assert!(!att_unconfirmed.exists());
        assert_eq!(unconfirmed_count(data_dir).expect("count after reboot"), 0);
    }

    #[test]
    fn tombstone_cap_refuses_65th_unconfirmed_attempt() {
        let tmp = TempDir::new().expect("tempdir");
        let data_dir = tmp.path();
        let boot = BootId::new("boot-cap");

        for i in 0..MAX_TOMBSTONES {
            let id = format!("att-{i:03}");
            prepare_attempt_dir(data_dir, &id, 200 + i as u64, boot.clone()).expect("prepare");
        }
        assert_eq!(
            unconfirmed_count(data_dir).expect("count"),
            u32::try_from(MAX_TOMBSTONES).unwrap()
        );

        let err = prepare_attempt_dir(data_dir, "att-overflow", 999, boot)
            .expect_err("65th unconfirmed attempt must be refused");
        assert_eq!(err.to_string(), "cleanup_unconfirmed");
    }
}
