//! The SHA-256 of a caller's ancestors' executables, on Linux (SPEC §6.1
//! step 3; M2 plan D-09; docs/AGENTS.md "The executable's SHA-256").
//!
//! The walk ([`envcloak_policy::gather_hashed`]) asks [`RequestHasher`] for
//! each ancestor of the caller's uid whose executable it could read. The
//! file is read through a descriptor opened from `/proc/<pid>/exe`
//! ([`envcloak_sys::open_exe`]), never by its path: a path can name
//! another file by the time it is read (a rename over it), and the
//! descriptor is the file the process runs, renamed or removed since. The
//! descriptor's file must be the one the walk saw (its device and inode).
//!
//! Hashing a large binary on every request would be slow, so
//! [`ExeHashCache`] keeps the last [`CACHE_ENTRIES`] digests, keyed by the
//! file's device, inode, size and change time ([`FileKey`]): an in-place
//! rewrite moves the change time, even when the size and the modification
//! time are put back, and a rename over the path gives another inode. A
//! cache, unlike a store of decisions, may forget: an entry pushed out is
//! hashed again when next needed. Four rules keep a digest from outliving
//! the bytes it was taken from:
//!
//! - A file whose last change is less than [`SETTLE`] before the lookup
//!   began has no digest ([`HashError::Unsettled`]), and is not read. A
//!   file system stamps every change within one tick of its clock with the
//!   same time (a millisecond or a few on Linux, a second on HFS+, two on
//!   FAT), so a write in that tick could leave the key as it was; once the
//!   clock has moved past the file's last change, every write moves it, so
//!   a key read again later, equal, shows the file unwritten since.
//! - The key is read again after hashing: a file that changed while it was
//!   read ([`HashError::Changed`]) has no identity for that request, and
//!   nothing is cached.
//! - A cached digest is returned only when the descriptor's key, read
//!   after the digest was found, is the one it is cached under: a key read
//!   before the file changed finds the digest of what the file held, and
//!   gets [`HashError::Changed`] instead.
//! - The digest goes to the walk with the key it describes
//!   ([`envcloak_policy::ExeDigest`]), and the walk reads each hashed
//!   file's key again ([`RequestHasher`]'s `key`) once the chain is read
//!   again: a file written after it was hashed, in place (the same inode),
//!   makes the walk start over (`envcloak_policy::gather_in_hashed`).
//!
//! Hashing runs outside the state lock, and outside the cache's own lock
//! (two requests may hash the same file at once; each gets the digest).
//! Each request may hash at most [`REQUEST_BUDGET`] bytes not already
//! cached ([`HashBudget`]), and no file larger than [`MAX_HASHED`]: past
//! either, the executable's identity is unknown for that request. An
//! unknown identity never changes a classification (the walk's root, kind,
//! labels and proof refusals do not depend on it), and no standing
//! approval can name it (M2 plan D-10). An agent updated less than
//! [`SETTLE`] before a request has no identity for that request.
//!
//! macOS: [`envcloak_sys::open_exe`] is unsupported and the walk reads no
//! device and inode there, so nothing is hashed; the code signature's
//! cdhash names the build.

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use envcloak_policy::{ExeDigest, ExeHasher};
use envcloak_sys::{FileKey, ProcInfo};
use sha2::{Digest, Sha256};

use crate::server::locked;

/// The digests the cache keeps.
pub(crate) const CACHE_ENTRIES: usize = 256;
/// The largest executable hashed: a larger one has no Linux identity.
pub(crate) const MAX_HASHED: u64 = 512 * 1024 * 1024;
/// The bytes one request may hash that are not already cached.
pub(crate) const REQUEST_BUDGET: u64 = 1024 * 1024 * 1024;
/// How long before a lookup began a file must have last changed for it to
/// have a digest (see the module documentation).
pub(crate) const SETTLE: Duration = Duration::from_secs(2);
/// The read size.
const CHUNK: usize = 64 * 1024;

/// Why an executable has no digest. Value-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HashError {
    /// Larger than the cache's largest ([`MAX_HASHED`]).
    TooLarge,
    /// More than the request's budget has left ([`REQUEST_BUDGET`]).
    OverBudget,
    /// The file changed while it was read: its key after the read differs,
    /// or it ended before or ran past its size.
    Changed,
    /// The file changed less than the settle time before the lookup began
    /// ([`SETTLE`]): its key could stay the same through a later write.
    Unsettled,
    /// A read failed.
    Io(io::ErrorKind),
}

/// The bytes a request may still hash ([`REQUEST_BUDGET`] at first).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HashBudget {
    left: u64,
}

impl HashBudget {
    pub(crate) fn new(bytes: u64) -> Self {
        HashBudget { left: bytes }
    }

    /// Takes `n` bytes, or refuses and takes nothing.
    fn take(&mut self, n: u64) -> Result<(), HashError> {
        self.left = self.left.checked_sub(n).ok_or(HashError::OverBudget)?;
        Ok(())
    }
}

#[derive(Debug)]
struct Entry {
    sha256: [u8; 32],
    /// When it was last used, in lookups: the least recently used goes
    /// first when the cache is full.
    used: u64,
}

#[derive(Debug, Default)]
struct Inner {
    entries: HashMap<FileKey, Entry>,
    lookups: u64,
    /// Bytes hashed since the cache was made (tests).
    hashed: u64,
}

/// The digests of the executables hashed so far. See the module
/// documentation.
#[derive(Debug)]
pub(crate) struct ExeHashCache {
    inner: Mutex<Inner>,
    capacity: usize,
    max_size: u64,
    settle: Duration,
}

impl ExeHashCache {
    pub(crate) fn new() -> Self {
        Self::with_limits(CACHE_ENTRIES, MAX_HASHED, SETTLE)
    }

    /// A cache of `capacity` digests that hashes no file larger than
    /// `max_size` and gives no digest for one changed less than `settle`
    /// before the lookup began.
    pub(crate) fn with_limits(capacity: usize, max_size: u64, settle: Duration) -> Self {
        ExeHashCache {
            inner: Mutex::new(Inner::default()),
            capacity: capacity.max(1),
            max_size,
            settle,
        }
    }

    /// The SHA-256 of the open file `file`, whose key (`FileKey::of`) the
    /// caller read as `key`: from the cache when a digest for `key` is
    /// there and `file` still has that key, otherwise read from `file`,
    /// within `budget`, its key read again afterwards, and cached. Either
    /// way the digest is returned only for a file whose key, read after the
    /// digest was found, is `key`: a key the caller read before the file
    /// changed never answers with the digest of what it held. A file that
    /// changed less than the settle time before the lookup began has none.
    ///
    /// # Errors
    /// [`HashError::Unsettled`] for a file changed less than the settle
    /// time before (and then nothing is read or taken),
    /// [`HashError::TooLarge`] above the largest size,
    /// [`HashError::OverBudget`] when `budget` has less left than the
    /// file's size (and then takes nothing), [`HashError::Changed`] when
    /// the file no longer has `key`, or changed while it was read,
    /// [`HashError::Io`] when a read failed.
    pub(crate) fn lookup(
        &self,
        file: &File,
        key: &FileKey,
        budget: &mut HashBudget,
    ) -> Result<[u8; 32], HashError> {
        if !settled(key, SystemTime::now(), self.settle) {
            return Err(HashError::Unsettled);
        }
        let cached = {
            let mut inner = locked(&self.inner);
            inner.lookups += 1;
            let now = inner.lookups;
            inner.entries.get_mut(key).map(|e| {
                e.used = now;
                e.sha256
            })
        };
        if let Some(digest) = cached {
            // Read after the lookup, outside the lock: the file is the
            // one the key names now.
            let now = FileKey::of(file).map_err(|e| HashError::Io(e.kind()))?;
            return if now == *key {
                Ok(digest)
            } else {
                Err(HashError::Changed)
            };
        }
        if key.size > self.max_size {
            return Err(HashError::TooLarge);
        }
        budget.take(key.size)?;
        let digest = hash_exactly(file, key.size)?;
        let after = FileKey::of(file).map_err(|e| HashError::Io(e.kind()))?;
        if after != *key {
            return Err(HashError::Changed);
        }
        let mut inner = locked(&self.inner);
        inner.hashed = inner.hashed.saturating_add(key.size);
        if inner.entries.len() >= self.capacity {
            let oldest = inner
                .entries
                .iter()
                .min_by_key(|(_, e)| e.used)
                .map(|(k, _)| *k);
            if let Some(k) = oldest {
                inner.entries.remove(&k);
            }
        }
        let used = inner.lookups;
        inner.entries.insert(
            *key,
            Entry {
                sha256: digest,
                used,
            },
        );
        Ok(digest)
    }

    /// Bytes hashed since the cache was made.
    #[cfg(test)]
    pub(crate) fn hashed_bytes(&self) -> u64 {
        locked(&self.inner).hashed
    }
}

/// Whether the file whose key is `key` last changed at least `settle`
/// before `began`, by the system clock. A change time the clock has not
/// reached (it was set back) is not settled.
fn settled(key: &FileKey, began: SystemTime, settle: Duration) -> bool {
    let (secs, nanos) = key.ctime;
    let (Ok(secs), Ok(nanos)) = (u64::try_from(secs), u32::try_from(nanos)) else {
        return false;
    };
    let Some(changed) = UNIX_EPOCH.checked_add(Duration::new(secs, 0)) else {
        return false;
    };
    let Some(changed) = changed.checked_add(Duration::from_nanos(u64::from(nanos))) else {
        return false;
    };
    began
        .duration_since(changed)
        .is_ok_and(|since| since >= settle)
}

/// The SHA-256 of the first `size` bytes of `file`, read from its start
/// whatever its offset. The read stops, `Changed`, where a file shorter
/// than `size` ends; a file whose size is not `size`, or that changed in
/// any other way, is caught by its key, which [`ExeHashCache::lookup`]
/// reads again after this (so stopping early only ends the loop).
fn hash_exactly(file: &File, size: u64) -> Result<[u8; 32], HashError> {
    let mut h = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let mut at = 0u64;
    while at < size {
        let want = usize::try_from((size - at).min(CHUNK as u64)).unwrap_or(CHUNK);
        let n = match file.read_at(&mut buf[..want], at) {
            Ok(0) => return Err(HashError::Changed),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(HashError::Io(e.kind())),
        };
        h.update(&buf[..n]);
        at += n as u64;
    }
    Ok(h.finalize().into())
}

/// The digest of the file process `p` runs, if it is the file the walk
/// saw, with the key it describes: opened through `/proc/<pid>/exe`, its
/// device and inode compared with those the walk read. `None` otherwise,
/// and on macOS.
pub(crate) fn exe_sha256(
    cache: &ExeHashCache,
    p: &ProcInfo,
    budget: &mut HashBudget,
) -> Option<ExeDigest> {
    let walked = p.exe.as_ref()?.file?;
    let file = envcloak_sys::open_exe(p.pid).ok()?;
    let key = FileKey::of(&file).ok()?;
    if (key.dev, key.ino) != walked {
        return None;
    }
    let sha256 = cache.lookup(&file, &key, budget).ok()?;
    Some(ExeDigest { sha256, key })
}

/// The key of the file process `p` runs now, through a new descriptor
/// opened from `/proc/<pid>/exe`. `None` when it cannot be opened (the
/// process exited or is no longer dumpable), and on macOS.
pub(crate) fn exe_key(p: &ProcInfo) -> Option<FileKey> {
    let file = envcloak_sys::open_exe(p.pid).ok()?;
    FileKey::of(&file).ok()
}

/// One request's hashing: the daemon's cache, and the request's budget.
#[derive(Debug)]
pub(crate) struct RequestHasher<'a> {
    cache: &'a ExeHashCache,
    budget: HashBudget,
}

impl<'a> RequestHasher<'a> {
    pub(crate) fn new(cache: &'a ExeHashCache) -> Self {
        Self::with_budget(cache, REQUEST_BUDGET)
    }

    pub(crate) fn with_budget(cache: &'a ExeHashCache, bytes: u64) -> Self {
        RequestHasher {
            cache,
            budget: HashBudget::new(bytes),
        }
    }
}

impl ExeHasher for RequestHasher<'_> {
    fn sha256(&mut self, p: &ProcInfo) -> Option<ExeDigest> {
        exe_sha256(self.cache, p, &mut self.budget)
    }

    fn key(&mut self, p: &ProcInfo) -> Option<FileKey> {
        exe_key(p)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::io::Write;
    use std::path::Path;

    /// The SHA-256 of `path` as the system's own tool computes it, an
    /// oracle apart from this crate's hasher (lesson L-02).
    pub(crate) fn oracle(path: &Path) -> [u8; 32] {
        let out = if cfg!(target_os = "macos") {
            std::process::Command::new("/usr/bin/shasum")
                .args(["-a", "256"])
                .arg(path)
                .output()
                .unwrap()
        } else {
            std::process::Command::new("sha256sum")
                .arg(path)
                .output()
                .unwrap()
        };
        assert!(out.status.success(), "the oracle failed");
        let hex = String::from_utf8(out.stdout).unwrap();
        let hex = hex.split_whitespace().next().unwrap().to_owned();
        let mut d = [0u8; 32];
        for (i, b) in d.iter_mut().enumerate() {
            *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        }
        d
    }

    pub(crate) fn dir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("ech")
            .tempdir_in("/tmp")
            .unwrap()
    }

    fn write(path: &Path, bytes: &[u8]) {
        let mut f = File::create(path).unwrap();
        f.write_all(bytes).unwrap();
        f.sync_all().unwrap();
    }

    /// Waits until a change to `f` would move its change time
    /// ([`envcloak_sys::wait_for_clock_past`] on its directory).
    fn clock_past(dir: &Path, f: &File) {
        let k = FileKey::of(f).unwrap();
        let d = File::open(dir).unwrap();
        envcloak_sys::wait_for_clock_past(&d, k.ctime, Duration::from_secs(5)).unwrap();
    }

    /// A cache that takes every file as settled: the tests' files were
    /// written just now.
    pub(crate) fn settled_at_once() -> ExeHashCache {
        ExeHashCache::with_limits(CACHE_ENTRIES, MAX_HASHED, Duration::ZERO)
    }

    fn lookup(cache: &ExeHashCache, f: &File) -> Result<[u8; 32], HashError> {
        let key = FileKey::of(f).unwrap();
        cache.lookup(f, &key, &mut HashBudget::new(REQUEST_BUDGET))
    }

    /// A binary rewritten in place, its size kept and its modification
    /// time put back, has a new change time, so a new key and a new digest:
    /// the cache never answers for it with the digest of what it held.
    /// Mutation checked: keying the cache by device and inode only fails
    /// this test (the old digest comes back).
    #[test]
    fn a_rewrite_in_place_with_size_and_mtime_kept_gets_a_new_hash() {
        let d = dir();
        let p = d.path().join("agent");
        write(&p, &[1u8; 4096]);
        let f = File::options().read(true).write(true).open(&p).unwrap();
        let cache = settled_at_once();
        let first = lookup(&cache, &f).unwrap();
        assert_eq!(first, oracle(&p));
        clock_past(d.path(), &f);
        let mtime = f.metadata().unwrap().modified().unwrap();
        let before = FileKey::of(&f).unwrap();
        f.write_all_at(&[2], 100).unwrap();
        f.set_modified(mtime).unwrap();
        let after = FileKey::of(&f).unwrap();
        assert_eq!(
            (after.dev, after.ino, after.size),
            (before.dev, before.ino, before.size)
        );
        assert_eq!(f.metadata().unwrap().modified().unwrap(), mtime);
        assert_ne!(after.ctime, before.ctime);
        let second = lookup(&cache, &f).unwrap();
        assert_eq!(second, oracle(&p));
        assert_ne!(second, first);
    }

    /// A rename over the path gives another inode and its own digest; the
    /// descriptor of the old file still hashes the old file, whatever the
    /// path names now.
    #[test]
    fn a_rename_over_gives_a_new_inode_and_hash() {
        let d = dir();
        let p = d.path().join("agent");
        write(&p, b"first build");
        let old = File::open(&p).unwrap();
        let cache = settled_at_once();
        let first = lookup(&cache, &old).unwrap();
        let first_oracle = oracle(&p);
        assert_eq!(first, first_oracle);
        let tmp = d.path().join("agent.new");
        write(&tmp, b"second build");
        std::fs::rename(&tmp, &p).unwrap();
        let new = File::open(&p).unwrap();
        assert_ne!(
            FileKey::of(&new).unwrap().ino,
            FileKey::of(&old).unwrap().ino
        );
        let second = lookup(&cache, &new).unwrap();
        assert_eq!(second, oracle(&p));
        assert_ne!(second, first);
        // The old file, by its descriptor, cached or hashed again.
        assert_eq!(lookup(&cache, &old).unwrap(), first_oracle);
        assert_eq!(
            lookup(&settled_at_once(), &old).unwrap(),
            first_oracle,
            "hashed again from the descriptor"
        );
    }

    /// The key is read again after hashing: a file that changed after its
    /// key was read has no digest, and nothing is cached for the stale key.
    /// A key whose size the file does not have gives none either: the
    /// file's key, read again after the read, differs (and a file shorter
    /// than that size ends the read early). Mutation checked: skipping the
    /// key's re-read fails this test; treating an early end as the end of
    /// the file does not (the key's re-read catches it), so that branch
    /// only ends the loop.
    #[test]
    fn a_file_changed_while_it_is_read_has_no_digest() {
        let d = dir();
        let p = d.path().join("agent");
        write(&p, &[3u8; 1000]);
        let f = File::options().read(true).write(true).open(&p).unwrap();
        let cache = settled_at_once();
        let stale = FileKey::of(&f).unwrap();
        clock_past(d.path(), &f);
        f.write_all_at(&[4], 10).unwrap();
        let mut budget = HashBudget::new(REQUEST_BUDGET);
        assert_eq!(
            cache.lookup(&f, &stale, &mut budget),
            Err(HashError::Changed)
        );
        assert_eq!(
            cache.lookup(&f, &stale, &mut budget),
            Err(HashError::Changed),
            "nothing was cached for the stale key"
        );
        // Its key as it is now gives the digest of what it holds now.
        assert_eq!(lookup(&cache, &f).unwrap(), oracle(&p));
        // A size the file does not have, either way.
        let now = FileKey::of(&f).unwrap();
        for size in [999, 1001] {
            let wrong = FileKey { size, ..now };
            assert_eq!(
                settled_at_once().lookup(&f, &wrong, &mut HashBudget::new(REQUEST_BUDGET)),
                Err(HashError::Changed),
                "size {size}"
            );
        }
    }

    /// A cached digest is returned only for a file that still has the key
    /// it is cached under: a key read before the file changed (the caller
    /// read it, then the file was rewritten) finds the old digest in the
    /// cache and gets `Changed`, not that digest; the file's key as it is
    /// now gives what it holds now. Mutation checked: returning a cached
    /// digest without reading the descriptor's key again fails this test.
    #[test]
    fn a_cached_digest_needs_the_file_to_still_have_its_key() {
        let d = dir();
        let p = d.path().join("agent");
        write(&p, &[8u8; 2048]);
        let f = File::options().read(true).write(true).open(&p).unwrap();
        let cache = settled_at_once();
        let stale = FileKey::of(&f).unwrap();
        let first = lookup(&cache, &f).unwrap();
        assert_eq!(first, oracle(&p));
        clock_past(d.path(), &f);
        f.write_all_at(&[9], 7).unwrap();
        assert_ne!(FileKey::of(&f).unwrap(), stale);
        let mut budget = HashBudget::new(REQUEST_BUDGET);
        assert_eq!(
            cache.lookup(&f, &stale, &mut budget),
            Err(HashError::Changed)
        );
        assert_eq!(budget, HashBudget::new(REQUEST_BUDGET), "nothing hashed");
        let now = lookup(&cache, &f).unwrap();
        assert_eq!(now, oracle(&p));
        assert_ne!(now, first);
        // The control: the file unchanged, the cached digest comes back
        // without a byte read.
        let hashed = cache.hashed_bytes();
        assert_eq!(lookup(&cache, &f).unwrap(), now);
        assert_eq!(cache.hashed_bytes(), hashed);
    }

    /// A 200 MB binary is hashed once: the second lookup is the cache's.
    #[test]
    fn a_200_mb_binary_is_hashed_once() {
        let d = dir();
        let p = d.path().join("agent");
        let f = File::create(&p).unwrap();
        f.set_len(200 * 1024 * 1024).unwrap();
        let f = File::open(&p).unwrap();
        let cache = settled_at_once();
        let first = lookup(&cache, &f).unwrap();
        assert_eq!(cache.hashed_bytes(), 200 * 1024 * 1024);
        assert_eq!(lookup(&cache, &f).unwrap(), first);
        assert_eq!(cache.hashed_bytes(), 200 * 1024 * 1024, "hashed once");
        assert_eq!(first, oracle(&p));
    }

    /// A file changed less than the settle time before the lookup began
    /// has no digest, and is not read: a write in the same tick of the file
    /// system's clock could leave its key as it was, so neither the cache
    /// nor the walk's check of the key after hashing could tell that it
    /// changed (Codex review: a digest kept past the bytes it names). A
    /// settle time no test can outwait stands for "just now". Mutation
    /// checked: dropping the settle check fails this test (the file is
    /// hashed and its digest returned).
    #[test]
    fn a_file_changed_just_now_has_no_digest() {
        let d = dir();
        let p = d.path().join("agent");
        write(&p, &[5u8; 512]);
        let f = File::open(&p).unwrap();
        let cache = ExeHashCache::with_limits(CACHE_ENTRIES, MAX_HASHED, Duration::from_secs(3600));
        let mut budget = HashBudget::new(REQUEST_BUDGET);
        let key = FileKey::of(&f).unwrap();
        assert_eq!(
            cache.lookup(&f, &key, &mut budget),
            Err(HashError::Unsettled)
        );
        assert_eq!(budget, HashBudget::new(REQUEST_BUDGET), "nothing taken");
        assert_eq!(cache.hashed_bytes(), 0, "nothing read");
        assert!(locked(&cache.inner).entries.is_empty());
        // The control: settled, it is hashed once and cached.
        let cache = settled_at_once();
        assert_eq!(lookup(&cache, &f).unwrap(), oracle(&p));
        lookup(&cache, &f).unwrap();
        assert_eq!(cache.hashed_bytes(), 512);
        // A change time the clock has not reached is not settled.
        let key = FileKey::of(&f).unwrap();
        let future = FileKey {
            ctime: (key.ctime.0 + 3600, 0),
            ..key
        };
        assert!(!settled(&future, SystemTime::now(), Duration::ZERO));
        assert!(settled(&key, SystemTime::now() + SETTLE, SETTLE));
    }

    /// A request's budget and the largest size: past either, no digest,
    /// and a refused file takes nothing from the budget. A cached digest
    /// costs none. Mutation checked: ignoring the budget fails this test.
    #[test]
    fn the_budget_and_the_largest_size_refuse() {
        let d = dir();
        let small = d.path().join("small");
        write(&small, &[6u8; 50]);
        let large = d.path().join("large");
        write(&large, &[7u8; 200]);
        let (small, large) = (File::open(&small).unwrap(), File::open(&large).unwrap());
        let cache = settled_at_once();
        let mut budget = HashBudget::new(100);
        let k = FileKey::of(&large).unwrap();
        assert_eq!(
            cache.lookup(&large, &k, &mut budget),
            Err(HashError::OverBudget)
        );
        assert_eq!(budget, HashBudget::new(100));
        let k = FileKey::of(&small).unwrap();
        cache.lookup(&small, &k, &mut budget).unwrap();
        assert_eq!(budget, HashBudget::new(50));
        cache.lookup(&small, &k, &mut budget).unwrap();
        assert_eq!(budget, HashBudget::new(50), "cached: free");
        let mut empty = HashBudget::new(0);
        cache.lookup(&small, &k, &mut empty).unwrap();
        // The largest size, refused before a byte is read.
        let capped = ExeHashCache::with_limits(CACHE_ENTRIES, 199, Duration::ZERO);
        let k = FileKey::of(&large).unwrap();
        assert_eq!(
            capped.lookup(&large, &k, &mut HashBudget::new(REQUEST_BUDGET)),
            Err(HashError::TooLarge)
        );
        assert_eq!(capped.hashed_bytes(), 0);
        let huge = d.path().join("huge");
        let f = File::create(&huge).unwrap();
        f.set_len(MAX_HASHED + 1).unwrap();
        let f = File::open(&huge).unwrap();
        let cache = settled_at_once();
        assert_eq!(lookup(&cache, &f), Err(HashError::TooLarge));
        assert_eq!(cache.hashed_bytes(), 0);
    }

    /// The cache holds at most its capacity; the least recently used goes
    /// first and is hashed again when next needed.
    #[test]
    fn the_cache_forgets_the_least_recently_used() {
        let d = dir();
        let files: Vec<File> = (0..3u8)
            .map(|i| {
                let p = d.path().join(format!("f{i}"));
                write(&p, &[i; 10]);
                File::open(&p).unwrap()
            })
            .collect();
        let cache = ExeHashCache::with_limits(2, MAX_HASHED, Duration::ZERO);
        lookup(&cache, &files[0]).unwrap();
        lookup(&cache, &files[1]).unwrap();
        lookup(&cache, &files[0]).unwrap();
        lookup(&cache, &files[2]).unwrap();
        assert_eq!(cache.hashed_bytes(), 30);
        assert_eq!(locked(&cache.inner).entries.len(), 2);
        // f1 went; f0 stayed.
        lookup(&cache, &files[0]).unwrap();
        assert_eq!(cache.hashed_bytes(), 30);
        lookup(&cache, &files[1]).unwrap();
        assert_eq!(cache.hashed_bytes(), 40);
    }
}

/// Real processes on Linux: what the walk records about them.
#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod linux_tests {
    #![allow(clippy::unwrap_used)]
    use super::tests::{dir, oracle, settled_at_once};
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};

    use envcloak_policy::{AgentCatalog, Claims, gather, gather_hashed};
    use envcloak_sys::{PeerIdentity, PeerSource};

    /// The system's `sleep`.
    fn sleep_bin() -> PathBuf {
        ["/usr/bin/sleep", "/bin/sleep"]
            .into_iter()
            .map(PathBuf::from)
            .find(|p| p.is_file())
            .expect("sleep is needed")
    }

    /// A copy of `sleep` at `path`, with `extra` bytes after it (an ELF
    /// file runs whatever trails it, and hashes otherwise).
    fn install(path: &Path, extra: &[u8]) {
        let mut bytes = std::fs::read(sleep_bin()).unwrap();
        bytes.extend_from_slice(extra);
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, bytes).unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::rename(&tmp, path).unwrap();
    }

    /// `path` started, killed on drop.
    struct Running(Child);

    impl Running {
        fn start(path: &Path) -> Self {
            let child = Command::new(path)
                .arg("120")
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            // The child runs the file once its exec is done: wait for its
            // executable to be the file at `path` (a bounded poll on the
            // kernel's own state, not a guessed delay).
            let pid = i32::try_from(child.id()).unwrap();
            let want = std::fs::metadata(path).unwrap();
            let want = {
                use std::os::unix::fs::MetadataExt;
                (want.dev(), want.ino())
            };
            let end = std::time::Instant::now() + Duration::from_secs(10);
            while envcloak_sys::proc_info(pid)
                .ok()
                .and_then(|p| p.exe.and_then(|e| e.file))
                != Some(want)
            {
                assert!(
                    std::time::Instant::now() < end,
                    "the child never ran {path:?}"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            Running(child)
        }

        fn info(&self) -> ProcInfo {
            envcloak_sys::proc_info(i32::try_from(self.0.id()).unwrap()).unwrap()
        }

        fn peer(&self) -> PeerIdentity {
            let p = self.info();
            PeerIdentity {
                uid: envcloak_sys::effective_uid(),
                pid: p.pid,
                start_time: p.start_time,
                pidversion: None,
                source: PeerSource::PeerCred,
            }
        }
    }

    impl Drop for Running {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn sha(p: &ProcInfo, cache: &ExeHashCache) -> Option<[u8; 32]> {
        exe_sha256(cache, p, &mut HashBudget::new(REQUEST_BUDGET)).map(|d| d.sha256)
    }

    /// The digest of a running process's executable is that of the file it
    /// runs, read through its descriptor: a rename over its path afterwards
    /// changes nothing for it, while a process started from the path after
    /// the rename gets the new file's digest. Mutation checked: hashing the
    /// path the kernel reports instead of the descriptor fails this test.
    #[test]
    fn the_running_file_is_hashed_not_its_path() {
        let d = dir();
        let p = d.path().join("agent");
        install(&p, b"");
        let first = oracle(&p);
        let a = Running::start(&p);
        let cache = settled_at_once();
        assert_eq!(sha(&a.info(), &cache), Some(first));
        install(&p, b"\0another build");
        let second = oracle(&p);
        assert_ne!(first, second);
        // The file it runs has no name now: the kernel shows the old path,
        // marked removed, and the path names the new file.
        let shown = a.info().exe.unwrap().path;
        assert_eq!(shown, PathBuf::from(format!("{} (deleted)", p.display())));
        assert_eq!(sha(&a.info(), &cache), Some(first), "the file it runs");
        let b = Running::start(&p);
        assert_eq!(sha(&b.info(), &cache), Some(second));
        assert_eq!(sha(&a.info(), &cache), Some(first));
    }

    /// An executable removed while it runs is hashed from its descriptor:
    /// the file stays until its last user closes it (docs/AGENTS.md).
    #[test]
    fn a_deleted_running_executable_is_hashed_from_its_descriptor() {
        let d = dir();
        let p = d.path().join("agent");
        install(&p, b"");
        let first = oracle(&p);
        let a = Running::start(&p);
        std::fs::remove_file(&p).unwrap();
        let info = a.info();
        let shown = info
            .exe
            .as_ref()
            .unwrap()
            .path
            .to_string_lossy()
            .into_owned();
        assert!(shown.ends_with(" (deleted)"), "{shown}");
        assert_eq!(sha(&info, &settled_at_once()), Some(first));
    }

    /// A descriptor whose file is not the one the walk saw (its device and
    /// inode) gives no digest: the process ran another file meanwhile.
    #[test]
    fn a_file_other_than_the_walks_has_no_digest() {
        let d = dir();
        let p = d.path().join("agent");
        install(&p, b"");
        let a = Running::start(&p);
        let mut info = a.info();
        let file = info.exe.as_ref().unwrap().file.unwrap();
        info.exe.as_mut().unwrap().file = Some((file.0, file.1 ^ 1));
        assert_eq!(sha(&info, &settled_at_once()), None);
        // The control: the walk's own device and inode.
        assert!(sha(&a.info(), &settled_at_once()).is_some());
    }

    /// Codex review (medium): the walk keeps a digest only while the file
    /// it was taken from is in that state. Right after the running file is
    /// hashed, its state changes and its inode stays, as with a write in
    /// place (here a permission change: a running file cannot be opened
    /// for writing); the walk reads the file's key again through the
    /// production hasher ([`RequestHasher`]), sees the change, and walks
    /// and hashes again, so the evidence's digest is taken from the file
    /// as it is now (the bytes are the same; the key is the new one). The
    /// control: unchanged, it is hashed once. Mutation checked (CI, Linux):
    /// leaving the key out of the walk's check after hashing fails this
    /// test (hashed once).
    #[test]
    fn a_file_whose_state_changed_after_hashing_is_hashed_again() {
        /// The production hasher, which changes the state of `path` once,
        /// right after it hashed `pid`'s file.
        struct ChangingOnce<'a> {
            inner: RequestHasher<'a>,
            path: PathBuf,
            pid: i32,
            change: bool,
            hashed: usize,
            keys: Vec<FileKey>,
        }
        impl ExeHasher for ChangingOnce<'_> {
            fn sha256(&mut self, p: &ProcInfo) -> Option<ExeDigest> {
                let d = self.inner.sha256(p);
                if p.pid == self.pid {
                    self.hashed += 1;
                    if std::mem::take(&mut self.change) {
                        let k = FileKey::of(&File::open(&self.path).unwrap()).unwrap();
                        let dir = File::open(self.path.parent().unwrap()).unwrap();
                        envcloak_sys::wait_for_clock_past(&dir, k.ctime, Duration::from_secs(5))
                            .unwrap();
                        std::fs::set_permissions(
                            &self.path,
                            std::fs::Permissions::from_mode(0o750),
                        )
                        .unwrap();
                    }
                }
                d
            }

            fn key(&mut self, p: &ProcInfo) -> Option<FileKey> {
                let k = self.inner.key(p);
                if p.pid == self.pid {
                    self.keys.extend(k);
                }
                k
            }
        }
        let d = dir();
        let p = d.path().join("agent");
        install(&p, b"");
        let first = oracle(&p);
        let a = Running::start(&p);
        let cat = AgentCatalog::builtin();
        for change in [true, false] {
            let cache = settled_at_once();
            let mut h = ChangingOnce {
                inner: RequestHasher::new(&cache),
                path: p.clone(),
                pid: a.info().pid,
                change,
                hashed: 0,
                keys: Vec::new(),
            };
            let e = gather_hashed(&a.peer(), Claims::none(), &cat, &mut h).unwrap();
            let now = FileKey::of(&File::open(&p).unwrap()).unwrap();
            assert_eq!(h.hashed, if change { 2 } else { 1 }, "change: {change}");
            assert_eq!(h.keys.last(), Some(&now), "change: {change}");
            assert_eq!(
                e.chain()[0].instance.exe.as_ref().unwrap().sha256,
                Some(first)
            );
        }
    }

    /// Codex review (medium): the digests reach a request's evidence on
    /// the daemon's own path, `requests::evidence` (which `unlock` reads
    /// its evidence through too), with the production cache and settle
    /// time: a caller running a system program, settled long ago, has
    /// that program's SHA-256 as the system's tool computes it; a copy
    /// written just now has none while it is not settled. Mutation checked
    /// (CI, Linux): reading the evidence there without the hasher
    /// (`gather`) fails this test.
    #[test]
    fn a_requests_evidence_carries_each_readable_executables_digest() {
        let d = dir();
        let shared = crate::server::Shared::for_tests(envcloak_core::vault::VaultPaths::under(
            d.path().join("data"),
        ));
        let sleep = std::fs::canonicalize(sleep_bin()).unwrap();
        let a = Running::start(&sleep);
        let e = crate::requests::evidence(&shared, &a.peer(), &[]).unwrap();
        assert_eq!(
            e.chain()[0].instance.exe.as_ref().unwrap().sha256,
            Some(oracle(&sleep)),
            "{e:?}"
        );
        let p = d.path().join("agent");
        install(&p, b"");
        let written = FileKey::of(&File::open(&p).unwrap()).unwrap();
        let b = Running::start(&p);
        let e = crate::requests::evidence(&shared, &b.peer(), &[]).unwrap();
        let answered = SystemTime::now();
        let digest = e.chain()[0].instance.exe.as_ref().unwrap().sha256;
        if settled(&written, answered, SETTLE) {
            eprintln!("the copy settled before the request ended (a loaded machine)");
            assert_eq!(digest, Some(oracle(&p)));
        } else {
            assert_eq!(digest, None, "not settled when the request ended");
        }
    }

    /// The walk records each hashed ancestor's digest; with the budget
    /// spent, none, and the classification (root, kind, labels, proof
    /// refusal, coverage) is the same either way, and the same as without
    /// hashing. Mutation checked: letting an unknown identity count as a
    /// match fails nothing here by design; the test pins that the budget
    /// changes only `sha256`.
    #[test]
    fn a_spent_budget_leaves_the_identity_unknown_and_the_classification_alone() {
        let d = dir();
        let p = d.path().join("agent");
        install(&p, b"");
        let first = oracle(&p);
        let a = Running::start(&p);
        let cat = AgentCatalog::builtin();
        let cache = settled_at_once();
        let plain = gather(&a.peer(), Claims::none(), &cat).unwrap();
        let mut full = RequestHasher::new(&cache);
        let hashed = gather_hashed(&a.peer(), Claims::none(), &cat, &mut full).unwrap();
        // A budget spent, on a cache that does not hold the file yet.
        let empty = settled_at_once();
        let mut none = RequestHasher::with_budget(&empty, 0);
        let spent = gather_hashed(&a.peer(), Claims::none(), &cat, &mut none).unwrap();
        let caller = |e: &envcloak_policy::SubjectEvidence| {
            e.chain()[0].instance.exe.as_ref().unwrap().sha256
        };
        assert_eq!(caller(&hashed), Some(first));
        assert_eq!(caller(&plain), None);
        assert_eq!(caller(&spent), None);
        assert_eq!(empty.hashed_bytes(), 0);
        for e in [&hashed, &spent] {
            assert_eq!(e.kind(), plain.kind());
            assert!(e.root().same(&plain.root()));
            assert_eq!(e.root_index(), plain.root_index());
            assert_eq!(e.label(), plain.label());
            assert_eq!(e.proof_refusal(), plain.proof_refusal());
            assert_eq!(e.chain().len(), plain.chain().len());
            for (x, y) in e.chain().iter().zip(plain.chain()) {
                assert!(x.instance.same(&y.instance));
                assert_eq!((x.sid, x.terminal, &x.agent), (y.sid, y.terminal, &y.agent));
            }
        }
    }
}
