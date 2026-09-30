//! The audit log (SPEC §6.1 step 5, §15.2 gate 33): entries are flushed
//! before an append returns, a failed write or flush leaves the log whole,
//! entries are sealed and hold no values, and a modified, deleted or
//! reordered entry is flagged at its sequence number, with an unanchored
//! tail reported as such.
//!
//! The segment layout the tests edit is the one docs/VAULT.md "Audit log"
//! gives: a 101-byte header, then frames of `len(4) seq(8) sealed(len)
//! mac(32)`.
#![allow(clippy::unwrap_used)]

mod common;

use std::fs::File;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use common::{Fixture, name, secret_item};
use envcloak_core::SecretBytes;
use envcloak_core::audit::{
    AnchorCheck, AuditIo, AuditKind, AuditRecord, AuditWriter, DecisionSummary, HEADER_LEN,
    MAX_ENTRY, MAX_SEGMENT, OsIo, Problem, ProblemKind, ProjectSummary, SubjectSummary,
    VerifyReport, read_entries, verify,
};
use envcloak_core::crypto::Keyring;
use envcloak_core::vault::{AuditHead, INITIAL_EPOCH, ItemId, Slug};
use envcloak_testkit::{assert_no_canary, by_label, canaries, fresh_seed, labels};

/// One write or flush the writer made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    /// Bytes appended to a segment.
    Write(usize),
    /// A segment flushed.
    SyncFile,
    /// The directory flushed.
    SyncDir,
}

/// What the shim is told to do.
#[derive(Debug, Default)]
struct Plan {
    ops: Vec<Op>,
    /// Fail the next write of a frame (not a header).
    fail_frame_write: bool,
    /// Fail the next flush of a segment.
    fail_file_sync: bool,
    /// Fail the next flush of a directory.
    fail_dir_sync: bool,
    /// The directories flushed, by device and inode.
    synced_dirs: Vec<(u64, u64)>,
    /// Rename this file to that one just before the next frame is written,
    /// as another program racing the writer would.
    move_before_frame: Option<(PathBuf, PathBuf)>,
}

/// The counting shim: records every call, then runs the real one, or fails
/// when the plan says so.
#[derive(Clone, Default)]
struct Shim(Arc<Mutex<Plan>>);

impl Shim {
    fn ops(&self) -> Vec<Op> {
        std::mem::take(&mut self.0.lock().unwrap().ops)
    }

    fn plan(&self) -> std::sync::MutexGuard<'_, Plan> {
        self.0.lock().unwrap()
    }
}

impl AuditIo for Shim {
    fn write(&mut self, f: &File, bytes: &[u8]) -> io::Result<()> {
        let mut p = self.0.lock().unwrap();
        p.ops.push(Op::Write(bytes.len()));
        if bytes.len() != HEADER_LEN {
            if let Some((from, to)) = p.move_before_frame.take() {
                std::fs::rename(from, to)?;
            }
        }
        if bytes.len() != HEADER_LEN && p.fail_frame_write {
            p.fail_frame_write = false;
            // Half the frame reaches the file, as a full disk would leave it.
            OsIo.write(f, &bytes[..bytes.len() / 2])?;
            return Err(io::Error::from_raw_os_error(libc::ENOSPC));
        }
        OsIo.write(f, bytes)
    }

    fn sync(&mut self, f: &File) -> io::Result<()> {
        let mut p = self.0.lock().unwrap();
        let m = f.metadata()?;
        let dir = m.is_dir();
        p.ops.push(if dir { Op::SyncDir } else { Op::SyncFile });
        if dir {
            p.synced_dirs.push((m.dev(), m.ino()));
        }
        if !dir && p.fail_file_sync {
            p.fail_file_sync = false;
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        if dir && p.fail_dir_sync {
            p.fail_dir_sync = false;
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        OsIo.sync(f)
    }
}

/// A vault to take keys from, its log directory and its keyring.
struct Log {
    f: Fixture,
    dir: PathBuf,
    keys: Keyring,
}

impl Log {
    fn new() -> Self {
        let (f, v) = Fixture::create();
        drop(v);
        let keys = Keyring::derive(&f.vmk(), &f.vault_id, INITIAL_EPOCH);
        let dir = f.paths.audit_dir.clone();
        Log { f, dir, keys }
    }

    fn writer(&self, anchor: Option<AuditHead>) -> AuditWriter {
        AuditWriter::open(&self.dir, &self.keys, anchor).unwrap().0
    }

    fn writer_with(&self, io: Shim, max_segment: u64) -> AuditWriter {
        AuditWriter::open_with_io(&self.dir, &self.keys, None, Box::new(io), max_segment)
            .unwrap()
            .0
    }

    fn verify(&self, anchor: Option<AuditHead>) -> VerifyReport {
        verify(&self.dir, &self.keys, anchor).unwrap()
    }

    /// The segment files, by name.
    fn segments(&self) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = std::fs::read_dir(&self.dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "seg"))
            .collect();
        v.sort();
        v
    }
}

/// A record for entry number `i`, with a marker only this entry holds.
fn record(i: u64) -> AuditRecord {
    AuditRecord {
        at: UNIX_EPOCH + Duration::from_millis(1_790_000_000_000 + i),
        kind: AuditKind::Run,
        request_id: Some("ABCDEFGH".into()),
        grant_id: None,
        subject: SubjectSummary {
            pid: 4242,
            kind: Some("agent".into()),
            agent: Some("Fixture Agent".into()),
            root_pid: Some(4000),
            root_exe: Some("/opt/fixture-agent".into()),
            ..SubjectSummary::default()
        },
        project: Some(ProjectSummary {
            dir: format!("/src/plaintext-marker-{i:04}"),
            manifest_sha256: [7; 32],
            approved_sha256: None,
        }),
        items: vec![(ItemId::generate(), Slug::new("openai/acme-web").unwrap())],
        decision: DecisionSummary {
            outcome: "covered".into(),
            ..DecisionSummary::default()
        },
        argv_redacted: vec!["./emit".into(), format!("--entry={i}")],
    }
}

/// Writes entries 1 to `n` and returns their records.
fn fill(w: &mut AuditWriter, from: u64, n: u64) -> Vec<AuditRecord> {
    (from..from + n)
        .map(|i| {
            let r = record(i);
            assert_eq!(w.append(&r).unwrap(), i);
            r
        })
        .collect()
}

/// The byte ranges of a segment's frames, with their sequence numbers.
fn frames(bytes: &[u8]) -> Vec<(u64, std::ops::Range<usize>)> {
    let mut out = Vec::new();
    let mut at = HEADER_LEN;
    while at + 12 <= bytes.len() {
        let len = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        let seq = u64::from_be_bytes(bytes[at + 4..at + 12].try_into().unwrap());
        let end = at + 12 + len + 32;
        assert!(end <= bytes.len(), "a torn frame where none was expected");
        out.push((seq, at..end));
        at = end;
    }
    out
}

fn problem(r: &VerifyReport) -> Option<(u64, ProblemKind)> {
    r.first_problem.map(|Problem { seq, kind }| (seq, kind))
}

/// The device and inode of a directory.
fn dir_id(p: &Path) -> (u64, u64) {
    let m = std::fs::metadata(p).unwrap();
    (m.dev(), m.ino())
}

/// Gate 33, the flush half: every append writes its frame and flushes the
/// segment before it returns, and the first also flushes the header and
/// the directory. Before a writer's first append it flushes the data
/// directory that names the log's directory, once per writer, whether or
/// not it made the directory (review T10 open 3, Codex F-64): a new
/// vault's directory was made by `ensure_dirs`, and an earlier writer may
/// have made it and failed, or crashed, before its flush. A failed flush
/// of it fails the append, and the next append, or the first of a writer
/// opened again, flushes it again. The flushes are `F_FULLFSYNC` on macOS
/// and `fsync` on Linux, counted by envcloak-sys's shim.
#[test]
fn every_append_is_flushed_before_it_returns() {
    // A new vault's log: its directory is there, made with the vault.
    let log = Log::new();
    let data = dir_id(log.dir.parent().unwrap());
    let shim = Shim::default();
    let mut w = log.writer_with(shim.clone(), MAX_SEGMENT);
    assert_eq!(shim.ops(), vec![], "opening writes nothing");

    let before = envcloak_sys::testing::sync_counts();
    assert_eq!(w.append(&record(1)).unwrap(), 1);
    let first = shim.ops();
    assert_eq!(first.len(), 6, "{first:?}");
    assert_eq!(first[0], Op::SyncDir, "the data directory, first");
    assert_eq!(first[1], Op::Write(HEADER_LEN));
    assert_eq!(&first[2..4], &[Op::SyncFile, Op::SyncDir]);
    assert!(matches!(first[4], Op::Write(n) if n > 12 + 40 + 32));
    assert_eq!(first[5], Op::SyncFile, "the frame is flushed last");
    assert_eq!(
        std::mem::take(&mut shim.plan().synced_dirs),
        [data, dir_id(&log.dir)]
    );
    let after = envcloak_sys::testing::sync_counts();
    let (full, plain) = (
        after.full_fsync - before.full_fsync,
        after.fsync - before.fsync,
    );
    if cfg!(target_os = "macos") {
        assert_eq!((full, plain), (4, 0), "F_FULLFSYNC, never plain fsync");
    } else {
        assert_eq!((full, plain), (0, 4));
    }

    for i in 2..=4 {
        let before = envcloak_sys::testing::sync_counts();
        assert_eq!(w.append(&record(i)).unwrap(), i);
        let ops = shim.ops();
        assert_eq!(ops.len(), 2, "{ops:?}");
        assert!(matches!(ops[0], Op::Write(_)));
        assert_eq!(ops[1], Op::SyncFile);
        let after = envcloak_sys::testing::sync_counts();
        assert_eq!(
            (after.full_fsync - before.full_fsync) + (after.fsync - before.fsync),
            1
        );
    }
    assert_eq!(w.head().0, 4);
    assert!(log.verify(None).ok());
    assert!(shim.plan().synced_dirs.is_empty(), "only once");

    // A writer opened again goes on in the same segment, and flushes the
    // data directory before its first append all the same.
    drop(w);
    let shim = Shim::default();
    let mut w = log.writer_with(shim.clone(), MAX_SEGMENT);
    assert_eq!(w.append(&record(5)).unwrap(), 5);
    let ops = shim.ops();
    assert!(
        matches!(ops[..], [Op::SyncDir, Op::Write(_), Op::SyncFile]),
        "{ops:?}"
    );
    assert_eq!(std::mem::take(&mut shim.plan().synced_dirs), [data]);
    fill(&mut w, 6, 1);
    let ops = shim.ops();
    assert!(
        matches!(ops[..], [Op::Write(_), Op::SyncFile]),
        "only once: {ops:?}"
    );
    assert_eq!(log.segments().len(), 1);
    assert!(log.verify(None).ok());

    // A missing directory: created, then the data directory that names it
    // is flushed before the first segment is made in it.
    let log = Log::new();
    std::fs::remove_dir(&log.dir).unwrap();
    let data = dir_id(log.dir.parent().unwrap());
    let shim = Shim::default();
    let mut w = log.writer_with(shim.clone(), MAX_SEGMENT);
    let before = envcloak_sys::testing::sync_counts();
    assert_eq!(w.append(&record(1)).unwrap(), 1);
    let first = shim.ops();
    assert_eq!(first.len(), 6, "{first:?}");
    assert_eq!(first[0], Op::SyncDir, "the data directory, first");
    assert_eq!(first[1], Op::Write(HEADER_LEN));
    assert_eq!(&first[2..4], &[Op::SyncFile, Op::SyncDir]);
    assert!(matches!(first[4], Op::Write(n) if n > 12 + 40 + 32));
    assert_eq!(first[5], Op::SyncFile);
    assert_eq!(
        std::mem::take(&mut shim.plan().synced_dirs),
        [data, dir_id(&log.dir)]
    );
    let after = envcloak_sys::testing::sync_counts();
    assert_eq!(
        (after.full_fsync - before.full_fsync) + (after.fsync - before.fsync),
        4
    );
    fill(&mut w, 2, 1);
    let ops = shim.ops();
    assert!(
        matches!(ops[..], [Op::Write(_), Op::SyncFile]),
        "only once: {ops:?}"
    );

    // That flush failing fails the append, which leaves no segment; the
    // next append flushes the data directory again.
    let log = Log::new();
    std::fs::remove_dir(&log.dir).unwrap();
    let shim = Shim::default();
    let mut w = log.writer_with(shim.clone(), MAX_SEGMENT);
    shim.plan().fail_dir_sync = true;
    assert!(w.append(&record(1)).is_err());
    assert_eq!(shim.ops(), [Op::SyncDir]);
    assert!(log.segments().is_empty());
    assert_eq!(w.head().0, 0);
    assert_eq!(w.append(&record(1)).unwrap(), 1);
    let ops = shim.ops();
    assert_eq!(ops.len(), 6, "{ops:?}");
    assert_eq!(ops[0], Op::SyncDir, "flushed again");
    assert!(log.verify(None).ok());
}

/// Codex F-64: a failed flush of the data directory, then the writer
/// dropped and opened again. The log's directory is there now (the failed
/// writer made it, or it was made with the vault), and the new writer
/// still flushes the data directory before its first append; a new writer
/// whose flush of it fails appends nothing either.
#[test]
fn a_writer_opened_again_after_a_failed_flush_flushes_the_data_directory() {
    for dir_missing in [true, false] {
        let log = Log::new();
        let data = dir_id(log.dir.parent().unwrap());
        if dir_missing {
            std::fs::remove_dir(&log.dir).unwrap();
        }
        let shim = Shim::default();
        let mut w = log.writer_with(shim.clone(), MAX_SEGMENT);
        shim.plan().fail_dir_sync = true;
        assert!(w.append(&record(1)).is_err());
        assert_eq!(shim.ops(), [Op::SyncDir]);
        assert_eq!(std::mem::take(&mut shim.plan().synced_dirs), [data]);
        drop(w);
        assert!(log.dir.is_dir() && log.segments().is_empty());

        let shim = Shim::default();
        let mut w = log.writer_with(shim.clone(), MAX_SEGMENT);
        shim.plan().fail_dir_sync = true;
        assert!(w.append(&record(1)).is_err(), "missing {dir_missing}");
        assert_eq!(shim.ops(), [Op::SyncDir]);
        assert!(log.segments().is_empty());
        drop(w);

        let shim = Shim::default();
        let mut w = log.writer_with(shim.clone(), MAX_SEGMENT);
        assert_eq!(w.append(&record(1)).unwrap(), 1);
        let ops = shim.ops();
        assert_eq!(ops.len(), 6, "missing {dir_missing}: {ops:?}");
        assert_eq!(ops[0], Op::SyncDir, "flushed after the reopen");
        assert_eq!(
            shim.plan().synced_dirs,
            [data, dir_id(&log.dir)],
            "missing {dir_missing}"
        );
        assert!(log.verify(None).ok());
    }
}

/// Gate 33, the failure half: a write that fails part way, or a flush that
/// fails, fails the append. Nothing is acknowledged: the segment is cut
/// back to what it was, the head does not move, and the next append takes
/// the same sequence number. The log then checks out, without the entries
/// that failed.
#[test]
fn a_failed_write_or_flush_fails_the_append_and_leaves_the_log_whole() {
    let log = Log::new();
    let shim = Shim::default();
    let mut w = log.writer_with(shim.clone(), MAX_SEGMENT);
    let mut kept = fill(&mut w, 1, 2);
    let seg = log.segments().pop().unwrap();
    let len = std::fs::metadata(&seg).unwrap().len();
    let head = w.head();

    let mut failed = record(100);
    failed.argv_redacted = vec!["the entry whose write failed".into()];
    shim.plan().fail_frame_write = true;
    let e = w.append(&failed).unwrap_err();
    assert_eq!(e.to_string(), "the audit log could not be read or written");
    assert_eq!(std::fs::metadata(&seg).unwrap().len(), len, "cut back");
    assert_eq!(w.head(), head);

    failed.argv_redacted = vec!["the entry whose flush failed".into()];
    shim.plan().fail_file_sync = true;
    let e = w.append(&failed).unwrap_err();
    assert_eq!(
        e.to_string(),
        "the audit entry could not be flushed to disk"
    );
    assert_eq!(std::fs::metadata(&seg).unwrap().len(), len, "cut back");
    assert_eq!(w.head(), head);

    // The retry takes the number the failures did not use.
    kept.extend(fill(&mut w, 3, 2));
    let (entries, report) = read_entries(&log.dir, &log.keys, None).unwrap();
    assert!(report.ok(), "{report:?}");
    assert_eq!(report.entries, 4);
    let seqs: Vec<u64> = entries.iter().map(|e| e.seq).collect();
    assert_eq!(seqs, vec![1, 2, 3, 4]);
    let records: Vec<AuditRecord> = entries.into_iter().map(|e| e.record).collect();
    assert_eq!(records, kept);
}

/// Gate 33: entries are sealed (no plaintext of theirs is in the segment
/// files) and open to exactly what was written; and the log of a vault
/// that holds the canaries holds none of them, raw or decrypted.
#[test]
fn entries_are_sealed_and_hold_no_values() {
    let cs = canaries(fresh_seed());
    let log = Log::new();
    let mut v = log.f.unlock();
    let mut items = Vec::new();
    v.transact(|t| {
        for (slug, label) in [
            ("openai/acme-web", labels::OPENAI_API_KEY),
            ("stripe/acme-web", labels::STRIPE_SECRET_KEY),
            ("db/acme-web", labels::DATABASE_URL),
        ] {
            let id = t.create_item(secret_item(slug))?;
            t.add_field(
                id,
                name("value"),
                SecretBytes::copy_from(by_label(&cs, label).value()),
            )?;
            items.push((id, Slug::new(slug).unwrap()));
        }
        Ok(())
    })
    .unwrap();
    let (mut w, _) = v.open_audit().unwrap();
    let mut written = Vec::new();
    for i in 1..=5 {
        let mut r = record(i);
        r.items.clone_from(&items);
        w.append(&r).unwrap();
        written.push(r);
    }
    v.save_audit_head(w.head_record()).unwrap();

    for seg in log.segments() {
        let raw = std::fs::read(&seg).unwrap();
        for needle in [
            "plaintext-marker",
            "openai/acme-web",
            "./emit",
            "Fixture Agent",
        ] {
            assert!(
                !raw.windows(needle.len()).any(|x| x == needle.as_bytes()),
                "{needle} is in a segment in plaintext"
            );
        }
        assert_no_canary(&raw, &cs);
    }
    let (entries, report) = v.read_audit().unwrap();
    assert!(report.ok());
    assert_eq!(report.anchor, AnchorCheck::Matched { seq: 5 });
    assert_eq!(report.unanchored_tail, None);
    let records: Vec<AuditRecord> = entries.iter().map(|e| e.record.clone()).collect();
    assert_eq!(records, written);
    for e in &entries {
        assert_no_canary(format!("{:?}", e.record).as_bytes(), &cs);
        for a in &e.record.argv_redacted {
            assert_no_canary(a.as_bytes(), &cs);
        }
    }
    drop(v);
    log.f.home.assert_clean(&cs);
}

/// Gate 33: an entry in the middle whose sealed bytes, chain value or
/// sequence number was changed is flagged at its sequence number; so is a
/// deleted one, and one moved out of its place. The entries after it
/// still check out.
#[test]
fn a_modified_deleted_or_reordered_entry_is_flagged_at_its_sequence_number() {
    let log = Log::new();
    let mut w = log.writer(None);
    fill(&mut w, 1, 10);
    drop(w);
    let seg = log.segments().pop().unwrap();
    let orig = std::fs::read(&seg).unwrap();
    let fr = frames(&orig);
    assert_eq!(fr.len(), 10);
    let (_, five) = fr[4].clone();
    let (_, six) = fr[5].clone();

    let check = |bytes: Vec<u8>, want: (u64, ProblemKind), what: &str| {
        std::fs::write(&seg, &bytes).unwrap();
        let r = log.verify(None);
        assert_eq!(problem(&r), Some(want), "{what}: {r:?}");
        assert!(r.last_seq >= 9, "{what}: the walk went on: {r:?}");
    };

    let mut b = orig.clone();
    b[five.start + 12 + 30] ^= 0x01;
    check(b, (5, ProblemKind::Altered), "a sealed byte flipped");

    let mut b = orig.clone();
    b[five.end - 1] ^= 0x80;
    check(b, (5, ProblemKind::ChainBroken), "the chain value changed");

    let mut b = orig.clone();
    b[five.start + 4..five.start + 12].copy_from_slice(&50u64.to_be_bytes());
    check(b, (5, ProblemKind::Missing), "the sequence number changed");

    let mut b = orig[..five.start].to_vec();
    b.extend_from_slice(&orig[five.end..]);
    check(b, (5, ProblemKind::Missing), "entry 5 deleted");

    let mut b = orig[..five.start].to_vec();
    b.extend_from_slice(&orig[six.clone()]);
    b.extend_from_slice(&orig[five.clone()]);
    b.extend_from_slice(&orig[six.end..]);
    check(b, (5, ProblemKind::Reordered), "entries 5 and 6 swapped");

    // Entry 5 replaced by entry 5 of another log of the same vault: it
    // opens, but it is not this chain's.
    let other_dir = log.f.home.root().join("other-audit");
    let (mut ow, _) = AuditWriter::open(&other_dir, &log.keys, None).unwrap();
    fill(&mut ow, 1, 4);
    let mut odd = record(5);
    odd.argv_redacted = vec!["another history".into()];
    ow.append(&odd).unwrap();
    let theirs = std::fs::read(other_dir.join(format!("{:020}.seg", 1))).unwrap();
    let (_, their_five) = frames(&theirs)[4].clone();
    let mut b = orig[..five.start].to_vec();
    b.extend_from_slice(&theirs[their_five]);
    b.extend_from_slice(&orig[five.end..]);
    check(
        b,
        (5, ProblemKind::ChainBroken),
        "entry 5 from another history",
    );

    std::fs::write(&seg, &orig).unwrap();
    assert!(log.verify(None).ok());
}

/// Gate 33: entries removed from the end are reported as the unanchored
/// tail, never as a whole log: after the anchor they cannot be told from a
/// log that stopped there; before it, the log is short of the anchor and
/// that is flagged.
#[test]
fn tail_truncation_is_an_unanchored_tail_or_a_missing_anchor() {
    let log = Log::new();
    let mut w = log.writer(None);
    fill(&mut w, 1, 6);
    let anchor = w.head_record();
    fill(&mut w, 7, 4);
    drop(w);
    let seg = log.segments().pop().unwrap();
    let orig = std::fs::read(&seg).unwrap();
    let fr = frames(&orig);

    let r = log.verify(Some(anchor));
    assert!(r.ok(), "{r:?}");
    assert_eq!(r.anchor, AnchorCheck::Matched { seq: 6 });
    assert_eq!(r.unanchored_tail, Some((7, 10)));

    // Without an anchor, the whole log is the tail.
    let r = log.verify(None);
    assert_eq!(
        (r.anchor, r.unanchored_tail),
        (AnchorCheck::None, Some((1, 10)))
    );

    // Cut back within the tail: nothing to flag, and the report says the
    // entries after the anchor are unanchored.
    std::fs::write(&seg, &orig[..fr[7].1.start]).unwrap();
    let r = log.verify(Some(anchor));
    assert!(r.ok(), "{r:?}");
    assert_eq!(r.unanchored_tail, Some((7, 7)));

    // Cut back to the anchor exactly: no tail.
    std::fs::write(&seg, &orig[..fr[6].1.start]).unwrap();
    let r = log.verify(Some(anchor));
    assert!(r.ok(), "{r:?}");
    assert_eq!(r.unanchored_tail, None);

    // Cut back before the anchor: flagged where the log stops.
    std::fs::write(&seg, &orig[..fr[3].1.start]).unwrap();
    let r = log.verify(Some(anchor));
    assert_eq!(problem(&r), Some((4, ProblemKind::Missing)), "{r:?}");
    assert_eq!(r.anchor, AnchorCheck::Missing { seq: 6 });

    // An anchor the log contradicts.
    std::fs::write(&seg, &orig).unwrap();
    let forged = AuditHead {
        seq: 6,
        mac: [0x5a; 32],
    };
    let r = log.verify(Some(forged));
    assert_eq!(problem(&r), Some((6, ProblemKind::AnchorMismatch)), "{r:?}");
}

/// A whole segment removed from the middle is flagged at its first entry;
/// one whose header was changed is flagged as damaged.
#[test]
fn a_deleted_or_damaged_segment_is_flagged() {
    let log = Log::new();
    let mut w = log.writer_with(Shim::default(), 2048);
    fill(&mut w, 1, 30);
    drop(w);
    let segs = log.segments();
    assert!(segs.len() >= 4, "{segs:?}");
    assert!(log.verify(None).ok());

    let middle = segs[1].clone();
    let first_seq: u64 = middle
        .file_stem()
        .unwrap()
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let bytes = std::fs::read(&middle).unwrap();
    std::fs::remove_file(&middle).unwrap();
    let r = log.verify(None);
    assert_eq!(
        problem(&r),
        Some((first_seq, ProblemKind::Missing)),
        "{r:?}"
    );
    assert_eq!(r.last_seq, 30, "the walk went on");

    let mut damaged = bytes;
    damaged[40] ^= 0x01;
    std::fs::write(&middle, &damaged).unwrap();
    let r = log.verify(None);
    assert_eq!(
        problem(&r),
        Some((first_seq, ProblemKind::SegmentDamaged)),
        "{r:?}"
    );
}

/// A crash in the middle of a write leaves a torn last entry: the first
/// bytes of the frame the writer was appending, entry 4's, which carries
/// its number. It was never acknowledged: the check reports it without
/// flagging the log, and the writer removes it and goes on.
#[test]
fn the_writer_removes_a_torn_entry_and_goes_on() {
    let log = Log::new();
    let mut w = log.writer(None);
    fill(&mut w, 1, 4);
    drop(w);
    let seg = log.segments().pop().unwrap();
    let mut bytes = std::fs::read(&seg).unwrap();
    let (seq, fourth) = frames(&bytes)[3].clone();
    assert_eq!(seq, 4);
    let whole = fourth.start;
    bytes.truncate(fourth.start + 40);
    std::fs::write(&seg, &bytes).unwrap();
    let r = log.verify(None);
    assert!(r.ok(), "{r:?}");
    assert!(r.torn_tail);
    assert_eq!(r.torn_bytes, 40);

    let (mut w, report) = AuditWriter::open(&log.dir, &log.keys, None).unwrap();
    assert!(report.torn_tail_removed);
    assert_eq!(report.torn_bytes, 40);
    assert!(!report.damaged);
    assert_eq!(std::fs::metadata(&seg).unwrap().len(), whole as u64);
    assert_eq!(w.append(&record(4)).unwrap(), 4);
    let r = log.verify(None);
    assert!(r.ok() && !r.torn_tail, "{r:?}");
    assert_eq!(log.segments().len(), 1, "it went on in the same segment");
}

/// A log cut back before the saved head (or rolled back to an older copy)
/// is noted when the writer opens it, and new entries go after the head,
/// in a new segment, so the gap stays visible and the chain from the
/// anchor on checks out.
#[test]
fn a_log_cut_before_its_anchor_goes_on_after_the_anchor() {
    let log = Log::new();
    let mut w = log.writer(None);
    fill(&mut w, 1, 6);
    let anchor = w.head_record();
    drop(w);
    let seg = log.segments().pop().unwrap();
    let orig = std::fs::read(&seg).unwrap();
    std::fs::write(&seg, &orig[..frames(&orig)[3].1.start]).unwrap();

    let (mut w, report) = AuditWriter::open(&log.dir, &log.keys, Some(anchor)).unwrap();
    assert_eq!(report.behind_anchor, Some((3, 6)));
    assert_eq!(w.append(&record(7)).unwrap(), 7);
    assert_eq!(w.append(&record(8)).unwrap(), 8);
    assert_eq!(log.segments().len(), 2);

    let (entries, r) = read_entries(&log.dir, &log.keys, Some(anchor)).unwrap();
    assert_eq!(problem(&r), Some((4, ProblemKind::Missing)), "{r:?}");
    assert_eq!(r.problems, 1, "{r:?}");
    assert_eq!(r.anchor, AnchorCheck::Matched { seq: 6 });
    assert_eq!(r.unanchored_tail, Some((7, 8)));
    let seqs: Vec<u64> = entries.iter().map(|e| e.seq).collect();
    assert_eq!(seqs, vec![1, 2, 3, 7, 8]);
}

/// A segment removed while the writer has it open (by another program
/// running as the user) is noticed: the next entry starts a new segment
/// rather than going into a file no one can read. When the directory
/// itself is gone and a file is in its place, the append fails, and it
/// works again once the directory is back. The check flags the removed
/// entries.
#[test]
fn a_removed_segment_is_noticed_and_an_unusable_directory_fails_the_append() {
    let log = Log::new();
    let mut w = log.writer(None);
    fill(&mut w, 1, 3);
    std::fs::remove_file(log.segments().pop().unwrap()).unwrap();
    assert_eq!(w.append(&record(4)).unwrap(), 4);
    assert_eq!(log.segments().len(), 1);

    std::fs::remove_dir_all(&log.dir).unwrap();
    std::fs::write(&log.dir, b"not a directory").unwrap();
    assert!(w.append(&record(5)).is_err());
    assert_eq!(w.head().0, 4);
    std::fs::remove_file(&log.dir).unwrap();
    assert_eq!(w.append(&record(5)).unwrap(), 5);

    let r = log.verify(None);
    assert_eq!(problem(&r), Some((1, ProblemKind::Missing)), "{r:?}");
    assert_eq!(r.last_seq, 5);
}

/// The vault's own helpers: the writer continues the log across a lock
/// and unlock in the same segment, and the head saved in the header is the
/// anchor the check uses.
#[test]
fn the_vault_saves_the_head_and_checks_against_it() {
    let log = Log::new();
    let mut v = log.f.unlock();
    let (mut w, report) = v.open_audit().unwrap();
    assert_eq!(report, Default::default());
    fill(&mut w, 1, 3);
    v.save_audit_head(w.head_record()).unwrap();
    assert_eq!(v.header().unwrap().audit_head, Some(w.head_record()));
    drop(w);
    let locked = v.lock();
    let mut v = locked.unlock(log.f.vmk()).map_err(|(_, e)| e).unwrap();
    assert_eq!(v.audit_anchor().map(|h| h.seq), Some(3));
    let (mut w, _) = v.open_audit().unwrap();
    assert_eq!(w.head().0, 3);
    fill(&mut w, 4, 2);
    assert_eq!(log.segments().len(), 1);
    let r = v.verify_audit().unwrap();
    assert!(r.ok(), "{r:?}");
    assert_eq!(r.anchor, AnchorCheck::Matched { seq: 3 });
    assert_eq!(r.unanchored_tail, Some((4, 5)));
    assert_eq!(r.head, w.head());
    v.save_audit_head(w.head_record()).unwrap();
    assert_eq!(v.verify_audit().unwrap().unanchored_tail, None);
}

/// Keys of another epoch or vault open nothing: every entry is flagged.
#[test]
fn another_vaults_keys_open_nothing() {
    let log = Log::new();
    let mut w = log.writer(None);
    fill(&mut w, 1, 2);
    let other = Log::new();
    let r = verify(&log.dir, &other.keys, None).unwrap();
    assert_eq!(problem(&r), Some((1, ProblemKind::SegmentDamaged)), "{r:?}");
}

/// A log left by a vault this one replaced (created after the old one was
/// deleted, with its audit directory still there) is moved aside whole
/// when the new vault's writer opens, and a new log starts: the check of
/// the new vault's log is then clean.
#[test]
fn another_vaults_log_is_moved_aside() {
    let old = Log::new();
    let mut w = old.writer(None);
    fill(&mut w, 1, 3);
    drop(w);
    let new = Log::new();
    std::fs::remove_dir_all(&new.dir).unwrap();
    std::fs::rename(&old.dir, &new.dir).unwrap();

    let (mut w, report) = AuditWriter::open(&new.dir, &new.keys, None).unwrap();
    assert!(report.other_vault_moved);
    assert!(!report.damaged);
    assert_eq!(w.append(&record(1)).unwrap(), 1);
    let r = new.verify(None);
    assert!(r.ok(), "{r:?}");
    assert_eq!(r.entries, 1);
    let parent = new.dir.parent().unwrap();
    let moved: Vec<_> = std::fs::read_dir(parent)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with("audit.replaced-"))
        .collect();
    assert_eq!(moved.len(), 1, "{moved:?}");
    let aside = parent.join(&moved[0]);
    let r = verify(&aside, &old.keys, None).unwrap();
    assert!(r.ok() && r.entries == 3, "{r:?}");

    // One segment of this vault among them: nothing is moved.
    let mut w2 = new.writer(None);
    fill(&mut w2, 2, 1);
    std::fs::rename(
        aside.join(format!("{:020}.seg", 1)),
        new.dir.join(format!("{:020}.seg", 9)),
    )
    .unwrap();
    let (_, report) = AuditWriter::open(&new.dir, &new.keys, None).unwrap();
    assert!(!report.other_vault_moved);
    assert!(report.damaged);
}

/// Bytes that cannot be framed at the end of the last segment are damage,
/// not a torn write: the writer leaves them for the check to report and
/// goes on in a new segment.
#[test]
fn damage_at_the_end_is_kept_for_the_check() {
    let log = Log::new();
    let mut w = log.writer(None);
    fill(&mut w, 1, 3);
    drop(w);
    let seg = log.segments().pop().unwrap();
    let mut bytes = std::fs::read(&seg).unwrap();
    let (_, last) = frames(&bytes)[2].clone();
    // A length no entry has, in the last entry.
    bytes[last.start..last.start + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    std::fs::write(&seg, &bytes).unwrap();
    let r = log.verify(None);
    assert_eq!(problem(&r), Some((3, ProblemKind::Unreadable)), "{r:?}");

    let (mut w, report) = AuditWriter::open(&log.dir, &log.keys, None).unwrap();
    assert!(report.damaged && !report.torn_tail_removed);
    assert_eq!(std::fs::read(&seg).unwrap(), bytes, "left as it was");
    assert_eq!(w.append(&record(3)).unwrap(), 3);
    assert_eq!(log.segments().len(), 2);
    let r = log.verify(None);
    assert_eq!(problem(&r), Some((3, ProblemKind::Unreadable)), "{r:?}");
}

/// Codex F-44: a segment renamed out of the directory, a segment replaced
/// by a copy of itself, and the directory renamed away all keep a link
/// count above zero, but entries written to them would not be in the log
/// the check reads. The writer notices each and starts a new segment in
/// the log's directory, which leaves the gap for the check to flag. A
/// segment moved while an entry is written to it fails that append, and
/// the retry goes to a new segment.
#[test]
fn a_renamed_segment_or_directory_takes_no_entry_with_it() {
    let log = Log::new();
    let shim = Shim::default();
    let mut w = log.writer_with(shim.clone(), MAX_SEGMENT);
    fill(&mut w, 1, 2);
    let seqs = |dir: &Path| -> Vec<u64> {
        let (entries, _) = read_entries(dir, &log.keys, None).unwrap();
        entries.iter().map(|e| e.seq).collect()
    };
    let outside = log.f.home.root().join("moved");
    std::fs::create_dir(&outside).unwrap();

    // The segment renamed out of the directory.
    let renamed = outside.join("renamed");
    std::fs::rename(log.segments().pop().unwrap(), &renamed).unwrap();
    let renamed_len = std::fs::metadata(&renamed).unwrap().len();
    assert_eq!(w.append(&record(3)).unwrap(), 3);
    assert_eq!(
        std::fs::metadata(&renamed).unwrap().len(),
        renamed_len,
        "nothing went to the renamed segment"
    );
    assert_eq!(seqs(&log.dir), vec![3]);

    // The segment replaced by a copy: the name is there, but it names
    // another file.
    let third = log.segments().pop().unwrap();
    let copy = log.dir.join("copy");
    std::fs::copy(&third, &copy).unwrap();
    std::fs::rename(&copy, &third).unwrap();
    assert_eq!(w.append(&record(4)).unwrap(), 4);
    assert_eq!(seqs(&log.dir), vec![3, 4]);
    assert_eq!(log.segments().len(), 2);

    // The directory renamed away: a new one is made where the log is.
    let aside = log.f.home.root().join("audit.aside");
    std::fs::rename(&log.dir, &aside).unwrap();
    assert_eq!(w.append(&record(5)).unwrap(), 5);
    assert_eq!(
        seqs(&aside),
        vec![3, 4],
        "nothing went to the moved directory"
    );
    assert_eq!(seqs(&log.dir), vec![5]);

    // The segment moved while entry 6 is written to it: the append fails,
    // the moved file is cut back, the head stays, and the retry goes to a
    // new segment in the log.
    let current = log.segments().pop().unwrap();
    let current_len = std::fs::metadata(&current).unwrap().len();
    let raced = outside.join("raced");
    shim.plan().move_before_frame = Some((current, raced.clone()));
    let head = w.head();
    assert!(w.append(&record(6)).is_err());
    assert_eq!(w.head(), head);
    assert_eq!(std::fs::metadata(&raced).unwrap().len(), current_len);
    assert_eq!(w.append(&record(6)).unwrap(), 6);
    assert_eq!(seqs(&log.dir), vec![6]);

    let r = log.verify(None);
    assert_eq!(problem(&r), Some((1, ProblemKind::Missing)), "{r:?}");
    assert_eq!(r.last_seq, 6);
}

/// A whole entry whose length field was made larger than the bytes left
/// looks like a write cut short, but is not one: its chain value is where
/// the entry really ends, before the next entry's number or at the end of
/// the file. It is flagged where it is, and the writer removes nothing,
/// with or without a saved head. A cut that the saved head covers is not a
/// crash's either (the entry was acknowledged): it is flagged and kept.
/// The same cut with no saved head over it is a torn tail.
#[test]
fn a_changed_length_or_a_cut_the_anchor_covers_is_kept_as_damage() {
    let log = Log::new();
    let mut w = log.writer(None);
    fill(&mut w, 1, 10);
    let anchor = w.head_record();
    drop(w);
    let seg = log.segments().pop().unwrap();
    let orig = std::fs::read(&seg).unwrap();
    let fr = frames(&orig);
    let reset = |bytes: &[u8]| {
        for s in log.segments() {
            std::fs::remove_file(s).unwrap();
        }
        std::fs::write(&seg, bytes).unwrap();
    };

    let mut seventh_inflated = orig.clone();
    let big = u32::try_from(MAX_ENTRY).unwrap().to_be_bytes();
    seventh_inflated[fr[6].1.start..fr[6].1.start + 4].copy_from_slice(&big);
    let mut last_inflated = orig.clone();
    let at = fr[9].1.start;
    let len = u32::from_be_bytes(orig[at..at + 4].try_into().unwrap());
    last_inflated[at..at + 4].copy_from_slice(&(len + 1).to_be_bytes());
    let cut = orig[..fr[9].1.end - 10].to_vec();

    for (what, bytes, anchor, seq) in [
        ("entry 7's length inflated", &seventh_inflated, None, 7),
        (
            "the same, under a saved head",
            &seventh_inflated,
            Some(anchor),
            7,
        ),
        ("the last entry's length inflated", &last_inflated, None, 10),
        (
            "the last entry cut, under a saved head",
            &cut,
            Some(anchor),
            10,
        ),
    ] {
        reset(bytes);
        let r = log.verify(anchor);
        assert_eq!(
            problem(&r),
            Some((seq, ProblemKind::Unreadable)),
            "{what}: {r:?}"
        );
        assert!(!r.torn_tail, "{what}: {r:?}");
        let (mut w, report) = AuditWriter::open(&log.dir, &log.keys, anchor).unwrap();
        assert!(
            report.damaged && !report.torn_tail_removed,
            "{what}: {report:?}"
        );
        assert_eq!(&std::fs::read(&seg).unwrap(), bytes, "{what}: kept");
        w.append(&record(11)).unwrap();
        assert_eq!(&std::fs::read(&seg).unwrap(), bytes, "{what}: kept");
        let r = log.verify(anchor);
        assert_eq!(problem(&r).map(|p| p.0), Some(seq), "{what}: {r:?}");
    }

    // The same cut with no saved head over it: what a crash leaves.
    reset(&cut);
    let r = log.verify(None);
    assert!(r.ok() && r.torn_tail, "{r:?}");
    let torn = (fr[9].1.len() - 10) as u64;
    assert_eq!(r.torn_bytes, torn);
    let (_, report) = AuditWriter::open(&log.dir, &log.keys, None).unwrap();
    assert!(report.torn_tail_removed && !report.damaged, "{report:?}");
    assert_eq!(report.torn_bytes, torn);
    assert_eq!(std::fs::read(&seg).unwrap(), &orig[..fr[9].1.start]);
}

/// Adversarial review of 7fb007d and Codex F-46: bytes at the end of the
/// last segment count as a crash's only while that segment checked out up
/// to them, and only when no whole entry is in them.
/// - The last entry's length made 1 to 11 bytes smaller reads as a shorter
///   entry (flagged) and a few bytes after it; an earlier entry's length
///   stretched to end just before the end of the file does the same. The
///   walk's expected number and chain value then come from a frame it has
///   already flagged, so the bytes after it say nothing about a crash.
/// - An entry whose length was stretched past the end and whose sealed
///   bytes were changed hides the whole entries after it, also when
///   entries between them were deleted (Codex's F-46 follow-up), however
///   few of its own bytes are left before the whole one; one whose
///   chain value was changed still opens where it really ends.
/// - An entry whole but for its length, stretched past the end, before
///   bytes that hold no entry (or a gap, then a damaged entry): its chain
///   value checks out where it really ends, which is neither the end of
///   the file nor where the next number starts.
///
/// Each is damage: flagged at its entry, not a torn tail, and kept by the
/// writer (which goes on in a new segment), with or without a saved head.
#[test]
fn bytes_after_damage_or_before_a_whole_entry_are_not_a_torn_tail() {
    let log = Log::new();
    let mut w = log.writer(None);
    fill(&mut w, 1, 1);
    let first = w.head_record();
    fill(&mut w, 2, 9);
    let head = w.head_record();
    drop(w);
    let seg = log.segments().pop().unwrap();
    let orig = std::fs::read(&seg).unwrap();
    let fr = frames(&orig);
    let reset = |bytes: &[u8]| {
        for s in log.segments() {
            std::fs::remove_file(s).unwrap();
        }
        std::fs::write(&seg, bytes).unwrap();
    };
    // Entry `i + 1`'s length field.
    let len_of = |i: usize| {
        let at = fr[i].1.start;
        u32::from_be_bytes(orig[at..at + 4].try_into().unwrap())
    };
    let with_len = |b: &mut Vec<u8>, i: usize, len: u32| {
        let at = fr[i].1.start;
        b[at..at + 4].copy_from_slice(&len.to_be_bytes());
    };

    let mut cases: Vec<(String, Vec<u8>, Option<AuditHead>, u64)> = Vec::new();
    for less in 1..=11 {
        let mut b = orig.clone();
        with_len(&mut b, 9, len_of(9) - less);
        cases.push((
            format!("the last length {less} smaller"),
            b.clone(),
            None,
            10,
        ));
        cases.push((
            format!("the last length {less} smaller, under a saved head"),
            b,
            Some(head),
            10,
        ));
    }
    let mut b = orig.clone();
    let reach = orig.len() - 5 - fr[8].1.start - 12 - 32;
    with_len(&mut b, 8, u32::try_from(reach).unwrap());
    cases.push((
        "entry 9's length reaching 5 bytes short of the end".into(),
        b,
        None,
        9,
    ));
    let mut b = orig.clone();
    with_len(&mut b, 1, u32::try_from(MAX_ENTRY).unwrap());
    b[fr[1].1.start + 12 + 40] ^= 0x01;
    cases.push((
        "entry 2 stretched past the end, its sealed bytes changed".into(),
        b.clone(),
        None,
        2,
    ));
    cases.push(("the same, entry 1 anchored".into(), b, Some(first), 2));
    // Codex F-46 follow-up: with entries 3 to 9 deleted, the whole entry
    // after the damaged one carries a number the bytes left could not
    // reach one entry at a time. It still opens under its own number.
    let mut b = orig[..fr[1].1.end].to_vec();
    b.extend_from_slice(&orig[fr[9].1.clone()]);
    with_len(&mut b, 1, u32::try_from(MAX_ENTRY).unwrap());
    b[fr[1].1.start + 12 + 40] ^= 0x01;
    cases.push((
        "entries 3 to 9 deleted, entry 2 stretched past the end, its sealed bytes changed".into(),
        b.clone(),
        None,
        2,
    ));
    cases.push((
        "the same after the gap, entry 1 anchored".into(),
        b,
        Some(first),
        2,
    ));
    // Verification of 640640c: only the first `keep` bytes of entry 2
    // left, its length stretched, before the whole entry 10. Entry 10 then
    // starts inside the smallest size an entry can have (84 bytes), or
    // inside the frame head itself; it opens there all the same. Every
    // such offset, and a few past it.
    let mut stretched = orig[fr[1].1.clone()].to_vec();
    stretched[..4].copy_from_slice(&u32::try_from(MAX_ENTRY).unwrap().to_be_bytes());
    assert!(stretched.len() > 96);
    for keep in 1..96 {
        let mut b = orig[..fr[1].1.start].to_vec();
        b.extend_from_slice(&stretched[..keep]);
        b.extend_from_slice(&orig[fr[9].1.clone()]);
        cases.push((
            format!("entries 3 to 9 deleted, {keep} bytes of entry 2 left, stretched"),
            b.clone(),
            None,
            2,
        ));
        cases.push((
            format!("the same with {keep} bytes, entry 1 anchored"),
            b,
            Some(first),
            2,
        ));
    }
    let mut b = orig.clone();
    with_len(&mut b, 9, len_of(9) + 1);
    let end = fr[9].1.end;
    b[end - 1] ^= 0x01;
    cases.push((
        "the last entry stretched, its chain value changed".into(),
        b,
        None,
        10,
    ));
    // Verification of 19e2e34: entry 2 whole and unchanged but for its
    // length, stretched past the end, and bytes after it that hold no
    // entry, or a gap and then a damaged entry 10. Entry 2 does not end at
    // the end of the file or where an entry 3 starts, but its chain value
    // checks out where it really ends. Every length of those bytes up to
    // a few past the smallest entry, and some longer.
    let noise = |n: usize, seed: u32| -> Vec<u8> {
        let mut x = seed;
        (0..n)
            .map(|_| {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                (x >> 16) as u8
            })
            .collect()
    };
    let mut damaged_ten = orig[fr[9].1.clone()].to_vec();
    damaged_ten[12 + 40] ^= 0x01;
    let mut after: Vec<(String, Vec<u8>)> = Vec::new();
    for n in (1..=100).chain([255, 363, 1000, 4096]) {
        after.push((format!("{n} bytes 0xff"), vec![0xff; n]));
        after.push((format!("{n} bytes of noise"), noise(n, 7 + n as u32)));
    }
    after.push(("a damaged entry 10".into(), damaged_ten.clone()));
    let mut noisy_ten = noise(30, 3);
    noisy_ten.extend_from_slice(&damaged_ten);
    after.push(("30 bytes of noise, a damaged entry 10".into(), noisy_ten));
    for (what, tail) in after {
        let mut b = orig[..fr[1].1.end].to_vec();
        with_len(&mut b, 1, u32::try_from(MAX_ENTRY).unwrap());
        b.extend_from_slice(&tail);
        cases.push((
            format!("entry 2 whole, stretched, then {what}"),
            b.clone(),
            None,
            2,
        ));
        cases.push((
            format!("entry 2 whole, stretched, then {what}, entry 1 anchored"),
            b,
            Some(first),
            2,
        ));
    }

    for (what, bytes, anchor, seq) in &cases {
        reset(bytes);
        let r = log.verify(*anchor);
        assert_eq!(problem(&r).map(|p| p.0), Some(*seq), "{what}: {r:?}");
        assert!(!r.torn_tail && r.torn_bytes == 0, "{what}: {r:?}");
        let (mut w, report) = AuditWriter::open(&log.dir, &log.keys, *anchor).unwrap();
        assert!(
            report.damaged && !report.torn_tail_removed && report.torn_bytes == 0,
            "{what}: {report:?}"
        );
        assert_eq!(&std::fs::read(&seg).unwrap(), bytes, "{what}: kept");
        w.append(&record(11)).unwrap();
        assert_eq!(&std::fs::read(&seg).unwrap(), bytes, "{what}: still kept");
        assert_eq!(log.segments().len(), 2, "{what}: went on in a new segment");
        let r = log.verify(*anchor);
        assert_eq!(problem(&r).map(|p| p.0), Some(*seq), "{what}: {r:?}");
        assert!(!r.torn_tail, "{what}: {r:?}");
    }

    // Controls: each change alone, on entry 2, is flagged too; and the
    // same log cut in the middle of its last entry, with no saved head
    // over it, is still what a crash leaves.
    let mut stretched = orig.clone();
    with_len(&mut stretched, 1, u32::try_from(MAX_ENTRY).unwrap());
    let mut changed = orig.clone();
    changed[fr[1].1.start + 12 + 40] ^= 0x01;
    for (what, bytes) in [("stretched", stretched), ("changed", changed)] {
        reset(&bytes);
        let r = log.verify(Some(first));
        assert_eq!(problem(&r).map(|p| p.0), Some(2), "{what}: {r:?}");
        assert!(!r.torn_tail, "{what}: {r:?}");
    }
    // The deletion alone is flagged where the numbers stop running.
    let mut gap = orig[..fr[1].1.end].to_vec();
    gap.extend_from_slice(&orig[fr[9].1.clone()]);
    reset(&gap);
    let r = log.verify(Some(first));
    assert_eq!(problem(&r), Some((3, ProblemKind::Missing)), "{r:?}");
    assert!(!r.torn_tail, "{r:?}");
    let cut = orig[..fr[9].1.end - 10].to_vec();
    reset(&cut);
    let r = log.verify(Some(first));
    assert!(r.ok() && r.torn_tail, "{r:?}");
    let (_, report) = AuditWriter::open(&log.dir, &log.keys, Some(first)).unwrap();
    assert!(report.torn_tail_removed && !report.damaged, "{report:?}");
    assert_eq!(std::fs::read(&seg).unwrap(), &orig[..fr[9].1.start]);
}

/// Group 3 verification (G3-V1): a crash leaves the start of the frame the
/// writer was appending, and that frame carries the number the walk
/// expects. Bytes whose frame head carries another number are not a
/// crash's, whatever else is in them. With entries 2 to 9 deleted, entry
/// 10 whole but for its length, stretched past the end (with or without
/// bytes after it), was taken for entry 2 cut short: it opens nowhere
/// entry 2 could end, so the check passed and the writer removed an entry
/// that opens under its own number. The same holds for no more than entry
/// 10's frame head. Each is flagged where entry 2 should be and kept, with
/// or without a saved head before it; the deletion alone is flagged there
/// too, and the start of a real entry 2, cut anywhere, is still a torn
/// tail.
#[test]
fn a_torn_frame_under_another_number_is_kept_as_damage() {
    let log = Log::new();
    let mut w = log.writer(None);
    fill(&mut w, 1, 1);
    let first = w.head_record();
    fill(&mut w, 2, 9);
    drop(w);
    let seg = log.segments().pop().unwrap();
    let orig = std::fs::read(&seg).unwrap();
    let fr = frames(&orig);
    assert_eq!((fr[1].0, fr[9].0), (2, 10));
    let reset = |bytes: &[u8]| {
        for s in log.segments() {
            std::fs::remove_file(s).unwrap();
        }
        std::fs::write(&seg, bytes).unwrap();
    };
    let one = &orig[..fr[0].1.end];
    let mut ten = orig[fr[9].1.clone()].to_vec();
    ten[..4].copy_from_slice(&u32::try_from(MAX_ENTRY).unwrap().to_be_bytes());

    let mut cases: Vec<(String, Vec<u8>)> = Vec::new();
    for (what, after) in [("", 0), (", then 50 bytes 0xff", 50)] {
        let mut b = one.to_vec();
        b.extend_from_slice(&ten);
        b.resize(b.len() + after, 0xff);
        cases.push((
            format!("entries 2 to 9 deleted, entry 10 stretched past the end{what}"),
            b,
        ));
    }
    for keep in [12, 40, 84, 200] {
        let mut b = one.to_vec();
        b.extend_from_slice(&ten[..keep]);
        cases.push((
            format!("entries 2 to 9 deleted, {keep} bytes of entry 10 left"),
            b,
        ));
    }
    for (what, bytes) in &cases {
        for anchor in [None, Some(first)] {
            reset(bytes);
            let r = log.verify(anchor);
            assert_eq!(
                problem(&r),
                Some((2, ProblemKind::Unreadable)),
                "{what}, {anchor:?}: {r:?}"
            );
            assert!(!r.torn_tail && r.torn_bytes == 0, "{what}: {r:?}");
            let (mut w, report) = AuditWriter::open(&log.dir, &log.keys, anchor).unwrap();
            assert!(
                report.damaged && !report.torn_tail_removed && report.torn_bytes == 0,
                "{what}, {anchor:?}: {report:?}"
            );
            assert_eq!(&std::fs::read(&seg).unwrap(), bytes, "{what}: kept");
            w.append(&record(11)).unwrap();
            assert_eq!(&std::fs::read(&seg).unwrap(), bytes, "{what}: still kept");
            let r = log.verify(anchor);
            assert_eq!(problem(&r), Some((2, ProblemKind::Unreadable)), "{what}");
        }
    }

    // Controls. The deletion alone is flagged where entry 2 should be.
    let mut gap = one.to_vec();
    gap.extend_from_slice(&orig[fr[9].1.clone()]);
    reset(&gap);
    let r = log.verify(Some(first));
    assert_eq!(problem(&r), Some((2, ProblemKind::Missing)), "{r:?}");
    // Entry 2 cut anywhere, entries after it never written, is what a
    // crash leaves: inside its length, inside its number, just after it,
    // and further on.
    let two = &orig[fr[1].1.clone()];
    for keep in [1, 4, 7, 11, 12, 13, 84, two.len() - 1] {
        let mut b = one.to_vec();
        b.extend_from_slice(&two[..keep]);
        for anchor in [None, Some(first)] {
            reset(&b);
            let r = log.verify(anchor);
            assert!(r.ok() && r.torn_tail, "{keep} bytes, {anchor:?}: {r:?}");
            assert_eq!(r.torn_bytes, keep as u64);
            let (mut w, report) = AuditWriter::open(&log.dir, &log.keys, anchor).unwrap();
            assert!(
                report.torn_tail_removed && !report.damaged,
                "{keep} bytes, {anchor:?}: {report:?}"
            );
            assert_eq!(std::fs::read(&seg).unwrap(), one, "{keep} bytes");
            assert_eq!(w.append(&record(2)).unwrap(), 2);
            let r = log.verify(anchor);
            assert!(r.ok() && !r.torn_tail, "{keep} bytes, {anchor:?}: {r:?}");
        }
    }
}

/// Codex F-46 follow-up: every framed candidate in bytes that look like a
/// torn tail is opened under the number it carries, within a fixed amount
/// of work. Bytes built to frame at every fourth offset, more than the
/// check opens, or to carry a number close to the expected one at every
/// twelfth, each of which is tried at every length (cycle 150), are kept
/// and flagged as damage rather than removed as a crash's, with or without
/// a saved head before them.
#[test]
fn bytes_too_many_to_check_are_kept_as_damage() {
    let log = Log::new();
    let mut w = log.writer(None);
    fill(&mut w, 1, 3);
    let three = w.head_record();
    drop(w);
    let seg = log.segments().pop().unwrap();
    let mut bytes = std::fs::read(&seg).unwrap();
    // Entry 4's frame, longer than the bytes that follow it: a torn tail,
    // unless something whole is in it.
    bytes.extend_from_slice(&u32::try_from(MAX_ENTRY).unwrap().to_be_bytes());
    bytes.extend_from_slice(&4u64.to_be_bytes());
    // Every fourth offset holds the length 1,024 and room for it.
    let mut framing = bytes.clone();
    for _ in 0..15_000 {
        framing.extend_from_slice(&[0, 0, 4, 0]);
    }
    // Every twelfth offset holds the number entry 5 would carry, which the
    // check opens at every length (Codex F-46, cycle 150).
    let mut numbered = bytes.clone();
    for _ in 0..5_000 {
        numbered.extend_from_slice(&[0, 0, 0, 0]);
        numbered.extend_from_slice(&5u64.to_be_bytes());
    }
    for (anchor, bytes) in [
        (None, &framing),
        (Some(three), &framing),
        (None, &numbered),
        (Some(three), &numbered),
    ] {
        std::fs::write(&seg, bytes).unwrap();
        let r = log.verify(anchor);
        assert_eq!(problem(&r), Some((4, ProblemKind::Unreadable)), "{r:?}");
        assert!(!r.torn_tail, "{r:?}");
        let (_, report) = AuditWriter::open(&log.dir, &log.keys, anchor).unwrap();
        assert!(
            report.damaged && !report.torn_tail_removed,
            "{anchor:?}: {report:?}"
        );
        assert_eq!(&std::fs::read(&seg).unwrap(), bytes, "{anchor:?}: kept");
    }
}

/// Codex F-46, cycle 150 replay: an entry whose sealed bytes are whole
/// but whose length was stretched past the end and whose chain value was
/// changed, with a byte after it, was taken for a crash's torn tail, since
/// only its chain value was tried at every length, and the writer removed
/// it (122 bytes). Its sealed bytes open where it really ends, which the
/// check now tries at every length in one pass:
/// - entry 2 so, with 0 to 40 bytes after it and more, with its chain
///   value changed, cut short and changed, or gone;
/// - entry 2 with its chain value cut short and right but its length
///   changed, which is no crash's either (a crash's frame says where its
///   entry ends);
/// - with entry 2 damaged past opening, or only part of it left, and
///   entries 3 to 9 deleted, entry 10 changed the same way: it opens under
///   its own number at its real length.
///
/// Each is damage, flagged at entry 2 and kept by the writer, with and
/// without entry 1 anchored. The controls: entry 2 cut anywhere in its
/// chain value (its sealed bytes whole, what is left of its chain value
/// right) or in its sealed bytes is what a crash leaves, and is removed;
/// its chain value changed alone, and its length stretched alone before a
/// byte, are flagged.
#[test]
fn an_entry_that_opens_whatever_its_length_and_chain_value_is_kept() {
    let log = Log::new();
    let mut w = log.writer(None);
    fill(&mut w, 1, 1);
    let first = w.head_record();
    fill(&mut w, 2, 9);
    drop(w);
    let seg = log.segments().pop().unwrap();
    let orig = std::fs::read(&seg).unwrap();
    let fr = frames(&orig);
    let reset = |bytes: &[u8]| {
        for s in log.segments() {
            std::fs::remove_file(s).unwrap();
        }
        std::fs::write(&seg, bytes).unwrap();
    };
    let one = &orig[..fr[0].1.end];
    let two = &orig[fr[1].1.clone()];
    let ten = &orig[fr[9].1.clone()];
    let max = u32::try_from(MAX_ENTRY).unwrap().to_be_bytes();
    // A frame's length, sealed bytes and chain value, changed as asked:
    // the length stretched, the chain value kept for `mac` bytes, and its
    // last kept byte flipped when `flip`.
    let changed = |frame: &[u8], len: [u8; 4], mac: usize, flip: bool| {
        let mut f = frame[..frame.len() - 32 + mac].to_vec();
        f[..4].copy_from_slice(&len);
        if flip && mac > 0 {
            let at = f.len() - 1;
            f[at] ^= 0x01;
        }
        f
    };
    let noise = |n: usize| -> Vec<u8> { (0..n).map(|i| (i * 37 + 11) as u8).collect() };

    let mut cases: Vec<(String, Vec<u8>)> = Vec::new();
    for after in (0..=40).chain([100, 1000]) {
        let mut b = one.to_vec();
        b.extend(changed(two, max, 32, true));
        b.extend(noise(after));
        cases.push((
            format!("entry 2 stretched, its chain value changed, {after} bytes after"),
            b,
        ));
    }
    for (mac, flip, after) in [(0, false, 0), (0, false, 1), (0, false, 33), (20, true, 1)] {
        let mut b = one.to_vec();
        b.extend(changed(two, max, mac, flip));
        b.extend(noise(after));
        cases.push((
            format!("entry 2 stretched, {mac} bytes of its chain value, {after} after"),
            b,
        ));
    }
    let real = u32::try_from(two.len() - 44).unwrap();
    for (len, mac) in [(real + 5, 10), (real + 1, 31), (real + 40, 0)] {
        let mut b = one.to_vec();
        b.extend(changed(two, len.to_be_bytes(), mac, false));
        cases.push((
            format!("entry 2's length {len} for {real}, {mac} right bytes of its chain value"),
            b,
        ));
    }
    let mut spoiled = two.to_vec();
    spoiled[12 + 40] ^= 0x01;
    for (what, head) in [
        ("damaged", spoiled.clone()),
        ("its first 30 bytes left", two[..30].to_vec()),
        ("its first 90 bytes left", two[..90].to_vec()),
    ] {
        let mut b = one.to_vec();
        b.extend_from_slice(&max);
        b.extend_from_slice(&head[4..]);
        b.extend(changed(ten, max, 32, true));
        b.extend(noise(1));
        cases.push((
            format!("entry 2 {what}, entries 3 to 9 deleted, entry 10 changed so"),
            b,
        ));
    }
    for (what, bytes) in &cases {
        for anchor in [None, Some(first)] {
            reset(bytes);
            let r = log.verify(anchor);
            assert_eq!(
                problem(&r).map(|p| p.0),
                Some(2),
                "{what}, {anchor:?}: {r:?}"
            );
            assert!(
                !r.torn_tail && r.torn_bytes == 0,
                "{what}, {anchor:?}: {r:?}"
            );
            let (mut w, report) = AuditWriter::open(&log.dir, &log.keys, anchor).unwrap();
            assert!(
                report.damaged && !report.torn_tail_removed && report.torn_bytes == 0,
                "{what}, {anchor:?}: {report:?}"
            );
            assert_eq!(&std::fs::read(&seg).unwrap(), bytes, "{what}: kept");
            w.append(&record(11)).unwrap();
            assert_eq!(&std::fs::read(&seg).unwrap(), bytes, "{what}: still kept");
        }
    }

    // Controls. Entry 2 cut in its chain value or its sealed bytes, with
    // nothing after it: a crash's, removed.
    for keep in (two.len() - 32..two.len()).chain([13, 60, two.len() - 33]) {
        let mut b = one.to_vec();
        b.extend_from_slice(&two[..keep]);
        for anchor in [None, Some(first)] {
            reset(&b);
            let r = log.verify(anchor);
            assert!(r.ok() && r.torn_tail, "{keep} bytes, {anchor:?}: {r:?}");
            let (mut w, report) = AuditWriter::open(&log.dir, &log.keys, anchor).unwrap();
            assert!(
                report.torn_tail_removed && !report.damaged,
                "{keep} bytes, {anchor:?}: {report:?}"
            );
            assert_eq!(std::fs::read(&seg).unwrap(), one, "{keep} bytes");
            assert_eq!(w.append(&record(2)).unwrap(), 2);
        }
    }
    // Each change alone: the chain value (the frame whole), and the length
    // stretched before a byte (its chain value checks out).
    let mut mac_only = one.to_vec();
    mac_only.extend(changed(two, two[..4].try_into().unwrap(), 32, true));
    let mut stretched = one.to_vec();
    stretched.extend(changed(two, max, 32, false));
    stretched.push(0xff);
    for (what, b) in [("chain value", mac_only), ("stretched", stretched)] {
        for anchor in [None, Some(first)] {
            reset(&b);
            let r = log.verify(anchor);
            assert_eq!(problem(&r).map(|p| p.0), Some(2), "{what}: {r:?}");
            assert!(!r.torn_tail, "{what}: {r:?}");
        }
    }
}

/// Codex review: a crash while the writer makes a segment (the first
/// append of a log, or a rollover) leaves an empty file, part of its
/// header, or zeros as the last segment. That is a torn tail, not damage:
/// the check passes, and the writer removes the file and makes it again.
/// Bytes that are not the start of the header the writer would write, or
/// a segment the saved head covers, are damage and are kept.
#[test]
fn a_crash_while_a_segment_is_made_is_a_torn_tail() {
    let log = Log::new();
    // One entry per segment: segment 4's header is the one the writer
    // writes after entry 3.
    let mut w = log.writer_with(Shim::default(), 1);
    fill(&mut w, 1, 3);
    let three = w.head_record();
    fill(&mut w, 4, 1);
    let four = w.head_record();
    drop(w);
    let segs = log.segments();
    assert_eq!(segs.len(), 4);
    let fourth = segs[3].clone();
    let header = std::fs::read(&fourth).unwrap()[..HEADER_LEN].to_vec();

    for (what, bytes, anchor) in [
        ("an empty file", Vec::new(), None),
        ("part of the header", header[..40].to_vec(), Some(three)),
        ("all but a byte", header[..HEADER_LEN - 1].to_vec(), None),
        ("zeros", vec![0; HEADER_LEN], Some(three)),
    ] {
        std::fs::write(&fourth, &bytes).unwrap();
        let r = log.verify(anchor);
        assert!(r.ok() && r.torn_tail, "{what}: {r:?}");
        assert_eq!(r.torn_bytes, bytes.len() as u64, "{what}");
        let (mut w, report) = AuditWriter::open(&log.dir, &log.keys, anchor).unwrap();
        assert!(
            report.torn_tail_removed && !report.damaged,
            "{what}: {report:?}"
        );
        assert_eq!(report.torn_bytes, bytes.len() as u64, "{what}");
        assert!(!fourth.exists(), "{what}: removed");
        assert_eq!(w.append(&record(4)).unwrap(), 4, "{what}");
        let r = log.verify(anchor);
        assert!(r.ok() && !r.torn_tail && r.last_seq == 4, "{what}: {r:?}");
    }

    let mut changed = header[..40].to_vec();
    changed[20] ^= 0x01;
    for (what, bytes, anchor) in [
        ("a changed byte", changed, Some(three)),
        ("under a saved head", header[..40].to_vec(), Some(four)),
    ] {
        std::fs::write(&fourth, &bytes).unwrap();
        let r = log.verify(anchor);
        assert_eq!(
            problem(&r),
            Some((4, ProblemKind::SegmentDamaged)),
            "{what}: {r:?}"
        );
        assert!(!r.torn_tail, "{what}: {r:?}");
        let (_, report) = AuditWriter::open(&log.dir, &log.keys, anchor).unwrap();
        assert!(
            report.damaged && !report.torn_tail_removed,
            "{what}: {report:?}"
        );
        assert_eq!(std::fs::read(&fourth).unwrap(), bytes, "{what}: kept");
    }
}
