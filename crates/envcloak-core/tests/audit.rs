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
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use common::{Fixture, name, secret_item};
use envcloak_core::SecretBytes;
use envcloak_core::audit::{
    AnchorCheck, AuditIo, AuditKind, AuditRecord, AuditWriter, DecisionSummary, HEADER_LEN,
    MAX_SEGMENT, OsIo, Problem, ProblemKind, ProjectSummary, SubjectSummary, VerifyReport,
    read_entries, verify,
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
        let dir = f.metadata()?.is_dir();
        p.ops.push(if dir { Op::SyncDir } else { Op::SyncFile });
        if !dir && p.fail_file_sync {
            p.fail_file_sync = false;
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

/// Gate 33, the flush half: every append writes its frame and flushes the
/// segment before it returns, and the first also flushes the header and
/// the directory. The flushes are `F_FULLFSYNC` on macOS and `fsync` on
/// Linux, counted by envcloak-sys's shim.
#[test]
fn every_append_is_flushed_before_it_returns() {
    let log = Log::new();
    let shim = Shim::default();
    let mut w = log.writer_with(shim.clone(), MAX_SEGMENT);
    assert_eq!(shim.ops(), vec![], "opening writes nothing");

    let before = envcloak_sys::testing::sync_counts();
    assert_eq!(w.append(&record(1)).unwrap(), 1);
    let first = shim.ops();
    assert_eq!(first.len(), 5, "{first:?}");
    assert_eq!(first[0], Op::Write(HEADER_LEN));
    assert_eq!(&first[1..3], &[Op::SyncFile, Op::SyncDir]);
    assert!(matches!(first[3], Op::Write(n) if n > 12 + 40 + 32));
    assert_eq!(first[4], Op::SyncFile, "the frame is flushed last");
    let after = envcloak_sys::testing::sync_counts();
    let (full, plain) = (
        after.full_fsync - before.full_fsync,
        after.fsync - before.fsync,
    );
    if cfg!(target_os = "macos") {
        assert_eq!((full, plain), (3, 0), "F_FULLFSYNC, never plain fsync");
    } else {
        assert_eq!((full, plain), (0, 3));
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

/// A crash in the middle of a write leaves a torn last entry. It was never
/// acknowledged: the check reports it without flagging the log, and the
/// writer removes it and goes on.
#[test]
fn the_writer_removes_a_torn_entry_and_goes_on() {
    let log = Log::new();
    let mut w = log.writer(None);
    fill(&mut w, 1, 3);
    drop(w);
    let seg = log.segments().pop().unwrap();
    let mut bytes = std::fs::read(&seg).unwrap();
    let whole = bytes.len();
    let (_, last) = frames(&bytes)[2].clone();
    let copy = bytes[last.start..last.start + 40].to_vec();
    bytes.extend_from_slice(&copy);
    std::fs::write(&seg, &bytes).unwrap();
    let r = log.verify(None);
    assert!(r.ok(), "{r:?}");
    assert!(r.torn_tail);

    let (mut w, report) = AuditWriter::open(&log.dir, &log.keys, None).unwrap();
    assert!(report.torn_tail_removed);
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
