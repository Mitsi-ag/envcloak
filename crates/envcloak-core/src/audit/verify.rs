//! Checking the log (SPEC §15.2 gate 33): every entry opens, the chain
//! holds from the first entry to the last, the sequence numbers run
//! without a gap, and the head saved in the vault's header is in it.
//!
//! The walk reads the segments in the order of their names. For each
//! entry it expects the next sequence number and the chain value after
//! the entry before. The first thing that does not match is reported at
//! the sequence number where it shows:
//! - an entry that does not open (its bytes, or its number, were changed):
//!   [`ProblemKind::Altered`];
//! - an entry whose chain value is not the one its predecessor gives:
//!   [`ProblemKind::ChainBroken`];
//! - a sequence number that never comes: [`ProblemKind::Missing`], or
//!   [`ProblemKind::Reordered`] when it comes later;
//! - a segment whose header does not authenticate, or bytes that cannot be
//!   framed: [`ProblemKind::SegmentDamaged`], [`ProblemKind::Unreadable`];
//! - a saved head (the anchor) that the log contradicts:
//!   [`ProblemKind::AnchorMismatch`], or [`ProblemKind::Missing`] when the
//!   log ends before it.
//!
//! After a problem the walk takes the stored chain value and goes on, so a
//! later, separate change is found too, and the writer, which uses the
//! same walk to find where to continue, chains new entries on from exactly
//! what a later check will compute.
//!
//! What the walk cannot see: entries removed from the end of the log after
//! the anchor. Those entries, the unanchored tail, are reported as such
//! ([`VerifyReport::unanchored_tail`]); a log that stops there looks the
//! same as one cut back to there. The daemon saves the head at lock, at
//! stop, and every 15 minutes or 100 entries, which bounds the tail.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use subtle::ConstantTimeEq;

use crate::crypto::Keyring;
use crate::vault::AuditHead;

use super::AuditError;
use super::record::AuditRecord;
use super::segment::{
    HEADER_LEN, LogKeys, Next, list_segments, next_frame, parse_header, read_segment,
};

/// What went wrong at a sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProblemKind {
    /// The entry does not open under its sequence number: its bytes, or the
    /// number in front of it, were changed.
    Altered,
    /// The entry's chain value is not the one the entry before it gives: an
    /// entry was changed, replaced or spliced in from another history.
    ChainBroken,
    /// No entry has this sequence number: it was deleted, or the log was
    /// cut before it.
    Missing,
    /// The entry with this sequence number is out of place.
    Reordered,
    /// A segment's header does not authenticate, names another vault or
    /// epoch, or its file cannot be read.
    SegmentDamaged,
    /// Bytes in a segment cannot be read as entries.
    Unreadable,
    /// The entry at the vault's saved head is not the one the head names.
    AnchorMismatch,
}

impl ProblemKind {
    /// The stable token.
    pub const fn token(self) -> &'static str {
        match self {
            ProblemKind::Altered => "altered",
            ProblemKind::ChainBroken => "chain_broken",
            ProblemKind::Missing => "missing",
            ProblemKind::Reordered => "reordered",
            ProblemKind::SegmentDamaged => "segment_damaged",
            ProblemKind::Unreadable => "unreadable",
            ProblemKind::AnchorMismatch => "anchor_mismatch",
        }
    }
}

/// A problem, at the sequence number where it shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Problem {
    pub seq: u64,
    pub kind: ProblemKind,
}

/// What became of the anchor, the head saved in the vault's header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnchorCheck {
    /// The vault has saved no head yet.
    None,
    /// The log holds the anchored entry, with the anchored chain value.
    Matched { seq: u64 },
    /// The log holds another chain value at the anchored sequence number.
    Mismatch { seq: u64 },
    /// The anchored entry is not in the log: removed, or the log ends
    /// before it.
    Missing { seq: u64 },
}

/// The result of [`verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// Segment files read.
    pub segments: usize,
    /// Entries read, in order or not.
    pub entries: u64,
    /// The last sequence number the walk reached.
    pub last_seq: u64,
    /// The first problem, in log order; `None` when the log checks out.
    pub first_problem: Option<Problem>,
    /// Problems in all; one change can show as more than one.
    pub problems: u64,
    pub anchor: AnchorCheck,
    /// The entries after the anchor (all of them when there is none), as
    /// (first, last): entries removed from the end of these would not be
    /// noticed.
    pub unanchored_tail: Option<(u64, u64)>,
    /// The last segment ends in an entry cut short by a crash. It was never
    /// acknowledged; the writer removes it when it next opens the log.
    pub torn_tail: bool,
    /// The chain's head at the end of the walk: the last sequence number
    /// and chain value. The daemon compares it with its own.
    pub head: (u64, [u8; 32]),
}

impl VerifyReport {
    /// Whether the log checks out: no problem, the anchor (if any) matched.
    pub fn ok(&self) -> bool {
        self.first_problem.is_none()
    }
}

/// An entry that opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub seq: u64,
    pub record: AuditRecord,
}

/// The last segment, for the writer.
#[derive(Debug)]
pub(crate) struct LastSegment {
    pub(crate) path: PathBuf,
    /// From its name.
    pub(crate) first_seq: u64,
    pub(crate) len: u64,
    /// Just past its last whole entry (or its header).
    pub(crate) good_len: u64,
    /// It ends in an entry cut short (the bytes from `good_len` on).
    pub(crate) torn: bool,
    /// Its header authenticated and its own entries checked out.
    pub(crate) clean: bool,
}

/// A walk's result.
#[derive(Debug)]
pub(crate) struct Walk {
    pub(crate) report: VerifyReport,
    /// The sequence number the next entry takes.
    pub(crate) next_seq: u64,
    /// The chain value the next entry chains on from.
    pub(crate) end_mac: [u8; 32],
    pub(crate) last: Option<LastSegment>,
}

/// Checks the log in `dir` for the vault epoch of `k` against `anchor`,
/// the head saved in the vault's header. A missing directory is an empty
/// log.
///
/// # Errors
/// The directory cannot be read. Everything about its contents is in the
/// report.
pub fn verify(
    dir: &Path,
    k: &Keyring,
    anchor: Option<AuditHead>,
) -> Result<VerifyReport, AuditError> {
    Ok(walk(dir, &LogKeys::new(k), anchor, true)?.report)
}

/// The entries of the log in `dir` that open, in log order, with the
/// check's report.
///
/// # Errors
/// As [`verify`].
pub fn read_entries(
    dir: &Path,
    k: &Keyring,
    anchor: Option<AuditHead>,
) -> Result<(Vec<AuditEntry>, VerifyReport), AuditError> {
    let mut out = Vec::new();
    let w = walk_with(dir, &LogKeys::new(k), anchor, true, &mut |seq, record| {
        out.push(AuditEntry { seq, record });
    })?;
    Ok((out, w.report))
}

pub(crate) fn walk(
    dir: &Path,
    keys: &LogKeys,
    anchor: Option<AuditHead>,
    open: bool,
) -> Result<Walk, AuditError> {
    walk_with(dir, keys, anchor, open, &mut |_, _| {})
}

/// The walk's running state.
struct Walker<'a> {
    keys: &'a LogKeys,
    anchor: Option<AuditHead>,
    anchor_state: Option<AnchorCheck>,
    /// Every sequence number in the log, to tell a missing entry from a
    /// misplaced one; empty when not classifying.
    all: HashSet<u64>,
    expected: u64,
    h: [u8; 32],
    first_problem: Option<Problem>,
    problems: u64,
    entries: u64,
    last_seq: u64,
}

impl Walker<'_> {
    fn flag(&mut self, kind: ProblemKind, seq: u64) {
        self.problems += 1;
        self.first_problem.get_or_insert(Problem { seq, kind });
    }

    /// Entry `seq` is not where it should be: missing, or later.
    fn absent(&mut self, seq: u64) {
        let kind = if self.all.contains(&seq) {
            ProblemKind::Reordered
        } else {
            ProblemKind::Missing
        };
        self.flag(kind, seq);
    }

    /// Checks the anchor against the chain value `mac` after entry `seq`.
    fn anchor_at(&mut self, seq: u64, mac: &[u8; 32]) {
        let Some(a) = self.anchor else { return };
        if self.anchor_state.is_some() || a.seq != seq {
            return;
        }
        if bool::from(a.mac.ct_eq(mac)) {
            self.anchor_state = Some(AnchorCheck::Matched { seq });
        } else {
            self.anchor_state = Some(AnchorCheck::Mismatch { seq });
            self.flag(ProblemKind::AnchorMismatch, seq);
        }
    }
}

pub(crate) fn walk_with(
    dir: &Path,
    keys: &LogKeys,
    anchor: Option<AuditHead>,
    open: bool,
    on_entry: &mut dyn FnMut(u64, AuditRecord),
) -> Result<Walk, AuditError> {
    let segs = list_segments(dir)?;
    let datas: Vec<Option<Vec<u8>>> = segs.iter().map(|(_, p)| read_segment(p).ok()).collect();
    let mut w = Walker {
        keys,
        anchor,
        anchor_state: None,
        all: HashSet::new(),
        expected: 1,
        h: keys.genesis(),
        first_problem: None,
        problems: 0,
        entries: 0,
        last_seq: 0,
    };
    if open {
        for data in datas.iter().flatten() {
            let mut at = HEADER_LEN;
            while let Next::Frame(f) = next_frame(data, at) {
                w.all.insert(f.seq);
                at = f.end;
            }
        }
    }
    let genesis = w.h;
    w.anchor_at(0, &genesis);
    let mut torn_tail = false;
    let mut last = None;
    for (i, ((name_seq, path), data)) in segs.iter().zip(&datas).enumerate() {
        let is_last = i + 1 == segs.len();
        let (clean, good_len, len, torn) = match data {
            Some(data) => {
                let (clean, good, torn) =
                    walk_segment(&mut w, *name_seq, data, is_last, open, on_entry);
                torn_tail |= torn;
                (clean, good as u64, data.len() as u64, torn)
            }
            None => {
                let at = w.expected;
                w.flag(ProblemKind::SegmentDamaged, at);
                (false, 0, 0, false)
            }
        };
        if is_last {
            last = Some(LastSegment {
                path: path.clone(),
                first_seq: *name_seq,
                len,
                good_len,
                torn,
                clean,
            });
        }
    }
    let anchor_state = match (w.anchor, w.anchor_state) {
        (None, _) => AnchorCheck::None,
        (Some(_), Some(s)) => s,
        (Some(a), None) => {
            if a.seq >= w.expected {
                // The log ends before the anchored entry.
                let at = w.expected;
                w.flag(ProblemKind::Missing, at);
            }
            AnchorCheck::Missing { seq: a.seq }
        }
    };
    let unanchored_tail = match anchor_state {
        AnchorCheck::None if w.last_seq > 0 => Some((1, w.last_seq)),
        AnchorCheck::Matched { seq } if w.last_seq > seq => Some((seq + 1, w.last_seq)),
        _ => None,
    };
    let report = VerifyReport {
        segments: segs.len(),
        entries: w.entries,
        last_seq: w.last_seq,
        first_problem: w.first_problem,
        problems: w.problems,
        anchor: anchor_state,
        unanchored_tail,
        torn_tail,
        head: (w.expected - 1, w.h),
    };
    Ok(Walk {
        report,
        next_seq: w.expected,
        end_mac: w.h,
        last,
    })
}

/// Walks one segment. Returns whether it is clean, the offset past its
/// last whole entry, and whether it ends in a torn entry.
fn walk_segment(
    w: &mut Walker<'_>,
    name_seq: u64,
    data: &[u8],
    is_last: bool,
    open: bool,
    on_entry: &mut dyn FnMut(u64, AuditRecord),
) -> (bool, usize, bool) {
    let mut clean = true;
    let mut at = HEADER_LEN.min(data.len());
    match parse_header(data, w.keys) {
        None => {
            let seq = w.expected;
            w.flag(ProblemKind::SegmentDamaged, seq);
            clean = false;
        }
        Some(hd) => {
            if hd.vault_id != w.keys.vault_id.0 || hd.epoch != w.keys.epoch {
                // Another vault's or epoch's segment: its entries do not
                // open with these keys.
                let seq = w.expected;
                w.flag(ProblemKind::SegmentDamaged, seq);
                return (false, data.len(), false);
            }
            if hd.first_seq != name_seq {
                w.flag(ProblemKind::SegmentDamaged, hd.first_seq);
                clean = false;
            }
            if let Some(before) = hd.first_seq.checked_sub(1) {
                w.anchor_at(before, &hd.prev_mac);
            }
            if hd.first_seq > w.expected {
                let seq = w.expected;
                w.absent(seq);
            } else if hd.first_seq < w.expected {
                w.flag(ProblemKind::Reordered, hd.first_seq);
                clean = false;
            } else if !bool::from(hd.prev_mac.ct_eq(&w.h)) {
                w.flag(ProblemKind::ChainBroken, hd.first_seq);
            }
            if hd.first_seq >= w.expected {
                w.expected = hd.first_seq;
                w.h = hd.prev_mac;
            }
        }
    }
    loop {
        match next_frame(data, at) {
            Next::End => return (clean, at, false),
            Next::Torn if is_last => return (clean, at, true),
            Next::Torn | Next::Unreadable => {
                let seq = w.expected;
                w.flag(ProblemKind::Unreadable, seq);
                return (false, at, false);
            }
            Next::Frame(f) => {
                w.entries += 1;
                at = f.end;
                if f.seq < w.expected {
                    w.flag(ProblemKind::Reordered, f.seq);
                    clean = false;
                    continue;
                }
                let mut in_order = true;
                if f.seq > w.expected {
                    let seq = w.expected;
                    w.absent(seq);
                    in_order = false;
                }
                let mut opened = true;
                if open {
                    match w.keys.open(f.seq, f.sealed) {
                        Some(r) => on_entry(f.seq, r),
                        None => {
                            w.flag(ProblemKind::Altered, f.seq);
                            opened = false;
                        }
                    }
                }
                if in_order && opened {
                    let computed = w.keys.chain(&w.h, f.seq, f.sealed);
                    if !bool::from(computed.ct_eq(&f.mac)) {
                        w.flag(ProblemKind::ChainBroken, f.seq);
                        clean = false;
                    }
                } else {
                    clean = false;
                }
                // Go on from the stored chain value (see the module
                // documentation).
                w.h = f.mac;
                w.expected = f.seq.saturating_add(1);
                w.last_seq = f.seq;
                w.anchor_at(f.seq, &f.mac);
            }
        }
    }
}
