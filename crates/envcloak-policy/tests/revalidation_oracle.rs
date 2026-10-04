//! An independent oracle for the post-hash revalidation of caller evidence
//! (M2 plan D-09, task M2-10): [`ProcInfo::unchanged`] field by field, and
//! [`gather_in_hashed`] over a synthetic chain that changes while it is
//! hashed. It was written apart from the crate, from the contract alone,
//! and adopted here as it ran against the candidate it qualified:
//!
//! - each case's expected outcome is written in the case (a boolean, an
//!   error, the digests a case keeps), never computed with the crate's own
//!   comparison;
//! - each case carries controls that the oracle itself works: reflexivity
//!   and symmetry for the field cases; for the chain cases, that the table
//!   was read after hashing, that the changed process was seen, that the
//!   hasher was asked for the caller (or, for a caller without executable
//!   metadata, was not) and never for the other user's init. A case whose
//!   controls fail fails the test, whatever its contract says.
//!
//! The field cases: twenty readings of one process, one field changed in
//! each (pid, parent, start, uid, session, terminal, command name, the
//! executable's presence, path, device, inode and signature, the
//! signature's identifier, team and cdhash); a digest or arguments added,
//! and two readings without an executable, are unchanged (the kernel's
//! readings hold neither, and the evidence re-reads arguments itself).
//!
//! The chain cases: caller (30) <- codex (20) <- init (1, root's). Stable
//! (digests kept); a hasher that answers nothing (no digest); the parent's
//! start, inode, device, path or command name changed after hashing (the
//! chain walked again, and the evidence is the new chain's); the caller
//! without executable metadata, its command name changed (read again all
//! the same, and never hashed); the caller's start changed (`CallerGone`);
//! the caller's post-hash read refused (`Io(PermissionDenied)`); the parent
//! gone while the caller still names it (`Hidden`); and a chain that
//! changes during every hashing (`Changed`).
//!
//! A second set of snapshot cases, from an earlier oracle of the same
//! kind, checks which processes are hashed at all and that a digest never
//! changes a decision: a stable chain and a silent hasher, a parent of
//! another uid (never hashed), and a caller or a parent without its
//! executable's device and inode (never hashed). That oracle's cases where
//! the chain changes after hashing expected a digest dropped from evidence
//! built on the chain as it was before hashing; the evidence now walks the
//! chain again instead, which the chain cases above check, so they are
//! left out.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::cell::Cell;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::rc::Rc;

use envcloak_policy::{
    AgentCatalog, Ancestor, Claims, EvidenceError, ExeHasher, SubjectEvidence, SubjectKind,
    gather_in, gather_in_hashed,
};
use envcloak_sys::{
    Argv, CodeSignature, ExeIdentity, PeerIdentity, PeerSource, ProcInfo, ProcessTable, StartTime,
};
use serde_json::{Value, json};

fn proc(pid: i32, ppid: i32, uid: u32, path: &str) -> ProcInfo {
    ProcInfo {
        pid,
        ppid,
        uid,
        start_time: StartTime::from_raw(u64::try_from(pid).expect("synthetic id") * 10),
        sid: Some(30),
        controlling_tty: Some(1),
        comm: OsString::from(path.rsplit('/').next().expect("basename")),
        exe: Some(ExeIdentity {
            path: PathBuf::from(path),
            file: Some((1, u64::try_from(pid).expect("synthetic id"))),
            sha256: None,
            signature: None,
        }),
        argv: None,
    }
}

fn signed(p: &mut ProcInfo) {
    p.exe.as_mut().expect("exe").signature = Some(CodeSignature {
        identifier: "fixture.signer".into(),
        team_id: Some("fixture.team".into()),
        cdhash: None,
    });
}

/// Field case `id`: two readings `a` and `b` of one process, and whether
/// `b.unchanged(&a)` must hold.
fn field_case(id: usize) -> Value {
    let mut a = proc(30, 20, 501, "/fixture/caller");
    let mut b = a.clone();
    match id {
        0 => {}
        1 => b.pid += 1,
        2 => b.ppid += 1,
        3 => b.start_time = StartTime::from_raw(301),
        4 => b.uid += 1,
        5 => b.sid = None,
        6 => b.controlling_tty = None,
        7 => b.comm = "changed".into(),
        8 => b.exe = None,
        9 => b.exe.as_mut().expect("exe").path = PathBuf::from("/fixture/new-caller"),
        10 => b.exe.as_mut().expect("exe").file = None,
        11 => b.exe.as_mut().expect("exe").file = Some((2, 30)),
        12 => b.exe.as_mut().expect("exe").file = Some((1, 31)),
        13 => signed(&mut b),
        14 => b.exe.as_mut().expect("exe").sha256 = Some([5; 32]),
        15 => b.argv = Some(Argv::new(["fixture-argument"])),
        16 => {
            a.exe = None;
            b.exe = None;
        }
        17..=19 => {
            signed(&mut a);
            b = a.clone();
            let signature = b
                .exe
                .as_mut()
                .expect("exe")
                .signature
                .as_mut()
                .expect("signature");
            match id {
                17 => signature.identifier = "other.signer".into(),
                18 => signature.team_id = None,
                19 => signature.cdhash = Some([7; 20]),
                _ => unreachable!(),
            }
        }
        _ => unreachable!(),
    }
    let want = matches!(id, 0 | 14 | 15 | 16);
    let got = b.unchanged(&a);
    let controls = a.unchanged(&a) && b.unchanged(&b) && got == a.unchanged(&b);
    json!({"id": id, "controls": controls, "contract": controls && got == want})
}

/// The chain cases' process table: caller (30) <- codex (20) <- init (1).
/// Once the hasher ran (`epoch` above 0), each read is counted and shows
/// the case's change.
struct Table {
    rows: BTreeMap<i32, ProcInfo>,
    epoch: Rc<Cell<usize>>,
    case: usize,
    post_reads: usize,
    changed_parent_seen: bool,
}

fn table(case: usize, epoch: Rc<Cell<usize>>) -> Table {
    let mut rows = BTreeMap::from([
        (30, proc(30, 20, 501, "/fixture/caller")),
        (20, proc(20, 1, 501, "/fixture/codex")),
        (1, proc(1, 0, 0, "/fixture/init")),
    ]);
    if case == 7 {
        rows.get_mut(&30).expect("caller").exe = None;
    }
    Table {
        rows,
        epoch,
        case,
        post_reads: 0,
        changed_parent_seen: false,
    }
}

/// Case `case`'s change to process `p`, once hashing ran.
fn change(p: &mut ProcInfo, case: usize) {
    match (case, p.pid) {
        (2, 20) => p.start_time = StartTime::from_raw(201),
        (3, 20) => p.exe.as_mut().expect("exe").file = Some((1, 21)),
        (4, 20) => p.exe.as_mut().expect("exe").file = Some((2, 20)),
        (5, 20) => p.exe.as_mut().expect("exe").path = PathBuf::from("/fixture/renamed/codex"),
        (6, 20) => p.comm = "renamed-parent".into(),
        (7, 30) => p.comm = "changed-caller".into(),
        (8, 30) => p.start_time = StartTime::from_raw(301),
        _ => {}
    }
}

impl ProcessTable for Table {
    fn info(&mut self, pid: i32) -> io::Result<ProcInfo> {
        let mut p = self
            .rows
            .get(&pid)
            .cloned()
            .ok_or(io::ErrorKind::NotFound)?;
        let epoch = self.epoch.get();
        if epoch > 0 {
            self.post_reads += 1;
            if pid == 20 {
                self.changed_parent_seen = true;
            }
            if (self.case, pid) == (9, 30) {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            if (self.case, pid) == (10, 20) {
                return Err(io::ErrorKind::NotFound.into());
            }
            change(&mut p, self.case);
        }
        if self.case == 11 && pid == 20 {
            p.comm = OsString::from(format!("snapshot-{epoch}"));
        }
        Ok(p)
    }

    fn argv(&mut self, _: i32) -> io::Result<Argv> {
        Err(io::ErrorKind::NotFound.into())
    }
}

/// A hasher that starts the case's change (case 11: a new one at every
/// call) and answers a digest per pid, or nothing (case 1).
struct Hasher {
    epoch: Rc<Cell<usize>>,
    case: usize,
    asked: Vec<i32>,
}

fn digest(pid: i32) -> [u8; 32] {
    [u8::try_from(pid).expect("synthetic id"); 32]
}

impl ExeHasher for Hasher {
    fn sha256(&mut self, p: &ProcInfo) -> Option<[u8; 32]> {
        self.asked.push(p.pid);
        if self.case == 11 {
            self.epoch.set(self.epoch.get() + 1);
        } else {
            self.epoch.set(1);
        }
        (self.case != 1).then(|| digest(p.pid))
    }
}

fn member(e: &SubjectEvidence, pid: i32) -> Option<&Ancestor> {
    e.chain().iter().find(|a| a.instance.pid == pid)
}

fn chain_case(case: usize) -> Value {
    let epoch = Rc::new(Cell::new(0));
    let mut t = table(case, epoch.clone());
    let mut h = Hasher {
        epoch,
        case,
        asked: Vec::new(),
    };
    let peer = PeerIdentity {
        uid: 501,
        pid: 30,
        start_time: StartTime::from_raw(300),
        pidversion: None,
        source: PeerSource::PeerCred,
    };
    let result = gather_in_hashed(
        &mut t,
        &peer,
        Claims::none(),
        &AgentCatalog::builtin(),
        &mut h,
    );
    let observed = match &result {
        Ok(e) => {
            if matches!(case, 8..=11) {
                false
            } else {
                let mut caller = t.rows[&30].clone();
                let mut parent = t.rows[&20].clone();
                change(&mut caller, case);
                change(&mut parent, case);
                let c = member(e, 30).expect("retained caller");
                let caller_ok = c.instance.start_time == caller.start_time
                    && c.sid == caller.sid
                    && c.terminal == caller.controlling_tty;
                let parent_ok = member(e, 20).is_some_and(|a| {
                    let want = parent.exe.as_ref().expect("exe");
                    a.instance.start_time == parent.start_time
                        && a.sid == parent.sid
                        && a.terminal == parent.controlling_tty
                        && a.instance
                            .exe
                            .as_ref()
                            .is_some_and(|x| x.file == want.file && x.path == want.path)
                });
                let digests = e.chain().iter().all(|a| {
                    a.instance.exe.as_ref().is_none_or(|x| {
                        x.sha256
                            == if case == 1 || a.instance.pid == 1 {
                                None
                            } else {
                                Some(digest(a.instance.pid))
                            }
                    })
                });
                let retry = matches!(case, 0 | 1) || h.asked.len() > if case == 7 { 1 } else { 2 };
                caller_ok && parent_ok && digests && retry
            }
        }
        Err(err) => match case {
            8 => *err == EvidenceError::CallerGone,
            9 => *err == EvidenceError::Io(io::ErrorKind::PermissionDenied),
            10 => *err == EvidenceError::Hidden,
            11 => *err == EvidenceError::Changed,
            _ => false,
        },
    };
    let controls = t.post_reads > 0
        && !h.asked.contains(&1)
        && h.epoch.get() > 0
        && (matches!(case, 8 | 9) || t.changed_parent_seen)
        && if case == 7 {
            !h.asked.contains(&30)
        } else {
            h.asked.contains(&30)
        };
    json!({
        "id": case,
        "controls": controls,
        "contract": controls && observed,
        "hash_requests": h.asked.len(),
        "post_reads": t.post_reads,
        "returned_error": result.is_err(),
    })
}

/// Post-hash revalidation: every field case and every chain case keeps its
/// controls and its contract.
#[test]
fn post_hash_snapshots_are_revalidated_before_evidence() {
    let fields: Vec<Value> = (0..20).map(field_case).collect();
    let chain: Vec<Value> = (0..12).map(chain_case).collect();
    for r in fields.iter().chain(&chain) {
        assert_eq!(r["controls"], true, "controls: {r}");
    }
    for r in fields.iter().chain(&chain) {
        assert_eq!(r["contract"], true, "contract: {r}");
    }
}

/// The snapshot cases' process table: helper (30) <- codex (20, leading
/// session 20) <- init (1), of uid 777. `after` is set once the hasher
/// ran; reads from then on are recorded.
struct SnapshotTable {
    rows: BTreeMap<i32, ProcInfo>,
    after: Rc<Cell<bool>>,
    rechecks: Vec<i32>,
}

fn snapshot_proc(pid: i32, ppid: i32, uid: u32, path: &str) -> ProcInfo {
    let mut p = proc(pid, ppid, uid, path);
    p.start_time = StartTime::from_raw(u64::try_from(pid).expect("positive") * 100);
    p.sid = Some(20);
    p.controlling_tty = Some(7);
    p
}

fn snapshot_table(case: usize, after: Rc<Cell<bool>>) -> SnapshotTable {
    let mut rows = BTreeMap::from([
        (30, snapshot_proc(30, 20, 777, "/fixture/ec-helper")),
        (20, snapshot_proc(20, 1, 777, "/fixture/codex")),
        (1, snapshot_proc(1, 0, 0, "/fixture/init")),
    ]);
    match case {
        8 => rows.get_mut(&20).expect("parent").uid = 778,
        9 => {
            rows.get_mut(&30)
                .expect("caller")
                .exe
                .as_mut()
                .expect("exe")
                .file = None
        }
        10 => {
            rows.get_mut(&20)
                .expect("parent")
                .exe
                .as_mut()
                .expect("exe")
                .file = None
        }
        _ => {}
    }
    SnapshotTable {
        rows,
        after,
        rechecks: Vec::new(),
    }
}

impl ProcessTable for SnapshotTable {
    fn info(&mut self, pid: i32) -> io::Result<ProcInfo> {
        let p = self
            .rows
            .get(&pid)
            .cloned()
            .ok_or(io::ErrorKind::NotFound)?;
        if self.after.get() {
            self.rechecks.push(pid);
        }
        Ok(p)
    }

    fn argv(&mut self, _: i32) -> io::Result<Argv> {
        Err(io::ErrorKind::NotFound.into())
    }
}

struct SnapshotHasher {
    after: Rc<Cell<bool>>,
    case: usize,
    asked: Vec<i32>,
}

fn value(pid: i32) -> [u8; 32] {
    [u8::try_from(pid).expect("synthetic bounded pid"); 32]
}

impl ExeHasher for SnapshotHasher {
    fn sha256(&mut self, p: &ProcInfo) -> Option<[u8; 32]> {
        self.asked.push(p.pid);
        self.after.set(true);
        (self.case != 1).then(|| value(p.pid))
    }
}

/// The digests of the caller (30) and the parent (20) in `e`.
fn digests(e: &SubjectEvidence) -> [Option<[u8; 32]>; 2] {
    [30, 20].map(|pid| {
        member(e, pid)
            .and_then(|a| a.instance.exe.as_ref())
            .and_then(|x| x.sha256)
    })
}

/// Which of the caller and the parent case `case` keeps a digest for.
fn expected(case: usize) -> [bool; 2] {
    match case {
        0 => [true, true],
        1 => [false, false],
        9 => [false, true],
        8 | 10 => [true, false],
        _ => panic!("unknown synthetic case"),
    }
}

fn judge(case: usize, got: [Option<[u8; 32]>; 2]) -> bool {
    let want = [30, 20].map(|pid| {
        let pos = usize::from(pid != 30);
        expected(case)[pos].then(|| value(pid))
    });
    got == want
}

fn snapshot_case(case: usize) -> Value {
    let cat = AgentCatalog::builtin();
    let peer = PeerIdentity {
        uid: 777,
        pid: 30,
        start_time: StartTime::from_raw(3000),
        pidversion: None,
        source: PeerSource::PeerCred,
    };
    let plain = gather_in(
        &mut snapshot_table(case, Rc::new(Cell::new(false))),
        &peer,
        Claims::none(),
        &cat,
    )
    .expect("stable plain evidence");
    let after = Rc::new(Cell::new(false));
    let mut t = snapshot_table(case, after.clone());
    let mut hasher = SnapshotHasher {
        after,
        case,
        asked: Vec::new(),
    };
    let hashed = gather_in_hashed(&mut t, &peer, Claims::none(), &cat, &mut hasher)
        .expect("synthetic evidence");
    let asked = match case {
        8 | 10 => vec![30],
        9 => vec![20],
        _ => vec![30, 20],
    };
    let classification = hashed.kind() == plain.kind()
        && hashed.root().same(&plain.root())
        && hashed.label() == plain.label()
        && hashed.proof_refusal() == plain.proof_refusal()
        && plain.chain().iter().all(|a| {
            [
                SubjectKind::Agent,
                SubjectKind::Terminal,
                SubjectKind::Unknown,
            ]
            .into_iter()
            .all(|k| hashed.covered_by(&a.instance, k) == plain.covered_by(&a.instance, k))
        });
    let read_after = t.rechecks.contains(&30) && t.rechecks.contains(&20);
    let got = digests(&hashed);
    let positive = hasher.asked == asked
        && classification
        && read_after
        && hasher.after.get()
        && hashed.chain().len() == 3
        && got[0].is_none_or(|v| v == value(30))
        && got[1].is_none_or(|v| v == value(20));
    json!({
        "id": case,
        "controls": positive,
        "contract": positive && judge(case, got),
        "requested_count": hasher.asked.len(),
        "classification_preserved": classification,
    })
}

/// Which processes are hashed, and that a digest decides nothing: every
/// snapshot case keeps its controls and its contract, and the comparison
/// refuses the trivial answers (no digest at all, or every digest kept).
#[test]
fn hash_identity_observations_fail_closed_without_reclassifying() {
    const CASES: [usize; 5] = [0, 1, 8, 9, 10];
    let cases: Vec<Value> = CASES.into_iter().map(snapshot_case).collect();
    for r in &cases {
        assert_eq!(r["controls"], true, "controls: {r}");
        assert_eq!(r["contract"], true, "contract: {r}");
    }
    let dropped = CASES.iter().filter(|c| !judge(**c, [None, None])).count();
    let stale = CASES
        .iter()
        .filter(|c| !judge(**c, [Some(value(30)), Some(value(20))]))
        .count();
    assert!(
        dropped > 0 && stale > 0,
        "the comparison refuses trivial observation vectors"
    );
}
