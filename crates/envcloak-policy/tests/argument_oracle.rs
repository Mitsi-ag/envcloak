//! An independent oracle for the arguments the evidence classifies a
//! process by, read again after each check of the chain (M2 plan D-09,
//! task M2-10): an `exec` of the same file keeps the pid, the start time,
//! the executable and the command name, so only its arguments say that
//! `node tool.js` now runs an agent's script. It was written apart from the
//! crate, from the contract alone, and adopted here as it ran against the
//! candidate it qualified:
//!
//! - each case's expected outcome is written in the case (the kind, the
//!   agent's label, basis and place in the chain, the root, the proof
//!   refusal, or `Changed`), never computed with a second gather of the
//!   crate's own;
//! - each case carries controls that the oracle itself works: how many
//!   times the arguments were read (one walk reads them twice, before and
//!   after its check), which processes the hasher was asked for (the
//!   caller and the interpreter on every walk, never the other user's
//!   init, nothing without a hasher), and the digests the evidence keeps.
//!   A case whose controls fail fails the test, whatever its contract says.
//!
//! The chain: caller (90) <- an interpreter (80, leading session 80 on a
//! terminal) <- init (1, root's). Three shapes of the interpreter: `node`,
//! a versioned `node22`, and one whose executable is hidden (its
//! `argv[0]` stands in). Three ways to gather: without a hasher, with one
//! that knows every digest, with one that knows none. Six timelines of its
//! arguments, one per read: an agent's script throughout; a tool's script,
//! then an agent's (the walk read the tool's, its check the agent's: walk
//! again, an agent); an agent's, then a tool's (walk again, a terminal);
//! a tool's throughout; a tool's that gains an argument changing nothing
//! it is (not walked again); and a script that changes at every read
//! (`Changed` after every attempt). Eighteen agent cases, twenty-seven
//! terminal cases, nine refusals.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;

use envcloak_policy::{
    AgentCatalog, Claims, EvidenceError, ExeDigest, ExeHasher, GATHER_ATTEMPTS, MatchBasis,
    ProofRefusal, SubjectKind, gather_in, gather_in_hashed,
};
use envcloak_sys::{
    Argv, ExeIdentity, FileKey, PeerIdentity, PeerSource, ProcInfo, ProcessTable, StartTime,
};

/// Gemini CLI's script under a distribution's npm global folder.
const AGENT_SCRIPT: &str = "/usr/lib/node_modules/@google/gemini-cli/bundle/gemini.js";
const TOOL_SCRIPT: &str = "/fixture/tool.js";

/// The interpreter's shapes.
const SHAPES: [&str; 3] = ["node", "node22", "hidden"];
/// The ways to gather.
const MODES: [&str; 3] = ["plain", "known digests", "unknown digests"];
/// The timelines of the interpreter's arguments.
const TIMELINES: [&str; 6] = [
    "agent throughout",
    "tool, then agent",
    "agent, then tool",
    "tool throughout",
    "tool, then tool with another argument",
    "changing at every read",
];

fn proc(pid: i32, ppid: i32, uid: u32, path: Option<&str>) -> ProcInfo {
    ProcInfo {
        pid,
        ppid,
        uid,
        start_time: StartTime::from_raw(u64::try_from(pid).expect("synthetic id") * 100),
        sid: Some(if pid == 1 { 1 } else { 80 }),
        controlling_tty: Some(7),
        comm: OsString::from(
            path.and_then(|x| x.rsplit('/').next())
                .unwrap_or("fixture-hidden"),
        ),
        exe: path.map(|x| ExeIdentity {
            path: PathBuf::from(x),
            file: Some((1, u64::try_from(pid).expect("synthetic id"))),
            sha256: None,
            signature: None,
        }),
        argv: None,
    }
}

struct Table {
    rows: BTreeMap<i32, ProcInfo>,
    /// How many times the interpreter's arguments were read.
    reads: usize,
    timeline: usize,
    shape: usize,
}

impl ProcessTable for Table {
    fn info(&mut self, pid: i32) -> io::Result<ProcInfo> {
        self.rows
            .get(&pid)
            .cloned()
            .ok_or_else(|| io::ErrorKind::NotFound.into())
    }

    fn argv(&mut self, pid: i32) -> io::Result<Argv> {
        if pid != 80 {
            return Err(io::ErrorKind::NotFound.into());
        }
        let n = self.reads;
        self.reads += 1;
        let agent = match self.timeline {
            0 => true,
            1 => n != 0,
            2 => n == 0,
            3 | 4 => false,
            5 => n % 2 == 1,
            _ => unreachable!(),
        };
        let name = if self.shape == 1 {
            "/fixture/runtime/node22"
        } else {
            "/fixture/runtime/node"
        };
        let script = if agent { AGENT_SCRIPT } else { TOOL_SCRIPT };
        let mut args = vec![name, script];
        if self.timeline == 4 && n > 0 {
            args.push("--watch");
        }
        Ok(Argv::new(args))
    }
}

struct Hasher {
    unknown: bool,
    asked: Vec<i32>,
}

impl ExeHasher for Hasher {
    fn sha256(&mut self, p: &ProcInfo) -> Option<ExeDigest> {
        self.asked.push(p.pid);
        (!self.unknown).then(|| ExeDigest {
            sha256: [u8::try_from(p.pid).expect("synthetic id"); 32],
            key: unwritten(p),
        })
    }

    fn key(&mut self, p: &ProcInfo) -> Option<FileKey> {
        Some(unwritten(p))
    }
}

/// The state of `p`'s file, the same at every read: no file is written in
/// these cases (the hasher's interface carries it since the review that
/// added the check of each hashed file's state).
fn unwritten(p: &ProcInfo) -> FileKey {
    let (dev, ino) = p.exe.as_ref().and_then(|e| e.file).unwrap_or_default();
    FileKey {
        dev,
        ino,
        size: 0,
        ctime: (0, 0),
    }
}

/// One case: whether its contract held, whether its controls held, and
/// what it got, for the failure message.
fn run(timeline: usize, shape: usize, mode: usize) -> (bool, bool, String) {
    let path = match shape {
        0 => Some("/fixture/runtime/node"),
        1 => Some("/fixture/runtime/node22"),
        2 => None,
        _ => unreachable!(),
    };
    let mut t = Table {
        rows: BTreeMap::from([
            (90, proc(90, 80, 1000, Some("/fixture/bin/caller"))),
            (80, proc(80, 1, 1000, path)),
            (1, proc(1, 0, 0, Some("/fixture/bin/init"))),
        ]),
        reads: 0,
        timeline,
        shape,
    };
    let peer = PeerIdentity {
        uid: 1000,
        pid: 90,
        start_time: StartTime::from_raw(9000),
        pidversion: None,
        source: PeerSource::PeerCred,
    };
    let mut h = Hasher {
        unknown: mode == 2,
        asked: vec![],
    };
    let cat = AgentCatalog::builtin();
    let r = if mode == 0 {
        gather_in(&mut t, &peer, Claims::none(), &cat)
    } else {
        gather_in_hashed(&mut t, &peer, Claims::none(), &cat, &mut h)
    };

    // The contract, written out.
    let agent = timeline <= 1;
    let contract = if timeline == 5 {
        matches!(r, Err(EvidenceError::Changed))
    } else {
        r.as_ref().is_ok_and(|e| {
            e.root().pid == 80
                && e.kind()
                    == if agent {
                        SubjectKind::Agent
                    } else {
                        SubjectKind::Terminal
                    }
                && e.proof_refusal() == agent.then_some(ProofRefusal::Agent)
                && if agent {
                    e.nearest_agent().is_some_and(|(index, l)| {
                        index == 1
                            && e.chain()[index].instance.pid == 80
                            && l.id == "gemini-cli"
                            && l.basis == MatchBasis::Asserted
                    })
                } else {
                    e.nearest_agent().is_none()
                }
        })
    };

    // The controls: the reads, the hashes, the digests kept.
    let reads = match timeline {
        0 | 3 | 4 => 2,
        1 | 2 => 4,
        5 => 2 * GATHER_ATTEMPTS,
        _ => unreachable!(),
    };
    let walks = reads / 2;
    let hashed = if mode == 0 {
        h.asked.is_empty()
    } else {
        h.asked.len() == (if shape == 2 { 1 } else { 2 }) * walks && !h.asked.contains(&1)
    };
    let digests = r.as_ref().map_or(true, |e| {
        e.chain().iter().all(|a| {
            a.instance.exe.as_ref().is_none_or(|x| {
                x.sha256
                    == if mode == 0 || mode == 2 || a.instance.pid == 1 {
                        None
                    } else {
                        Some([u8::try_from(a.instance.pid).expect("synthetic id"); 32])
                    }
            })
        })
    });
    let controls = t.reads == reads && hashed && digests;
    let got = match &r {
        Ok(e) => format!(
            "{:?} root {} nearest {:?}, {} reads, hashed {:?}",
            e.kind(),
            e.root().pid,
            e.nearest_agent().map(|(i, l)| (i, l.id.clone(), l.basis)),
            t.reads,
            h.asked
        ),
        Err(e) => format!("{e:?}, {} reads, hashed {:?}", t.reads, h.asked),
    };
    (contract, controls, got)
}

/// Every case's contract and controls hold: 54 cases, 18 agents, 27
/// terminals, 9 refusals.
///
/// Mutation checked: the evidence not reading the arguments again after
/// the walk's check fails the agent and terminal cases whose script
/// changed between the reads, and the refusals; reading the chain again
/// only when a hasher is given fails the same cases gathered plainly.
#[test]
fn arguments_read_again_decide_as_the_contract_says() {
    let mut failed = Vec::new();
    let (mut agents, mut terminals, mut refusals) = (0, 0, 0);
    for (shape, shape_name) in SHAPES.iter().enumerate() {
        for (mode, mode_name) in MODES.iter().enumerate() {
            for (timeline, timeline_name) in TIMELINES.iter().enumerate() {
                let (contract, controls, got) = run(timeline, shape, mode);
                if contract && controls {
                    match timeline {
                        5 => refusals += 1,
                        0 | 1 => agents += 1,
                        _ => terminals += 1,
                    }
                } else {
                    failed.push(format!(
                        "{shape_name}, {mode_name}, {timeline_name}: contract {contract}, \
                         controls {controls}: {got}"
                    ));
                }
            }
        }
    }
    assert!(failed.is_empty(), "{}", failed.join("\n"));
    assert_eq!((agents, terminals, refusals), (18, 27, 9));
}
