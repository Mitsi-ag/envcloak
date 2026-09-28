//! Caller evidence from synthetic chains and a scripted process table
//! (SPEC §10a, §10b "Root selection" and "Match" rules 3 and 4): root
//! selection, the subject's kind, claims that only tighten, coverage (the
//! agent barrier, pid reuse, kinds), what is classified and what is read,
//! and the walk repeated while the ancestry changes. Real processes are in
//! evidence_gates.rs.
#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::ffi::OsString;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use envcloak_policy::{
    AGENTS_DIR, AgentCatalog, AgentLabel, Ancestor, CatalogSource, ChainEnd, Claims, EvidenceError,
    GATHER_ATTEMPTS, ProcessInstance, SubjectEvidence, SubjectKind, gather_in,
};
use envcloak_sys::{
    ExeIdentity, MAX_ANCESTRY, PeerIdentity, PeerSource, ProcInfo, ProcessTable, StartTime,
};

fn inst(pid: i32, start: u64) -> ProcessInstance {
    ProcessInstance {
        pid,
        start_time: StartTime::from_raw(start),
        pidversion: None,
        exe: None,
    }
}

fn label(id: &str, source: CatalogSource) -> AgentLabel {
    AgentLabel {
        id: id.to_owned(),
        name: id.to_owned(),
        source,
    }
}

/// A process: pid, start time (the pid times 10, so parents are older),
/// session, and an agent label.
fn p(pid: i32, sid: i32, agent: Option<AgentLabel>) -> Ancestor {
    Ancestor {
        instance: inst(pid, 10 * u64::try_from(pid).unwrap()),
        sid: Some(sid),
        agent,
    }
}

fn builtin(id: &str) -> Option<AgentLabel> {
    Some(label(id, CatalogSource::Builtin))
}

fn extension(id: &str) -> Option<AgentLabel> {
    Some(label(id, CatalogSource::Extension))
}

fn ev(chain: Vec<Ancestor>, terminal: bool, claims: &[&str]) -> SubjectEvidence {
    ev_end(chain, ChainEnd::Top, terminal, claims)
}

fn ev_end(chain: Vec<Ancestor>, end: ChainEnd, terminal: bool, claims: &[&str]) -> SubjectEvidence {
    SubjectEvidence::from_chain(
        chain,
        end,
        terminal,
        Claims::from_markers(claims).unwrap(),
        None,
    )
    .unwrap()
}

/// A terminal session: envcloak (90) <- sh (80) <- zsh (70, the session
/// leader) <- login (60, a session of its own) <- Terminal (50, in
/// launchd's session) <- launchd (1).
fn terminal_chain(agent_at_80: Option<AgentLabel>) -> Vec<Ancestor> {
    vec![
        p(90, 70, None),
        p(80, 70, agent_at_80),
        p(70, 70, None),
        p(60, 60, None),
        p(50, 1, None),
        p(1, 1, None),
    ]
}

#[test]
fn the_nearest_agent_is_the_root() {
    let e = ev(terminal_chain(builtin("claude-code")), true, &[]);
    assert_eq!(e.kind(), SubjectKind::Agent);
    assert_eq!(e.root().pid, 80);
    assert_eq!(e.nearest_agent().unwrap().0, 1);
    assert_eq!(e.label().unwrap().id, "claude-code");
    assert!(e.agent_involved());
    assert_eq!(e.session_leader().unwrap().pid, 70);

    // Codex run by Claude Code: the nearer one.
    let mut chain = terminal_chain(builtin("claude-code"));
    chain[0].agent = None;
    chain.insert(1, p(85, 70, builtin("codex")));
    let e = ev(chain, true, &[]);
    assert_eq!(e.root().pid, 85);
    assert_eq!(e.label().unwrap().id, "codex");

    // A builtin agent above the session leader (one that runs its commands
    // in terminals of its own) is still the root.
    let chain = vec![
        p(90, 90, None),
        p(80, 70, builtin("claude-code")),
        p(70, 70, None),
        p(1, 1, None),
    ];
    let e = ev(chain, true, &[]);
    assert_eq!(e.session_leader().unwrap().pid, 90);
    assert_eq!(e.root().pid, 80);
    assert_eq!(e.kind(), SubjectKind::Agent);
}

#[test]
fn without_an_agent_the_session_leader_is_the_root() {
    let e = ev(terminal_chain(None), true, &[]);
    assert_eq!(e.kind(), SubjectKind::Terminal);
    assert_eq!(e.root().pid, 70);
    assert!(!e.agent_involved());
    assert!(e.label().is_none());

    // No controlling terminal (setsid, a service): unknown, same root.
    let e = ev(terminal_chain(None), false, &[]);
    assert_eq!(e.kind(), SubjectKind::Unknown);
    assert_eq!(e.root().pid, 70);
}

#[test]
fn an_orphan_has_lost_its_ancestry() {
    // Double-forked out of session 70, whose leader still runs elsewhere:
    // reparented to launchd. Still on the session's terminal, and claiming
    // an agent: unknown all the same.
    for claims in [&[][..], &["CLAUDECODE"][..]] {
        let e = ev(vec![p(95, 70, None), p(1, 1, None)], true, claims);
        assert!(e.session_leader().is_none());
        assert_eq!(e.kind(), SubjectKind::Unknown, "{claims:?}");
        assert_eq!(e.root().pid, 95, "the topmost in its session");
    }
    // The session leader died; the topmost live ancestor in the session is
    // the root.
    let e = ev(
        vec![p(95, 70, None), p(85, 70, None), p(1, 1, None)],
        true,
        &[],
    );
    assert_eq!(e.kind(), SubjectKind::Unknown);
    assert_eq!(e.root().pid, 85);
}

#[test]
fn pid_1_is_never_a_root_nor_an_agent() {
    // A GUI app runs in launchd's session: launchd is its session leader,
    // and is not taken as one.
    let e = ev(
        vec![p(90, 1, None), p(50, 1, None), p(1, 1, None)],
        false,
        &[],
    );
    assert!(e.session_leader().is_none());
    assert_eq!(e.root().pid, 50);
    assert_eq!(e.kind(), SubjectKind::Unknown);
    assert!(!e.covered_by(&inst(1, 10), SubjectKind::Unknown));

    let e = ev(
        vec![p(90, 90, None), p(1, 1, builtin("claude-code"))],
        true,
        &[],
    );
    assert!(e.nearest_agent().is_none());
    assert_eq!(e.root().pid, 90);
}

#[test]
fn an_extension_agent_above_the_session_does_not_widen_the_root() {
    // An extension matched the terminal emulator (50): the caller is an
    // agent subject, but the root stays the session leader.
    let mut chain = terminal_chain(None);
    chain[4].agent = extension("terminal-app");
    let e = ev(chain.clone(), true, &[]);
    assert_eq!(e.kind(), SubjectKind::Agent);
    assert_eq!(e.root().pid, 70);
    assert!(e.covered_by(&e.root(), SubjectKind::Agent));
    // And a grant rooted there by some other caller does not cover it.
    assert!(!e.covered_by(&chain[4].instance, SubjectKind::Agent));

    // Within the session, an extension agent is the root as a builtin one.
    let e = ev(terminal_chain(extension("aider")), true, &[]);
    assert_eq!(e.root().pid, 80);
    assert!(e.covered_by(&e.root(), SubjectKind::Agent));
}

#[test]
fn claims_only_tighten() {
    let plain = ev(terminal_chain(None), true, &[]);
    let claimed = ev(terminal_chain(None), true, &["CLAUDECODE"]);
    assert_eq!(plain.kind(), SubjectKind::Terminal);
    assert_eq!(claimed.kind(), SubjectKind::Agent);
    assert_eq!(claimed.root(), plain.root());
    assert_eq!(claimed.chain(), plain.chain());
    assert!(claimed.agent_involved());
    // A terminal grant no longer covers it; one approved for it does.
    assert!(plain.covered_by(&plain.root(), SubjectKind::Terminal));
    assert!(!claimed.covered_by(&plain.root(), SubjectKind::Terminal));
    assert!(claimed.covered_by(&plain.root(), SubjectKind::Agent));

    // No claim lowers an agent found by ancestry: claims cannot say "no
    // agent".
    let agent = ev(terminal_chain(builtin("codex")), true, &[]);
    assert_eq!(agent.kind(), SubjectKind::Agent);
    assert!(agent.agent_involved());
}

#[test]
fn the_agent_barrier_and_terminal_grants() {
    // A terminal grant rooted at the session leader...
    let human = ev(terminal_chain(None), true, &[]);
    let terminal_root = human.root();
    assert!(human.covered_by(&terminal_root, SubjectKind::Terminal));
    // ...does not cover an agent started in that terminal, even when its
    // grant kind is not checked: the agent sits between root and caller.
    let agent = ev(terminal_chain(builtin("fixture")), true, &[]);
    assert!(!agent.covered_by(&terminal_root, SubjectKind::Terminal));
    assert!(!agent.covered_by(&terminal_root, SubjectKind::Agent));
    // The agent's own grant does.
    assert!(agent.covered_by(&agent.root(), SubjectKind::Agent));
    // The caller itself being an agent is a barrier too.
    let mut chain = terminal_chain(None);
    chain[0].agent = builtin("codex");
    let e = ev(chain, true, &[]);
    assert!(!e.covered_by(&terminal_root, SubjectKind::Agent));
    assert!(e.covered_by(&e.root(), SubjectKind::Agent));
}

#[test]
fn a_recycled_pid_never_matches() {
    let e = ev(terminal_chain(builtin("claude-code")), true, &[]);
    let root = e.root();
    let reused = ProcessInstance {
        start_time: StartTime::from_raw(root.start_time.raw() + 1),
        ..root.clone()
    };
    assert!(e.covered_by(&root, SubjectKind::Agent));
    assert!(!e.covered_by(&reused, SubjectKind::Agent));
    // Nor another process of the chain's pid with an older start.
    let older = ProcessInstance {
        start_time: StartTime::from_raw(root.start_time.raw() - 1),
        ..root.clone()
    };
    assert!(!e.covered_by(&older, SubjectKind::Agent));
    // Not in the chain at all.
    assert!(!e.covered_by(&inst(12345, 1), SubjectKind::Agent));
    // macOS: the direct peer's pid version, when both sides know it.
    let mut chain = terminal_chain(None);
    chain[0].instance.pidversion = Some(7);
    let e = ev(chain, true, &[]);
    let caller = e.caller().clone();
    assert!(e.covered_by(&caller, SubjectKind::Unknown));
    let other_version = ProcessInstance {
        pidversion: Some(8),
        ..caller
    };
    assert!(!e.covered_by(&other_version, SubjectKind::Unknown));
}

#[test]
fn an_empty_chain_is_no_evidence() {
    for end in [ChainEnd::Top, ChainEnd::Cut] {
        assert!(SubjectEvidence::from_chain(Vec::new(), end, true, Claims::none(), None).is_none());
    }
}

/// [`MAX_ANCESTRY`] processes, the caller (1000) first, each the child of
/// the next: the first 51 in a terminal session led by 950, the rest in
/// session 900. `agent_at` labels one of them a builtin agent.
fn long_chain(agent_at: Option<usize>) -> Vec<Ancestor> {
    (0..MAX_ANCESTRY)
        .map(|k| {
            let pid = 1000 - i32::try_from(k).unwrap();
            let sid = if pid >= 950 { 950 } else { 900 };
            p(
                pid,
                sid,
                (agent_at == Some(k)).then(|| label("codex", CatalogSource::Builtin)),
            )
        })
        .collect()
}

#[test]
fn a_cut_chain_fails_closed() {
    // The same processes, seen whole and cut. Whole, the caller is a
    // terminal subject rooted at its session leader.
    let whole = ev_end(long_chain(None), ChainEnd::Top, true, &[]);
    assert!(!whole.cut());
    assert_eq!(whole.kind(), SubjectKind::Terminal);
    assert!(!whole.agent_involved());
    let leader = whole.session_leader().unwrap().clone();
    assert_eq!(leader.pid, 950);
    assert!(whole.covered_by(&leader, SubjectKind::Terminal));

    // Cut, an agent may be above the cut: unknown, its proofs refused, and
    // no terminal grant covers it wherever it is rooted.
    for claims in [&[][..], &["CLAUDECODE"][..]] {
        let cut = ev_end(long_chain(None), ChainEnd::Cut, true, claims);
        assert!(cut.cut());
        assert!(cut.nearest_agent().is_none());
        assert_eq!(cut.kind(), SubjectKind::Unknown, "{claims:?}");
        assert!(cut.agent_involved(), "{claims:?}");
        assert_eq!(cut.chain(), whole.chain());
        assert!(cut.root().same(&whole.root()));
        for a in cut.chain() {
            assert!(!cut.covered_by(&a.instance, SubjectKind::Terminal));
        }
        // A grant approved for what it is still covers it.
        assert!(cut.covered_by(&cut.root(), SubjectKind::Unknown));
    }
    let cut = ev_end(long_chain(None), ChainEnd::Cut, true, &[]);
    assert!(cut.label().is_none(), "no agent to show");

    // A known agent below the cut is found as in a whole chain.
    let cut = ev_end(long_chain(Some(10)), ChainEnd::Cut, true, &[]);
    assert_eq!(cut.kind(), SubjectKind::Agent);
    assert_eq!(cut.root_index(), 10);
    assert_eq!(cut.label().unwrap().id, "codex");
    assert!(cut.agent_involved());
    assert!(
        !cut.covered_by(&leader, SubjectKind::Agent),
        "the agent barrier"
    );
}

/// A process table a test scripts: each pid's answers in order, the last
/// one repeated; argument reads are recorded.
#[derive(Default)]
struct Table {
    answers: HashMap<i32, Vec<ProcInfo>>,
    reads: HashMap<i32, usize>,
    argv: HashMap<i32, Vec<&'static str>>,
    argv_reads: Vec<i32>,
}

fn info(pid: i32, ppid: i32, sid: i32, uid: u32, exe: Option<&str>) -> ProcInfo {
    ProcInfo {
        pid,
        ppid,
        start_time: StartTime::from_raw(10 * u64::try_from(pid).unwrap()),
        uid,
        sid: Some(sid),
        controlling_tty: true,
        comm: OsString::from(exe.and_then(|e| e.rsplit('/').next()).unwrap_or("hidden")),
        exe: exe.map(|e| ExeIdentity {
            path: PathBuf::from(e),
            file: None,
            signature: None,
        }),
        argv: None,
    }
}

impl Table {
    fn add(mut self, answers: Vec<ProcInfo>) -> Self {
        self.answers.insert(answers[0].pid, answers);
        self
    }

    fn with_argv(mut self, pid: i32, argv: Vec<&'static str>) -> Self {
        self.argv.insert(pid, argv);
        self
    }
}

impl ProcessTable for Table {
    fn info(&mut self, pid: i32) -> io::Result<ProcInfo> {
        let n = self.reads.entry(pid).or_default();
        let answers = self.answers.get(&pid).ok_or(io::ErrorKind::NotFound)?;
        let a = answers[(*n).min(answers.len() - 1)].clone();
        *n += 1;
        Ok(a)
    }

    fn argv(&mut self, pid: i32) -> io::Result<Vec<OsString>> {
        self.argv_reads.push(pid);
        let a = self.argv.get(&pid).ok_or(io::ErrorKind::PermissionDenied)?;
        Ok(a.iter().map(OsString::from).collect())
    }
}

fn peer(pid: i32) -> PeerIdentity {
    PeerIdentity {
        uid: 501,
        pid,
        start_time: StartTime::from_raw(10 * u64::try_from(pid).unwrap()),
        pidversion: Some(3),
        source: PeerSource::AuditToken,
    }
}

/// envcloak (90, exe hidden) <- node running Claude Code's cli.js (80) <-
/// zsh (70, session leader) <- a root-owned `claude` (60) <- launchd.
fn table() -> Table {
    Table::default()
        .add(vec![info(90, 80, 70, 501, None)])
        .add(vec![info(80, 70, 70, 501, Some("/usr/bin/node"))])
        .add(vec![info(70, 60, 70, 501, Some("/bin/zsh"))])
        .add(vec![info(60, 1, 60, 0, Some("/usr/local/bin/claude"))])
        .add(vec![info(1, 0, 1, 0, Some("/sbin/launchd"))])
        .with_argv(90, vec!["envcloak", "run", "--", "npm", "test"])
        .with_argv(
            80,
            vec![
                "node",
                "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js",
            ],
        )
}

#[test]
fn gather_classifies_the_callers_processes_from_what_it_reads() {
    let cat = AgentCatalog::builtin();
    let mut t = table();
    let e = gather_in(&mut t, &peer(90), Claims::none(), &cat).unwrap();
    let pids: Vec<i32> = e.chain().iter().map(|a| a.instance.pid).collect();
    assert_eq!(pids, [90, 80, 70, 60, 1]);
    // Arguments were read for the hidden executable and the interpreter
    // only: not for zsh, nor for processes of another user.
    t.argv_reads.sort_unstable();
    assert_eq!(t.argv_reads, [80, 90]);
    assert_eq!(e.nearest_agent().unwrap().0, 1);
    assert_eq!(e.label().unwrap().id, "claude-code");
    // Another user's `claude` is not an agent.
    assert!(e.chain()[3].agent.is_none());
    assert_eq!(e.root().pid, 80);
    assert_eq!(e.kind(), SubjectKind::Agent);
    // The peer's pid version is kept for it alone.
    assert_eq!(e.caller().pidversion, Some(3));
    assert!(
        e.chain()[1..]
            .iter()
            .all(|a| a.instance.pidversion.is_none())
    );
    // No argument is kept.
    let shown = format!("{e:?}");
    assert!(
        !shown.contains("npm") && !shown.contains("cli.js"),
        "{shown}"
    );
}

/// A caller (2000, the CLI) under `shells` nested shells (pids 1999
/// down), under the native Claude Code, under zsh (100, the session
/// leader), under launchd.
fn nested_under_claude(shells: i32) -> Table {
    let top = 2000 - shells - 1;
    let mut t = Table::default()
        .add(vec![info(
            2000,
            1999,
            100,
            501,
            Some("/usr/local/bin/envcloak"),
        )])
        .add(vec![info(
            top,
            100,
            100,
            501,
            Some("/Users/u/.local/share/claude/versions/2.1.0"),
        )])
        .add(vec![info(100, 1, 100, 501, Some("/bin/zsh"))])
        .add(vec![info(1, 0, 1, 0, Some("/sbin/launchd"))]);
    for pid in top + 1..2000 {
        t = t.add(vec![info(pid, pid - 1, 100, 501, Some("/bin/sh"))]);
    }
    t
}

#[test]
fn an_agent_above_the_cut_is_not_forgotten() {
    let cat = AgentCatalog::builtin();
    // Shallow: the chain reaches launchd, and Claude Code is the root.
    let mut t = nested_under_claude(3);
    let e = gather_in(&mut t, &peer(2000), Claims::none(), &cat).unwrap();
    assert!(!e.cut());
    assert_eq!(e.chain().len(), 7);
    assert_eq!(e.label().unwrap().id, "claude-code");
    assert_eq!(e.kind(), SubjectKind::Agent);
    // 72 shells deep, with no markers: Claude Code is past the cut. The
    // caller is not a terminal subject, and its proofs are refused.
    let mut t = nested_under_claude(72);
    let e = gather_in(&mut t, &peer(2000), Claims::none(), &cat).unwrap();
    assert!(e.cut());
    assert_eq!(e.chain().len(), MAX_ANCESTRY);
    assert!(e.nearest_agent().is_none());
    assert!(e.session_leader().is_none());
    assert_eq!(e.kind(), SubjectKind::Unknown);
    assert!(e.agent_involved());
    for a in e.chain() {
        assert!(!e.covered_by(&a.instance, SubjectKind::Terminal));
    }
    // A chain of exactly MAX_ANCESTRY processes that ends at launchd is
    // whole.
    let mut t = nested_under_claude(i32::try_from(MAX_ANCESTRY).unwrap() - 4);
    let e = gather_in(&mut t, &peer(2000), Claims::none(), &cat).unwrap();
    assert!(!e.cut(), "{}", e.chain().len());
    assert_eq!(e.label().unwrap().id, "claude-code");
}

/// The builtin catalog plus one extension file holding `text`, in a
/// private `agents.d`.
fn catalog_with(text: &str) -> (tempfile::TempDir, AgentCatalog) {
    let root = tempfile::Builder::new()
        .prefix("ece")
        .tempdir_in("/tmp")
        .unwrap();
    let dir = root.path().join(AGENTS_DIR);
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let file = dir.join("x.toml");
    std::fs::write(&file, text).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let cat = AgentCatalog::load(root.path());
    assert!(cat.problems().is_empty(), "{:?}", cat.problems());
    (root, cat)
}

/// Review finding F-36: an ancestor above the caller's session (200, a
/// `review-holder` whose arguments name an agent) is read and classified
/// because an extension calls `review-holder` an interpreter. It is an
/// extension match, so it roots no grant above the caller's session, and
/// a grant rooted at it covers no caller in a sibling session.
///
/// envcloak (320) <- zsh (300, a session leader) <- review-holder (200) <-
/// launchd, and beside it envcloak (330) <- zsh (310, another session
/// leader) <- review-holder (200).
#[test]
fn an_extension_interpreter_does_not_widen_the_root() {
    let (_dir, ext) = catalog_with("interpreters = [\"review-holder\"]\n");
    let builtin = AgentCatalog::builtin();
    for argv in [
        vec!["codex", "serve"],
        vec!["node", "/opt/x/@anthropic-ai/claude-code/cli.js"],
    ] {
        let table = || {
            Table::default()
                .add(vec![info(
                    320,
                    300,
                    300,
                    501,
                    Some("/usr/local/bin/envcloak"),
                )])
                .add(vec![info(300, 200, 300, 501, Some("/bin/zsh"))])
                .add(vec![info(
                    330,
                    310,
                    310,
                    501,
                    Some("/usr/local/bin/envcloak"),
                )])
                .add(vec![info(310, 200, 310, 501, Some("/bin/zsh"))])
                .add(vec![info(
                    200,
                    1,
                    200,
                    501,
                    Some("/opt/tools/review-holder"),
                )])
                .add(vec![info(1, 0, 1, 0, Some("/sbin/launchd"))])
                .with_argv(200, argv.clone())
        };
        // Without the extension its arguments are not read.
        let mut t = table();
        let e = gather_in(&mut t, &peer(320), Claims::none(), &builtin).unwrap();
        assert!(t.argv_reads.is_empty());
        assert!(e.nearest_agent().is_none());
        assert_eq!(e.root().pid, 300);

        // With it they are, and the match is an extension's.
        let mut t = table();
        let e = gather_in(&mut t, &peer(320), Claims::none(), &ext).unwrap();
        assert_eq!(t.argv_reads, [200], "{argv:?}");
        let (n, l) = e.nearest_agent().unwrap();
        assert_eq!((n, l.source), (2, CatalogSource::Extension), "{argv:?}");
        assert_eq!(e.kind(), SubjectKind::Agent);
        assert_eq!(e.root().pid, 300, "{argv:?}");
        let holder = e.chain()[2].instance.clone();
        assert!(!e.covered_by(&holder, SubjectKind::Agent));

        // A caller in the sibling session is not covered by a grant rooted
        // at 200 either.
        let mut t = table();
        let sibling = gather_in(&mut t, &peer(330), Claims::none(), &ext).unwrap();
        assert_eq!(sibling.root().pid, 310);
        for kind in [
            SubjectKind::Agent,
            SubjectKind::Unknown,
            SubjectKind::Terminal,
        ] {
            assert!(!sibling.covered_by(&holder, kind), "{argv:?} {kind:?}");
        }
    }
}

#[test]
fn gather_labels_claims_with_the_catalog() {
    let cat = AgentCatalog::builtin();
    let mut t = Table::default()
        .add(vec![info(90, 70, 70, 501, Some("/usr/local/bin/envcloak"))])
        .add(vec![info(70, 1, 70, 501, Some("/bin/zsh"))])
        .add(vec![info(1, 0, 1, 0, Some("/sbin/launchd"))]);
    let claims = Claims::from_markers(["CODEX_THREAD_ID"]).unwrap();
    let e = gather_in(&mut t, &peer(90), claims, &cat).unwrap();
    assert_eq!(e.kind(), SubjectKind::Agent);
    assert!(e.nearest_agent().is_none());
    assert_eq!(e.label().unwrap().id, "codex");
    assert_eq!(e.root().pid, 70);
}

#[test]
fn gather_walks_again_when_the_ancestry_changed() {
    let cat = AgentCatalog::builtin();
    // zsh (70) looks different on its second read only: the first walk
    // fails its re-validation, the second is steady.
    let mut t = table().add(vec![
        info(70, 60, 70, 501, Some("/bin/zsh")),
        {
            let mut changed = info(70, 60, 70, 501, Some("/bin/zsh"));
            changed.start_time = StartTime::from_raw(1);
            changed
        },
        info(70, 60, 70, 501, Some("/bin/zsh")),
    ]);
    let e = gather_in(&mut t, &peer(90), Claims::none(), &cat).unwrap();
    assert_eq!(e.root().pid, 80);
    assert_eq!(t.reads[&90], 4, "two walks, each reading the peer twice");
}

#[test]
fn an_ancestry_that_keeps_changing_is_refused() {
    let cat = AgentCatalog::builtin();
    // Every read of zsh shows another start time, each still older than
    // its child's, so every walk passes and every re-validation fails.
    let mut t = table().add(
        (0..20)
            .map(|i| {
                let mut z = info(70, 60, 70, 501, Some("/bin/zsh"));
                z.start_time = StartTime::from_raw(700 - i);
                z
            })
            .collect(),
    );
    let err = gather_in(&mut t, &peer(90), Claims::none(), &cat).unwrap_err();
    assert_eq!(err, EvidenceError::Changed);
    assert_eq!(err.token(), "ancestry_changed");
    assert_eq!(t.reads[&90], 2 * GATHER_ATTEMPTS);
}

#[test]
fn a_caller_that_is_gone_is_refused_at_once() {
    let cat = AgentCatalog::builtin();
    let mut t = table();
    let mut wrong = peer(90);
    wrong.start_time = StartTime::from_raw(5);
    let err = gather_in(&mut t, &wrong, Claims::none(), &cat).unwrap_err();
    assert_eq!(err, EvidenceError::CallerGone);
    assert_eq!(t.reads[&90], 1);
    let mut t = table();
    assert_eq!(
        gather_in(&mut t, &peer(91), Claims::none(), &cat).unwrap_err(),
        EvidenceError::CallerGone
    );
}
