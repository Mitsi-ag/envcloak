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
    ExeHasher, GATHER_ATTEMPTS, MatchBasis, ProcessInstance, ProofRefusal, SubjectEvidence,
    SubjectKind, gather_in, gather_in_hashed,
};
use envcloak_sys::{
    Argv, CodeSignature, ExeIdentity, MAX_ANCESTRY, PeerIdentity, PeerSource, ProcInfo,
    ProcessTable, StartTime,
};

fn inst(pid: i32, start: u64) -> ProcessInstance {
    ProcessInstance {
        pid,
        start_time: StartTime::from_raw(start),
        pidversion: None,
        exe: None,
    }
}

fn label(id: &str, source: CatalogSource, basis: MatchBasis) -> AgentLabel {
    AgentLabel {
        id: id.to_owned(),
        name: id.to_owned(),
        product: id.to_owned(),
        source,
        basis,
    }
}

/// A process: pid, start time (the pid times 10, so parents are older),
/// session, and an agent label.
fn p(pid: i32, sid: i32, agent: Option<AgentLabel>) -> Ancestor {
    Ancestor {
        instance: inst(pid, 10 * u64::try_from(pid).unwrap()),
        sid: Some(sid),
        terminal: None,
        agent,
    }
}

/// A builtin entry matched the executable.
fn builtin(id: &str) -> Option<AgentLabel> {
    Some(label(id, CatalogSource::Builtin, MatchBasis::Executable))
}

/// A builtin entry matched what the process says about itself.
fn asserted(id: &str) -> Option<AgentLabel> {
    Some(label(id, CatalogSource::Builtin, MatchBasis::Asserted))
}

fn extension(id: &str) -> Option<AgentLabel> {
    Some(label(id, CatalogSource::Extension, MatchBasis::Executable))
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

/// `a` on the terminal `tty`.
fn on(tty: u64, a: Ancestor) -> Ancestor {
    Ancestor {
        terminal: Some(tty),
        ..a
    }
}

/// An agent's command, as Claude Code runs one: envcloak (95) <- sh (90,
/// leading a session of its own without a terminal) <- the agent (80, in
/// the person's terminal session 70 on terminal 7) <- zsh (70) <- login
/// (60) <- Terminal (50) <- launchd.
fn agent_command_chain() -> Vec<Ancestor> {
    vec![
        p(95, 90, None),
        p(90, 90, None),
        on(7, p(80, 70, builtin("claude-code"))),
        on(7, p(70, 70, None)),
        p(60, 60, None),
        p(50, 1, None),
        p(1, 1, None),
    ]
}

/// A person's command on terminal `tty` in session `sid`: envcloak
/// (`pid`) <- zsh (`sid`, the leader) <- login (60) <- Terminal (50) <-
/// launchd.
fn person_on(pid: i32, sid: i32, tty: u64) -> SubjectEvidence {
    ev(
        vec![
            on(tty, p(pid, sid, None)),
            on(tty, p(sid, sid, None)),
            p(60, 60, None),
            p(50, 1, None),
            p(1, 1, None),
        ],
        true,
        &[],
    )
}

/// Review T9 open 3 (gate 23: approval input is never read from the
/// requester's terminal): an approver that shares a session or a
/// terminal with an agent's or an unknown requester's chain, up to its
/// root, is refused `requester_terminal`, though it is a terminal subject
/// that may give other proofs; one on another terminal is not, and a
/// person approves their own terminal's request.
#[test]
fn an_approval_from_the_requesters_terminal_is_refused() {
    let running = |_: &ProcessInstance| true;
    let agent = ev(agent_command_chain(), false, &[]);
    assert_eq!(agent.kind(), SubjectKind::Agent);
    assert_eq!(agent.root().pid, 80);

    // A shell the agent left in its session, or the person's own shell
    // there once the agent is in the background: the agent's session and
    // terminal.
    let same = person_on(75, 70, 7);
    assert_eq!(same.proof_refusal(), None);
    assert!(same.shares_terminal_with(&agent, &running));
    assert_eq!(
        same.approval_refusal(&agent, &running),
        Some(ProofRefusal::RequesterTerminal)
    );
    assert_eq!(
        ProofRefusal::RequesterTerminal.token(),
        "requester_terminal"
    );
    // Another session that made the agent's terminal its own.
    let stolen = person_on(85, 84, 7);
    assert_eq!(
        stolen.approval_refusal(&agent, &running),
        Some(ProofRefusal::RequesterTerminal)
    );
    // The session the agent ran the command in.
    let command_session = person_on(99, 90, 8);
    assert_eq!(
        command_session.approval_refusal(&agent, &running),
        Some(ProofRefusal::RequesterTerminal)
    );
    // Another terminal window: its own session and terminal.
    let other = person_on(35, 30, 9);
    assert!(!other.shares_terminal_with(&agent, &running));
    assert_eq!(other.approval_refusal(&agent, &running), None);
    // Only the chain up to the root counts: session 60 (login) is above
    // the agent.
    let above = person_on(65, 60, 9);
    assert_eq!(above.approval_refusal(&agent, &running), None);

    // An unknown requester (a job a service manager started) is compared
    // the same way.
    let job = ev(vec![p(97, 97, None), p(1, 1, None)], false, &[]);
    assert_eq!(job.kind(), SubjectKind::Unknown);
    assert_eq!(
        person_on(98, 97, 9).approval_refusal(&job, &running),
        Some(ProofRefusal::RequesterTerminal)
    );
    assert_eq!(other.approval_refusal(&job, &running), None);

    // A person's own request, from their terminal, is theirs to approve
    // there.
    let mine = person_on(76, 70, 7);
    assert_eq!(mine.kind(), SubjectKind::Terminal);
    assert!(same.shares_terminal_with(&mine, &running));
    assert_eq!(same.approval_refusal(&mine, &running), None);

    // Only processes still running count: once the agent (80) and the
    // command's session (90, 95) are gone, their session ids and the
    // terminal's device can belong to a person's new terminal window.
    let gone = |i: &ProcessInstance| ![80, 90, 95].contains(&i.pid);
    assert_eq!(same.approval_refusal(&agent, &gone), None);
    assert_eq!(stolen.approval_refusal(&agent, &gone), None);
    let agent_left = |i: &ProcessInstance| ![90, 95].contains(&i.pid);
    assert_eq!(
        stolen.approval_refusal(&agent, &agent_left),
        Some(ProofRefusal::RequesterTerminal)
    );

    // Every other refusal comes first.
    let claimed = ev(
        vec![
            on(9, p(35, 30, None)),
            on(9, p(30, 30, None)),
            p(1, 1, None),
        ],
        true,
        &["CLAUDECODE"],
    );
    assert_eq!(
        claimed.approval_refusal(&agent, &running),
        Some(ProofRefusal::Agent)
    );
}

/// Review F-70: the approval refusal reaches the requester's nearest
/// agent even where that agent may not be the grant's root. An agent
/// known only by what it says about itself, or through a user extension,
/// roots its command's grant at the command's own session (so the grant
/// never widens), yet it runs on the person's terminal all the same: a
/// sibling shell on that terminal is refused, as for a builtin agent
/// known by its executable. The four ways an agent is known, on one
/// chain: the agent (80) on terminal 7 in session 70, its command in a
/// session of its own (90) without a terminal.
#[test]
fn an_approval_from_the_terminal_of_an_agent_that_is_not_the_root_is_refused() {
    let running = |_: &ProcessInstance| true;
    for (agent_label, root) in [
        (builtin("claude-code"), 80),
        (asserted("claude-code"), 90),
        (extension("my-agent"), 90),
        (
            Some(label(
                "my-agent",
                CatalogSource::Extension,
                MatchBasis::Asserted,
            )),
            90,
        ),
    ] {
        let mut chain = agent_command_chain();
        chain[2].agent = agent_label.clone();
        let agent = ev(chain, false, &[]);
        let what = format!("{agent_label:?}");
        assert_eq!(agent.kind(), SubjectKind::Agent, "{what}");
        // The grant's root is as before: the agent only for a builtin
        // match on its executable, else the command's session, and a
        // grant rooted at the agent covers the command only then.
        assert_eq!(agent.root().pid, root, "{what}");
        assert_eq!(
            agent.covered_by(&inst(80, 800), SubjectKind::Agent),
            root == 80,
            "{what}"
        );

        // A shell on the agent's terminal, in its session or in one that
        // took the terminal: refused.
        for approver in [person_on(75, 70, 7), person_on(85, 84, 7)] {
            assert_eq!(approver.proof_refusal(), None, "{what}");
            assert_eq!(
                approver.approval_refusal(&agent, &running),
                Some(ProofRefusal::RequesterTerminal),
                "{what}"
            );
        }
        // The command's own session: refused.
        assert_eq!(
            person_on(99, 90, 8).approval_refusal(&agent, &running),
            Some(ProofRefusal::RequesterTerminal),
            "{what}"
        );
        // Another terminal window, and a session above the agent (login's,
        // 60): allowed.
        assert_eq!(
            person_on(35, 30, 9).approval_refusal(&agent, &running),
            None,
            "{what}"
        );
        assert_eq!(
            person_on(65, 60, 9).approval_refusal(&agent, &running),
            None,
            "{what}"
        );
        // Once the agent has exited, its terminal's device can be a
        // person's new window.
        let agent_gone = |i: &ProcessInstance| i.pid != 80;
        assert_eq!(
            person_on(85, 84, 7).approval_refusal(&agent, &agent_gone),
            None,
            "{what}"
        );
    }
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

    // No controlling terminal (setsid, a service): unknown, same root. Its
    // ancestry reaches its session leader: not an orphan.
    let e = ev(terminal_chain(None), false, &[]);
    assert_eq!(e.kind(), SubjectKind::Unknown);
    assert_eq!(e.root().pid, 70);
    assert!(!e.orphaned());
    assert!(!e.agent_involved());
}

/// SPEC §10b: a proof is taken only from a terminal subject. Every other
/// caller is refused, with the first reason that applies: an agent by any
/// evidence, a cut chain, a lost ancestry, or no terminal session.
#[test]
fn only_a_terminal_subject_gives_a_proof() {
    let e = ev(terminal_chain(None), true, &[]);
    assert_eq!(e.kind(), SubjectKind::Terminal);
    assert_eq!(e.proof_refusal(), None);

    let cases: Vec<(&str, SubjectEvidence, ProofRefusal)> = vec![
        (
            "an agent in the ancestry",
            ev(terminal_chain(builtin("claude-code")), true, &[]),
            ProofRefusal::Agent,
        ),
        (
            "an agent's marker",
            ev(terminal_chain(None), true, &["CLAUDECODE"]),
            ProofRefusal::Agent,
        ),
        (
            "a chain cut at the depth limit",
            ev_end(terminal_chain(None), ChainEnd::Cut, true, &[]),
            ProofRefusal::ChainCut,
        ),
        (
            "an orphan on its old terminal",
            ev(vec![p(95, 70, None), p(1, 1, None)], true, &[]),
            ProofRefusal::Orphaned,
        ),
        // A session without a terminal, whose leader is alive in the
        // chain: `setsid` without the parent exiting.
        (
            "setsid under a terminal",
            ev(
                vec![
                    p(95, 95, None),
                    p(90, 70, None),
                    p(70, 70, None),
                    p(1, 1, None),
                ],
                false,
                &[],
            ),
            ProofRefusal::NoTerminal,
        ),
        // A job `systemd-run --user` started: it leads its own session, a
        // child of the user's service manager.
        (
            "a systemd --user job",
            ev(
                vec![p(95, 95, None), p(40, 40, None), p(1, 1, None)],
                false,
                &[],
            ),
            ProofRefusal::NoTerminal,
        ),
        // A `launchctl submit` job, or a GUI app's helper, in pid 1's
        // session.
        (
            "a launchd job",
            ev(vec![p(95, 1, None), p(1, 1, None)], false, &[]),
            ProofRefusal::NoTerminal,
        ),
    ];
    for (what, e, want) in cases {
        assert_ne!(e.kind(), SubjectKind::Terminal, "{what}");
        assert_eq!(e.proof_refusal(), Some(want), "{what}");
    }
    // The service-manager jobs and `setsid` show no agent and are no
    // orphans: the refusal comes from the missing terminal alone.
    let job = ev(
        vec![p(95, 95, None), p(40, 40, None), p(1, 1, None)],
        false,
        &[],
    );
    assert!(!job.agent_involved());
    assert!(!job.orphaned());
    for r in [
        ProofRefusal::Agent,
        ProofRefusal::ChainCut,
        ProofRefusal::Orphaned,
        ProofRefusal::NoTerminal,
    ] {
        assert!(!r.token().is_empty());
    }
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
        // Whatever ran it is no longer seen: its proofs are refused, as
        // they were inside the agent's tree it may have left (SPEC §10b).
        assert!(e.orphaned(), "{claims:?}");
        assert!(e.agent_involved(), "{claims:?}");
    }
    // Without a terminal, or reparented to a subreaper, all the same.
    for chain in [
        vec![p(95, 70, None), p(1, 1, None)],
        vec![p(95, 70, None), p(40, 40, None), p(1, 1, None)],
    ] {
        let e = ev(chain, false, &[]);
        assert!(e.orphaned());
        assert!(e.agent_involved());
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
    assert!(e.orphaned());
    assert!(e.agent_involved());
    // The session is unknown: fail closed.
    let e = SubjectEvidence::from_chain(
        vec![
            Ancestor {
                sid: None,
                ..p(95, 70, None)
            },
            p(1, 1, None),
        ],
        ChainEnd::Top,
        false,
        Claims::none(),
        None,
    )
    .unwrap();
    assert!(e.orphaned());
    assert!(e.agent_involved());
}

#[test]
fn pid_1_is_never_a_root() {
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
    // It has lost nothing: pid 1 leads that session and is in the chain.
    assert!(!e.orphaned());
    assert!(!e.agent_involved());
    // With a terminal, pid 1's session is a container's whose init is a
    // shell; a process there may have been reparented to it.
    let e = ev(vec![p(90, 1, None), p(1, 1, None)], true, &[]);
    assert!(e.orphaned());
    assert!(e.agent_involved());
}

/// Review T8 open 3: a caller that is pid 1 itself (a container whose
/// pid 1 is the shell or the CLI, with the daemon in the same pid
/// namespace) was taken for its own session leader and root, against the
/// contract (never pid 1), and `covered_by` then refused every grant
/// rooted there: each request opened a pending request no approval could
/// ever end. It has no evidence now, with or without a terminal or an
/// agent label, and the walk refuses it as `caller_is_init`, not as a
/// caller that exited. A child of pid 1 in its session is still rooted at
/// itself.
#[test]
fn a_caller_that_is_pid_1_has_no_evidence() {
    for terminal in [false, true] {
        for agent in [None, builtin("claude-code")] {
            let e = SubjectEvidence::from_chain(
                vec![p(1, 1, agent)],
                ChainEnd::Top,
                terminal,
                Claims::none(),
                None,
            );
            assert!(e.is_none(), "{terminal}");
        }
    }
    let mut t = Table::default().add(vec![info(1, 0, 1, 501, Some("/bin/sh"))]);
    let err = gather_in(&mut t, &peer(1), Claims::none(), &AgentCatalog::builtin()).unwrap_err();
    assert_eq!(err, EvidenceError::CallerIsInit);
    assert_eq!(err.token(), "caller_is_init");
    let e = ev(vec![p(2, 1, None), p(1, 1, None)], false, &[]);
    assert!(e.session_leader().is_none());
    assert_eq!(e.root().pid, 2);
    assert!(e.covered_by(&e.root(), SubjectKind::Unknown));
}

/// A known agent that is pid 1 of the daemon's pid namespace (a container
/// whose entrypoint ends in `exec claude`, with envcloakd started in it) is
/// an agent all the same: the kind, the label, the barrier and refused
/// proofs. Only the root comes from the session rules, as pid 1 is never
/// one.
#[test]
fn an_agent_that_is_pid_1_is_an_agent_but_no_root() {
    let agent_at_1 = |id| p(1, 1, builtin(id));
    // A command the agent runs in a session of its own, without a
    // terminal, under `env -i` (no markers), and in its own tree.
    for chain in [
        vec![p(95, 95, None), agent_at_1("claude-code")],
        vec![p(96, 95, None), p(95, 95, None), agent_at_1("claude-code")],
    ] {
        let e = ev(chain, false, &[]);
        assert_eq!(e.nearest_agent().unwrap().1.id, "claude-code");
        assert_eq!(e.kind(), SubjectKind::Agent);
        assert_eq!(e.label().unwrap().id, "claude-code");
        assert!(e.agent_involved(), "its proofs are refused");
        assert_eq!(e.root().pid, 95, "the session leader, never pid 1");
        assert!(e.covered_by(&e.root(), SubjectKind::Agent));
        for kind in [
            SubjectKind::Agent,
            SubjectKind::Unknown,
            SubjectKind::Terminal,
        ] {
            assert!(!e.covered_by(&inst(1, 10), kind), "{kind:?}");
        }
    }
    // A pseudo-terminal the agent opened (`script`): its session has a
    // terminal, and is still no terminal subject's.
    let e = ev(
        vec![p(97, 96, None), p(96, 96, None), agent_at_1("codex")],
        true,
        &[],
    );
    assert_eq!(e.kind(), SubjectKind::Agent);
    assert!(e.agent_involved());
    assert!(!e.covered_by(&e.root(), SubjectKind::Terminal));
    assert!(e.covered_by(&e.root(), SubjectKind::Agent));
    // An agent below pid 1 is still the nearer one, and the root.
    let e = ev(
        vec![
            p(97, 96, None),
            p(96, 96, builtin("fixture")),
            agent_at_1("codex"),
        ],
        true,
        &[],
    );
    assert_eq!(e.nearest_agent().unwrap().0, 1);
    assert_eq!(e.root().pid, 96);
}

/// The container of the test above, read from a process table: pid 1 of
/// the caller's uid is classified; the host's, which runs as root, never
/// is.
#[test]
fn gather_classifies_pid_1_of_the_callers_uid() {
    let cat = AgentCatalog::builtin();
    for (uid, agent) in [(501, true), (0, false)] {
        let mut t = Table::default()
            .add(vec![info(95, 1, 95, 501, Some("/usr/bin/env"))])
            .add(vec![info(1, 0, 1, uid, Some("/usr/local/bin/claude"))]);
        let e = gather_in(&mut t, &peer(95), Claims::none(), &cat).unwrap();
        assert_eq!(e.chain()[1].agent.is_some(), agent, "uid {uid}");
        assert_eq!(e.root().pid, 95, "uid {uid}");
        if agent {
            assert_eq!(e.label().unwrap().id, "claude-code");
            assert_eq!(e.kind(), SubjectKind::Agent);
            assert!(e.agent_involved());
        } else {
            assert!(e.label().is_none());
            assert_eq!(e.kind(), SubjectKind::Terminal);
        }
    }
}

/// A caller in pid 1's session without a terminal (a GUI app's helper or
/// extension host, a `launchd` job) is rooted at the topmost process below
/// pid 1: the whole app. Such a grant covers the app's callers in that
/// session, never the sessions the app starts: its integrated terminals,
/// or the commands an agent the catalog does not know runs in sessions of
/// their own.
#[test]
fn a_root_in_pid_1s_session_covers_no_other_session() {
    // extension host (90) <- helper (80) <- IDE (50) <- launchd, all in
    // launchd's session.
    let ide = vec![
        p(90, 1, None),
        p(80, 1, None),
        p(50, 1, None),
        p(1, 1, None),
    ];
    let helper = ev(ide.clone(), false, &[]);
    assert_eq!(helper.root().pid, 50);
    assert_eq!(helper.kind(), SubjectKind::Unknown);
    let app = helper.root();
    assert!(helper.covered_by(&app, SubjectKind::Unknown));
    // Another of the app's callers in that session is covered.
    let sibling = ev(
        vec![p(85, 1, None), p(50, 1, None), p(1, 1, None)],
        false,
        &[],
    );
    assert!(sibling.covered_by(&app, SubjectKind::Unknown));
    assert!(sibling.covered_by(&app, SubjectKind::Agent));

    // envcloak (97) <- zsh (96, leading a session on the integrated
    // terminal) <- pty host (60) <- IDE (50) <- launchd.
    let terminal = ev(
        vec![
            p(97, 96, None),
            p(96, 96, None),
            p(60, 1, None),
            p(50, 1, None),
            p(1, 1, None),
        ],
        true,
        &[],
    );
    assert_eq!(terminal.kind(), SubjectKind::Terminal);
    // A command an unknown agent (70) runs in a session of its own.
    let command = ev(
        vec![
            p(98, 98, None),
            p(70, 1, None),
            p(50, 1, None),
            p(1, 1, None),
        ],
        false,
        &[],
    );
    for e in [&terminal, &command] {
        for kind in [
            SubjectKind::Agent,
            SubjectKind::Unknown,
            SubjectKind::Terminal,
        ] {
            assert!(!e.covered_by(&app, kind), "{kind:?}");
            assert!(!e.covered_by(&e.chain()[2].instance, kind), "{kind:?}");
        }
        // Its own grant covers it.
        assert!(e.covered_by(&e.root(), SubjectKind::Unknown));
    }
    // A process above the session outside pid 1's session covers no more
    // (review T8 open 1): `login` (60, a session of its own) over the
    // shell's session.
    let e = ev(terminal_chain(None), true, &[]);
    for kind in [
        SubjectKind::Agent,
        SubjectKind::Unknown,
        SubjectKind::Terminal,
    ] {
        assert!(!e.covered_by(&e.chain()[3].instance, kind), "{kind:?}");
    }
    // So does a builtin agent in pid 1's session, known by its
    // executable: it runs each command in a session of its own.
    let e = ev(
        vec![
            p(98, 98, None),
            p(70, 1, builtin("claude-code")),
            p(1, 1, None),
        ],
        false,
        &[],
    );
    assert_eq!(e.root().pid, 70);
    assert!(e.covered_by(&e.root(), SubjectKind::Agent));
}

/// Review T8 open 1: a root above the caller's session that is no agent
/// was kept from covering sibling sessions only in session 1, where
/// macOS runs GUI apps; on Linux only pid 1 has session 1
/// (systemd gives each unit a session of its own), and a `tmux` server
/// leads a session of its own on both systems. So an IDE's grant, rooted
/// at the desktop shell leading its session, and a `tmux` server's own
/// job's grant covered every terminal below them. Coverage is the same on
/// every system: only a builtin agent known by its executable roots above
/// a session, and any other root covers its own session run.
#[test]
fn a_root_above_the_session_covers_no_other_session_on_any_system() {
    let kinds = [
        SubjectKind::Agent,
        SubjectKind::Unknown,
        SubjectKind::Terminal,
    ];
    // Linux: extension host (90) <- IDE (50) <- gnome-shell (40, leading
    // the desktop session, not pid 1) <- systemd --user (30) <- systemd.
    let helper = ev(
        vec![
            p(90, 40, None),
            p(50, 40, None),
            p(40, 40, None),
            p(30, 30, None),
            p(1, 1, None),
        ],
        false,
        &[],
    );
    assert_eq!(helper.session_leader().unwrap().pid, 40);
    let desktop = helper.root();
    assert_eq!(desktop.pid, 40);
    assert!(helper.covered_by(&desktop, SubjectKind::Unknown));
    // Another of the IDE's processes in that session is covered.
    let sibling = ev(
        vec![
            p(85, 40, None),
            p(50, 40, None),
            p(40, 40, None),
            p(30, 30, None),
            p(1, 1, None),
        ],
        false,
        &[],
    );
    assert!(sibling.covered_by(&desktop, SubjectKind::Unknown));
    // The IDE's integrated terminal: bash (96) leads a session of its own
    // under the pty host (60); and a command an unknown agent (70) in the
    // IDE runs in a session of its own.
    let terminal = ev(
        vec![
            p(97, 96, None),
            p(96, 96, None),
            p(60, 40, None),
            p(50, 40, None),
            p(40, 40, None),
            p(30, 30, None),
            p(1, 1, None),
        ],
        true,
        &[],
    );
    assert_eq!(terminal.kind(), SubjectKind::Terminal);
    let command = ev(
        vec![
            p(98, 98, None),
            p(70, 40, None),
            p(50, 40, None),
            p(40, 40, None),
            p(30, 30, None),
            p(1, 1, None),
        ],
        false,
        &[],
    );
    for e in [&terminal, &command] {
        for kind in kinds {
            assert!(!e.covered_by(&desktop, kind), "{kind:?}");
            for above in &e.chain()[2..e.chain().len() - 1] {
                assert!(!e.covered_by(&above.instance, kind), "{kind:?}");
            }
        }
        assert!(e.covered_by(&e.root(), SubjectKind::Unknown));
    }

    // tmux on either system: a job the server runs itself (`run-shell`,
    // 61, in the server's session without a terminal) is rooted at the
    // server (60, leading its own session); a pane's shell (96) leads a
    // session of its own under it.
    for above_server in [vec![p(1, 1, None)], vec![p(30, 30, None), p(1, 1, None)]] {
        let chain = |caller: Vec<Ancestor>| {
            let mut c = caller;
            c.push(p(60, 60, None));
            c.extend(above_server.iter().cloned());
            c
        };
        let job = ev(chain(vec![p(61, 60, None)]), false, &[]);
        let server = job.root();
        assert_eq!(server.pid, 60);
        assert!(job.covered_by(&server, SubjectKind::Unknown));
        let pane = ev(chain(vec![p(97, 96, None), p(96, 96, None)]), true, &[]);
        assert_eq!(pane.kind(), SubjectKind::Terminal);
        for kind in kinds {
            assert!(!pane.covered_by(&server, kind), "{kind:?}");
        }
        assert!(pane.covered_by(&pane.root(), SubjectKind::Terminal));
    }

    // Ordinary chains are still covered by their own grants. A second
    // command in a Terminal.app shell (macOS), and over ssh: bash (70)
    // leads the session under the connection's sshd (60) and the
    // listener (50).
    let first = ev(terminal_chain(None), true, &[]);
    assert_eq!(first.root().pid, 70);
    let again = ev(
        vec![
            p(95, 70, None),
            p(70, 70, None),
            p(60, 60, None),
            p(50, 1, None),
            p(1, 1, None),
        ],
        true,
        &[],
    );
    assert!(again.covered_by(&first.root(), SubjectKind::Terminal));
    let ssh = |caller: i32| {
        ev(
            vec![
                p(caller, 70, None),
                p(80, 70, None),
                p(70, 70, None),
                p(60, 60, None),
                p(50, 50, None),
                p(1, 1, None),
            ],
            true,
            &[],
        )
    };
    let (a, b) = (ssh(90), ssh(91));
    assert_eq!((a.kind(), a.root().pid), (SubjectKind::Terminal, 70));
    assert!(b.covered_by(&a.root(), SubjectKind::Terminal));
    // A builtin agent known by its executable still roots above the
    // session, in the desktop's session on Linux as in pid 1's on macOS:
    // it runs each command in a session of its own.
    for agent_sid in [40, 1] {
        let run = |caller: i32| {
            ev(
                vec![
                    p(caller, caller, None),
                    p(70, agent_sid, builtin("claude-code")),
                    p(40, 40, None),
                    p(1, 1, None),
                ],
                false,
                &[],
            )
        };
        let (a, b) = (run(98), run(99));
        assert_eq!(a.root().pid, 70);
        assert!(b.covered_by(&a.root(), SubjectKind::Agent), "{agent_sid}");
    }
}

/// Review note: `==` and `Hash` are the per-root key. The executable's
/// path (renamed, or removed on Linux) and whether the pid version is
/// known do not change which process it is.
#[test]
fn a_process_instance_is_keyed_by_pid_and_start_time() {
    use std::collections::HashSet;
    use std::hash::BuildHasher;
    let base = inst(80, 800);
    let exe = |path: &str| {
        Some(ExeIdentity {
            path: PathBuf::from(path),
            file: Some((1, 2)),
            sha256: None,
            signature: None,
        })
    };
    let variants = [
        ProcessInstance {
            exe: exe("/usr/local/bin/claude"),
            ..base.clone()
        },
        ProcessInstance {
            exe: exe("/usr/local/bin/claude (deleted)"),
            ..base.clone()
        },
        ProcessInstance {
            pidversion: Some(3),
            exe: exe("/tmp/renamed"),
            ..base.clone()
        },
    ];
    let hasher = std::collections::hash_map::RandomState::new();
    let mut keys = HashSet::new();
    keys.insert(base.clone());
    for v in &variants {
        assert_eq!(*v, base);
        assert_eq!(hasher.hash_one(v), hasher.hash_one(&base));
        assert!(v.same(&base));
        keys.insert(v.clone());
    }
    assert_eq!(keys.len(), 1);
    // Another start time, or another pid, is another process.
    assert_ne!(inst(80, 801), base);
    assert_ne!(inst(81, 800), base);
    // `same` also tells two known pid versions apart.
    let v7 = ProcessInstance {
        pidversion: Some(7),
        ..base.clone()
    };
    let v8 = ProcessInstance {
        pidversion: Some(8),
        ..base.clone()
    };
    assert_eq!(v7, v8);
    assert!(!v7.same(&v8));
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

/// Review finding F-37: a builtin agent matched only on what it says about
/// itself (`argv[0]`, its script, its command name) is an agent, and a
/// barrier, but no root above the caller's session.
#[test]
fn an_asserted_agent_above_the_session_does_not_widen_the_root() {
    // As in the_nearest_agent_is_the_root, the agent (80) above the
    // caller's own session (90).
    let chain = |agent| {
        vec![
            p(90, 90, None),
            p(80, 70, agent),
            p(70, 70, None),
            p(1, 1, None),
        ]
    };
    let by_exe = ev(chain(builtin("claude-code")), true, &[]);
    assert_eq!(by_exe.root().pid, 80);
    let e = ev(chain(asserted("claude-code")), true, &[]);
    assert_eq!(e.kind(), SubjectKind::Agent);
    assert!(e.agent_involved());
    assert_eq!(e.label().unwrap().id, "claude-code");
    assert_eq!(e.nearest_agent().unwrap().0, 1);
    assert_eq!(e.root().pid, 90, "the caller's session leader");
    assert!(e.covered_by(&e.root(), SubjectKind::Agent));
    for kind in [
        SubjectKind::Agent,
        SubjectKind::Unknown,
        SubjectKind::Terminal,
    ] {
        assert!(!e.covered_by(&e.chain()[1].instance, kind), "{kind:?}");
        // Nor above it: the agent barrier.
        assert!(!e.covered_by(&e.chain()[2].instance, kind), "{kind:?}");
    }

    // Within the caller's session it is the root, as any agent is.
    let e = ev(terminal_chain(asserted("claude-code")), true, &[]);
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

/// The markers the agents' documentation names (M2 plan task M2-10) are
/// claims like `CLAUDECODE`: the CLI finds them in its environment by
/// name, and each makes a terminal subject an agent one, labeled with its
/// agent, its chain and root unchanged, a terminal grant no longer
/// covering it and its proofs refused.
#[test]
fn the_documented_markers_only_tighten() {
    let cat = AgentCatalog::builtin();
    let plain = ev(terminal_chain(None), true, &[]);
    for (marker, id) in [
        ("CLAUDE_CODE_CHILD_SESSION", "claude-code"),
        ("CURSOR_AGENT", "cursor"),
        ("CURSOR_SANDBOX", "cursor"),
        ("GEMINI_CLI", "gemini-cli"),
    ] {
        let found = Claims::from_vars([OsString::from(marker), OsString::from("PATH")], &cat);
        assert_eq!(found.markers(), [marker]);
        let claimed = SubjectEvidence::from_chain(
            terminal_chain(None),
            ChainEnd::Top,
            true,
            found,
            cat.agent_for_marker(marker),
        )
        .unwrap();
        assert_eq!(claimed.kind(), SubjectKind::Agent, "{marker}");
        assert_eq!(claimed.label().unwrap().id, id);
        assert_eq!(claimed.label().unwrap().basis, MatchBasis::Asserted);
        assert_eq!(claimed.chain(), plain.chain());
        assert_eq!(claimed.root(), plain.root());
        assert_eq!(claimed.proof_refusal(), Some(ProofRefusal::Agent));
        assert!(!claimed.covered_by(&plain.root(), SubjectKind::Terminal));
    }
}

/// An agent's command on a pseudo-terminal of its own, in a new session
/// it leads: envcloak (95) <- sh (91, leading session 91 on terminal 9,
/// the pseudo-terminal the agent opened) <- the agent (80, in the person's
/// session 70 on terminal 7) <- zsh (70) <- login (60) <- Terminal (50)
/// <- launchd. Gemini CLI's `node-pty` and Codex's `tty: true` start
/// commands so (M2 plan risk K-03).
fn agent_pty_chain(agent: Option<AgentLabel>) -> Vec<Ancestor> {
    vec![
        on(9, p(95, 91, None)),
        on(9, p(91, 91, None)),
        on(7, p(80, 70, agent)),
        on(7, p(70, 70, None)),
        p(60, 60, None),
        p(50, 1, None),
        p(1, 1, None),
    ]
}

/// Gates 23 and 25 (risk K-03): a command an agent starts on a
/// pseudo-terminal of its own has a controlling terminal and its own
/// session leader, yet it is an agent subject: a grant for that terminal
/// does not cover it, and its proofs are refused, whether the agent is
/// known by its executable (Codex, rooted at it) or only by its script
/// under node (Gemini CLI, rooted in the command's session). The control:
/// the same chain with an agent the catalog does not know is a terminal
/// subject a terminal grant covers and whose proofs are taken.
#[test]
fn a_command_an_agent_starts_on_its_own_pty_is_an_agent() {
    let leader = inst(91, 910);
    for (agent, root) in [
        (builtin("codex"), 80),
        (asserted("gemini-cli"), 91),
        (asserted("qwen-code"), 91),
        (builtin("copilot-cli"), 80),
    ] {
        let e = ev(agent_pty_chain(agent.clone()), true, &[]);
        assert!(e.terminal());
        assert!(e.session_leader().unwrap().same(&leader));
        assert_eq!(e.kind(), SubjectKind::Agent, "{agent:?}");
        assert_eq!(e.root().pid, root, "{agent:?}");
        assert!(!e.covered_by(&leader, SubjectKind::Terminal));
        assert!(!e.covered_by(&e.root(), SubjectKind::Terminal));
        assert_eq!(e.proof_refusal(), Some(ProofRefusal::Agent));
        // And an approval from the person's terminal 7, where the agent
        // runs, is refused for its requests.
        let person = person_on(75, 70, 7);
        assert_eq!(
            person.approval_refusal(&e, &|_| true),
            Some(ProofRefusal::RequesterTerminal)
        );
    }
    let unknown = ev(agent_pty_chain(None), true, &[]);
    assert_eq!(unknown.kind(), SubjectKind::Terminal);
    assert!(unknown.covered_by(&leader, SubjectKind::Terminal));
    assert_eq!(unknown.proof_refusal(), None);
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
                (agent_at == Some(k)).then(|| builtin("codex").unwrap()),
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
        controlling_tty: Some(0x1_0003),
        comm: OsString::from(exe.and_then(|e| e.rsplit('/').next()).unwrap_or("hidden")),
        exe: exe.map(|e| ExeIdentity {
            path: PathBuf::from(e),
            file: None,
            sha256: None,
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

    fn argv(&mut self, pid: i32) -> io::Result<Argv> {
        self.argv_reads.push(pid);
        let a = self.argv.get(&pid).ok_or(io::ErrorKind::PermissionDenied)?;
        Ok(Argv::new(a))
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
    // Known by its script, which it names itself; in the caller's session
    // that still roots the grant.
    assert_eq!(e.label().unwrap().basis, MatchBasis::Asserted);
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

/// The table of the F-37 review probe: envcloak (320) <- zsh (300, a
/// session leader) <- the holder (200) <- launchd, and beside it envcloak
/// (330) <- zsh (310, another session leader) <- the holder.
fn sibling_sessions(holder: ProcInfo, argv: Option<Vec<&'static str>>) -> Table {
    let t = Table::default()
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
        .add(vec![holder])
        .add(vec![info(1, 0, 1, 0, Some("/sbin/launchd"))]);
    match argv {
        Some(a) => t.with_argv(200, a),
        None => t,
    }
}

/// The holder: pid 200, its own session leader, run by launchd, with
/// executable `exe`, command name `comm` and, on macOS, `signature`.
fn holder(exe: Option<&str>, comm: &str, signature: Option<(&str, &str)>) -> ProcInfo {
    let mut h = info(200, 1, 200, 501, exe);
    h.comm = OsString::from(comm);
    if let (Some(e), Some((identifier, team))) = (h.exe.as_mut(), signature) {
        e.signature = Some(CodeSignature {
            identifier: identifier.to_owned(),
            team_id: Some(team.to_owned()),
            cdhash: None,
        });
    }
    h
}

/// Review finding F-37, as its probe found it: with the builtin catalog
/// alone and the holder's executable unchanged, changing only its
/// `argv[0]` (or its script, or its command name) made it Codex or Claude
/// Code, rooted the grant for a caller in one session at it, and so let
/// that grant cover the sibling session. Now such a match labels and
/// tightens only: the root stays the caller's session leader. A match on
/// the executable or signature still roots above the session, as an
/// agent that runs each command in a session of its own needs.
#[test]
fn only_the_executable_roots_a_grant_above_the_session() {
    let cat = AgentCatalog::builtin();
    let asserted_cases: Vec<(&str, ProcInfo, Option<Vec<&'static str>>, &str)> = vec![
        (
            "argv[0]",
            holder(Some("/usr/bin/node"), "node", None),
            Some(vec!["codex"]),
            "codex",
        ),
        (
            "script",
            holder(Some("/usr/bin/node"), "node", None),
            Some(vec!["node", "/opt/x/@anthropic-ai/claude-code/cli.js"]),
            "claude-code",
        ),
        (
            "command name",
            holder(Some("/usr/bin/tmux"), "claude", None),
            None,
            "claude-code",
        ),
        (
            "hidden executable",
            holder(None, "x", None),
            Some(vec!["/opt/vendor/codex"]),
            "codex",
        ),
    ];
    // The control: node as itself is no agent, and roots nothing.
    let mut t = sibling_sessions(
        holder(Some("/usr/bin/node"), "node", None),
        Some(vec!["node"]),
    );
    let e = gather_in(&mut t, &peer(320), Claims::none(), &cat).unwrap();
    assert!(e.nearest_agent().is_none());
    assert_eq!(e.root().pid, 300);

    for (what, h, argv, id) in asserted_cases {
        let mut t = sibling_sessions(h.clone(), argv.clone());
        let e = gather_in(&mut t, &peer(320), Claims::none(), &cat).unwrap();
        let (n, l) = e.nearest_agent().unwrap();
        assert_eq!(
            (n, l.id.as_str(), l.source, l.basis),
            (2, id, CatalogSource::Builtin, MatchBasis::Asserted),
            "{what}"
        );
        assert!(!l.may_root_above_session(), "{what}");
        assert_eq!(e.kind(), SubjectKind::Agent, "{what}");
        assert!(e.agent_involved(), "{what}");
        assert_eq!(e.root().pid, 300, "{what}");
        let root = e.root();
        let held = e.chain()[2].instance.clone();

        let mut t = sibling_sessions(h, argv);
        let sibling = gather_in(&mut t, &peer(330), Claims::none(), &cat).unwrap();
        assert_eq!(sibling.root().pid, 310, "{what}");
        for kind in [
            SubjectKind::Agent,
            SubjectKind::Unknown,
            SubjectKind::Terminal,
        ] {
            assert!(!sibling.covered_by(&root, kind), "{what} {kind:?}");
            assert!(!sibling.covered_by(&held, kind), "{what} {kind:?}");
        }
    }

    // The executable, or the signature: the holder is the agent, and the
    // root of both sessions' grants.
    for (what, h) in [
        (
            "executable",
            holder(
                Some("/Users/u/.local/share/claude/versions/2.1.0"),
                "2.1.0",
                None,
            ),
        ),
        (
            "signature",
            holder(
                Some("/tmp/x/renamed"),
                "renamed",
                Some(("com.anthropic.claude-code", "Q6L2SF6YDW")),
            ),
        ),
    ] {
        let mut t = sibling_sessions(h.clone(), None);
        let e = gather_in(&mut t, &peer(320), Claims::none(), &cat).unwrap();
        let (n, l) = e.nearest_agent().unwrap();
        assert_eq!(
            (n, l.id.as_str(), l.basis),
            (2, "claude-code", MatchBasis::Executable),
            "{what}"
        );
        assert!(l.may_root_above_session());
        assert_eq!(e.root().pid, 200, "{what}");
        let mut t = sibling_sessions(h, None);
        let sibling = gather_in(&mut t, &peer(330), Claims::none(), &cat).unwrap();
        assert_eq!(sibling.root().pid, 200, "{what}");
        assert!(sibling.covered_by(&e.root(), SubjectKind::Agent), "{what}");
        assert!(!sibling.covered_by(&e.root(), SubjectKind::Terminal));
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

/// Linux `/proc` mounted with `hidepid`: the caller's ancestors of
/// another user (here 60, above zsh) are hidden. The request is refused as
/// `ancestry_hidden`, at once, not as a change walked three times.
#[test]
fn a_hidden_ancestor_is_refused_as_hidden() {
    let cat = AgentCatalog::builtin();
    let mut t = Table::default()
        .add(vec![info(90, 70, 70, 501, Some("/usr/local/bin/envcloak"))])
        .add(vec![info(70, 60, 70, 501, Some("/bin/zsh"))]);
    let err = gather_in(&mut t, &peer(90), Claims::none(), &cat).unwrap_err();
    assert_eq!(err, EvidenceError::Hidden);
    assert_eq!(err.token(), "ancestry_hidden");
    assert!(err.to_string().contains("hidepid"), "{err}");
    assert_eq!(t.reads[&90], 1, "one walk");
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

/// A hasher a test scripts: a digest per pid, every pid it is asked for
/// recorded.
#[derive(Default)]
struct Hasher {
    digests: HashMap<i32, [u8; 32]>,
    asked: Vec<i32>,
}

impl ExeHasher for Hasher {
    fn sha256(&mut self, p: &ProcInfo) -> Option<[u8; 32]> {
        self.asked.push(p.pid);
        self.digests.get(&p.pid).copied()
    }
}

/// `p` with its executable's device and inode read, as the Linux walk
/// reads them.
fn with_file(mut p: ProcInfo, file: (u64, u64)) -> ProcInfo {
    p.exe.as_mut().unwrap().file = Some(file);
    p
}

/// [`table`] with each executable's device and inode, as on Linux, and
/// `extra` answers for pid 70 and 80 after the two reads of the walk.
fn linux_table(extra70: Option<ProcInfo>, extra80: Option<ProcInfo>) -> Table {
    let node = with_file(info(80, 70, 70, 501, Some("/usr/bin/node")), (1, 80));
    let zsh = with_file(info(70, 60, 70, 501, Some("/bin/zsh")), (1, 70));
    let answers = |p: ProcInfo, extra: Option<ProcInfo>| {
        let mut v = vec![p.clone(), p];
        v.extend(extra);
        v
    };
    Table::default()
        .add(vec![info(90, 80, 70, 501, None)])
        .add(answers(node, extra80))
        .add(answers(zsh, extra70))
        .add(vec![with_file(
            info(60, 1, 60, 0, Some("/usr/local/bin/claude")),
            (1, 60),
        )])
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

fn digest(e: &SubjectEvidence, pid: i32) -> Option<[u8; 32]> {
    e.chain()
        .iter()
        .find(|a| a.instance.pid == pid)
        .and_then(|a| a.instance.exe.as_ref())
        .and_then(|x| x.sha256)
}

/// SPEC §6.1 step 3: the walk records the SHA-256 of each executable of
/// the caller's uid whose device and inode it read (Linux), nearest the
/// caller first; not the hidden caller's, nor another user's. The
/// classification is the one the walk without hashing gives, and an
/// identity that is not known (a hasher that answers nothing: a budget
/// spent, a file too large) leaves the evidence exactly as that walk's.
#[test]
fn gather_records_executable_digests_and_classifies_alike() {
    let cat = AgentCatalog::builtin();
    let plain = gather_in(
        &mut linux_table(None, None),
        &peer(90),
        Claims::none(),
        &cat,
    )
    .unwrap();
    let mut h = Hasher::default();
    h.digests.insert(80, [8; 32]);
    h.digests.insert(70, [7; 32]);
    h.digests.insert(60, [6; 32]);
    let hashed = gather_in_hashed(
        &mut linux_table(None, None),
        &peer(90),
        Claims::none(),
        &cat,
        &mut h,
    )
    .unwrap();
    assert_eq!(h.asked, [80, 70], "the caller's uid only, nearest first");
    assert_eq!(digest(&hashed, 80), Some([8; 32]));
    assert_eq!(digest(&hashed, 70), Some([7; 32]));
    assert_eq!(digest(&hashed, 60), None, "another user's process");
    assert_eq!(digest(&hashed, 90), None, "a hidden executable");
    assert_eq!(hashed.kind(), plain.kind());
    assert!(hashed.root().same(&plain.root()));
    assert_eq!(hashed.label(), plain.label());
    assert_eq!(hashed.proof_refusal(), plain.proof_refusal());
    for a in plain.chain() {
        for kind in [
            SubjectKind::Agent,
            SubjectKind::Terminal,
            SubjectKind::Unknown,
        ] {
            assert_eq!(
                hashed.covered_by(&a.instance, kind),
                plain.covered_by(&a.instance, kind)
            );
        }
    }
    // Unknown identities: the evidence is the plain walk's, field for
    // field.
    let mut unknown = Hasher::default();
    let none = gather_in_hashed(
        &mut linux_table(None, None),
        &peer(90),
        Claims::none(),
        &cat,
        &mut unknown,
    )
    .unwrap();
    assert_eq!(unknown.asked, [80, 70]);
    assert_eq!(none, plain);
    // Without a device and inode (macOS), nothing is asked.
    let mut mac = Hasher::default();
    gather_in_hashed(&mut table(), &peer(90), Claims::none(), &cat, &mut mac).unwrap();
    assert!(mac.asked.is_empty());
}

/// Start times are read again after hashing: a process that exited (its
/// pid now another process's) or that runs another file since the walk
/// keeps no digest, and the rest of the evidence is unchanged. Mutation
/// checked: skipping the re-read after hashing fails this test.
#[test]
fn a_digest_is_dropped_when_its_process_changed_while_hashing() {
    let cat = AgentCatalog::builtin();
    let mut reused = with_file(info(70, 60, 70, 501, Some("/bin/zsh")), (1, 70));
    reused.start_time = StartTime::from_raw(99_999);
    let execd = with_file(info(80, 70, 70, 501, Some("/usr/bin/node")), (1, 81));
    let mut h = Hasher::default();
    h.digests.insert(80, [8; 32]);
    h.digests.insert(70, [7; 32]);
    let e = gather_in_hashed(
        &mut linux_table(Some(reused), Some(execd)),
        &peer(90),
        Claims::none(),
        &cat,
        &mut h,
    )
    .unwrap();
    assert_eq!(h.asked, [80, 70]);
    assert_eq!(digest(&e, 70), None, "its pid is another process's");
    assert_eq!(digest(&e, 80), None, "it runs another file");
    let plain = gather_in(
        &mut linux_table(None, None),
        &peer(90),
        Claims::none(),
        &cat,
    )
    .unwrap();
    assert_eq!(e, plain);
    // The control: unchanged, both keep their digests.
    let mut h = Hasher::default();
    h.digests.insert(80, [8; 32]);
    h.digests.insert(70, [7; 32]);
    let same70 = with_file(info(70, 60, 70, 501, Some("/bin/zsh")), (1, 70));
    let same80 = with_file(info(80, 70, 70, 501, Some("/usr/bin/node")), (1, 80));
    let e = gather_in_hashed(
        &mut linux_table(Some(same70), Some(same80)),
        &peer(90),
        Claims::none(),
        &cat,
        &mut h,
    )
    .unwrap();
    assert_eq!(
        (digest(&e, 70), digest(&e, 80)),
        (Some([7; 32]), Some([8; 32]))
    );
}
