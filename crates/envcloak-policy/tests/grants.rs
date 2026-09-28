//! The grant store on synthetic chains (SPEC §10a "Bounds", §10b): the
//! store parts of gates 23, 27, 28, 29, 30 and 32, and the attempt
//! limiter. Real processes and the daemon are in
//! `crates/envcloak-daemon/tests/grants.rs` and
//! `crates/envcloak-cli/tests/approve.rs`.
//!
//! Time is a [`Now`] the test moves by hand, so wall-clock and awake-time
//! expiry are tested apart, and the flood windows run without waiting.
#![allow(clippy::unwrap_used)]

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use envcloak_core::vault::{Classification, FieldId, FieldName, ItemId, Slug};
use envcloak_policy::{
    AUTO_DENY, AccessRequest, Ancestor, ApprovalOptions, ApprovalProof, ApproveError,
    AttemptLimiter, BoundBinding, BoundRef, CatalogSource, ChainEnd, Claims, DENIAL_WINDOW,
    Decision, DenyReason, EnvName, GrantId, MAX_AGENT_TTL, MAX_DENIALS, MAX_GRANTS, MAX_PENDING,
    MAX_PENDING_PER_ROOT, MAX_TERMINAL_TTL, MatchBasis, Mode, Now, OptionsError, PENDING_TTL,
    PendingId, ProcessInstance, ProjectIdentity, ProofKind, ProofRefusal, RevokeSelector,
    SubjectEvidence, SubjectKind, Uses, statement_digest,
};
use envcloak_policy::{AgentLabel, GrantStore};
use envcloak_sys::StartTime;

// ------------------------------------------------------------- fixtures

fn inst(pid: i32, start: u64) -> ProcessInstance {
    ProcessInstance {
        pid,
        start_time: StartTime::from_raw(start),
        pidversion: None,
        exe: None,
    }
}

fn label(id: &str) -> AgentLabel {
    AgentLabel {
        id: id.to_owned(),
        name: id.to_owned(),
        source: CatalogSource::Builtin,
        basis: MatchBasis::Executable,
    }
}

/// A process: pid, start time (the pid times 10), session, agent.
fn p(pid: i32, sid: i32, agent: Option<&str>) -> Ancestor {
    Ancestor {
        instance: inst(pid, 10 * u64::try_from(pid).unwrap()),
        sid: Some(sid),
        agent: agent.map(label),
    }
}

fn ev(chain: Vec<Ancestor>, terminal: bool, claims: &[&str]) -> SubjectEvidence {
    SubjectEvidence::from_chain(
        chain,
        ChainEnd::Top,
        terminal,
        Claims::from_markers(claims).unwrap(),
        None,
    )
    .unwrap()
}

/// A terminal session: envcloak (90) <- zsh (70, the session leader) <-
/// login (60) <- Terminal (50, in launchd's session) <- launchd (1).
fn terminal() -> SubjectEvidence {
    ev(
        vec![
            p(90, 70, None),
            p(70, 70, None),
            p(60, 60, None),
            p(50, 1, None),
            p(1, 1, None),
        ],
        true,
        &[],
    )
}

/// The same terminal, with the fixture agent between the shell and the
/// caller: envcloak (92) <- fixture-agent (80) <- zsh (70) <- ...
fn under_agent() -> SubjectEvidence {
    ev(
        vec![
            p(92, 70, None),
            p(80, 70, Some("fixture")),
            p(70, 70, None),
            p(60, 60, None),
            p(50, 1, None),
            p(1, 1, None),
        ],
        false,
        &[],
    )
}

/// A caller under the same agent, in a session of its own (as Claude Code
/// and Codex run their commands).
fn under_agent_own_session(pid: i32) -> SubjectEvidence {
    ev(
        vec![
            p(pid, pid, None),
            p(80, 70, Some("fixture")),
            p(70, 70, None),
            p(60, 60, None),
            p(50, 1, None),
            p(1, 1, None),
        ],
        false,
        &[],
    )
}

fn project(dir: &str, dev: u64, ino: u64) -> ProjectIdentity {
    ProjectIdentity {
        canonical_dir: PathBuf::from(dir),
        dev,
        ino,
        manifest_path: PathBuf::from(dir).join("envcloak.toml"),
    }
}

fn acme() -> ProjectIdentity {
    project("/src/acme-web", 1, 100)
}

struct Item {
    slug: &'static str,
    item: ItemId,
    field: FieldId,
}

fn items() -> Vec<Item> {
    ["openai/acme-web", "stripe/acme-web", "github/acme-web"]
        .into_iter()
        .map(|slug| Item {
            slug,
            item: ItemId::generate(),
            field: FieldId::generate(),
        })
        .collect()
}

fn bound(env: &str, it: &Item) -> BoundRef {
    BoundRef {
        binding: BoundBinding {
            env_name: EnvName::new(env).unwrap(),
            item: it.item,
            field: it.field,
            classification: Classification::Test,
        },
        slug: Slug::new(it.slug).unwrap(),
        field_name: FieldName::new("value").unwrap(),
        first_use: false,
    }
}

fn request(subject: SubjectEvidence, bindings: Vec<BoundRef>, argv: &[&str]) -> AccessRequest {
    AccessRequest {
        subject,
        project: acme(),
        manifest_sha256: [7u8; 32],
        bindings,
        mode: Mode::Inject,
        argv_display: argv.iter().map(|a| (*a).to_owned()).collect(),
        new_project: false,
    }
}

fn now_at(secs: u64) -> Now {
    Now {
        wall: SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000 + secs),
        awake: Duration::from_secs(1000 + secs),
        including_sleep: Duration::from_secs(1000 + secs),
    }
}

fn store() -> GrantStore {
    let mut s = GrantStore::new();
    s.set_epochs(1, 1);
    s
}

fn proof(approver: SubjectEvidence) -> ApprovalProof {
    ApprovalProof {
        approver,
        kind: ProofKind::Passphrase,
    }
}

fn session(secs: u64) -> ApprovalOptions {
    ApprovalOptions {
        uses: Uses::Session,
        ttl_secs: secs,
        live: Vec::new(),
    }
}

fn once() -> ApprovalOptions {
    ApprovalOptions {
        uses: Uses::Once,
        ttl_secs: 3600,
        live: Vec::new(),
    }
}

fn pending_id(d: &Decision) -> PendingId {
    match d {
        Decision::Pending(id) => *id,
        other => panic!("expected a pending request, got {other:?}"),
    }
}

fn covered(d: &Decision) -> GrantId {
    match d {
        Decision::Covered(g) => *g,
        other => panic!("expected a covered request, got {other:?}"),
    }
}

/// Opens a pending request for `r` and approves it as the terminal
/// subject with `opts`, at `now`.
fn approve(
    s: &mut GrantStore,
    r: AccessRequest,
    opts: ApprovalOptions,
    now: &Now,
) -> Result<GrantId, ApproveError> {
    let id = pending_id(&s.decide(r, now));
    let digest = statement_digest(s.pending_descriptor(&id, now).unwrap(), &opts);
    s.approve(&id, proof(terminal()), opts, digest, now)
}

// ------------------------------------------------ approve and its proofs

/// Gate 23's store part: the proof must come from a caller with no agent
/// in its evidence, and the statement must be the pending request's.
#[test]
fn a_proof_from_an_agent_descended_caller_is_refused() {
    let it = items();
    let mut s = store();
    let now = now_at(0);
    let id = pending_id(&s.decide(
        request(
            under_agent(),
            vec![bound("OPENAI_API_KEY", &it[0])],
            &["./emit"],
        ),
        &now,
    ));
    let opts = session(3600);
    let digest = statement_digest(s.pending_descriptor(&id, &now).unwrap(), &opts);

    // The agent itself, a command under it, a shell claiming an agent
    // marker, an orphan and a cut chain: all refused, and the request
    // stays pending.
    let orphan = ev(vec![p(95, 70, None), p(1, 1, None)], true, &[]);
    let cut = SubjectEvidence::from_chain(
        vec![p(90, 70, None), p(70, 70, None)],
        ChainEnd::Cut,
        true,
        Claims::none(),
        None,
    )
    .unwrap();
    let claimed = ev(
        vec![p(90, 70, None), p(70, 70, None), p(1, 1, None)],
        true,
        &["CLAUDECODE"],
    );
    for approver in [
        under_agent(),
        under_agent_own_session(93),
        orphan,
        cut,
        claimed,
    ] {
        assert!(approver.agent_involved());
        assert!(approver.proof_refusal().is_some());
        let e = s
            .approve(&id, proof(approver), opts.clone(), digest, &now)
            .unwrap_err();
        assert_eq!(e, ApproveError::ProofRefused);
        assert!(s.pending_descriptor(&id, &now).is_some());
    }
    // No agent is seen, but there is no terminal session: a job a service
    // manager started in a session of its own (`systemd-run --user`) or in
    // pid 1's (`launchctl submit`), and a command that forked out and
    // called `setsid`. No person could have typed their proof.
    let own_session = ev(vec![p(96, 96, None), p(1, 1, None)], false, &[]);
    let launchd_job = ev(vec![p(97, 1, None), p(1, 1, None)], false, &[]);
    let setsid = ev(
        vec![p(98, 98, None), p(70, 70, None), p(1, 1, None)],
        false,
        &[],
    );
    for approver in [own_session, launchd_job, setsid] {
        assert!(!approver.agent_involved(), "{approver:?}");
        assert_eq!(approver.proof_refusal(), Some(ProofRefusal::NoTerminal));
        let e = s
            .approve(&id, proof(approver), opts.clone(), digest, &now)
            .unwrap_err();
        assert_eq!(e, ApproveError::ProofRefused);
    }
    assert!(s.pending_descriptor(&id, &now).is_some());
    assert_eq!(s.grants().count(), 0);
    assert_eq!(terminal().proof_refusal(), None);

    // A statement that differs from the pending request: another id,
    // other options, or one byte of the digest.
    let mut wrong = digest;
    wrong[0] ^= 1;
    let e = s
        .approve(&id, proof(terminal()), opts.clone(), wrong, &now)
        .unwrap_err();
    assert_eq!(e, ApproveError::StatementMismatch);
    let e = s
        .approve(&id, proof(terminal()), once(), digest, &now)
        .unwrap_err();
    assert_eq!(e, ApproveError::StatementMismatch);
    let other = PendingId::parse("ABCDEFGH").unwrap();
    let e = s
        .approve(&other, proof(terminal()), opts.clone(), digest, &now)
        .unwrap_err();
    assert_eq!(e, ApproveError::NoSuchRequest);
    assert_eq!(s.grants().count(), 0);

    // The right statement from a terminal subject creates the grant.
    let g = s
        .approve(&id, proof(terminal()), opts, digest, &now)
        .unwrap();
    assert!(s.pending_descriptor(&id, &now).is_none());
    let grant = s.grant(g).unwrap();
    assert_eq!(grant.root, inst(80, 800));
    assert_eq!(grant.kind, SubjectKind::Agent);
    assert_eq!(grant.label.as_deref(), Some("fixture"));
    assert_eq!(grant.uses, Uses::Session);
    // Approved once: the request is gone.
    let e = s
        .approve(&id, proof(terminal()), session(3600), digest, &now)
        .unwrap_err();
    assert_eq!(e, ApproveError::NoSuchRequest);
}

#[test]
fn the_pending_request_carries_the_flags_and_expires() {
    let it = items();
    let mut s = store();
    let now = now_at(0);
    let mut b = bound("OPENAI_API_KEY", &it[0]);
    b.first_use = true;
    let mut r = request(
        under_agent(),
        vec![b, bound("STRIPE_SECRET_KEY", &it[1])],
        &["./emit"],
    );
    r.new_project = true;
    let id = pending_id(&s.decide(r, &now));
    let d = s.pending_descriptor(&id, &now).unwrap();
    assert_eq!(d.request, id.to_string());
    assert_eq!(d.request.len(), 8);
    assert_eq!(d.nonce.len(), 64);
    assert!(d.project.new_project);
    assert_eq!(d.project.dir, "/src/acme-web");
    assert_eq!(d.subject.kind, SubjectKind::Agent);
    assert_eq!(d.subject.label.as_deref(), Some("fixture"));
    assert_eq!(d.subject.root.pid, 80);
    assert_eq!(d.subject.caller_pid, 92);
    assert_eq!(d.bindings.len(), 2);
    assert_eq!(d.bindings[0].env_name, "OPENAI_API_KEY");
    assert_eq!(d.bindings[0].slug, "openai/acme-web");
    assert_eq!(d.bindings[0].item, it[0].item.to_string());
    assert!(d.bindings[0].first_use);
    assert!(!d.bindings[1].first_use);
    assert_eq!(d.bindings[1].classification, "test");
    assert_eq!(d.argv, vec!["./emit"]);
    assert_eq!(d.mode, Mode::Inject);
    assert_eq!(d.expires_in_secs, PENDING_TTL.as_secs());

    // A second, identical request while it is pending gets the same id;
    // a different one gets its own.
    let again = s.decide(
        request(
            under_agent(),
            vec![
                bound("OPENAI_API_KEY", &it[0]),
                bound("STRIPE_SECRET_KEY", &it[1]),
            ],
            &["./emit"],
        ),
        &now,
    );
    assert_eq!(pending_id(&again), id);
    let other = s.decide(
        request(
            under_agent(),
            vec![bound("OPENAI_API_KEY", &it[0])],
            &["./emit"],
        ),
        &now,
    );
    assert_ne!(pending_id(&other), id);

    // Pending requests expire after 10 minutes.
    let later = now_at(PENDING_TTL.as_secs());
    assert!(s.pending_descriptor(&id, &later).is_none());
    let e = s
        .approve(&id, proof(terminal()), session(3600), [0u8; 32], &later)
        .unwrap_err();
    assert_eq!(e, ApproveError::NoSuchRequest);
}

#[test]
fn approval_options_are_bounded() {
    let it = items();
    let now = now_at(0);
    let agent_request = || request(under_agent(), vec![bound("OPENAI_API_KEY", &it[0])], &["x"]);
    let terminal_request = || request(terminal(), vec![bound("OPENAI_API_KEY", &it[0])], &["x"]);
    // A job a service manager started: its evidence is missing, so it gets
    // the tighter bound, a terminal's, not an agent's.
    let unknown_request = || {
        let job = ev(vec![p(97, 1, None), p(1, 1, None)], false, &[]);
        assert_eq!(job.kind(), SubjectKind::Unknown);
        request(job, vec![bound("OPENAI_API_KEY", &it[0])], &["x"])
    };
    assert!(MAX_TERMINAL_TTL < MAX_AGENT_TTL);
    for (mk, max) in [
        (&agent_request as &dyn Fn() -> AccessRequest, MAX_AGENT_TTL),
        (&terminal_request, MAX_TERMINAL_TTL),
        (&unknown_request, MAX_TERMINAL_TTL),
    ] {
        let mut s = store();
        let e = approve(&mut s, mk(), session(max.as_secs() + 1), &now).unwrap_err();
        assert_eq!(e, ApproveError::InvalidOptions(OptionsError::TtlTooLong));
        let mut s = store();
        let e = approve(&mut s, mk(), session(0), &now).unwrap_err();
        assert_eq!(e, ApproveError::InvalidOptions(OptionsError::TtlZero));
        let mut s = store();
        let mut o = session(60);
        o.live.push(EnvName::new("NOT_BOUND").unwrap());
        let e = approve(&mut s, mk(), o, &now).unwrap_err();
        assert_eq!(e, ApproveError::InvalidOptions(OptionsError::LiveNotBound));
        let mut s = store();
        let mut o = session(max.as_secs());
        o.live.push(EnvName::new("OPENAI_API_KEY").unwrap());
        let g = approve(&mut s, mk(), o, &now).unwrap();
        assert!(s.grant(g).unwrap().bindings[0].live);
    }
    // The grant store is bounded. Each grant is for another agent
    // instance, so none covers the next request.
    let mut s = store();
    for n in 0..MAX_GRANTS {
        let agent = 1000 + i32::try_from(n).unwrap();
        let chain = vec![
            p(agent + 10_000, 70, None),
            p(agent, 70, Some("fixture")),
            p(70, 70, None),
            p(1, 1, None),
        ];
        let r = request(
            ev(chain, false, &[]),
            vec![bound("OPENAI_API_KEY", &it[0])],
            &["x"],
        );
        let pid = pending_id(&s.decide(r, &now));
        let digest = statement_digest(s.pending_descriptor(&pid, &now).unwrap(), &once());
        s.approve(&pid, proof(terminal()), once(), digest, &now)
            .unwrap();
    }
    let e = approve(&mut s, agent_request(), once(), &now).unwrap_err();
    assert_eq!(e, ApproveError::TooManyGrants);
}

// ------------------------------------------------------------- coverage

/// Gate 27: after the root exits and its pid is reused, the new process
/// is not covered: the start time differs.
#[test]
fn a_recycled_root_pid_is_not_covered() {
    let it = items();
    let mut s = store();
    let now = now_at(0);
    let g = approve(
        &mut s,
        request(
            under_agent(),
            vec![bound("OPENAI_API_KEY", &it[0])],
            &["./emit"],
        ),
        session(3600),
        &now,
    )
    .unwrap();
    assert_eq!(s.grant(g).unwrap().root, inst(80, 800));
    // The same tree, the agent's pid reused by a new process.
    let mut chain = vec![
        p(92, 70, None),
        p(80, 70, Some("fixture")),
        p(70, 70, None),
        p(1, 1, None),
    ];
    chain[1].instance = inst(80, 801);
    let reused = ev(chain, false, &[]);
    let d = s.decide(
        request(reused, vec![bound("OPENAI_API_KEY", &it[0])], &["./emit"]),
        &now,
    );
    assert!(matches!(d, Decision::Pending(_)), "{d:?}");
    // The original instance is still covered.
    let d = s.decide(
        request(
            under_agent(),
            vec![bound("OPENAI_API_KEY", &it[0])],
            &["./emit"],
        ),
        &now,
    );
    assert_eq!(covered(&d), g);
}

/// Gate 28: any added or changed binding prompts; a manifest change that
/// leaves the bindings a subset does not; the project identity decides
/// whether a copy or a move is the same project.
#[test]
fn binding_changes_after_approval_prompt_for_the_difference() {
    let it = items();
    let mut s = store();
    let now = now_at(0);
    let two = || {
        vec![
            bound("OPENAI_API_KEY", &it[0]),
            bound("STRIPE_SECRET_KEY", &it[1]),
        ]
    };
    let g = approve(
        &mut s,
        request(under_agent(), two(), &["./emit"]),
        session(3600),
        &now,
    )
    .unwrap();

    // A subset, another command line, and a comment-only manifest change
    // (another hash, the same bindings) are covered.
    let mut r = request(
        under_agent(),
        vec![bound("OPENAI_API_KEY", &it[0])],
        &["npm", "test"],
    );
    r.manifest_sha256 = [8u8; 32];
    assert_eq!(covered(&s.decide(r, &now)), g);
    // The same command from another process under the same agent, in a
    // session of its own.
    assert_eq!(
        covered(&s.decide(
            request(under_agent_own_session(93), two(), &["./emit"]),
            &now
        )),
        g
    );

    // An added reference, a retargeted variable (the same name, another
    // item), a renamed variable (another name, the same item) and another
    // field of the same item each prompt. Each case gets a store of its
    // own, so the pending cap does not decide.
    let mut three = two();
    three.push(bound("GITHUB_TOKEN", &it[2]));
    let retargeted = vec![
        bound("OPENAI_API_KEY", &it[2]),
        bound("STRIPE_SECRET_KEY", &it[1]),
    ];
    let renamed = vec![
        bound("OPENAI_KEY", &it[0]),
        bound("STRIPE_SECRET_KEY", &it[1]),
    ];
    let mut other_field = two();
    other_field[0].binding.field = FieldId::generate();
    // Each prompts for the difference: the statement marks the bindings
    // the grant already holds, and asks for the rest.
    for (changed, new) in [
        (three, vec!["GITHUB_TOKEN"]),
        (retargeted, vec!["OPENAI_API_KEY"]),
        (renamed, vec!["OPENAI_KEY"]),
        (other_field, vec!["OPENAI_API_KEY"]),
    ] {
        let mut s = store();
        approve(
            &mut s,
            request(under_agent(), two(), &["./emit"]),
            session(3600),
            &now,
        )
        .unwrap();
        let n = changed.len();
        let id = pending_id(&s.decide(request(under_agent(), changed, &["./emit"]), &now));
        let d = s.pending_descriptor(&id, &now).unwrap();
        let asked: Vec<&str> = d
            .bindings
            .iter()
            .filter(|b| !b.granted)
            .map(|b| b.env_name.as_str())
            .collect();
        assert_eq!(asked, new);
        assert!(d.bindings.iter().any(|b| b.granted), "{d:?}");
        // Approved, the new grant holds the whole request.
        let digest = statement_digest(d, &session(600));
        let g2 = s
            .approve(&id, proof(terminal()), session(600), digest, &now)
            .unwrap();
        assert_eq!(s.grant(g2).unwrap().bindings.len(), n);
    }
    // A `once` grant marks nothing: it ends at its next use, so the new
    // grant is what would hold those bindings. The statement asks for all
    // of them.
    let mut once_store = store();
    let once = approve(
        &mut once_store,
        request(under_agent(), two(), &["./emit"]),
        ApprovalOptions {
            uses: Uses::Once,
            ttl_secs: 3600,
            live: Vec::new(),
        },
        &now,
    )
    .unwrap();
    let mut three = two();
    three.push(bound("GITHUB_TOKEN", &it[2]));
    let id =
        pending_id(&once_store.decide(request(under_agent(), three.clone(), &["./emit"]), &now));
    assert!(
        once_store
            .pending_descriptor(&id, &now)
            .unwrap()
            .bindings
            .iter()
            .all(|b| !b.granted)
    );
    // A session grant's bindings are marked; the once grant's still are
    // not.
    approve(
        &mut once_store,
        request(
            under_agent(),
            vec![bound("GITHUB_TOKEN", &it[2])],
            &["./emit"],
        ),
        session(3600),
        &now,
    )
    .unwrap();
    let id = pending_id(&once_store.decide(request(under_agent(), three, &["./emit", "2"]), &now));
    let granted: Vec<&str> = once_store
        .pending_descriptor(&id, &now)
        .unwrap()
        .bindings
        .iter()
        .filter(|b| b.granted)
        .map(|b| b.env_name.as_str())
        .collect();
    assert_eq!(granted, vec!["GITHUB_TOKEN"]);
    assert!(once_store.grant(once).is_some());

    // A grant held by another root, or for another project, marks
    // nothing: another agent's request asks for everything.
    let mut s3 = store();
    approve(
        &mut s3,
        request(under_agent(), two(), &["./emit"]),
        session(3600),
        &now,
    )
    .unwrap();
    let mut elsewhere = request(under_agent(), two(), &["./emit"]);
    elsewhere.project = project("/src/other", 1, 200);
    let id = pending_id(&s3.decide(elsewhere, &now));
    assert!(
        s3.pending_descriptor(&id, &now)
            .unwrap()
            .bindings
            .iter()
            .all(|b| !b.granted)
    );
    // A stricter mode is covered by a looser grant, not the reverse.
    let mut proxy = request(under_agent(), two(), &["./emit"]);
    proxy.mode = Mode::Proxy;
    assert_eq!(covered(&s.decide(proxy, &now)), g);
    let mut s2 = store();
    let mut r = request(under_agent(), two(), &["./emit"]);
    r.mode = Mode::Proxy;
    approve(&mut s2, r, session(3600), &now).unwrap();
    assert!(matches!(
        s2.decide(request(under_agent(), two(), &["./emit"]), &now),
        Decision::Pending(_)
    ));

    // A copy (another inode) and a move (another path, the same inode) are
    // other projects; a symlinked path resolves to the same identity.
    for other in [
        project("/src/acme-web", 1, 101),
        project("/src/acme-web-2", 1, 100),
    ] {
        let mut r = request(under_agent(), two(), &["./emit"]);
        r.project = other;
        assert!(matches!(s.decide(r, &now), Decision::Pending(_)));
    }
    let mut r = request(under_agent(), two(), &["./emit"]);
    r.project = acme();
    assert_eq!(covered(&s.decide(r, &now)), g);
}

#[test]
fn the_agent_barrier_and_kinds_apply_to_grants() {
    let it = items();
    let mut s = store();
    let now = now_at(0);
    // A grant for the terminal: its root is the shell (70).
    let g = approve(
        &mut s,
        request(
            terminal(),
            vec![bound("OPENAI_API_KEY", &it[0])],
            &["./emit"],
        ),
        session(3600),
        &now,
    )
    .unwrap();
    assert_eq!(s.grant(g).unwrap().root, inst(70, 700));
    assert_eq!(s.grant(g).unwrap().kind, SubjectKind::Terminal);
    // The agent under that shell is not covered (gate 25's grant half).
    assert!(matches!(
        s.decide(
            request(
                under_agent(),
                vec![bound("OPENAI_API_KEY", &it[0])],
                &["./emit"]
            ),
            &now
        ),
        Decision::Pending(_)
    ));
    // Nor a process in another session.
    let other = ev(
        vec![p(91, 91, None), p(60, 60, None), p(1, 1, None)],
        true,
        &[],
    );
    assert!(matches!(
        s.decide(
            request(other, vec![bound("OPENAI_API_KEY", &it[0])], &["./emit"]),
            &now
        ),
        Decision::Pending(_)
    ));
    // The shell's own commands are.
    assert_eq!(
        covered(&s.decide(
            request(terminal(), vec![bound("OPENAI_API_KEY", &it[0])], &["ls"]),
            &now
        )),
        g
    );
}

// ------------------------------------------------------ expiry and ends

/// Gate 29: wall-clock and awake-time expiry, tested apart; revocation
/// needs no proof; lock and the root's exit end grants.
#[test]
fn grants_expire_on_either_clock() {
    let it = items();
    let now = now_at(0);
    let r = || {
        request(
            under_agent(),
            vec![bound("OPENAI_API_KEY", &it[0])],
            &["./emit"],
        )
    };

    // The wall clock passes the deadline while awake time does not (the
    // clock was stepped forward).
    let mut s = store();
    let g = approve(&mut s, r(), session(3600), &now).unwrap();
    let mut wall_only = now_at(0);
    wall_only.wall += Duration::from_secs(3599);
    assert_eq!(covered(&s.decide(r(), &wall_only)), g);
    wall_only.wall += Duration::from_secs(1);
    assert!(matches!(s.decide(r(), &wall_only), Decision::Pending(_)));
    assert_eq!(s.grants().count(), 0);

    // Awake time passes the deadline while the wall clock does not (the
    // clock was stepped back).
    let mut s = store();
    let g = approve(&mut s, r(), session(3600), &now).unwrap();
    let mut awake_only = now_at(0);
    awake_only.awake += Duration::from_secs(3599);
    assert_eq!(covered(&s.decide(r(), &awake_only)), g);
    awake_only.awake += Duration::from_secs(1);
    assert!(matches!(s.decide(r(), &awake_only), Decision::Pending(_)));
    assert_eq!(s.grants().count(), 0);
}

#[test]
fn revoke_lock_root_exit_and_epochs_end_grants() {
    let it = items();
    let now = now_at(0);
    let r = |n: u32| {
        request(
            under_agent(),
            vec![bound("OPENAI_API_KEY", &it[0])],
            &[&n.to_string()],
        )
    };
    let t = || {
        request(
            terminal(),
            vec![bound("STRIPE_SECRET_KEY", &it[1])],
            &["./emit"],
        )
    };

    // Revoke by id, then all. No proof is involved.
    let mut s = store();
    let g1 = approve(&mut s, r(1), once(), &now).unwrap();
    let g2 = approve(&mut s, t(), session(60), &now).unwrap();
    assert_eq!(s.grants().count(), 2);
    assert_eq!(s.revoke(RevokeSelector::Id(g1)), 1);
    assert_eq!(s.revoke(RevokeSelector::Id(g1)), 0);
    assert!(s.grant(g1).is_none());
    assert_eq!(covered(&s.decide(t(), &now)), g2);
    assert_eq!(s.revoke(RevokeSelector::All), 1);
    assert!(matches!(s.decide(t(), &now), Decision::Pending(_)));
    assert_eq!(s.revoke(RevokeSelector::All), 0);

    // Lock drops every grant and pending request; the pending request's
    // id is unknown afterwards.
    let mut s = store();
    approve(&mut s, r(1), session(60), &now).unwrap();
    let pending = pending_id(&s.decide(t(), &now));
    s.on_lock();
    assert_eq!(s.grants().count(), 0);
    assert!(s.pending_descriptor(&pending, &now).is_none());
    s.set_epochs(1, 1);
    assert!(matches!(s.decide(r(1), &now), Decision::Pending(_)));

    // The root's exit: the sweep asks whether each root is alive.
    let mut s = store();
    let g1 = approve(&mut s, r(1), session(60), &now).unwrap();
    let g2 = approve(&mut s, t(), session(60), &now).unwrap();
    s.sweep(&now, &|root| root.pid != 80);
    assert!(s.grant(g1).is_none());
    assert!(s.grant(g2).is_some());
    s.sweep(&now, &|_| true);
    assert!(s.grant(g2).is_some());

    // A policy epoch bump (the user tightening policy) ends grants made
    // under the old epoch; a vault epoch change (a new VMK) too.
    let mut s = store();
    approve(&mut s, r(1), session(60), &now).unwrap();
    s.set_policy_epoch(2);
    assert_eq!(s.grants().count(), 0);
    let mut s = store();
    approve(&mut s, r(1), session(60), &now).unwrap();
    s.set_epochs(2, 1);
    assert_eq!(s.grants().count(), 0);

    // An expired grant is gone from the list too.
    let mut s = store();
    approve(&mut s, r(1), session(60), &now).unwrap();
    let later = now_at(60);
    s.sweep(&later, &|_| true);
    assert_eq!(s.grants().count(), 0);
}

/// SPEC §10b "A grant ends on": deleting a bound item ends every grant
/// that binds it, and every pending request that asks for it; grants and
/// requests for other items stay.
#[test]
fn removing_an_item_ends_the_grants_and_requests_that_bind_it() {
    let it = items();
    let now = now_at(0);
    let both = || {
        request(
            terminal(),
            vec![
                bound("OPENAI_API_KEY", &it[0]),
                bound("STRIPE_SECRET_KEY", &it[1]),
            ],
            &["./emit"],
        )
    };
    let stripe = || {
        request(
            under_agent(),
            vec![bound("STRIPE_SECRET_KEY", &it[1])],
            &["./emit"],
        )
    };
    let github = || {
        request(
            under_agent(),
            vec![bound("GITHUB_TOKEN", &it[2])],
            &["./emit"],
        )
    };
    let mut s = store();
    let g_both = approve(&mut s, both(), session(60), &now).unwrap();
    let g_stripe = approve(&mut s, stripe(), session(60), &now).unwrap();
    // The same item for another project: no grant covers it, so it waits.
    let mut other = stripe();
    other.project = project("/src/other", 2, 200);
    let waiting_stripe = pending_id(&s.decide(other, &now));
    let waiting_github = pending_id(&s.decide(github(), &now));
    assert_eq!(s.binding_item(it[1].item), 2);
    assert_eq!(s.binding_item(it[2].item), 0);

    assert_eq!(s.on_item_removed(it[1].item), 2);
    assert!(s.grant(g_both).is_none());
    assert!(s.grant(g_stripe).is_none());
    assert!(s.pending_descriptor(&waiting_stripe, &now).is_none());
    assert!(s.pending_descriptor(&waiting_github, &now).is_some());
    assert_eq!(s.binding_item(it[1].item), 0);
    // Nothing else binds it: removing it again ends nothing.
    assert_eq!(s.on_item_removed(it[1].item), 0);
    assert_eq!(s.on_item_removed(it[0].item), 0);
    assert!(s.pending_descriptor(&waiting_github, &now).is_some());
}

// ---------------------------------------------------------- once grants

/// Gate 30: a `once` grant covers exactly one request. The store is used
/// under one lock, so the decision and the consumption are one step for
/// concurrent callers.
#[test]
fn a_once_grant_is_consumed_exactly_once() {
    let it = items();
    let mut s = store();
    let now = now_at(0);
    let r = || {
        request(
            under_agent(),
            vec![bound("OPENAI_API_KEY", &it[0])],
            &["./emit"],
        )
    };
    let g = approve(&mut s, r(), once(), &now).unwrap();
    assert_eq!(s.grant(g).unwrap().uses, Uses::Once);

    // Concurrent requests, decided one after the other under the lock:
    // the first consumes the grant, every other one is pending.
    assert_eq!(covered(&s.decide(r(), &now)), g);
    assert!(s.consume(g));
    assert!(!s.consume(g));
    assert!(s.grant(g).is_none());
    let pending = pending_id(&s.decide(r(), &now));
    assert_eq!(pending_id(&s.decide(r(), &now)), pending);

    // A session grant is not used up.
    let mut s = store();
    let g = approve(&mut s, r(), session(60), &now).unwrap();
    for _ in 0..3 {
        assert_eq!(covered(&s.decide(r(), &now)), g);
        assert!(s.consume(g));
    }

    // With both, a session grant is preferred, so the once grant is kept.
    // Both requests are opened before either grant exists, because the
    // once grant would cover the second.
    let mut s = store();
    let a = pending_id(&s.decide(r(), &now));
    let b = pending_id(&s.decide(
        request(
            under_agent(),
            vec![bound("OPENAI_API_KEY", &it[0])],
            &["./other"],
        ),
        &now,
    ));
    let digest = statement_digest(s.pending_descriptor(&a, &now).unwrap(), &once());
    let once_grant = s
        .approve(&a, proof(terminal()), once(), digest, &now)
        .unwrap();
    let digest = statement_digest(s.pending_descriptor(&b, &now).unwrap(), &session(60));
    let session_grant = s
        .approve(&b, proof(terminal()), session(60), digest, &now)
        .unwrap();
    assert_eq!(covered(&s.decide(r(), &now)), session_grant);
    assert!(s.grant(once_grant).is_some());
}

// -------------------------------------------------------- flood control

/// Gate 32's store part: the pending caps hold, an identical request
/// after a denial is denied without a prompt, and three denials for one
/// root auto-deny it for 30 minutes.
#[test]
fn pending_caps_hold_per_root_and_per_daemon() {
    let it = items();
    let mut s = store();
    let now = now_at(0);
    let r = |n: u32| {
        request(
            under_agent(),
            vec![bound("OPENAI_API_KEY", &it[0])],
            &[&n.to_string()],
        )
    };
    let mut ids = Vec::new();
    for n in 0..MAX_PENDING_PER_ROOT {
        ids.push(pending_id(&s.decide(r(u32::try_from(n).unwrap()), &now)));
    }
    let d = s.decide(r(99), &now);
    assert_eq!(d, Decision::Denied(DenyReason::PendingPerRoot));
    // The existing ones are still returned as they are.
    assert_eq!(pending_id(&s.decide(r(0), &now)), ids[0]);
    // Another root (another agent instance) has a cap of its own, and
    // the daemon has one in all.
    let mut roots = 1;
    loop {
        let agent = 200 + roots;
        let chain = vec![
            p(300 + roots, 70, None),
            p(agent, 70, Some("fixture")),
            p(70, 70, None),
            p(1, 1, None),
        ];
        let subject = ev(chain, false, &[]);
        let full = s.counts(&now).1 >= MAX_PENDING;
        let d = s.decide(
            request(subject, vec![bound("OPENAI_API_KEY", &it[0])], &["x"]),
            &now,
        );
        if full {
            assert_eq!(d, Decision::Denied(DenyReason::PendingTotal));
            break;
        }
        assert!(matches!(d, Decision::Pending(_)), "{d:?}");
        roots += 1;
        assert!(roots < 100);
    }
    assert_eq!(s.counts(&now), (0, MAX_PENDING));
    // Expiry frees the places.
    let later = now_at(PENDING_TTL.as_secs());
    assert!(matches!(s.decide(r(99), &later), Decision::Pending(_)));
}

#[test]
fn denials_are_remembered_and_three_auto_deny_the_root() {
    let it = items();
    let mut s = store();
    let now = now_at(0);
    let r = |n: u32| {
        request(
            under_agent(),
            vec![bound("OPENAI_API_KEY", &it[0])],
            &[&n.to_string()],
        )
    };

    // A denied request, repeated within 10 minutes, is denied at once;
    // after the window it prompts again.
    let id = pending_id(&s.decide(r(1), &now));
    let outcome = s.deny(&id, &now).unwrap();
    assert!(!outcome.root_auto_denied);
    assert!(s.deny(&id, &now).is_err());
    assert_eq!(s.decide(r(1), &now), Decision::Denied(DenyReason::Repeated));
    // A different command line from the same root still prompts.
    let id2 = pending_id(&s.decide(r(2), &now));
    let before_window = now_at(DENIAL_WINDOW.as_secs() - 1);
    assert_eq!(
        s.decide(r(1), &before_window),
        Decision::Denied(DenyReason::Repeated)
    );
    let after_window = now_at(DENIAL_WINDOW.as_secs());
    assert!(matches!(
        s.decide(r(1), &after_window),
        Decision::Pending(_)
    ));

    // Three denials within 10 minutes: the root is auto-denied for 30
    // minutes, whatever it asks for; other roots are not.
    let mut s = store();
    let mut auto = false;
    for n in 0..3 {
        let id = pending_id(&s.decide(r(n), &now));
        auto = s.deny(&id, &now).unwrap().root_auto_denied;
    }
    assert!(auto);
    assert_eq!(
        s.decide(r(7), &now),
        Decision::Denied(DenyReason::RootDenied)
    );
    let other = ev(
        vec![
            p(93, 93, None),
            p(81, 70, Some("fixture")),
            p(70, 70, None),
            p(1, 1, None),
        ],
        false,
        &[],
    );
    assert!(matches!(
        s.decide(
            request(other, vec![bound("OPENAI_API_KEY", &it[0])], &["x"]),
            &now
        ),
        Decision::Pending(_)
    ));
    let before = now_at(AUTO_DENY.as_secs() - 1);
    assert_eq!(
        s.decide(r(7), &before),
        Decision::Denied(DenyReason::RootDenied)
    );
    let after = now_at(AUTO_DENY.as_secs());
    assert!(matches!(s.decide(r(7), &after), Decision::Pending(_)));
    let _ = id2;

    // Three denials spread over more than 10 minutes do not.
    let mut s = store();
    for n in 0..3u64 {
        let at = now_at(n * (DENIAL_WINDOW.as_secs() / 2 + 1));
        let id = pending_id(&s.decide(r(u32::try_from(n).unwrap()), &at));
        assert!(!s.deny(&id, &at).unwrap().root_auto_denied);
    }
}

/// Review finding F-39: denials from many other roots never make the
/// store forget one early. With [`MAX_DENIALS`] denials remembered and no
/// time passing, the first request is still denied as repeated, its
/// root's count toward the auto-deny still holds, and no new request is
/// opened for anyone (`denials_full`) until the oldest window ends; the
/// requests already pending can still be denied, and are remembered too.
#[test]
fn a_full_denial_list_forgets_nothing_early() {
    let it = items();
    let mut s = store();
    let now = now_at(0);
    let first = |n: u32| {
        request(
            under_agent(),
            vec![bound("OPENAI_API_KEY", &it[0])],
            &[&n.to_string()],
        )
    };
    // The first root is denied twice: one more denial auto-denies it.
    for n in 0..2 {
        let id = pending_id(&s.decide(first(n), &now));
        assert!(!s.deny(&id, &now).unwrap().root_auto_denied);
    }
    // Other roots, one denial each, until the list is full, with one more
    // pending request from the first root and a few from others waiting.
    let other = |k: i32| {
        let agent = 2000 + k;
        request(
            ev(
                vec![
                    p(agent + 10_000, 70, None),
                    p(agent, 70, Some("fixture")),
                    p(70, 70, None),
                    p(1, 1, None),
                ],
                false,
                &[],
            ),
            vec![bound("OPENAI_API_KEY", &it[0])],
            &["x"],
        )
    };
    let last = i32::try_from(MAX_DENIALS).unwrap() - 3;
    for k in 0..last {
        let id = pending_id(&s.decide(other(k), &now));
        assert!(!s.deny(&id, &now).unwrap().root_auto_denied);
    }
    let waiting_first = pending_id(&s.decide(first(5), &now));
    let waiting_other = pending_id(&s.decide(other(999), &now));
    let id = pending_id(&s.decide(other(last), &now));
    s.deny(&id, &now).unwrap();
    let k = last;
    // 64 denials: nothing new opens, for anyone.
    assert_eq!(
        s.decide(other(k + 1), &now),
        Decision::Denied(DenyReason::DenialsFull)
    );
    assert_eq!(
        s.decide(first(6), &now),
        Decision::Denied(DenyReason::DenialsFull)
    );
    // The first denials are still remembered, and requests already
    // pending are still returned.
    for n in 0..2 {
        assert_eq!(
            s.decide(first(n), &now),
            Decision::Denied(DenyReason::Repeated)
        );
    }
    assert_eq!(pending_id(&s.decide(first(5), &now)), waiting_first);
    // Pending requests can still be denied, past the 64, and count: the
    // first root's third denial auto-denies it.
    assert!(s.deny(&waiting_first, &now).unwrap().root_auto_denied);
    assert!(!s.deny(&waiting_other, &now).unwrap().root_auto_denied);
    assert_eq!(
        s.decide(first(0), &now),
        Decision::Denied(DenyReason::RootDenied)
    );
    assert_eq!(
        s.decide(other(999), &now),
        Decision::Denied(DenyReason::Repeated)
    );
    // Within the window nothing is forgotten; after it, requests open
    // again.
    let almost = now_at(DENIAL_WINDOW.as_secs() - 1);
    assert_eq!(
        s.decide(other(1), &almost),
        Decision::Denied(DenyReason::Repeated)
    );
    assert_eq!(
        s.decide(other(10_000), &almost),
        Decision::Denied(DenyReason::DenialsFull)
    );
    let after = now_at(DENIAL_WINDOW.as_secs());
    assert!(matches!(s.decide(other(1), &after), Decision::Pending(_)));
    assert_eq!(
        DenyReason::from_token("denials_full"),
        Some(DenyReason::DenialsFull)
    );
}

// ------------------------------------------------------ attempt limiter

/// Gate 32's limiter: 5 free failures, then a wait of 30 seconds that
/// doubles up to an hour; a success clears it.
#[test]
fn the_attempt_limiter_waits_after_five_failures() {
    let mut l = AttemptLimiter::new();
    let mut now = now_at(0);
    for _ in 0..5 {
        assert!(l.check(&now).is_ok());
        l.failed(&now);
    }
    assert_eq!(l.failures(), 5);
    assert_eq!(l.check(&now), Err(Duration::from_secs(30)));
    now.awake += Duration::from_secs(29);
    assert_eq!(l.check(&now), Err(Duration::from_secs(1)));
    now.awake += Duration::from_secs(1);
    assert!(l.check(&now).is_ok());
    l.failed(&now);
    assert_eq!(l.check(&now), Err(Duration::from_secs(60)));
    let mut wait = 60;
    for _ in 0..10 {
        now.awake += Duration::from_secs(wait);
        assert!(l.check(&now).is_ok());
        l.failed(&now);
        wait = (wait * 2).min(3600);
        assert_eq!(l.check(&now), Err(Duration::from_secs(wait)));
    }
    assert_eq!(wait, 3600);
    // The wall clock does not shorten a wait: only awake time counts.
    now.wall += Duration::from_secs(7200);
    assert_eq!(l.check(&now), Err(Duration::from_secs(3600)));
    now.awake += Duration::from_secs(3600);
    assert!(l.check(&now).is_ok());
    l.succeeded();
    assert_eq!(l.failures(), 0);
    assert!(l.check(&now).is_ok());
    l.failed(&now);
    assert!(l.check(&now).is_ok());
}

// ---------------------------------------------------------- identifiers

#[test]
fn identifiers_are_crockford_and_parse_back() {
    let g = GrantId::generate();
    let text = g.to_string();
    assert_eq!(text.len(), 26);
    assert!(
        text.bytes()
            .all(|b| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&b))
    );
    assert_eq!(GrantId::parse(&text), Some(g));
    assert_eq!(GrantId::parse(&text.to_lowercase()), Some(g));
    assert_eq!(GrantId::parse("8ZZZZZZZZZZZZZZZZZZZZZZZZZ"), None);
    assert_eq!(GrantId::parse(""), None);
    assert_eq!(GrantId::parse(&text[..25]), None);
    assert_ne!(GrantId::generate(), g);

    let p = PendingId::generate();
    let text = p.to_string();
    assert_eq!(text.len(), 8);
    assert_eq!(PendingId::parse(&text), Some(p));
    assert_eq!(PendingId::parse(&text.to_lowercase()), Some(p));
    assert_eq!(PendingId::parse("ABCDEFG"), None);
    assert_eq!(PendingId::parse("ABCDEFGHI"), None);
    assert_eq!(PendingId::parse("ABCDEFG!"), None);
    // Crockford aliases: I and L read as 1, O as 0.
    assert_eq!(PendingId::parse("0O1IL222"), PendingId::parse("00111222"));
}
