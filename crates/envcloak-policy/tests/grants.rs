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

use envcloak_core::crypto::ItemClass;
use envcloak_core::vault::{
    Account, Classification, FieldId, FieldKind, FieldMeta, FieldName, ItemDetails, ItemId,
    ItemMeta, Slug,
};
use envcloak_policy::BindingSource;
use envcloak_policy::{
    AUTO_DENY, AccessRequest, Ancestor, ApprovalOptions, ApprovalProof, ApproveError,
    AttemptLimiter, BoundBinding, BoundRef, CatalogSource, ChainEnd, Claims, DENIAL_WINDOW,
    Decision, DenyReason, EnvName, GrantId, MAX_AGENT_TTL, MAX_DENIALS, MAX_GRANTS, MAX_PENDING,
    MAX_PENDING_PER_ROOT, MAX_TERMINAL_TTL, MatchBasis, Mode, Now, OptionsError, PENDING_TTL,
    PendingCap, PendingDescriptor, PendingId, ProcessInstance, ProjectIdentity, ProofKind,
    ProofRefusal, Proposal, RevokeSelector, SubjectEvidence, SubjectKind, Uses, proposals,
    render_statement, statement_digest,
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
        product: id.to_owned(),
        source: CatalogSource::Builtin,
        basis: MatchBasis::Executable,
    }
}

/// A process: pid, start time (the pid times 10), session, agent.
fn p(pid: i32, sid: i32, agent: Option<&str>) -> Ancestor {
    Ancestor {
        instance: inst(pid, 10 * u64::try_from(pid).unwrap()),
        sid: Some(sid),
        terminal: None,
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
        source: envcloak_policy::BindingSource::Env,
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

/// Every process is still running: what `alive` says when no root
/// exited.
fn running(_: &ProcessInstance) -> bool {
    true
}

fn store() -> GrantStore {
    let mut s = GrantStore::new();
    s.set_epochs(1, 1);
    s
}

/// The vault as these tests have it: each item a pending request binds,
/// as the request recorded it (a secret of one field), so a statement
/// reads now as it did when the request was made. The live-key guard's
/// tests below give the store a vault of their own instead.
fn held(s: &GrantStore, id: &PendingId, now: &Now) -> Vec<ItemMeta> {
    s.pending(id, now)
        .map(|p| metas(&p.request.bindings))
        .unwrap_or_default()
}

/// The vault's metadata for `bindings`: a secret of one field each, of the
/// classification the binding records.
fn metas(bindings: &[BoundRef]) -> Vec<ItemMeta> {
    bindings
        .iter()
        .map(|b| {
            meta(
                b.binding.item,
                b.binding.field,
                b.slug.as_str(),
                b.binding.classification,
            )
        })
        .collect()
}

/// One secret item of one field `value`.
fn meta(item: ItemId, field: FieldId, slug: &str, class: Classification) -> ItemMeta {
    ItemMeta {
        id: item,
        class: ItemClass::Secret,
        slug: Slug::new(slug).unwrap(),
        details: ItemDetails {
            classification: class,
            ..ItemDetails::default()
        },
        created_at: 0,
        updated_at: 0,
        fields: vec![FieldMeta {
            id: field,
            name: FieldName::new("value").unwrap(),
            kind: FieldKind::Value,
            prior_count: 0,
            created_at: 0,
            updated_at: 0,
        }],
        classification_changed_at: None,
        exposure: None,
        rotate_recommended: false,
        login: None,
    }
}

/// The store's statement and approval with the vault of [`held`].
trait Held {
    fn shown(&self, id: &PendingId, now: &Now) -> Option<PendingDescriptor>;
    fn approve_held(
        &mut self,
        id: &PendingId,
        proof: ApprovalProof,
        opts: ApprovalOptions,
        digest: [u8; 32],
        now: &Now,
    ) -> Result<GrantId, ApproveError>;
}

impl Held for GrantStore {
    fn shown(&self, id: &PendingId, now: &Now) -> Option<PendingDescriptor> {
        self.pending_descriptor(id, now, &held(self, id, now))
    }

    fn approve_held(
        &mut self,
        id: &PendingId,
        proof: ApprovalProof,
        opts: ApprovalOptions,
        digest: [u8; 32],
        now: &Now,
    ) -> Result<GrantId, ApproveError> {
        let vault = held(self, id, now);
        self.approve(id, proof, opts, digest, now, &vault)
    }
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
    let digest = statement_digest(&s.shown(&id, now).unwrap(), &opts);
    s.approve_held(&id, proof(terminal()), opts, digest, now)
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
    let digest = statement_digest(&s.shown(&id, &now).unwrap(), &opts);

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
            .approve_held(&id, proof(approver), opts.clone(), digest, &now)
            .unwrap_err();
        assert_eq!(e, ApproveError::ProofRefused);
        assert!(s.shown(&id, &now).is_some());
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
            .approve_held(&id, proof(approver), opts.clone(), digest, &now)
            .unwrap_err();
        assert_eq!(e, ApproveError::ProofRefused);
    }
    assert!(s.shown(&id, &now).is_some());
    assert_eq!(s.grants().count(), 0);
    assert_eq!(terminal().proof_refusal(), None);

    // A statement that differs from the pending request: another id,
    // other options, or one byte of the digest.
    let mut wrong = digest;
    wrong[0] ^= 1;
    let e = s
        .approve_held(&id, proof(terminal()), opts.clone(), wrong, &now)
        .unwrap_err();
    assert_eq!(e, ApproveError::StatementMismatch);
    let e = s
        .approve_held(&id, proof(terminal()), once(), digest, &now)
        .unwrap_err();
    assert_eq!(e, ApproveError::StatementMismatch);
    let other = PendingId::parse("ABCDEFGH").unwrap();
    let e = s
        .approve_held(&other, proof(terminal()), opts.clone(), digest, &now)
        .unwrap_err();
    assert_eq!(e, ApproveError::NoSuchRequest);
    assert_eq!(s.grants().count(), 0);

    // The right statement from a terminal subject creates the grant.
    let g = s
        .approve_held(&id, proof(terminal()), opts, digest, &now)
        .unwrap();
    assert!(s.shown(&id, &now).is_none());
    let grant = s.grant(g).unwrap();
    assert_eq!(grant.root, inst(80, 800));
    assert_eq!(grant.kind, SubjectKind::Agent);
    assert_eq!(grant.label.as_deref(), Some("fixture"));
    assert_eq!(grant.uses, Uses::Session);
    // Approved once: the request is gone.
    let e = s
        .approve_held(&id, proof(terminal()), session(3600), digest, &now)
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
    let d = s.shown(&id, &now).unwrap();
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
    assert!(s.shown(&id, &later).is_none());
    let e = s
        .approve_held(&id, proof(terminal()), session(3600), [0u8; 32], &later)
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
        let digest = statement_digest(&s.shown(&pid, &now).unwrap(), &once());
        s.approve_held(&pid, proof(terminal()), once(), digest, &now)
            .unwrap();
    }
    let e = approve(&mut s, agent_request(), once(), &now).unwrap_err();
    assert_eq!(e, ApproveError::TooManyGrants);
}

/// Review T9 open 1: agent markers set in a person's shell (claims only,
/// `CLAUDECODE=1`) made the subject an agent rooted at the session
/// leader, so its approval could run 24 hours instead of 12. The agent
/// bound needs the root to be a known agent process: the terminal chain
/// with a claim is refused 24 hours (`ttl_too_long`) and given 12, and so
/// is a caller whose only agent says so about itself above its session;
/// a grant rooted at a known agent still gets 24 hours.
#[test]
fn only_a_grant_rooted_at_a_known_agent_gets_the_agent_bound() {
    let it = items();
    let now = now_at(0);
    let shell = |claims: &[&str]| {
        ev(
            vec![
                p(90, 70, None),
                p(70, 70, None),
                p(60, 60, None),
                p(50, 1, None),
                p(1, 1, None),
            ],
            true,
            claims,
        )
    };
    let claimed = shell(&["CLAUDECODE"]);
    assert_eq!(claimed.kind(), SubjectKind::Agent);
    assert_eq!(claimed.root().pid, 70);
    // An agent known only by what it says about itself, above the
    // caller's session: an agent subject, rooted at the session leader.
    let asserted = {
        let mut chain = vec![
            p(95, 95, None),
            p(80, 70, None),
            p(70, 70, None),
            p(1, 1, None),
        ];
        chain[1].agent = Some(AgentLabel {
            basis: MatchBasis::Asserted,
            ..label("claude-code")
        });
        ev(chain, false, &[])
    };
    assert_eq!(asserted.kind(), SubjectKind::Agent);
    assert_eq!(asserted.root().pid, 95);
    for subject in [claimed, asserted] {
        let r = || {
            request(
                subject.clone(),
                vec![bound("OPENAI_API_KEY", &it[0])],
                &["x"],
            )
        };
        let mut s = store();
        let e = approve(&mut s, r(), session(MAX_AGENT_TTL.as_secs()), &now).unwrap_err();
        assert_eq!(e, ApproveError::InvalidOptions(OptionsError::TtlTooLong));
        let e = approve(&mut s, r(), session(MAX_TERMINAL_TTL.as_secs() + 1), &now).unwrap_err();
        assert_eq!(e, ApproveError::InvalidOptions(OptionsError::TtlTooLong));
        let g = approve(&mut s, r(), session(MAX_TERMINAL_TTL.as_secs()), &now).unwrap();
        assert_eq!(s.grant(g).unwrap().kind, SubjectKind::Agent);
    }
    // Rooted at a known agent: the agent bound.
    let mut s = store();
    let r = request(under_agent(), vec![bound("OPENAI_API_KEY", &it[0])], &["x"]);
    assert_eq!(r.subject.root().pid, 80);
    approve(&mut s, r, session(MAX_AGENT_TTL.as_secs()), &now).unwrap();
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
        let d = s.shown(&id, &now).unwrap();
        let asked: Vec<&str> = d
            .bindings
            .iter()
            .filter(|b| !b.granted)
            .map(|b| b.env_name.as_str())
            .collect();
        assert_eq!(asked, new);
        assert!(d.bindings.iter().any(|b| b.granted), "{d:?}");
        // Approved, the new grant holds the whole request.
        let digest = statement_digest(&d, &session(600));
        let g2 = s
            .approve_held(&id, proof(terminal()), session(600), digest, &now)
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
            .shown(&id, &now)
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
    let shown = once_store.shown(&id, &now).unwrap();
    let granted: Vec<&str> = shown
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
        s3.shown(&id, &now)
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

/// F-77, expiry and root exit before commit: `in_force`, which a delivery
/// asks on fresh clocks once its answer is built, holds until either
/// deadline, without a decision or a sweep in between to remove the
/// grant: a second before each deadline it holds; at the wall clock's
/// (awake time short of its own) and at awake time's (the wall clock
/// short of its own) it does not, though the grant is still in the store.
/// Nor once its root has exited (SPEC §10b: a grant never outlives its
/// root), which `alive` is asked about for the grant's own root instance,
/// though no sweep has removed it. A grant an epoch bump removed (it is
/// no longer in the store), a revoked grant and an id never issued are
/// not in force: `in_force` holds only for a grant that is there.
///
/// Mutations: compare only the wall clock (the awake case holds); only
/// awake time (the wall case holds); `alive` not asked (the exited root's
/// grant holds).
#[test]
fn a_grant_is_in_force_until_either_deadline() {
    let it = items();
    let now = now_at(0);
    let r = || {
        request(
            under_agent(),
            vec![bound("OPENAI_API_KEY", &it[0])],
            &["./emit"],
        )
    };
    let mut s = store();
    let g = approve(&mut s, r(), once(), &now).unwrap();
    assert!(s.in_force(g, &now, &running));
    let ttl = Duration::from_secs(once().ttl_secs);
    let short = ttl - Duration::from_secs(1);

    let mut wall = now_at(0);
    wall.wall += short;
    assert!(
        s.in_force(g, &wall, &running),
        "a second before the wall deadline"
    );
    wall.wall += Duration::from_secs(1);
    assert!(
        !s.in_force(g, &wall, &running),
        "at the wall deadline, awake short"
    );

    let mut awake = now_at(0);
    awake.awake += short;
    assert!(
        s.in_force(g, &awake, &running),
        "a second before the awake deadline"
    );
    awake.awake += Duration::from_secs(1);
    assert!(
        !s.in_force(g, &awake, &running),
        "at the awake deadline, wall short"
    );

    // Asking removes nothing: the grant is there until a decision or a
    // sweep expires it.
    assert!(s.grant(g).is_some());
    assert!(s.in_force(g, &now, &running));

    // Its root exited (no sweep since): not in force, asked about the
    // grant's own root; another process's exit changes nothing.
    let root = s.grant(g).unwrap().root.clone();
    assert!(!s.in_force(g, &now, &|r| *r != root), "its root exited");
    assert!(
        s.in_force(g, &now, &|r| *r == root),
        "another process exited"
    );
    assert!(s.grant(g).is_some(), "asking removed the grant");

    s.set_policy_epoch(2);
    assert!(s.grant(g).is_none(), "an epoch bump left the grant");
    assert!(
        !s.in_force(g, &now, &running),
        "removed by a policy epoch bump"
    );
    let mut s = store();
    let g = approve(&mut s, r(), once(), &now).unwrap();
    assert_eq!(s.revoke(RevokeSelector::Id(g)), 1);
    assert!(!s.in_force(g, &now, &running), "a revoked grant");
    assert!(!s.in_force(GrantId::parse(&"0".repeat(26)).unwrap(), &now, &running));
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
    assert!(s.shown(&pending, &now).is_none());
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
    assert!(s.shown(&waiting_stripe, &now).is_none());
    assert!(s.shown(&waiting_github, &now).is_some());
    assert_eq!(s.binding_item(it[1].item), 0);
    // Nothing else binds it: removing it again ends nothing.
    assert_eq!(s.on_item_removed(it[1].item), 0);
    assert_eq!(s.on_item_removed(it[0].item), 0);
    assert!(s.shown(&waiting_github, &now).is_some());
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
    let digest = statement_digest(&s.shown(&a, &now).unwrap(), &once());
    let once_grant = s
        .approve_held(&a, proof(terminal()), once(), digest, &now)
        .unwrap();
    let digest = statement_digest(&s.shown(&b, &now).unwrap(), &session(60));
    let session_grant = s
        .approve_held(&b, proof(terminal()), session(60), digest, &now)
        .unwrap();
    assert_eq!(covered(&s.decide(r(), &now)), session_grant);
    assert!(s.grant(once_grant).is_some());
}

// -------------------------------------------------------- flood control

/// Gate 32's store part: the pending caps hold (a request over one is
/// answered `too_many_pending`, never denied), an identical request after
/// a denial is denied without a prompt, and three denials for one root
/// auto-deny it for 30 minutes.
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
    // Over a cap, nothing is refused and nothing opened: the caller may
    // ask again once a place is free (M2 plan D-04).
    let d = s.decide(r(99), &now);
    assert_eq!(d, Decision::TooManyPending(PendingCap::PerRoot));
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
            assert_eq!(d, Decision::TooManyPending(PendingCap::Total));
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

/// Review T9 open 2: a root auto-denied after three denials was still
/// served by the grant it held: decide() answered `covered` before it
/// looked at the auto-deny, although SPEC 10a and flood.rs deny the root
/// whatever it asks. The auto-deny is checked first: the root's covered
/// request is `root_denied` for the 30 minutes, another root's grant still
/// covers its own, and the root's grant, kept, covers it again after.
#[test]
fn an_auto_denied_root_is_denied_what_its_grant_covers() {
    let it = items();
    let mut s = store();
    let now = now_at(0);
    let covered_request = || request(under_agent(), vec![bound("OPENAI_API_KEY", &it[0])], &["x"]);
    let hours = |h: u64| session(h * 3600);
    let g = approve(&mut s, covered_request(), hours(3), &now).unwrap();
    assert_eq!(s.decide(covered_request(), &now), Decision::Covered(g));
    // Another root, a terminal, with a grant of its own.
    let theirs = || request(terminal(), vec![bound("OPENAI_API_KEY", &it[0])], &["y"]);
    let t = approve(&mut s, theirs(), hours(3), &now).unwrap();
    // Three requests the grant does not cover, from the same root, denied.
    let mut auto = false;
    for n in 0..3 {
        let asks_more = request(
            under_agent(),
            vec![bound("STRIPE_SECRET_KEY", &it[1])],
            &[&n.to_string()],
        );
        let id = pending_id(&s.decide(asks_more, &now));
        auto = s.deny(&id, &now).unwrap().root_auto_denied;
    }
    assert!(auto);
    assert_eq!(
        s.decide(covered_request(), &now),
        Decision::Denied(DenyReason::RootDenied)
    );
    let before = now_at(AUTO_DENY.as_secs() - 1);
    assert_eq!(
        s.decide(covered_request(), &before),
        Decision::Denied(DenyReason::RootDenied)
    );
    assert_eq!(s.decide(theirs(), &before), Decision::Covered(t));
    // The grant was kept: once the auto-deny ends it covers again.
    let after = now_at(AUTO_DENY.as_secs());
    assert!(s.grant(g).is_some());
    assert_eq!(s.decide(covered_request(), &after), Decision::Covered(g));
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

// --------------------------------------------- the live-key guard (M2-13)

/// `b` with the item recorded as `class` when the request was made.
fn classified(mut b: BoundRef, class: Classification) -> BoundRef {
    b.binding.classification = class;
    b
}

/// A caller with no agent in its evidence and no terminal: a job in a
/// session of its own (`systemd-run --user`). An unknown subject.
fn unknown() -> SubjectEvidence {
    ev(vec![p(96, 96, None), p(1, 1, None)], false, &[])
}

fn live(names: &[&str], uses: Uses) -> ApprovalOptions {
    ApprovalOptions {
        uses,
        ttl_secs: 600,
        live: names.iter().map(|n| EnvName::new(n).unwrap()).collect(),
    }
}

/// Gate 40, sentence 1, the store's part (SPEC §10b "Live-key guard"): an
/// agent's or an unknown subject's request with a live binding is not
/// approved without that binding's tick. The refusal comes before the
/// proof would be looked at (`check_approval`) and again at approval,
/// makes no grant, and leaves the request pending; it names the item it
/// left unticked. With the tick, the grant records it (`live = true`).
#[test]
fn an_agent_or_unknown_approval_without_its_live_tick_makes_no_grant() {
    for requester in [under_agent(), unknown()] {
        let kind = requester.kind();
        assert_ne!(kind, SubjectKind::Terminal);
        let it = items();
        let mut s = store();
        let now = now_at(0);
        let r = request(
            requester,
            vec![
                bound("OPENAI_API_KEY", &it[0]),
                classified(bound("STRIPE_SECRET_KEY", &it[1]), Classification::Live),
            ],
            &["./emit"],
        );
        let vault = metas(&r.bindings);
        let id = pending_id(&s.decide(r, &now));
        let d = s.pending_descriptor(&id, &now, &vault).unwrap();
        assert_eq!(d.bindings[1].classification, "live", "{kind:?}");
        let opts = session(3600);
        let digest = statement_digest(&d, &opts);
        assert_eq!(
            s.check_approval(&id, &opts, digest, &now, &vault),
            Err(ApproveError::LiveNotTicked),
            "{kind:?}"
        );
        let e = s
            .approve(&id, proof(terminal()), opts.clone(), digest, &now, &vault)
            .unwrap_err();
        assert_eq!(e, ApproveError::LiveNotTicked, "{kind:?}");
        assert_eq!(s.grants().count(), 0, "{kind:?}");
        assert!(s.pending(&id, &now).is_some(), "{kind:?}");
        let unticked = s.unticked_items(&id, &opts, &now, &vault);
        assert_eq!(unticked.len(), 1, "{kind:?}");
        assert_eq!(unticked[0].0, it[1].item, "{kind:?}");
        assert_eq!(unticked[0].1.as_str(), "stripe/acme-web", "{kind:?}");
        // A tick of the other binding is not this one's.
        let wrong = live(&["OPENAI_API_KEY"], Uses::Session);
        let e = s
            .approve(
                &id,
                proof(terminal()),
                wrong.clone(),
                statement_digest(&d, &wrong),
                &now,
                &vault,
            )
            .unwrap_err();
        assert_eq!(e, ApproveError::LiveNotTicked, "{kind:?}");
        // Ticked: one grant, holding the tick.
        let ticked = live(&["STRIPE_SECRET_KEY"], Uses::Once);
        assert!(s.unticked_items(&id, &ticked, &now, &vault).is_empty());
        let g = s
            .approve(
                &id,
                proof(terminal()),
                ticked.clone(),
                statement_digest(&d, &ticked),
                &now,
                &vault,
            )
            .unwrap();
        let grant = s.grant(g).unwrap();
        assert_eq!(grant.kind, kind);
        let held: Vec<(&str, bool)> = grant
            .bindings
            .iter()
            .map(|b| (b.env_name.as_str(), b.live))
            .collect();
        assert_eq!(
            held,
            vec![("OPENAI_API_KEY", false), ("STRIPE_SECRET_KEY", true)]
        );
    }
}

/// Gate 40's other side: a terminal subject's live bindings need no tick
/// (SPEC §10b: the guard is for agent and unknown subjects; M1's rules
/// stand for the person's own terminal).
#[test]
fn a_terminal_subject_needs_no_live_tick() {
    let it = items();
    let mut s = store();
    let now = now_at(0);
    let r = request(
        terminal(),
        vec![classified(
            bound("STRIPE_SECRET_KEY", &it[1]),
            Classification::Live,
        )],
        &["./emit"],
    );
    let vault = metas(&r.bindings);
    let id = pending_id(&s.decide(r.clone(), &now));
    let d = s.pending_descriptor(&id, &now, &vault).unwrap();
    let opts = session(3600);
    let g = s
        .approve(
            &id,
            proof(terminal()),
            opts.clone(),
            statement_digest(&d, &opts),
            &now,
            &vault,
        )
        .unwrap();
    assert!(!s.grant(g).unwrap().bindings[0].live);
    // And the grant holds the live binding at use.
    assert_eq!(covered(&s.decide(r, &now)), g);
}

/// L-09 at approval ("Cache classification at approval" is the
/// mutation): the classification is read from the vault when the
/// statement is shown and again when it is approved, never taken from
/// what the request recorded. A request made while its item was a test
/// key, whose item the vault now holds as live (with nothing else told
/// to the store), is shown as live: the statement read before is a
/// `statement_mismatch`, the one shown now needs the tick, and with it
/// the grant records it.
#[test]
fn the_classification_is_read_from_the_vault_when_shown_and_approved() {
    let it = items();
    let mut s = store();
    let now = now_at(0);
    let r = request(
        under_agent(),
        vec![bound("STRIPE_SECRET_KEY", &it[1])],
        &["./emit"],
    );
    let before = metas(&r.bindings);
    let id = pending_id(&s.decide(r, &now));
    let opts = session(3600);
    let then = s.pending_descriptor(&id, &now, &before).unwrap();
    assert_eq!(then.bindings[0].classification, "test");
    let read_then = statement_digest(&then, &opts);
    // The vault now holds the item as live.
    let after = vec![meta(
        it[1].item,
        it[1].field,
        it[1].slug,
        Classification::Live,
    )];
    let shown = s.pending_descriptor(&id, &now, &after).unwrap();
    assert_eq!(shown.bindings[0].classification, "live");
    let e = s
        .approve(
            &id,
            proof(terminal()),
            opts.clone(),
            read_then,
            &now,
            &after,
        )
        .unwrap_err();
    assert_eq!(e, ApproveError::StatementMismatch);
    let e = s
        .approve(
            &id,
            proof(terminal()),
            opts.clone(),
            statement_digest(&shown, &opts),
            &now,
            &after,
        )
        .unwrap_err();
    assert_eq!(e, ApproveError::LiveNotTicked);
    assert_eq!(s.grants().count(), 0);
    let ticked = live(&["STRIPE_SECRET_KEY"], Uses::Session);
    let g = s
        .approve(
            &id,
            proof(terminal()),
            ticked.clone(),
            statement_digest(&shown, &ticked),
            &now,
            &after,
        )
        .unwrap();
    assert!(s.grant(g).unwrap().bindings[0].live);
    // A vault that lacks a bound item is not the one the request was made
    // from: nothing is shown and nothing approved.
    let r = request(
        under_agent(),
        vec![bound("OPENAI_API_KEY", &it[0])],
        &["./emit"],
    );
    let id = pending_id(&s.decide(r, &now));
    assert!(s.pending_descriptor(&id, &now, &[]).is_none());
    assert_eq!(
        s.check_approval(&id, &opts, read_then, &now, &[]),
        Err(ApproveError::NoSuchRequest)
    );
}

/// L-09 at use: a grant holds an agent's (or an unknown subject's)
/// binding only with its tick while the item is live by the
/// classification the request read from the vault, never by one recorded
/// at approval. A grant approved while the item was a test key does not
/// cover the request once it reads the item as live, even if nothing ended
/// the grant; a grant with the tick does; a terminal grant is as in M1.
#[test]
fn a_grant_does_not_hold_an_item_that_became_live_without_its_tick() {
    let it = items();
    let now = now_at(0);
    let test_binding = || bound("STRIPE_SECRET_KEY", &it[1]);
    let live_binding = || classified(bound("STRIPE_SECRET_KEY", &it[1]), Classification::Live);
    let requesters: [fn() -> SubjectEvidence; 2] = [under_agent, unknown];
    for requester in requesters {
        let mut s = store();
        let g = approve_with_vault(
            &mut s,
            request(requester(), vec![test_binding()], &["./emit"]),
            session(3600),
            &now,
        );
        // As a test key, it is held.
        assert_eq!(
            covered(&s.decide(
                request(requester(), vec![test_binding()], &["./emit"]),
                &now
            )),
            g
        );
        // Read as live, it is not: the request asks again, and the
        // statement asks for it (no grant holds it).
        let id = pending_id(&s.decide(
            request(requester(), vec![live_binding()], &["./emit"]),
            &now,
        ));
        let vault = vec![meta(
            it[1].item,
            it[1].field,
            it[1].slug,
            Classification::Live,
        )];
        let d = s.pending_descriptor(&id, &now, &vault).unwrap();
        assert!(!d.bindings[0].granted, "{d:?}");
        // The ticked grant holds it.
        let ticked = live(&["STRIPE_SECRET_KEY"], Uses::Session);
        let t = s
            .approve(
                &id,
                proof(terminal()),
                ticked.clone(),
                statement_digest(&d, &ticked),
                &now,
                &vault,
            )
            .unwrap();
        assert_eq!(
            covered(&s.decide(
                request(requester(), vec![live_binding()], &["./emit"]),
                &now
            )),
            t
        );
    }
    // A terminal grant for a terminal subject holds it either way.
    let mut s = store();
    let g = approve_with_vault(
        &mut s,
        request(terminal(), vec![test_binding()], &["./emit"]),
        session(3600),
        &now,
    );
    assert_eq!(
        covered(&s.decide(request(terminal(), vec![live_binding()], &["./emit"]), &now)),
        g
    );
}

/// Opens `r` and approves it as the person with `opts`, with the vault of
/// `r`'s own bindings.
fn approve_with_vault(
    s: &mut GrantStore,
    r: AccessRequest,
    opts: ApprovalOptions,
    now: &Now,
) -> GrantId {
    let vault = metas(&r.bindings);
    let id = pending_id(&s.decide(r, now));
    let d = s.pending_descriptor(&id, now, &vault).unwrap();
    let digest = statement_digest(&d, &opts);
    s.approve(&id, proof(terminal()), opts, digest, now, &vault)
        .unwrap()
}

/// A secret item for the proposal tests: `slug` of `provider`, with
/// `fields` (each a field id and name), classified `class`, with the
/// account label `label`.
fn provider_item(
    slug: &str,
    provider: &str,
    class: Classification,
    label: Option<&str>,
    fields: &[&str],
) -> ItemMeta {
    let mut m = meta(ItemId::generate(), FieldId::generate(), slug, class);
    m.details.provider = Some(provider.to_owned());
    m.details.account = Account {
        label: label.map(str::to_owned),
        ..Account::default()
    };
    m.fields = fields
        .iter()
        .map(|f| FieldMeta {
            id: FieldId::generate(),
            name: FieldName::new(f).unwrap(),
            kind: FieldKind::Value,
            prior_count: 0,
            created_at: 0,
            updated_at: 0,
        })
        .collect();
    m
}

/// A binding of `env` to field `field` of `m`, recorded as `m` is now.
fn binding_of(env: &str, m: &ItemMeta, field: &str) -> BoundRef {
    let f = m.fields.iter().find(|f| f.name.as_str() == field).unwrap();
    BoundRef {
        binding: BoundBinding {
            env_name: EnvName::new(env).unwrap(),
            item: m.id,
            field: f.id,
            classification: m.details.classification,
        },
        slug: m.slug.clone(),
        field_name: f.name.clone(),
        first_use: false,
        source: envcloak_policy::BindingSource::Env,
    }
}

/// Gate 40, sentence 2 (SPEC §10b): for each live binding, the same
/// provider's test item is proposed, and nothing else: not another
/// provider's, not a live or unknown one, not one whose account label
/// differs from the live item's when both have one, not a card's or a
/// login's, not one a reference cannot bind unambiguously. One per
/// binding, the one with an equal account label first, then by slug, with
/// the layer the binding came from; a test binding, an unknown one and an
/// item of no provider get none.
///
/// Mutation (verifier, round 2): candidates of any classification but
/// live (`classification != Live` in place of `== Test`): the unknown item
/// of the same provider and label, which sorts before every test item, is
/// proposed and this fails. And of any classification at all: the live one
/// that sorts first is.
#[test]
fn the_same_providers_test_item_is_proposed_for_each_live_binding() {
    let live_one = provider_item(
        "stripe/acme-live",
        "stripe",
        Classification::Live,
        Some("acme"),
        &["value"],
    );
    let live_two = provider_item(
        "stripe/two-live",
        "stripe",
        Classification::Live,
        None,
        &["secret", "publishable"],
    );
    let test_unlabeled = provider_item(
        "stripe/aaa-test",
        "stripe",
        Classification::Test,
        None,
        &["value"],
    );
    let test_same_label = provider_item(
        "stripe/zzz-test",
        "stripe",
        Classification::Test,
        Some("acme"),
        &["value"],
    );
    let test_other_label = provider_item(
        "stripe/aa-other",
        "stripe",
        Classification::Test,
        Some("globex"),
        &["value"],
    );
    let test_two_fields = provider_item(
        "stripe/bbb-test",
        "stripe",
        Classification::Test,
        Some("globex"),
        &["publishable", "secret"],
    );
    let test_wrong_fields = provider_item(
        "stripe/aab-test",
        "stripe",
        Classification::Test,
        None,
        &["a", "b"],
    );
    let other_provider = provider_item(
        "github/aaa-test",
        "github",
        Classification::Test,
        None,
        &["value"],
    );
    let unknown_class = provider_item(
        "stripe/aac-unknown",
        "stripe",
        Classification::Unknown,
        None,
        &["value"],
    );
    let mut login = provider_item(
        "stripe/aad-login",
        "stripe",
        Classification::Test,
        None,
        &["value"],
    );
    login.class = ItemClass::Login;
    let mut no_provider = provider_item(
        "stripe/none",
        "stripe",
        Classification::Live,
        None,
        &["value"],
    );
    no_provider.details.provider = None;
    // Of the same provider and the same account label as `live_one`, and
    // sorting before every test item: an unknown key and another live
    // one. Neither is a test key (SPEC §10b: `unknown` is not), so neither
    // is ever proposed, whatever the order.
    let unknown_first = provider_item(
        "stripe/a-unknown",
        "stripe",
        Classification::Unknown,
        Some("acme"),
        &["value"],
    );
    let live_first = provider_item(
        "stripe/a-live",
        "stripe",
        Classification::Live,
        Some("acme"),
        &["value"],
    );
    // A login and a card classified test, of the same provider and label,
    // sorting before every secret: never proposed, as no reference binds
    // them (verifier, round 2: the login sorted after the test items, so
    // its filter could be dropped unseen).
    let mut login_first = provider_item(
        "stripe/a-a-login",
        "stripe",
        Classification::Test,
        Some("acme"),
        &["value"],
    );
    login_first.class = ItemClass::Login;
    let mut card_first = provider_item(
        "stripe/a-b-card",
        "stripe",
        Classification::Test,
        Some("acme"),
        &["value"],
    );
    card_first.class = ItemClass::Card;
    let vault = vec![
        live_one.clone(),
        live_two.clone(),
        test_unlabeled.clone(),
        test_same_label.clone(),
        test_other_label.clone(),
        test_two_fields.clone(),
        test_wrong_fields.clone(),
        other_provider.clone(),
        unknown_class.clone(),
        login,
        no_provider.clone(),
        unknown_first.clone(),
        live_first.clone(),
        login_first.clone(),
        card_first.clone(),
    ];
    let mut bindings = vec![
        binding_of("STRIPE_SECRET_KEY", &live_one, "value"),
        binding_of("STRIPE_TWO_KEY", &live_two, "secret"),
        binding_of("STRIPE_TEST_KEY", &test_unlabeled, "value"),
        binding_of("STRIPE_UNKNOWN_KEY", &unknown_class, "value"),
        binding_of("NO_PROVIDER_KEY", &no_provider, "value"),
    ];
    // The second binding came from a profile: its proposal says so.
    let dev = BindingSource::Profile {
        profile: "dev".to_owned(),
    };
    bindings[1].source = dev.clone();
    let got = proposals(&bindings, &vault);
    assert_eq!(
        got,
        vec![
            // The equal account label first, though another sorts before;
            // never the unknown or the live one of that label, which sort
            // first.
            Proposal {
                env_name: "STRIPE_SECRET_KEY".to_owned(),
                live_slug: "stripe/acme-live".to_owned(),
                test_slug: "stripe/zzz-test".to_owned(),
                test_field: None,
                source: BindingSource::Env,
            },
            // No label on the live item: the first by slug that a
            // reference binds (one field, or the binding's field).
            Proposal {
                env_name: "STRIPE_TWO_KEY".to_owned(),
                live_slug: "stripe/two-live".to_owned(),
                test_slug: "stripe/aa-other".to_owned(),
                test_field: None,
                source: dev.clone(),
            },
        ]
    );
    // With no test item of the provider left, nothing is proposed: not the
    // unknown key, not the other live one, however they sort.
    let no_test: Vec<ItemMeta> = vault
        .iter()
        .filter(|m| m.details.classification != Classification::Test)
        .cloned()
        .collect();
    assert!(no_test.iter().any(|m| m.id == unknown_first.id));
    assert!(no_test.iter().any(|m| m.id == live_first.id));
    assert_eq!(proposals(&bindings, &no_test), Vec::<Proposal>::new());
    // The positive controls: the login and the card made secrets are
    // proposed first, as their label and slug put them; and the unknown
    // item made a test key is proposed first.
    for first in [&login_first, &card_first] {
        let mut as_secret = vault.clone();
        as_secret
            .iter_mut()
            .filter(|m| m.id == login_first.id || m.id == card_first.id)
            .filter(|m| m.id != first.id)
            .for_each(|m| m.details.classification = Classification::Live);
        as_secret
            .iter_mut()
            .find(|m| m.id == first.id)
            .unwrap()
            .class = ItemClass::Secret;
        assert_eq!(
            proposals(&bindings[..1], &as_secret)[0].test_slug,
            first.slug.as_str()
        );
    }
    // The unknown item made a test key is proposed first.
    let mut made_test = no_test.clone();
    made_test
        .iter_mut()
        .find(|m| m.id == unknown_first.id)
        .unwrap()
        .details
        .classification = Classification::Test;
    assert_eq!(
        proposals(&bindings[..1], &made_test)[0].test_slug,
        "stripe/a-unknown"
    );
    // Without the item of an equal label, an unlabeled one; never the
    // other label's.
    let fewer: Vec<ItemMeta> = vault
        .iter()
        .filter(|m| m.id != test_same_label.id)
        .cloned()
        .collect();
    assert_eq!(
        proposals(&bindings[..1], &fewer)[0].test_slug,
        "stripe/aaa-test"
    );
    // A test item of several fields binds by the live binding's field; one
    // without that field cannot be bound by a reference, and is not
    // proposed, though it is the only test item there.
    assert_eq!(
        proposals(
            &bindings[1..2],
            &[live_two.clone(), test_wrong_fields.clone()]
        ),
        Vec::<Proposal>::new()
    );
    let only_two: Vec<ItemMeta> = vec![live_two.clone(), test_two_fields.clone()];
    assert_eq!(
        proposals(&bindings[1..2], &only_two),
        vec![Proposal {
            env_name: "STRIPE_TWO_KEY".to_owned(),
            live_slug: "stripe/two-live".to_owned(),
            test_slug: "stripe/bbb-test".to_owned(),
            test_field: Some("secret".to_owned()),
            source: dev,
        }]
    );
    // The proposal is read from the vault as it is: the live item as a
    // test key now has none, and a binding whose item is gone has none.
    let mut relabeled = vault.clone();
    relabeled[0].details.classification = Classification::Test;
    assert!(proposals(&bindings[..1], &relabeled).is_empty());
    assert!(proposals(&bindings[..1], &vault[1..]).is_empty());
    // The rendering lists it before the live binding.
    let mut s = store();
    let now = now_at(0);
    let id = pending_id(&s.decide(
        request(under_agent(), bindings[..1].to_vec(), &["./emit"]),
        &now,
    ));
    let d = s.pending_descriptor(&id, &now, &vault).unwrap();
    let text = render_statement(&d, &session(3600));
    let test = text.find("stripe/zzz-test").unwrap();
    let ticks = text.find("STRIPE_SECRET_KEY = stripe/acme-live").unwrap();
    assert!(test < ticks, "{text}");
    assert!(
        text.contains(
            "run `envcloak ref --manifest /src/acme-web/envcloak.toml \
             STRIPE_SECRET_KEY=stripe/zzz-test`"
        ),
        "{text}"
    );
}

/// A statement whose proposals changed is a `statement_mismatch` (gate
/// 40; "Leave proposals out of the digest" is the mutation): the test item
/// the person read as proposed was removed, or reclassified, or another
/// became the one proposed, after they read it. The statement shown now
/// approves.
#[test]
fn a_statement_whose_proposals_changed_is_a_mismatch() {
    let live_item = provider_item(
        "stripe/acme-live",
        "stripe",
        Classification::Live,
        None,
        &["value"],
    );
    let test_item = provider_item(
        "stripe/acme-test",
        "stripe",
        Classification::Test,
        None,
        &["value"],
    );
    let earlier = provider_item(
        "stripe/aaa-test",
        "stripe",
        Classification::Test,
        None,
        &["value"],
    );
    let vault = vec![live_item.clone(), test_item.clone()];
    let mut s = store();
    let now = now_at(0);
    let id = pending_id(&s.decide(
        request(
            under_agent(),
            vec![binding_of("STRIPE_SECRET_KEY", &live_item, "value")],
            &["./emit"],
        ),
        &now,
    ));
    let opts = live(&["STRIPE_SECRET_KEY"], Uses::Once);
    let read = s.pending_descriptor(&id, &now, &vault).unwrap();
    assert_eq!(read.proposals.len(), 1);
    let digest = statement_digest(&read, &opts);
    let mut reclassified = vault.clone();
    reclassified[1].details.classification = Classification::Live;
    let changes = [
        vec![live_item.clone()],
        reclassified,
        vec![live_item.clone(), test_item.clone(), earlier],
    ];
    for now_vault in &changes {
        let shown = s.pending_descriptor(&id, &now, now_vault).unwrap();
        assert_ne!(shown.proposals, read.proposals);
        assert_eq!(
            s.check_approval(&id, &opts, digest, &now, now_vault),
            Err(ApproveError::StatementMismatch)
        );
        let e = s
            .approve(
                &id,
                proof(terminal()),
                opts.clone(),
                digest,
                &now,
                now_vault,
            )
            .unwrap_err();
        assert_eq!(e, ApproveError::StatementMismatch);
    }
    assert_eq!(s.grants().count(), 0);
    let now_vault = &changes[2];
    let shown = s.pending_descriptor(&id, &now, now_vault).unwrap();
    s.approve(
        &id,
        proof(terminal()),
        opts.clone(),
        statement_digest(&shown, &opts),
        &now,
        now_vault,
    )
    .unwrap();
}
