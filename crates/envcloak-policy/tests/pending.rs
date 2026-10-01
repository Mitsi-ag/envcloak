//! How a request stands, for the process tree that waits on it (SPEC §6.1
//! step 4, M2 plan D-04): `GrantStore::poll` on synthetic chains, with a
//! [`Now`] the test moves by hand. The daemon's `pending.state` and
//! `envcloak run --wait` are in `crates/envcloak-daemon/tests/pending.rs`
//! and `crates/envcloak-cli/tests/wait.rs`; the waiting schedule against
//! this store in `crates/envcloak-ipc/tests/wait.rs`.
#![allow(clippy::unwrap_used)]

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use envcloak_core::vault::{Classification, FieldId, FieldName, ItemId, Slug};
use envcloak_policy::{
    AccessRequest, AgentLabel, Ancestor, ApprovalOptions, ApprovalProof, BoundBinding, BoundRef,
    Busy, CatalogSource, ChainEnd, Claims, Decision, EnvName, GrantStore, MAX_OUTCOMES,
    MAX_PENDING, MAX_POLL_ROOTS, MatchBasis, Mode, Now, OUTCOME_TTL, PENDING_TTL,
    POLLS_PER_REQUEST, PendingId, PendingState, ProcessInstance, ProjectIdentity, ProofKind,
    RevokeSelector, SubjectEvidence, Uses, statement_digest,
};
use envcloak_sys::StartTime;

fn inst(pid: i32) -> ProcessInstance {
    ProcessInstance {
        pid,
        start_time: StartTime::from_raw(10 * u64::try_from(pid).unwrap()),
        pidversion: None,
        exe: None,
    }
}

fn p(pid: i32, sid: i32, agent: Option<&str>) -> Ancestor {
    Ancestor {
        instance: inst(pid),
        sid: Some(sid),
        terminal: None,
        agent: agent.map(|id| AgentLabel {
            id: id.to_owned(),
            name: id.to_owned(),
            source: CatalogSource::Builtin,
            basis: MatchBasis::Executable,
        }),
    }
}

fn ev(chain: Vec<Ancestor>, terminal: bool) -> SubjectEvidence {
    SubjectEvidence::from_chain(chain, ChainEnd::Top, terminal, Claims::none(), None).unwrap()
}

/// A person's terminal: envcloak (90) <- zsh (70, the session leader) <-
/// Terminal (50) <- launchd (1).
fn person() -> SubjectEvidence {
    ev(
        vec![
            p(90, 70, None),
            p(70, 70, None),
            p(50, 1, None),
            p(1, 1, None),
        ],
        true,
    )
}

/// A command `pid` of agent `agent` (in a session of its own, as Claude
/// Code runs each command), the agent started from zsh (70): the agent is
/// the root.
fn under(agent: i32, pid: i32) -> SubjectEvidence {
    ev(
        vec![
            p(pid, pid, None),
            p(agent, 70, Some("fixture")),
            p(70, 70, None),
            p(50, 1, None),
            p(1, 1, None),
        ],
        false,
    )
}

/// A grandchild of the agent's command `pid`: still the agent's tree.
fn deeper(agent: i32, pid: i32) -> SubjectEvidence {
    ev(
        vec![
            p(pid + 1, pid, None),
            p(pid, pid, None),
            p(agent, 70, Some("fixture")),
            p(70, 70, None),
            p(50, 1, None),
            p(1, 1, None),
        ],
        false,
    )
}

/// The same pid as agent 80's command 81, but another process (another
/// start time): a recycled pid is not the tree.
fn recycled() -> SubjectEvidence {
    let mut agent = p(80, 70, Some("fixture"));
    agent.instance.start_time = StartTime::from_raw(12_345);
    ev(
        vec![
            p(81, 81, None),
            agent,
            p(70, 70, None),
            p(50, 1, None),
            p(1, 1, None),
        ],
        false,
    )
}

fn request(subject: SubjectEvidence, argv: &str, item: &(ItemId, FieldId)) -> AccessRequest {
    AccessRequest {
        subject,
        project: ProjectIdentity {
            canonical_dir: PathBuf::from("/src/acme-web"),
            dev: 1,
            ino: 100,
            manifest_path: PathBuf::from("/src/acme-web/envcloak.toml"),
        },
        manifest_sha256: [7u8; 32],
        bindings: vec![BoundRef {
            binding: BoundBinding {
                env_name: EnvName::new("OPENAI_API_KEY").unwrap(),
                item: item.0,
                field: item.1,
                classification: Classification::Test,
            },
            slug: Slug::new("openai/acme-web").unwrap(),
            field_name: FieldName::new("value").unwrap(),
            first_use: false,
        }],
        mode: Mode::Inject,
        argv_display: vec![argv.to_owned()],
        new_project: false,
    }
}

/// `ms` milliseconds after a fixed start, on every clock.
fn at_ms(ms: u64) -> Now {
    Now {
        wall: SystemTime::UNIX_EPOCH
            + Duration::from_secs(1_800_000_000)
            + Duration::from_millis(ms),
        awake: Duration::from_secs(1000) + Duration::from_millis(ms),
        including_sleep: Duration::from_secs(1000) + Duration::from_millis(ms),
    }
}

fn store() -> GrantStore {
    let mut s = GrantStore::new();
    s.set_epochs(1, 1);
    s
}

fn item() -> (ItemId, FieldId) {
    (ItemId::generate(), FieldId::generate())
}

fn opened(s: &mut GrantStore, r: AccessRequest, now: &Now) -> PendingId {
    match s.decide(r, now) {
        Decision::Pending(id) => id,
        other => panic!("expected a pending request, got {other:?}"),
    }
}

fn approve(s: &mut GrantStore, id: &PendingId, now: &Now) {
    let opts = ApprovalOptions {
        uses: Uses::Once,
        ttl_secs: 600,
        live: Vec::new(),
    };
    let digest = statement_digest(s.pending_descriptor(id, now).unwrap(), &opts);
    let proof = ApprovalProof {
        approver: person(),
        kind: ProofKind::Passphrase,
    };
    s.approve(id, proof, opts, digest, now).unwrap();
}

/// A poll that the limit admits: each from a root of its own, so none
/// runs out.
fn poll(s: &mut GrantStore, id: &PendingId, caller: &SubjectEvidence, now: &Now) -> PendingState {
    s.poll(id, caller, now).unwrap()
}

/// Gate for D-04's "only to the request's own subject root": the state is
/// told to the requester, to anything else in its root's tree (another
/// command of the same agent, a grandchild), and to nothing outside it: a
/// person's terminal, another agent's command, a recycled pid. Outside,
/// a live request reads exactly as an id no request has.
///
/// Mutation: answer the real state to any caller (drop the tree check in
/// `GrantStore::poll`): the outsiders read `pending` and this fails.
#[test]
fn a_requests_state_is_told_only_to_its_own_tree() {
    let it = item();
    let mut s = store();
    let now = at_ms(0);
    let id = opened(&mut s, request(under(80, 81), "./emit", &it), &now);
    for (who, caller) in [
        ("the requester", under(80, 81)),
        ("another command of the agent", under(80, 85)),
        ("a grandchild", deeper(80, 81)),
    ] {
        assert_eq!(
            poll(&mut s, &id, &caller, &now),
            PendingState::Pending,
            "{who}"
        );
    }
    let nobody = PendingId::parse("ZZZZZZZZ").unwrap();
    for (who, caller) in [
        ("a person's terminal", person()),
        ("another agent's command", under(180, 181)),
        ("a recycled pid", recycled()),
    ] {
        assert_eq!(
            poll(&mut s, &id, &caller, &now),
            PendingState::Unknown,
            "{who}"
        );
        assert_eq!(
            poll(&mut s, &nobody, &caller, &now),
            PendingState::Unknown,
            "{who}"
        );
    }
    // Asking opened nothing and approved nothing.
    assert_eq!(s.counts(&now), (0, 1));
}

/// Approved, denied and expired (the injected clock reaching the
/// request's lifetime) are told to the tree once the request has left
/// the pending list, while the outcome is remembered; then, and to any
/// other tree all along, `unknown`. Lock ends pending requests and their
/// outcomes: `unknown`, after which `run.request` says the vault is
/// locked.
#[test]
fn approved_denied_and_expired_are_told_after_the_request_ends() {
    let it = item();
    let mut s = store();
    let now = at_ms(0);
    let me = under(80, 81);
    let a = opened(&mut s, request(me.clone(), "a", &it), &now);
    let d = opened(&mut s, request(me.clone(), "d", &it), &now);
    let e = opened(&mut s, request(me.clone(), "e", &it), &now);

    approve(&mut s, &a, &now);
    s.deny(&d, &now).unwrap();
    assert_eq!(poll(&mut s, &a, &me, &at_ms(10)), PendingState::Approved);
    assert_eq!(poll(&mut s, &d, &me, &at_ms(20)), PendingState::Denied);
    assert_eq!(poll(&mut s, &e, &me, &at_ms(30)), PendingState::Pending);
    for id in [&a, &d, &e] {
        assert_eq!(
            poll(&mut s, id, &person(), &at_ms(40)),
            PendingState::Unknown
        );
    }
    // Outcomes are remembered for OUTCOME_TTL after they happen, and a
    // request waits PENDING_TTL: a moment before both, the request still
    // waits and the outcomes are told; at them, the request has expired,
    // which its tree is told (no sweep ran in between), and the older
    // outcomes are forgotten.
    let ttl = u64::try_from(PENDING_TTL.as_millis()).unwrap();
    let kept = u64::try_from(OUTCOME_TTL.as_millis()).unwrap();
    assert_eq!(
        kept, ttl,
        "a waiter is told its outcome for as long as it may wait"
    );
    // (Polls of one root a few hundred milliseconds apart, as a waiter's
    // are, so the limit is not what this is about.)
    assert_eq!(
        poll(&mut s, &d, &me, &at_ms(ttl - 601)),
        PendingState::Denied
    );
    assert_eq!(
        poll(&mut s, &a, &me, &at_ms(ttl - 301)),
        PendingState::Approved
    );
    assert_eq!(
        poll(&mut s, &e, &me, &at_ms(ttl - 1)),
        PendingState::Pending
    );
    assert_eq!(poll(&mut s, &e, &me, &at_ms(ttl)), PendingState::Expired);
    assert_eq!(s.counts(&at_ms(ttl)).1, 0);
    assert_eq!(
        poll(&mut s, &a, &me, &at_ms(ttl + 300)),
        PendingState::Unknown
    );
    assert_eq!(
        poll(&mut s, &d, &me, &at_ms(ttl + 600)),
        PendingState::Unknown
    );
    assert_eq!(
        poll(&mut s, &e, &me, &at_ms(ttl + kept - 1)),
        PendingState::Expired
    );
    assert_eq!(
        poll(&mut s, &e, &me, &at_ms(ttl + kept)),
        PendingState::Unknown
    );

    // Lock: a pending request and an outcome alike become unknown.
    let now = at_ms(3 * kept);
    let p = opened(&mut s, request(me.clone(), "p", &it), &now);
    let q = opened(&mut s, request(me.clone(), "q", &it), &now);
    s.deny(&q, &now).unwrap();
    s.on_lock();
    for id in [&p, &q] {
        assert_eq!(poll(&mut s, id, &me, &now), PendingState::Unknown);
    }
    assert_eq!(s.waiting_counts().0, 0);
}

/// An item removed or reclassified ends the requests that bind it, with
/// no outcome: they are `unknown`, and asked again the request is
/// decided afresh (it no longer binds, or shows the new classification).
#[test]
fn a_request_ended_by_its_item_is_unknown() {
    let it = item();
    let mut s = store();
    let now = at_ms(0);
    let me = under(80, 81);
    let id = opened(&mut s, request(me.clone(), "x", &it), &now);
    s.on_item_reclassified(it.0);
    assert_eq!(poll(&mut s, &id, &me, &now), PendingState::Unknown);
}

/// D-04's poll limit: a root's bucket refills POLLS_PER_REQUEST a second
/// for each of its live pending requests and holds one second's worth; a
/// root with none still gets one request's worth, to read an outcome. One
/// root's polls never spend another's.
///
/// Mutation: size the bucket per root instead of per pending request (a
/// fixed POLLS_PER_REQUEST whatever the root has pending): the
/// three-request root runs out after 4 polls and this fails.
#[test]
fn polls_are_limited_per_root_by_its_live_requests() {
    let it = item();
    let mut s = store();
    let now = at_ms(0);
    let me = under(80, 81);
    let per = usize::try_from(POLLS_PER_REQUEST).unwrap();
    let ids: Vec<PendingId> = (0..3)
        .map(|n| opened(&mut s, request(me.clone(), &n.to_string(), &it), &now))
        .collect();
    // Three live requests: twelve polls at once, then busy.
    for n in 0..3 * per {
        assert_eq!(
            s.poll(&ids[n % 3], &me, &now),
            Ok(PendingState::Pending),
            "poll {n}"
        );
    }
    assert_eq!(s.poll(&ids[0], &me, &now), Err(Busy));
    // Busy says nothing about the id: an unknown one is refused alike.
    let nobody = PendingId::parse("ZZZZZZZZ").unwrap();
    assert_eq!(s.poll(&nobody, &me, &now), Err(Busy));
    // Another root is not spent by this one's polls.
    assert_eq!(
        s.poll(&ids[0], &under(180, 181), &now),
        Ok(PendingState::Unknown)
    );
    // It refills 12 a second: one poll every 1000/12 ms.
    assert_eq!(s.poll(&ids[0], &me, &at_ms(80)), Err(Busy));
    assert_eq!(s.poll(&ids[0], &me, &at_ms(84)), Ok(PendingState::Pending));
    // A second later it is full again, and holds no more than a second's
    // worth however long it rests.
    let rested = at_ms(60_000);
    for n in 0..3 * per {
        assert!(s.poll(&ids[1], &me, &rested).is_ok(), "poll {n}");
    }
    assert_eq!(s.poll(&ids[1], &me, &rested), Err(Busy));

    // One live request: four a second.
    let mut s = store();
    let one = opened(&mut s, request(me.clone(), "one", &it), &now);
    for n in 0..per {
        assert!(s.poll(&one, &me, &now).is_ok(), "poll {n}");
    }
    assert_eq!(s.poll(&one, &me, &now), Err(Busy));
    // Approved: the root has none live, and still reads its outcome at
    // one request's rate.
    approve(&mut s, &one, &at_ms(1000));
    for n in 0..per {
        assert_eq!(
            s.poll(&one, &me, &at_ms(1000)),
            Ok(PendingState::Approved),
            "poll {n}"
        );
    }
    assert_eq!(s.poll(&one, &me, &at_ms(1000)), Err(Busy));
}

/// Polls that reach the limiter out of order (the daemon read each one's
/// time before taking the store's lock, so concurrent polls can arrive
/// with times that go backwards) refill no interval twice: the bucket's
/// clock never moves back.
///
/// Mutation: take each poll's time as the bucket's (`b.at = now`): the
/// late poll stamped 250 ms moves it back, the next one at 500 ms refills
/// those 250 ms again, and a poll the budget does not allow is admitted.
#[test]
fn polls_out_of_order_refill_no_interval_twice() {
    let it = item();
    let mut s = store();
    let me = under(80, 81);
    let one = opened(&mut s, request(me.clone(), "one", &it), &at_ms(0));
    let per = usize::try_from(POLLS_PER_REQUEST).unwrap();
    // Four at once, then none.
    for n in 0..per {
        assert!(s.poll(&one, &me, &at_ms(0)).is_ok(), "poll {n}");
    }
    assert_eq!(s.poll(&one, &me, &at_ms(0)), Err(Busy));
    // Half a second later, two.
    for n in 0..2 {
        assert!(s.poll(&one, &me, &at_ms(500)).is_ok(), "poll {n}");
    }
    assert_eq!(s.poll(&one, &me, &at_ms(500)), Err(Busy));
    // A poll stamped earlier arrives late: refused, and the bucket's clock
    // stays where it was.
    assert_eq!(s.poll(&one, &me, &at_ms(250)), Err(Busy));
    assert_eq!(s.poll(&one, &me, &at_ms(500)), Err(Busy));
    // The next poll is due 250 ms after 500 ms, not after 250 ms.
    assert_eq!(s.poll(&one, &me, &at_ms(749)), Err(Busy));
    assert_eq!(s.poll(&one, &me, &at_ms(750)), Ok(PendingState::Pending));
}

/// `pending_all` lists the requests oldest first, by when each was opened
/// and then by id, whatever their random ids: the order `pending.list` and
/// `envcloak pending` promise.
///
/// Mutation: list them in the store's order (by id): twenty requests
/// opened one after another come back shuffled and this fails.
#[test]
fn pending_requests_are_listed_oldest_first() {
    let it = item();
    let mut s = store();
    let mut opened_in_order = Vec::new();
    for n in 0..MAX_PENDING {
        // Each from an agent of its own: 3 per root at most.
        let agent = 3000 + 2 * i32::try_from(n).unwrap();
        let me = under(agent, agent + 1);
        let at = at_ms(10 * u64::try_from(n).unwrap());
        opened_in_order.push(opened(&mut s, request(me, "x", &it), &at));
    }
    let listed: Vec<PendingId> = s.pending_all(&at_ms(1000)).map(|p| p.id).collect();
    assert_eq!(listed, opened_in_order);
    // Opened at the same moment: by id.
    let mut s = store();
    let a = opened(&mut s, request(under(4000, 4001), "a", &it), &at_ms(0));
    let b = opened(&mut s, request(under(4002, 4003), "b", &it), &at_ms(0));
    let mut by_id = vec![a, b];
    by_id.sort_unstable();
    let listed: Vec<PendingId> = s.pending_all(&at_ms(1)).map(|p| p.id).collect();
    assert_eq!(listed, by_id);
}

/// Both stores a poll adds to are bounded: past MAX_POLL_ROOTS roots that
/// polled within the last second, a new root is refused (`busy`) rather
/// than another root's budget forgotten, and a second later they are
/// forgotten, being full again; past MAX_OUTCOMES outcomes the oldest is
/// forgotten (its waiter asks `run.request` again).
#[test]
fn the_poll_limit_and_the_outcomes_are_bounded() {
    let mut s = store();
    let now = at_ms(0);
    let id = PendingId::parse("ZZZZZZZZ").unwrap();
    let roots = i32::try_from(MAX_POLL_ROOTS).unwrap();
    for n in 0..roots {
        let agent = 1000 + 2 * n;
        assert!(s.poll(&id, &under(agent, agent + 1), &now).is_ok(), "{n}");
    }
    assert_eq!(s.waiting_counts().1, MAX_POLL_ROOTS);
    let late = under(1000 + 2 * roots, 1001 + 2 * roots);
    assert_eq!(s.poll(&id, &late, &at_ms(999)), Err(Busy));
    assert_eq!(s.poll(&id, &late, &at_ms(1000)), Ok(PendingState::Unknown));
    assert_eq!(s.waiting_counts().1, 1);

    // Outcomes: each request from an agent of its own (3 per root at
    // most), approved at once.
    let it = item();
    let mut s = store();
    let mut first = None;
    let mut last = None;
    for n in 0..i32::try_from(MAX_OUTCOMES).unwrap() + 10 {
        let now = at_ms(u64::try_from(n).unwrap());
        let agent = 5000 + 2 * n;
        let me = under(agent, agent + 1);
        let id = opened(&mut s, request(me.clone(), "x", &it), &now);
        approve(&mut s, &id, &now);
        // Grants are bounded too; this is about the outcomes.
        s.revoke(RevokeSelector::All);
        first.get_or_insert((id, me.clone()));
        last = Some((id, me));
    }
    assert_eq!(s.waiting_counts().0, MAX_OUTCOMES);
    let now = at_ms(10_000);
    let (id, me) = first.unwrap();
    assert_eq!(poll(&mut s, &id, &me, &now), PendingState::Unknown);
    let (id, me) = last.unwrap();
    assert_eq!(poll(&mut s, &id, &me, &now), PendingState::Approved);
}
