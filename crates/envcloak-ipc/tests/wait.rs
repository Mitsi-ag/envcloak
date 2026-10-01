//! Waiting for an approval (SPEC §6.1 step 4, M2 plan D-04): the
//! [`Wait`] decision on scripted answers, the [`wait_for_run`] driver on a
//! scripted transport, and five waiters under one root against the real
//! grant store ([`GrantStore`]) on a simulated clock: three requests
//! pending, two refused `too_many_pending`, every one approved in turn.
//! No real time passes and nothing is timed: the clock is the test's.
//! The real daemon and `envcloak run --wait` are in
//! `crates/envcloak-daemon/tests/pending.rs` and
//! `crates/envcloak-cli/tests/wait.rs`.
#![allow(clippy::unwrap_used)]

use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use envcloak_core::vault::{Classification, FieldId, FieldName, ItemId, Slug};
use envcloak_ipc::proto::{ErrorKind, RpcError, RunAnswer};
use envcloak_ipc::view::DecisionView;
use envcloak_ipc::wait::{
    Action, Clock, Event, FAST_POLL, Finish, MAX_BACKOFF, MAX_WAIT, Notice, SLOW_POLL, Transport,
    Wait, Waited, wait_for_run,
};
use envcloak_ipc::{ClientError, WireSecret};
use envcloak_policy::{
    AccessRequest, AgentLabel, Ancestor, ApprovalOptions, ApprovalProof, BoundBinding, BoundRef,
    CatalogSource, ChainEnd, Claims, Decision, EnvName, GrantStore, MatchBasis, Mode, Now,
    PendingId, PendingState, ProcessInstance, ProjectIdentity, ProofKind, SubjectEvidence, Uses,
    statement_digest,
};
use envcloak_sys::StartTime;

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn id(s: &str) -> PendingId {
    PendingId::parse(s).unwrap()
}

fn pending(s: &str) -> DecisionView {
    DecisionView::Pending {
        request: s.to_owned(),
    }
}

fn covered() -> DecisionView {
    DecisionView::Covered {
        grant: "01K00000000000000000000000".to_owned(),
        redact: true,
        mode: Mode::Inject,
        manifest_changed: false,
    }
}

fn rpc(kind: ErrorKind, reason: Option<&str>) -> ClientError {
    ClientError::Rpc(match reason {
        Some(r) => RpcError::with_reason(kind, r),
        None => RpcError::new(kind),
    })
}

fn busy() -> ClientError {
    rpc(ErrorKind::Busy, None)
}

fn crowded() -> ClientError {
    rpc(ErrorKind::TooManyPending, Some("pending_per_root"))
}

/// `busy` doubles the pause, up to 2 seconds, and never ends the wait;
/// the pause never gets shorter after it; `approved` asks `run.request`
/// again at once, without a pause; the request is announced once.
///
/// Mutation: treat `busy` as a refusal (finish on it): this fails at the
/// first `busy`. Mutation: poll again at the fast pace after `busy`
/// (forget the doubling): this fails at the 500 ms pause.
#[test]
fn busy_doubles_the_pause_up_to_two_seconds_and_never_refuses() {
    let mut w = Wait::new(Duration::ZERO, MAX_WAIT);
    let mut t = Duration::ZERO;
    assert_eq!(w.next(t, Event::Start), (Action::Request, None));
    let p = pending("ABCDEFGH");
    assert_eq!(
        w.next(t, Event::Answered(Ok(&p))),
        (
            Action::Sleep(FAST_POLL),
            Some(Notice::Pending(id("ABCDEFGH")))
        )
    );
    t += FAST_POLL;
    assert_eq!(w.next(t, Event::Woke), (Action::Poll(id("ABCDEFGH")), None));
    let mut pauses = Vec::new();
    for _ in 0..5 {
        let (a, n) = w.next(t, Event::Polled(Err(busy())));
        assert_eq!(n, None);
        let Action::Sleep(d) = a else {
            panic!("busy ended the wait: {a:?}")
        };
        pauses.push(d.as_millis());
        t += d;
        assert_eq!(w.next(t, Event::Woke).0, Action::Poll(id("ABCDEFGH")));
    }
    assert_eq!(pauses, [500, 1000, 2000, 2000, 2000]);
    assert_eq!(MAX_BACKOFF, ms(2000));
    // A pending answer after busy keeps the longer pause.
    assert_eq!(
        w.next(t, Event::Polled(Ok(PendingState::Pending))),
        (Action::Sleep(MAX_BACKOFF), None)
    );
    // The same request named again is not announced again.
    assert_eq!(w.next(t, Event::Answered(Ok(&p))).1, None);
    assert_eq!(
        w.next(t, Event::Polled(Ok(PendingState::Approved))),
        (Action::Request, None)
    );
    assert_eq!(
        w.next(t, Event::Answered(Ok(&covered()))),
        (Action::Finish(Finish::Decided), None)
    );
}

/// `busy` from `run.request` (the daemon answers it while Argon2id runs
/// for an unlock or a person's approval) is waited out the same way: the
/// pause doubles and `run.request` is asked again, never a poll in its
/// place, whether it came first or when asking again after `approved`.
///
/// Mutation: treat `busy` from `run.request` as a failure: this fails at
/// the first one.
#[test]
fn busy_from_run_request_is_asked_again() {
    let mut w = Wait::new(Duration::ZERO, MAX_WAIT);
    let t = Duration::ZERO;
    w.next(t, Event::Start);
    assert_eq!(
        w.next(t, Event::Answered(Err(busy()))),
        (Action::Sleep(ms(500)), None)
    );
    assert_eq!(w.next(ms(500), Event::Woke).0, Action::Request);
    let p = pending("ABCDEFGH");
    assert_eq!(
        w.next(ms(500), Event::Answered(Ok(&p))).1,
        Some(Notice::Pending(id("ABCDEFGH")))
    );
    assert_eq!(
        w.next(ms(1000), Event::Woke).0,
        Action::Poll(id("ABCDEFGH"))
    );
    assert_eq!(
        w.next(ms(1000), Event::Polled(Ok(PendingState::Approved)))
            .0,
        Action::Request
    );
    // Busy while asking again after the approval: asked again, not
    // polled.
    assert_eq!(
        w.next(ms(1000), Event::Answered(Err(busy()))).0,
        Action::Sleep(ms(1000))
    );
    assert_eq!(w.next(ms(2000), Event::Woke).0, Action::Request);
    assert_eq!(
        w.next(ms(2000), Event::Answered(Ok(&covered()))).0,
        Action::Finish(Finish::Decided)
    );
    // At the deadline: timed out for a request named, the error if none.
    let mut w = Wait::new(Duration::ZERO, ms(300));
    w.next(t, Event::Start);
    assert_eq!(
        w.next(t, Event::Answered(Err(busy()))).0,
        Action::Sleep(ms(300))
    );
    assert_eq!(w.next(ms(300), Event::Woke).0, Action::Request);
    assert_eq!(
        w.next(ms(300), Event::Answered(Err(busy()))).0,
        Action::Finish(Finish::Failed(busy()))
    );
}

/// Without `busy` the pauses are 250 ms for the first second, 500 ms for
/// the next, then 1 s: a request approved now is seen within one step.
#[test]
fn the_nominal_pauses_go_from_250_ms_to_one_second() {
    let mut w = Wait::new(Duration::ZERO, MAX_WAIT);
    let mut t = Duration::ZERO;
    w.next(t, Event::Start);
    let (mut a, _) = w.next(t, Event::Answered(Ok(&pending("ABCDEFGH"))));
    let mut pauses = Vec::new();
    for _ in 0..9 {
        let Action::Sleep(d) = a else { panic!("{a:?}") };
        pauses.push(d.as_millis());
        t += d;
        assert_eq!(w.next(t, Event::Woke).0, Action::Poll(id("ABCDEFGH")));
        a = w.next(t, Event::Polled(Ok(PendingState::Pending))).0;
    }
    assert_eq!(
        pauses,
        [250, 250, 250, 250, 500, 500, 1000, 1000, 1000],
        "every 250 ms for the first second, then 500 ms, then {SLOW_POLL:?}"
    );
}

/// `too_many_pending` (a pending cap full, nothing opened) is announced
/// once and asked again with the busy backoff, never taken as a refusal;
/// once a place is free the request opens and is announced.
#[test]
fn too_many_pending_is_asked_again_with_the_busy_backoff() {
    let mut w = Wait::new(Duration::ZERO, MAX_WAIT);
    let mut t = Duration::ZERO;
    assert_eq!(w.next(t, Event::Start).0, Action::Request);
    let (a, n) = w.next(t, Event::Answered(Err(crowded())));
    let ClientError::Rpc(r) = crowded() else {
        unreachable!()
    };
    assert_eq!(n, Some(Notice::TooManyPending(r)));
    assert_eq!(a, Action::Sleep(ms(500)));
    let mut pauses = vec![500];
    for _ in 0..3 {
        t += ms(*pauses.last().unwrap());
        assert_eq!(w.next(t, Event::Woke), (Action::Request, None));
        let (a, n) = w.next(t, Event::Answered(Err(crowded())));
        assert_eq!(n, None, "announced once");
        let Action::Sleep(d) = a else { panic!("{a:?}") };
        pauses.push(u64::try_from(d.as_millis()).unwrap());
    }
    assert_eq!(pauses, [500, 1000, 2000, 2000]);
    t += MAX_BACKOFF;
    assert_eq!(w.next(t, Event::Woke).0, Action::Request);
    assert_eq!(
        w.next(t, Event::Answered(Ok(&pending("ABCDEFGH")))).1,
        Some(Notice::Pending(id("ABCDEFGH")))
    );
}

/// The deadline: the last pause is cut at it, a last poll is made there,
/// and a request still pending then ends the wait as timed out; one over
/// a cap at the deadline ends as `too_many_pending`. Denied and expired
/// end the wait at once; `unknown` asks again, and a new request is
/// announced (once).
#[test]
fn the_deadline_denied_expired_and_unknown() {
    // Timed out, after a poll at the deadline itself.
    let wait = ms(1100);
    let mut w = Wait::new(Duration::ZERO, wait);
    let mut t = Duration::ZERO;
    w.next(t, Event::Start);
    let (mut a, _) = w.next(t, Event::Answered(Ok(&pending("ABCDEFGH"))));
    let mut polls = Vec::new();
    loop {
        match a {
            Action::Sleep(d) => {
                t += d;
                assert_eq!(w.next(t, Event::Woke).0, Action::Poll(id("ABCDEFGH")));
                polls.push(t.as_millis());
                a = w.next(t, Event::Polled(Ok(PendingState::Pending))).0;
            }
            Action::Finish(f) => {
                assert_eq!(f, Finish::TimedOut(id("ABCDEFGH")));
                break;
            }
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(polls, [250, 500, 750, 1000, 1100]);
    // Over a cap at the deadline.
    let mut w = Wait::new(Duration::ZERO, ms(400));
    w.next(Duration::ZERO, Event::Start);
    assert_eq!(
        w.next(Duration::ZERO, Event::Answered(Err(crowded()))).0,
        Action::Sleep(ms(400))
    );
    assert_eq!(w.next(ms(400), Event::Woke).0, Action::Request);
    let ClientError::Rpc(r) = crowded() else {
        unreachable!()
    };
    assert_eq!(
        w.next(ms(400), Event::Answered(Err(crowded()))).0,
        Action::Finish(Finish::TooManyPending(r))
    );
    // Denied, expired; unknown asks again and announces a new request.
    for (state, end) in [
        (PendingState::Denied, Finish::Denied(id("ABCDEFGH"))),
        (PendingState::Expired, Finish::Expired(id("ABCDEFGH"))),
    ] {
        let mut w = Wait::new(Duration::ZERO, MAX_WAIT);
        w.next(Duration::ZERO, Event::Start);
        w.next(Duration::ZERO, Event::Answered(Ok(&pending("ABCDEFGH"))));
        assert_eq!(
            w.next(FAST_POLL, Event::Woke).0,
            Action::Poll(id("ABCDEFGH"))
        );
        assert_eq!(
            w.next(FAST_POLL, Event::Polled(Ok(state))).0,
            Action::Finish(end)
        );
    }
    let mut w = Wait::new(Duration::ZERO, MAX_WAIT);
    w.next(Duration::ZERO, Event::Start);
    w.next(Duration::ZERO, Event::Answered(Ok(&pending("ABCDEFGH"))));
    w.next(FAST_POLL, Event::Woke);
    assert_eq!(
        w.next(FAST_POLL, Event::Polled(Ok(PendingState::Unknown)))
            .0,
        Action::Request
    );
    assert_eq!(
        w.next(FAST_POLL, Event::Answered(Ok(&pending("JKMNPQRS"))))
            .1,
        Some(Notice::Pending(id("JKMNPQRS")))
    );
    // Any other failure ends the wait with it; so does an id that is not
    // one, or not in its canonical form.
    let mut w = Wait::new(Duration::ZERO, MAX_WAIT);
    w.next(Duration::ZERO, Event::Start);
    let locked = rpc(ErrorKind::VaultLocked, None);
    assert_eq!(
        w.next(Duration::ZERO, Event::Answered(Err(locked))).0,
        Action::Finish(Finish::Failed(locked))
    );
    for bad in ["not an id", "abcdefgh", "ABCDEFGHJ"] {
        let mut w = Wait::new(Duration::ZERO, MAX_WAIT);
        w.next(Duration::ZERO, Event::Start);
        assert_eq!(
            w.next(Duration::ZERO, Event::Answered(Ok(&pending(bad)))).0,
            Action::Finish(Finish::Failed(ClientError::Protocol)),
            "{bad}"
        );
    }
}

/// A transport that answers from scripts, and counts the calls.
struct Scripted {
    requests: VecDeque<Result<RunAnswer, ClientError>>,
    polls: VecDeque<Result<PendingState, ClientError>>,
    asked: Vec<&'static str>,
}

impl Transport for Scripted {
    fn request(&mut self) -> Result<RunAnswer, ClientError> {
        self.asked.push("request");
        self.requests.pop_front().unwrap()
    }

    fn poll(&mut self, _: &PendingId) -> Result<PendingState, ClientError> {
        self.asked.push("poll");
        self.polls.pop_front().unwrap()
    }
}

/// A clock that moves only when the wait pauses.
#[derive(Default)]
struct TestClock {
    now: Duration,
    pauses: Vec<Duration>,
}

impl Clock for TestClock {
    fn now(&self) -> Duration {
        self.now
    }

    fn sleep(&mut self, d: Duration) {
        self.pauses.push(d);
        self.now += d;
    }
}

/// The driver: the covered answer comes back whole, with its value; the
/// notices are told once each; a denial ends it.
#[test]
fn the_driver_returns_the_deciding_answer_and_tells_each_notice_once() {
    let value = envcloak_core::SecretBytes::copy_from(b"a value of the test, not a key");
    let answer = RunAnswer {
        decision: covered(),
        values: vec![envcloak_ipc::proto::ReleasedValue {
            env_name: "OPENAI_API_KEY".to_owned(),
            slug: "openai/acme-web".to_owned(),
            allow_short: false,
            value: WireSecret::new(value),
        }],
    };
    let mut t = Scripted {
        requests: VecDeque::from([
            Err(crowded()),
            Ok(RunAnswer::decided(pending("ABCDEFGH"))),
            Ok(answer),
        ]),
        polls: VecDeque::from([
            Ok(PendingState::Pending),
            Err(busy()),
            Ok(PendingState::Approved),
        ]),
        asked: Vec::new(),
    };
    let mut c = TestClock::default();
    let mut told = Vec::new();
    let got = wait_for_run(&mut t, &mut c, MAX_WAIT, &mut |n| told.push(n)).unwrap();
    let Waited::Answer(a) = got else {
        panic!("{got:?}")
    };
    assert_eq!(a.decision, covered());
    assert_eq!(a.values.len(), 1);
    assert_eq!(
        t.asked,
        ["request", "request", "poll", "poll", "poll", "request"]
    );
    let ms: Vec<u128> = c.pauses.iter().map(Duration::as_millis).collect();
    assert_eq!(ms, [500, 500, 500, 1000]);
    assert_eq!(told.len(), 2);
    assert!(matches!(told[0], Notice::TooManyPending(_)));
    assert_eq!(told[1], Notice::Pending(id("ABCDEFGH")));

    let mut t = Scripted {
        requests: VecDeque::from([Ok(RunAnswer::decided(pending("ABCDEFGH")))]),
        polls: VecDeque::from([Ok(PendingState::Denied)]),
        asked: Vec::new(),
    };
    let got = wait_for_run(&mut t, &mut TestClock::default(), MAX_WAIT, &mut |_| {}).unwrap();
    assert!(
        matches!(got, Waited::Denied(i) if i == id("ABCDEFGH")),
        "{got:?}"
    );
}

// ---------------------------------------------- five waiters, one root

fn inst(pid: i32) -> ProcessInstance {
    ProcessInstance {
        pid,
        start_time: StartTime::from_raw(10 * u64::try_from(pid).unwrap()),
        pidversion: None,
        exe: None,
    }
}

fn anc(pid: i32, sid: i32, agent: bool) -> Ancestor {
    Ancestor {
        instance: inst(pid),
        sid: Some(sid),
        terminal: None,
        agent: agent.then(|| AgentLabel {
            id: "fixture".to_owned(),
            name: "fixture".to_owned(),
            source: CatalogSource::Builtin,
            basis: MatchBasis::Executable,
        }),
    }
}

/// Command `pid` of the agent 80, in a session of its own: the agent is
/// every waiter's root.
fn under_agent(pid: i32) -> SubjectEvidence {
    SubjectEvidence::from_chain(
        vec![
            anc(pid, pid, false),
            anc(80, 70, true),
            anc(70, 70, false),
            anc(1, 1, false),
        ],
        ChainEnd::Top,
        false,
        Claims::none(),
        None,
    )
    .unwrap()
}

fn person() -> SubjectEvidence {
    SubjectEvidence::from_chain(
        vec![anc(95, 90, false), anc(90, 90, false), anc(1, 1, false)],
        ChainEnd::Top,
        true,
        Claims::none(),
        None,
    )
    .unwrap()
}

fn request_of(n: i32, item: (ItemId, FieldId)) -> AccessRequest {
    AccessRequest {
        subject: under_agent(100 + n),
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
        argv_display: vec![format!("./job-{n}")],
        new_project: false,
    }
}

fn now_at(t: Duration) -> Now {
    Now {
        wall: SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000) + t,
        awake: Duration::from_secs(1000) + t,
        including_sleep: Duration::from_secs(1000) + t,
    }
}

/// What one simulated waiter saw.
#[derive(Debug, Default)]
struct Seen {
    finish: Option<Finish>,
    /// The first answer to its first `run.request`: pending, or over the
    /// cap.
    first: Option<&'static str>,
    /// Each `pending.state` answer, as its word or `busy`.
    polls: Vec<&'static str>,
    /// Each pause asked for, and whether `busy` or `too_many_pending`
    /// came just before it.
    pauses: Vec<(Duration, bool)>,
}

/// Five waiters under one root, each its own state machine with its own
/// process (so its own requests), started together, against one store,
/// on the simulated clock, step by step. A person approves each pending
/// request (`once`) three seconds after it opened. `noisy` adds a sixth
/// process of the same root that polls an unknown id every 10 ms for the
/// first five seconds and never backs off.
fn five_waiters(noisy: bool) -> Vec<Seen> {
    const WAITERS: usize = 5;
    let item = (ItemId::generate(), FieldId::generate());
    let mut store = GrantStore::new();
    store.set_epochs(1, 1);
    let mut waits: Vec<Wait> = (0..WAITERS)
        .map(|_| Wait::new(Duration::ZERO, ms(120_000)))
        .collect();
    let mut seen: Vec<Seen> = (0..WAITERS).map(|_| Seen::default()).collect();
    // Each waiter's next action and when it is due.
    let mut due: Vec<(Duration, Action)> = waits
        .iter_mut()
        .map(|w| (Duration::ZERO, w.next(Duration::ZERO, Event::Start).0))
        .collect();
    let mut opened_at: Vec<(PendingId, Duration)> = Vec::new();
    let mut busy_before = [false; WAITERS];
    let noise = under_agent(150);
    let nobody = PendingId::parse("ZZZZZZZZ").unwrap();
    let mut t = Duration::ZERO;
    while t <= ms(120_000) && seen.iter().any(|s| s.finish.is_none()) {
        let now = now_at(t);
        // The person's approvals, as the requests turn three seconds old.
        let ripe: Vec<PendingId> = opened_at
            .iter()
            .filter(|(_, at)| t >= *at + ms(3000))
            .map(|(id, _)| *id)
            .collect();
        opened_at.retain(|(id, _)| !ripe.contains(id));
        for id in ripe {
            let opts = ApprovalOptions {
                uses: Uses::Once,
                ttl_secs: 600,
                live: Vec::new(),
            };
            let Some(d) = store.pending_descriptor(&id, &now) else {
                continue;
            };
            let digest = statement_digest(d, &opts);
            let proof = ApprovalProof {
                approver: person(),
                kind: ProofKind::Passphrase,
            };
            store.approve(&id, proof, opts, digest, &now).unwrap();
        }
        if noisy && t < ms(5000) && t.as_millis() % 10 == 0 {
            let _ = store.poll(&nobody, &noise, &now);
        }
        for n in 0..WAITERS {
            // Every action due now, in order: a call takes no time.
            while due[n].0 <= t && seen[n].finish.is_none() {
                let caller = under_agent(100 + i32::try_from(n).unwrap());
                let (action, _) = match due[n].1 {
                    Action::Request => {
                        let (view, err) =
                            match store.decide(request_of(i32::try_from(n).unwrap(), item), &now) {
                                Decision::Covered(g) => {
                                    assert!(store.consume(g));
                                    (Some(covered()), None)
                                }
                                Decision::Pending(id) => {
                                    if !opened_at.iter().any(|(o, _)| *o == id) {
                                        opened_at.push((id, t));
                                    }
                                    (Some(pending(&id.to_string())), None)
                                }
                                Decision::TooManyPending(cap) => (
                                    None,
                                    Some(rpc(ErrorKind::TooManyPending, Some(cap.token()))),
                                ),
                                Decision::Denied(r) => (
                                    Some(DecisionView::Denied {
                                        reason: r.token().to_owned(),
                                    }),
                                    None,
                                ),
                            };
                        seen[n].first.get_or_insert(if err.is_some() {
                            "too_many_pending"
                        } else {
                            "answered"
                        });
                        busy_before[n] = err.is_some();
                        let answer = match (&view, err) {
                            (Some(v), None) => Ok(v),
                            (_, Some(e)) => Err(e),
                            (None, None) => unreachable!(),
                        };
                        waits[n].next(t, Event::Answered(answer))
                    }
                    Action::Poll(id) => {
                        let r = store.poll(&id, &caller, &now);
                        seen[n].polls.push(r.map_or("busy", PendingState::word));
                        busy_before[n] = r.is_err();
                        waits[n].next(t, Event::Polled(r.map_err(|_| busy())))
                    }
                    Action::Sleep(d) => {
                        seen[n].pauses.push((d, busy_before[n]));
                        busy_before[n] = false;
                        due[n].0 = t + d;
                        waits[n].next(t + d, Event::Woke)
                    }
                    Action::Finish(f) => {
                        seen[n].finish = Some(f);
                        continue;
                    }
                };
                due[n].1 = action;
            }
        }
        t += ms(1);
    }
    seen
}

/// D-04's five-waiter case against the real grant store: three requests
/// go pending and two waiters get `too_many_pending` and ask again; as
/// each is approved a place frees and the next waiter's request opens.
/// Every waiter's run is covered in the end; no wait ends any other way;
/// the only refusal any poll sees is `busy`; and with the nominal
/// schedule, three waiters of one root polling every 250 ms see none,
/// because the root's budget grows with each live request.
///
/// Mutation: size the poll bucket per root instead of per pending request
/// (`PollLimiter::take` with a fixed rate): the three waiters' first
/// second, 12 polls, exceeds a one-request budget and `busy` appears.
#[test]
fn five_waiters_under_one_root_all_reach_their_outcome() {
    let seen = five_waiters(false);
    for (n, s) in seen.iter().enumerate() {
        assert_eq!(s.finish, Some(Finish::Decided), "waiter {n}: {s:?}");
        assert!(
            s.polls
                .iter()
                .all(|p| ["pending", "approved", "busy"].contains(p)),
            "waiter {n}: {s:?}"
        );
        assert!(!s.polls.contains(&"busy"), "waiter {n}: {s:?}");
    }
    let firsts: Vec<&str> = seen.iter().map(|s| s.first.unwrap()).collect();
    assert_eq!(
        firsts.iter().filter(|f| **f == "too_many_pending").count(),
        2,
        "{firsts:?}"
    );
}

/// The same five waiters while another process of their root polls far
/// too fast: their polls are refused, only with `busy`, and each backs off
/// on it (the pause after a `busy` doubles, up to 2 seconds, and never
/// shrinks), and every waiter still reaches its outcome.
///
/// Mutation: treat `busy` as a refusal: the waits end early and this
/// fails. Mutation: keep the pause after `busy`: the doubling check fails.
#[test]
fn five_waiters_back_off_on_busy_and_still_reach_their_outcome() {
    let seen = five_waiters(true);
    let mut busy_seen = 0;
    for (n, s) in seen.iter().enumerate() {
        assert_eq!(s.finish, Some(Finish::Decided), "waiter {n}: {s:?}");
        assert!(
            s.polls
                .iter()
                .all(|p| ["pending", "approved", "busy"].contains(p)),
            "waiter {n}: {s:?}"
        );
        busy_seen += s.polls.iter().filter(|p| **p == "busy").count();
        let mut last = Duration::ZERO;
        for (d, after_busy) in &s.pauses {
            assert!(*d >= last, "waiter {n}: a pause shrank: {:?}", s.pauses);
            if *after_busy {
                assert!(
                    *d == (last * 2).min(MAX_BACKOFF) || (last == Duration::ZERO && *d == ms(500)),
                    "waiter {n}: no backoff on busy: {:?}",
                    s.pauses
                );
            }
            assert!(*d <= MAX_BACKOFF, "waiter {n}: {:?}", s.pauses);
            last = *d;
        }
    }
    assert!(busy_seen > 0, "the noisy poller made no waiter busy");
}
