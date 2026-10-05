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

use std::cell::Cell;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, SystemTime};

use envcloak_core::crypto::ItemClass;
use envcloak_core::vault::{
    Classification, FieldId, FieldKind, FieldMeta, FieldName, ItemDetails, ItemId, ItemMeta, Slug,
};
use envcloak_ipc::proto::{ErrorKind, RpcError, RunAnswer};
use envcloak_ipc::view::DecisionView;
use envcloak_ipc::wait::{
    Action, CALL_GRACE, Clock, Event, FAST_POLL, Finish, MAX_BACKOFF, MAX_WAIT, Notice, SLOW_POLL,
    Transport, Wait, Waited, wait_for_run,
};
use envcloak_ipc::{ClientError, FrameError, WireSecret};
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

/// A transport that answers from scripts, and counts the calls. Each
/// call takes the time its script says (none unless `delays` has one),
/// on the clock it shares with a [`TestClock`]; `traced` says, check by
/// check, whether a tracer is attached (never, once it runs out).
#[derive(Default)]
struct Scripted {
    requests: VecDeque<Result<RunAnswer, ClientError>>,
    polls: VecDeque<Result<PendingState, ClientError>>,
    asked: Vec<&'static str>,
    /// How long each call takes, in the order of the calls.
    delays: VecDeque<Duration>,
    /// Each call's time left, and when it was made.
    within: Vec<(Duration, Duration)>,
    traced: VecDeque<bool>,
    clock: Rc<Cell<Duration>>,
}

impl Scripted {
    fn new(
        requests: impl IntoIterator<Item = Result<RunAnswer, ClientError>>,
        polls: impl IntoIterator<Item = Result<PendingState, ClientError>>,
    ) -> Scripted {
        Scripted {
            requests: requests.into_iter().collect(),
            polls: polls.into_iter().collect(),
            ..Scripted::default()
        }
    }

    fn call(&mut self, what: &'static str, within: Duration) {
        self.asked.push(what);
        self.within.push((self.clock.get(), within));
        let d = self.delays.pop_front().unwrap_or_default();
        self.clock.set(self.clock.get() + d);
    }

    /// A clock on this transport's time.
    fn clock(&self) -> TestClock {
        TestClock {
            now: Rc::clone(&self.clock),
            pauses: Vec::new(),
        }
    }
}

impl Transport for Scripted {
    fn traced(&mut self) -> bool {
        self.asked.push("traced?");
        self.traced.pop_front().unwrap_or(false)
    }

    fn request(&mut self, within: Duration) -> Result<RunAnswer, ClientError> {
        self.call("request", within);
        self.requests.pop_front().unwrap()
    }

    fn poll(&mut self, _: &PendingId, within: Duration) -> Result<PendingState, ClientError> {
        self.call("poll", within);
        self.polls.pop_front().unwrap()
    }
}

/// A clock that moves when the wait pauses, and when a scripted call
/// takes time.
#[derive(Default)]
struct TestClock {
    now: Rc<Cell<Duration>>,
    pauses: Vec<Duration>,
}

impl Clock for TestClock {
    fn now(&self) -> Duration {
        self.now.get()
    }

    fn sleep(&mut self, d: Duration) {
        self.pauses.push(d);
        self.now.set(self.now.get() + d);
    }
}

/// The calls a scripted transport saw, without the tracer checks.
fn calls(t: &Scripted) -> Vec<&'static str> {
    t.asked
        .iter()
        .copied()
        .filter(|a| *a != "traced?")
        .collect()
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
        proposals: Vec::new(),
    };
    let mut t = Scripted::new(
        [
            Err(crowded()),
            Ok(RunAnswer::decided(pending("ABCDEFGH"))),
            Ok(answer),
        ],
        [
            Ok(PendingState::Pending),
            Err(busy()),
            Ok(PendingState::Approved),
        ],
    );
    let mut c = t.clock();
    let mut told = Vec::new();
    let got = wait_for_run(&mut t, &mut c, MAX_WAIT, &mut |n| told.push(n)).unwrap();
    let Waited::Answer(a) = got else {
        panic!("{got:?}")
    };
    assert_eq!(a.decision, covered());
    assert_eq!(a.values.len(), 1);
    assert_eq!(
        calls(&t),
        ["request", "request", "poll", "poll", "poll", "request"]
    );
    // The tracer is looked for before each `run.request`, and only then.
    assert_eq!(
        t.asked,
        [
            "traced?", "request", "traced?", "request", "poll", "poll", "poll", "traced?",
            "request"
        ]
    );
    let ms: Vec<u128> = c.pauses.iter().map(Duration::as_millis).collect();
    assert_eq!(ms, [500, 500, 500, 1000]);
    assert_eq!(told.len(), 2);
    assert!(matches!(told[0], Notice::TooManyPending(_)));
    assert_eq!(told[1], Notice::Pending(id("ABCDEFGH")));

    let mut t = Scripted::new(
        [Ok(RunAnswer::decided(pending("ABCDEFGH")))],
        [Ok(PendingState::Denied)],
    );
    let mut c = t.clock();
    let got = wait_for_run(&mut t, &mut c, MAX_WAIT, &mut |_| {}).unwrap();
    assert!(
        matches!(got, Waited::Denied(i) if i == id("ABCDEFGH")),
        "{got:?}"
    );
}

fn covered_with_a_value() -> RunAnswer {
    RunAnswer {
        decision: covered(),
        values: vec![envcloak_ipc::proto::ReleasedValue {
            env_name: "OPENAI_API_KEY".to_owned(),
            slug: "openai/acme-web".to_owned(),
            allow_short: false,
            value: WireSecret::new(envcloak_core::SecretBytes::copy_from(
                b"a value of the test, not a key",
            )),
        }],
        proposals: Vec::new(),
    }
}

/// Each call of a wait is given only the time left to the wait's limit
/// (the deadline plus CALL_GRACE), for its connect, writes and reads; the
/// last poll, made at the deadline itself, CALL_GRACE.
///
/// Mutation: pass each call a fixed time (the client's 300 seconds)
/// instead of the time left: the times recorded differ and this fails.
#[test]
fn every_call_is_given_only_the_time_left_to_the_limit() {
    let wait = ms(1100);
    let mut t = Scripted::new(
        [Ok(RunAnswer::decided(pending("ABCDEFGH")))],
        (0..5).map(|_| Ok(PendingState::Pending)),
    );
    let mut c = t.clock();
    let got = wait_for_run(&mut t, &mut c, wait, &mut |_| {}).unwrap();
    assert!(
        matches!(got, Waited::TimedOut(i) if i == id("ABCDEFGH")),
        "{got:?}"
    );
    let limit = wait + CALL_GRACE;
    assert_eq!(t.within.len(), 6, "{:?}", t.within);
    for (at, within) in &t.within {
        assert_eq!(*within, limit - *at, "{:?}", t.within);
    }
    assert_eq!(t.within.last(), Some(&(wait, CALL_GRACE)));
    let w = Wait::new(ms(500), wait);
    assert_eq!(w.deadline(), ms(1600));
    assert_eq!(w.limit(), ms(1600) + CALL_GRACE);
    assert_eq!(w.time_left(ms(1600)), Some(CALL_GRACE));
    assert_eq!(w.time_left(w.limit()), None);
    assert_eq!(w.time_left(w.limit() - Duration::from_micros(999)), None);
}

/// `unknown` at or after the deadline ends the wait as timed out and is
/// not asked again; before it, `run.request` is asked again. `approved`
/// after the deadline is asked again once (the approval came within the
/// wait), its answer due by the limit.
///
/// Mutation: ask `run.request` again on `unknown` whenever it comes: the
/// late poll is followed by another request and this fails.
#[test]
fn unknown_after_the_deadline_is_not_asked_again() {
    let mut w = Wait::new(Duration::ZERO, ms(1000));
    w.next(Duration::ZERO, Event::Start);
    w.next(Duration::ZERO, Event::Answered(Ok(&pending("ABCDEFGH"))));
    let mut early = w.clone();
    assert_eq!(
        early
            .next(ms(999), Event::Polled(Ok(PendingState::Unknown)))
            .0,
        Action::Request
    );
    assert_eq!(
        w.next(ms(1000), Event::Polled(Ok(PendingState::Unknown))).0,
        Action::Finish(Finish::TimedOut(id("ABCDEFGH")))
    );

    // The driver: a poll made before the deadline, answered `unknown`
    // after it.
    let mut t = Scripted::new(
        [Ok(RunAnswer::decided(pending("ABCDEFGH")))],
        [Ok(PendingState::Unknown)],
    );
    t.delays = VecDeque::from([Duration::ZERO, ms(1500)]);
    let mut c = t.clock();
    let got = wait_for_run(&mut t, &mut c, ms(1000), &mut |_| {}).unwrap();
    assert!(
        matches!(got, Waited::TimedOut(i) if i == id("ABCDEFGH")),
        "{got:?}"
    );
    assert_eq!(calls(&t), ["request", "poll"]);

    // `approved` answered after the deadline is not asked again either:
    // the approval may have come after the deadline (review of M2-03).
    let mut t = Scripted::new(
        [
            Ok(RunAnswer::decided(pending("ABCDEFGH"))),
            Ok(covered_with_a_value()),
        ],
        [Ok(PendingState::Approved)],
    );
    t.delays = VecDeque::from([Duration::ZERO, ms(1500)]);
    let mut c = t.clock();
    let got = wait_for_run(&mut t, &mut c, ms(1000), &mut |_| {}).unwrap();
    assert!(
        matches!(got, Waited::TimedOut(i) if i == id("ABCDEFGH")),
        "{got:?}"
    );
    assert_eq!(calls(&t), ["request", "poll"]);
    // Answered by the deadline, it is asked again, once, with the time
    // left to the limit.
    let mut t = Scripted::new(
        [
            Ok(RunAnswer::decided(pending("ABCDEFGH"))),
            Ok(covered_with_a_value()),
        ],
        [Ok(PendingState::Approved)],
    );
    t.delays = VecDeque::from([Duration::ZERO, ms(750)]);
    let mut c = t.clock();
    let got = wait_for_run(&mut t, &mut c, ms(1000), &mut |_| {}).unwrap();
    assert!(matches!(got, Waited::Answer(_)), "{got:?}");
    assert_eq!(calls(&t), ["request", "poll", "request"]);
    assert_eq!(
        t.within.last(),
        Some(&(ms(1000), ms(1000) + CALL_GRACE - ms(1000)))
    );
}

/// An answer read after the limit is dropped unused and the wait ends
/// `Unanswered`: a covered one's values never reach the caller, so nothing
/// is started late. A call given up at its timeout (the time left to the
/// limit) ends the wait the same way; a connection that fails before the
/// deadline is that failure.
///
/// Mutation: keep an answer read after the limit (drop the check after
/// the call): the covered answer comes back and this fails.
#[test]
fn an_answer_after_the_limit_starts_nothing() {
    // Approved at 250 ms; asked again, the covered answer is read 6 s
    // later, past the limit of 1 s plus CALL_GRACE.
    let mut t = Scripted::new(
        [
            Ok(RunAnswer::decided(pending("ABCDEFGH"))),
            Ok(covered_with_a_value()),
        ],
        [Ok(PendingState::Approved)],
    );
    t.delays = VecDeque::from([Duration::ZERO, Duration::ZERO, ms(6000)]);
    let mut c = t.clock();
    let got = wait_for_run(&mut t, &mut c, ms(1000), &mut |_| {}).unwrap();
    assert!(matches!(got, Waited::Unanswered), "{got:?}");
    assert_eq!(calls(&t), ["request", "poll", "request"]);

    // A poll given up at its timeout, at the limit.
    let timeout = ClientError::Frame(FrameError::Io(std::io::ErrorKind::WouldBlock));
    let mut t = Scripted::new(
        [Ok(RunAnswer::decided(pending("ABCDEFGH")))],
        [Err(timeout)],
    );
    t.delays = VecDeque::from([Duration::ZERO, ms(1000) + CALL_GRACE - FAST_POLL]);
    let mut c = t.clock();
    let got = wait_for_run(&mut t, &mut c, ms(1000), &mut |_| {}).unwrap();
    assert!(matches!(got, Waited::Unanswered), "{got:?}");

    // A connection that fails before the deadline is that failure.
    let cut = ClientError::Frame(FrameError::Truncated);
    let mut t = Scripted::new([Ok(RunAnswer::decided(pending("ABCDEFGH")))], [Err(cut)]);
    let mut c = t.clock();
    let got = wait_for_run(&mut t, &mut c, ms(1000), &mut |_| {});
    assert_eq!(got.unwrap_err(), cut);
}

/// Before each `run.request`, whose answer may carry values, the driver
/// looks for a tracer: one attached while the wait went on stops it
/// before the request after the approval is sent.
///
/// Mutation: skip the check (send `run.request` whatever `traced` says):
/// the covered answer comes back and this fails.
#[test]
fn a_tracer_attached_while_waiting_stops_the_wait_before_a_request() {
    let mut t = Scripted::new(
        [
            Ok(RunAnswer::decided(pending("ABCDEFGH"))),
            Ok(covered_with_a_value()),
        ],
        [Ok(PendingState::Pending), Ok(PendingState::Approved)],
    );
    t.traced = VecDeque::from([false, true]);
    let mut c = t.clock();
    let got = wait_for_run(&mut t, &mut c, MAX_WAIT, &mut |_| {}).unwrap();
    assert!(matches!(got, Waited::Traced), "{got:?}");
    assert_eq!(calls(&t), ["request", "poll", "poll"]);
    assert_eq!(
        t.requests.len(),
        1,
        "the request after the approval was sent"
    );
    // Traced from the start: nothing is asked at all.
    let mut t = Scripted::new([], []);
    t.traced = VecDeque::from([true]);
    let mut c = t.clock();
    let got = wait_for_run(&mut t, &mut c, MAX_WAIT, &mut |_| {}).unwrap();
    assert!(matches!(got, Waited::Traced), "{got:?}");
    assert!(calls(&t).is_empty());
}

/// Over a real socket, a daemon that takes the connection and then never
/// answers holds a wait of one second no longer than its limit (the
/// deadline plus CALL_GRACE), not the client's 300-second call timeout:
/// the wait ends `Unanswered`.
///
/// Mutation: connect each call of `Fresh` with `Client::connect` (its
/// 300-second timeout): the wait is still blocked at this test's
/// 60-second bound and this fails.
#[test]
fn a_silent_daemon_holds_a_wait_no_longer_than_its_limit() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::sync::mpsc;
    use std::time::Instant;

    use envcloak_ipc::RunPaths;
    use envcloak_ipc::proto::RunRequestParams;
    use envcloak_ipc::wait::{Fresh, SystemClock};

    let home = envcloak_testkit::TestHome::new();
    let p = RunPaths::under(home.root().join("run").join("envcloak")).unwrap();
    std::fs::create_dir_all(&p.dir).unwrap();
    std::fs::set_permissions(&p.dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let l = UnixListener::bind(&p.socket).unwrap();
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let server = std::thread::spawn(move || {
        // Takes the one connection and holds it, unanswered.
        let held = l.accept().unwrap();
        let _ = done_rx.recv();
        drop(held);
    });
    let (tx, rx) = mpsc::channel();
    let paths = p.clone();
    let started = Instant::now();
    std::thread::spawn(move || {
        let params = RunRequestParams {
            manifest: "/nowhere/envcloak.toml".to_owned(),
            profile: None,
            refs: Vec::new(),
            env_file: None,
            argv: vec!["./emit".to_owned()],
            claims: Vec::new(),
        };
        let mut t = Fresh {
            paths: &paths,
            params: &params,
        };
        let got = wait_for_run(
            &mut t,
            &mut SystemClock::new(),
            Duration::from_secs(1),
            &mut |_| {},
        );
        let _ = tx.send(format!("{got:?}"));
    });
    let got = rx
        .recv_timeout(Duration::from_secs(60))
        .expect("the wait outlasted its limit by far");
    let took = started.elapsed();
    let _ = done_tx.send(());
    server.join().unwrap();
    assert_eq!(got, "Ok(Unanswered)");
    assert!(
        took >= Duration::from_secs(1) && took < Duration::from_secs(1) + CALL_GRACE * 2,
        "{took:?}"
    );
}

/// A call the daemon did not take is asked again after the busy pause,
/// until the deadline: a connection closed, reset or no longer connected
/// before any answer (as the daemon closes one at its connection limit;
/// macOS sometimes reports that close, racing the request, as not
/// connected), at once or on the request, and, once the daemon has
/// answered this wait, nothing listening there.
/// Before any answer, nothing listening is the failure at once, as it is
/// without waiting; a socket or daemon that fails a check, and an answer
/// cut short, are never asked again; and a call not taken at the deadline
/// ends the wait with that failure.
///
/// Mutation: end the wait on a connection closed before any answer
/// (`not_taken` always false): the first call ends it and this fails.
/// Mutation: leave `NotConnected` out of `not_taken`: the third request
/// ends the wait and this fails.
#[test]
fn a_call_the_daemon_did_not_take_is_asked_again_until_the_deadline() {
    use std::io::ErrorKind as Io;
    let closed = ClientError::Frame(FrameError::Closed);
    let pipe = ClientError::Frame(FrameError::Io(Io::BrokenPipe));
    let reset = ClientError::Frame(FrameError::Io(Io::ConnectionReset));
    let gone = ClientError::Frame(FrameError::Io(Io::NotConnected));
    let mut t = Scripted::new(
        [
            Err(closed),
            Err(pipe),
            Err(gone),
            Ok(RunAnswer::decided(pending("ABCDEFGH"))),
            Ok(covered_with_a_value()),
        ],
        [
            Err(ClientError::Unavailable),
            Err(reset),
            Err(gone),
            Ok(PendingState::Approved),
        ],
    );
    let mut c = t.clock();
    let got = wait_for_run(&mut t, &mut c, MAX_WAIT, &mut |_| {}).unwrap();
    assert!(matches!(got, Waited::Answer(_)), "{got:?}");
    assert_eq!(
        calls(&t),
        [
            "request", "request", "request", "request", "poll", "poll", "poll", "poll", "request"
        ]
    );
    // The busy pause: doubled each time, and never shorter after.
    let paused: Vec<u128> = c.pauses.iter().map(Duration::as_millis).collect();
    assert_eq!(paused, [500, 1000, 2000, 2000, 2000, 2000, 2000]);

    // Before any answer, nothing listening is the failure, at once.
    let mut t = Scripted::new([Err(ClientError::Unavailable)], []);
    let mut c = t.clock();
    let got = wait_for_run(&mut t, &mut c, MAX_WAIT, &mut |_| {});
    assert_eq!(got.unwrap_err(), ClientError::Unavailable);
    assert_eq!(calls(&t), ["request"]);

    // A socket or daemon that fails a check, and an answer cut short, are
    // never asked again, before an answer or after.
    for e in [
        ClientError::Unverified(envcloak_ipc::Unverified::ForeignServer),
        ClientError::Frame(FrameError::Truncated),
        ClientError::Protocol,
    ] {
        let mut t = Scripted::new([Err(e)], []);
        let mut c = t.clock();
        assert_eq!(
            wait_for_run(&mut t, &mut c, MAX_WAIT, &mut |_| {}).unwrap_err(),
            e
        );
        let mut t = Scripted::new([Ok(RunAnswer::decided(pending("ABCDEFGH")))], [Err(e)]);
        let mut c = t.clock();
        assert_eq!(
            wait_for_run(&mut t, &mut c, MAX_WAIT, &mut |_| {}).unwrap_err(),
            e
        );
    }

    // Not taken at the deadline: that failure ends the wait, for a poll
    // and for the request asked after an approval.
    let mut w = Wait::new(Duration::ZERO, ms(1000));
    w.next(Duration::ZERO, Event::Start);
    w.next(Duration::ZERO, Event::Answered(Ok(&pending("ABCDEFGH"))));
    let mut early = w.clone();
    assert_eq!(
        early.next(ms(999), Event::Polled(Err(closed))).0,
        Action::Sleep(ms(1))
    );
    assert_eq!(
        w.clone().next(ms(1000), Event::Polled(Err(closed))).0,
        Action::Finish(Finish::Failed(closed))
    );
    assert_eq!(
        w.next(ms(1200), Event::Answered(Err(ClientError::Unavailable)))
            .0,
        Action::Finish(Finish::Failed(ClientError::Unavailable))
    );
}

/// A waiter may pass a smaller grace than CALL_GRACE, so that its wait
/// and its grace together stay under a host's timeout: the limit is the
/// deadline plus that grace, never more than CALL_GRACE, and each call is
/// given only the time left to it.
///
/// Mutation: ignore the grace passed (always CALL_GRACE): the limit and
/// the times given to the calls are 5 seconds after the deadline and this
/// fails.
#[test]
fn a_smaller_grace_ends_the_wait_sooner() {
    use envcloak_ipc::wait::wait_for_run_with_grace;
    let w = Wait::with_grace(ms(500), ms(1000), ms(1500));
    assert_eq!(w.deadline(), ms(1500));
    assert_eq!(w.limit(), ms(3000));
    assert_eq!(w.time_left(ms(1500)), Some(ms(1500)));
    // Never more than CALL_GRACE.
    let w = Wait::with_grace(Duration::ZERO, ms(1000), Duration::from_secs(60));
    assert_eq!(w.limit(), ms(1000) + CALL_GRACE);

    let mut t = Scripted::new(
        [Ok(RunAnswer::decided(pending("ABCDEFGH")))],
        (0..5).map(|_| Ok(PendingState::Pending)),
    );
    let mut c = t.clock();
    let got = wait_for_run_with_grace(&mut t, &mut c, ms(1100), ms(700), &mut |_| {}).unwrap();
    assert!(
        matches!(got, Waited::TimedOut(i) if i == id("ABCDEFGH")),
        "{got:?}"
    );
    for (at, within) in &t.within {
        assert_eq!(*within, ms(1800) - *at, "{:?}", t.within);
    }
    assert_eq!(t.within.last(), Some(&(ms(1100), ms(700))));

    // Approved at the deadline, the request after it answered only after
    // the smaller limit: dropped, and nothing starts.
    let mut t = Scripted::new(
        [
            Ok(RunAnswer::decided(pending("ABCDEFGH"))),
            Ok(covered_with_a_value()),
        ],
        [Ok(PendingState::Approved)],
    );
    t.delays = VecDeque::from([Duration::ZERO, ms(750), ms(800)]);
    let mut c = t.clock();
    let got = wait_for_run_with_grace(&mut t, &mut c, ms(1000), ms(500), &mut |_| {}).unwrap();
    assert!(matches!(got, Waited::Unanswered), "{got:?}");
    assert_eq!(calls(&t), ["request", "poll", "request"]);
}

// ------------------------------------------- waits on real connections

/// A run directory under a test home with a listener on its socket, where
/// `serve` takes the connections on a thread of its own; and the wait of
/// `wait` a waiter makes there over real connections ([`Fresh`]), on the
/// system's clock, asking `params`. Returns how the wait ended (as text)
/// and how long it took; a wait still going after 60 seconds fails the
/// test. The server thread is left to end with the test.
fn wait_on_peer(
    wait: Duration,
    params: envcloak_ipc::proto::RunRequestParams,
    serve: impl FnOnce(std::os::unix::net::UnixListener) + Send + 'static,
) -> (String, Duration) {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::sync::mpsc;
    use std::time::Instant;

    use envcloak_ipc::RunPaths;
    use envcloak_ipc::wait::{Fresh, SystemClock};

    let home = envcloak_testkit::TestHome::new();
    let p = RunPaths::under(home.root().join("run").join("envcloak")).unwrap();
    std::fs::create_dir_all(&p.dir).unwrap();
    std::fs::set_permissions(&p.dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let l = UnixListener::bind(&p.socket).unwrap();
    std::thread::spawn(move || serve(l));
    let (tx, rx) = mpsc::channel();
    let started = Instant::now();
    std::thread::spawn(move || {
        let mut t = Fresh {
            paths: &p,
            params: &params,
        };
        let got = wait_for_run(&mut t, &mut SystemClock::new(), wait, &mut |_| {});
        let _ = tx.send(format!("{got:?}"));
    });
    let got = rx
        .recv_timeout(Duration::from_secs(60))
        .expect("the wait outlasted its limit by far");
    let took = started.elapsed();
    drop(home);
    (got, took)
}

fn run_params(argv: Vec<String>) -> envcloak_ipc::proto::RunRequestParams {
    envcloak_ipc::proto::RunRequestParams {
        manifest: "/nowhere/envcloak.toml".to_owned(),
        profile: None,
        refs: Vec::new(),
        env_file: None,
        argv,
        claims: Vec::new(),
    }
}

/// The bytes of the response to request 1 that answers `a`.
fn answer_bytes(a: &RunAnswer) -> Vec<u8> {
    let f = envcloak_ipc::proto::result_frame(1, a).unwrap();
    let mut out = Vec::new();
    f.write_to(&mut out).unwrap();
    out
}

/// The slack a loaded test machine may add to a wait's limit.
const SLACK: Duration = Duration::from_secs(3);

/// A daemon that reads the request and then sends a well-formed answer
/// one byte at a time, header and body alike, a byte every 250 ms, holds a
/// wait of one second no longer than its limit (the deadline plus
/// CALL_GRACE): every read waits only for the time left to the limit, not
/// a whole timeout again for each byte, and the wait ends `Unanswered`.
///
/// Mutation: set the call's timeouts once at connect and read and write
/// blocking (`Client::call` on the stream itself, as before): each byte
/// arrives within the timeout, the answer is read whole about 20 seconds
/// in, and this fails on the time taken.
#[test]
fn a_daemon_sending_a_byte_at_a_time_holds_a_wait_no_longer_than_its_limit() {
    use std::io::Write;
    let answer = answer_bytes(&RunAnswer::decided(pending("ABCDEFGH")));
    assert!(answer.len() > 60, "{}", answer.len());
    let (got, took) = wait_on_peer(
        Duration::from_secs(1),
        run_params(vec!["./emit".to_owned()]),
        move |l| {
            let (mut s, _) = l.accept().unwrap();
            // The request, whole, then the answer a byte at a time.
            drop(envcloak_ipc::Frame::read_from(&mut s).unwrap());
            for b in &answer {
                if s.write_all(&[*b]).is_err() {
                    return;
                }
                std::thread::sleep(ms(250));
            }
            std::thread::sleep(Duration::from_secs(60));
        },
    );
    assert_eq!(got, "Ok(Unanswered)");
    let limit = Duration::from_secs(1) + CALL_GRACE;
    assert!(took >= limit - ms(100), "{took:?}");
    assert!(took < limit + SLACK, "{took:?}");
}

/// A daemon that reads the request slowly, 4 KiB every 100 ms, and never
/// answers, holds a wait of one second no longer than its limit when the
/// request is too large for the socket's buffers (an argv of 900,000
/// bytes): every write waits only for the time left to the limit, and the
/// wait ends `Unanswered`.
///
/// Mutation: set the call's timeouts once at connect and read and write
/// blocking (`Client::call` on the stream itself, as before): each write
/// makes progress within the timeout, the request is sent whole about 20
/// seconds in and its answer then waited for, and this fails on the time
/// taken.
#[test]
fn a_daemon_reading_slowly_holds_a_wait_no_longer_than_its_limit() {
    use std::io::Read;
    let (got, took) = wait_on_peer(
        Duration::from_secs(1),
        run_params(vec!["a".repeat(900_000)]),
        |l| {
            let (mut s, _) = l.accept().unwrap();
            let mut buf = vec![0u8; 4096];
            loop {
                match s.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => std::thread::sleep(ms(100)),
                }
            }
            std::thread::sleep(Duration::from_secs(60));
        },
    );
    assert_eq!(got, "Ok(Unanswered)");
    let limit = Duration::from_secs(1) + CALL_GRACE;
    assert!(took >= limit - ms(100), "{took:?}");
    assert!(took < limit + SLACK, "{took:?}");
}

/// Over real connections, a daemon that closes the first two connections
/// unanswered (as it does at its connection limit) and answers the third:
/// the waiter asks again after the busy pause and gets the answer.
///
/// Mutation: end the wait on a connection closed before any answer: the
/// wait fails with the first close and this fails.
#[test]
fn connections_closed_unanswered_are_asked_again() {
    use std::io::Write;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let seen = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&seen);
    let answer = answer_bytes(&RunAnswer::decided(DecisionView::Denied {
        reason: "repeated".to_owned(),
    }));
    let (got, took) = wait_on_peer(
        Duration::from_secs(20),
        run_params(vec!["./emit".to_owned()]),
        move |l| {
            for _ in 0..2 {
                drop(l.accept().unwrap());
                counted.fetch_add(1, Ordering::SeqCst);
            }
            let (mut s, _) = l.accept().unwrap();
            counted.fetch_add(1, Ordering::SeqCst);
            drop(envcloak_ipc::Frame::read_from(&mut s).unwrap());
            s.write_all(&answer).unwrap();
            std::thread::sleep(Duration::from_secs(60));
        },
    );
    assert!(got.starts_with("Ok(Answer("), "{got}");
    assert!(got.contains("repeated"), "{got}");
    assert_eq!(seen.load(Ordering::SeqCst), 3);
    // Two busy pauses, 500 ms and 1 s.
    assert!(
        took >= ms(1400) && took < Duration::from_secs(10),
        "{took:?}"
    );
}

/// Over a real connection, a daemon that resets the connection part way
/// through its answer ends the wait with that answer cut short, never
/// asked again: the daemon sees one connection. It reads the request but
/// its last byte and closes after half its answer, a close with a byte
/// unread, which Linux reports to the reader as a reset once the bytes
/// sent are read; macOS reports it as the end of the stream, cut short
/// alike.
///
/// Mutation: report a failure inside a frame as its I/O error
/// (`Frame::read_from` as before, for anything but a timeout): on Linux
/// the wait takes the reset for a call the daemon did not take, connects
/// again until its deadline and ends with the closed connection, and this
/// fails.
#[test]
fn an_answer_cut_short_by_a_reset_is_never_asked_again() {
    use std::io::{Read, Write};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let seen = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&seen);
    let answer = answer_bytes(&RunAnswer::decided(pending("ABCDEFGH")));
    let (got, took) = wait_on_peer(
        Duration::from_secs(3),
        run_params(vec!["./emit".to_owned()]),
        move |l| {
            let (mut s, _) = l.accept().unwrap();
            counted.fetch_add(1, Ordering::SeqCst);
            let mut header = [0u8; 4];
            s.read_exact(&mut header).unwrap();
            let len = usize::try_from(u32::from_be_bytes(header)).unwrap();
            // All of the body but its last byte: the client has written
            // the whole request, and one byte of it stays unread.
            let mut body = vec![0u8; len - 1];
            s.read_exact(&mut body).unwrap();
            s.write_all(&answer[..answer.len() / 2]).unwrap();
            drop(s);
            // Any connection after it is counted and closed unanswered.
            for c in l.incoming() {
                counted.fetch_add(1, Ordering::SeqCst);
                drop(c);
            }
        },
    );
    assert_eq!(got, "Err(Frame(Truncated))");
    assert_eq!(seen.load(Ordering::SeqCst), 1);
    assert!(took < Duration::from_secs(3), "{took:?}");
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
            product: "fixture".to_owned(),
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

/// The vault's metadata for `item`, as [`request_of`] binds it: one test
/// secret with one field.
fn metas(item: (ItemId, FieldId)) -> Vec<ItemMeta> {
    vec![ItemMeta {
        id: item.0,
        class: ItemClass::Secret,
        slug: Slug::new("openai/acme-web").unwrap(),
        details: ItemDetails {
            classification: Classification::Test,
            ..ItemDetails::default()
        },
        created_at: 0,
        updated_at: 0,
        fields: vec![FieldMeta {
            id: item.1,
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
    }]
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
            source: envcloak_policy::BindingSource::Env,
        }],
        mode: Mode::Inject,
        argv_display: vec![format!("./job-{n}")],
        new_project: false,
        managed: None,
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
            let vault = metas(item);
            let Some(d) = store.pending_descriptor(&id, &now, &vault) else {
                continue;
            };
            let digest = statement_digest(&d, &opts);
            let proof = ApprovalProof {
                approver: person(),
                kind: ProofKind::Passphrase,
            };
            store
                .approve(&id, proof, opts, digest, &now, &vault)
                .unwrap();
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

/// The grace after the deadline finishes a run approved within the wait,
/// and never starts one approved during the grace (review of M2-03,
/// M2R-14): a poll made before the deadline and answered `approved` after
/// it, during the grace, ends the wait timed out with no request asked;
/// read at the deadline itself it is asked again as before.
///
/// Mutation checked: the `approved` arm without its deadline check, as
/// before: the request is asked again after the deadline, the covered
/// answer starts the command, and this fails.
#[test]
fn an_approval_read_after_the_deadline_starts_nothing() {
    let mut w = Wait::with_grace(Duration::ZERO, ms(1000), ms(1000));
    w.next(Duration::ZERO, Event::Start);
    w.next(Duration::ZERO, Event::Answered(Ok(&pending("ABCDEFGH"))));
    assert_eq!(
        w.next(ms(1000), Event::Woke).0,
        Action::Poll(id("ABCDEFGH"))
    );
    assert_eq!(
        w.next(ms(1400), Event::Polled(Ok(PendingState::Approved)))
            .0,
        Action::Finish(Finish::TimedOut(id("ABCDEFGH")))
    );
    // The control: read at the deadline, it is asked again, and its
    // covered answer, read in the grace, is the run's.
    let mut w = Wait::with_grace(Duration::ZERO, ms(1000), ms(1000));
    w.next(Duration::ZERO, Event::Start);
    w.next(Duration::ZERO, Event::Answered(Ok(&pending("ABCDEFGH"))));
    w.next(ms(1000), Event::Woke);
    assert_eq!(
        w.next(ms(1000), Event::Polled(Ok(PendingState::Approved)))
            .0,
        Action::Request
    );
    assert_eq!(
        w.next(ms(1600), Event::Answered(Ok(&covered()))).0,
        Action::Finish(Finish::Decided)
    );

    // Through the driver: the request is answered at 750 ms, and the poll
    // made at the 1 s deadline 650 ms later, approved; nothing more is
    // asked.
    let mut t = Scripted::new(
        [
            Ok(RunAnswer::decided(pending("ABCDEFGH"))),
            Ok(covered_with_a_value()),
        ],
        [Ok(PendingState::Approved)],
    );
    t.delays = VecDeque::from([ms(750), ms(650)]);
    let mut c = t.clock();
    let got = wait_for_run_with_grace_of(&mut t, &mut c, ms(1000), ms(1000));
    assert!(
        matches!(got, Waited::TimedOut(i) if i == id("ABCDEFGH")),
        "{got:?}"
    );
    assert_eq!(calls(&t), ["request", "poll"]);
}

/// A covered answer read after the deadline is taken only as the answer
/// to the request asked again on its own approval read in time (reviews
/// of M2-03 and M2-RES1, M2R-14): any other may be covered by an approval
/// given after the deadline, another waiter's under the same root
/// included, and the wait has timed out. So: one asked again after `busy`
/// just before the deadline times out with its request; the first
/// request, read late with no request named, ends unanswered (its values
/// dropped unused); one asked while a pending cap was full ends as
/// `too_many_pending`; and an approval read in time for one request is no
/// evidence for the request that replaced it. The controls: read by the
/// deadline, each is the run's, and so is the answer to a request asked
/// again on its own approval read in time, read late.
///
/// Mutations checked: no check of a covered answer read after the
/// deadline (as before M2R-14): the re-asked request's answer starts the
/// command and this fails. A late covered answer taken whenever no request
/// is named (as the M2R-14 fix had it): the first and the capped answers
/// start the command and this fails. The evidence kept for any approval
/// read in time, whatever request it was for (a flag, as the M2R-14 fix
/// had it): the replacing request's late answer starts the command and
/// this fails. The evidence kept when the request is pending again: the
/// same request's late answer starts the command and this fails.
#[test]
fn a_covered_answer_read_after_the_deadline_needs_an_approval_read_in_time() {
    let mut w = Wait::with_grace(Duration::ZERO, ms(1000), ms(1000));
    w.next(Duration::ZERO, Event::Start);
    w.next(Duration::ZERO, Event::Answered(Ok(&pending("ABCDEFGH"))));
    assert_eq!(w.next(ms(250), Event::Woke).0, Action::Poll(id("ABCDEFGH")));
    w.next(ms(250), Event::Polled(Ok(PendingState::Pending)));
    // `busy` from a request asked again: asked again at the deadline.
    w.next(ms(900), Event::Answered(Err(busy())));
    assert_eq!(w.next(ms(1000), Event::Woke).0, Action::Request);
    assert_eq!(
        w.next(ms(1400), Event::Answered(Ok(&covered()))).0,
        Action::Finish(Finish::TimedOut(id("ABCDEFGH")))
    );
    // Read at the deadline, the same answer is the run's.
    let mut w = Wait::with_grace(Duration::ZERO, ms(1000), ms(1000));
    w.next(Duration::ZERO, Event::Start);
    w.next(Duration::ZERO, Event::Answered(Ok(&pending("ABCDEFGH"))));
    w.next(ms(900), Event::Answered(Err(busy())));
    w.next(ms(1000), Event::Woke);
    assert_eq!(
        w.next(ms(1000), Event::Answered(Ok(&covered()))).0,
        Action::Finish(Finish::Decided)
    );

    // The first request, read late: nothing names a request, and nothing
    // shows the grant came before the deadline.
    let mut w = Wait::with_grace(Duration::ZERO, ms(1000), ms(1000));
    w.next(Duration::ZERO, Event::Start);
    assert_eq!(
        w.next(ms(1500), Event::Answered(Ok(&covered()))).0,
        Action::Finish(Finish::Unanswered)
    );
    // Read by the deadline, it is the run's.
    let mut w = Wait::with_grace(Duration::ZERO, ms(1000), ms(1000));
    w.next(Duration::ZERO, Event::Start);
    assert_eq!(
        w.next(ms(1000), Event::Answered(Ok(&covered()))).0,
        Action::Finish(Finish::Decided)
    );

    // Asked while a pending cap was full, read late; an approval read in
    // time for the request before the cap is no evidence for it.
    let ClientError::Rpc(cap) = crowded() else {
        unreachable!()
    };
    let mut w = Wait::with_grace(Duration::ZERO, ms(1000), ms(1000));
    w.next(Duration::ZERO, Event::Start);
    w.next(Duration::ZERO, Event::Answered(Ok(&pending("ABCDEFGH"))));
    w.next(ms(250), Event::Woke);
    assert_eq!(
        w.next(ms(250), Event::Polled(Ok(PendingState::Approved))).0,
        Action::Request
    );
    w.next(ms(300), Event::Answered(Err(crowded())));
    assert_eq!(w.next(ms(1000), Event::Woke).0, Action::Request);
    assert_eq!(
        w.next(ms(1400), Event::Answered(Ok(&covered()))).0,
        Action::Finish(Finish::TooManyPending(cap))
    );

    // A request that replaced the one approved in time: the approval was
    // for the first, not for it.
    let mut w = Wait::with_grace(Duration::ZERO, ms(1000), ms(1000));
    w.next(Duration::ZERO, Event::Start);
    w.next(Duration::ZERO, Event::Answered(Ok(&pending("ABCDEFGH"))));
    w.next(ms(250), Event::Woke);
    w.next(ms(250), Event::Polled(Ok(PendingState::Approved)));
    assert_eq!(
        w.next(ms(300), Event::Answered(Ok(&pending("JKMNPQRS")))).1,
        Some(Notice::Pending(id("JKMNPQRS")))
    );
    w.next(ms(900), Event::Answered(Err(busy())));
    assert_eq!(w.next(ms(1000), Event::Woke).0, Action::Request);
    assert_eq!(
        w.next(ms(1400), Event::Answered(Ok(&covered()))).0,
        Action::Finish(Finish::TimedOut(id("JKMNPQRS")))
    );

    // Pending again under the same id after its approval: whatever the
    // approval was, it does not cover the request now.
    let mut w = Wait::with_grace(Duration::ZERO, ms(1000), ms(1000));
    w.next(Duration::ZERO, Event::Start);
    w.next(Duration::ZERO, Event::Answered(Ok(&pending("ABCDEFGH"))));
    w.next(ms(250), Event::Woke);
    w.next(ms(250), Event::Polled(Ok(PendingState::Approved)));
    w.next(ms(300), Event::Answered(Ok(&pending("ABCDEFGH"))));
    w.next(ms(900), Event::Answered(Err(busy())));
    assert_eq!(w.next(ms(1000), Event::Woke).0, Action::Request);
    assert_eq!(
        w.next(ms(1400), Event::Answered(Ok(&covered()))).0,
        Action::Finish(Finish::TimedOut(id("ABCDEFGH")))
    );

    // The control: the request asked again on its own approval read in
    // time, answered after `busy` and read late, is the run's.
    let mut w = Wait::with_grace(Duration::ZERO, ms(1000), ms(1000));
    w.next(Duration::ZERO, Event::Start);
    w.next(Duration::ZERO, Event::Answered(Ok(&pending("ABCDEFGH"))));
    w.next(ms(1000), Event::Woke);
    assert_eq!(
        w.next(ms(1000), Event::Polled(Ok(PendingState::Approved)))
            .0,
        Action::Request
    );
    assert_eq!(
        w.next(ms(1400), Event::Answered(Ok(&covered()))).0,
        Action::Finish(Finish::Decided)
    );

    // Through the driver: the first request answered covered 1.5 s into a
    // 1 s wait is dropped, with its value, and nothing starts.
    let mut t = Scripted::new([Ok(covered_with_a_value())], []);
    t.delays = VecDeque::from([ms(1500)]);
    let mut c = t.clock();
    let got = wait_for_run_with_grace_of(&mut t, &mut c, ms(1000), ms(1000));
    assert!(matches!(got, Waited::Unanswered), "{got:?}");
    assert_eq!(calls(&t), ["request"]);
}

/// [`wait_for_run_with_grace`] on `t` and `c`.
fn wait_for_run_with_grace_of(
    t: &mut Scripted,
    c: &mut TestClock,
    wait: Duration,
    grace: Duration,
) -> Waited {
    envcloak_ipc::wait::wait_for_run_with_grace(t, c, wait, grace, &mut |_| {}).unwrap()
}

/// A clock on the system's time whose every pause first asks the
/// stand-in daemon of [`a_waiter_holds_no_connection_through_any_pause`]
/// how many of the waiter's connections are still open, and records the
/// answer: a barrier at the start of each pause.
struct PauseBarrier {
    inner: envcloak_ipc::wait::SystemClock,
    ask: std::sync::mpsc::Sender<()>,
    answer: std::sync::mpsc::Receiver<usize>,
    open_at_pauses: Vec<usize>,
}

impl Clock for PauseBarrier {
    fn now(&self) -> Duration {
        self.inner.now()
    }

    fn sleep(&mut self, d: Duration) {
        self.ask.send(()).unwrap();
        let open = self
            .answer
            .recv_timeout(Duration::from_secs(30))
            .expect("the stand-in daemon did not count");
        self.open_at_pauses.push(open);
        self.inner.sleep(d);
    }
}

/// D-04, with a barrier at every pause (Codex and verifier review of
/// M2-03, M2R-15): over real connections ([`Fresh`]), a waiter whose
/// request stays pending for a wait of 31 seconds (past the daemon's
/// 30-second idle bound) holds none of its connections open during any
/// pause. Each time the wait pauses, the stand-in daemon, which keeps its
/// end of every connection it took, reads each without blocking: a
/// connection the waiter closed reads as its end, one it still holds
/// would block. The earlier test could not tell a waiter that kept each
/// connection through the pause and closed it just before the next from
/// one that closed it at once.
///
/// Mutation checked: `Fresh` keeping each call's connection until its
/// next call (closed just before the next connect): every pause finds one
/// connection open and this fails.
#[test]
fn a_waiter_holds_no_connection_through_any_pause() {
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::{Arc, Mutex, mpsc};

    use envcloak_ipc::RunPaths;
    use envcloak_ipc::view::PendingStateView;
    use envcloak_ipc::wait::{Fresh, SystemClock};

    let home = envcloak_testkit::TestHome::new();
    let p = RunPaths::under(home.root().join("run").join("envcloak")).unwrap();
    std::fs::create_dir_all(&p.dir).unwrap();
    std::fs::set_permissions(&p.dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let l = UnixListener::bind(&p.socket).unwrap();
    let held: Arc<Mutex<Vec<UnixStream>>> = Arc::default();
    let pending = answer_bytes(&RunAnswer::decided(pending("ABCDEFGH")));
    let still = {
        let f = envcloak_ipc::proto::result_frame(
            1,
            &PendingStateView {
                state: PendingState::Pending,
            },
        )
        .unwrap();
        let mut out = Vec::new();
        f.write_to(&mut out).unwrap();
        out
    };
    // The daemon: every request answered pending, its end of the
    // connection kept, before the answer goes out, so that the count at a
    // pause sees it.
    let taken = Arc::clone(&held);
    std::thread::spawn(move || {
        let mut first = true;
        while let Ok((mut s, _)) = l.accept() {
            if envcloak_ipc::Frame::read_from(&mut s).is_err() {
                continue;
            }
            taken.lock().unwrap().push(s.try_clone().unwrap());
            let answer = if std::mem::take(&mut first) {
                &pending
            } else {
                &still
            };
            let _ = s.write_all(answer);
        }
    });
    // The count: each connection read without blocking; open while a read
    // would block.
    let (ask, asked) = mpsc::channel::<()>();
    let (tell, answer) = mpsc::channel::<usize>();
    let counted = Arc::clone(&held);
    std::thread::spawn(move || {
        while asked.recv().is_ok() {
            let mut open = 0;
            for s in counted.lock().unwrap().iter_mut() {
                s.set_nonblocking(true).unwrap();
                let mut b = [0u8; 1];
                match s.read(&mut b) {
                    Ok(0) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => open += 1,
                    other => panic!("the waiter sent more than a request: {other:?}"),
                }
            }
            if tell.send(open).is_err() {
                return;
            }
        }
    });
    let mut clock = PauseBarrier {
        inner: SystemClock::new(),
        ask,
        answer,
        open_at_pauses: Vec::new(),
    };
    let params = run_params(vec!["./emit".to_owned()]);
    let mut t = Fresh {
        paths: &p,
        params: &params,
    };
    let got = wait_for_run(&mut t, &mut clock, Duration::from_secs(31), &mut |_| {}).unwrap();
    assert!(
        matches!(got, Waited::TimedOut(i) if i == id("ABCDEFGH")),
        "{got:?}"
    );
    let pauses = clock.open_at_pauses;
    // About 35 pauses: four of 250 ms, two of 500 ms, then one a second.
    assert!(pauses.len() >= 30, "{} pauses", pauses.len());
    assert!(
        pauses.iter().all(|n| *n == 0),
        "connections open at the pauses: {pauses:?}"
    );
    // The waiter made a connection for its request and one for each poll.
    assert_eq!(held.lock().unwrap().len(), pauses.len() + 1);
}
