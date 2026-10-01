//! Waiting for a person's approval without holding a connection (SPEC
//! §6.1 step 4, M2 plan D-04).
//!
//! No client waits for a person on an open connection: a few processes
//! holding connections could keep `envcloak lock` and `status` out, and the
//! daemon closes a connection whose next frame does not start within 30
//! seconds. A waiter (`envcloak run --wait`, and from M2 the MCP server
//! and `mcp-bridge`) asks instead, each time on a fresh connection:
//!
//! 1. `run.request`. Covered or denied ends the wait. Pending names the
//!    request, which is announced once per request id ([`Notice::Pending`]);
//!    `too_many_pending` (a pending cap is full, nothing was opened) is
//!    announced once ([`Notice::TooManyPending`]) and asked again after the
//!    busy backoff, never taken as a refusal; so is `busy` (the daemon
//!    answers it while Argon2id runs for an unlock or a person's
//!    approval, which is when a waiter is most likely to ask).
//! 2. `pending.state` for the request, after a pause: every 250 ms for the
//!    first second, then every 500 ms for a second, then every second
//!    ([`Backoff`]). `pending` keeps waiting; `approved` and `unknown` (the
//!    request ended in a way this tree is no longer told: a lock, a
//!    restart, a reclassified item, or its outcome forgotten) ask
//!    `run.request` again at once, which a grant now covers or which opens
//!    a new request; `denied` and `expired` end the wait. `busy` (the
//!    root asked too often) doubles the pause, up to 2 seconds, and is
//!    never taken as a refusal. A pause never gets shorter.
//!
//! A call the daemon did not take, its connection closed, reset or no
//! longer connected before any answer (the daemon closes a connection at
//! once, unanswered, when 32 are open or 8 of one process), or, once the
//! daemon has answered this wait, refused or with no socket there (a
//! daemon restarting, or a listener whose backlog is full on macOS), is
//! asked again after the busy backoff, as `busy` is, until the deadline.
//! Before any answer, no daemon there is the failure at once, as it is
//! without waiting; a socket or daemon that fails a check, and a
//! connection that ends, fails or times out once part of an answer has
//! come ([`FrameError::Truncated`]), are never asked again.
//!
//! The wait ends at its deadline, at most [`MAX_WAIT`] (the pending
//! request's lifetime): the last poll is made at the deadline itself, and a
//! request still pending then is [`Finish::TimedOut`]; so is one told
//! `unknown` at or after the deadline, which is not asked again. Only
//! `approved` is still asked again then, once: the approval came within the
//! wait. A call the daemon did not take at the deadline ends the wait with
//! that failure. Nothing here reads a terminal or any input: approval
//! input is never read from the requesting process's terminal.
//!
//! **Bounded.** No call of a wait is answered later than its limit, the
//! deadline plus its grace ([`CALL_GRACE`] unless the waiter passes less,
//! [`Wait::limit`]): each call is given only the time left to the limit,
//! one instant for the whole call ([`Client::connect_by`]): the connect
//! gets the time left, and each write and each read waits for the socket
//! for at most the time then left, so a daemon that answers nothing,
//! sends its answer a byte at a time, or reads the request slowly holds
//! the call no longer; none is made once the limit has passed; and an
//! answer read after it is dropped unused, a covered one's values wiped
//! with it, and the wait ends [`Waited::Unanswered`], so nothing is
//! started late. A waiter's whole wait therefore lasts at most its
//! duration plus its grace, and a waiter that must finish within a host's
//! tool timeout (the MCP server and `mcp-bridge`) keeps the two together
//! under it ([`wait_for_run_with_grace`]).
//!
//! **Traced.** Before each `run.request`, whose answer may carry values,
//! the driver asks whether a tracer is now attached to this process
//! ([`Transport::traced`]); if one is, the wait ends [`Waited::Traced`]
//! without asking. `envcloak run` checks once before its first request
//! (gate 19); a wait can last minutes, so the check is made again before
//! every request that could release values (SPEC §5 "Process hardening").
//!
//! [`Wait`] is the decision alone, a state machine fed the answers and the
//! time, so it can be driven by a test's clock as well as by
//! [`wait_for_run`], which runs it over fresh connections ([`Fresh`]) on
//! the system's clock ([`SystemClock`]).

use std::time::{Duration, Instant};

use envcloak_policy::{PENDING_TTL, PendingId, PendingState};

use crate::client::{Client, ClientError};
use crate::frame::FrameError;
use crate::paths::RunPaths;
use crate::proto::{ErrorKind, RpcError, RunAnswer, RunRequestParams};
use crate::view::DecisionView;

/// The longest wait: the pending request's lifetime.
pub const MAX_WAIT: Duration = PENDING_TTL;

/// The first pause, and every pause of the first second.
pub const FAST_POLL: Duration = Duration::from_millis(250);
/// Polls made [`FAST_POLL`] apart before the pauses grow.
pub const FAST_POLLS: u32 = 4;
/// The pause the nominal schedule settles at.
pub const SLOW_POLL: Duration = Duration::from_secs(1);
/// The longest pause `busy` and `too_many_pending` grow it to.
pub const MAX_BACKOFF: Duration = Duration::from_secs(2);
/// How long after the deadline a call may still be answered: the last
/// poll is made at the deadline itself, and a request approved by then is
/// asked again once, which the daemon answers after writing its audit
/// entry durably. Nothing of a wait is answered later than the deadline
/// plus this ([`Wait::limit`]), or the smaller grace a waiter passes
/// ([`Wait::with_grace`]).
pub const CALL_GRACE: Duration = Duration::from_secs(5);

/// The pause before the next poll or retry. It never shrinks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    interval: Duration,
    answers: u32,
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new()
    }
}

impl Backoff {
    /// The schedule's start: [`FAST_POLL`].
    pub fn new() -> Self {
        Backoff {
            interval: FAST_POLL,
            answers: 0,
        }
    }

    /// The pause to take now.
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// After a `pending` answer: [`FAST_POLL`] for the first
    /// [`FAST_POLLS`] polls, twice that for the next two, then
    /// [`SLOW_POLL`]; never shorter than the pause already reached.
    pub fn after_pending(&mut self) {
        self.answers = self.answers.saturating_add(1);
        let nominal = if self.answers < FAST_POLLS {
            FAST_POLL
        } else if self.answers < FAST_POLLS + 2 {
            FAST_POLL * 2
        } else {
            SLOW_POLL
        };
        self.interval = self.interval.max(nominal);
    }

    /// After `busy` or `too_many_pending`: twice the pause, at most
    /// [`MAX_BACKOFF`] (and never shorter than it was).
    pub fn after_busy(&mut self) {
        self.interval = self
            .interval
            .saturating_mul(2)
            .min(MAX_BACKOFF)
            .max(self.interval);
    }
}

/// What happened, for [`Wait::next`].
#[derive(Debug)]
pub enum Event<'a> {
    /// The wait begins.
    Start,
    /// `run.request` answered (the decision only; the values stay with the
    /// driver).
    Answered(Result<&'a DecisionView, ClientError>),
    /// `pending.state` answered.
    Polled(Result<PendingState, ClientError>),
    /// The pause asked for is over.
    Woke,
}

/// What to do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Send `run.request`, on a fresh connection.
    Request,
    /// Ask `pending.state` for this request, on a fresh connection.
    Poll(PendingId),
    /// Pause this long, holding no connection, then report [`Event::Woke`].
    Sleep(Duration),
    /// The wait is over.
    Finish(Finish),
}

/// Something to tell the person, once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Notice {
    /// A request is waiting for approval: announced once per id.
    Pending(PendingId),
    /// A pending cap is full: announced the first time only.
    TooManyPending(RpcError),
}

/// How a wait ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finish {
    /// `run.request` answered covered or denied: the driver uses that
    /// answer.
    Decided,
    /// A person denied the request.
    Denied(PendingId),
    /// The request expired before anyone approved it.
    Expired(PendingId),
    /// The deadline came with the request still pending.
    TimedOut(PendingId),
    /// The deadline came while every place for a request was taken.
    TooManyPending(RpcError),
    /// Any other failure of either call, and a call the daemon did not
    /// take at the deadline.
    Failed(ClientError),
}

/// The waiting decision: see the module documentation.
#[derive(Debug, Clone)]
pub struct Wait {
    deadline: Duration,
    /// The deadline plus the grace.
    limit: Duration,
    backoff: Backoff,
    /// The request waited on, once `run.request` named one.
    request: Option<PendingId>,
    /// After the pause, `run.request` again rather than a poll.
    ask_again: bool,
    /// The last request announced.
    announced: Option<PendingId>,
    /// `too_many_pending` was announced.
    crowded: bool,
    /// The daemon has answered a call of this wait.
    answered: bool,
}

/// Whether `e` is the daemon's `kind`.
fn is_kind(e: &ClientError, kind: ErrorKind) -> bool {
    matches!(e, ClientError::Rpc(r) if r.kind == kind)
}

/// Whether `e` says the daemon did not take the call, so that it is asked
/// again (see the module documentation): its connection closed before any
/// answer, or reset (as a close with the request unread shows on Linux),
/// at once or on the request, or no longer connected (as macOS sometimes
/// reports a close that races the request); or, once the daemon has
/// `answered` this wait, nothing listening there. A connection that ends
/// or fails inside an answer ([`FrameError::Truncated`]), a timeout, a
/// socket or daemon that failed a check, and a malformed answer are not.
fn not_taken(e: &ClientError, answered: bool) -> bool {
    use std::io::ErrorKind as Io;
    match e {
        ClientError::Frame(
            FrameError::Closed
            | FrameError::Io(
                Io::BrokenPipe | Io::ConnectionReset | Io::ConnectionAborted | Io::NotConnected,
            ),
        ) => true,
        ClientError::Unavailable => answered,
        _ => false,
    }
}

impl Wait {
    /// A wait of `wait` (at most [`MAX_WAIT`]) from `now`, on any clock
    /// that only moves forward, with [`CALL_GRACE`] after its deadline for
    /// a last answer.
    pub fn new(now: Duration, wait: Duration) -> Wait {
        Self::with_grace(now, wait, CALL_GRACE)
    }

    /// A wait as [`Wait::new`] makes, with `grace` (at most
    /// [`CALL_GRACE`]) after its deadline for a last answer: a waiter that
    /// must be done within a host's timeout passes less, so that its wait
    /// and its grace together stay under it. A shorter grace leaves less
    /// time for the request asked after an approval seen at the deadline,
    /// which then ends the wait [`Waited::Unanswered`] if the daemon is
    /// slow to answer it.
    pub fn with_grace(now: Duration, wait: Duration, grace: Duration) -> Wait {
        let deadline = now.saturating_add(wait.min(MAX_WAIT));
        Wait {
            deadline,
            limit: deadline.saturating_add(grace.min(CALL_GRACE)),
            backoff: Backoff::new(),
            request: None,
            ask_again: true,
            announced: None,
            crowded: false,
            answered: false,
        }
    }

    /// When the last poll is made: a request still pending then has timed
    /// out.
    pub fn deadline(&self) -> Duration {
        self.deadline
    }

    /// The latest time any call of this wait may be answered: the
    /// deadline plus its grace.
    pub fn limit(&self) -> Duration {
        self.limit
    }

    /// How long a call made at `now` may take, connect to answer: the
    /// time left to [`Wait::limit`], or `None` when less than a
    /// millisecond is left and no call is made.
    pub fn time_left(&self, now: Duration) -> Option<Duration> {
        self.limit
            .checked_sub(now)
            .filter(|d| *d >= Duration::from_millis(1))
    }

    /// The pause asked for at `now`: the backoff's, cut at the deadline.
    fn pause(&self, now: Duration) -> Action {
        Action::Sleep(
            self.backoff
                .interval()
                .min(self.deadline.saturating_sub(now)),
        )
    }

    /// The next action, at `now`, after `e`; and a notice to show, if any.
    pub fn next(&mut self, now: Duration, e: Event<'_>) -> (Action, Option<Notice>) {
        let answer = match &e {
            Event::Answered(r) => Some(r.as_ref().map(|_| ())),
            Event::Polled(r) => Some(r.as_ref().map(|_| ())),
            Event::Start | Event::Woke => None,
        };
        let answered_before = self.answered;
        if let Some(Ok(()) | Err(ClientError::Rpc(_))) = answer {
            self.answered = true;
        }
        match e {
            Event::Start => (Action::Request, None),
            Event::Answered(Ok(DecisionView::Pending { request })) => {
                let Some(id) = PendingId::parse(request).filter(|id| id.to_string() == *request)
                else {
                    return (Action::Finish(Finish::Failed(ClientError::Protocol)), None);
                };
                let notice = (self.announced != Some(id)).then_some(Notice::Pending(id));
                self.request = Some(id);
                self.ask_again = false;
                self.announced = Some(id);
                if now >= self.deadline {
                    return (Action::Finish(Finish::TimedOut(id)), notice);
                }
                (self.pause(now), notice)
            }
            Event::Answered(Ok(_)) => (Action::Finish(Finish::Decided), None),
            Event::Answered(Err(e)) if is_kind(&e, ErrorKind::TooManyPending) => {
                let ClientError::Rpc(r) = e else {
                    return (Action::Finish(Finish::Failed(e)), None);
                };
                let notice = (!self.crowded).then_some(Notice::TooManyPending(r));
                self.crowded = true;
                self.request = None;
                self.ask_again = true;
                if now >= self.deadline {
                    return (Action::Finish(Finish::TooManyPending(r)), notice);
                }
                self.backoff.after_busy();
                (self.pause(now), notice)
            }
            Event::Answered(Err(e)) if is_kind(&e, ErrorKind::Busy) => {
                // Asked again after the pause; the request it may have
                // named stays the one waited on.
                self.ask_again = true;
                if now >= self.deadline {
                    let end = self.request.map_or(Finish::Failed(e), Finish::TimedOut);
                    return (Action::Finish(end), None);
                }
                self.backoff.after_busy();
                (self.pause(now), None)
            }
            // Not taken: asked again after the busy pause, until the
            // deadline, where it is the failure.
            Event::Answered(Err(e)) if not_taken(&e, answered_before) => {
                self.ask_again = true;
                if now >= self.deadline {
                    return (Action::Finish(Finish::Failed(e)), None);
                }
                self.backoff.after_busy();
                (self.pause(now), None)
            }
            Event::Answered(Err(e)) => (Action::Finish(Finish::Failed(e)), None),
            Event::Woke => match self.request {
                Some(id) if !self.ask_again => (Action::Poll(id), None),
                _ => (Action::Request, None),
            },
            Event::Polled(r) => {
                let Some(id) = self.request else {
                    return (Action::Finish(Finish::Failed(ClientError::Protocol)), None);
                };
                match r {
                    Ok(PendingState::Pending) => {
                        if now >= self.deadline {
                            return (Action::Finish(Finish::TimedOut(id)), None);
                        }
                        self.backoff.after_pending();
                        (self.pause(now), None)
                    }
                    // Approved within the wait: asked again, even at the
                    // deadline, once.
                    Ok(PendingState::Approved) => {
                        self.ask_again = true;
                        (Action::Request, None)
                    }
                    // Ended in a way this tree is not told: asked again
                    // while the wait lasts, never after it.
                    Ok(PendingState::Unknown) => {
                        if now >= self.deadline {
                            return (Action::Finish(Finish::TimedOut(id)), None);
                        }
                        self.ask_again = true;
                        (Action::Request, None)
                    }
                    Ok(PendingState::Denied) => (Action::Finish(Finish::Denied(id)), None),
                    Ok(PendingState::Expired) => (Action::Finish(Finish::Expired(id)), None),
                    Err(e) if is_kind(&e, ErrorKind::Busy) => {
                        self.ask_again = false;
                        if now >= self.deadline {
                            return (Action::Finish(Finish::TimedOut(id)), None);
                        }
                        self.backoff.after_busy();
                        (self.pause(now), None)
                    }
                    Err(e) if not_taken(&e, answered_before) => {
                        self.ask_again = false;
                        if now >= self.deadline {
                            return (Action::Finish(Finish::Failed(e)), None);
                        }
                        self.backoff.after_busy();
                        (self.pause(now), None)
                    }
                    Err(e) => (Action::Finish(Finish::Failed(e)), None),
                }
            }
        }
    }
}

/// How a driven wait ended.
#[derive(Debug)]
pub enum Waited {
    /// `run.request` answered covered or denied: the answer, with the
    /// values a covered one carries.
    Answer(RunAnswer),
    /// A person denied the request.
    Denied(PendingId),
    /// The request expired before anyone approved it.
    Expired(PendingId),
    /// The deadline came with the request still pending.
    TimedOut(PendingId),
    /// The deadline came while every place for a request was taken.
    TooManyPending(RpcError),
    /// A tracer was attached to this process before a `run.request`: the
    /// wait stopped without asking (see the module documentation).
    Traced,
    /// The daemon did not answer a call by the wait's limit, the deadline
    /// plus [`CALL_GRACE`]: the call was given up, or its answer, read
    /// too late, dropped unused with any values it carried. Nothing was
    /// started.
    Unanswered,
}

/// The calls a wait makes, and the check before a `run.request`.
pub trait Transport {
    /// Whether a tracer is attached to this process now (an error reading
    /// it counts as one). Asked before each `run.request`.
    fn traced(&mut self) -> bool;

    /// `run.request`, answered within `within` or given up.
    ///
    /// # Errors
    /// As [`Client::run_request`].
    fn request(&mut self, within: Duration) -> Result<RunAnswer, ClientError>;

    /// `pending.state` for `id`, answered within `within` or given up.
    ///
    /// # Errors
    /// As [`Client::pending_state`].
    fn poll(&mut self, id: &PendingId, within: Duration) -> Result<PendingState, ClientError>;
}

/// The time a wait reads, and how it pauses.
pub trait Clock {
    /// Time since some fixed point, only ever moving forward.
    fn now(&self) -> Duration;
    /// Pauses for `d`.
    fn sleep(&mut self, d: Duration);
}

/// Each call on a connection of its own, verified as
/// [`Client::connect`] verifies it, bounded as a whole by the instant the
/// time the wait has left ends ([`Client::connect_by`]), and closed when
/// the answer is read: no connection stays open between two calls.
/// Whether this process is traced is read from the kernel
/// ([`envcloak_sys::tracer_present`]).
#[derive(Debug)]
pub struct Fresh<'a> {
    pub paths: &'a RunPaths,
    pub params: &'a RunRequestParams,
}

impl Transport for Fresh<'_> {
    fn traced(&mut self) -> bool {
        !matches!(envcloak_sys::tracer_present(), Ok(false))
    }

    fn request(&mut self, within: Duration) -> Result<RunAnswer, ClientError> {
        Client::connect_by(self.paths, by(within)?)?.run_request(self.params)
    }

    fn poll(&mut self, id: &PendingId, within: Duration) -> Result<PendingState, ClientError> {
        Client::connect_by(self.paths, by(within)?)?.pending_state(id)
    }
}

/// The instant `within` from now.
fn by(within: Duration) -> Result<Instant, ClientError> {
    Instant::now()
        .checked_add(within)
        .ok_or(ClientError::Frame(FrameError::Io(
            std::io::ErrorKind::InvalidInput,
        )))
}

/// The monotonic clock, and `std::thread::sleep`.
#[derive(Debug, Clone, Copy)]
pub struct SystemClock {
    start: Instant,
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemClock {
    pub fn new() -> Self {
        SystemClock {
            start: Instant::now(),
        }
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        self.start.elapsed()
    }

    fn sleep(&mut self, d: Duration) {
        std::thread::sleep(d);
    }
}

/// Whether a call that ended at `now` with `r` was not answered in time:
/// read after the wait's limit, whatever it says, or given up at its
/// timeout. A call's timeout is the time left to the limit when it was
/// made, so one that timed out did so after the deadline.
fn too_late<T>(w: &Wait, now: Duration, r: &Result<T, ClientError>) -> bool {
    let timed_out = matches!(
        r,
        Err(ClientError::Frame(
            FrameError::Truncated
                | FrameError::Io(std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)
        ))
    );
    now > w.limit() || (timed_out && now >= w.deadline())
}

/// Runs a [`Wait`] of `wait` over `t` on clock `c`, with [`CALL_GRACE`]
/// for a last answer, telling `notice` what to show. See the module
/// documentation.
///
/// # Errors
/// Any failure of either call other than `busy` and `too_many_pending`,
/// which are waited out (`busy` from `run.request` too, unless the wait
/// ends before any request was named), other than a call the daemon did
/// not take before the deadline, which is asked again, and other than a
/// call the daemon did not answer by the wait's limit
/// ([`Waited::Unanswered`]).
pub fn wait_for_run(
    t: &mut dyn Transport,
    c: &mut dyn Clock,
    wait: Duration,
    notice: &mut dyn FnMut(Notice),
) -> Result<Waited, ClientError> {
    wait_for_run_with_grace(t, c, wait, CALL_GRACE, notice)
}

/// [`wait_for_run`] with `grace` (at most [`CALL_GRACE`]) after the
/// deadline for a last answer ([`Wait::with_grace`]): the whole wait ends
/// by `wait` plus `grace`.
///
/// # Errors
/// As [`wait_for_run`].
pub fn wait_for_run_with_grace(
    t: &mut dyn Transport,
    c: &mut dyn Clock,
    wait: Duration,
    grace: Duration,
    notice: &mut dyn FnMut(Notice),
) -> Result<Waited, ClientError> {
    let mut w = Wait::with_grace(c.now(), wait, grace);
    let (mut action, mut told) = w.next(c.now(), Event::Start);
    loop {
        if let Some(n) = told.take() {
            notice(n);
        }
        let (next, n) = match action {
            Action::Request => {
                // The answer may carry values: never asked under a tracer.
                if t.traced() {
                    return Ok(Waited::Traced);
                }
                let Some(within) = w.time_left(c.now()) else {
                    return Ok(Waited::Unanswered);
                };
                let answer = t.request(within);
                let now = c.now();
                if too_late(&w, now, &answer) {
                    // Dropped unused: a covered answer's values are wiped
                    // with it, and nothing is started.
                    drop(answer);
                    return Ok(Waited::Unanswered);
                }
                let (next, n) = w.next(
                    now,
                    Event::Answered(answer.as_ref().map(|a| &a.decision).map_err(|e| *e)),
                );
                if next == Action::Finish(Finish::Decided) {
                    if let Some(n) = n {
                        notice(n);
                    }
                    return answer.map(Waited::Answer);
                }
                (next, n)
            }
            Action::Poll(id) => {
                let Some(within) = w.time_left(c.now()) else {
                    return Ok(Waited::Unanswered);
                };
                let state = t.poll(&id, within);
                let now = c.now();
                if too_late(&w, now, &state) {
                    return Ok(Waited::Unanswered);
                }
                w.next(now, Event::Polled(state))
            }
            Action::Sleep(d) => {
                c.sleep(d);
                w.next(c.now(), Event::Woke)
            }
            Action::Finish(f) => {
                return match f {
                    Finish::Decided => Err(ClientError::Protocol),
                    Finish::Denied(id) => Ok(Waited::Denied(id)),
                    Finish::Expired(id) => Ok(Waited::Expired(id)),
                    Finish::TimedOut(id) => Ok(Waited::TimedOut(id)),
                    Finish::TooManyPending(r) => Ok(Waited::TooManyPending(r)),
                    Finish::Failed(e) => Err(e),
                };
            }
        };
        action = next;
        told = n;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_schedule_starts_fast_and_never_shrinks() {
        let mut b = Backoff::new();
        let mut seen = vec![b.interval()];
        for _ in 0..8 {
            b.after_pending();
            seen.push(b.interval());
        }
        let ms: Vec<u128> = seen.iter().map(Duration::as_millis).collect();
        assert_eq!(ms, [250, 250, 250, 250, 500, 500, 1000, 1000, 1000]);
        // Busy doubles, up to 2 s, and a later answer keeps it.
        let mut b = Backoff::new();
        b.after_busy();
        assert_eq!(b.interval(), Duration::from_millis(500));
        b.after_pending();
        assert_eq!(b.interval(), Duration::from_millis(500));
        for _ in 0..5 {
            b.after_busy();
        }
        assert_eq!(b.interval(), MAX_BACKOFF);
        b.after_pending();
        assert_eq!(b.interval(), MAX_BACKOFF);
    }
}
