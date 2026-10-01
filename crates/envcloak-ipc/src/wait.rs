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
//! The wait ends at its deadline, at most [`MAX_WAIT`] (the pending
//! request's lifetime): the last poll is made at the deadline itself, and a
//! request still pending then is [`Finish::TimedOut`]. Nothing here reads
//! a terminal or any input: approval input is never read from the
//! requesting process's terminal.
//!
//! [`Wait`] is the decision alone, a state machine fed the answers and the
//! time, so it can be driven by a test's clock as well as by
//! [`wait_for_run`], which runs it over fresh connections ([`Fresh`]) on
//! the system's clock ([`SystemClock`]).

use std::time::{Duration, Instant};

use envcloak_policy::{PENDING_TTL, PendingId, PendingState};

use crate::client::{Client, ClientError};
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
    /// Any other failure of either call.
    Failed(ClientError),
}

/// The waiting decision: see the module documentation.
#[derive(Debug, Clone)]
pub struct Wait {
    deadline: Duration,
    backoff: Backoff,
    /// The request waited on, once `run.request` named one.
    request: Option<PendingId>,
    /// After the pause, `run.request` again rather than a poll.
    ask_again: bool,
    /// The last request announced.
    announced: Option<PendingId>,
    /// `too_many_pending` was announced.
    crowded: bool,
}

/// Whether `e` is the daemon's `kind`.
fn is_kind(e: &ClientError, kind: ErrorKind) -> bool {
    matches!(e, ClientError::Rpc(r) if r.kind == kind)
}

impl Wait {
    /// A wait of `wait` (at most [`MAX_WAIT`]) from `now`, on any clock
    /// that only moves forward.
    pub fn new(now: Duration, wait: Duration) -> Wait {
        Wait {
            deadline: now.saturating_add(wait.min(MAX_WAIT)),
            backoff: Backoff::new(),
            request: None,
            ask_again: true,
            announced: None,
            crowded: false,
        }
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
                    Ok(PendingState::Approved | PendingState::Unknown) => {
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
}

/// The two calls a wait makes.
pub trait Transport {
    /// `run.request`.
    ///
    /// # Errors
    /// As [`Client::run_request`].
    fn request(&mut self) -> Result<RunAnswer, ClientError>;

    /// `pending.state` for `id`.
    ///
    /// # Errors
    /// As [`Client::pending_state`].
    fn poll(&mut self, id: &PendingId) -> Result<PendingState, ClientError>;
}

/// The time a wait reads, and how it pauses.
pub trait Clock {
    /// Time since some fixed point, only ever moving forward.
    fn now(&self) -> Duration;
    /// Pauses for `d`.
    fn sleep(&mut self, d: Duration);
}

/// Each call on a connection of its own, verified as
/// [`Client::connect`] verifies it and closed when the answer is read: no
/// connection stays open between two calls.
#[derive(Debug)]
pub struct Fresh<'a> {
    pub paths: &'a RunPaths,
    pub params: &'a RunRequestParams,
}

impl Transport for Fresh<'_> {
    fn request(&mut self) -> Result<RunAnswer, ClientError> {
        Client::connect(self.paths)?.run_request(self.params)
    }

    fn poll(&mut self, id: &PendingId) -> Result<PendingState, ClientError> {
        Client::connect(self.paths)?.pending_state(id)
    }
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

/// Runs a [`Wait`] of `wait` over `t` on clock `c`, telling `notice` what
/// to show. See the module documentation.
///
/// # Errors
/// Any failure of either call other than `busy` and `too_many_pending`,
/// which are waited out (`busy` from `run.request` too, unless the wait
/// ends before any request was named).
pub fn wait_for_run(
    t: &mut dyn Transport,
    c: &mut dyn Clock,
    wait: Duration,
    notice: &mut dyn FnMut(Notice),
) -> Result<Waited, ClientError> {
    let mut w = Wait::new(c.now(), wait);
    let (mut action, mut told) = w.next(c.now(), Event::Start);
    loop {
        if let Some(n) = told.take() {
            notice(n);
        }
        let (next, n) = match action {
            Action::Request => {
                let answer = t.request();
                let (next, n) = w.next(
                    c.now(),
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
                let state = t.poll(&id);
                w.next(c.now(), Event::Polled(state))
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
