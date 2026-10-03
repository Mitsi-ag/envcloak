//! `envcloak mcp`: EnvCloak's MCP server (SPEC §7; M2 plan task M2-06,
//! decisions D-01, D-03, D-20, D-22), which agent hosts start and talk to
//! over its standard input and output.
//!
//! It is a hand-written JSON-RPC server on `serde_json` (D-01): one message
//! per line ([`stdio`]), `initialize` with version negotiation, `ping`,
//! `tools/list`, `tools/call` and `notifications/cancelled`
//! ([`lifecycle`]); unknown methods and tools are protocol errors, and
//! tool failures are results with a fixed token ([`router::ToolResult`]).
//! Nothing from the input is echoed in an error ([`rpc`]).
//!
//! It never receives a value (D-03): the tools that need the daemon ask it
//! for metadata only, and `run_with_secrets` runs a child `envcloak run`,
//! which alone receives the values and redacts the command's output before
//! this server reads it ([`tools::run_with_secrets`]). It never offers a
//! proof, and it has no reveal or doctor tool. The M2 tools are in
//! [`tools`]; [`Router::register_backend`] is the seam for M2b's sign-in
//! tools and browser backend.
//!
//! Calls run on [`WORKERS`] threads, with at most [`QUEUE`] more waiting;
//! a call beyond that is answered `busy` at once. A call's time, the wait
//! that keeps it under the host's cutoff, runs from its arrival: one still
//! waiting for a worker when it runs out is answered `busy` then, whether
//! or not a worker is free, and nothing of it runs, so calls that hold
//! every worker longer leave none unanswered past the cutoff (Codex
//! reviews of M2-06 and M2-RES1; [`Call::time_left`]: `run_with_secrets`
//! is given only what is left). A call the host cancels
//! (`notifications/cancelled`) is answered nothing further: one still
//! waiting leaves the queue at once, one running has its child stopped
//! ([`child::Call::cancel`]), and an answer still waiting to be written
//! (behind writes a slow host has not read) is withdrawn; only one the
//! writer has begun to write goes out. At the end of input every call in hand is
//! stopped the same way, and the server waits for them, at most
//! [`SHUTDOWN_WAIT`], before it returns. Answers waiting to be written are
//! bounded ([`stdio::Outbox`]): a host that stops reading them while it
//! goes on sending ends the session ([`Stalled`]). Input is read on a
//! thread of its own, so the output's closing (a failed write, or that
//! bound) ends the session at once, while the host keeps its input open
//! and sends nothing: the calls in hand are stopped then too.

pub mod child;
pub mod lifecycle;
pub mod router;
pub mod rpc;
pub mod stdio;
pub mod tools;

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

pub use child::Call;
pub use router::{
    Annotations, Backend, RegisterError, Router, Target, Tool, ToolResult, ToolSchema,
};
pub use tools::Ctx;

use lifecycle::Phase;
use rpc::{Id, Incoming};
use stdio::{Line, LineReader, Outbox};

/// How many tool calls run at once.
pub const WORKERS: usize = 4;
/// How many more may wait for one; a call beyond is answered `busy`.
pub const QUEUE: usize = 32;
/// How long the end of input waits for the calls in hand to stop.
pub const SHUTDOWN_WAIT: Duration = Duration::from_secs(8);
/// How long the end waits for the answers queued to be written.
pub const WRITER_WAIT: Duration = Duration::from_secs(5);

/// Why [`Server::run`] ended the session: the host went on sending but
/// stopped reading the answers, and the queue of answers filled
/// ([`stdio::Outbox::stalled`]). The calls in hand were stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stalled;

impl std::fmt::Display for Stalled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the host stopped reading the answers")
    }
}

impl std::error::Error for Stalled {}

/// Waits up to `limit` for every one of `threads` to finish. Whether all
/// did.
fn finished_within<T>(threads: &[std::thread::JoinHandle<T>], limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    while !threads.iter().all(std::thread::JoinHandle::is_finished) {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    true
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One call in hand: from its arrival until its answer is written, or
/// until it is known that none will be.
#[derive(Debug, Default)]
struct Slot {
    call: Call,
    answer: Mutex<Answer>,
}

/// Where a call's answer is.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// The call runs, or waits for a worker.
    #[default]
    Pending,
    /// Its answer waits for the writer: a cancellation still withdraws it.
    Queued,
    /// Its answer is being written, or none will be: nothing more is sent
    /// for it, and a cancellation changes nothing.
    Settled,
}

/// The calls in hand, by id, and those of them waiting for a worker.
#[derive(Default)]
struct InFlight {
    calls: Mutex<HashMap<Id, Arc<Slot>>>,
    /// Told when a call's answer leaves [`Answer::Pending`], and when a
    /// call leaves.
    changed: Condvar,
    stopping: AtomicBool,
    queue: Queue,
}

impl std::fmt::Debug for InFlight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InFlight").finish_non_exhaustive()
    }
}

/// The calls waiting for a worker, oldest first: at most [`QUEUE`]. A
/// worker takes the oldest; a call taken out by its expiry or its
/// cancellation is no worker's.
#[derive(Default)]
struct Queue {
    state: Mutex<Queued>,
    /// Told when a call is queued, and when the queue closes.
    changed: Condvar,
}

#[derive(Default)]
struct Queued {
    jobs: VecDeque<Job>,
    closed: bool,
}

impl Queue {
    /// Queues `job`, or hands it back when [`QUEUE`] wait already or the
    /// queue is closed.
    fn push(&self, job: Job) -> Result<(), Job> {
        let mut q = lock(&self.state);
        if q.closed || q.jobs.len() >= QUEUE {
            return Err(job);
        }
        q.jobs.push_back(job);
        self.changed.notify_all();
        Ok(())
    }

    /// The oldest call, once there is one; `None` once the queue is
    /// closed and empty.
    fn pop(&self) -> Option<Job> {
        let mut q = lock(&self.state);
        loop {
            if let Some(job) = q.jobs.pop_front() {
                return Some(job);
            }
            if q.closed {
                return None;
            }
            q = self.changed.wait(q).unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Takes out the call `slot` is the slot of, if it still waits.
    fn remove(&self, slot: &Arc<Slot>) -> Option<Job> {
        let mut q = lock(&self.state);
        let i = q.jobs.iter().position(|j| Arc::ptr_eq(&j.slot, slot))?;
        q.jobs.remove(i)
    }

    /// Takes out every call waiting.
    fn drain(&self) -> Vec<Job> {
        lock(&self.state).jobs.drain(..).collect()
    }

    /// No call is queued from now on; the workers end once it is empty.
    fn close(&self) {
        lock(&self.state).closed = true;
        self.changed.notify_all();
    }
}

impl InFlight {
    /// A slot for `id`, unless one is in hand already.
    fn open(&self, id: &Id) -> Option<Arc<Slot>> {
        let mut calls = lock(&self.calls);
        if calls.contains_key(id) {
            return None;
        }
        let slot = Arc::new(Slot::default());
        calls.insert(id.clone(), Arc::clone(&slot));
        Some(slot)
    }

    /// Closes the call `id`, when `slot` is still its slot.
    fn close(&self, id: &Id, slot: &Arc<Slot>) {
        let mut calls = lock(&self.calls);
        if calls.get(id).is_some_and(|s| Arc::ptr_eq(s, slot)) {
            calls.remove(id);
        }
        self.changed.notify_all();
    }

    /// Cancels the call `id`, if it is in hand: one waiting for a worker
    /// leaves at once, answered nothing; a running call is stopped, and an
    /// answer still waiting for the writer is withdrawn. One whose answer
    /// is being written goes on.
    fn cancel(&self, id: &Id) {
        let slot = lock(&self.calls).get(id).cloned();
        if let Some(slot) = slot {
            if let Some(job) = self.queue.remove(&slot) {
                job.slot.call.cancel();
                self.unanswered(&job.id, &job.slot);
                return;
            }
            let answer = lock(&slot.answer);
            if *answer != Answer::Settled {
                slot.call.cancel();
            }
        }
    }

    /// Closes the call `id`, which nothing will be sent for.
    fn unanswered(&self, id: &Id, slot: &Arc<Slot>) {
        *lock(&slot.answer) = Answer::Settled;
        self.close(id, slot);
    }

    /// Queues `answer` for `id` unless the call was cancelled (or, with
    /// `None`, sends nothing). The call stays in hand while the answer
    /// waits, so a cancellation can still withdraw it; it is closed once
    /// the writer is done with it.
    fn answer(
        self: &Arc<Self>,
        id: &Id,
        slot: &Arc<Slot>,
        outbox: &Outbox,
        answer: Option<Vec<u8>>,
    ) {
        let queued = {
            let mut state = lock(&slot.answer);
            match answer {
                Some(a) if !slot.call.cancelled() => {
                    *state = Answer::Queued;
                    Some(a)
                }
                _ => {
                    *state = Answer::Settled;
                    None
                }
            }
        };
        match queued {
            Some(a) => {
                let delivery = Delivery {
                    inflight: Arc::clone(self),
                    id: id.clone(),
                    slot: Arc::clone(slot),
                };
                outbox.send_withdrawable(a, Arc::new(delivery));
                let _calls = lock(&self.calls);
                self.changed.notify_all();
            }
            None => self.close(id, slot),
        }
    }

    /// Cancels every call still running or waiting for a worker, and waits
    /// up to `limit` for all of them to end. Answers already waiting for
    /// the writer are left to it.
    fn stop_all(&self, limit: Duration) {
        self.stopping.store(true, Ordering::SeqCst);
        for job in self.queue.drain() {
            job.slot.call.cancel();
            self.unanswered(&job.id, &job.slot);
        }
        let slots: Vec<Arc<Slot>> = lock(&self.calls).values().cloned().collect();
        for slot in slots {
            let answer = lock(&slot.answer);
            if *answer == Answer::Pending {
                slot.call.cancel();
            }
        }
        let calls = lock(&self.calls);
        let _ = self
            .changed
            .wait_timeout_while(calls, limit, |c| {
                c.values().any(|s| *lock(&s.answer) == Answer::Pending)
            })
            .unwrap_or_else(PoisonError::into_inner);
    }
}

/// A call's answer on its way to the writer ([`stdio::Ticket`]): written
/// only if the call was not cancelled meanwhile, and the call closed once
/// the writer is done with it.
struct Delivery {
    inflight: Arc<InFlight>,
    id: Id,
    slot: Arc<Slot>,
}

impl stdio::Ticket for Delivery {
    fn take(&self) -> bool {
        let mut answer = lock(&self.slot.answer);
        *answer = Answer::Settled;
        !self.slot.call.cancelled()
    }

    fn done(&self) {
        self.inflight.close(&self.id, &self.slot);
    }
}

/// What the session waits for: a line of input, or the output's closing.
enum Event {
    Input(io::Result<Line>),
    OutputClosed,
}

/// Reads lines from `stdin` and hands each to the session, until the end
/// of input, a failed read, or the session's end (its receiver dropped).
/// The channel holds one line, so no more than one is read ahead.
fn read_lines<R: Read>(stdin: R, events: &mpsc::SyncSender<Event>) {
    let mut reader = LineReader::new(stdin);
    loop {
        let line = reader.next_line();
        let more = matches!(line, Ok(Line::Message(_) | Line::Oversized));
        if events.send(Event::Input(line)).is_err() || !more {
            return;
        }
    }
}

/// A call waiting for a worker.
struct Job {
    id: Id,
    name: String,
    args: Map<String, Value>,
    slot: Arc<Slot>,
}

/// Stops the calls in hand from another thread (a termination signal).
#[derive(Debug, Clone)]
pub struct Shutdown {
    inflight: Arc<InFlight>,
}

impl Shutdown {
    /// Cancels every call in hand, stopping their children, and waits up
    /// to [`SHUTDOWN_WAIT`] for them.
    pub fn stop(&self) {
        self.inflight.stop_all(SHUTDOWN_WAIT);
    }
}

/// The server.
#[derive(Debug)]
pub struct Server {
    router: Arc<Router>,
    inflight: Arc<InFlight>,
}

impl Default for Server {
    fn default() -> Self {
        Server::new()
    }
}

impl Server {
    /// A server with the M2 tools ([`tools::m2_tools`]), each listed.
    pub fn new() -> Server {
        let mut router = Router::new();
        for tool in tools::m2_tools() {
            // The M2 tools' names are distinct (tested).
            let _ = router.register(tool);
        }
        Server::with_router(router)
    }

    /// A server with `router`'s tools.
    pub fn with_router(router: Router) -> Server {
        Server {
            router: Arc::new(router),
            inflight: Arc::new(InFlight::default()),
        }
    }

    /// What `tools/list` shows.
    pub fn tools(&self) -> Vec<ToolSchema> {
        self.router.list()
    }

    /// A handle that stops the calls in hand.
    pub fn shutdown(&self) -> Shutdown {
        Shutdown {
            inflight: Arc::clone(&self.inflight),
        }
    }

    /// Serves `stdin` until it ends or `stdout` closes, answering on
    /// `stdout`; then stops every call in hand and returns. `stdin` is read
    /// on a thread of its own, which a read the host never answers may
    /// leave blocked after this returns.
    ///
    /// # Errors
    /// When reading `stdin` fails; [`Stalled`] (inside an
    /// [`io::ErrorKind::Other`] error) when the host stopped reading the
    /// answers while it went on sending.
    pub fn run<R: Read + Send + 'static, W: Write + Send + 'static>(
        self,
        stdin: R,
        stdout: W,
        ctx: Ctx,
    ) -> io::Result<()> {
        let ctx = Arc::new(ctx);
        let (events_tx, events) = mpsc::sync_channel::<Event>(1);
        let wake = events_tx.clone();
        // A full channel holds a line the loop takes next, after which it
        // sees the output closed: the closing is never missed.
        let (outbox, writer) = stdio::spawn_writer(stdout, move || {
            let _ = wake.try_send(Event::OutputClosed);
        });
        std::thread::spawn(move || read_lines(stdin, &events_tx));
        let mut workers: Vec<_> = (0..WORKERS)
            .map(|_| {
                let router = Arc::clone(&self.router);
                let inflight = Arc::clone(&self.inflight);
                let outbox = outbox.clone();
                let ctx = Arc::clone(&ctx);
                std::thread::spawn(move || worker(&router, &inflight, &outbox, &ctx))
            })
            .collect();
        {
            let inflight = Arc::clone(&self.inflight);
            let outbox = outbox.clone();
            let budget = ctx.wait;
            workers.push(std::thread::spawn(move || {
                expire_waiting(&inflight, &outbox, budget);
            }));
        }
        let mut phase = Phase::New;
        let read = loop {
            if outbox.closed() {
                break Ok(());
            }
            match events.recv() {
                Ok(Event::OutputClosed | Event::Input(Ok(Line::End))) | Err(_) => break Ok(()),
                Ok(Event::Input(Err(e))) => break Err(e),
                Ok(Event::Input(Ok(Line::Oversized))) => {
                    outbox.send(rpc::error(None, rpc::PARSE_ERROR, rpc::PARSE_MESSAGE));
                }
                Ok(Event::Input(Ok(Line::Message(bytes)))) => {
                    let incoming = rpc::parse(&bytes);
                    drop(bytes);
                    self.handle(incoming, &mut phase, &outbox);
                }
            }
        };
        drop(events);
        // The end: what is in hand is stopped and waited for.
        self.inflight.stop_all(SHUTDOWN_WAIT);
        self.inflight.queue.close();
        // Each worker ends once the queue is closed and its call done, and
        // the expiry once the queue is closed. One still in a tool a second
        // later is left to the process's exit.
        finished_within(&workers, Duration::from_secs(1));
        for w in workers {
            if w.is_finished() {
                let _ = w.join();
            }
        }
        // The writer ends once what was queued is written; a host that
        // reads nothing more holds its write for ever, and it is left to
        // the process's exit then.
        let stalled = outbox.stalled();
        drop(outbox);
        if finished_within(std::slice::from_ref(&writer), WRITER_WAIT) {
            let _ = writer.join();
        }
        if stalled {
            return Err(io::Error::other(Stalled));
        }
        read
    }

    fn handle(&self, incoming: Incoming, phase: &mut Phase, outbox: &Outbox) {
        let (id, method, params) = match incoming {
            Incoming::Response => return,
            Incoming::Invalid { id, code, message } => {
                outbox.send(rpc::error(id.as_ref(), code, message));
                return;
            }
            Incoming::Notification { method, params } => {
                if method == "notifications/cancelled" {
                    if let Some(id) = params
                        .as_ref()
                        .and_then(|p| p.get("requestId"))
                        .and_then(Id::from_value)
                    {
                        self.inflight.cancel(&id);
                    }
                }
                // `notifications/initialized` needs nothing; other
                // notifications are dropped.
                return;
            }
            Incoming::Request { id, method, params } => (id, method, params),
        };
        let params = params.unwrap_or_default();
        let answer = match (method.as_str(), *phase) {
            ("ping", _) => rpc::result(&id, json!({})),
            ("initialize", Phase::New) => match params.get("protocolVersion") {
                Some(Value::String(v)) => {
                    *phase = Phase::Ready;
                    rpc::result(&id, lifecycle::initialize_result(lifecycle::negotiate(v)))
                }
                _ => rpc::error(
                    Some(&id),
                    rpc::INVALID_PARAMS,
                    "initialize needs a protocolVersion",
                ),
            },
            ("initialize", Phase::Ready) => rpc::error(
                Some(&id),
                rpc::INVALID_REQUEST,
                "the session is initialized already",
            ),
            ("tools/list" | "tools/call", Phase::New) => rpc::error(
                Some(&id),
                rpc::INVALID_REQUEST,
                "the session is not initialized: send initialize first",
            ),
            ("tools/list", Phase::Ready) => {
                if params.contains_key("cursor") {
                    rpc::error(
                        Some(&id),
                        rpc::INVALID_PARAMS,
                        "no such cursor: tools/list is one page",
                    )
                } else {
                    let tools: Vec<Value> = self.tools().iter().map(ToolSchema::to_json).collect();
                    rpc::result(&id, json!({"tools": tools}))
                }
            }
            ("tools/call", Phase::Ready) => match self.enqueue(&id, &params) {
                Ok(()) => return,
                Err(answer) => answer,
            },
            _ => rpc::error(Some(&id), rpc::METHOD_NOT_FOUND, "method not found"),
        };
        outbox.send(answer);
    }

    /// Queues a `tools/call`, or returns the error to answer it with.
    fn enqueue(&self, id: &Id, params: &Map<String, Value>) -> Result<(), Vec<u8>> {
        let name = match params.get("name") {
            Some(Value::String(n)) => n.clone(),
            _ => {
                return Err(rpc::error(
                    Some(id),
                    rpc::INVALID_PARAMS,
                    "tools/call needs the tool's name",
                ));
            }
        };
        let args = match params.get("arguments") {
            None | Some(Value::Null) => Map::new(),
            Some(Value::Object(a)) => a.clone(),
            Some(_) => {
                return Err(rpc::error(
                    Some(id),
                    rpc::INVALID_PARAMS,
                    "a tool's arguments must be an object",
                ));
            }
        };
        if self.router.route(&name).is_none() {
            return Err(rpc::error(Some(id), rpc::INVALID_PARAMS, rpc::UNKNOWN_TOOL));
        }
        let Some(slot) = self.inflight.open(id) else {
            return Err(rpc::error(
                Some(id),
                rpc::INVALID_REQUEST,
                "a call with this id is in progress",
            ));
        };
        let job = Job {
            id: id.clone(),
            name,
            args,
            slot,
        };
        match self.inflight.queue.push(job) {
            Ok(()) => Ok(()),
            Err(job) => {
                self.inflight.close(&job.id, &job.slot);
                Err(rpc::error(
                    Some(id),
                    rpc::BUSY,
                    "busy: the server has as many calls in hand as it takes; try again shortly",
                ))
            }
        }
    }
}

/// Answers `busy`, with nothing of it run, each call still waiting for a
/// worker when its time from its arrival, `budget`, runs out: then, and not
/// when a worker is free, which calls that hold every worker could put off
/// past the host's cutoff (Codex review of M2-RES1). Ends once the queue
/// is closed.
fn expire_waiting(inflight: &Arc<InFlight>, outbox: &Outbox, budget: Duration) {
    let queue = &inflight.queue;
    let mut q = lock(&queue.state);
    loop {
        let now = Instant::now();
        // Oldest first, so the calls whose time is out are at the front.
        let mut due = Vec::new();
        while q
            .jobs
            .front()
            .is_some_and(|j| j.slot.call.deadline(budget) <= now)
        {
            due.extend(q.jobs.pop_front());
        }
        if !due.is_empty() {
            drop(q);
            for job in due {
                let failed = ToolResult::Err(tools::run_with_secrets::no_time_left());
                inflight.answer(
                    &job.id,
                    &job.slot,
                    outbox,
                    Some(rpc::result(&job.id, failed.to_json())),
                );
            }
            q = lock(&queue.state);
            continue;
        }
        if q.closed {
            return;
        }
        let next = q.jobs.front().map(|j| j.slot.call.deadline(budget));
        q = match next {
            Some(at) => {
                queue
                    .changed
                    .wait_timeout(q, at.saturating_duration_since(now))
                    .unwrap_or_else(PoisonError::into_inner)
                    .0
            }
            None => queue
                .changed
                .wait(q)
                .unwrap_or_else(PoisonError::into_inner),
        };
    }
}

fn worker(router: &Router, inflight: &Arc<InFlight>, outbox: &Outbox, ctx: &Ctx) {
    loop {
        let Some(job) = inflight.queue.pop() else {
            return;
        };
        if inflight.stopping.load(Ordering::SeqCst) || job.slot.call.cancelled() {
            inflight.answer(&job.id, &job.slot, outbox, None);
            continue;
        }
        let call = &job.slot.call;
        // A call that waited for a worker past the host's time is answered
        // at once, and nothing of it runs (Codex review of M2-06): the
        // host has given up on it, and what it would start could outlive
        // the answer nobody reads.
        if call.time_left(ctx.wait).is_none() {
            let failed = ToolResult::Err(tools::run_with_secrets::no_time_left());
            inflight.answer(
                &job.id,
                &job.slot,
                outbox,
                Some(rpc::result(&job.id, failed.to_json())),
            );
            continue;
        }
        let answer = match router.route(&job.name) {
            Some(Target::Tool(t)) => rpc::result(&job.id, t.call(&job.args, ctx, call).to_json()),
            Some(Target::Backend(b)) => {
                rpc::result(&job.id, b.call(&job.name, &job.args, ctx, call).to_json())
            }
            // Not reached: a call is queued only for a listed tool, and the
            // router does not change. Answered as `tools/call` answers a
            // tool that is not listed, all the same.
            None => rpc::error(Some(&job.id), rpc::INVALID_PARAMS, rpc::UNKNOWN_TOOL),
        };
        inflight.answer(&job.id, &job.slot, outbox, Some(answer));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A writer that holds its first write until told to, says when that
    /// write began, and keeps everything it is given.
    struct Held {
        entered: mpsc::Sender<()>,
        go: mpsc::Receiver<()>,
        first: bool,
        out: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for Held {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            if std::mem::take(&mut self.first) {
                let _ = self.entered.send(());
                if self.go.recv_timeout(Duration::from_secs(30)).is_err() {
                    return Err(io::ErrorKind::TimedOut.into());
                }
            }
            lock(&self.out).extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A writer held on a first message: its outbox, its thread, the
    /// sender that releases it, and what it writes.
    struct HeldWriter {
        outbox: Outbox,
        thread: std::thread::JoinHandle<()>,
        go: mpsc::Sender<()>,
        out: Arc<Mutex<Vec<u8>>>,
    }

    impl HeldWriter {
        fn new() -> HeldWriter {
            let (entered_tx, entered) = mpsc::channel();
            let (go, go_rx) = mpsc::channel();
            let out = Arc::new(Mutex::new(Vec::new()));
            let (outbox, thread) = stdio::spawn_writer(
                Held {
                    entered: entered_tx,
                    go: go_rx,
                    first: true,
                    out: Arc::clone(&out),
                },
                || {},
            );
            assert!(outbox.send(b"first\n".to_vec()));
            entered
                .recv_timeout(Duration::from_secs(30))
                .expect("the writer took the first message");
            HeldWriter {
                outbox,
                thread,
                go,
                out,
            }
        }

        /// Releases the writer, joins it, and returns what it wrote.
        fn finish(self) -> Vec<u8> {
            self.go.send(()).unwrap();
            drop(self.outbox);
            self.thread.join().unwrap();
            lock(&self.out).clone()
        }
    }

    /// A call's answer waiting behind a write the host does not read is
    /// withdrawn by the call's cancellation: it is never written, and the
    /// call leaves once the writer is done with it. The call stays in hand
    /// while its answer waits, so its id is not taken twice meanwhile. An
    /// answer not cancelled is written, and its call then leaves. (Codex
    /// review of M2-06, medium: the call was closed as soon as its answer
    /// was queued, and a cancellation could no longer reach it.)
    ///
    /// Mutation checked: the writer not asking a message's ticket (every
    /// queued answer written): the cancelled answer is written and this
    /// fails.
    #[test]
    fn a_cancellation_withdraws_an_answer_waiting_to_be_written() {
        let w = HeldWriter::new();
        let inflight = Arc::new(InFlight::default());
        let (cancelled, kept) = (Id::Unsigned(7), Id::Unsigned(8));
        for id in [&cancelled, &kept] {
            let slot = inflight.open(id).unwrap();
            let answer = format!("answer-{id:?}\n").into_bytes();
            inflight.answer(id, &slot, &w.outbox, Some(answer));
            assert!(
                inflight.open(id).is_none(),
                "{id:?} left while its answer waits"
            );
        }
        inflight.cancel(&cancelled);
        let written = String::from_utf8(w.finish()).unwrap();
        assert_eq!(written, format!("first\nanswer-{kept:?}\n"));
        assert!(lock(&inflight.calls).is_empty(), "a call is still in hand");
    }

    /// The end of the session stops what runs and leaves the answers
    /// waiting to be written to the writer: it does not wait for them.
    #[test]
    fn stopping_all_leaves_queued_answers_to_the_writer() {
        let w = HeldWriter::new();
        let inflight = Arc::new(InFlight::default());
        let id = Id::Unsigned(9);
        let slot = inflight.open(&id).unwrap();
        inflight.answer(&id, &slot, &w.outbox, Some(b"answer\n".to_vec()));
        let start = Instant::now();
        inflight.stop_all(Duration::from_secs(20));
        assert!(start.elapsed() < Duration::from_secs(10));
        assert!(!slot.call.cancelled());
        assert_eq!(w.finish(), b"first\nanswer\n");
        assert!(lock(&inflight.calls).is_empty());
    }
}
