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
//! a call beyond that is answered `busy` at once. A call the host cancels
//! (`notifications/cancelled`) is answered nothing further: one still
//! waiting is dropped, and one running has its child stopped
//! ([`child::Call::cancel`]). At the end of input every call in hand is
//! stopped the same way, and the server waits for them, at most
//! [`SHUTDOWN_WAIT`], before it returns. Answers waiting to be written are
//! bounded ([`stdio::Outbox`]): a host that stops reading them while it
//! goes on sending ends the session ([`Stalled`]).

pub mod child;
pub mod lifecycle;
pub mod router;
pub mod rpc;
pub mod stdio;
pub mod tools;

use std::collections::HashMap;
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

/// One call in hand.
#[derive(Debug, Default)]
struct Slot {
    call: Call,
    /// Set when its answer was sent or it was cancelled: from then on
    /// nothing more is sent for it.
    settled: Mutex<bool>,
}

/// The calls in hand, by id.
#[derive(Debug, Default)]
struct InFlight {
    calls: Mutex<HashMap<Id, Arc<Slot>>>,
    emptied: Condvar,
    stopping: AtomicBool,
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

    fn close(&self, id: &Id) {
        let mut calls = lock(&self.calls);
        calls.remove(id);
        if calls.is_empty() {
            self.emptied.notify_all();
        }
    }

    /// Cancels the call `id`, if it is in hand and not answered.
    fn cancel(&self, id: &Id) {
        let slot = lock(&self.calls).get(id).cloned();
        if let Some(slot) = slot {
            let settled = lock(&slot.settled);
            if !*settled {
                slot.call.cancel();
            }
        }
    }

    /// Sends `answer` for `id` unless the call was cancelled (or, with
    /// `None`, sends nothing), and closes it.
    fn answer(&self, id: &Id, slot: &Slot, outbox: &Outbox, answer: Option<Vec<u8>>) {
        {
            let mut settled = lock(&slot.settled);
            if let Some(answer) = answer {
                if !*settled && !slot.call.cancelled() {
                    outbox.send(answer);
                }
            }
            *settled = true;
        }
        self.close(id);
    }

    /// Cancels every call in hand, and waits up to `limit` for all to end.
    fn stop_all(&self, limit: Duration) {
        self.stopping.store(true, Ordering::SeqCst);
        let slots: Vec<Arc<Slot>> = lock(&self.calls).values().cloned().collect();
        for slot in slots {
            let settled = lock(&slot.settled);
            if !*settled {
                slot.call.cancel();
            }
        }
        let calls = lock(&self.calls);
        let _ = self
            .emptied
            .wait_timeout_while(calls, limit, |c| !c.is_empty())
            .unwrap_or_else(PoisonError::into_inner);
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
    /// `stdout`; then stops every call in hand and returns.
    ///
    /// # Errors
    /// When reading `stdin` fails; [`Stalled`] (inside an
    /// [`io::ErrorKind::Other`] error) when the host stopped reading the
    /// answers while it went on sending.
    pub fn run<R: Read, W: Write + Send + 'static>(
        self,
        stdin: R,
        stdout: W,
        ctx: Ctx,
    ) -> io::Result<()> {
        let ctx = Arc::new(ctx);
        let (outbox, writer) = stdio::spawn_writer(stdout);
        let (jobs, queue) = mpsc::sync_channel::<Job>(QUEUE);
        let queue = Arc::new(Mutex::new(queue));
        let workers: Vec<_> = (0..WORKERS)
            .map(|_| {
                let queue = Arc::clone(&queue);
                let router = Arc::clone(&self.router);
                let inflight = Arc::clone(&self.inflight);
                let outbox = outbox.clone();
                let ctx = Arc::clone(&ctx);
                std::thread::spawn(move || worker(&queue, &router, &inflight, &outbox, &ctx))
            })
            .collect();
        let mut reader = LineReader::new(stdin);
        let mut phase = Phase::New;
        let read = loop {
            if outbox.closed() {
                break Ok(());
            }
            match reader.next_line() {
                Ok(Line::End) => break Ok(()),
                Err(e) => break Err(e),
                Ok(Line::Oversized) => {
                    outbox.send(rpc::error(None, rpc::PARSE_ERROR, rpc::PARSE_MESSAGE));
                }
                Ok(Line::Message(bytes)) => {
                    let incoming = rpc::parse(&bytes);
                    drop(bytes);
                    self.handle(incoming, &mut phase, &outbox, &jobs);
                }
            }
        };
        // The end: what is in hand is stopped and waited for.
        self.inflight.stop_all(SHUTDOWN_WAIT);
        drop(jobs);
        // Each worker ends once its queue is closed and its call done. One
        // still in a tool a second later is left to the process's exit.
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

    fn handle(
        &self,
        incoming: Incoming,
        phase: &mut Phase,
        outbox: &Outbox,
        jobs: &mpsc::SyncSender<Job>,
    ) {
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
            ("tools/call", Phase::Ready) => match self.enqueue(&id, &params, jobs) {
                Ok(()) => return,
                Err(answer) => answer,
            },
            _ => rpc::error(Some(&id), rpc::METHOD_NOT_FOUND, "method not found"),
        };
        outbox.send(answer);
    }

    /// Queues a `tools/call`, or returns the error to answer it with.
    fn enqueue(
        &self,
        id: &Id,
        params: &Map<String, Value>,
        jobs: &mpsc::SyncSender<Job>,
    ) -> Result<(), Vec<u8>> {
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
        match jobs.try_send(job) {
            Ok(()) => Ok(()),
            Err(mpsc::TrySendError::Full(job) | mpsc::TrySendError::Disconnected(job)) => {
                self.inflight.close(&job.id);
                Err(rpc::error(
                    Some(id),
                    rpc::BUSY,
                    "busy: the server has as many calls in hand as it takes; try again shortly",
                ))
            }
        }
    }
}

fn worker(
    queue: &Mutex<mpsc::Receiver<Job>>,
    router: &Router,
    inflight: &InFlight,
    outbox: &Outbox,
    ctx: &Ctx,
) {
    loop {
        let job = lock(queue).recv();
        let Ok(job) = job else { return };
        if inflight.stopping.load(Ordering::SeqCst) || job.slot.call.cancelled() {
            inflight.answer(&job.id, &job.slot, outbox, None);
            continue;
        }
        let call = &job.slot.call;
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
