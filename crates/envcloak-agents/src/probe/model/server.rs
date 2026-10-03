//! The scripted model's server: loopback only, a random port, a per-run
//! token, a time limit, and caps on every request and on the run.

use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use super::http::{self, Form, HttpError, MAX_HEAD};
use super::script::Script;
use super::wire::{self, Api, BodyError, Pick};
use super::{Incomplete, Limits, Outcome, Recorded, Token};

/// The `Server` header of every response. The release check looks for it
/// in `envcloak` and `envcloakd` and must not find it there: this server
/// is never linked into them.
pub const SERVER: &str = "envcloak-probe-model/1 (scripted, not a model)";

/// A bound server, not yet serving. [`Server::serve`] runs it until a
/// [`Handle::stop`] or its time limit.
#[derive(Debug)]
pub struct Server {
    listener: TcpListener,
    shared: Arc<Shared>,
}

/// Reads and stops a running [`Server`] from other threads.
#[derive(Debug, Clone)]
pub struct Handle {
    shared: Arc<Shared>,
}

struct Shared {
    addr: SocketAddr,
    token: Token,
    script: Script,
    limits: Limits,
    started: Instant,
    state: Mutex<State>,
    stop: AtomicBool,
    /// Set with `stop`, under its own lock, for the time-limit thread.
    stopped: Mutex<bool>,
    stopped_cv: Condvar,
    conns: Mutex<Conns>,
    conns_cv: Condvar,
    /// Barriers released so far ([`Handle::release`]).
    released: Mutex<HashSet<String>>,
    released_cv: Condvar,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("addr", &self.addr)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct State {
    requests: Vec<Recorded>,
    outcome: Outcome,
    seq: u64,
}

#[derive(Default)]
struct Conns {
    next: u64,
    live: HashMap<u64, TcpStream>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Server {
    /// Binds `127.0.0.1` on a port the system picks and makes the run's
    /// token.
    ///
    /// # Errors
    /// When the port cannot be bound or no random bytes are available.
    pub fn bind(script: Script, limits: Limits) -> io::Result<Server> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let addr = listener.local_addr()?;
        let shared = Arc::new(Shared {
            addr,
            token: Token::generate()?,
            script,
            limits,
            started: Instant::now(),
            state: Mutex::new(State::default()),
            stop: AtomicBool::new(false),
            stopped: Mutex::new(false),
            stopped_cv: Condvar::new(),
            conns: Mutex::new(Conns::default()),
            conns_cv: Condvar::new(),
            released: Mutex::new(HashSet::new()),
            released_cv: Condvar::new(),
        });
        Ok(Server { listener, shared })
    }

    /// The address it listens on.
    pub fn addr(&self) -> SocketAddr {
        self.shared.addr
    }

    /// The run's token: hosts must present it as their API key.
    pub fn api_key(&self) -> &Token {
        &self.shared.token
    }

    /// A handle for reading and stopping the run.
    pub fn handle(&self) -> Handle {
        Handle {
            shared: Arc::clone(&self.shared),
        }
    }

    /// Serves until [`Handle::stop`] or the time limit, then closes every
    /// connection and returns once their threads are done (at most a few
    /// seconds later).
    pub fn serve(self) {
        let shared = Arc::clone(&self.shared);
        let timer = std::thread::spawn(move || time_limit(&shared));
        for stream in self.listener.incoming() {
            if self.shared.stop.load(Ordering::SeqCst) {
                break;
            }
            let Ok(stream) = stream else { continue };
            let Ok(peer) = stream.peer_addr() else {
                continue;
            };
            admit(&self.shared, stream, peer);
        }
        drop(self.listener);
        let mut conns = lock(&self.shared.conns);
        for stream in conns.live.values() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        let end = Instant::now() + Duration::from_secs(5);
        while !conns.live.is_empty() {
            let now = Instant::now();
            if now >= end {
                break;
            }
            conns = self
                .shared
                .conns_cv
                .wait_timeout(conns, end - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        drop(conns);
        let _ = timer.join();
    }
}

/// Ends the run at its time limit, unless it is stopped first.
fn time_limit(shared: &Shared) {
    let deadline = shared.started + shared.limits.time;
    let mut stopped = lock(&shared.stopped);
    while !*stopped {
        let now = Instant::now();
        if now >= deadline {
            drop(stopped);
            lock(&shared.state).outcome.mark(Incomplete::TimeLimit);
            stop(shared);
            return;
        }
        stopped = shared
            .stopped_cv
            .wait_timeout(stopped, deadline - now)
            .unwrap_or_else(PoisonError::into_inner)
            .0;
    }
}

fn stop(shared: &Shared) {
    if shared.stop.swap(true, Ordering::SeqCst) {
        return;
    }
    *lock(&shared.stopped) = true;
    shared.stopped_cv.notify_all();
    // Held replies give up.
    drop(lock(&shared.released));
    shared.released_cv.notify_all();
    // Wakes the accept loop, which sees the flag and returns.
    let _ = TcpStream::connect_timeout(&shared.addr, Duration::from_secs(1));
}

/// A connection from `peer`: refused unless `peer` is a loopback address
/// and the connection cap has room, else served on its own thread.
fn admit(shared: &Arc<Shared>, stream: TcpStream, peer: SocketAddr) {
    if !peer.ip().is_loopback() {
        lock(&shared.state).outcome.bad_peer += 1;
        let _ = stream.shutdown(Shutdown::Both);
        return;
    }
    let id = {
        let mut conns = lock(&shared.conns);
        if conns.live.len() >= shared.limits.connections {
            drop(conns);
            lock(&shared.state).outcome.busy += 1;
            let _ = stream.shutdown(Shutdown::Both);
            return;
        }
        let Ok(clone) = stream.try_clone() else {
            return;
        };
        conns.next += 1;
        let id = conns.next;
        conns.live.insert(id, clone);
        id
    };
    let shared = Arc::clone(shared);
    let spawned = std::thread::Builder::new().spawn({
        let shared = Arc::clone(&shared);
        move || {
            let mut stream = stream;
            let _ = stream.set_read_timeout(Some(shared.limits.idle));
            let _ = stream.set_write_timeout(Some(shared.limits.idle));
            let _ = stream.set_nodelay(true);
            serve_connection(&shared, &mut stream);
            linger(&mut stream);
            let mut conns = lock(&shared.conns);
            conns.live.remove(&id);
            shared.conns_cv.notify_all();
        }
    });
    if spawned.is_err() {
        let mut conns = lock(&shared.conns);
        if let Some(s) = conns.live.remove(&id) {
            let _ = s.shutdown(Shutdown::Both);
        }
    }
}

/// Closes a connection the way HTTP servers do after refusing a request
/// they did not read whole: the write side first, then what the client
/// still sends is read and dropped (at most 16 MiB, until it pauses for
/// 200 ms), so the refusal reaches it rather than a reset.
fn linger(stream: &mut TcpStream) {
    let _ = stream.shutdown(Shutdown::Write);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let mut chunk = [0u8; 65536];
    let mut left: usize = 16 * 1024 * 1024;
    while left > 0 {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => left = left.saturating_sub(n),
        }
    }
    chunk.zeroize();
    let _ = stream.shutdown(Shutdown::Both);
}

/// Feeds one connection's bytes to the server and returns what it wrote
/// back: the request handling of a real connection, over memory. For the
/// hostile-input tests (and M2-25's fuzz target); `testing` only.
#[cfg(feature = "testing")]
pub fn serve_bytes(handle: &Handle, input: &[u8]) -> Vec<u8> {
    struct Mem<'a> {
        input: &'a [u8],
        output: Vec<u8>,
    }
    impl Read for Mem<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            // A few bytes at a time, so heads and bodies split across reads.
            let n = buf.len().min(self.input.len()).min(97);
            buf[..n].copy_from_slice(&self.input[..n]);
            self.input = &self.input[n..];
            Ok(n)
        }
    }
    impl Write for Mem<'_> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.output.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut mem = Mem {
        input,
        output: Vec::new(),
    };
    serve_connection(&handle.shared, &mut mem);
    mem.output
}

/// Requests on one connection, until it closes, errs, idles out, asks to
/// close or the run stops.
fn serve_connection<S: Read + Write>(shared: &Shared, stream: &mut S) {
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(16 * 1024));
    while !shared.stop.load(Ordering::SeqCst) {
        let end = match read_head(stream, &mut buf) {
            Ok(Some(end)) => end,
            Ok(None) => return,
            Err(HttpError::HeadTooLarge) => {
                lock(&shared.state).outcome.malformed += 1;
                respond(
                    stream,
                    &Response::error(431, "the request head is too large"),
                );
                return;
            }
            Err(_) => {
                lock(&shared.state).outcome.malformed += 1;
                respond(stream, &Response::error(400, "malformed request"));
                return;
            }
        };
        let head = match http::parse_head(&buf[..end], shared.limits.body) {
            Ok(h) => h,
            Err(HttpError::BodyTooLarge) => {
                lock(&shared.state).outcome.mark(Incomplete::BodyCap);
                respond(
                    stream,
                    &Response::error(413, "the request body is too large"),
                );
                return;
            }
            Err(HttpError::HeadTooLarge) => {
                lock(&shared.state).outcome.malformed += 1;
                respond(
                    stream,
                    &Response::error(431, "the request head is too large"),
                );
                return;
            }
            Err(HttpError::Malformed(_)) => {
                lock(&shared.state).outcome.malformed += 1;
                respond(stream, &Response::error(400, "malformed request"));
                return;
            }
        };
        // The head's bytes, credentials included, leave the buffer; what
        // follows is this request's body, then any next request.
        buf.drain(..end);
        // What the record keeps of the head: every header's value (the
        // run's token as `<token>`) and a forwarded request's whole
        // target, counted against the metadata cap.
        let values = shared.token.recorded_values(&head);
        let meta = super::meta_len(
            &head.method,
            &head.path,
            head.query.as_deref(),
            &head.header_names,
            &values,
            head.forward.as_ref().map_or(&[][..], |f| f.as_slice()),
        );
        if head.form != Form::Origin {
            // A host reaching for anywhere else through the proxy the
            // harness names, by a tunnel or a forwarded request: refused,
            // and recorded by the `host:port` it names, with its whole
            // target, its header values and its body (Codex review,
            // medium: a value in the path, query or body of a refused
            // proxy request was never recorded, so never swept).
            let seq = {
                let mut state = lock(&shared.state);
                state.outcome.connect += 1;
                let Some(seq) = reserve(&mut state, &shared.limits, meta, head.content_length)
                else {
                    drop(state);
                    respond(stream, &full());
                    return;
                };
                seq
            };
            let Some(body) = read_body(stream, &mut buf, head.content_length) else {
                lock(&shared.state).outcome.malformed += 1;
                return;
            };
            let mut rec = Recorded::of(seq, shared.started.elapsed(), &head, values, 403);
            rec.api = Some(
                if head.form == Form::Tunnel {
                    "connect"
                } else {
                    "proxy"
                }
                .to_owned(),
            );
            rec.body = body;
            lock(&shared.state).requests.push(rec);
            let sent = respond_keep(
                stream,
                &Response::error(403, "the scripted model reaches nothing else"),
                false,
            );
            answered(shared, seq, sent);
            return;
        }
        if is_hello(&head) {
            let mut state = lock(&shared.state);
            let Some(seq) = reserve(&mut state, &shared.limits, meta, 0) else {
                drop(state);
                respond(stream, &full());
                return;
            };
            let mut rec = Recorded::of(seq, shared.started.elapsed(), &head, values, 200);
            rec.api = Some("hello".to_owned());
            state.requests.push(rec);
            drop(state);
            let empty = Response {
                status: 200,
                content_type: "text/plain",
                body: Zeroizing::new(Vec::new()),
            };
            let sent = respond_keep(stream, &empty, !head.close);
            answered(shared, seq, sent);
            if !sent || head.close {
                return;
            }
            continue;
        }
        if !shared.token.admits(&head) {
            let mut state = lock(&shared.state);
            state.outcome.bad_token += 1;
            let Some(seq) = reserve(&mut state, &shared.limits, meta, 0) else {
                drop(state);
                respond(stream, &full());
                return;
            };
            state.requests.push(Recorded::of(
                seq,
                shared.started.elapsed(),
                &head,
                values,
                401,
            ));
            drop(state);
            let sent = respond_keep(
                stream,
                &Response::error(401, "the token is wrong or missing"),
                false,
            );
            answered(shared, seq, sent);
            return;
        }
        let api = match (head.method.as_str(), head.path.as_str()) {
            ("POST", "/v1/messages") => Some(Api::Messages),
            ("POST", "/v1/responses") => Some(Api::Responses),
            _ => None,
        };
        let seq = {
            let mut state = lock(&shared.state);
            let Some(seq) = reserve(&mut state, &shared.limits, meta, head.content_length) else {
                drop(state);
                respond(stream, &full());
                return;
            };
            seq
        };
        let Some(body) = read_body(stream, &mut buf, head.content_length) else {
            lock(&shared.state).outcome.malformed += 1;
            return;
        };
        let (status, response, pick) = match api {
            None => (
                404,
                Response::error(404, "the scripted model has no such endpoint"),
                None,
            ),
            Some(api) => match reply(shared, api, &body, seq) {
                Ok((pick, reply)) => (
                    200,
                    Response {
                        status: 200,
                        content_type: reply.content_type,
                        body: reply.body,
                    },
                    Some(pick),
                ),
                Err(_) => (400, Response::error(400, "malformed request body"), None),
            },
        };
        let barrier = match pick {
            Some(Pick::Step(n)) => shared.script.step(n).and_then(|s| s.after.clone()),
            _ => None,
        };
        let keep = status == 200 || status == 404;
        {
            let mut state = lock(&shared.state);
            match (status, pick) {
                (404, _) => state.outcome.unknown += 1,
                (400, _) => state.outcome.malformed += 1,
                (_, Some(Pick::Mismatch)) => state.outcome.mismatch += 1,
                (_, Some(Pick::Exhausted)) => state.outcome.exhausted += 1,
                _ => {}
            }
            let mut rec = Recorded::of(seq, shared.started.elapsed(), &head, values, status);
            rec.api = api.map(|a| a.name().to_owned());
            rec.pick = pick.map(Pick::name);
            rec.body = body;
            state.requests.push(rec);
        }
        if let Some(name) = barrier {
            if !wait_released(shared, &name) {
                // The run ended with the reply held: never sent.
                let mut state = lock(&shared.state);
                state.outcome.mark(Incomplete::HeldReply);
                state.outcome.unanswered += 1;
                return;
            }
        }
        let sent = respond_keep(stream, &response, keep && !head.close);
        answered(shared, seq, sent);
        if !sent || !keep || head.close {
            return;
        }
    }
}

/// Records whether the reply to request `seq` was sent whole.
fn answered(shared: &Shared, seq: u64, sent: bool) {
    let mut state = lock(&shared.state);
    if sent {
        if let Some(r) = state.requests.iter_mut().rev().find(|r| r.seq == seq) {
            r.answered = true;
        }
    } else {
        state.outcome.unanswered += 1;
    }
}

/// Waits until the barrier `name` is released; false when the run stops
/// first.
fn wait_released(shared: &Shared, name: &str) -> bool {
    let mut released = lock(&shared.released);
    loop {
        if released.contains(name) {
            return true;
        }
        if shared.stop.load(Ordering::SeqCst) {
            return false;
        }
        released = shared
            .released_cv
            .wait_timeout(released, Duration::from_secs(1))
            .unwrap_or_else(PoisonError::into_inner)
            .0;
    }
}

/// Claude Code's connectivity check, `HEAD /api/hello`, which it sends to
/// its base URL with no credential and no body (seen with 2.1.280; M2-04's
/// spike in docs/ACCEPTANCE.md). Answered 200 with nothing, and recorded.
fn is_hello(head: &http::Head) -> bool {
    head.method == "HEAD" && head.path == "/api/hello" && head.content_length == 0
}

/// Room in the run for one more record whose metadata counts `meta`
/// bytes ([`Recorded::meta_len`]) with a body of `body` bytes: the next
/// sequence number, with the record, its metadata and its body counted;
/// or `None`, with the run marked incomplete, when any of the three caps
/// would be passed. Every path that records a request comes through here
/// first, so nothing a request sends grows the run past its caps.
fn reserve(state: &mut State, limits: &Limits, meta: usize, body: usize) -> Option<u64> {
    let meta = meta as u64;
    // Reservations, not records: a request holds its place from here,
    // while its body is still being read, so connections that reserve at
    // the same time cannot pass the cap between them.
    if state.seq >= limits.records as u64 || state.outcome.recorded_meta + meta > limits.meta as u64
    {
        state.outcome.mark(Incomplete::RecordCap);
        return None;
    }
    if state.outcome.recorded_bytes + body as u64 > limits.total as u64 {
        state.outcome.mark(Incomplete::TotalCap);
        return None;
    }
    state.outcome.recorded_meta += meta;
    state.outcome.recorded_bytes += body as u64;
    state.seq += 1;
    Some(state.seq)
}

/// The refusal once the run has recorded all it may.
fn full() -> Response {
    Response::error(503, "the run has recorded all it may")
}

/// The reply to a request for `api`: the body parsed as JSON and handed
/// to the protocol's builder.
fn reply(
    shared: &Shared,
    api: Api,
    body: &[u8],
    seq: u64,
) -> Result<(Pick, wire::Reply), BodyError> {
    let value: Value = serde_json::from_slice(body).map_err(|_| BodyError("not JSON"))?;
    match api {
        Api::Messages => wire::messages(&value, &shared.script, seq),
        Api::Responses => wire::responses(&value, &shared.script, seq),
    }
}

/// Reads until `buf` holds a whole head. `Ok(None)` when the connection
/// ends (or idles out, or fails) before a request starts; a request cut
/// short is malformed.
fn read_head<S: Read>(
    stream: &mut S,
    buf: &mut Zeroizing<Vec<u8>>,
) -> Result<Option<usize>, HttpError> {
    let mut chunk = [0u8; 8192];
    let result = loop {
        if let Some(end) = http::head_end(buf) {
            break Ok(Some(end));
        }
        if buf.len() > MAX_HEAD {
            break Err(HttpError::HeadTooLarge);
        }
        match stream.read(&mut chunk) {
            Ok(0) if buf.is_empty() => break Ok(None),
            Ok(0) => break Err(HttpError::Malformed("cut short")),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) if buf.is_empty() => break Ok(None),
            Err(_) => break Err(HttpError::Malformed("cut short")),
        }
    };
    chunk.zeroize();
    result
}

/// The `len` bytes of a body: those already in `buf` first, then from the
/// stream. `None` when the stream ends or fails first.
fn read_body<S: Read>(
    stream: &mut S,
    buf: &mut Zeroizing<Vec<u8>>,
    len: usize,
) -> Option<Zeroizing<Vec<u8>>> {
    let mut body = Zeroizing::new(Vec::with_capacity(len));
    let have = buf.len().min(len);
    body.extend_from_slice(&buf[..have]);
    buf.drain(..have);
    let mut chunk = [0u8; 8192];
    let mut ok = true;
    while body.len() < len {
        let want = (len - body.len()).min(chunk.len());
        match stream.read(&mut chunk[..want]) {
            Ok(0) => {
                ok = false;
                break;
            }
            Ok(n) => body.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => {
                ok = false;
                break;
            }
        }
    }
    chunk.zeroize();
    ok.then_some(body)
}

struct Response {
    status: u16,
    content_type: &'static str,
    body: Zeroizing<Vec<u8>>,
}

impl Response {
    /// A fixed error: the status and a message that holds nothing the
    /// request did.
    fn error(status: u16, message: &'static str) -> Response {
        let kind = match status {
            401 => "authentication_error",
            403 => "permission_error",
            404 => "not_found_error",
            413 | 431 => "request_too_large",
            503 => "overloaded_error",
            _ => "invalid_request_error",
        };
        let body = serde_json::json!({
            "type": "error",
            "error": {"type": kind, "message": format!("envcloak-probe-model: {message}")},
        });
        Response {
            status,
            content_type: "application/json",
            body: Zeroizing::new(body.to_string().into_bytes()),
        }
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Content Too Large",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

fn respond<S: Write>(stream: &mut S, response: &Response) {
    let _ = respond_keep(stream, response, false);
}

/// Writes `response`; whether it was all written.
fn respond_keep<S: Write>(stream: &mut S, response: &Response, keep: bool) -> bool {
    let mut out: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(response.body.len() + 256));
    let head = format!(
        "HTTP/1.1 {} {}\r\nServer: {SERVER}\r\nContent-Type: {}\r\nContent-Length: {}\r\n\
         Cache-Control: no-cache\r\nConnection: {}\r\n\r\n",
        response.status,
        reason(response.status),
        response.content_type,
        response.body.len(),
        if keep { "keep-alive" } else { "close" },
    );
    out.extend_from_slice(head.as_bytes());
    out.extend_from_slice(&response.body);
    stream.write_all(&out).and_then(|()| stream.flush()).is_ok()
}

impl Handle {
    /// The address the server listens on.
    pub fn addr(&self) -> SocketAddr {
        self.shared.addr
    }

    /// Stops the run: no new connection is accepted, and open ones are
    /// closed. [`Server::serve`] then returns.
    pub fn stop(&self) {
        stop(&self.shared);
    }

    /// Releases the barrier `name`: a reply held for a step with `after:
    /// name` is sent, and later ones are not held.
    pub fn release(&self, name: &str) {
        lock(&self.shared.released).insert(name.to_owned());
        self.shared.released_cv.notify_all();
    }

    /// Whether the run has stopped (by [`Handle::stop`] or its limit).
    pub fn stopped(&self) -> bool {
        self.shared.stop.load(Ordering::SeqCst)
    }

    /// The outcome so far.
    pub fn outcome(&self) -> Outcome {
        lock(&self.shared.state).outcome.clone()
    }

    /// Writes every request recorded so far and the outcome as one line
    /// of JSON (see the module documentation), `final` saying whether the
    /// run has ended. Written from a wiping buffer.
    ///
    /// # Errors
    /// When `out` fails.
    pub fn write_report(&self, out: &mut dyn Write, last: bool) -> io::Result<()> {
        let state = lock(&self.shared.state);
        let report = super::ReportRef {
            last,
            requests: &state.requests,
            outcome: &state.outcome,
        };
        let mut line: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
        serde_json::to_writer(&mut *line, &report).map_err(io::Error::other)?;
        drop(state);
        line.push(b'\n');
        out.write_all(&line)?;
        out.flush()
    }

    /// Every request recorded so far, copied.
    pub fn requests(&self) -> Vec<Recorded> {
        lock(&self.shared.state).requests.clone()
    }

    /// Takes the recorded requests out of the run and drops them, which
    /// wipes their bodies.
    pub fn wipe(&self) {
        lock(&self.shared.state).requests.clear();
    }
}

/// Lets a test hand the server a connection as if it came from `peer`:
/// the accept path's peer check, over a real socket. `testing` only.
#[cfg(feature = "testing")]
pub fn admit_as(handle: &Handle, stream: TcpStream, peer: SocketAddr) {
    admit(&handle.shared, stream, peer);
}
