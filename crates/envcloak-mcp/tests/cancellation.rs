//! The server's stopping of a tool's child, watched from outside (M2 plan
//! task M2-06; the cycle279 review's gates): a fixture leader and the
//! descendant it starts in its group hold a lifeline
//! (`envcloak_testkit::lifeline`), so a test sees when every one of them
//! has exited without reading a process number, and the server's input
//! and output are under the test's control (`envcloak_testkit::controlled`),
//! each with a witness of its drop. The tool, [`Scene`], runs the fixture
//! through `envcloak_mcp::child::run`, as `run_with_secrets` runs `envcloak
//! run`. No real tool, daemon or value is involved: those are tested in
//! crates/envcloak-cli/tests/mcp.rs and crates/envcloak-e2e.
//!
//! Each fixture ends by itself at its stop request (made when its lifeline
//! is dropped, however the test ends) or its deadline, so a failing test
//! leaves nothing running, and nothing here signals a process.
#![allow(clippy::unwrap_used)]

use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use envcloak_mcp::child::{self, KILL_GRACE, TERM_GRACE};
use envcloak_mcp::{Annotations, Call, Ctx, Router, Server, Stalled, Tool, ToolResult, ToolSchema};
use envcloak_testkit::controlled::{self, InputControl, OutputControl};
use envcloak_testkit::lifeline::{self, Holders, Lifeline};
use serde_json::{Map, Value, json};

/// What one call of [`Scene`] saw: its child's end, or that it was not
/// run.
type Seen = Arc<Mutex<Option<Value>>>;

/// A tool that runs the lifeline fixture of `kind` holding `group`, and
/// notes how it ended.
struct Scene {
    kind: &'static str,
    group: std::path::PathBuf,
    stop: std::path::PathBuf,
    terms: Option<std::path::PathBuf>,
    limit: Option<Duration>,
    seen: Seen,
}

impl Tool for Scene {
    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "scene",
            title: "test",
            description: "test",
            input: json!({"type": "object", "additionalProperties": false}),
            output: json!({"type": "object"}),
            annotations: Annotations::default(),
        }
    }

    fn call(&self, _: &Map<String, Value>, _: &Ctx, call: &Call) -> ToolResult {
        let mut cmd = std::process::Command::new(lifeline::python3());
        cmd.args(["-I", "-B", "-c", lifeline::FIXTURE, self.kind])
            .arg(&self.group)
            .arg(&self.stop)
            .arg(lifeline::FIXTURE_SECONDS.to_string())
            .arg("")
            .arg(self.terms.clone().unwrap_or_default())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C");
        let v = match child::run(cmd, call, self.limit) {
            Ok(c) => json!({
                "code": c.code,
                "signal": c.signal,
                "timed_out": c.timed_out,
                "cut": c.cut,
                "output": c.stdout.head().len() + c.stderr.head().len(),
                "cancelled": call.cancelled(),
            }),
            Err(_) => json!({"not_run": true, "cancelled": call.cancelled()}),
        };
        *self.seen.lock().unwrap() = Some(v);
        ToolResult::Ok(json!({"done": true}))
    }
}

/// A server with one [`Scene`] tool, on its own thread, over controlled
/// input and output; the fixture's lifeline and what its call saw.
struct Stage {
    input: InputControl,
    output: OutputControl,
    server: Option<JoinHandle<std::io::Result<()>>>,
    group: Lifeline,
    seen: Seen,
}

impl Stage {
    fn new(kind: &'static str, limit: Option<Duration>, terms: bool) -> Stage {
        let group = Lifeline::new();
        let seen: Seen = Arc::default();
        let mut router = Router::new();
        router
            .register(Box::new(Scene {
                kind,
                group: group.socket(),
                stop: group.stop_path(),
                terms: terms.then(|| group.path("terms")),
                limit,
                seen: Arc::clone(&seen),
            }))
            .unwrap();
        let (reader, input) = controlled::controlled_input();
        let (writer, output) = controlled::controlled_output();
        let ctx = Ctx::new("/nonexistent/envcloak".into(), None, Duration::from_secs(1));
        let server =
            std::thread::spawn(move || Server::with_router(router).run(reader, writer, ctx));
        let stage = Stage {
            input,
            output,
            server: Some(server),
            group,
            seen,
        };
        stage
            .input
            .send(&json!({"jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                       "clientInfo": {"name": "test", "version": "1"}}}));
        assert!(
            stage.answered(0, Duration::from_secs(30)),
            "no initialize answer"
        );
        stage
            .input
            .send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
        stage
    }

    /// Calls the scene as request 1, and waits until its fixture is
    /// ready: the holders of its lifeline.
    fn start(&self) -> Holders {
        self.input
            .send(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "scene", "arguments": {}}}));
        let mut holders = self
            .group
            .accept(Duration::from_secs(30))
            .expect("the fixture connected");
        assert!(
            holders.ready(Duration::from_secs(30)),
            "the fixture is not ready"
        );
        holders
    }

    fn cancel(&self, times: usize) {
        for _ in 0..times {
            self.input.send(
                &json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
                "params": {"requestId": 1, "reason": "test"}}),
            );
        }
    }

    fn ping(&self, id: i64) {
        self.input
            .send(&json!({"jsonrpc": "2.0", "id": id, "method": "ping"}));
    }

    /// The ids of the answers written so far; every line must be one.
    fn ids(&self) -> Vec<i64> {
        self.output
            .messages()
            .into_iter()
            .map(|m| {
                let v = m.unwrap_or_else(|len| panic!("a line of {len} bytes is not JSON"));
                assert_eq!(v["jsonrpc"], "2.0", "{v}");
                v["id"].as_i64().unwrap_or_else(|| panic!("no id: {v}"))
            })
            .collect()
    }

    /// Whether an answer to `id` was written within `limit`.
    fn answered(&self, id: i64, limit: Duration) -> bool {
        let end = Instant::now() + limit;
        loop {
            if self.ids().contains(&id) {
                return true;
            }
            if Instant::now() >= end {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// What the scene's call saw, once its tool has returned.
    fn seen(&self, limit: Duration) -> Value {
        let end = Instant::now() + limit;
        loop {
            if let Some(v) = self.seen.lock().unwrap().clone() {
                return v;
            }
            assert!(Instant::now() < end, "the scene's call did not return");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Whether the server returned within `limit`.
    fn returned_within(&self, limit: Duration) -> bool {
        let server = self.server.as_ref().unwrap();
        let end = Instant::now() + limit;
        while !server.is_finished() {
            if Instant::now() >= end {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        true
    }

    /// Ends the input, releases a held write and joins the server; what it
    /// returned. A server that ended its session while its input was open
    /// returned with its reader still waiting for a line, and with its
    /// writer held: each is dropped once the end of input, or the release,
    /// reaches it, which is waited for here (finitely). Only then is the
    /// output complete.
    fn end(&mut self) -> std::io::Result<()> {
        self.input.end();
        self.output.release();
        let done = self.server.take().unwrap().join().unwrap();
        let end = Instant::now() + Duration::from_secs(30);
        while !(self.input.reader_dropped() && self.output.writer_dropped()) {
            assert!(
                Instant::now() < end,
                "the server kept its input ({}) or its output ({})",
                !self.input.reader_dropped(),
                !self.output.writer_dropped()
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        done
    }
}

/// Every answer written is valid and answers a request once.
fn unique(ids: &[i64]) -> bool {
    let set: std::collections::BTreeSet<_> = ids.iter().collect();
    set.len() == ids.len()
}

/// Gate 1: a call whose child ends by itself is answered once, with the
/// child's code, and every holder of the lifeline has exited: a silent
/// observer would pass the cancellation gates by never seeing an end, and
/// this shows it sees one.
#[test]
fn a_finished_call_is_answered_once_and_its_processes_are_gone() {
    let mut s = Stage::new("dies-of-term", Some(Duration::from_secs(60)), false);
    let mut holders = s.start();
    s.group.stop();
    assert!(
        holders.ended_within(Duration::from_secs(10)),
        "a holder runs on"
    );
    assert!(s.answered(1, Duration::from_secs(30)));
    let seen = s.seen(Duration::from_secs(30));
    assert_eq!(seen["code"], 3, "{seen}");
    assert_eq!(
        (seen["cut"].clone(), seen["timed_out"].clone()),
        (json!(false), json!(false))
    );
    s.end().unwrap();
    assert_eq!(s.ids(), [0, 1]);
}

/// Gate 2: cancellation, sent three times, ends a leader that dies of
/// `SIGTERM` and its descendant in the same group that ignores it; the
/// cancelled call is answered nothing, and the session goes on (a ping is
/// answered).
///
/// Mutation checked: `notifications/cancelled` ignored (the router never
/// cancelling): the leader and its descendant run on, the lifeline does
/// not end and this fails.
#[test]
fn a_cancelled_call_ends_its_group_and_is_answered_nothing() {
    let mut s = Stage::new("dies-of-term", Some(Duration::from_secs(60)), false);
    let mut holders = s.start();
    s.cancel(3);
    assert!(
        holders.ended_within(Duration::from_secs(10)),
        "a process of the cancelled call's group runs on"
    );
    let seen = s.seen(Duration::from_secs(30));
    assert_eq!(seen["signal"], libc::SIGTERM, "{seen}");
    assert_eq!(seen["cancelled"], true);
    s.ping(2);
    assert!(s.answered(2, Duration::from_secs(30)));
    s.end().unwrap();
    let ids = s.ids();
    assert!(
        !ids.contains(&1),
        "the cancelled call was answered: {ids:?}"
    );
    assert!(unique(&ids));
}

/// Gate 3: a leader that takes `SIGTERM` and goes on gets a second one
/// [`TERM_GRACE`] after the first, and `SIGKILL`, with its group,
/// [`KILL_GRACE`] after that; three cancellations do not hasten either.
///
/// Mutation checked: no second `SIGTERM` (`SIGKILL` once `TERM_GRACE` has
/// passed): the leader notes one `SIGTERM` and this fails.
#[test]
fn a_leader_that_takes_sigterm_gets_a_second_and_then_sigkill() {
    let mut s = Stage::new("takes-term", Some(Duration::from_secs(60)), true);
    let mut holders = s.start();
    let start = Instant::now();
    s.cancel(3);
    assert!(
        holders.ended_within(Duration::from_secs(30)),
        "the group outlived SIGKILL"
    );
    let took = start.elapsed();
    let terms = lifeline::terms_noted(&s.group.path("terms"));
    assert_eq!(terms.len(), 2, "{terms:?}");
    let apart = terms[1] - terms[0];
    let slack = 0.2;
    assert!(apart >= TERM_GRACE.as_secs_f64() - slack, "{apart}");
    assert!(
        took >= TERM_GRACE + KILL_GRACE - Duration::from_millis(200),
        "{took:?}"
    );
    let seen = s.seen(Duration::from_secs(30));
    assert_eq!(seen["signal"], libc::SIGKILL, "{seen}");
    assert_eq!(
        (seen["cancelled"].clone(), seen["timed_out"].clone()),
        (json!(true), json!(false))
    );
    s.ping(2);
    assert!(s.answered(2, Duration::from_secs(30)));
    s.end().unwrap();
    assert!(!s.ids().contains(&1));
}

/// Gate 4: the host closes its end of the output (every write fails)
/// while it keeps its input open: the next answer's write fails, the
/// session ends, and the running call is stopped with its whole group,
/// though the input never ended.
///
/// Mutation checked: the writer's failure not waking the server (its
/// `on_close` doing nothing): the server waits for input, the call runs
/// on, the lifeline does not end and this fails.
#[test]
fn a_closed_output_stops_the_call_while_the_input_stays_open() {
    let mut s = Stage::new("dies-of-term", Some(Duration::from_secs(60)), false);
    let mut holders = s.start();
    s.output.break_writes();
    s.ping(2);
    assert!(
        holders.ended_within(Duration::from_secs(15)),
        "the call outlived the closed output"
    );
    assert!(
        s.returned_within(Duration::from_secs(30)),
        "the server waits on"
    );
    assert!(s.input.open(), "the input ended");
    s.end().unwrap();
    assert_eq!(s.ids(), [0]);
}

/// Gate 5: the host stops reading (a write held) and goes on sending: once
/// the answers waiting reach their bound, the session ends with
/// [`Stalled`], the running call is stopped with its group before the held
/// write is released, and the server returns while the input is still
/// open. Released, the writer drains the answers it had admitted, each
/// once and in order, and nothing for the stopped call.
///
/// Mutation checked: no bound on the answers waiting (every one queued):
/// the session never stalls, the call runs on, the lifeline does not end
/// before the release and this fails.
#[test]
fn a_flood_behind_a_held_write_stops_the_call_before_the_release() {
    let mut s = Stage::new("dies-of-term", Some(Duration::from_secs(60)), false);
    let mut holders = s.start();
    s.output.hold_next();
    s.ping(2);
    assert!(
        s.output.entered(Duration::from_secs(30)),
        "the write was not held"
    );
    let before = s.output.bytes().len();
    for id in 3..4099 {
        s.ping(id);
    }
    assert!(
        holders.ended_within(Duration::from_secs(15)),
        "the call outlived the stall"
    );
    assert!(
        s.returned_within(Duration::from_secs(30)),
        "the server waits on"
    );
    assert!(s.input.open(), "the input ended");
    assert_eq!(
        s.output.bytes().len(),
        before,
        "a held write let bytes through"
    );
    let done = s.end();
    let err = done.unwrap_err();
    assert!(err.get_ref().is_some_and(|e| e.is::<Stalled>()), "{err:?}");
    let ids = s.ids();
    let admitted: Vec<i64> = std::iter::once(0)
        .chain(2..2 + i64::try_from(envcloak_mcp::stdio::MAX_QUEUED).unwrap())
        .collect();
    assert_eq!(ids, admitted);
}

/// Gate 6: a call past its limit is killed with its group, and answered,
/// told from a cancelled one (`timed_out`, not cancelled); its output,
/// which no one else held, is read to its end. A call cancelled before its
/// child starts starts nothing: the fixture never connects.
///
/// Mutation checked: the limit killing the leader alone (`SIGKILL` to its
/// pid, not its group) and not counting as a stop at its exit: the
/// descendant runs on holding the lifeline and the output, and this
/// fails.
#[test]
fn a_timed_out_call_is_told_from_a_cancelled_one_and_a_precancelled_one_starts_nothing() {
    let mut s = Stage::new("dies-of-term", Some(Duration::from_secs(2)), false);
    let mut holders = s.start();
    assert!(
        holders.ended_within(Duration::from_secs(15)),
        "the group outlived its limit"
    );
    assert!(s.answered(1, Duration::from_secs(30)));
    let seen = s.seen(Duration::from_secs(30));
    assert_eq!(seen["signal"], libc::SIGKILL, "{seen}");
    assert_eq!(
        (
            seen["timed_out"].clone(),
            seen["cancelled"].clone(),
            seen["cut"].clone()
        ),
        (json!(true), json!(false), json!(false))
    );
    s.end().unwrap();

    let group = Lifeline::new();
    let call = Call::new();
    call.cancel();
    let cmd = lifeline::fixture("dies-of-term", &group, None, None);
    assert_eq!(
        child::run(cmd, &call, None).unwrap_err(),
        child::NotRun::Cancelled
    );
    assert!(
        group.accept(Duration::from_millis(500)).is_none(),
        "a cancelled call started its child"
    );
}

/// Gate 7, the negative control: a descendant that left the leader's group
/// is outside what the server owns. Cancelled, the leader dies; the
/// descendant runs on, holding the lifeline and the output, which is cut
/// at the drain's end; it ends only at the fixture's stop request. So the
/// observer sees a survivor when there is one, and no whole-tree claim is
/// made.
#[test]
fn a_descendant_outside_the_group_is_not_signalled_and_the_output_is_cut() {
    let mut s = Stage::new("escape", Some(Duration::from_secs(60)), false);
    let mut holders = s.start();
    s.cancel(1);
    let seen = s.seen(Duration::from_secs(30));
    assert_eq!(seen["signal"], libc::SIGTERM, "{seen}");
    assert_eq!(seen["cut"], true, "{seen}");
    assert!(
        !holders.ended_within(Duration::from_millis(300)),
        "the escaped descendant was signalled"
    );
    s.group.stop();
    assert!(
        holders.ended_within(Duration::from_secs(10)),
        "the stop request was not taken"
    );
    s.ping(2);
    assert!(s.answered(2, Duration::from_secs(30)));
    s.end().unwrap();
    assert!(!s.ids().contains(&1));
}

/// An answer the host cancels while it waits behind a write the host does
/// not read is never written (Codex review of M2-06, medium). The call is
/// cancelled once its child has ended and its tool has returned, so its
/// answer is on its way to the writer, held behind the answer to a ping;
/// the held write is released only once the server has handled the
/// cancellation (the reader has read two lines past it). Whether the
/// cancellation reached the answer before it was queued or after (in the
/// queue), nothing is written for it, and the ping's answer and those
/// after it are. `src/lib.rs`'s
/// `a_cancellation_withdraws_an_answer_waiting_to_be_written` pins the
/// queued case down.
#[test]
fn a_cancelled_answer_waiting_behind_a_held_write_is_never_written() {
    let mut s = Stage::new("dies-of-term", Some(Duration::from_secs(60)), false);
    let mut holders = s.start();
    s.output.hold_next();
    s.ping(2);
    assert!(
        s.output.entered(Duration::from_secs(30)),
        "the write was not held"
    );
    s.group.stop();
    assert!(
        holders.ended_within(Duration::from_secs(10)),
        "a holder runs on"
    );
    let seen = s.seen(Duration::from_secs(30));
    assert_eq!(seen["code"], 3, "{seen}");
    s.cancel(1);
    s.ping(3);
    s.ping(4);
    assert!(
        s.input.all_read(Duration::from_secs(30)),
        "the server did not read on"
    );
    s.output.release();
    assert!(s.answered(4, Duration::from_secs(30)));
    s.end().unwrap();
    let ids = s.ids();
    assert!(
        !ids.contains(&1),
        "the cancelled answer was written: {ids:?}"
    );
    assert_eq!(ids, [0, 2, 3, 4]);
}
