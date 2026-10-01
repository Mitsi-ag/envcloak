//! Waiting and finding a request over the daemon's socket (SPEC §6.1 step
//! 4, §10b; M2 plan D-04): `pending.state`, answered only to the request's
//! own process tree, within its root's poll limit, opening nothing and
//! auditing nothing; `pending.list`, answered only where a proof would be
//! taken; and a waiter on fresh connections ([`wait_for_run`]) that sees an
//! approval at its next poll and a lock as the end of its request. The
//! store's rules on synthetic chains are in
//! `crates/envcloak-policy/tests/pending.rs`, the schedule in
//! `crates/envcloak-ipc/tests/wait.rs`, and `envcloak run --wait` and
//! `envcloak pending` with real agents in
//! `crates/envcloak-cli/tests/wait.rs`.
//!
//! The caller is this test process, made a terminal session first, as in
//! tests/grants.rs; a request from another tree is made by a child of this
//! test binary that leads a session on a pseudo-terminal of its own
//! ([`pending_child`]). Under a developer's agent the approvals are
//! refused, as they must be; run the tests outside its tree then.
#![allow(clippy::unwrap_used)]

mod common;

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use common::{MANIFEST, client, passphrase, project, seed_vault};
use envcloak_core::SecretBytes;
use envcloak_ipc::proto::{ErrorKind, RunRequestParams};
use envcloak_ipc::view::{DecisionView, VaultState};
use envcloak_ipc::wait::{Fresh, MAX_WAIT, SLOW_POLL, SystemClock, Waited, wait_for_run};
use envcloak_ipc::{Client, ClientError, RunPaths};
use envcloak_policy::{ApprovalOptions, PendingId, PendingState, SubjectKind, statement_digest};
use envcloak_testkit::{
    Canary, Daemon, TestHome, assert_no_canary, by_label, canaries, fresh_seed, labels,
};

fn rpc_kind(e: ClientError) -> (ErrorKind, Option<&'static str>) {
    match e {
        ClientError::Rpc(r) => (r.kind, r.reason),
        other => panic!("expected an error response, got {other:?}"),
    }
}

/// A seeded vault, a daemon (with its test trace) with it unlocked, and
/// the project.
struct Fixture {
    cs: Vec<Canary>,
    home: TestHome,
    d: Daemon,
    manifest: String,
}

impl Fixture {
    fn new() -> Self {
        common::terminal_session();
        let cs = canaries(fresh_seed());
        let home = TestHome::new();
        let kit = seed_vault(&home, &cs);
        let mut cs = cs;
        cs.push(kit);
        let mut cmd = Command::new(common::exe());
        home.apply(&mut cmd).env(envcloak_sys::testing::TRACE, "1");
        let d = Daemon::start_command(cmd, &[]);
        let mut c = client(&home);
        c.unlock(passphrase(&cs), &[]).unwrap();
        assert_eq!(c.status().unwrap().vault.state, VaultState::Unlocked);
        let manifest = project(&home, "acme-web", MANIFEST);
        Fixture {
            cs,
            home,
            d,
            manifest: manifest.to_str().unwrap().to_owned(),
        }
    }

    fn params(&self, argv: &[&str]) -> RunRequestParams {
        RunRequestParams {
            manifest: self.manifest.clone(),
            profile: None,
            refs: Vec::new(),
            env_file: None,
            argv: argv.iter().map(|a| (*a).to_owned()).collect(),
            claims: Vec::new(),
        }
    }

    fn paths(&self) -> RunPaths {
        common::run_paths(&self.home)
    }

    fn approve(&self, id: &str, opts: ApprovalOptions) -> String {
        let mut c = client(&self.home);
        let d = c.pending_get(id, &[]).unwrap();
        let digest = statement_digest(&d, &opts);
        let pass = by_label(&self.cs, labels::VAULT_PASSPHRASE).value();
        c.approve(id, opts, &digest, SecretBytes::copy_from(pass), &[])
            .unwrap()
            .grant
    }

    /// How many audit lines the daemon has written.
    fn audited(&self) -> usize {
        self.d.log().matches("envcloakd: audit: ").count()
    }

    fn sweep(&self) {
        assert_no_canary(&self.d.log_bytes(), &self.cs);
        self.home.assert_clean(&self.cs);
    }
}

fn pending(d: &DecisionView) -> String {
    match d {
        DecisionView::Pending { request } => request.clone(),
        other => panic!("expected pending, got {other:?}"),
    }
}

/// `pending.state` on a fresh connection, as a waiter asks it.
fn state(f: &Fixture, id: &str) -> Result<PendingState, ClientError> {
    client(&f.home).pending_state(&PendingId::parse(id).unwrap())
}

/// Set in the environment of [`pending_child`]: its mode (`requester`,
/// `terminal` or `no_terminal`), the daemon's run directory and the
/// manifest's path, a line each.
const CHILD_ENV: &str = "ENVCLOAK_TEST_PENDING_CHILD";

/// Runs only as a child of a test here: this test binary again, as a
/// process of another tree. `requester` and `terminal` lead a session on
/// a pseudo-terminal of their own, as a person's command in another
/// terminal window; `no_terminal` leads one without a terminal, as a
/// service manager's job. A `requester` first asks `run.request` and
/// prints `id=<id>`. Then each mode prints `ready` and answers the lines
/// on its standard input until it closes: `poll <id>` with `state=<word>`
/// (or `state=busy`), `list` with `list=<ids>` (comma-separated).
#[test]
fn pending_child() {
    let Some(spec) = std::env::var_os(CHILD_ENV) else {
        return;
    };
    let spec = spec.into_string().unwrap();
    let mut lines = spec.lines();
    let (mode, run_dir, manifest) = (
        lines.next().unwrap(),
        lines.next().unwrap(),
        lines.next().unwrap(),
    );
    match mode {
        "requester" | "terminal" => common::terminal_session(),
        "no_terminal" => envcloak_sys::testing::setsid().unwrap(),
        other => panic!("unknown mode {other}"),
    }
    let paths = RunPaths::under(std::path::PathBuf::from(run_dir)).unwrap();
    if mode == "requester" {
        let answer = Client::connect(&paths)
            .unwrap()
            .run_request(&RunRequestParams {
                manifest: manifest.to_owned(),
                profile: None,
                refs: Vec::new(),
                env_file: None,
                argv: vec!["./child".to_owned()],
                claims: Vec::new(),
            })
            .unwrap();
        println!("\nid={}", pending(&answer.decision));
    }
    println!("\nready");
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap();
        let mut c = Client::connect(&paths).unwrap();
        if let Some(id) = line.strip_prefix("poll ") {
            let answer = c.pending_state(&PendingId::parse(id).unwrap());
            println!("\nstate={}", answer.map_or("busy", PendingState::word));
        } else if line == "list" {
            let list = c.pending_list(&[]).unwrap();
            let ids: Vec<&str> = list.requests.iter().map(|r| r.request.as_str()).collect();
            println!("\nlist={}", ids.join(","));
        }
    }
}

/// A [`pending_child`] running, asked one line at a time.
struct Other {
    child: Child,
    stdin: Option<ChildStdin>,
    out: BufReader<ChildStdout>,
}

impl Other {
    fn start(f: &Fixture, mode: &str) -> (Other, Option<String>) {
        let run_dir = envcloak_testkit::daemon_run_dir(&f.home);
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        f.home
            .apply(&mut cmd)
            .args([
                "--exact",
                "pending_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(
                CHILD_ENV,
                format!("{mode}\n{}\n{}", run_dir.to_str().unwrap(), f.manifest),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = cmd.spawn().unwrap();
        let stdin = child.stdin.take();
        let out = BufReader::new(child.stdout.take().unwrap());
        let mut o = Other { child, stdin, out };
        let id = (mode == "requester").then(|| o.line("id="));
        o.line("ready");
        (o, id)
    }

    /// The next line that starts with `prefix`, without it.
    fn line(&mut self, prefix: &str) -> String {
        loop {
            let mut l = String::new();
            assert!(
                self.out.read_line(&mut l).unwrap() > 0,
                "the child ended before {prefix}"
            );
            if let Some(rest) = l.trim_end().strip_prefix(prefix) {
                return rest.to_owned();
            }
        }
    }

    fn ask(&mut self, line: &str, prefix: &str) -> String {
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{line}").unwrap();
        stdin.flush().unwrap();
        self.line(prefix)
    }
}

impl Drop for Other {
    fn drop(&mut self) {
        // Its input closes and it ends by itself; killed only while it is
        // still this test's unreaped child.
        drop(self.stdin.take());
        let end = Instant::now() + Duration::from_secs(30);
        while Instant::now() < end {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// D-04: a request's state is told only to its own process tree. Another
/// tree's process (this test process, which is the requester's parent but
/// not in its tree) is told `unknown` for the live request, exactly as
/// for an id no request has; the requester is told `pending`, then
/// `approved`. Asking opens no request and writes no audit entry.
///
/// Mutation: answer the real state to any caller (drop the tree check in
/// `GrantStore::poll`): this process is told `pending` and this fails.
#[test]
fn a_requests_state_is_told_only_to_its_own_tree() {
    let f = Fixture::new();
    let (mut other, id) = Other::start(&f, "requester");
    let id = id.unwrap();
    let mut c = client(&f.home);
    assert_eq!(c.status().unwrap().approvals.pending, 1);
    let before = f.audited();
    assert_eq!(state(&f, &id).unwrap(), PendingState::Unknown);
    assert_eq!(state(&f, "ZZZZZZZZ").unwrap(), PendingState::Unknown);
    assert_eq!(other.ask(&format!("poll {id}"), "state="), "pending");
    let st = c.status().unwrap();
    assert_eq!((st.approvals.grants, st.approvals.pending), (0, 1));
    assert_eq!(f.audited(), before, "pending.state wrote an audit entry");

    // Approved from this terminal session (another tree than the
    // requester's): the requester is told so, and this process still
    // only `unknown`.
    f.approve(&id, ApprovalOptions::once(Duration::from_secs(600)));
    assert_eq!(other.ask(&format!("poll {id}"), "state="), "approved");
    assert_eq!(state(&f, &id).unwrap(), PendingState::Unknown);

    // A malformed id is malformed for everyone.
    let mut s = common::raw(&f.home);
    common::send_json(
        &mut s,
        &serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "pending.state",
            "params": {"request": "not an id"}}),
    );
    assert_eq!(
        common::error_kind(&common::read_json(&mut s).unwrap()),
        "invalid_params"
    );
    common::send_json(
        &mut s,
        &serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "pending.state",
            "params": {"request": id, "claims": ["CLAUDECODE"]}}),
    );
    assert_eq!(
        common::error_kind(&common::read_json(&mut s).unwrap()),
        "invalid_params",
        "pending.state takes no claims"
    );
    drop(other);
    f.sweep();
}

/// D-04's poll limit at the socket: a root with one live request may poll
/// four times a second; more at once are refused `busy`, and a second
/// later it may poll again.
#[test]
fn polls_over_the_roots_limit_are_busy() {
    let f = Fixture::new();
    let id = pending(
        &client(&f.home)
            .run_request(&f.params(&["./emit"]))
            .unwrap()
            .decision,
    );
    // Twelve polls on one connection, as fast as they come: the bucket
    // holds four, and refills four a second.
    let id = PendingId::parse(&id).unwrap();
    let mut c = client(&f.home);
    let started = Instant::now();
    let answers: Vec<Result<PendingState, ClientError>> =
        (0..12).map(|_| c.pending_state(&id)).collect();
    let took = started.elapsed();
    assert_eq!(answers[..4], [Ok(PendingState::Pending); 4], "{answers:?}");
    for a in &answers {
        match a {
            Ok(s) => assert_eq!(*s, PendingState::Pending),
            Err(e) => assert_eq!(rpc_kind(*e), (ErrorKind::Busy, None)),
        }
    }
    let ok = answers.iter().filter(|a| a.is_ok()).count();
    let refilled = usize::try_from(took.as_millis() * 4 / 1000).unwrap();
    assert!(ok <= 4 + refilled + 1, "{ok} in {took:?}: {answers:?}");
    assert!(ok < 12, "never busy in {took:?}: {answers:?}");
    std::thread::sleep(Duration::from_millis(1100));
    assert_eq!(c.pending_state(&id).unwrap(), PendingState::Pending);
    f.sweep();
}

/// D-04, `pending.list`: the requests a caller may approve. A request from
/// this session claiming an agent's marker (an agent subject by its
/// claims, rooted here) is not listed to this session, which shares its
/// session and terminal, nor to this process claiming the marker, nor to
/// a caller without a terminal; a person's terminal elsewhere lists it,
/// with its id, kind, project and bindings. This session lists its own
/// terminal request: a person approves their own terminal's request.
///
/// Mutation: no proof check in `pending.list` (no early return, and the
/// per-request filter only the requester's session and terminal): the
/// caller without a terminal lists the request and this fails. Removing
/// the early return alone changes nothing, since the per-request filter
/// (`approval_refusal`) begins with the same check.
#[test]
fn pending_list_shows_a_request_only_where_a_proof_would_be_taken() {
    let f = Fixture::new();
    let mut agent = f.params(&["./emit"]);
    agent.claims = vec!["CLAUDECODE".to_owned()];
    let id = pending(&client(&f.home).run_request(&agent).unwrap().decision);
    let claims = vec!["CLAUDECODE".to_owned()];
    assert!(
        client(&f.home)
            .pending_list(&[])
            .unwrap()
            .requests
            .is_empty()
    );
    assert!(
        client(&f.home)
            .pending_list(&claims)
            .unwrap()
            .requests
            .is_empty()
    );
    let (mut bare, _) = Other::start(&f, "no_terminal");
    assert_eq!(bare.ask("list", "list="), "");
    let (mut person, _) = Other::start(&f, "terminal");
    assert_eq!(person.ask("list", "list="), id);

    // What the person's terminal is shown: here, through a request of
    // this session's own, which it lists too.
    let own = pending(
        &client(&f.home)
            .run_request(&f.params(&["./own"]))
            .unwrap()
            .decision,
    );
    let list = client(&f.home).pending_list(&[]).unwrap();
    assert_eq!(list.requests.len(), 1, "{list:?}");
    let r = &list.requests[0];
    assert_eq!(r.request, own);
    assert_eq!(r.kind, SubjectKind::Terminal);
    assert_eq!(r.agent, None);
    assert!(r.project.ends_with("acme-web"), "{r:?}");
    assert_eq!(r.bindings, ["openai/acme-web", "stripe/acme-web"]);
    assert!(r.age_secs < 60 && r.expires_in_secs > 540, "{r:?}");
    let shown = person.ask("list", "list=");
    let mut both: Vec<&str> = shown.split(',').collect();
    both.sort_unstable();
    let mut want = vec![id.as_str(), own.as_str()];
    want.sort_unstable();
    assert_eq!(both, want);
    drop((bare, person));
    f.sweep();
}

/// `pending.list` names its requests oldest first, whatever their random
/// ids, and fits in one frame however many bindings each has: three
/// requests of this session, each binding 3,002 items (3,000 `--ref`s to
/// an item with a 128-byte slug, as a long env file would), then three
/// of other sessions. Every binding listed in full would be about 1.2 MB,
/// over the 1 MiB frame: each request names its first
/// MAX_LISTED_BINDINGS and counts the rest.
///
/// Mutation: list every binding (no `take` in `pending_view`): the answer
/// exceeds the frame, the call fails and this fails. Mutation: list them
/// in the store's order (no sort in `pending_all`): the six come back
/// shuffled (in 719 orders of 720) and this fails.
#[test]
fn a_long_listing_fits_one_frame_oldest_first() {
    use envcloak_ipc::view::MAX_LISTED_BINDINGS;
    let f = Fixture::new();
    let slug = format!("long/{}", "a".repeat(123));
    assert_eq!(slug.len(), 128);
    client(&f.home)
        .items_add(&envcloak_ipc::proto::AddParams {
            slug: Some(slug.clone()),
            provider: None,
            field: None,
            account: None,
            env_hint: None,
            allow_short: false,
            value: envcloak_ipc::WireSecret::new(SecretBytes::copy_from(
                by_label(&f.cs, labels::DATABASE_URL).value(),
            )),
            claims: Vec::new(),
        })
        .unwrap();
    let mut opened = Vec::new();
    for n in 0..3 {
        let mut p = f.params(&[&format!("./job-{n}")]);
        p.refs = (0..3000).map(|i| format!("V{i}={slug}")).collect();
        opened.push(pending(&client(&f.home).run_request(&p).unwrap().decision));
    }
    let mut others = Vec::new();
    for _ in 0..3 {
        let (other, id) = Other::start(&f, "requester");
        opened.push(id.unwrap());
        others.push(other);
    }
    let list = client(&f.home).pending_list(&[]).unwrap();
    let ids: Vec<&str> = list.requests.iter().map(|r| r.request.as_str()).collect();
    assert_eq!(ids, opened);
    for r in &list.requests[..3] {
        assert_eq!(r.bindings.len(), MAX_LISTED_BINDINGS);
        assert_eq!(
            r.more_bindings,
            u64::try_from(3002 - MAX_LISTED_BINDINGS).unwrap()
        );
        assert!(r.bindings.contains(&slug), "{:?}", r.bindings);
    }
    for r in &list.requests[3..] {
        assert_eq!(r.bindings, ["openai/acme-web", "stripe/acme-web"]);
        assert_eq!(r.more_bindings, 0);
    }
    drop(others);
    f.sweep();
}

/// A request over the per-root cap, asked again and again, is audited
/// once at first (`count=1`); the answers after it are counted and
/// written together, here when the vault locks (`count=3`), not one
/// entry each.
///
/// Mutation: audit every `too_many_pending` answer (write each in
/// `State::audit_crowded`): four entries are written and this fails.
/// Mutation: drop the counted answers at the lock (no drain in
/// `State::lock`): no `count=3` entry comes and this fails.
#[test]
fn a_crowded_request_is_audited_once_with_its_count() {
    let f = Fixture::new();
    for n in 0..3 {
        pending(
            &client(&f.home)
                .run_request(&f.params(&[&format!("./job-{n}")]))
                .unwrap()
                .decision,
        );
    }
    for _ in 0..4 {
        let e = client(&f.home)
            .run_request(&f.params(&["./crowded"]))
            .unwrap_err();
        assert_eq!(
            rpc_kind(e),
            (ErrorKind::TooManyPending, Some("pending_per_root"))
        );
    }
    assert!(client(&f.home).lock().unwrap().was_unlocked);
    // The barrier: the entry the lock writes for the counted answers,
    // after every earlier one.
    let crowded = |log: &str| -> Vec<String> {
        log.lines()
            .filter(|l| l.starts_with("envcloakd: audit: request decision=too_many_pending "))
            .map(str::to_owned)
            .collect()
    };
    let end = Instant::now() + Duration::from_secs(30);
    while !crowded(&f.d.log()).iter().any(|l| l.ends_with(" count=3")) {
        assert!(Instant::now() < end, "{}", f.d.log());
        std::thread::sleep(Duration::from_millis(20));
    }
    let lines = crowded(&f.d.log());
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(lines[0].ends_with(" count=1"), "{lines:?}");
    assert!(lines[0].contains(" id=pending_per_root "), "{lines:?}");
    f.sweep();
}

/// A waiter on fresh connections sees an approval at its next poll: this
/// test approves once the trace shows the request polled (the barrier),
/// and the first `pending.state` the daemon answers after the approval is
/// `approved`, then `run.request` is covered, within one pause.
#[test]
fn an_approval_is_seen_at_the_next_poll() {
    let f = Fixture::new();
    let (tx, rx) = mpsc::channel();
    let params = f.params(&["./emit"]);
    let paths = f.paths();
    let waiter = std::thread::spawn(move || {
        let mut t = Fresh {
            paths: &paths,
            params: &params,
        };
        let mut ids = Vec::new();
        let got = wait_for_run(&mut t, &mut SystemClock::new(), MAX_WAIT, &mut |n| {
            ids.push(n);
        });
        let _ = tx.send((
            got.map(|w| match w {
                Waited::Answer(a) => format!("{:?}", a.decision),
                other => format!("{other:?}"),
            }),
            ids.len(),
        ));
    });
    // The barrier: the request is pending and has been polled twice.
    let polled = |f: &Fixture| {
        f.d.log()
            .lines()
            .filter(|l| {
                l.starts_with("envcloakd: test: pending.state ") && l.ends_with("answer=pending")
            })
            .count()
    };
    let end = Instant::now() + Duration::from_secs(30);
    while polled(&f) < 2 {
        assert!(Instant::now() < end, "{}", f.d.log());
        std::thread::sleep(Duration::from_millis(20));
    }
    let id = client(&f.home).pending_list(&[]).unwrap().requests[0]
        .request
        .clone();
    f.approve(&id, ApprovalOptions::once(Duration::from_secs(600)));
    let approved = Instant::now();
    let (got, announced) = rx.recv_timeout(Duration::from_secs(30)).unwrap();
    let took = approved.elapsed();
    waiter.join().unwrap();
    let got = got.unwrap();
    assert!(got.starts_with("Covered"), "{got}");
    assert_eq!(announced, 1, "the request is announced once");
    assert!(
        took < SLOW_POLL + Duration::from_secs(2),
        "{took:?} after the approval"
    );
    // In the daemon's order: after the approval's audit line, every poll
    // of the request was answered `approved` (exactly one), never
    // `pending`.
    let log = f.d.log();
    let after = log
        .split_once(&format!("audit: approved request={id} "))
        .unwrap()
        .1;
    let polls: Vec<&str> = after
        .lines()
        .filter(|l| l.contains("pending.state pid=") && l.contains(&id))
        .collect();
    assert_eq!(polls.len(), 1, "{log}");
    assert!(polls[0].ends_with("answer=approved"), "{log}");
    f.sweep();
}

/// A lock ends the wait: the request is gone (`unknown` to its tree), and
/// asked again `run.request` says the vault is locked, which ends the
/// waiter with that error. A denial ends it as denied.
#[test]
fn a_lock_or_a_denial_ends_the_wait() {
    let f = Fixture::new();
    for end in ["lock", "deny"] {
        let (tx, rx) = mpsc::channel();
        let params = f.params(&[&format!("./{end}")]);
        let paths = f.paths();
        let waiter = std::thread::spawn(move || {
            let mut t = Fresh {
                paths: &paths,
                params: &params,
            };
            let got = wait_for_run(&mut t, &mut SystemClock::new(), MAX_WAIT, &mut |_| {});
            let _ = tx.send(got.map(|w| format!("{w:?}")));
        });
        let end_at = Instant::now() + Duration::from_secs(30);
        let id = loop {
            if let Some(r) = client(&f.home).pending_list(&[]).unwrap().requests.first() {
                break r.request.clone();
            }
            assert!(Instant::now() < end_at);
            std::thread::sleep(Duration::from_millis(20));
        };
        let got = if end == "lock" {
            assert!(client(&f.home).lock().unwrap().was_unlocked);
            let got = rx.recv_timeout(Duration::from_secs(30)).unwrap();
            client(&f.home).unlock(passphrase(&f.cs), &[]).unwrap();
            got
        } else {
            client(&f.home).deny(&id).unwrap();
            rx.recv_timeout(Duration::from_secs(30)).unwrap()
        };
        waiter.join().unwrap();
        match end {
            "lock" => assert_eq!(got.map_err(rpc_kind), Err((ErrorKind::VaultLocked, None))),
            _ => assert_eq!(got.unwrap(), format!("Denied(PendingId({id}))")),
        }
    }
    f.sweep();
}
