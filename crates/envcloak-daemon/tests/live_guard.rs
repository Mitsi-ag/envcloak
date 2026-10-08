//! The live-key guard over the daemon's socket (SPEC §10b "Live-key
//! guard", "Writes that need a proof", "A grant ends on"; gate 40,
//! sentences 1 and 2; M2 plan M2-13): an agent's or an unknown subject's
//! approval that leaves a live binding unticked makes no grant and is
//! audited; a terminal subject's is as in M1; the same provider's test item
//! is proposed in the pending answer and the statement, read from the
//! vault each time; `items.reclassify` tightens with no proof and loosens
//! only with one, and either change ends the grants and pending requests
//! that bind the item; a rotation that makes a test item live does too
//! (F-47). The store's rules on synthetic chains are in
//! `crates/envcloak-policy/tests/grants.rs`, the statement's in
//! `crates/envcloak-policy/tests/statement.rs`, and `envcloak approve`,
//! `envcloak run` and `envcloak items reclassify` in
//! `crates/envcloak-cli/tests/live_guard.rs`.
//!
//! This test process is the person: a terminal session, as in
//! tests/grants.rs. The requests the guard is for come from a child of
//! this test binary in another tree ([`live_child`]): an agent (a session
//! on a pseudo-terminal of its own, claiming an agent's marker) or an
//! unknown subject (a session without a terminal). Under a developer's
//! agent the approvals are refused, as they must be; run the tests outside
//! its tree then.
#![allow(clippy::unwrap_used)]

mod common;

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use common::{client, passphrase, project, seed_vault, start};
use envcloak_core::SecretBytes;
use envcloak_core::audit::{AuditEntry, AuditKind};
use envcloak_core::vault::{LockedVault, Vault, VaultPaths};
use envcloak_ipc::proto::{AddParams, ErrorKind, RunRequestParams};
use envcloak_ipc::view::{ClassificationView, DecisionView, TargetView};
use envcloak_ipc::{Client, ClientError, RunPaths, WireSecret};
use envcloak_policy::{
    ApprovalOptions, BindingSource, EnvName, PendingId, Proposal, SubjectKind, Uses,
    render_statement, statement_digest,
};
use envcloak_testkit::{
    Canary, Daemon, TestHome, assert_no_canary, by_label, canaries, fresh_seed, labels,
};

fn rpc_kind(e: ClientError) -> (ErrorKind, Option<&'static str>) {
    match e {
        ClientError::Rpc(r) => (r.kind, r.reason),
        other => panic!("expected an error response, got {other:?}"),
    }
}

/// A Stripe key of `kind` (`test` or `live`), made at run time.
fn stripe_key(kind: &str) -> String {
    let seed = fresh_seed();
    let tail: String = (0..32u32)
        .map(|i| {
            let n = u8::try_from((seed.rotate_left(7 * i) ^ (u64::from(i) * 0x9e37)) % 36).unwrap();
            char::from(if n < 10 { b'0' + n } else { b'a' + n - 10 })
        })
        .collect();
    format!("{}_{kind}_{tail}", concat!("s", "k"))
}

/// The project: the Stripe test item in the default profile.
const MANIFEST: &str = "[project]
name = \"acme-web\"

[env]
STRIPE_SECRET_KEY = \"stripe/acme-test\"
";

/// A seeded vault (OpenAI live, GitHub live, a short unknown value), the
/// Stripe pair `stripe/acme-test` and `stripe/acme-live` added as `envcloak
/// add` adds them (provider and classification detected), a running
/// daemon with the vault unlocked, and the project.
struct Fixture {
    cs: Vec<Canary>,
    /// The seed `cs` was made from, which a [`live_child`] makes them
    /// from again.
    seed: u64,
    home: TestHome,
    d: Daemon,
    manifest: String,
}

impl Fixture {
    fn new() -> Self {
        common::terminal_session();
        let seed = fresh_seed();
        let cs = canaries(seed);
        let home = TestHome::new();
        let kit = seed_vault(&home, &cs);
        let mut cs = cs;
        cs.push(kit);
        let d = start(&home);
        client(&home).unlock(passphrase(&cs), &[]).unwrap();
        let manifest = project(&home, "acme-web", MANIFEST);
        let mut f = Fixture {
            cs,
            seed,
            home,
            d,
            manifest: manifest.to_str().unwrap().to_owned(),
        };
        for (slug, kind, class) in [
            ("stripe/acme-test", "test", ClassificationView::Test),
            ("stripe/acme-live", "live", ClassificationView::Live),
        ] {
            let key = stripe_key(kind);
            let added = f.add(slug, &key);
            assert_eq!(added, class, "{slug}");
            f.cs.push(Canary::new(format!("STRIPE_{kind}"), key));
        }
        f
    }

    /// Adds `value` as `slug`, with no proof, as `envcloak add` does;
    /// returns the classification it was given.
    fn add(&self, slug: &str, value: &str) -> ClassificationView {
        client(&self.home)
            .items_add(&AddParams {
                slug: Some(slug.to_owned()),
                provider: None,
                field: None,
                account: None,
                env_hint: Some("STRIPE_SECRET_KEY".to_owned()),
                allow_short: false,
                value: WireSecret::new(SecretBytes::copy_from(value.as_bytes())),
                claims: Vec::new(),
            })
            .unwrap()
            .item
            .classification
    }

    fn pass(&self) -> SecretBytes {
        SecretBytes::copy_from(by_label(&self.cs, labels::VAULT_PASSPHRASE).value())
    }

    /// The statement of `id` as the daemon shows it to this terminal
    /// session.
    fn shown(&self, id: &str) -> envcloak_policy::PendingDescriptor {
        client(&self.home).pending_get(id, &[]).unwrap()
    }

    /// Approves `id` with `opts`, over the statement shown now.
    fn approve(&self, id: &str, opts: ApprovalOptions) -> Result<String, ClientError> {
        let d = self.shown(id);
        let digest = statement_digest(&d, &opts);
        client(&self.home)
            .approve(id, opts, &digest, self.pass(), &[])
            .map(|a| a.grant)
    }

    fn target(&self, slug: &str) -> TargetView {
        client(&self.home).items_target(slug, None, &[]).unwrap()
    }

    fn grants(&self) -> Vec<(String, Vec<(String, bool)>)> {
        client(&self.home)
            .grants_list()
            .unwrap()
            .grants
            .into_iter()
            .map(|g| {
                (
                    g.id,
                    g.bindings
                        .into_iter()
                        .map(|b| (b.env_name, b.live))
                        .collect(),
                )
            })
            .collect()
    }

    /// Stops the daemon (SIGTERM locks the vault first) and opens the
    /// vault here with the passphrase.
    fn stop_and_open(&mut self) -> Vault {
        self.d.signal("-TERM");
        assert!(self.d.wait_exit(Duration::from_secs(30)).is_some());
        LockedVault::open(&VaultPaths::under(common::data_dir(&self.home)))
            .unwrap()
            .unlock_with_passphrase(&self.pass())
            .map_err(|(_, e)| e)
            .unwrap()
    }

    /// Sweeps what the daemon wrote: its log and the home (the vault,
    /// audit log and backups ciphertext only).
    fn sweep(&self) {
        assert_no_canary(&self.d.log_bytes(), &self.cs);
        self.home.assert_clean(&self.cs);
    }
}

fn ticking(names: &[&str], uses: Uses) -> ApprovalOptions {
    ApprovalOptions {
        uses,
        ttl_secs: 3600,
        live: names.iter().map(|n| EnvName::new(n).unwrap()).collect(),
    }
}

/// Set in the environment of [`live_child`]: its mode (`agent`,
/// `unknown`, `ancestry` or `plain`), the daemon's run directory, the
/// manifest's path and the canaries' seed, a line each.
const CHILD_ENV: &str = "ENVCLOAK_TEST_LIVE_CHILD";
/// Set for an `ancestry` [`live_child`]: the path of `fixture-agent`.
const CHILD_AGENT: &str = "ENVCLOAK_TEST_LIVE_AGENT";

/// Runs only as a child of a test here: this test binary again, in
/// another tree. `agent` leads a session on a pseudo-terminal of its own
/// and claims Claude Code's marker, so the daemon takes it for an agent by
/// its claims; `unknown` leads a session without a terminal, as a service
/// manager's job or a command that forked out and called `setsid` does;
/// `ancestry` leads a session on a pseudo-terminal of its own and runs
/// `fixture-agent` (which the builtin catalog knows) with this binary
/// again in `plain` mode, which claims nothing: an agent by its ancestry
/// alone, with no marker. It prints `ready`, then answers each line on its
/// standard input, the `--ref` bindings separated by spaces (none on an
/// empty line), with `answer=covered`, `answer=pending <id>`,
/// `answer=denied <reason>` or `answer=error <kind>`, and
/// `proposals=<json>`. A line `reclassify <slug> <to>` instead asks
/// `items.reclassify` over the socket, with the item's id from
/// `items.show` and the vault passphrase as the proof, and answers
/// `answer=<classification>` or `answer=error <kind>`, and `proposals=[]`;
/// a line `check <id>` asks `approve` of that request without a
/// passphrase (the CLI's check), with no tick, and answers the same way.
/// A covered answer's values are dropped, and wiped, unprinted.
#[test]
fn live_child() {
    let Some(spec) = std::env::var_os(CHILD_ENV) else {
        return;
    };
    let spec = spec.into_string().unwrap();
    let mut lines = spec.lines();
    let (mode, run_dir, manifest, seed) = (
        lines.next().unwrap(),
        lines.next().unwrap(),
        lines.next().unwrap(),
        lines.next().unwrap().parse::<u64>().unwrap(),
    );
    let claims = match mode {
        "agent" => {
            common::terminal_session();
            vec!["CLAUDECODE".to_owned()]
        }
        "unknown" => {
            envcloak_sys::testing::setsid().unwrap();
            Vec::new()
        }
        "ancestry" => {
            common::terminal_session();
            let status = Command::new(std::env::var_os(CHILD_AGENT).unwrap())
                .arg("--")
                .arg(std::env::current_exe().unwrap())
                .args(["--exact", "live_child", "--nocapture", "--test-threads=1"])
                .env(CHILD_ENV, spec.replacen("ancestry", "plain", 1))
                .status()
                .unwrap();
            std::process::exit(status.code().unwrap_or(1));
        }
        "plain" => Vec::new(),
        other => panic!("unknown mode {other}"),
    };
    let paths = RunPaths::under(std::path::PathBuf::from(run_dir)).unwrap();
    println!("\nready");
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap();
        if let Some(id) = line.strip_prefix("check ") {
            let opts = ApprovalOptions {
                uses: Uses::Session,
                ttl_secs: 3600,
                live: Vec::new(),
            };
            let said = match Client::connect(&paths)
                .unwrap()
                .approve_check(id, opts, &[0u8; 32], &claims)
            {
                Ok(_) => "approved".to_owned(),
                Err(e) => format!("error {}", e.token()),
            };
            println!("\nanswer={said}\nproposals=[]");
            continue;
        }
        if let Some(rest) = line.strip_prefix("reclassify ") {
            let (slug, to) = rest.split_once(' ').unwrap();
            let to = match to {
                "test" => ClassificationView::Test,
                "unknown" => ClassificationView::Unknown,
                other => panic!("not a loosening: {other}"),
            };
            let mut c = Client::connect(&paths).unwrap();
            let item = c.items_show(slug).unwrap();
            let target = TargetView {
                item,
                field: None,
                grants: 0,
            };
            let pass =
                SecretBytes::copy_from(by_label(&canaries(seed), labels::VAULT_PASSPHRASE).value());
            let said = match c.items_reclassify(&target, to, pass, &claims) {
                Ok(done) => done.classification.as_str().to_owned(),
                Err(e) => format!("error {}", e.token()),
            };
            println!("\nanswer={said}\nproposals=[]");
            continue;
        }
        let answer = Client::connect(&paths)
            .unwrap()
            .run_request(&RunRequestParams {
                manifest: manifest.to_owned(),
                profile: None,
                refs: line.split_whitespace().map(str::to_owned).collect(),
                env_file: None,
                argv: vec!["./child".to_owned()],
                claims: claims.clone(),
                launch: None,
                bridge: None,
                fds: Vec::new(),
            });
        let (said, proposals) = match answer {
            Ok(a) => (
                match &a.decision {
                    DecisionView::Covered { .. } => "covered".to_owned(),
                    DecisionView::Pending { request } => format!("pending {request}"),
                    DecisionView::Denied { reason } => format!("denied {reason}"),
                    DecisionView::Started {} => "started".to_owned(),
                },
                serde_json::to_string(&a.proposals).unwrap(),
            ),
            Err(e) => (format!("error {}", e.token()), "[]".to_owned()),
        };
        println!("\nanswer={said}\nproposals={proposals}");
    }
}

/// A [`live_child`] running, asked one request at a time.
struct Requester {
    child: Child,
    stdin: Option<ChildStdin>,
    out: BufReader<ChildStdout>,
}

impl Requester {
    fn start(f: &Fixture, mode: &str) -> Requester {
        let run_dir = envcloak_testkit::daemon_run_dir(&f.home);
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        f.home
            .apply(&mut cmd)
            .args(["--exact", "live_child", "--nocapture", "--test-threads=1"])
            .env(
                CHILD_ENV,
                format!(
                    "{mode}\n{}\n{}\n{}",
                    run_dir.to_str().unwrap(),
                    f.manifest,
                    f.seed
                ),
            )
            .env(CHILD_AGENT, envcloak_testkit::testkit_bin("fixture-agent"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = cmd.spawn().unwrap();
        let stdin = child.stdin.take();
        let out = BufReader::new(child.stdout.take().unwrap());
        let mut r = Requester { child, stdin, out };
        r.line("ready");
        r
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

    /// `run.request` with `refs`: the answer, and the proposals.
    fn ask(&mut self, refs: &[&str]) -> (String, Vec<Proposal>) {
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{}", refs.join(" ")).unwrap();
        stdin.flush().unwrap();
        let answer = self.line("answer=");
        let proposals = serde_json::from_str(&self.line("proposals=")).unwrap();
        (answer, proposals)
    }

    /// `run.request` with `refs`, which must be pending: its id.
    fn pending(&mut self, refs: &[&str]) -> String {
        let (answer, _) = self.ask(refs);
        let id = answer
            .strip_prefix("pending ")
            .unwrap_or_else(|| panic!("expected a pending request, got {answer}"))
            .to_owned();
        PendingId::parse(&id).unwrap();
        id
    }
}

impl Drop for Requester {
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

/// The audit entries of `kind`, read from the vault the daemon left.
fn entries(v: &Vault, kind: AuditKind) -> Vec<AuditEntry> {
    let (entries, _) = v.read_audit().unwrap();
    entries
        .into_iter()
        .filter(|e| e.record.kind == kind)
        .collect()
}

/// Gate 40, sentence 1: an agent's request, and an unknown subject's,
/// with a live binding. Approved without the binding's tick, it is refused
/// `live_not_ticked` before the passphrase is looked at (a wrong one is
/// not counted), no grant is made, the request stays pending, and the
/// refusal is audited (kind `live_refused`, with the item left unticked);
/// approved with the tick, the grant holds it (`live`) and the run is
/// covered.
///
/// Asked without a passphrase (`envcloak approve`'s check, which reads
/// none where the guard refuses), the approval is refused and audited the
/// same way; with every tick it passes every check before the proof and
/// ends there (`invalid_params`), with no grant and no attempt counted.
///
/// Mutations: remove the tick check (`unticked_live` answering none): the
/// approval without `--live` makes a grant and this fails; apply it to
/// agents only (`live_guarded` false for an unknown subject): the
/// `unknown` round fails; end a check at the proof before the guard (the
/// missing passphrase refused first): the check is `invalid_params`, not
/// audited, and this fails.
#[test]
fn an_agent_or_unknown_approval_needs_each_live_tick() {
    let mut f = Fixture::new();
    for mode in ["agent", "unknown"] {
        let mut r = Requester::start(&f, mode);
        let refs = [
            "STRIPE_SECRET_KEY=stripe/acme-live",
            "OPENAI_API_KEY=openai/acme-web",
        ];
        let id = r.pending(&refs);
        let d = f.shown(&id);
        let kind = if mode == "agent" {
            SubjectKind::Agent
        } else {
            SubjectKind::Unknown
        };
        assert_eq!(d.subject.kind, kind);
        let classes: Vec<(&str, &str)> = d
            .bindings
            .iter()
            .map(|b| (b.env_name.as_str(), b.classification.as_str()))
            .collect();
        assert_eq!(
            classes,
            [("OPENAI_API_KEY", "live"), ("STRIPE_SECRET_KEY", "live")],
            "{mode}"
        );
        let mut c = client(&f.home);
        let failures = c.status().unwrap().approvals.proof_failures;
        // Without either tick, and with only one: refused, with a wrong
        // passphrase too, which is never looked at.
        for (names, pass) in [
            (
                vec![],
                SecretBytes::copy_from(b"not the passphrase, not at all"),
            ),
            (vec![], f.pass()),
            (vec!["OPENAI_API_KEY"], f.pass()),
        ] {
            let opts = ticking(&names, Uses::Session);
            let digest = statement_digest(&d, &opts);
            let e = c.approve(&id, opts, &digest, pass, &[]).unwrap_err();
            assert_eq!(
                rpc_kind(e),
                (ErrorKind::LiveNotTicked, None),
                "{mode} {names:?}"
            );
        }
        // The check without a passphrase: refused the same way, and
        // audited; with both ticks it ends at the proof it lacks.
        let opts = ticking(&[], Uses::Session);
        let e = c
            .approve_check(&id, opts.clone(), &statement_digest(&d, &opts), &[])
            .unwrap_err();
        assert_eq!(rpc_kind(e), (ErrorKind::LiveNotTicked, None), "{mode}");
        let both = ticking(&["STRIPE_SECRET_KEY", "OPENAI_API_KEY"], Uses::Session);
        let e = c
            .approve_check(&id, both.clone(), &statement_digest(&d, &both), &[])
            .unwrap_err();
        assert_eq!(rpc_kind(e), (ErrorKind::InvalidParams, None), "{mode}");
        assert_eq!(c.status().unwrap().approvals.proof_failures, failures);
        assert!(f.grants().is_empty(), "{mode}");
        assert_eq!(f.shown(&id), d, "{mode}: still pending, as it was");
        let refused =
            f.d.log()
                .matches(&format!(
                    "envcloakd: audit: approve refused reason=live_not_ticked request={id} "
                ))
                .count();
        assert_eq!(refused, 4, "{mode}");
        // Both ticked: the grant holds both, and the run is covered.
        let g = f
            .approve(
                &id,
                ticking(&["STRIPE_SECRET_KEY", "OPENAI_API_KEY"], Uses::Session),
            )
            .unwrap();
        let grants = f.grants();
        assert_eq!(grants.len(), 1, "{mode}");
        assert_eq!(grants[0].0, g);
        assert_eq!(
            grants[0].1,
            [
                ("OPENAI_API_KEY".to_owned(), true),
                ("STRIPE_SECRET_KEY".to_owned(), true)
            ]
        );
        assert_eq!(r.ask(&refs).0, "covered", "{mode}");
        drop(r);
        assert_eq!(
            client(&f.home).grants_revoke(None).unwrap().revoked,
            1,
            "{mode}"
        );
    }
    // The audit log holds the refusals by kind, each naming the request
    // and the items left unticked, never a value.
    let v = f.stop_and_open();
    let refused = entries(&v, AuditKind::LiveRefused);
    assert_eq!(refused.len(), 8);
    for e in &refused {
        assert_eq!(e.record.decision.outcome, "refused");
        assert_eq!(e.record.decision.reason.as_deref(), Some("live_not_ticked"));
        assert!(e.record.request_id.is_some());
        let slugs: Vec<&str> = e.record.items.iter().map(|(_, s)| s.as_str()).collect();
        assert!(slugs.contains(&"stripe/acme-live"), "{slugs:?}");
        assert_no_canary(format!("{:?}", e.record).as_bytes(), &f.cs);
    }
    drop(v);
    f.sweep();
}

/// Gate 40's other side: a terminal subject's live bindings need no tick,
/// as in M1 (SPEC §10b: the guard is for agent and unknown subjects).
#[test]
fn a_terminal_subject_needs_no_live_tick() {
    let f = Fixture::new();
    let params = RunRequestParams {
        manifest: f.manifest.clone(),
        profile: None,
        refs: vec!["STRIPE_SECRET_KEY=stripe/acme-live".to_owned()],
        env_file: None,
        argv: vec!["./emit".to_owned()],
        claims: Vec::new(),
        launch: None,
        bridge: None,
        fds: Vec::new(),
    };
    let DecisionView::Pending { request } = client(&f.home).run_request(&params).unwrap().decision
    else {
        panic!("expected a pending request");
    };
    let d = f.shown(&request);
    assert_eq!(d.subject.kind, SubjectKind::Terminal);
    assert_eq!(d.bindings[0].classification, "live");
    f.approve(&request, ticking(&[], Uses::Session)).unwrap();
    assert!(matches!(
        client(&f.home).run_request(&params).unwrap().decision,
        DecisionView::Covered { .. }
    ));
    f.sweep();
}

/// Gate 40, sentence 2: the test item is proposed. A pending answer names,
/// for the live binding, the same provider's test item (which the
/// `approval_required` text shows), and so does the statement, before the
/// bindings; the daemon substitutes nothing (the request still binds the
/// live item). The proposals are read from the vault when the statement is
/// shown and again when it is approved: one read before the test item was
/// reclassified is a `statement_mismatch`, and the one shown now approves.
///
/// Mutation: leave the proposals out of the digest (`canonical_statement`
/// without them): the statement read before approves, and this fails.
#[test]
fn the_test_item_is_proposed_and_a_changed_proposal_is_a_mismatch() {
    let f = Fixture::new();
    let mut r = Requester::start(&f, "agent");
    let (answer, proposals) = r.ask(&["STRIPE_SECRET_KEY=stripe/acme-live"]);
    let id = answer.strip_prefix("pending ").unwrap().to_owned();
    let expected = vec![Proposal {
        env_name: "STRIPE_SECRET_KEY".to_owned(),
        live_slug: "stripe/acme-live".to_owned(),
        test_slug: "stripe/acme-test".to_owned(),
        test_field: None,
        // Asked with `--ref`: the advice is to give another.
        source: BindingSource::Ref,
    }];
    assert_eq!(proposals, expected);
    let read = f.shown(&id);
    assert_eq!(read.proposals, expected);
    assert_eq!(read.bindings[0].slug, "stripe/acme-live");
    let opts = ticking(&["STRIPE_SECRET_KEY"], Uses::Once);
    let text = render_statement(&read, &opts);
    let test = text
        .find("give `--ref STRIPE_SECRET_KEY=stripe/acme-test` in place of the --ref")
        .unwrap();
    let live = text.find("STRIPE_SECRET_KEY = stripe/acme-live").unwrap();
    assert!(test < live, "{text}");
    let digest = statement_digest(&read, &opts);
    // The test item becomes live (no proof: tightening). The request does
    // not bind it, so it stays; its statement no longer proposes it.
    let done = client(&f.home)
        .items_reclassify_live("stripe/acme-test", &[])
        .unwrap();
    assert_eq!(done.reclassified_from, Some(ClassificationView::Test));
    let now = f.shown(&id);
    assert!(now.proposals.is_empty(), "{now:?}");
    let mut c = client(&f.home);
    let e = c
        .approve(&id, opts.clone(), &digest, f.pass(), &[])
        .unwrap_err();
    assert_eq!(rpc_kind(e), (ErrorKind::StatementMismatch, None));
    assert!(f.grants().is_empty());
    let g = c
        .approve(
            &id,
            opts.clone(),
            &statement_digest(&now, &opts),
            f.pass(),
            &[],
        )
        .unwrap();
    assert!(!g.grant.is_empty());
    // A pending answer with nothing to propose carries none.
    let (answer, proposals) = r.ask(&["STRIPE_SECRET_KEY=stripe/acme-live", "X=openai/acme-web"]);
    assert!(answer.starts_with("pending "), "{answer}");
    assert!(proposals.is_empty(), "{proposals:?}");
    drop(r);
    f.sweep();
}

/// A request asked again under one root through another layer is pending
/// on its own, and each pending answer proposes what its statement does
/// (Codex, round 3: deduplication by the fingerprint alone answered a
/// request repeated through `[env]` with the id of the one asked through
/// `--ref`, its advice built from `[env]` while the statement, from the
/// request first made, advised the `--ref`; following the statement left
/// the live binding of `[env]` in place). The live Stripe key is bound by
/// `--ref`, then, the manifest changed to bind it in `[env]`, by `[env]`:
/// the same variable, item and field, two requests. Asked again through
/// either layer, the request already pending for it.
///
/// Mutation: deduplicate by the fingerprint alone (`same_layers`
/// answering true): the `[env]` request gets the `--ref` request's id,
/// its answer advises `[env]` while the statement advises the `--ref`,
/// and this fails.
#[test]
fn a_request_through_another_layer_is_pending_on_its_own() {
    let f = Fixture::new();
    let mut r = Requester::start(&f, "agent");
    let live_ref = "STRIPE_SECRET_KEY=stripe/acme-live";
    let (by_ref, by_ref_proposed) = r.ask(&[live_ref]);
    let by_ref = by_ref.strip_prefix("pending ").unwrap().to_owned();
    // The manifest's `[env]` binds the live key now.
    let manifest = std::fs::read_to_string(&f.manifest).unwrap();
    let changed = manifest.replace(
        "STRIPE_SECRET_KEY = \"stripe/acme-test\"",
        "STRIPE_SECRET_KEY = \"stripe/acme-live\"",
    );
    assert_ne!(changed, manifest);
    std::fs::write(&f.manifest, changed).unwrap();
    let (by_env, by_env_proposed) = r.ask(&[]);
    let by_env = by_env.strip_prefix("pending ").unwrap().to_owned();
    assert_ne!(by_env, by_ref, "one pending request for two layers");
    // Each answer proposes what its statement does, for its own layer.
    for (id, proposed, source) in [
        (&by_ref, &by_ref_proposed, BindingSource::Ref),
        (&by_env, &by_env_proposed, BindingSource::Env),
    ] {
        let shown = f.shown(id);
        assert_eq!(&shown.proposals, proposed, "{id}");
        let stripe: Vec<&Proposal> = proposed
            .iter()
            .filter(|x| x.env_name == "STRIPE_SECRET_KEY")
            .collect();
        assert_eq!(stripe.len(), 1, "{proposed:?}");
        assert_eq!(stripe[0].source, source, "{id}");
        assert_eq!(stripe[0].test_slug, "stripe/acme-test");
    }
    // Asked again through either layer: the request pending for it.
    assert_eq!(r.pending(&[]), by_env);
    assert_eq!(r.pending(&[live_ref]), by_ref);
    drop(r);
    f.sweep();
}

/// SPEC §10b "A grant ends on" (R-M2-22): a reclassification by hand,
/// test to live, ends the grants and pending requests that bind the item;
/// the agent's next request is pending and needs the tick. Tightening
/// needs no proof: the agent itself may ask it. Audited with the change
/// and the grants it ended; one that changes nothing ends nothing.
///
/// Mutation: keep the grants (`on_item_reclassified` not called): the
/// grant is still listed and this fails.
#[test]
fn a_test_to_live_reclassification_ends_the_grants_that_bind_the_item() {
    let mut f = Fixture::new();
    let mut r = Requester::start(&f, "agent");
    let id = r.pending(&[]);
    assert_eq!(f.shown(&id).bindings[0].classification, "test");
    // A test key: no tick needed.
    f.approve(&id, ticking(&[], Uses::Session)).unwrap();
    assert_eq!(r.ask(&[]).0, "covered");
    let waiting = r.pending(&["X=stripe/acme-test", "Y=openai/acme-web"]);
    assert_eq!(f.grants().len(), 1);
    // Asked over the agent's own claims: tightening takes no proof.
    let done = client(&f.home)
        .items_reclassify_live("stripe/acme-test", &["CLAUDECODE".to_owned()])
        .unwrap();
    assert_eq!(
        (
            done.classification,
            done.reclassified_from,
            done.grants_ended
        ),
        (ClassificationView::Live, Some(ClassificationView::Test), 1)
    );
    assert!(f.grants().is_empty());
    let e = client(&f.home).pending_get(&waiting, &[]).unwrap_err();
    assert_eq!(rpc_kind(e), (ErrorKind::NoSuchRequest, None));
    // Asked again: pending, the item live, refused without its tick.
    let id = r.pending(&[]);
    let d = f.shown(&id);
    assert_eq!(d.bindings[0].classification, "live");
    let e = f.approve(&id, ticking(&[], Uses::Session)).unwrap_err();
    assert_eq!(rpc_kind(e), (ErrorKind::LiveNotTicked, None));
    // Again: nothing changes, nothing ends.
    let again = client(&f.home)
        .items_reclassify_live("stripe/acme-test", &[])
        .unwrap();
    assert_eq!((again.reclassified_from, again.grants_ended), (None, 0));
    assert!(f.shown(&id).bindings[0].classification == "live");
    let log = f.d.log();
    assert!(
        log.contains("envcloakd: audit: item reclassified id=")
            && log.contains(" from=test to=live grants_ended=1 "),
        "{log}"
    );
    drop(r);
    let v = f.stop_and_open();
    let changes: Vec<(String, Option<String>, Option<u64>)> = entries(&v, AuditKind::Reclassify)
        .into_iter()
        .map(|e| {
            (
                e.record.decision.outcome,
                e.record.decision.reason,
                e.record.decision.count,
            )
        })
        .collect();
    assert_eq!(
        changes,
        [
            (
                "reclassified".to_owned(),
                Some("test_to_live".to_owned()),
                Some(1)
            ),
            (
                "unchanged".to_owned(),
                Some("live_to_live".to_owned()),
                Some(0)
            ),
        ]
    );
    drop(v);
    f.sweep();
}

/// SPEC §10b "Writes that need a proof": reclassifying towards `test` or
/// `unknown` loosens the guard and needs a passphrase proof from a
/// terminal subject. Without a passphrase the request is malformed; with
/// a wrong one it is counted and changes nothing; from an agent it is
/// refused before anything is looked at; with an item id that is not the
/// slug's it is refused. With the proof it changes, and ends the grants
/// that bind the item. Towards `live` no passphrase is taken.
///
/// Mutation: take no proof towards `test` (`loosen` without `prove`):
/// the change without a passphrase, or with a wrong one, goes through and
/// this fails.
#[test]
fn live_to_test_needs_a_proof() {
    let f = Fixture::new();
    let item = f.target("stripe/acme-live").item.id;
    // Each on a connection of its own: an error answers the request and
    // nothing else is read from it.
    let send = |params: serde_json::Value| {
        let mut s = common::raw(&f.home);
        common::send_json(
            &mut s,
            &serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "items.reclassify",
                "params": params}),
        );
        common::error_kind(&common::read_json(&mut s).unwrap())
    };
    // No passphrase towards test; an id without a passphrase towards
    // unknown; a passphrase towards live.
    assert_eq!(
        send(serde_json::json!({"slug": "stripe/acme-live", "to": "test"})),
        "invalid_params"
    );
    assert_eq!(
        send(serde_json::json!({"slug": "stripe/acme-live", "to": "unknown", "item": item})),
        "invalid_params"
    );
    assert_eq!(
        send(serde_json::json!({"slug": "stripe/acme-live", "to": "live",
            "passphrase": "not the passphrase, not at all"})),
        "invalid_params"
    );
    let target = f.target("stripe/acme-live");
    assert_eq!(target.item.classification, ClassificationView::Live);
    let mut c = client(&f.home);
    // A wrong passphrase: counted, nothing changed.
    let e = c
        .items_reclassify(
            &target,
            ClassificationView::Test,
            SecretBytes::copy_from(b"not the passphrase, not at all"),
            &[],
        )
        .unwrap_err();
    assert_eq!(rpc_kind(e), (ErrorKind::WrongPassphrase, None));
    assert_eq!(c.status().unwrap().approvals.proof_failures, 1);
    // From an agent: refused before anything is looked at.
    let e = c
        .items_reclassify(
            &target,
            ClassificationView::Test,
            f.pass(),
            &["CLAUDECODE".to_owned()],
        )
        .unwrap_err();
    assert_eq!(rpc_kind(e).0, ErrorKind::ProofRefused);
    // Another item's id under this slug.
    let mut other = target.clone();
    other.item.id = f.target("stripe/acme-test").item.id;
    let e = c
        .items_reclassify(&other, ClassificationView::Test, f.pass(), &[])
        .unwrap_err();
    assert_eq!(rpc_kind(e), (ErrorKind::NoSuchItem, Some("item_changed")));
    assert_eq!(
        f.target("stripe/acme-live").item.classification,
        ClassificationView::Live
    );
    // A grant that binds it, made with the tick by an agent.
    let mut r = Requester::start(&f, "agent");
    let id = r.pending(&["STRIPE_SECRET_KEY=stripe/acme-live"]);
    f.approve(&id, ticking(&["STRIPE_SECRET_KEY"], Uses::Session))
        .unwrap();
    // With the proof: live to unknown, then to test.
    let done = c
        .items_reclassify(&target, ClassificationView::Unknown, f.pass(), &[])
        .unwrap();
    assert_eq!(
        (
            done.classification,
            done.reclassified_from,
            done.grants_ended
        ),
        (
            ClassificationView::Unknown,
            Some(ClassificationView::Live),
            1
        )
    );
    let done = c
        .items_reclassify(&target, ClassificationView::Test, f.pass(), &[])
        .unwrap();
    assert_eq!(
        (
            done.classification,
            done.reclassified_from,
            done.grants_ended
        ),
        (
            ClassificationView::Test,
            Some(ClassificationView::Unknown),
            0
        )
    );
    // A test key now: the agent needs no tick.
    let id = r.pending(&["STRIPE_SECRET_KEY=stripe/acme-live"]);
    assert_eq!(f.shown(&id).bindings[0].classification, "test");
    f.approve(&id, ticking(&[], Uses::Once)).unwrap();
    drop(r);
    f.sweep();
}

/// A loosening is a proof (SPEC §10b "Writes that need a proof"), so it is
/// refused, before the passphrase is looked at, to every caller that may
/// not give one, whatever it sends over the socket: an agent known by its
/// ancestry alone, with no marker and no claim (`fixture-agent`, which the
/// builtin catalog knows), and a caller with no terminal (a session of its
/// own, as a service manager's job or a command that forked out and
/// called `setsid`). Both destinations, `test` and `unknown`, each with
/// the right passphrase: refused `proof_refused`, logged with the reason,
/// no attempt counted, and the item still live. The approval check without
/// a passphrase (M2-13) is refused to them the same way, before the
/// request is looked at: the guard never runs for them, and nothing is
/// audited as `live_refused`. The positive control: the
/// same calls from the person's terminal session change it (in
/// [`live_to_test_needs_a_proof`]), and the ancestry child is an agent
/// to the daemon by its ancestry (its run request shows the catalog's
/// agent).
///
/// Mutation (Codex, round 2): the loosening's origin check dropped
/// (`prove` taking the proof from any caller): each call changes the item
/// and this fails.
#[test]
fn a_loosening_is_refused_to_an_unmarked_agent_and_a_caller_without_a_terminal() {
    let f = Fixture::new();
    let failures = client(&f.home).status().unwrap().approvals.proof_failures;
    for (mode, reason) in [("ancestry", "agent"), ("unknown", "no_terminal")] {
        let mut r = Requester::start(&f, mode);
        let id = r.pending(&["STRIPE_SECRET_KEY=stripe/acme-live"]);
        if mode == "ancestry" {
            // An agent to the daemon by its ancestry, with no claim.
            let d = f.shown(&id);
            assert_eq!(d.subject.kind, SubjectKind::Agent, "{d:?}");
            assert!(
                d.subject
                    .label
                    .as_deref()
                    .is_some_and(|l| l.contains("fixture agent")),
                "{d:?}"
            );
        }
        let (answer, _) = r.ask(&[&format!("check {id}")]);
        assert_eq!(answer, "error proof_refused", "{mode}");
        for to in ["test", "unknown"] {
            let (answer, _) = r.ask(&[&format!("reclassify stripe/acme-live {to}")]);
            assert_eq!(answer, "error proof_refused", "{mode} {to}");
            assert_eq!(
                f.target("stripe/acme-live").item.classification,
                ClassificationView::Live,
                "{mode} {to}"
            );
        }
        for method in ["items.reclassify", "approve"] {
            assert!(
                f.d.log()
                    .contains(&format!("proof refused method={method} reason={reason} ")),
                "{mode} {method}: {}",
                f.d.log()
            );
        }
        drop(r);
    }
    assert!(
        !f.d.log().contains("reason=live_not_ticked"),
        "{}",
        f.d.log()
    );
    assert_eq!(
        client(&f.home).status().unwrap().approvals.proof_failures,
        failures
    );
    f.sweep();
}

/// F-47 regression with the guard (SPEC §10b): rotating a test value to a
/// value the registry recognizes as live makes the item live and ends the
/// grant an agent held without a tick; the agent's next request needs the
/// tick.
#[test]
fn a_rotation_to_a_live_value_ends_the_unticked_grant() {
    let mut f = Fixture::new();
    let mut r = Requester::start(&f, "agent");
    let id = r.pending(&[]);
    f.approve(&id, ticking(&[], Uses::Session)).unwrap();
    assert_eq!(r.ask(&[]).0, "covered");
    let live = stripe_key("live");
    f.cs.push(Canary::new("STRIPE_ROTATED", live.clone()));
    let target = f.target("stripe/acme-test");
    let rotated = client(&f.home)
        .items_rotate(
            &target,
            SecretBytes::copy_from(live.as_bytes()),
            f.pass(),
            &[],
        )
        .unwrap();
    assert_eq!(
        (
            rotated.classification,
            rotated.reclassified_from,
            rotated.grants_ended
        ),
        (ClassificationView::Live, Some(ClassificationView::Test), 1)
    );
    let id = r.pending(&[]);
    let e = f.approve(&id, ticking(&[], Uses::Session)).unwrap_err();
    assert_eq!(rpc_kind(e), (ErrorKind::LiveNotTicked, None));
    f.approve(&id, ticking(&["STRIPE_SECRET_KEY"], Uses::Session))
        .unwrap();
    assert_eq!(r.ask(&[]).0, "covered");
    drop(r);
    let v = f.stop_and_open();
    assert_eq!(entries(&v, AuditKind::LiveRefused).len(), 1);
    drop(v);
    f.sweep();
}
