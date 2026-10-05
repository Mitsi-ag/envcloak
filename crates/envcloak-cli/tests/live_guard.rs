//! The live-key guard through the CLI (SPEC §10b "Live-key guard",
//! "Writes that need a proof"; gate 40, sentences 1 and 2; M2 plan
//! M2-13): `envcloak approve` refuses an agent's or an unknown process's
//! request whose live bindings it leaves unticked before it reads the
//! passphrase, and approves it with the ticks; `envcloak run`'s
//! `approval_required` line names the same provider's test item and the
//! `envcloak ref` line that binds it, waiting or not; `envcloak items
//! reclassify` tightens with no proof and loosens only with one. The
//! daemon's side is in `crates/envcloak-daemon/tests/live_guard.rs`.
//!
//! The requesters are `envcloak run` without a terminal (an unknown
//! subject) and `envcloak run` as the command of the fixture agent on a
//! terminal of the agent's (an agent subject). The person is this test
//! process's own command on a terminal of its own
//! (`common::run_on_terminal`). Under a developer's agent every proof here
//! is refused, as it must be; run the tests outside its tree then.
#![allow(clippy::unwrap_used)]

mod common;

use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::Duration;

use common::{
    MANIFEST, cli, finish_within, on_terminal_program, outside_dir, project, run, run_on_terminal,
    secret_file, seed_vault, start_daemon, stderr, stdout,
};
use envcloak_testkit::{
    Canary, Daemon, TestHome, assert_no_canary, by_label, canaries, fresh_seed, labels, testkit_bin,
};

/// A seeded vault (OpenAI and GitHub live, Stripe test), a daemon with it
/// unlocked through the CLI, the project, and the passphrase (and a wrong
/// one) on files for `--passphrase-fd`.
struct Fixture {
    cs: Vec<Canary>,
    home: TestHome,
    d: Daemon,
    manifest: PathBuf,
    files: tempfile::TempDir,
    pass: PathBuf,
    wrong: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let cs = canaries(fresh_seed());
        let home = TestHome::new();
        let kit = seed_vault(&home, &cs);
        let mut cs = cs;
        cs.push(kit);
        let d = start_daemon(&home);
        let files = outside_dir();
        let pass = secret_file(
            files.path(),
            "pass",
            by_label(&cs, labels::VAULT_PASSPHRASE).value(),
        );
        let wrong = secret_file(files.path(), "wrong", b"not the passphrase at all, no");
        let out = run_on_terminal(
            &home,
            &["unlock", "--passphrase-fd", "3"],
            &[(3, &pass, true)],
        );
        assert!(out.status.success(), "{}{}", stderr(&out), d.log());
        let manifest = project(&home, "acme-web", MANIFEST).join("envcloak.toml");
        Fixture {
            cs,
            home,
            d,
            manifest,
            files,
            pass,
            wrong,
        }
    }

    /// Adds a Stripe key of `kind` as `slug` (`envcloak add stripe
    /// --slug <slug> --stdin`), made at run time and swept for.
    fn add_stripe(&mut self, slug: &str, kind: &str) {
        let seed = fresh_seed();
        let tail: String = (0..32u32)
            .map(|i| {
                let n =
                    u8::try_from((seed.rotate_left(5 * i) ^ (u64::from(i) * 0x51)) % 36).unwrap();
                char::from(if n < 10 { b'0' + n } else { b'a' + n - 10 })
            })
            .collect();
        let key = format!("{}_{kind}_{tail}", concat!("s", "k"));
        let file = secret_file(self.files.path(), &format!("{kind}-key"), key.as_bytes());
        self.cs.push(Canary::new(format!("STRIPE_{kind}"), key));
        let out = run(
            &self.home,
            &["add", "stripe", "--slug", slug, "--stdin"],
            &[(0, &file, true)],
        );
        assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    }

    /// `envcloak <args>` on a terminal of its own, as a person runs it,
    /// with `pass` on descriptor 3.
    fn person(&self, args: &[&str], pass: &Path) -> Output {
        let out = run_on_terminal(&self.home, args, &[(3, pass, true)]);
        self.swept(&out);
        out
    }

    /// `envcloak run --manifest <m> <args> -- /usr/bin/true` without a
    /// terminal: an unknown subject.
    fn unknown_run(&self, args: &[&str]) -> Output {
        let m = self.manifest.to_str().unwrap();
        let mut argv = vec!["run", "--manifest", m];
        argv.extend_from_slice(args);
        argv.extend_from_slice(&["--", "/usr/bin/true"]);
        let out = run(&self.home, &argv, &[]);
        self.swept(&out);
        out
    }

    /// `envcloak <args>` as the fixture agent's command on a terminal of
    /// the agent's: an agent subject.
    fn agent(&self, args: &[&str]) -> Output {
        let agent = testkit_bin("fixture-agent");
        let mut argv: Vec<&Path> = vec![agent.as_path(), Path::new("--"), cli()];
        argv.extend(args.iter().map(Path::new));
        let out = finish_within(
            on_terminal_program(&self.home, &argv, &[]),
            Duration::from_secs(60),
        );
        self.swept(&out);
        out
    }

    fn swept(&self, out: &Output) {
        assert_no_canary(&out.stdout, &self.cs);
        assert_no_canary(&out.stderr, &self.cs);
    }

    fn sweep(&self) {
        assert_no_canary(&self.d.log_bytes(), &self.cs);
        self.home.assert_clean(&self.cs);
    }
}

/// The request id in `approval_required: request=<id>:`.
fn request_id(err: &str) -> String {
    let line = err
        .lines()
        .find(|l| l.contains("approval_required"))
        .unwrap_or_else(|| panic!("no approval_required in: {err}"));
    let id = line
        .split("request=")
        .nth(1)
        .and_then(|s| s.split(':').next())
        .unwrap_or_else(|| panic!("no request id in: {err}"));
    assert_eq!(id.len(), 8, "{line}");
    id.to_owned()
}

/// Gate 40, sentence 1, through the CLI: an unknown process's request
/// binding the live OpenAI key. `envcloak approve` without `--live`
/// shows the statement, which names the tick it lacks, and exits 1 with
/// `live_not_ticked` before it sends anything: a wrong passphrase given is
/// not counted, the daemon is asked nothing, and no grant is made. With
/// `--live OPENAI_API_KEY` it approves, the statement saying the tick is
/// the person's.
///
/// Mutation: drop `envcloak approve`'s check (`unticked_live` answering
/// none in the CLI): the passphrase is sent, the daemon refuses, the
/// wrong one is counted, and this fails.
#[test]
fn approve_refuses_an_unticked_live_key_before_the_passphrase() {
    let f = Fixture::new();
    let out = f.unknown_run(&[]);
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    let id = request_id(&stderr(&out));
    let refused = f.person(
        &["approve", &id, "--for", "1h", "--passphrase-fd", "3"],
        &f.wrong,
    );
    assert_eq!(refused.status.code(), Some(1));
    let (shown, err) = (stdout(&refused), stderr(&refused));
    assert!(err.starts_with("envcloak: live_not_ticked: "), "{err}");
    assert!(
        shown.contains(
            "OPENAI_API_KEY = openai/acme-web#value  (live key, first use: no project uses this \
             item yet, live: not allowed by you, so this approval is refused unless you add \
             --live OPENAI_API_KEY)"
        ),
        "{shown}"
    );
    assert!(
        shown.contains("Approve again with --live OPENAI_API_KEY."),
        "{shown}"
    );
    // `status` names failed attempts only when there are some.
    let status = stdout(&run(&f.home, &["status"], &[]));
    assert!(!status.contains("failed passphrase attempts"), "{status}");
    assert!(
        status.contains("grants: 0 in force, 1 waiting for approval"),
        "{status}"
    );
    let log = f.d.log();
    assert!(!log.contains("approve failed"), "{log}");
    assert!(!log.contains("approve refused"), "{log}");
    // Ticked: approved. (The grant holds the tick, which `grants.list`
    // shows while its root, the run that asked, lives: envcloakd's
    // tests/live_guard.rs.)
    let ok = f.person(
        &[
            "approve",
            &id,
            "--for",
            "1h",
            "--live",
            "OPENAI_API_KEY",
            "--passphrase-fd",
            "3",
        ],
        &f.pass,
    );
    assert!(ok.status.success(), "{}{}", stdout(&ok), stderr(&ok));
    let shown = stdout(&ok);
    assert!(
        shown.contains(
            "OPENAI_API_KEY = openai/acme-web#value  (live key, first use: no project uses this \
             item yet, live: allowed by you)"
        ),
        "{shown}"
    );
    assert!(
        shown.contains(&format!("Approved request {id}: grant ")),
        "{shown}"
    );
    f.sweep();
}

/// Gate 40, sentence 2, through the CLI: the agent's `envcloak run`
/// binding the live Stripe key names, on its `approval_required` line,
/// the same provider's test item and the `envcloak ref` line that binds
/// it, waiting or not; `envcloak approve` lists it before the bindings.
/// The daemon substitutes nothing: the statement still binds the live
/// item.
///
/// Mutation: leave the proposals off the line (`proposed` answering
/// nothing): the line names no test item and this fails.
#[test]
fn the_approval_required_line_names_the_test_item() {
    let mut f = Fixture::new();
    f.add_stripe("stripe/acme-test", "test");
    f.add_stripe("stripe/acme-live", "live");
    let m = f.manifest.to_str().unwrap().to_owned();
    let refs = ["--ref", "STRIPE_SECRET_KEY=stripe/acme-live"];
    let named = "STRIPE_SECRET_KEY is bound to the live key stripe/acme-live: to use the test \
                 key stripe/acme-test instead, run `envcloak ref \
                 STRIPE_SECRET_KEY=stripe/acme-test` and run this again";
    let mut argv = vec!["run", "--manifest", &m];
    argv.extend_from_slice(&refs);
    argv.extend_from_slice(&["--", "/usr/bin/true"]);
    let out = f.agent(&argv);
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    let err = stderr(&out);
    let id = request_id(&err);
    assert!(
        err.starts_with(&format!(
            "envcloak: approval_required: request={id}: run \"envcloak approve {id}\" in a \
             terminal you control; {named}\n"
        )),
        "{err}"
    );
    // Waiting: the line it prints names it too.
    let mut argv = vec!["run", "--manifest", &m, "--wait", "1s"];
    argv.extend_from_slice(&refs);
    argv.extend_from_slice(&["--", "/usr/bin/true"]);
    let out = f.agent(&argv);
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(
        err.contains(&format!(
            "in a terminal you control; {named}; waiting up to 1s for it"
        )),
        "{err}"
    );
    // The statement: the proposal first, the live binding as asked.
    let shown = f.person(&["approve", &id, "--passphrase-fd", "3"], &f.wrong);
    assert_eq!(shown.status.code(), Some(1), "{}", stderr(&shown));
    let text = stdout(&shown);
    let proposal = text
        .find("      envcloak ref STRIPE_SECRET_KEY=stripe/acme-test")
        .unwrap_or_else(|| panic!("{text}"));
    let binding = text
        .find("STRIPE_SECRET_KEY = stripe/acme-live#value  (live key")
        .unwrap_or_else(|| panic!("{text}"));
    assert!(proposal < binding, "{text}");
    // Without a test item of its provider there is nothing to name.
    let out = f.agent(&["run", "--manifest", &m, "--", "/usr/bin/true"]);
    assert!(!stderr(&out).contains("test key"), "{}", stderr(&out));
    f.sweep();
}

/// `envcloak items reclassify` (SPEC §10b): towards live with no proof,
/// from the agent itself; towards test only with the passphrase from a
/// person's terminal, refused from the agent before the passphrase is
/// read and counted when wrong; an item already of that classification
/// asks for nothing.
///
/// Mutation: read the passphrase towards live too, or take none towards
/// test: the agent's tightening, or the wrong passphrase's count, fails
/// this.
#[test]
fn items_reclassify_tightens_freely_and_loosens_with_a_proof() {
    let f = Fixture::new();
    let out = f.agent(&["items", "reclassify", "stripe/acme-web", "live"]);
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    assert_eq!(
        stdout(&out),
        "Reclassified stripe/acme-web from test to live: 0 grants that bound it ended, so its \
         runs need a new approval.\n"
    );
    // The agent cannot loosen it: refused before any passphrase is read.
    let out = f.agent(&["items", "reclassify", "stripe/acme-web", "test"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).starts_with("envcloak: proof_refused: "),
        "{}",
        stderr(&out)
    );
    // A person, with a wrong passphrase: counted, nothing changed.
    let out = f.person(
        &[
            "items",
            "reclassify",
            "stripe/acme-web",
            "test",
            "--passphrase-fd",
            "3",
        ],
        &f.wrong,
    );
    assert_eq!(out.status.code(), Some(1));
    // With `--passphrase-fd` the statement goes to standard error, before
    // the failure.
    let err = stderr(&out);
    assert!(
        err.starts_with("Reclassify stripe/acme-web from live to test.\n"),
        "{err}"
    );
    assert!(err.contains("\nenvcloak: wrong_passphrase:"), "{err}");
    let status = stdout(&run(&f.home, &["status"], &[]));
    assert!(status.contains("failed passphrase attempts: 1"), "{status}");
    // With the passphrase.
    let out = f.person(
        &[
            "items",
            "reclassify",
            "stripe/acme-web",
            "test",
            "--passphrase-fd",
            "3",
            "--json",
        ],
        &f.pass,
    );
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    assert_eq!(
        v,
        serde_json::json!({"slug": "stripe/acme-web", "classification": "test",
            "reclassified_from": "live", "grants_ended": 0})
    );
    // Already test: nothing asked for (a wrong passphrase is never read),
    // nothing changed.
    let out = f.person(
        &[
            "items",
            "reclassify",
            "stripe/acme-web",
            "test",
            "--passphrase-fd",
            "3",
        ],
        &f.wrong,
    );
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    assert_eq!(
        stdout(&out),
        "stripe/acme-web is test already; nothing changed.\n"
    );
    let status = stdout(&run(&f.home, &["status"], &[]));
    assert!(!status.contains("failed passphrase attempts"), "{status}");
    // Usage: an unknown classification, a passphrase towards live, a key
    // as the slug (never echoed).
    for bad in [
        &["items", "reclassify", "stripe/acme-web", "prod"][..],
        &[
            "items",
            "reclassify",
            "stripe/acme-web",
            "live",
            "--passphrase-fd",
            "3",
        ],
        &["items", "reclassify"],
    ] {
        let out = run(&f.home, bad, &[]);
        assert_eq!(out.status.code(), Some(2), "{bad:?}: {}", stderr(&out));
    }
    let key = std::str::from_utf8(by_label(&f.cs, labels::OPENAI_API_KEY).value()).unwrap();
    let out = run(&f.home, &["items", "reclassify", key, "live"], &[]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    f.swept(&out);
    f.sweep();
}
