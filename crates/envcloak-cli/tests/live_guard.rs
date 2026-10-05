//! The live-key guard through the CLI (SPEC §10b "Live-key guard",
//! "Writes that need a proof"; gate 40, sentences 1 and 2; M2 plan
//! M2-13): `envcloak approve` refuses an agent's or an unknown process's
//! request whose live bindings it leaves unticked before it reads the
//! passphrase, the refusal the daemon's own and audited, and approves it
//! with the ticks; `envcloak run`'s `approval_required` line names the
//! same provider's test item and how to bind it for the layer the live
//! binding came from, waiting or not, and following that, from any
//! directory, binds the test item in the requested project; `envcloak
//! items reclassify` tightens with no proof and loosens only with one. A
//! command that must not read the passphrase is given one it cannot read
//! without blocking ([`unread`]). The daemon's side is in
//! `crates/envcloak-daemon/tests/live_guard.rs`.
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
    MANIFEST, cli, cli_command, data_dir, finish_within, on_terminal_program, outside_dir, project,
    python3, run, run_on_terminal, secret_file, seed_vault, start_daemon, stderr, stdout,
};
use envcloak_core::SecretBytes;
use envcloak_core::audit::AuditKind;
use envcloak_core::vault::{LockedVault, VaultPaths};
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

    /// The audit entries of `kind`, read from the vault once the daemon
    /// stopped (SIGTERM locks it first).
    fn audited(mut self, kind: AuditKind) -> Vec<envcloak_core::audit::AuditEntry> {
        self.d.signal("-TERM");
        assert!(self.d.wait_exit(Duration::from_secs(30)).is_some());
        let v = LockedVault::open(&VaultPaths::under(data_dir(&self.home)))
            .unwrap()
            .unlock_with_passphrase(&SecretBytes::copy_from(
                by_label(&self.cs, labels::VAULT_PASSPHRASE).value(),
            ))
            .map_err(|(_, e)| e)
            .unwrap();
        let (entries, _) = v.read_audit().unwrap();
        entries
            .into_iter()
            .filter(|e| e.record.kind == kind)
            .collect()
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

/// A descriptor a command cannot read without blocking: a FIFO under
/// `dir` whose write end this test holds open and never writes, so a read
/// of it waits for as long as the test holds it (Codex, round 3: a file
/// holding a wrong passphrase proved nothing, since the daemon refuses an
/// unticked approval before it verifies a passphrase, so one read and sent
/// was refused and uncounted all the same). The command is given it as
/// `--passphrase-fd`; [`Unread::check`] after the command, which must have
/// ended within its limit, says that the command opened it. Nothing is
/// ever written to it.
struct Unread {
    path: PathBuf,
    writer: std::thread::JoinHandle<std::fs::File>,
}

fn unread(dir: &Path, name: &str) -> Unread {
    let path = dir.join(name);
    let made = std::process::Command::new(python3())
        .args(["-c", "import os, sys\nos.mkfifo(sys.argv[1], 0o600)\n"])
        .arg(&path)
        .status()
        .unwrap();
    assert!(made.success());
    let at = path.clone();
    // Opening the write end waits for the reader, the command's wrapper,
    // which opens it before the command starts.
    let writer =
        std::thread::spawn(move || std::fs::OpenOptions::new().write(true).open(&at).unwrap());
    Unread { path, writer }
}

impl Unread {
    /// The command opened the descriptor (and, having ended, read
    /// nothing from it: a read would still be waiting). Lets go of the
    /// write end.
    fn check(self) {
        // Its open returned when the command's wrapper opened the read
        // end, before the command started; the thread may be scheduled
        // late on a loaded machine.
        let until = std::time::Instant::now() + Duration::from_secs(30);
        while !self.writer.is_finished() && std::time::Instant::now() < until {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            self.writer.is_finished(),
            "the command never opened the descriptor"
        );
        drop(self.writer.join().unwrap());
    }
}

/// Gate 40, sentence 1, through the CLI: an unknown process's request
/// binding the live OpenAI key. `envcloak approve` without `--live`
/// shows the statement, which names the tick it lacks and says that
/// nothing is approved, reads no passphrase (its descriptor is one a read
/// of would block, [`unread`], and the refusal comes within the limit),
/// and asks the daemon without one: the daemon refuses `live_not_ticked`
/// and audits it (Codex, round 2: the CLI's own refusal was never
/// audited), and no grant is made. With no test key proposed, the failure
/// names none. With `--live OPENAI_API_KEY` it approves, the statement
/// saying the tick is the person's.
///
/// Mutations: drop `envcloak approve`'s check (`unticked_live` answering
/// none in the CLI): the passphrase is read, which blocks, and this fails
/// at the limit; read the passphrase before the check (`read_secret_fd`
/// above `unticked_live`), with the check and its refusal kept: the same;
/// refuse in the CLI alone, as round 1 did (the check never sent): nothing
/// is audited, and this fails.
#[test]
fn approve_refuses_an_unticked_live_key_before_the_passphrase() {
    let f = Fixture::new();
    let out = f.unknown_run(&[]);
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    let id = request_id(&stderr(&out));
    let fd = unread(f.files.path(), "unread-approve");
    let refused = f.person(
        &["approve", &id, "--for", "1h", "--passphrase-fd", "3"],
        &fd.path,
    );
    fd.check();
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
    assert!(
        shown.ends_with(
            "Nothing is approved: no passphrase is asked for an approval that leaves a live \
             key unticked.\n"
        ),
        "{shown}"
    );
    assert!(!shown.contains("The passphrase you enter"), "{shown}");
    // No test key of the provider: the failure names none.
    assert!(!err.contains("or bind"), "{err}");
    // `status` names failed attempts only when there are some.
    let status = stdout(&run(&f.home, &["status"], &[]));
    assert!(!status.contains("failed passphrase attempts"), "{status}");
    assert!(
        status.contains("grants: 0 in force, 1 waiting for approval"),
        "{status}"
    );
    // The refusal is the daemon's, and audited once.
    let log = f.d.log();
    assert!(!log.contains("approve failed"), "{log}");
    assert_eq!(
        log.matches(&format!(
            "approve refused reason=live_not_ticked request={id} "
        ))
        .count(),
        1,
        "{log}"
    );
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
    // The sealed log holds the refusal (kind `live_refused`), naming the
    // request and the item left unticked.
    let refused = f.audited(AuditKind::LiveRefused);
    assert_eq!(refused.len(), 1);
    let r = &refused[0].record;
    assert_eq!(r.request_id.as_deref(), Some(id.as_str()));
    assert_eq!(r.decision.reason.as_deref(), Some("live_not_ticked"));
    let slugs: Vec<&str> = r.items.iter().map(|(_, s)| s.as_str()).collect();
    assert_eq!(slugs, ["openai/acme-web"]);
}

/// The project of the layer tests: the live Stripe key in `[env]` and in
/// the profile `dev`.
const LIVE_MANIFEST: &str = "[project]
name = \"acme-live\"

[env]
STRIPE_SECRET_KEY = \"stripe/acme-live\"

[env.dev]
STRIPE_SECRET_KEY = \"stripe/acme-live\"
";

/// The slugs the person's `envcloak pending --json` lists for request
/// `id`: what the request binds.
fn pending_slugs(f: &Fixture, id: &str) -> Vec<String> {
    let out = run_on_terminal(&f.home, &["pending", "--json"], &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let r = v["requests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["request"] == id)
        .unwrap_or_else(|| panic!("{id} is not listed: {v}"));
    r["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_owned())
        .collect()
}

/// The text between `before` and the next backtick after it, in `line`.
fn quoted_after<'a>(line: &'a str, before: &str) -> &'a str {
    let rest = &line[line
        .find(before)
        .unwrap_or_else(|| panic!("no {before:?} in: {line}"))
        + before.len()..];
    &rest[..rest.find('`').unwrap()]
}

/// Gate 40, sentence 2, through the CLI: the agent's `envcloak run`
/// binding the live Stripe key names, on its `approval_required` line,
/// the same provider's test item and how to bind it, waiting or not;
/// `envcloak approve` lists it before the bindings. The daemon
/// substitutes nothing: the statement still binds the live item.
///
/// How to bind it follows the layer the live binding came from, and the
/// test follows the line it is given, as an agent would, then asks again:
/// the next request binds the test item, for each layer (verifier and
/// Codex, round 2: `envcloak ref NAME=...` writes `[env]`, which a
/// `--ref`, an env file and a profile replace, so following the line round
/// 1 printed asked for the live item again). A `--ref` is replaced; the
/// env file's line is set; a profile's binding is changed with `envcloak
/// ref --manifest <m> --profile`; `[env]`'s with `envcloak ref --manifest
/// <m>`. The edits are followed from another project's directory, as a
/// run with `--manifest` or a terminal elsewhere would (Codex, round 3:
/// `envcloak ref` alone edits the manifest nearest the directory it runs
/// in): the requested project changes and the other stays byte for byte.
/// The controls: the round-1 line, followed for the `--ref` run, leaves
/// the live item bound; the round-2 line, without the manifest, followed
/// from the other project, edits that one and leaves the live item bound.
///
/// Mutations: leave the proposals off the line (`proposed` answering
/// nothing): the line names no test item and this fails; advise every
/// layer as `[env]` (`Proposal::advice` answering `envcloak ref NAME=...`
/// whatever the source): the `--ref` line differs, and following the
/// env file's and the profile's still binds the live item; leave the
/// manifest out of the line (`envcloak ref NAME=...` for `[env]` and a
/// profile): the line differs, and followed from the other project it
/// edits that one.
#[test]
fn the_approval_required_line_names_the_test_item() {
    let mut f = Fixture::new();
    f.add_stripe("stripe/acme-test", "test");
    f.add_stripe("stripe/acme-live", "live");
    let dir = project(&f.home, "acme-live", LIVE_MANIFEST);
    let m = dir.join("envcloak.toml").to_str().unwrap().to_owned();
    // The agent's `envcloak run` with `args`: its request id and line.
    let ask = |args: &[&str]| -> (String, String) {
        let mut argv = vec!["run", "--manifest", m.as_str()];
        argv.extend_from_slice(args);
        argv.extend_from_slice(&["--", "/usr/bin/true"]);
        let out = f.agent(&argv);
        assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
        let err = stderr(&out);
        let id = request_id(&err);
        let line = err
            .lines()
            .find(|l| l.contains("approval_required"))
            .unwrap()
            .to_owned();
        (id, line)
    };
    // `envcloak <args>` in `at`, as the agent runs `envcloak ref`.
    let in_dir = |at: &Path, args: &[&str]| {
        let mut cmd = cli_command(&f.home, args, &[]);
        cmd.current_dir(at);
        let out = finish_within(cmd, Duration::from_secs(60));
        f.swept(&out);
        assert!(out.status.success(), "{args:?}: {}", stderr(&out));
    };
    let in_project = |args: &[&str]| in_dir(&dir, args);
    // Another project, which binds the same live key: where a terminal
    // that follows the line may be.
    let other = project(&f.home, "acme-other", LIVE_MANIFEST);
    let other_manifest = std::fs::read(other.join("envcloak.toml")).unwrap();
    let elsewhere = |args: &[&str]| {
        in_dir(&other, args);
        assert_eq!(
            std::fs::read(other.join("envcloak.toml")).unwrap(),
            other_manifest,
            "{args:?} edited another project"
        );
    };
    let words = |cmd: &str| -> Vec<String> {
        let w: Vec<String> = cmd.split_whitespace().map(str::to_owned).collect();
        assert_eq!(w[0], "envcloak", "{cmd}");
        w[1..].to_vec()
    };

    // A `--ref`: give another.
    let live_ref = "STRIPE_SECRET_KEY=stripe/acme-live";
    let (id, line) = ask(&["--ref", live_ref]);
    let named = "STRIPE_SECRET_KEY is bound to the live key stripe/acme-live: to use the test \
                 key stripe/acme-test instead, give `--ref STRIPE_SECRET_KEY=stripe/acme-test` \
                 in place of the --ref for STRIPE_SECRET_KEY, and run this again";
    assert_eq!(
        line,
        format!(
            "envcloak: approval_required: request={id}: run \"envcloak approve {id}\" in a \
             terminal you control; {named}"
        )
    );
    assert_eq!(pending_slugs(&f, &id), ["stripe/acme-live"]);
    // Waiting: the line it prints names it too.
    let mut argv = vec!["run", "--manifest", m.as_str(), "--wait", "1s"];
    argv.extend_from_slice(&["--ref", live_ref, "--", "/usr/bin/true"]);
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
        .find("      to bind it: give `--ref STRIPE_SECRET_KEY=stripe/acme-test` in place")
        .unwrap_or_else(|| panic!("{text}"));
    let binding = text
        .find("STRIPE_SECRET_KEY = stripe/acme-live#value  (live key")
        .unwrap_or_else(|| panic!("{text}"));
    assert!(proposal < binding, "{text}");
    // The failure names the test key it could bind instead.
    assert!(
        stderr(&shown).starts_with(
            "envcloak: live_not_ticked: the request is an agent's or an unknown process's, and \
             the approval leaves a live key unticked, so no grant was made: tick each live \
             binding with --live NAME; or bind the test key the statement proposes for \
             STRIPE_SECRET_KEY\n"
        ),
        "{}",
        stderr(&shown)
    );
    // The control: round 1's line, `envcloak ref NAME=<test>`, followed for
    // a `--ref` run, binds the live item still.
    in_project(&["ref", "STRIPE_SECRET_KEY=stripe/acme-test"]);
    let (id, _) = ask(&["--ref", live_ref]);
    assert_eq!(pending_slugs(&f, &id), ["stripe/acme-live"]);
    in_project(&["ref", "STRIPE_SECRET_KEY=stripe/acme-live"]);
    // Followed as given: the test item is bound.
    let given = quoted_after(&line, "give `");
    let (flag, binding) = given.split_once(' ').unwrap();
    assert_eq!(flag, "--ref");
    let (id, line) = ask(&["--ref", binding]);
    assert_eq!(pending_slugs(&f, &id), ["stripe/acme-test"]);
    assert!(!line.contains("test key"), "{line}");

    // The env file: set its line.
    let env_file = f.files.path().join("refs.env");
    let lines = [
        "# the keys".to_owned(),
        "PLAIN_SETTING=1".to_owned(),
        "STRIPE_SECRET_KEY=envcloak://stripe/acme-live".to_owned(),
    ];
    std::fs::write(&env_file, lines.join("\n") + "\n").unwrap();
    let env_arg = env_file.to_str().unwrap().to_owned();
    let (id, line) = ask(&["--env-file", &env_arg]);
    assert!(
        line.contains(
            "instead, set line 3 of the --env-file to \
             `STRIPE_SECRET_KEY=envcloak://stripe/acme-test`, and run this again"
        ),
        "{line}"
    );
    assert_eq!(pending_slugs(&f, &id), ["stripe/acme-live"]);
    let at: usize = line
        .split("set line ")
        .nth(1)
        .and_then(|s| s.split(' ').next())
        .unwrap()
        .parse()
        .unwrap();
    let mut changed = lines.clone();
    changed[at - 1] = quoted_after(&line, "of the --env-file to `").to_owned();
    std::fs::write(&env_file, changed.join("\n") + "\n").unwrap();
    let (id, line) = ask(&["--env-file", &env_arg]);
    assert_eq!(pending_slugs(&f, &id), ["stripe/acme-test"]);
    assert!(!line.contains("test key"), "{line}");

    // A profile: `envcloak ref --manifest <m> --profile`, followed from
    // the other project.
    let (id, line) = ask(&["--profile", "dev"]);
    assert!(
        line.contains(&format!(
            "instead, run `envcloak ref --manifest {m} --profile dev \
             STRIPE_SECRET_KEY=stripe/acme-test`, and run this again"
        )),
        "{line}"
    );
    assert_eq!(pending_slugs(&f, &id), ["stripe/acme-live"]);
    elsewhere(
        &words(quoted_after(&line, "instead, run `"))
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    let (id, line) = ask(&["--profile", "dev"]);
    assert_eq!(pending_slugs(&f, &id), ["stripe/acme-test"]);
    assert!(!line.contains("test key"), "{line}");

    // `[env]`: `envcloak ref --manifest <m>`. The control first: round 2's
    // line, without the manifest, followed from the other project, edits
    // that one, and the requested project still binds the live item.
    let (id, line) = ask(&[]);
    assert!(
        line.contains(&format!(
            "instead, run `envcloak ref --manifest {m} STRIPE_SECRET_KEY=stripe/acme-test`, and \
             run this again"
        )),
        "{line}"
    );
    assert_eq!(pending_slugs(&f, &id), ["stripe/acme-live"]);
    in_dir(&other, &["ref", "STRIPE_SECRET_KEY=stripe/acme-test"]);
    assert_ne!(
        std::fs::read(other.join("envcloak.toml")).unwrap(),
        other_manifest
    );
    let (id, _) = ask(&[]);
    assert_eq!(pending_slugs(&f, &id), ["stripe/acme-live"]);
    std::fs::write(other.join("envcloak.toml"), &other_manifest).unwrap();
    elsewhere(
        &words(quoted_after(&line, "instead, run `"))
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    let (id, line) = ask(&[]);
    assert_eq!(pending_slugs(&f, &id), ["stripe/acme-test"]);
    assert!(!line.contains("test key"), "{line}");

    // Without a live binding of a provider with a test item, there is
    // nothing to name.
    let out = f.agent(&[
        "run",
        "--manifest",
        f.manifest.to_str().unwrap(),
        "--",
        "/usr/bin/true",
    ]);
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
/// this; read it before asking whether the item is test already: the
/// last reclassification blocks on its descriptor ([`unread`]) and this
/// fails at the limit.
#[test]
fn items_reclassify_tightens_freely_and_loosens_with_a_proof() {
    let f = Fixture::new();
    let out = f.agent(&["items", "reclassify", "stripe/acme-web", "live"]);
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    assert_eq!(
        stdout(&out),
        "Reclassified stripe/acme-web from test to live. No grant bound it.\n"
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
    // Already test: nothing asked for (the passphrase's descriptor is one
    // a read of would block, and the command ends within its limit),
    // nothing changed.
    let fd = unread(f.files.path(), "unread-reclassify");
    let out = f.person(
        &[
            "items",
            "reclassify",
            "stripe/acme-web",
            "test",
            "--passphrase-fd",
            "3",
        ],
        &fd.path,
    );
    fd.check();
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
