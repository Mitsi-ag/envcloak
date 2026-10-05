//! Story step S9 (M2 plan §4; task M2-13; gate 40, sentences 1 and 2):
//! the live-key guard through a pinned host. Claude Code, driven by the
//! scripted model, runs `envcloak run --profile live -- ./digest` through
//! its Bash tool in a project whose `[env]` binds the Stripe test key and
//! whose profile `live` binds the live one:
//!
//! - the run is held for approval, and its `approval_required` line, which
//!   the host sends its model, names the same provider's test item and how
//!   to bind it in the live one's place: the `envcloak ref` line for the
//!   profile, naming the project's manifest;
//! - the person, in a terminal of their own, runs `envcloak approve <id>`:
//!   the statement lists `stripe/acme-test` first, with that line, before
//!   the live binding; the approval is refused `live_not_ticked` without a
//!   passphrase asked, no grant is made, and the daemon audits the refusal;
//! - `envcloak approve <id> --live STRIPE_SECRET_KEY --once`, with the
//!   passphrase, grants one use: the model's next turn, held until then,
//!   runs the command again, which gets the live key (its digest is the
//!   live fixture's, not the test one's), and the turn after that is held
//!   for approval again.
//!
//! The project binds only the Stripe key, so the one tick S9 gives is the
//! one the guard needs: the M1 fixture repo's `[env]` binds two other live
//! keys (OpenAI's and GitHub's), whose ticks S9 does not give. M2-26
//! composes this step into the ordered story.
//!
//! Nothing the host printed, stored or sent its model holds a value or an
//! encoding of one, while its transcript holds a positive control the
//! same session printed.

use std::path::PathBuf;

use envcloak_e2e::k01::{self, Reach, Shell};
use envcloak_e2e::{Harness, quoted, sha256_hex, text, versions_toml, write_script};
use envcloak_testkit::agents::{AgentHome, Host, HostFlags, Installed, ModelRequest, require};
use envcloak_testkit::transcripts::Sweep;
use envcloak_testkit::{Canary, fresh_seed, labels};
use serde_json::json;

use super::skeleton::last_tool_output;

/// The project: the test key in `[env]`, the live one in profile `live`.
const MANIFEST: &str = "[project]
name = \"acme-pay\"

[env]
STRIPE_SECRET_KEY = \"stripe/acme-test\"

[env.live]
STRIPE_SECRET_KEY = \"stripe/acme-live\"
";

/// A Stripe key of `kind` (`test` or `live`), made at run time: no
/// key-shaped literal is in the source.
fn stripe_key(kind: &str) -> String {
    let tail: String = (0..2)
        .map(|_| format!("{:016x}", fresh_seed()))
        .collect::<String>();
    format!("{}_{kind}_{tail}", concat!("s", "k"))
}

/// The vault, made by the person, and the two Stripe keys added: the test
/// one as `stripe/acme-test`, the live one as `stripe/acme-live`, each a
/// fixture swept for. The project `acme-pay` with `./digest`, which prints
/// the SHA-256 of the key it gets.
fn vault_and_project(h: &mut Harness) -> PathBuf {
    let home = h.home.home();
    let pass = h.secret_file(labels::VAULT_PASSPHRASE, true);
    let kit = h.files().join("kit");
    let created = h.human(
        &home,
        &[
            "vault",
            "create",
            "--passphrase-fd",
            "3",
            "--kit-fd",
            "4",
            "--kdf-memory",
            "64MiB",
        ],
        &[(3, &pass, true), (4, &kit, false)],
        &[],
    );
    assert_eq!(created.code, 0, "{}", created.all());
    let kit_text = std::fs::read_to_string(&kit).unwrap();
    h.add_canary(Canary::new(
        envcloak_e2e::RECOVERY_KIT,
        kit_text.trim_end().to_owned(),
    ));
    let confirmed = h.human(
        &home,
        &["recovery", "confirm", "--kit-fd", "4"],
        &[(4, &kit, true)],
        &[],
    );
    assert_eq!(confirmed.code, 0, "{}", confirmed.all());
    let cli = h.cli();
    for (kind, label) in [("test", "STRIPE_TEST"), ("live", "STRIPE_LIVE")] {
        h.add_canary(Canary::new(label, stripe_key(kind)));
        let file = h.secret_file(label, true);
        let slug = format!("stripe/acme-{kind}");
        let added = h.program(
            &cli,
            &["add", "stripe", "--slug", &slug, "--stdin"],
            Some(&file),
        );
        assert!(added.status.success(), "{}", text(&added));
        assert!(
            String::from_utf8_lossy(&added.stdout)
                .contains(&format!("  provider: stripe ({kind} key)\n")),
            "{slug} is not a {kind} key: {}",
            text(&added)
        );
    }
    let repo = h.home.root().join("acme-pay");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(repo.join("envcloak.toml"), MANIFEST).unwrap();
    let digest = format!(
        "#!/bin/sh\nprintf %s \"$STRIPE_SECRET_KEY\" | {} -c 'import hashlib, sys; \
         print(\"digest\", hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'\n",
        quoted(envcloak_e2e::python3().to_str().unwrap())
    );
    write_script(&repo.join("digest"), &digest);
    h.assert_swept("S9 setup");
    repo
}

/// The request id in `approval_required: request=<ID>: ...`, in what the
/// host sent its model; `None` when there is none, whole.
fn request_id(output: &str) -> Option<String> {
    output
        .split("request=")
        .nth(1)
        .and_then(|r| r.get(..8))
        .filter(|id| id.chars().all(|c| c.is_ascii_alphanumeric()))
        .map(str::to_owned)
}

/// What invocation `nonce` printed after its marker; `None` unless the
/// marker is there exactly once.
fn invocation<'a>(output: &'a str, nonce: &str) -> Option<&'a str> {
    let marker = format!("ecinv-{nonce}");
    if output.lines().filter(|l| l.trim() == marker).count() != 1 {
        return None;
    }
    output.split(&marker).nth(1)
}

/// [`invocation`], or the test fails naming it.
fn own<'a>(output: &'a str, nonce: &str) -> &'a str {
    invocation(output, nonce).unwrap_or_else(|| panic!("not invocation {nonce}'s own output"))
}

/// [`request_id`], or the test fails.
fn id_in(output: &str) -> String {
    request_id(output).unwrap_or_else(|| panic!("no request id in what the host sent its model"))
}

/// The exit codes `echo "EXIT=$?"` printed.
fn exits(output: &str) -> Vec<&str> {
    output
        .lines()
        .filter_map(|l| l.trim().strip_prefix("EXIT="))
        .collect()
}

/// The last tool result in the request the script answered with `pick`.
fn after_step(requests: &[ModelRequest], pick: &str) -> String {
    requests
        .iter()
        .find(|r| r.pick.as_deref() == Some(pick))
        .map(|r| last_tool_output(&String::from_utf8_lossy(&r.body)))
        .unwrap_or_else(|| panic!("no request for {pick}"))
}

/// S9 on Claude Code with its sandbox off (its default; K-01: the shell
/// reaches the daemon on both systems).
///
/// Mutations: the tick check removed (`unticked_live` answering none):
/// the first approval grants and this fails; the proposals left off the
/// line or the statement: the test item is not named and this fails; the
/// advice without the manifest: the line differs and this fails; the
/// grant not consumed (`--once` held as a session): the third run is
/// covered and this fails.
#[test]
fn s9_claude_code_a_live_key_needs_its_tick() {
    let found = Installed::find(&versions_toml(), Host::ClaudeCode.id(), "native");
    let Some(installed) = require(found, "S9 (Claude Code)") else {
        return;
    };
    let os = std::env::consts::OS;
    assert!(
        matches!(
            k01::expected(Shell::ClaudeUnsandboxed, os, k01::user_namespace()),
            Some(Reach::Reaches)
        ),
        "K-01 does not have Claude Code's own shell reach the daemon on {os}"
    );
    let mut h = Harness::start();
    let repo = vault_and_project(&mut h);
    let manifest = std::fs::canonicalize(&repo)
        .unwrap()
        .join("envcloak.toml")
        .to_str()
        .unwrap()
        .to_owned();
    let live_digest = sha256_hex(h.value("STRIPE_LIVE"));
    let test_digest = sha256_hex(h.value("STRIPE_TEST"));

    let mut agent = AgentHome::within(&h.home, Host::ClaudeCode, installed);
    // Claude Code cuts a command's output past 30,000 characters by
    // default; the whole of it is what is swept.
    agent.set_env("BASH_MAX_OUTPUT_LENGTH", "500000");
    let flags = HostFlags::claude("default", &["Bash"]);
    let control = Canary::new(
        "POSITIVE_CONTROL",
        format!("ecctl-{:016x}{:016x}", fresh_seed(), fresh_seed()),
    );
    let nonces: Vec<String> = (0..3).map(|_| format!("{:016x}", fresh_seed())).collect();
    let run_digest = |nonce: &str| {
        format!(
            "printf '%s%s\\n' 'ecinv-' '{nonce}'; {} run --profile live -- ./digest; echo \
             \"EXIT=$?\"",
            quoted(h.cli().to_str().unwrap())
        )
    };
    let (head, tail) = control.as_str().split_at(control.as_str().len() / 2);
    let script = json!({"steps": [
        {"say": "I'll run digest with the live profile.", "shell": run_digest(&nonces[0])},
        {"say": "Running it again.", "shell": run_digest(&nonces[1]), "after": "approved"},
        {"say": "Once more.", "shell": run_digest(&nonces[2])},
        {"shell": format!("printf '%s%s\\n' {} {}", quoted(head), quoted(tail))},
        {"say": "done"},
    ]});
    let mut running = agent.spawn(
        &script,
        "Run ./digest through envcloak with the live profile.",
        &flags,
        &repo,
    );

    // The first run, as the host sent it to its model: held for approval,
    // the test item named with the line that binds it for the profile.
    let held = running.model.wait_for("step 1", &mut running.child);
    h.record(
        "the host's request to its model (S9, first run)",
        &held.body,
    );
    let first = last_tool_output(&String::from_utf8_lossy(&held.body));
    let first_run = own(&first, &nonces[0]);
    assert_eq!(exits(first_run), ["125"], "{first_run}");
    let id = id_in(first_run);
    let line = format!(
        "envcloak: approval_required: request={id}: run \"envcloak approve {id}\" in a terminal \
         you control; STRIPE_SECRET_KEY is bound to the live key stripe/acme-live: to use the \
         test key stripe/acme-test instead, run `envcloak ref --manifest {manifest} --profile \
         live STRIPE_SECRET_KEY=stripe/acme-test`, and run this again"
    );
    assert!(
        first_run.lines().any(|l| l.trim() == line),
        "no line {line:?} in:\n{first_run}"
    );
    assert!(!first_run.contains("digest "), "{first_run}");

    // The person, without the tick: the statement lists the test item
    // first; refused, no passphrase asked, no grant, audited.
    let refused = h.human(&repo, &["approve", &id], &[], &[]);
    assert_eq!(refused.code, 1, "{}", refused.all());
    assert!(
        refused.err().starts_with("envcloak: live_not_ticked: "),
        "{}",
        refused.all()
    );
    let statement = refused.out();
    let proposed = statement
        .find("    STRIPE_SECRET_KEY: the test key stripe/acme-test, not the live key stripe/acme-live\n")
        .unwrap_or_else(|| panic!("no proposal in:\n{statement}"));
    let advice = statement
        .find(&format!(
            "      to bind it: run `envcloak ref --manifest {manifest} --profile live \
             STRIPE_SECRET_KEY=stripe/acme-test`\n"
        ))
        .unwrap_or_else(|| panic!("no advice in:\n{statement}"));
    let binding = statement
        .find("    STRIPE_SECRET_KEY = stripe/acme-live#value  (live key")
        .unwrap_or_else(|| panic!("no live binding in:\n{statement}"));
    assert!(proposed < advice && advice < binding, "{statement}");
    assert!(
        statement.ends_with(
            "Nothing is approved: no passphrase is asked for an approval that leaves a live \
             key unticked.\n"
        ),
        "{statement}"
    );
    assert!(
        !refused.shown().contains("Vault passphrase"),
        "{}",
        refused.all()
    );
    let cli = h.cli();
    let status = text(&h.program(&cli, &["status"], None));
    assert!(
        status.contains("grants: 0 in force, 1 waiting for approval"),
        "{status}"
    );
    let audited: usize = h
        .daemon_logs()
        .iter()
        .map(|l| {
            String::from_utf8_lossy(l)
                .matches(&format!(
                    "approve refused reason=live_not_ticked request={id} "
                ))
                .count()
        })
        .sum();
    assert_eq!(audited, 1, "the refusal is not audited once");

    // With the tick, for one use.
    let typed = format!("{}\r", h.canary(labels::VAULT_PASSPHRASE).as_str());
    let approved = h.human(
        &repo,
        &["approve", &id, "--live", "STRIPE_SECRET_KEY", "--once"],
        &[],
        &[("Vault passphrase to approve this: ", &typed)],
    );
    assert_eq!(approved.code, 0, "{}", approved.all());
    assert!(
        approved.shown().contains(
            "STRIPE_SECRET_KEY = stripe/acme-live#value  (live key, first use: no \
                       project uses this item yet, live: allowed by you)"
        ),
        "{}",
        approved.all()
    );
    assert!(
        approved
            .out()
            .contains(&format!("Approved request {id}: grant "))
            && approved.out().contains(", for one request."),
        "{}",
        approved.all()
    );
    running.model.release("approved");
    let run = running.wait();
    agent.check_pinned();
    agent.check_isolated();
    h.record("the host's stdout (S9)", &run.output.stdout);
    h.record("the host's stderr (S9)", &run.output.stderr);
    for r in &run.model.requests {
        h.record(
            &format!("the host's request {} to its model (S9)", r.seq),
            &r.body,
        );
    }
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    assert!(run.model.clean(), "{:?}", run.model.outcome);
    let picks: Vec<&str> = run
        .model
        .model_calls()
        .iter()
        .filter_map(|r| r.pick.as_deref())
        .collect();
    assert_eq!(picks, ["step 0", "step 1", "step 2", "step 3", "step 4"]);

    // The rerun got the live key: its digest, not the test key's.
    let second = after_step(&run.model.requests, "step 2");
    let second_run = own(&second, &nonces[1]);
    assert_eq!(exits(second_run), ["0"], "{second_run}");
    assert!(
        second_run
            .lines()
            .any(|l| l.trim() == format!("digest {live_digest}")),
        "the rerun did not get the live key"
    );
    assert!(
        !second_run.contains(&test_digest),
        "the rerun got the test key"
    );
    // One use: the next run is held for approval again.
    let third = after_step(&run.model.requests, "step 3");
    let third_run = own(&third, &nonces[2]);
    assert_eq!(exits(third_run), ["125"], "{third_run}");
    assert!(
        third_run.contains("envcloak: approval_required: request="),
        "{third_run}"
    );
    assert_ne!(id_in(third_run), id);
    assert!(!third_run.contains("digest "), "{third_run}");
    println!(
        "receipt: S9 host=claude-code os={os}: approval without --live refused live_not_ticked \
         (no grant, audited), --live STRIPE_SECRET_KEY --once delivered the live key once"
    );

    // The sweep: every capture, every daemon log, the home, and the host's
    // stores, with the control the session printed.
    let control_out = after_step(&run.model.requests, "step 4");
    assert!(control_out.contains(control.as_str()), "{control_out}");
    h.assert_swept("S9");
    let mut cs = h.canaries.clone();
    cs.push(control);
    let hits = Sweep::host_stores(&agent, &cs, &[&run.model]);
    assert_eq!(hits.unreadable(), 0, "{hits}");
    assert!(
        hits.in_store_as("claude/projects", "POSITIVE_CONTROL", "raw") >= 1,
        "the positive control is not in claude/projects:\n{hits}"
    );
    let leaks: usize = h
        .canaries
        .iter()
        .map(|c| {
            hits.stores
                .iter()
                .map(|s| hits.in_store(&s.store, &c.label))
                .sum::<usize>()
                + hits.in_model(&c.label)
        })
        .sum();
    assert_eq!(leaks, 0, "{hits}");
}

/// An invocation's output and the request id are read whole: a marker
/// there twice, or an id cut short, is not taken.
#[test]
fn s9_reads_an_invocation_whole() {
    let out = "x\necinv-n1\nenvcloak: approval_required: request=ABCDEFGH: run\nEXIT=125\n";
    let after = invocation(out, "n1").unwrap();
    assert_eq!(exits(after), ["125"]);
    assert_eq!(request_id(after).as_deref(), Some("ABCDEFGH"));
    assert_eq!(invocation("ecinv-n1\necinv-n1\n", "n1"), None);
    assert_eq!(invocation("ecinv-n2\n", "n1"), None);
    assert_eq!(request_id("request=AB"), None);
    assert_eq!(request_id("request=ABCD-FGH"), None);
}
