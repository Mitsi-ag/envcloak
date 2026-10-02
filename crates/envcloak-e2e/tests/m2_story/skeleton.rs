//! Story step S0 (M2 plan task M2-04): the walking skeleton. A pinned host
//! (Claude Code, Codex), driven by the scripted model with its flags
//! pinned (§4 setup), runs `envcloak run -- ./emit --quick` in the M1
//! fixture repo `acme-web` through its own shell tool, twice, each
//! invocation marked with a nonce of its own so its result is told from
//! any other. What the shell gets is K-01's table (`envcloak_e2e::k01`,
//! which `agent_hosts` asserts its measurements against and
//! docs/AGENTS.md records), for the shell setting each case pins:
//!
//! - where the table says the shell reaches the daemon (a qualified path),
//!   the positive story: the daemon answers `approval_required`; the
//!   person approves from a terminal of their own, with the statement
//!   naming the host and the grant rooted at the host process itself; the
//!   model's next turn, held until then by a barrier, reruns the command,
//!   which now gets its values: every serializer's frames, and a digest
//!   per runtime and variable equal to the fixture's (an oracle that does
//!   not depend on the redactor);
//! - where it says the sandbox blocks the socket (`unsupported
//!   (sandbox_blocks_socket)`), the refusal, which is not a delivery and
//!   is reported as such: each invocation's own result is the table's
//!   refusal and nothing else (the CLI's one `daemon_unverified` line and
//!   exit 125, or the sandbox running no command at all), the daemon is
//!   meanwhile running and answers `envcloak status` from outside the
//!   sandbox with the same environment (so the refusal is the sandbox's,
//!   not a daemon that stopped or a directory that is gone), it logs no
//!   request, nothing of the command's output exists, and docs/AGENTS.md
//!   records the same refusal and `unsupported` for the host.
//!
//! Either way nothing the host printed, stored or sent its model holds a
//! value or any encoding of one, while the host's transcript holds a
//! positive control the same session printed.
//!
//! The cases (§4 setup): Claude Code with its sandbox off (its default:
//! qualified on both systems); Claude Code with its sandbox on and the
//! allowance M2-08 writes where it writes one (macOS: the socket's
//! resolved path; Linux: none, K-01); Codex `exec --sandbox
//! workspace-write` with the bounded setting M2-08 writes on macOS, and
//! with no network setting on Linux, where it writes none.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use envcloak_e2e::k01::{self, Reach, Shell};
use envcloak_e2e::{
    Emitters, Harness, Human, NAMES, age, quoted, sha256_hex, text, versions_toml, write_script,
};
use envcloak_testkit::agents::{AgentHome, Host, HostFlags, Installed, require};
use envcloak_testkit::transcripts::Sweep;
use envcloak_testkit::{Canary, daemon_socket, fresh_seed, labels};
use serde_json::json;

/// The fixture repo: `.env` with the M1 values, and `./emit` with its
/// configuration (the M1 story's, without the `short` profile).
fn write_repo(h: &mut Harness, emitters: &Emitters) -> PathBuf {
    let repo = h.home.root().join("acme-web");
    std::fs::create_dir_all(&repo).unwrap();
    let v = |l: &str| h.canary(l).as_str().to_owned();
    let dq = |s: &str| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""));
    let env = format!(
        "# acme-web\nOPENAI_API_KEY={}\nSTRIPE_SECRET_KEY={}\nGITHUB_TOKEN={}\nDATABASE_URL={}\n\
         PORT=8080\n",
        v(labels::OPENAI_API_KEY),
        v(labels::STRIPE_SECRET_KEY),
        v(labels::GITHUB_TOKEN),
        dq(&v(labels::DATABASE_URL)),
    );
    std::fs::write(repo.join(".env"), env).unwrap();
    age(&repo.join(".env"), Duration::from_secs(600));
    h.allow_plaintext(repo.join(".env"));
    let config = repo.join("emit.json");
    emitters.write_config(&config, &["DATABASE_URL"]);
    write_script(&repo.join("emit"), &emitters.script(&config));
    repo
}

/// S1 of the M1 story, as the person: the vault, the import, the kit
/// confirmed, the plaintext deleted.
fn vault_and_import(h: &mut Harness, repo: &Path) {
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
    let imported = h.human(repo, &["init", "--import", "--yes"], &[], &[]);
    assert_eq!(imported.code, 0, "{}", imported.all());
    let confirmed = h.human(
        repo,
        &["recovery", "confirm", "--kit-fd", "4"],
        &[(4, &kit, true)],
        &[],
    );
    assert_eq!(confirmed.code, 0, "{}", confirmed.all());
    let deleted = h.human(repo, &["init", "--delete-plaintext"], &[], &[]);
    assert_eq!(deleted.code, 0, "{}", deleted.all());
    h.allow_no_plaintext();
    h.assert_swept("S0 setup");
}

/// `envcloak approve <id> --for 1h` by the person, typing the passphrase.
fn approve(h: &mut Harness, repo: &Path, id: &str) -> Human {
    let typed = format!("{}\r", h.canary(labels::VAULT_PASSPHRASE).as_str());
    h.human(
        repo,
        &["approve", id, "--for", "1h"],
        &[],
        &[("Vault passphrase to approve this: ", &typed)],
    )
}

/// The request id in `approval_required: request=<ID>: ...`, as the host
/// sent the command's output to its model.
fn request_id(text: &str) -> String {
    text.split("request=")
        .nth(1)
        .and_then(|r| r.get(..8))
        .filter(|id| id.chars().all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or_else(|| panic!("no request id in what the host sent its model"))
        .to_owned()
}

/// One S0 case: `host` in the shell setting `shell`, which K-01's table
/// says reaches the daemon here (the positive story) or not (the
/// refusal).
fn s0(host: Host, shell: Shell, name: &str) {
    let found = Installed::find(&versions_toml(), host.id(), "native");
    let Some(installed) = require(found, &format!("S0 ({name})")) else {
        return;
    };
    let os = std::env::consts::OS;
    let ns = if k01::user_namespace() {
        " (in a user namespace)"
    } else {
        ""
    };
    let expected = k01::expected(shell, os, k01::user_namespace())
        .unwrap_or_else(|| panic!("{shell:?} is not a setting on {os}"));
    let mut h = Harness::start();
    // Gate 8's serializers are the M1 story's; S0 needs output that holds
    // the values, and Python's and serde's are enough.
    let emitters = Emitters::python_and_serde(Path::new(env!("CARGO_BIN_EXE_ec-emit-serde")));
    let repo = write_repo(&mut h, &emitters);
    // What every serializer makes of each value, made outside EnvCloak,
    // looked for as it is.
    let values: BTreeMap<&str, Vec<u8>> = NAMES.iter().map(|n| (*n, h.value(n).to_vec())).collect();
    let pairs: Vec<(&str, &[u8])> = values.iter().map(|(n, v)| (*n, v.as_slice())).collect();
    let results = emitters.oracle(&repo.join("emit.json"), &pairs);
    for (label, bytes) in &results {
        h.add_needle(format!("{label} of a fixture"), bytes.clone());
    }
    // Where each result holds its value, which a frame's markers must
    // cover: the oracle again, on other values of the same shape, and
    // where the two differ (verifier, low: a frame with its value redacted
    // only in part passed).
    let others: Vec<(&str, Vec<u8>)> = values.iter().map(|(n, v)| (*n, other_value(v))).collect();
    let other_pairs: Vec<(&str, &[u8])> = others.iter().map(|(n, v)| (*n, v.as_slice())).collect();
    let cores = cores(
        &results,
        &emitters.oracle(&repo.join("emit.json"), &other_pairs),
    )
    .unwrap_or_else(|why| panic!("{why}"));
    vault_and_import(&mut h, &repo);

    let mut agent = AgentHome::within(&h.home, host, installed);
    let flags = configure(&mut agent, shell, &daemon_socket(&h.home));
    // The positive control: a canary this session prints, which the
    // host's transcript must hold, so a clean sweep below means something.
    let control = Canary::new(
        "POSITIVE_CONTROL",
        format!("ecctl-{:016x}{:016x}", fresh_seed(), fresh_seed()),
    );
    // Each invocation prints a nonce of its own first, named in two
    // pieces: whole, it is that invocation's output. `envcloak run`'s
    // standard output and error (redacted) go to files of that
    // invocation's own, printed after its exit status: the host merges
    // the two streams into one, which can cut a frame in two, and Codex
    // shortens what it sends its model, so the files are what the test
    // reads frames and digests from (swept with the home, as the tool
    // result is with the request bodies).
    let (first_nonce, second_nonce) = (
        format!("{:016x}", fresh_seed()),
        format!("{:016x}", fresh_seed()),
    );
    let run_emit = |nonce: &str| {
        format!(
            "printf '%s%s\\n' 'ecinv-' '{nonce}'; {} run -- ./emit --quick >emit-{nonce}.out \
             2>emit-{nonce}.err; echo \"EXIT=$?\"; cat emit-{nonce}.out emit-{nonce}.err",
            quoted(h.cli().to_str().unwrap())
        )
    };
    // Named in two pieces: whole, it can only be what the command printed.
    // Where the sandbox runs no command at all, nothing can print it: the
    // model says it instead, and the host keeps it with its reply.
    let (head, tail) = control.as_str().split_at(control.as_str().len() / 2);
    let print_control = format!("printf '%s%s\\n' {} {}", quoted(head), quoted(tail));
    let control_step = if matches!(expected, Reach::NotRun(_)) {
        json!({"say": control.as_str(), "shell": "true"})
    } else {
        json!({"shell": print_control})
    };
    let script = json!({"steps": [
        {"say": "I'll run emit through EnvCloak.", "shell": run_emit(&first_nonce)},
        {"say": "Running it again.", "shell": run_emit(&second_nonce), "after": "approved"},
        control_step,
        {"say": "done"},
    ]});
    let requests_before = audit_requests(&h);
    daemon_answers(&mut h, "before the host starts");
    let mut running = agent.spawn(&script, "Run ./emit through envcloak.", &flags, &repo);

    // What the first invocation printed, as the host sent it to its
    // model: the last tool result in the request after the call.
    let held = running.model.wait_for("step 1", &mut running.child);
    h.record(
        "the host's request to its model (S0, first run)",
        &held.body,
    );
    let first = String::from_utf8_lossy(&held.body).into_owned();
    let first_run = last_tool_output(&first);
    // Swept clean just above, so its end can be shown.
    let shown = tail_of(&first_run);
    match expected {
        Reach::Reaches => {
            // Approval needed, nothing released.
            if let Err(why) = held_for_approval(&first_run, &first_nonce) {
                panic!("the first run: {why}:\n{shown}");
            }
            let id = request_id(&first);
            // The person approves from a terminal of their own; the
            // statement names the host.
            let approved = approve(&mut h, &repo, &id);
            assert_eq!(approved.code, 0, "{}", approved.all());
            let agent_name = match host {
                Host::ClaudeCode => "Claude Code",
                Host::Codex => "Codex",
            };
            assert!(
                approved
                    .shown()
                    .contains(&format!("requested by: agent {agent_name}")),
                "{}",
                approved.all()
            );
            // What the daemon recorded for the request: the subject, and
            // the process its grant is rooted at, which must be the host
            // this test started, that very process (its pid, still
            // unreaped, and its start time), running the pinned entry.
            let root = rooted_at(&approved.shown())
                .unwrap_or_else(|why| panic!("the statement's root: {why}\n{}", approved.all()));
            let host_pid = running.child.id();
            assert_eq!(
                root.pid, host_pid,
                "the grant is rooted at pid {}, not at the host (pid {host_pid})",
                root.pid
            );
            assert_eq!(
                Some(root.start),
                envcloak_testkit::agents::start_time(host_pid),
                "the grant's root is another process instance than the running host"
            );
            assert!(
                is_entry(&root.exe, &agent.installed),
                "the grant's root runs {}, not the host's pinned entry",
                root.exe.display()
            );
            println!(
                "measurement: S0 subject host={} os={os} shell={shell:?}: requested by: agent \
                 {agent_name}, rooted at the host process itself (its pid and start time), \
                 running the pinned entry",
                host.id(),
            );
        }
        refusal => {
            // This invocation's own result is the refusal the table gives,
            // the daemon is up and answers outside the sandbox, and it saw
            // no request.
            if let Err(why) = refused(&first_run, &first_nonce, refusal) {
                panic!("the first run: {why}:\n{shown}");
            }
            daemon_answers(&mut h, "after the first run was refused");
            assert_eq!(
                audit_requests(&h),
                requests_before,
                "the daemon saw a request from the sandbox"
            );
        }
    }
    running.model.release("approved");
    let run = running.wait();
    agent.check_pinned();
    agent.check_isolated();
    h.record("the host's stdout (S0)", &run.output.stdout);
    h.record("the host's stderr (S0)", &run.output.stderr);
    for r in &run.model.requests {
        h.record(
            &format!("the host's request {} to its model (S0)", r.seq),
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
    assert_eq!(picks, ["step 0", "step 1", "step 2", "step 3"]);

    // What the rerun printed: the last tool result in the request after
    // it. The earlier results in the same conversation (the first run's)
    // say nothing about the rerun, and its nonce tells them apart.
    let second = run
        .model
        .requests
        .iter()
        .find(|r| r.pick.as_deref() == Some("step 2"))
        .map(|r| last_tool_output(&String::from_utf8_lossy(&r.body)))
        .unwrap();
    let shown = tail_of(&second);
    match expected {
        Reach::Reaches => {
            let streams = [".out", ".err"].map(|ext| {
                std::fs::read(repo.join(format!("emit-{second_nonce}{ext}")))
                    .unwrap_or_else(|e| panic!("the rerun's {ext} file: {e}"))
            });
            // Swept before anything is read from them for a message
            // (verifier, low: a digest error quoted the unswept file).
            for (stream, ext) in streams.iter().zip([".out", ".err"]) {
                h.record(&format!("the rerun's emit{ext} file (S0)"), stream);
            }
            if let Err(why) = delivered(
                &second,
                &second_nonce,
                &streams,
                &emitters,
                &results,
                &cores,
                &values,
            ) {
                panic!("the rerun: {why}:\n{shown}");
            }
            // The counter the refusal path compares is seen to count: the
            // delivered run's request is in the audit (verifier, low:
            // with no positive control, a changed audit line would make
            // the refusal path's check 0 == 0).
            assert!(
                audit_requests(&h) > requests_before,
                "the daemon's audit counted no request for a delivered run"
            );
        }
        refusal => {
            if let Err(why) = refused(&second, &second_nonce, refusal) {
                panic!("the rerun: {why}:\n{shown}");
            }
            daemon_answers(&mut h, "after the rerun was refused");
            assert_eq!(
                audit_requests(&h),
                requests_before,
                "the daemon saw a request from the sandbox"
            );
            // The receipt: where the host's sandboxed shell is
            // unsupported, what this run found is what docs/AGENTS.md
            // records for it. A sandbox that ran no command gives none
            // (an environment limitation, `Reach::receipt`).
            if k01::unsupported(os) && matches!(expected, Reach::Refused(_)) {
                k01::check_documented();
            }
        }
    }
    println!(
        "receipt: S0 host={} os={os}{ns} shell={shell:?}: {}; {}",
        host.id(),
        expected.receipt(os),
        match expected {
            Reach::Reaches => "executed: approved and delivered",
            Reach::Refused(_) => "expected refusal, verified for both invocations (not a delivery)",
            Reach::NotRun(_) => {
                "the sandbox ran neither invocation, verified (neither a delivery nor the refusal)"
            }
        }
    );

    // The control is in the tool result the host sent its model (or, where
    // no command runs, in the reply the host sent back with it).
    let third = run
        .model
        .requests
        .iter()
        .find(|r| r.pick.as_deref() == Some("step 3"))
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .unwrap();
    let carried = match expected {
        Reach::NotRun(_) => third.contains(control.as_str()),
        _ => last_tool_output(&third).contains(control.as_str()),
    };
    assert!(
        carried,
        "the control is not in what the host sent its model after it"
    );

    // The sweep: every capture, every daemon log, the whole home, raw.
    h.assert_swept("S0");
    let mut cs = h.canaries.clone();
    cs.push(control.clone());
    let hits = Sweep::host_stores(&agent, &cs, &[&run.model]);
    // A store the sweep could not read is no clean result.
    assert_eq!(hits.unreadable(), 0, "{hits}");
    let store = match host {
        Host::ClaudeCode => "claude/projects",
        Host::Codex => "codex/sessions",
    };
    assert!(
        hits.in_store_as(store, "POSITIVE_CONTROL", "raw") >= 1,
        "the positive control is not in {store}:\n{hits}"
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
    candidate_density(&agent);
}

/// The settings the person makes for `shell` (M2 plan §4; M2-08's
/// installer will write the allowances), written into the agent's home
/// and labelled so, and the host's flags.
fn configure(agent: &mut AgentHome, shell: Shell, socket: &Path) -> HostFlags {
    match shell {
        Shell::ClaudeUnsandboxed
        | Shell::ClaudeSandboxNoAllowance
        | Shell::ClaudeSandboxAllowResolved => {
            // Claude Code cuts a command's output past 30,000 characters
            // by default; the whole of it is what is swept.
            agent.set_env("BASH_MAX_OUTPUT_LENGTH", "500000");
            let mut sandbox = json!({"enabled": true, "failIfUnavailable": true,
                "autoAllowBashIfSandboxed": true, "allowUnsandboxedCommands": false});
            if shell == Shell::ClaudeSandboxAllowResolved {
                // macOS resolves /tmp to /private/tmp before its sandbox
                // compares a path.
                let resolved = std::fs::canonicalize(socket).unwrap();
                sandbox["network"] = json!({"allowUnixSockets": [resolved.to_str().unwrap()]});
            }
            let settings = if shell == Shell::ClaudeUnsandboxed {
                json!({})
            } else {
                json!({"_comment": "the person's settings (M2 plan §4)", "sandbox": sandbox})
            };
            let dir = agent.home_dir().join(".claude");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("settings.json"), settings.to_string()).unwrap();
            HostFlags::claude("default", &["Bash"])
        }
        Shell::CodexWorkspaceWriteBounded => {
            agent.codex_config(&format!(
                "# The person's settings (M2 plan §4; M2-08's installer writes them):\n\
                 # command networking on, limited to EnvCloak's socket.\n\
                 [sandbox_workspace_write]\nnetwork_access = true\n\
                 [features.network_proxy]\nenabled = true\n\
                 [features.network_proxy.unix_sockets]\n{} = \"allow\"\n",
                json!(socket.to_str().unwrap())
            ));
            HostFlags::codex("workspace-write", "never")
        }
        // No network setting: what M2-08 leaves on Linux.
        Shell::CodexWorkspaceWrite => HostFlags::codex("workspace-write", "never"),
        other => panic!("S0 does not run {other:?}"),
    }
}

/// The daemon the harness started is still running, that very process,
/// and answers `envcloak status` from outside any sandbox, with the
/// environment the host's commands get: the check, independent of the
/// host, that a refusal inside the sandbox is the sandbox's (review: a
/// stopped daemon or a runtime directory gone would give an unrelated
/// failure the refusal check alone could take for it).
fn daemon_answers(h: &mut Harness, when: &str) {
    assert!(h.daemon.is_running(), "the daemon is not running {when}");
    let cli = h.cli();
    let out = h.program(&cli, &["status"], None);
    let said = text(&out);
    let pid = h.daemon.pid();
    assert!(
        out.status.success() && said.contains(&format!("daemon: running (pid {pid},")),
        "the daemon (pid {pid}) does not answer outside the sandbox {when}:\n{said}"
    );
}

/// How many lines of `output` are the invocation marker `ecinv-<nonce>`;
/// `None` when there is none.
fn invocation(output: &str, nonce: &str) -> Option<usize> {
    let marker = format!("ecinv-{nonce}");
    let n = output.lines().filter(|l| l.trim() == marker).count();
    (n > 0).then_some(n)
}

/// Whether `output` holds an invocation marker other than `nonce`'s: a
/// line that starts with `ecinv-` and is not `ecinv-<nonce>`, another
/// invocation's output, which fails the step whatever else is there
/// (Codex review, low: a foreign marker with no exit line passed).
fn foreign_invocation(output: &str, nonce: &str) -> bool {
    let marker = format!("ecinv-{nonce}");
    output
        .lines()
        .map(str::trim)
        .any(|l| l.starts_with("ecinv-") && l != marker)
}

/// What only a command that got its values prints: a serializer's frame,
/// a digest, the serializer list, a redaction marker.
const DELIVERY_TRACES: [&str; 5] = ["<W|", "<B|", "sha256 ", "SERIALIZERS ", "[envcloak:"];

/// Whether `output` is the invocation `nonce` held for approval, and
/// nothing else: its marker once and no other invocation's, after it the
/// `approval_required` line and exit 125, and no trace of a delivery (no
/// frame, digest, serializer list or redaction marker: verifier, low,
/// only the refusal and the delivery were checked for them). Why not,
/// when it is not.
fn held_for_approval(output: &str, nonce: &str) -> Result<(), String> {
    if let Some(trace) = DELIVERY_TRACES.iter().find(|t| output.contains(*t)) {
        return Err(format!("a trace of a delivery ({trace:?})"));
    }
    if foreign_invocation(output, nonce) {
        return Err("another invocation's output".to_owned());
    }
    if invocation(output, nonce) != Some(1) {
        return Err(format!("not invocation {nonce}'s own output"));
    }
    let after = output
        .split(&format!("ecinv-{nonce}"))
        .nth(1)
        .unwrap_or_default();
    let pending = after
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("envcloak: approval_required: request="))
        .count();
    match (pending, exits(after).as_slice()) {
        (1, ["125"]) => Ok(()),
        (n, codes) => Err(format!(
            "not held for approval: {n} `approval_required` line(s), exit codes {codes:?}"
        )),
    }
}

/// Whether `output` is the invocation `nonce`'s refusal as K-01's table
/// gives it, and nothing else: for a CLI refusal, the marker once, then
/// exactly one `envcloak:` line, the table's message with "nothing was
/// sent to it", and exit 125; for a sandbox that runs no command, its
/// message and no marker, `envcloak:` line or exit at all. In both, no
/// trace of a delivery and no other invocation's marker. Why not, when it
/// is not.
fn refused(output: &str, nonce: &str, want: Reach) -> Result<(), String> {
    if let Some(trace) = DELIVERY_TRACES.iter().find(|t| output.contains(*t)) {
        return Err(format!("a trace of a delivery ({trace:?})"));
    }
    if foreign_invocation(output, nonce) {
        return Err("another invocation's output".to_owned());
    }
    let lines: Vec<&str> = output
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("envcloak: "))
        .collect();
    match want {
        Reach::Refused(message) => {
            if invocation(output, nonce) != Some(1) {
                return Err(format!("not invocation {nonce}'s own output"));
            }
            let after = output
                .split(&format!("ecinv-{nonce}"))
                .nth(1)
                .unwrap_or_default();
            let refusal = format!("envcloak: {message}{}", k01::NOTHING_SENT);
            match (lines.as_slice(), exits(after).as_slice()) {
                ([line], ["125"]) if *line == refusal && after.contains(&refusal) => Ok(()),
                (lines, codes) => Err(format!(
                    "not the refusal {refusal:?} and exit 125: {} `envcloak:` line(s) \
                     {lines:?}, exit codes {codes:?}",
                    lines.len()
                )),
            }
        }
        Reach::NotRun(message) => {
            if !output.contains(message) {
                return Err(format!("the sandbox did not say {message:?}"));
            }
            if invocation(output, nonce).is_some() || !lines.is_empty() || !exits(output).is_empty()
            {
                return Err("the command ran".to_owned());
            }
            Ok(())
        }
        Reach::Reaches => Err("no refusal is expected".to_owned()),
    }
}

/// Whether the invocation `nonce` delivered: in the tool result the host
/// sent its model, the marker once (and no other invocation's) and exit
/// 0; in what `envcloak run` printed on its standard output and error
/// (`streams`, each written by one writer, so no frame is cut), every
/// serializer listed with every result, both frames of every result the
/// oracle made, each holding that result as the serializer made it with
/// its value redacted ([`frames`]), a digest per serializer and variable
/// equal to the fixture value's SHA-256 (what the command received,
/// checked by an oracle that does not depend on the redactor), and a
/// redaction marker for every binding on both streams. Why not, when it
/// is not; the reason quotes nothing the streams hold.
fn delivered(
    output: &str,
    nonce: &str,
    streams: &[Vec<u8>; 2],
    emitters: &Emitters,
    results: &[(String, Vec<u8>)],
    cores: &BTreeMap<String, std::ops::Range<usize>>,
    values: &BTreeMap<&str, Vec<u8>>,
) -> Result<(), String> {
    if invocation(output, nonce) != Some(1) {
        return Err(format!("not invocation {nonce}'s own output"));
    }
    if foreign_invocation(output, nonce) {
        return Err("another invocation's output".to_owned());
    }
    if exits(output) != ["0"] {
        return Err(format!("exit codes {:?}, not 0", exits(output)));
    }
    let [out, err] = streams
        .each_ref()
        .map(|s| String::from_utf8_lossy(s).into_owned());
    for slug in [
        "openai/acme-web",
        "stripe/acme-web",
        "github/acme-web",
        "database-url/acme-web",
    ] {
        let marker = format!("[envcloak:{slug}]");
        if !out.contains(&marker) || !err.contains(&marker) {
            return Err(format!("no redaction marker for {slug} on both streams"));
        }
    }
    let output = format!("{out}{err}");
    let tags = emitters.tags();
    let listed = format!("SERIALIZERS {} RESULTS {}", tags.join(","), results.len());
    if !output.contains(&listed) || !output.contains("DONE") {
        return Err(format!("no {listed:?} and DONE"));
    }
    frames(streams, results, cores)?;
    let digests: BTreeMap<(&str, &str), &str> = out
        .lines()
        .filter_map(|l| {
            let mut w = l.trim().split(' ');
            (w.next() == Some("sha256")).then_some(())?;
            Some(((w.next()?, w.next()?), w.next()?))
        })
        .collect();
    for tag in &tags {
        for name in NAMES {
            let want = sha256_hex(&values[name]);
            match digests.get(&(tag.as_str(), name)) {
                Some(got) if *got == want => {}
                Some(_) => return Err(format!("the {tag} digest of {name} is not the fixture's")),
                None => return Err(format!("no {tag} digest of {name}")),
            }
        }
    }
    Ok(())
}

/// The binding each of [`NAMES`] has in `acme-web`.
fn slug_of(name: &str) -> Option<&'static str> {
    match name {
        "OPENAI_API_KEY" => Some("openai/acme-web"),
        "STRIPE_SECRET_KEY" => Some("stripe/acme-web"),
        "GITHUB_TOKEN" => Some("github/acme-web"),
        "DATABASE_URL" => Some("database-url/acme-web"),
        _ => None,
    }
}

/// `value` with every letter and digit replaced by another of its kind
/// (letters rotated by 13, digits by 5) and every other byte kept: what
/// the oracle is run on a second time, so each result keeps its length in
/// every encoding the serializers use and differs where it holds the
/// value ([`value_span`]). Never a value of the vault: it is held here
/// only, for the oracle.
fn other_value(value: &[u8]) -> Vec<u8> {
    value
        .iter()
        .map(|b| match b {
            b'a'..=b'z' => b'a' + (b - b'a' + 13) % 26,
            b'A'..=b'Z' => b'A' + (b - b'A' + 13) % 26,
            b'0'..=b'9' => b'0' + (b - b'0' + 5) % 10,
            other => *other,
        })
        .collect()
}

/// The span of `result` that holds its value: from the first byte to the
/// last that `other` (the same serializer's result for
/// [`other_value`]) differs in. `None` when the two differ in length or
/// not at all, where the value's place cannot be told.
fn value_span(result: &[u8], other: &[u8]) -> Option<std::ops::Range<usize>> {
    if result.len() != other.len() {
        return None;
    }
    let differs = |i: &usize| result[*i] != other[*i];
    let start = (0..result.len()).find(differs)?;
    let end = (0..result.len()).rev().find(differs)? + 1;
    Some(start..end)
}

/// What of a result's value span (`span`) a marker must cover: all of it,
/// but for a base64 result, whose value the redactor finds only as the
/// 3-byte groups wholly inside it (crates/envcloak-redact, "Coverage"),
/// up to three characters at each end (two from the value's own bytes
/// and one shared with what is beside it).
fn must_cover(label: &str, span: std::ops::Range<usize>) -> std::ops::Range<usize> {
    let base64 = label
        .split_once('/')
        .is_some_and(|(_, tag)| tag.starts_with("b64"));
    if !base64 {
        return span;
    }
    let start = span.start + 3;
    start..span.end.saturating_sub(3).max(start)
}

/// For each result, by label, what a marker must cover
/// ([`value_span`], [`must_cover`]), from the oracle's results for the
/// fixture values and for [`other_value`]s. Refused, naming the label
/// only, when the two runs' labels differ or a result's value cannot be
/// placed, or leaves nothing to cover.
fn cores(
    results: &[(String, Vec<u8>)],
    others: &[(String, Vec<u8>)],
) -> Result<BTreeMap<String, std::ops::Range<usize>>, String> {
    let labels = |r: &[(String, Vec<u8>)]| r.iter().map(|(l, _)| l.clone()).collect::<Vec<_>>();
    if labels(results) != labels(others) {
        return Err("the two oracle runs made different results".to_owned());
    }
    let mut out = BTreeMap::new();
    for ((label, result), (_, other)) in results.iter().zip(others) {
        let span =
            value_span(result, other).ok_or_else(|| format!("{label}'s value cannot be placed"))?;
        let core = must_cover(label, span);
        if core.is_empty() {
            return Err(format!(
                "{label}'s value leaves nothing a marker must cover"
            ));
        }
        out.insert(label.clone(), core);
    }
    Ok(out)
}

/// Whether every result the oracle made (`<NAME>/<serializer>` and its
/// bytes) has exactly one whole frame (`<W|`) and one frame written in
/// pieces (`<B|`) on the two streams together, each payload the result as
/// the serializer made it with one or more non-empty spans replaced by
/// its own binding's marker, those spans covering what `cores` gives for
/// it, and nothing else changed ([`redacted_from`]): so a frame with its
/// payload gone, cut short, unredacted, redacted in part or for another
/// binding fails (verifier, low: only the frame names were checked, then
/// a value redacted in part passed). Why not, naming the frame and never
/// its payload.
fn frames(
    streams: &[Vec<u8>; 2],
    results: &[(String, Vec<u8>)],
    cores: &BTreeMap<String, std::ops::Range<usize>>,
) -> Result<(), String> {
    for (label, result) in results {
        let name = label.split('/').next().unwrap_or_default();
        let slug = slug_of(name).ok_or_else(|| format!("no binding for {label}"))?;
        let marker = format!("[envcloak:{slug}]");
        let core = cores
            .get(label)
            .ok_or_else(|| format!("no place of the value in {label}"))?;
        for frame in ["<W|", "<B|"] {
            let head = format!("{frame}{label}=");
            let lines: Vec<&[u8]> = streams
                .iter()
                .flat_map(|s| s.split(|b| *b == b'\n'))
                .filter(|l| l.starts_with(head.as_bytes()))
                .collect();
            let [line] = lines.as_slice() else {
                return Err(format!("{} {frame}{label} frame(s), not one", lines.len()));
            };
            if !redacted_from(&line[head.len()..], result, marker.as_bytes(), core) {
                return Err(format!(
                    "the {frame}{label} frame is not that result with its value redacted as \
                     {slug}"
                ));
            }
        }
    }
    Ok(())
}

/// Whether `payload` is `result` with one or more non-empty spans each
/// replaced by `marker`, those spans covering all of `core` (where the
/// result holds its value, [`cores`]), and nothing else changed: the
/// pieces between the markers are, in order, a prefix of `result`, parts
/// of it, and a suffix of it, each apart from the next by at least one
/// byte, and none of them shows a byte of `core` (a piece left of it ends
/// at its start at the latest, one right of it starts at its end at the
/// earliest; an empty piece shows nothing). Each piece is placed
/// leftmost where it may be, which leaves the most room for the rest.
fn redacted_from(
    payload: &[u8],
    result: &[u8],
    marker: &[u8],
    core: &std::ops::Range<usize>,
) -> bool {
    let mut pieces: Vec<&[u8]> = Vec::new();
    let mut rest = payload;
    while let Some(at) = rest.windows(marker.len()).position(|w| w == marker) {
        pieces.push(&rest[..at]);
        rest = &rest[at + marker.len()..];
    }
    pieces.push(rest);
    let (Some((first, middle)), Some(last)) = (pieces.split_first(), pieces.last()) else {
        return false;
    };
    if pieces.len() < 2 || !result.starts_with(first) || !result.ends_with(last) {
        return false;
    }
    let limit = result.len() - last.len();
    if first.len() > core.start || limit < core.end {
        return false;
    }
    let shows_none = |at: usize, len: usize| len == 0 || at + len <= core.start || at >= core.end;
    let mut at = first.len();
    for piece in &middle[..middle.len() - 1] {
        let from = at + 1;
        let Some(found) = result.get(from..limit).and_then(|r| {
            (0..=r.len().checked_sub(piece.len())?)
                .find(|i| r[*i..].starts_with(piece) && shows_none(from + i, piece.len()))
        }) else {
            return false;
        };
        at = from + found + piece.len();
    }
    at < limit
}

/// The last 3,000 characters of `text`, for a failure message (what it
/// is taken from was swept first).
fn tail_of(text: &str) -> &str {
    text.char_indices()
        .rev()
        .nth(3000)
        .map_or(text, |(at, _)| &text[at..])
}

/// The process an approval statement says the grant is rooted at.
#[derive(Debug)]
struct Root {
    pid: u32,
    /// In the kernel's units, as the daemon records it.
    start: u64,
    exe: PathBuf,
}

/// The root in the statement's `requested by: ... rooted at pid <pid>
/// started at <start>, <executable>` line, or why there is none: a line
/// missing, or any part of it missing or not a number, is refused, never
/// guessed.
fn rooted_at(statement: &str) -> Result<Root, String> {
    let line = statement
        .lines()
        .find(|l| l.contains("requested by:"))
        .ok_or("no `requested by:` line")?;
    let (_, rest) = line
        .split_once(", rooted at pid ")
        .ok_or("no `rooted at pid`")?;
    let (pid, rest) = rest.split_once(" started at ").ok_or("no `started at`")?;
    let (start, exe) = rest.split_once(", ").ok_or("no executable for the root")?;
    let exe = exe.trim();
    if exe.is_empty() {
        return Err("an empty executable for the root".to_owned());
    }
    Ok(Root {
        pid: pid.parse().map_err(|_| "a pid that is not a number")?,
        start: start
            .parse()
            .map_err(|_| "a start time that is not a number")?,
        exe: PathBuf::from(exe),
    })
}

/// Whether `exe` is the host's pinned entry (or the program it starts).
fn is_entry(exe: &Path, installed: &Installed) -> bool {
    let canonical = |p: &Path| std::fs::canonicalize(p).ok();
    let mut pinned = vec![canonical(&installed.exe)];
    if let Some((starts, _)) = &installed.pin.starts {
        pinned.push(canonical(&installed.dir.join(starts)));
    }
    canonical(exe).is_some_and(|e| pinned.contains(&Some(e)))
}

/// The text of the last tool result in a request body (Anthropic
/// Messages or OpenAI Responses): what the call the model made last
/// printed, as the host sent it.
fn last_tool_output(body: &str) -> String {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        return String::new();
    };
    let text = |c: &serde_json::Value| match c {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(parts) => parts
            .iter()
            .filter_map(|p| p["text"].as_str())
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    };
    let mut out = String::new();
    for m in v["messages"].as_array().into_iter().flatten() {
        for c in m["content"].as_array().into_iter().flatten() {
            if c["type"] == "tool_result" {
                out = text(&c["content"]);
            }
        }
    }
    for item in v["input"].as_array().into_iter().flatten() {
        if item["type"] == "function_call_output" {
            out = text(&item["output"]);
        }
    }
    out
}

/// The exit codes `echo "EXIT=$?"` printed in one command's output.
fn exits(output: &str) -> Vec<&str> {
    output
        .lines()
        .filter_map(|l| l.trim().strip_prefix("EXIT="))
        .collect()
}

/// The number of `request` lines in the daemons' audit log so far.
fn audit_requests(h: &Harness) -> usize {
    h.daemon_logs()
        .iter()
        .map(|l| {
            String::from_utf8_lossy(l)
                .matches("envcloakd: audit: request ")
                .count()
        })
        .sum()
}

/// Candidates of 16 or more characters per MiB in what the host wrote to
/// its stores during the step, before and after de-duplication (K-21;
/// D-32 sizes the comparison budget from it). A candidate here is a run
/// of 16 or more bytes between whitespace, quotes, and JSON and shell
/// punctuation; the scanner's tokenizer (M2-12) is narrower, so this is an
/// upper bound, and each candidate may add up to three decoded forms.
fn candidate_density(agent: &AgentHome) {
    use std::collections::HashSet;
    let stores = envcloak_testkit::transcripts::transcript_roots(agent.host, &agent.host_dirs());
    let mut files = Vec::new();
    for store in &stores {
        match store.shape {
            envcloak_testkit::transcripts::Shape::Named(part) => {
                for e in std::fs::read_dir(&store.path)
                    .into_iter()
                    .flatten()
                    .flatten()
                {
                    if e.file_name().to_string_lossy().contains(part) {
                        collect(&e.path(), &mut files);
                    }
                }
            }
            _ => collect(&store.path, &mut files),
        }
    }
    files.sort();
    files.dedup();
    let (mut bytes, mut total) = (0usize, 0usize);
    let mut distinct: HashSet<Vec<u8>> = HashSet::new();
    for f in &files {
        let Ok(data) = std::fs::read(f) else { continue };
        bytes += data.len();
        for token in data.split(|b| b.is_ascii_whitespace() || b"\"'`,;(){}[]<>|&\\".contains(b)) {
            if token.len() >= 16 {
                total += 1;
                distinct.insert(token.to_vec());
            }
        }
    }
    let mib = bytes as f64 / (1024.0 * 1024.0);
    println!(
        "measurement: candidates of 16+ characters host={} os={}: {bytes} bytes in {} files, \
         {total} candidates ({:.0} per MiB), {} distinct ({:.0} per MiB)",
        agent.host.id(),
        std::env::consts::OS,
        files.len(),
        total as f64 / mib.max(f64::MIN_POSITIVE),
        distinct.len(),
        distinct.len() as f64 / mib.max(f64::MIN_POSITIVE),
    );
}

/// Every regular file at or below `path`.
fn collect(path: &Path, out: &mut Vec<PathBuf>) {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    if meta.is_file() {
        out.push(path.to_path_buf());
    } else if meta.is_dir() {
        for e in std::fs::read_dir(path).into_iter().flatten().flatten() {
            collect(&e.path(), out);
        }
    }
}

/// The statement's root is read whole or refused: a statement with no
/// root, or a root with a part missing or not a number, is never taken
/// for one.
#[test]
fn the_statement_s_root_is_read_whole_or_refused() {
    let good = "Approval request ab12cd34\n  requested by: agent Codex (caller pid 7), \
                rooted at pid 42 started at 1700000000123, /opt/x/codex\n  project: /p\n";
    let root = rooted_at(good).unwrap();
    assert_eq!(
        (root.pid, root.start, root.exe.as_path()),
        (42, 1_700_000_000_123, Path::new("/opt/x/codex"))
    );
    for bad in [
        "",
        "  project: /p\n",
        "  requested by: agent Codex (caller pid 7)\n",
        "  requested by: agent Codex (caller pid 7), rooted at pid  started at 1, /x\n",
        "  requested by: agent Codex (caller pid 7), rooted at pid 4x2 started at 1, /x\n",
        "  requested by: agent Codex (caller pid 7), rooted at pid 42 started at -1, /x\n",
        "  requested by: agent Codex (caller pid 7), rooted at pid 42 started at 1\n",
        "  requested by: agent Codex (caller pid 7), rooted at pid 42 started at 1, \n",
    ] {
        assert!(rooted_at(bad).is_err(), "{bad:?}");
    }
}

/// The refusal check takes only the table's refusal of this very
/// invocation, and nothing that would also be there if the daemon had
/// stopped, another invocation's result came back, or the command had
/// run (Codex review, high: any `daemon_unavailable` or
/// `daemon_unverified` line with exit 125 passed).
#[test]
fn a_refusal_is_this_invocation_s_and_the_table_s() {
    let ok = format!(
        "ecinv-n1\nenvcloak: {}{}\nEXIT=125\n",
        k01::RUNTIME_DIR,
        k01::NOTHING_SENT
    );
    assert_eq!(refused(&ok, "n1", Reach::Refused(k01::RUNTIME_DIR)), Ok(()));
    let not_run = format!(
        "Exit code 1 /bin/bash: x: Permission denied {}",
        k01::SECCOMP_HELPER
    );
    assert_eq!(
        refused(&not_run, "n1", Reach::NotRun(k01::SECCOMP_HELPER)),
        Ok(())
    );
    let unavailable = "ecinv-n1\nenvcloak: daemon_unavailable: the EnvCloak daemon is not \
                       running; start it\nEXIT=125\n";
    let other_unverified = format!(
        "ecinv-n1\nenvcloak: {}{}\nEXIT=125\n",
        k01::NO_PEER_PID,
        k01::NOTHING_SENT
    );
    let another_invocation = ok.replace("n1", "n0");
    // Another invocation's marker beside this one's, with no output of
    // its own (Codex review, low).
    let and_another = format!("ecinv-n0\n{ok}");
    let twice = format!("{ok}{ok}");
    let ran = format!("{ok}<W|OPENAI_API_KEY/raw=[envcloak:openai/acme-web]\n");
    let exit_1 = ok.replace("EXIT=125", "EXIT=1");
    for bad in [
        unavailable.to_owned(),
        other_unverified,
        another_invocation,
        and_another,
        twice,
        ran,
        exit_1,
        String::new(),
    ] {
        assert!(
            refused(&bad, "n1", Reach::Refused(k01::RUNTIME_DIR)).is_err(),
            "{bad:?}"
        );
    }
    for bad in [
        ok.clone(),
        "Exit code 1".to_owned(),
        // Another invocation's marker and nothing else of it: still not a
        // sandbox that ran nothing (Codex review, low: only this
        // invocation's marker was refused).
        format!("ecinv-n0\n{not_run}"),
    ] {
        assert!(
            refused(&bad, "n1", Reach::NotRun(k01::SECCOMP_HELPER)).is_err(),
            "{bad:?}"
        );
    }
}

/// The first run on a qualified path is taken as held only when it is
/// this invocation's, held once with exit 125, and nothing of a delivery
/// came with it (verifier, low: a frame, digest, serializer list or
/// marker beside `approval_required` passed, as did another
/// invocation's marker).
#[test]
fn a_held_run_is_this_invocation_s_and_released_nothing() {
    let line = "envcloak: approval_required: request=ab12cd34: run \"envcloak approve \
                ab12cd34\" in a terminal you control";
    let ok = format!("ecinv-n1\nEXIT=125\n{line}\n");
    assert_eq!(held_for_approval(&ok, "n1"), Ok(()));
    let mut bad: Vec<String> = DELIVERY_TRACES
        .iter()
        .map(|t| format!("{ok}{t}x\n"))
        .collect();
    bad.extend([
        format!("ecinv-n0\n{ok}"),
        ok.replace("n1", "n0"),
        format!("{ok}{ok}"),
        ok.replace("EXIT=125", "EXIT=0"),
        ok.replace(line, "envcloak: approval_denied: no"),
        format!("{line}\necinv-n1\nEXIT=125\n"),
        format!("{ok}{line}\n"),
        String::new(),
    ]);
    for b in &bad {
        assert!(held_for_approval(b, "n1").is_err(), "{b:?}");
    }
}

/// A frame is taken only as the serializer's own result with spans of
/// it replaced by its own binding's marker, those spans covering where
/// the result holds its value (verifier, low: frames with every payload
/// removed passed; then one redacted only in part, its value's remaining
/// text visible, passed): the control passes; payloads removed, cut
/// short where what is left differs from the result, left unredacted or
/// redacted in part, redacted as another binding, or with anything
/// added, a frame missing or doubled, all fail, and no reason quotes a
/// payload.
#[test]
fn a_frame_is_its_result_with_the_value_redacted() {
    let m = "[envcloak:openai/acme-web]";
    // The base64 of `u`, a value and `!!!`, as `emit.py` makes it at
    // offset 1: its value spans bytes 1 to 15, and the redactor leaves up
    // to three characters at each end of that.
    let b64 = "dVZBTFVFVkFMVUUhISE=";
    assert_eq!(
        value_span(b64.as_bytes(), b"dUlOWUhSSU5ZSFIhISE="),
        Some(1..15)
    );
    let b64_core = must_cover("X/b64url-at1", 1..15);
    assert_eq!(b64_core, 4..12);
    for (payload, result, core, ok) in [
        (m.to_owned(), "VALUEVALUE", 0..10, true),
        (format!("\"{m}\""), "\"VALUEVALUE\"", 1..11, true),
        (format!("dVZB{m}VUUhISE="), b64, b64_core.clone(), true),
        (format!("dT{m}IQ=="), "dTVBTFVFVkFMVUUhIQ==", 2..16, true),
        (format!("\"{m}{m}\""), "\"VALUEVALUE\"", 1..11, true),
        (format!("a{m}b{m}c"), "aVALUEbVALUEc", 1..6, true),
        (String::new(), "VALUEVALUE", 0..10, false),
        ("VALUEVALUE".to_owned(), "VALUEVALUE", 0..10, false),
        // A marker may cover the quote beside the value too.
        (format!("\"{m}"), "\"VALUEVALUE\"", 1..11, true),
        (format!("{m}\""), "\"VALUEVALUE\"", 1..11, true),
        // Redacted in part: what is left of the value shows, at its end,
        // its start, or between two markers (verifier, low).
        (format!("{m}ALUEVALUE"), "VALUEVALUE", 0..10, false),
        (format!("{m}E"), "VALUEVALUE", 0..10, false),
        (format!("V{m}"), "VALUEVALUE", 0..10, false),
        (format!("{m}LUEV{m}"), "VALUEVALUE", 0..10, false),
        (format!("a{m}b{m}c"), "aVALUEbVALUEc", 1..12, false),
        (format!("dVZBT{m}VUUhISE="), b64, b64_core.clone(), false),
        (format!("dVZB{m}MVUUhISE="), b64, b64_core.clone(), false),
        // Cut short, before or after the marker.
        ("\"VALU".to_owned(), "\"VALUEVALUE\"", 1..11, false),
        (format!("dT{m}IQ="), "dTVBTFVFVkFMVUUhIQ==", 2..16, false),
        (format!("\"{m}\"x"), "\"VALUEVALUE\"", 1..11, false),
        (format!("\"\"{m}"), "\"VALUEVALUE\"", 1..11, false),
        (
            "\"[envcloak:stripe/acme-web]\"".to_owned(),
            "\"VALUEVALUE\"",
            1..11,
            false,
        ),
        (m.to_owned(), "", 0..0, false),
        (format!("ab{m}"), "ab", 2..2, false),
    ] {
        assert_eq!(
            redacted_from(payload.as_bytes(), result.as_bytes(), m.as_bytes(), &core),
            ok,
            "{payload:?} from {result:?}"
        );
    }
    let results = vec![
        ("OPENAI_API_KEY/raw".to_owned(), b"VALUEVALUE".to_vec()),
        (
            "OPENAI_API_KEY/py-json-ascii".to_owned(),
            b"\"VALUEVALUE\"".to_vec(),
        ),
    ];
    let others = vec![
        ("OPENAI_API_KEY/raw".to_owned(), b"INYHRINYHR".to_vec()),
        (
            "OPENAI_API_KEY/py-json-ascii".to_owned(),
            b"\"INYHRINYHR\"".to_vec(),
        ),
    ];
    let cores = cores(&results, &others).unwrap();
    assert_eq!(
        cores.values().cloned().collect::<Vec<_>>(),
        [1..11, 0..10],
        "{cores:?}"
    );
    let good = [
        format!("<W|OPENAI_API_KEY/raw={m}\n<B|OPENAI_API_KEY/raw={m}\n"),
        format!(
            "<W|OPENAI_API_KEY/py-json-ascii=\"{m}\"\n<B|OPENAI_API_KEY/py-json-ascii=\"{m}\"\n"
        ),
    ];
    let streams = |out: &str, err: &str| [out.as_bytes().to_vec(), err.as_bytes().to_vec()];
    assert_eq!(
        frames(&streams(&good[0], &good[1]), &results, &cores),
        Ok(())
    );
    // The verifier's case: the frame's value redacted in part.
    let part = good[0].replacen(m, &format!("{m}ALUEVALUE"), 1);
    let why = frames(&streams(&part, &good[1]), &results, &cores).unwrap_err();
    assert!(!why.contains("VALUE"), "{why}");
    let emptied = |s: &str| {
        s.lines()
            .map(|l| format!("{}=\n", l.split('=').next().unwrap()))
            .collect::<String>()
    };
    for (out, err) in [
        (emptied(&good[0]), emptied(&good[1])),
        (emptied(&good[0]), good[1].clone()),
        (good[0].replace(m, "VALUEVALUE"), good[1].clone()),
        (
            good[0].replace(m, "[envcloak:github/acme-web]"),
            good[1].clone(),
        ),
        (
            good[0].replace(&format!("{m}\n<B"), "\n<B"),
            good[1].clone(),
        ),
        (good[0].lines().next().unwrap().to_owned(), good[1].clone()),
        (format!("{}{}", good[0], good[0]), good[1].clone()),
        (good[0].clone(), String::new()),
    ] {
        let why = frames(&streams(&out, &err), &results, &cores).unwrap_err();
        assert!(!why.contains("VALUE"), "{why}");
    }
}

/// Where a result holds its value is found, not typed: the other values
/// change every letter and digit and keep every length, a result the
/// two runs make alike or of different lengths, or a label one run lacks,
/// is refused, and the base64 results alone leave the redactor's
/// boundary characters out of what must be covered.
#[test]
fn where_a_result_holds_its_value_is_found_by_changing_the_value() {
    let v = b"sk_live-Az09.x/Y@zZ:9".to_vec();
    let w = other_value(&v);
    assert_eq!(w.len(), v.len());
    for (a, b) in v.iter().zip(&w) {
        if a.is_ascii_alphanumeric() {
            assert_ne!(a, b);
            assert_eq!(
                (
                    a.is_ascii_lowercase(),
                    a.is_ascii_uppercase(),
                    a.is_ascii_digit()
                ),
                (
                    b.is_ascii_lowercase(),
                    b.is_ascii_uppercase(),
                    b.is_ascii_digit()
                )
            );
        } else {
            assert_eq!(a, b);
        }
    }
    assert_eq!(value_span(b"\"abc\"", b"\"nop\""), Some(1..4));
    assert_eq!(value_span(b"abc", b"abc"), None);
    assert_eq!(value_span(b"abc", b"abcd"), None);
    assert_eq!(must_cover("OPENAI_API_KEY/b64-nopad-at2", 1..30), 4..27);
    assert_eq!(must_cover("OPENAI_API_KEY/py-json-ascii", 1..30), 1..30);
    assert_eq!(must_cover("OPENAI_API_KEY/b64-at0", 0..5), 3..3);
    let results = vec![("A/raw".to_owned(), b"abc".to_vec())];
    for others in [
        vec![("A/raw".to_owned(), b"abc".to_vec())],
        vec![("A/raw".to_owned(), b"abcd".to_vec())],
        vec![("B/raw".to_owned(), b"nop".to_vec())],
        vec![],
    ] {
        assert!(cores(&results, &others).is_err(), "{others:?}");
    }
    // A span the boundary leaves nothing of cannot vouch for a frame.
    assert!(
        cores(
            &[("A/b64-at0".to_owned(), b"abcde".to_vec())],
            &[("A/b64-at0".to_owned(), b"nopqr".to_vec())]
        )
        .is_err()
    );
}

/// K-01's receipt for a sandboxed shell rests on a run outside a user
/// namespace (inside one, Claude Code's Linux sandbox runs no command,
/// an environment limitation): CI runs S0's sandboxed cases there, in the
/// pull-request `gates` job, in `agents-e2e` and in the release job, as
/// required steps, never allowed to fail (verifier, low). Each such step
/// runs under its own condition exactly (verifier, low: `if: false`
/// passed), names only tests `m2_story` has, and fails unless every one
/// it names ran and passed (verifier, low: a misspelt name ran nothing
/// with `--exact`, and the step passed).
#[test]
fn ci_runs_the_sandboxed_cases_outside_a_user_namespace_as_required_steps() {
    let ci = ci_file();
    let jobs = ci_jobs(&ci);
    let tests = story_tests();
    for (job, prefix, condition) in [
        (
            "gates",
            "Story steps, sandboxed cases outside a user namespace",
            "${{ !cancelled() }}",
        ),
        (
            "agents-e2e",
            "Story steps, sandboxed cases outside a user namespace",
            "${{ !cancelled() && runner.os == 'Linux' && github.event_name != 'pull_request' }}",
        ),
        (
            "release",
            "S0 on the release binaries, sandboxed cases outside a user namespace",
            "${{ !cancelled() && runner.os == 'Linux' }}",
        ),
    ] {
        let body = ci_job(&jobs, job);
        assert!(
            !body.contains("continue-on-error"),
            "the {job} job may fail without failing CI"
        );
        let steps = ci_steps(body, prefix);
        assert_eq!(steps.len(), 1, "{job}: no single outside-namespace S0 step");
        let step = steps[0];
        assert_eq!(
            yaml_value(step, 8, "if"),
            Some(condition),
            "{job}'s outside-namespace S0 step does not run under its own condition"
        );
        for needed in ["unshare --net --", "--test m2_story", "set -o pipefail"] {
            assert!(step.contains(needed), "{job}'s step lacks {needed:?}");
        }
        assert!(
            !step.contains("--user") && !step.contains("continue-on-error"),
            "{job}'s step is not a required run outside a user namespace"
        );
        let names = exact_names(step);
        for name in [
            "skeleton::s0_claude_code_sandboxed",
            "skeleton::s0_codex_workspace_write",
        ] {
            assert!(names.contains(&name), "{job}'s step does not run {name}");
        }
        for name in &names {
            assert!(
                tests.contains(&(*name).to_owned()),
                "{job}'s step names {name}, which m2_story has no test of"
            );
        }
        assert_ran_all(step, names.len(), job);
    }
}

/// Every step of every job that runs tests by name with `--exact`, the
/// open-network positive controls included (verifier, low: those ran
/// `the_network_is_what_ci_says` unguarded, so a renamed test would run
/// nothing and pass), names only tests its target has and fails unless
/// every one it names ran and passed.
#[test]
fn ci_fails_every_exact_step_whose_tests_did_not_all_run() {
    let ci = ci_file();
    let mut open_controls = 0;
    for (job, body) in ci_jobs(&ci) {
        for text in body.split("\n      - name: ").skip(1) {
            // What the step runs: its lines but comments (the comment
            // above the next step's name is in this one's text).
            let step: String = text
                .lines()
                .filter(|l| !l.trim_start().starts_with('#'))
                .map(|l| format!("{l}\n"))
                .collect();
            let step = step.as_str();
            if !step.contains("--exact") {
                continue;
            }
            let name = step.lines().next().unwrap_or_default();
            let target = step
                .split_once("--test ")
                .and_then(|(_, t)| t.split_whitespace().next())
                .unwrap_or_else(|| panic!("{job}/{name}: --exact with no --test target"));
            let tests = target_tests(target);
            let names = exact_names(step);
            assert!(!names.is_empty(), "{job}/{name}: no test named");
            for n in &names {
                assert!(
                    tests.contains(&(*n).to_owned()),
                    "{job}/{name} names {n}, which {target} has no test of"
                );
            }
            assert_ran_all(step, names.len(), &format!("{job}/{name}"));
            if name.contains("network outside") {
                assert_eq!(names, ["the_network_is_what_ci_says"], "{job}/{name}");
                assert_eq!(
                    yaml_env(step, 8)
                        .iter()
                        .find(|(k, _)| k == "ENVCLOAK_TEST_NETWORK")
                        .map(|(_, v)| v.as_str()),
                    Some("open"),
                    "{job}/{name}"
                );
                open_controls += 1;
            }
        }
    }
    // The gates job's, agents-e2e's and the release job's.
    assert_eq!(
        open_controls, 3,
        "not every agent job checks the open network"
    );
}

/// Gate 12 on the hosts' paths (Codex review, medium: no host job set
/// `RUST_LOG=trace` or `RUST_BACKTRACE=full`, and the jobs that did had
/// no host): the `gates` and `agents-e2e` jobs set both for every step.
/// And S0 runs on the release binaries (Codex review, medium: the release
/// job installed no host, so S0 skipped there): the release job installs
/// the pinned tier-1 hosts and runs `m2_story` on `target/release` with
/// the hosts required, at trace, loopback only, on both systems.
#[test]
fn ci_runs_the_hosts_at_trace_and_s0_on_the_release_binaries() {
    let ci = ci_file();
    let jobs = ci_jobs(&ci);
    let trace = [("RUST_LOG", "trace"), ("RUST_BACKTRACE", "full")];
    for job in ["gates", "agents-e2e"] {
        let env = yaml_env(ci_job(&jobs, job), 4);
        for (k, v) in trace {
            assert_eq!(
                env.iter().find(|(n, _)| n == k).map(|(_, x)| x.as_str()),
                Some(v),
                "the {job} job does not set {k}={v}"
            );
        }
    }
    let release = ci_job(&jobs, "release");
    assert!(!release.contains("continue-on-error"));
    let install = ci_steps(release, "Install and verify the pinned tier-1 hosts");
    assert_eq!(install.len(), 1, "the release job installs no host");
    assert!(install[0].contains("install-agent-hosts.py --tier 1"));
    let mut runs = 0;
    for (prefix, os, isolation) in [
        (
            "S0 on the release binaries, loopback only (Linux)",
            "Linux",
            "unshare --user --map-root-user --net --",
        ),
        (
            "S0 on the release binaries, sandboxed cases outside a user namespace",
            "Linux",
            "unshare --net --",
        ),
        (
            "S0 on the release binaries, loopback only (macOS)",
            "macOS",
            "os.setgroups([4242])",
        ),
    ] {
        let steps = ci_steps(release, prefix);
        assert_eq!(
            steps.len(),
            1,
            "the release job has no single step {prefix:?}"
        );
        let step = steps[0];
        let condition = yaml_value(step, 8, "if").unwrap_or_default();
        assert!(
            condition.contains(&format!("runner.os == '{os}'")) && !condition.contains("false"),
            "{prefix}: runs under {condition:?}"
        );
        assert!(
            step.contains("--test m2_story") && step.contains(isolation),
            "{prefix}"
        );
        let env = yaml_env(step, 8);
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        for (k, v) in trace.into_iter().chain([
            ("ENVCLOAK_TEST_REQUIRE_AGENT_HOSTS", "\"1\""),
            (
                "ENVCLOAK_E2E_BIN_DIR",
                "${{ github.workspace }}/target/release",
            ),
            (
                "ENVCLOAK_AGENT_HOSTS",
                "${{ github.workspace }}/../agent-hosts",
            ),
            ("ENVCLOAK_TEST_NETWORK", "loopback-only"),
        ]) {
            assert_eq!(get(k), Some(v), "{prefix}: {k}");
        }
        runs += 1;
    }
    assert_eq!(runs, 3);
}

fn ci_file() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/ci.yml");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn ci_job<'a>(jobs: &'a [(String, String)], job: &str) -> &'a str {
    jobs.iter()
        .find(|(name, _)| name == job)
        .map(|(_, b)| b.as_str())
        .unwrap_or_else(|| panic!("ci.yml has no {job} job"))
}

/// The steps of a job's text whose name starts with `prefix`, each from
/// its name on.
fn ci_steps<'a>(job: &'a str, prefix: &str) -> Vec<&'a str> {
    job.split("\n      - name: ")
        .skip(1)
        .filter(|s| s.starts_with(prefix))
        .collect()
}

/// The value of `key` at `indent` spaces in `text` (a job's or a step's
/// own line, not a nested one).
fn yaml_value<'a>(text: &'a str, indent: usize, key: &str) -> Option<&'a str> {
    let head = format!("{}{key}: ", " ".repeat(indent));
    text.lines().find_map(|l| l.strip_prefix(head.as_str()))
}

/// The variables of the `env:` block at `indent` spaces in `text`.
fn yaml_env(text: &str, indent: usize) -> Vec<(String, String)> {
    let head = format!("{}env:", " ".repeat(indent));
    let inner = " ".repeat(indent + 2);
    let mut out = Vec::new();
    let mut lines = text.lines().skip_while(|l| *l != head);
    if lines.next().is_none() {
        return out;
    }
    for l in lines {
        let Some(rest) = l.strip_prefix(inner.as_str()) else {
            break;
        };
        if rest.starts_with(' ') || rest.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = rest.split_once(": ") {
            out.push((k.to_owned(), v.trim().to_owned()));
        }
    }
    out
}

/// The test names a step gives `--exact`: the words after it that are
/// test names (letters, digits, `_` and `::`), to the end of the quoted
/// command or the first other word (`2>&1`, a pipe), line continuations
/// passed over.
fn exact_names(step: &str) -> Vec<&str> {
    let after = step
        .split_once("--exact")
        .map(|(_, a)| a)
        .unwrap_or_else(|| panic!("a step runs no exact test list"));
    let list = after.split('"').next().unwrap_or_default();
    list.split_whitespace()
        .filter(|w| *w != "\\")
        .take_while(|w| {
            w.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
        })
        .collect()
}

/// Every test of a test target, as `--exact` names it: `m2_story`'s
/// ([`story_tests`]) or `agent_hosts`'s.
fn target_tests(target: &str) -> Vec<String> {
    match target {
        "m2_story" => story_tests(),
        "agent_hosts" => {
            let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/agent_hosts.rs");
            test_fns(&std::fs::read_to_string(path).unwrap(), "")
        }
        other => panic!("ci.yml runs --exact tests of {other}, which no check here lists"),
    }
}

/// The `#[test]` functions of a source file's text, each as `<module><name>`.
fn test_fns(text: &str, module: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut lines = text.lines().map(str::trim);
    while let Some(l) = lines.next() {
        if l == "#[test]" {
            let name = lines
                .next()
                .and_then(|f| f.strip_prefix("fn "))
                .and_then(|f| f.split('(').next())
                .unwrap_or_else(|| panic!("a #[test] without a fn"));
            out.push(format!("{module}{name}"));
        }
    }
    out
}

/// Every test `m2_story` has, as `--exact` names it: its own and
/// `skeleton::`'s.
fn story_tests() -> Vec<String> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/m2_story");
    let mut out = Vec::new();
    for (file, module) in [("main.rs", ""), ("skeleton.rs", "skeleton::")] {
        out.extend(test_fns(
            &std::fs::read_to_string(dir.join(file)).unwrap(),
            module,
        ));
    }
    out
}

/// The step fails unless all `n` tests it names ran and passed: its
/// output goes through `tee` to a log, with `pipefail` set, and the log is
/// checked for the count (cargo's "running 1 test", "running 3 tests").
fn assert_ran_all(step: &str, n: usize, job: &str) {
    let log = step
        .split("| tee \"")
        .nth(1)
        .and_then(|r| r.split('"').next())
        .unwrap_or_else(|| panic!("{job}'s step keeps no log to check"));
    assert!(
        step.lines().any(|l| l.trim() == "set -o pipefail"),
        "{job}'s step does not fail with the tests it pipes"
    );
    let tests = if n == 1 { "test" } else { "tests" };
    for check in [
        format!("grep -qx 'running {n} {tests}' \"{log}\""),
        format!("grep -q '^test result: ok. {n} passed; 0 failed' \"{log}\""),
    ] {
        assert!(
            step.lines().any(|l| l.trim() == check),
            "{job}'s step does not check that its {n} tests ran: {check}"
        );
    }
}

/// The jobs of a workflow file, by name, each with its text.
fn ci_jobs(ci: &str) -> Vec<(String, String)> {
    let jobs = ci
        .split("\njobs:\n")
        .nth(1)
        .unwrap_or_else(|| panic!("ci.yml has no jobs"));
    let mut out: Vec<(String, String)> = Vec::new();
    for line in jobs.lines() {
        let top = line.len() > 2
            && line.starts_with("  ")
            && !line.starts_with("   ")
            && line.trim_end().ends_with(':')
            && !line.trim_start().starts_with('#');
        if top {
            out.push((line.trim().trim_end_matches(':').to_owned(), String::new()));
        } else if let Some((_, body)) = out.last_mut() {
            body.push_str(line);
            body.push('\n');
        }
    }
    out
}

/// K-01's table and docs/AGENTS.md agree: every refusal the table gives
/// is recorded there, and the K-01 section names both hosts `unsupported
/// (sandbox_blocks_socket)` on Linux.
#[test]
fn k01_s_table_is_what_the_docs_record() {
    k01::check_documented();
    for (shell, os, ns, want) in [
        (Shell::ClaudeUnsandboxed, "linux", true, Reach::Reaches),
        (
            Shell::ClaudeSandboxNoAllowance,
            "linux",
            true,
            Reach::NotRun(k01::SECCOMP_HELPER),
        ),
        (
            Shell::ClaudeSandboxNoAllowance,
            "linux",
            false,
            Reach::Refused(k01::RUNTIME_DIR),
        ),
        (
            Shell::ClaudeSandboxAllowResolved,
            "macos",
            false,
            Reach::Reaches,
        ),
        (
            Shell::CodexWorkspaceWriteBounded,
            "macos",
            false,
            Reach::Reaches,
        ),
        (
            Shell::CodexWorkspaceWrite,
            "linux",
            true,
            Reach::Refused(k01::RUNTIME_DIR),
        ),
    ] {
        assert_eq!(
            k01::expected(shell, os, ns),
            Some(want),
            "{shell:?} {os} {ns}"
        );
    }
    assert_eq!(
        k01::expected(Shell::ClaudeSandboxAllowResolved, "linux", false),
        None
    );
}

/// Claude Code with its sandbox off: qualified on both systems.
#[test]
fn s0_claude_code_runs_envcloak_and_the_person_approves() {
    s0(Host::ClaudeCode, Shell::ClaudeUnsandboxed, "Claude Code");
}

/// Claude Code with its sandbox on: macOS with the socket allowance M2-08
/// writes (qualified); Linux with none (K-01: refused).
#[test]
fn s0_claude_code_sandboxed() {
    let shell = if cfg!(target_os = "macos") {
        Shell::ClaudeSandboxAllowResolved
    } else {
        Shell::ClaudeSandboxNoAllowance
    };
    s0(Host::ClaudeCode, shell, "Claude Code, sandboxed");
}

/// Claude Code with its sandbox on and no socket allowance (a person who
/// switched the sandbox on without M2-08's allowance; on Linux the same
/// setting as [`s0_claude_code_sandboxed`]): refused on both systems, so
/// the refusal story runs on macOS too.
#[test]
fn s0_claude_code_sandboxed_without_an_allowance() {
    s0(
        Host::ClaudeCode,
        Shell::ClaudeSandboxNoAllowance,
        "Claude Code, sandboxed without an allowance",
    );
}

/// Codex `exec --sandbox workspace-write`: macOS with the bounded setting
/// M2-08 writes (qualified); Linux with none (K-01: refused).
#[test]
fn s0_codex_workspace_write() {
    let shell = if cfg!(target_os = "macos") {
        Shell::CodexWorkspaceWriteBounded
    } else {
        Shell::CodexWorkspaceWrite
    };
    s0(Host::Codex, shell, "Codex");
}
