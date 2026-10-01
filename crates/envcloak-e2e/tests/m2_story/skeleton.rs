//! Story step S0 (M2 plan task M2-04): the walking skeleton. A pinned host
//! (Claude Code, Codex), driven by the scripted model with its flags
//! pinned (§4 setup), runs `envcloak run -- ./emit --quick` in the M1
//! fixture repo `acme-web` through its own shell tool. The daemon answers
//! `approval_required`; the person approves from a terminal of their own,
//! with the statement naming the host; the model's next turn, held until
//! then by a barrier, reruns the command, which now gets its values; and
//! nothing the host printed, stored or sent its model holds a value or
//! any encoding of one, while the host's transcript holds a positive
//! control the same session printed.
//!
//! Codex runs in its `workspace-write` sandbox with the settings §4 says
//! the person makes (M2-08's installer will write them): command
//! networking on, the network proxy on with no domain rule, and one
//! `unix_sockets` allow rule for EnvCloak's socket.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use envcloak_e2e::{Emitters, Harness, Human, NAMES, age, quoted, versions_toml, write_script};
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

fn s0(host: Host, name: &str) {
    let found = Installed::find(&versions_toml(), host.id(), "native");
    let Some(installed) = require(found, &format!("S0 ({name})")) else {
        return;
    };
    let mut h = Harness::start();
    let emitters = Emitters::prepare(
        &Path::new(env!("CARGO_TARGET_TMPDIR")).join("e2e-emitters"),
        Path::new(env!("CARGO_BIN_EXE_ec-emit-serde")),
    );
    let repo = write_repo(&mut h, &emitters);
    // What every serializer makes of each value, made outside EnvCloak,
    // looked for as it is.
    let values: BTreeMap<&str, Vec<u8>> = NAMES.iter().map(|n| (*n, h.value(n).to_vec())).collect();
    let pairs: Vec<(&str, &[u8])> = values.iter().map(|(n, v)| (*n, v.as_slice())).collect();
    for (label, bytes) in emitters.oracle(&repo.join("emit.json"), &pairs) {
        h.add_needle(format!("{label} of a fixture"), bytes);
    }
    vault_and_import(&mut h, &repo);

    let mut agent = AgentHome::within(&h.home, host, installed);
    let flags = match host {
        Host::ClaudeCode => {
            // Claude Code cuts a command's output past 30,000 characters
            // by default; the whole of it is what is swept.
            agent.set_env("BASH_MAX_OUTPUT_LENGTH", "500000");
            HostFlags::claude("default", &["Bash"])
        }
        Host::Codex => {
            let socket = daemon_socket(&h.home);
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
    };
    // The positive control: a canary this session prints, which the
    // host's transcript must hold, so a clean sweep below means something.
    let control = Canary::new(
        "POSITIVE_CONTROL",
        format!("ecctl-{:016x}{:016x}", fresh_seed(), fresh_seed()),
    );
    let run_emit = format!(
        "{} run -- ./emit --quick; echo \"EXIT=$?\"",
        quoted(h.cli().to_str().unwrap())
    );
    let script = json!({"steps": [
        {"say": "I'll run emit through EnvCloak.", "shell": run_emit},
        {"say": "Approved; running it again.", "shell": run_emit, "after": "approved"},
        {"shell": format!("echo {}", control.as_str())},
        {"say": "done"},
    ]});
    let mut running = agent.spawn(&script, "Run ./emit through envcloak.", &flags, &repo);

    // The host sent the first run's output to its model: approval needed,
    // nothing released.
    let held = running.model.wait_for("step 1", &mut running.child);
    h.record(
        "the host's request to its model (S0, first run)",
        &held.body,
    );
    let first = String::from_utf8_lossy(&held.body).into_owned();
    assert!(
        first.contains("approval_required"),
        "the first run was not held for approval"
    );
    assert!(first.contains("EXIT=125"), "the first run did not exit 125");
    let id = request_id(&first);

    // The person approves from a terminal of their own; the statement
    // names the host.
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
    println!(
        "measurement: S0 subject host={} os={}: requested by: agent {agent_name}",
        host.id(),
        std::env::consts::OS
    );
    running.model.release("approved");
    let run = running.wait();
    agent.check_pinned();
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

    // The rerun got its values: exit 0, and redaction markers where the
    // values were.
    let second = run
        .model
        .requests
        .iter()
        .find(|r| r.pick.as_deref() == Some("step 2"))
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .unwrap();
    assert!(second.contains("EXIT=0"), "the rerun did not exit 0");
    assert!(
        second.contains("[envcloak:openai/acme-web]"),
        "no redaction marker in the rerun's output"
    );

    // The sweep: every capture, every daemon log, the whole home, raw.
    h.assert_swept("S0");
    let mut cs = h.canaries.clone();
    cs.push(control.clone());
    let hits = Sweep::host_stores(&agent, &cs, &[&run.model]);
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
}

#[test]
fn s0_claude_code_runs_envcloak_and_the_person_approves() {
    s0(Host::ClaudeCode, "Claude Code");
}

#[test]
fn s0_codex_runs_envcloak_and_the_person_approves() {
    s0(Host::Codex, "Codex");
}
