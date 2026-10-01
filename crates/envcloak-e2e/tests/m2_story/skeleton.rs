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
//! `unix_sockets` allow rule for EnvCloak's socket. Codex honours that rule
//! on macOS only; on Linux its sandbox refuses the socket (K-01, measured
//! by `agent_hosts`), so there S0 checks the other half of K-01: the CLI
//! fails closed in the sandbox, twice, the daemon sees no request, and the
//! sweep is as clean, with the positive control found.

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
    // Gate 8's serializers are the M1 story's; S0 needs output that holds
    // the values, and Python's and serde's are enough.
    let emitters = Emitters::python_and_serde(Path::new(env!("CARGO_BIN_EXE_ec-emit-serde")));
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
    // Named in two pieces: whole, it can only be what the command printed.
    let (head, tail) = control.as_str().split_at(control.as_str().len() / 2);
    let print_control = format!("printf '%s%s\\n' {} {}", quoted(head), quoted(tail));
    let script = json!({"steps": [
        {"say": "I'll run emit through EnvCloak.", "shell": run_emit},
        {"say": "Approved; running it again.", "shell": run_emit, "after": "approved"},
        {"shell": print_control},
        {"say": "done"},
    ]});
    let requests_before = audit_requests(&h);
    let mut running = agent.spawn(&script, "Run ./emit through envcloak.", &flags, &repo);

    // The host sent the first run's output to its model: approval needed,
    // nothing released.
    let held = running.model.wait_for("step 1", &mut running.child);
    h.record(
        "the host's request to its model (S0, first run)",
        &held.body,
    );
    let first = String::from_utf8_lossy(&held.body).into_owned();
    // Swept clean just above, so its end can be shown.
    let tail = first
        .char_indices()
        .rev()
        .nth(3000)
        .map_or(first.as_str(), |(at, _)| &first[at..]);
    // What the first run printed: the last tool result in the request
    // (the one for the call the model made last).
    let first_run = last_tool_output(&first);
    let held_for_approval = first_run.contains("approval_required");
    let refused = !held_for_approval && sandbox_refuses_the_socket(host);
    assert!(
        held_for_approval || refused,
        "the first run was not held for approval; the request ends:\n{tail}"
    );
    if held_for_approval {
        assert_eq!(
            exits(&first_run),
            ["125"],
            "the first run did not exit 125; the request ends:\n{tail}"
        );
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
        // What the daemon recorded for the request: the subject, and the
        // process its grant is rooted at, by its executable.
        let root = rooted_at(&approved.shown(), &agent.installed);
        println!(
            "measurement: S0 subject host={} os={}: requested by: agent {agent_name}, \
             rooted at {root}",
            host.id(),
            std::env::consts::OS
        );
    } else {
        // K-01 on this system: the CLI cannot open the socket from the
        // host's sandbox, so it fails closed before it sends a byte, and
        // the daemon never sees a request.
        let refusal = refused_once(&first_run)
            .unwrap_or_else(|why| panic!("the first run: {why}; the request ends:\n{tail}"));
        println!(
            "measurement: S0 host={} os={}: unsupported under its sandbox with the bounded \
             setting (K-01): {refusal}",
            host.id(),
            std::env::consts::OS
        );
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
    // say nothing about the rerun.
    let second = run
        .model
        .requests
        .iter()
        .find(|r| r.pick.as_deref() == Some("step 2"))
        .map(|r| last_tool_output(&String::from_utf8_lossy(&r.body)))
        .unwrap();
    if held_for_approval {
        // The rerun got its values: exit 0, and redaction markers where
        // the values were.
        assert_eq!(exits(&second), ["0"], "the rerun did not exit 0");
        assert!(
            second.contains("[envcloak:openai/acme-web]"),
            "no redaction marker in the rerun's output"
        );
    } else {
        // Refused again, by the CLI, before it sent a byte: one refusal
        // line and exit 125 in the rerun's own result; and nothing
        // reached the daemon.
        if let Err(why) = refused_once(&second) {
            panic!("the rerun was not refused: {why}");
        }
        assert_eq!(
            audit_requests(&h),
            requests_before,
            "the daemon saw a request from the sandbox"
        );
    }

    // The control is in the tool result the host sent its model.
    let third = run
        .model
        .requests
        .iter()
        .find(|r| r.pick.as_deref() == Some("step 3"))
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .unwrap();
    assert!(
        last_tool_output(&third).contains(control.as_str()),
        "the printed control is not in the tool result the host sent its model"
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
    candidate_density(&agent);
}

/// The executable the approval statement's `rooted at` names, as the
/// host's entry (`<the host's entry>`, the pinned file itself) or by its
/// file name; pids and start times left out.
fn rooted_at(statement: &str, installed: &Installed) -> String {
    let Some(line) = statement.lines().find(|l| l.contains("requested by:")) else {
        return "?".to_owned();
    };
    let Some(exe) = line.rsplit_once(", ").map(|(_, e)| e.trim()) else {
        return "?".to_owned();
    };
    let canonical = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let mut pinned = vec![canonical(&installed.exe)];
    if let Some((starts, _)) = &installed.pin.starts {
        pinned.push(canonical(&installed.dir.join(starts)));
    }
    if pinned.contains(&canonical(Path::new(exe))) {
        "<the host's entry>".to_owned()
    } else {
        Path::new(exe)
            .file_name()
            .map_or("?".to_owned(), |n| n.to_string_lossy().into_owned())
    }
}

/// Whether `host`'s sandbox, with the settings §4 pins, is measured to
/// refuse the daemon's socket on this system (K-01), so that S0 checks the
/// refusal instead of the approval. Codex 0.159.2 honours `unix_sockets`
/// rules on macOS only (`unix_socket_permissions_supported` in its
/// `network-proxy/src/runtime.rs` is `cfg!(target_os = "macos")`); on
/// Linux its network seccomp filter in proxy-routed mode refuses every
/// Unix socket unless all are allowed (`linux-sandbox/src/landlock.rs`),
/// which K-01 rules out. `agent_hosts` measures both systems.
fn sandbox_refuses_the_socket(host: Host) -> bool {
    host == Host::Codex && cfg!(target_os = "linux")
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

/// The CLI's refusal in one command's output (K-01's fail-closed half):
/// exactly one `envcloak: daemon_unverified: ...` or `envcloak:
/// daemon_unavailable: ...` line and `EXIT=125`, the exit of `run`'s own
/// failures. The refusal line, or why the output is not that.
fn refused_once(output: &str) -> Result<String, String> {
    let lines: Vec<&str> = output
        .lines()
        .map(str::trim)
        .filter(|l| {
            l.starts_with("envcloak: daemon_unverified: ")
                || l.starts_with("envcloak: daemon_unavailable: ")
        })
        .collect();
    let codes = exits(output);
    match (lines.as_slice(), codes.as_slice()) {
        ([line], ["125"]) => Ok((*line).to_owned()),
        (lines, codes) => Err(format!(
            "{} refusal line(s), exit codes {codes:?}",
            lines.len()
        )),
    }
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

#[test]
fn s0_claude_code_runs_envcloak_and_the_person_approves() {
    s0(Host::ClaudeCode, "Claude Code");
}

#[test]
fn s0_codex_runs_envcloak_and_the_person_approves() {
    s0(Host::Codex, "Codex");
}
