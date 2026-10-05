//! Story steps S7 and S8 through EnvCloak's MCP server (M2 plan task
//! M2-06; gate 35, and gate 8 through `run_with_secrets`), on the M1
//! fixture repo `acme-web` imported by the person:
//!
//! - the official MCP TypeScript SDK client, pinned
//!   (crates/envcloak-e2e/mcp-client, installed by `install-agent-hosts.py
//!   --mcp-client`), is the independent client (L-02): started by
//!   `fixture-agent`, so the server is an agent's, it lists the tools and
//!   calls every one, the SDK checking each structured result against the
//!   tool's output schema; `run_with_secrets` of `./emit` first answers
//!   with the pending request, the person finds it with `envcloak pending`
//!   on a terminal of their own and approves it (a wrong passphrase
//!   first), and the call made again runs `./emit` in its full mode: every
//!   serializer's result whole and split at every byte with idle flushes,
//!   then each runtime's digest of each value, which must equal the
//!   fixture's (the oracle that does not depend on the redactor: run
//!   without `envcloak run`, the command has no value);
//! - Claude Code, pinned, driven by the scripted model with the server
//!   registered by its own CLI with the installer's per-server timeout,
//!   calls `list_secrets`, `project_status` and `request_new_secret` (S7)
//!   and `run_with_secrets` (S8), whose first answer comes within the
//!   host's cutoff, and after the person's approval the rerun's digests
//!   match.
//!
//! Every byte any process printed, every request body the scripted model
//! received, every answer (its structured output decoded too), the host's
//! stores and the home are swept for every canary in every encoding and
//! for what each serializer makes of each value.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use envcloak_agents::tool_timeouts;
use envcloak_e2e::{
    Emitters, Harness, NAMES, WRONG_PASSPHRASE, sha256_hex, text, token, versions_toml,
};
use envcloak_testkit::agents::{
    AgentHome, GroupChild, Host, HostFlags, Installed, mcp_client, require, require_mcp_client,
};
use envcloak_testkit::transcripts::Sweep;
use envcloak_testkit::{Canary, fresh_seed, labels, testkit_bin};
use serde_json::{Value, json};

use super::skeleton::{LIVE_APPROVAL, approve, last_tool_output, vault_and_import, write_repo};

/// The tools the server lists, in order.
const TOOLS: [&str; 5] = [
    "list_secrets",
    "project_status",
    "add_reference",
    "run_with_secrets",
    "request_new_secret",
];

/// The slugs `init --import` gives the fixture repo's keys.
const SLUGS: [&str; 4] = [
    "database-url/acme-web",
    "github/acme-web",
    "openai/acme-web",
    "stripe/acme-web",
];

/// The fixture repo, its values and what each serializer makes of them,
/// imported by the person; the plaintext is gone.
struct Story {
    h: Harness,
    repo: PathBuf,
    emitters: Emitters,
    values: BTreeMap<&'static str, Vec<u8>>,
}

fn story() -> Story {
    let mut h = Harness::start();
    let emitters = story_emitters();
    let repo = write_repo(&mut h, &emitters);
    let values: BTreeMap<&str, Vec<u8>> = NAMES.iter().map(|n| (*n, h.value(n).to_vec())).collect();
    let pairs: Vec<(&str, &[u8])> = values.iter().map(|(n, v)| (*n, v.as_slice())).collect();
    for (label, bytes) in emitters.oracle(&repo.join("emit.json"), &pairs) {
        h.add_needle(format!("{label} of a fixture"), bytes);
    }
    vault_and_import(&mut h, &repo);
    Story {
        h,
        repo,
        emitters,
        values,
    }
}

/// The serializers `./emit` runs through `run_with_secrets`. Where
/// `ENVCLOAK_TEST_REQUIRE_EMITTERS` asks for them (the release job, both
/// systems), every gate-8 runtime: Python, Node, Go, .NET, PHP and
/// serde_json, each required, the Go and .NET emitters taken from the
/// build the fixture story made in the same target directory, earlier in
/// that job with the network open (verifier, M2-06 round 2: gate 8 through
/// the tool covered two serializers only). Elsewhere (the pull-request
/// `gates` job and `agents-e2e`, which have the runner's own runtimes or
/// none, and loopback only) Python's serializers and serde_json, which
/// need nothing found or built.
fn story_emitters() -> Emitters {
    let serde = Path::new(env!("CARGO_BIN_EXE_ec-emit-serde"));
    let all = std::env::var("ENVCLOAK_TEST_REQUIRE_EMITTERS").is_ok_and(|v| !v.is_empty());
    if all {
        let build = Path::new(env!("CARGO_TARGET_TMPDIR")).join("e2e-emitters");
        let emitters = Emitters::prepare(&build, serde);
        eprintln!(
            "S7 and S8 serializers: {}; not installed here: {}",
            emitters.tags().join(", "),
            emitters.missing.join(", ")
        );
        emitters
    } else {
        Emitters::python_and_serde(serde)
    }
}

/// The request ids `envcloak pending --json` lists to the person.
fn pending(h: &mut Harness, repo: &Path) -> Vec<String> {
    let out = h.human(repo, &["pending", "--json"], &[], &[]);
    assert_eq!(out.code, 0, "{}", out.all());
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    v["requests"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["request"].as_str().unwrap().to_owned())
        .collect()
}

/// The person approves `id`: a wrong passphrase first, refused and
/// granting nothing, then the right one.
fn approve_after_a_wrong_passphrase(h: &mut Harness, repo: &Path, id: &str) {
    let typed = format!("{}\r", h.canary(WRONG_PASSPHRASE).as_str());
    let wrong = h.human(
        repo,
        &LIVE_APPROVAL.map(|a| if a == "ID" { id } else { a }),
        &[],
        &[("Vault passphrase to approve this: ", &typed)],
    );
    assert_eq!(wrong.code, 1, "{}", wrong.all());
    assert_eq!(token(&wrong.stderr), "wrong_passphrase", "{}", wrong.all());
    let right = approve(h, repo, id);
    assert_eq!(right.code, 0, "{}", right.all());
    assert!(
        right.shown().contains("requested by: agent "),
        "{}",
        right.all()
    );
}

/// `sha256 <runtime> <NAME> <hex>` lines.
fn digests(stdout: &str) -> BTreeMap<(String, String), String> {
    stdout
        .lines()
        .filter_map(|l| {
            let mut w = l.split(' ');
            (w.next() == Some("sha256")).then_some(())?;
            let (tag, name, hex) = (w.next()?, w.next()?, w.next()?);
            Some(((tag.to_owned(), name.to_owned()), hex.to_owned()))
        })
        .collect()
}

/// Every runtime's digest of every value in `stdout` equals the
/// fixture's: the command got each value.
fn check_digests(stdout: &str, emitters: &Emitters, values: &BTreeMap<&str, Vec<u8>>) {
    let got = digests(stdout);
    for tag in emitters.tags() {
        for name in NAMES {
            assert_eq!(
                got.get(&(tag.clone(), name.to_owned())),
                Some(&sha256_hex(&values[name])),
                "the {tag} digest of {name}"
            );
        }
    }
}

/// What a `run_with_secrets` result printed, decoded, kept for the sweep.
fn keep_output(h: &mut Harness, what: &str, s: &Value) {
    for stream in ["stdout", "stderr", "message"] {
        if let Some(t) = s[stream].as_str() {
            h.record(&format!("{what} ({stream}, decoded)"), t.as_bytes());
        }
    }
}

/// The official SDK client drives every tool (S7, S8, gate 35); see the
/// module documentation.
///
/// Mutations checked: `run_with_secrets` running argv directly, not
/// through `envcloak run`: the command has no values and the digest check
/// fails. A `reveal` tool added to the M2 tools: the tools check fails.
#[test]
fn s7_s8_the_sdk_client_drives_every_tool() {
    let Some(client) = require_mcp_client(mcp_client(&versions_toml()), "S7 and S8 (SDK client)")
    else {
        return;
    };
    let Story {
        mut h,
        repo,
        emitters,
        values,
    } = story();
    let dir = repo.to_str().unwrap().to_owned();
    let key = h.canary(labels::STRIPE_SECRET_KEY).as_str().to_owned();
    let token = h.canary(labels::GITHUB_TOKEN).as_str().to_owned();
    let env: serde_json::Map<String, Value> = h
        .home
        .vars()
        .into_iter()
        .map(|(k, v)| (k.to_owned(), json!(v.to_str().unwrap())))
        .collect();
    let call = |name: &str, args: Value| json!({"call": name, "arguments": args});
    let plan = json!({
        "command": h.cli().to_str().unwrap(),
        "args": ["mcp", "--wait-ms", "3000"],
        "env": env,
        "cwd": dir,
        "steps": [
            {"list": true},
            call("list_secrets", json!({"project_dir": dir})),
            call("project_status", json!({"project_dir": dir})),
            call("request_new_secret", json!({"provider": "stripe"})),
            call("run_with_secrets", json!({"project_dir": dir, "argv": ["./emit"]})),
            {"barrier": "approved"},
            call("run_with_secrets", json!({"project_dir": dir, "argv": ["./emit"]})),
            call("project_status", json!({"project_dir": dir})),
            call("add_reference", json!({"project_dir": dir, "env_name": "GITHUB_TOKEN_CI",
                                          "slug": "github/acme-web"})),
            call("reveal", json!({"slug": "openai/acme-web"})),
            call("doctor", json!({})),
            call("list_secrets", json!({"project_dir": dir, "value": key})),
            call("run_with_secrets", json!({"project_dir": dir, "argv": ["curl", "-H", token]})),
        ],
    });
    let plan_path = h.files().join("sdk-plan.json");
    std::fs::write(&plan_path, plan.to_string()).unwrap();
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("mcp-client/client.mjs");

    // The agent starts the client, which starts the server.
    let mut cmd = Command::new(testkit_bin("fixture-agent"));
    h.home
        .apply(&mut cmd)
        .arg("--")
        .arg(&client.node)
        .arg(&script)
        .arg(&client.node_modules)
        .arg(&plan_path)
        .current_dir(&repo)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // The agent leads a group of its own, with the client and the server
    // in it: a failure anywhere below (a panic at the barrier, say) kills
    // the group when `child` drops, while the agent is unreaped (L-03).
    let mut child = GroupChild::spawn(&mut cmd).unwrap();
    let mut stdin = child.take_stdin().unwrap();
    let stdout = BufReader::new(child.take_stdout().unwrap());
    let mut stderr = child.take_stderr().unwrap();
    let (tx, lines) = mpsc::channel();
    std::thread::spawn(move || {
        for line in stdout.split(b'\n').map_while(Result::ok) {
            if tx.send(line).is_err() {
                return;
            }
        }
    });
    let err = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = stderr.read_to_end(&mut v);
        v
    });

    let mut steps: BTreeMap<usize, Value> = BTreeMap::new();
    let mut initialized = Value::Null;
    let end = Instant::now() + Duration::from_secs(900);
    loop {
        let left = end.saturating_duration_since(Instant::now());
        let Ok(line) = lines.recv_timeout(left) else {
            break;
        };
        h.record("the SDK client's output", &line);
        let v: Value = serde_json::from_slice(&line).unwrap();
        if let Some(i) = v["step"].as_u64() {
            if let Some(s) = v["result"].get("structuredContent") {
                keep_output(&mut h, "an answer through the SDK client", s);
            }
            steps.insert(usize::try_from(i).unwrap(), v);
        } else if v.get("initialized").is_some() {
            initialized = v["initialized"].clone();
        } else if v["barrier"] == "approved" {
            // The person reads the id from `envcloak pending`, never from
            // the agent's output, and it is the one the tool named.
            let ids = pending(&mut h, &repo);
            let named = steps[&4]["result"]["structuredContent"]["request"].clone();
            assert_eq!(ids.len(), 1, "{ids:?}");
            assert_eq!(json!(ids[0]), named);
            approve_after_a_wrong_passphrase(&mut h, &repo, &ids[0]);
            stdin.write_all(b"go\n").unwrap();
            stdin.flush().unwrap();
        }
    }
    drop(stdin);
    let status = child
        .end_within(Duration::from_secs(120))
        .expect("the SDK client did not exit after its plan");
    let err = err.join().unwrap();
    h.record("the SDK client's stderr (the server's own)", &err);
    assert!(status.success(), "{}", String::from_utf8_lossy(&err));

    // The session, as the SDK sees it.
    assert_eq!(initialized["serverVersion"]["name"], "envcloak");
    assert_eq!(
        initialized["capabilities"],
        json!({"tools": {"listChanged": false}})
    );
    let s = |i: usize| -> &Value {
        let v = &steps[&i];
        assert!(v.get("error").is_none(), "step {i}: {v}");
        &v["result"]
    };
    // tools/list: the five tools; no reveal, doctor or usage_summary.
    let tools = s(0)["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names, TOOLS);
    for t in tools {
        let a = &t["annotations"];
        assert!(
            !(a["readOnlyHint"] == true && a["destructiveHint"] == true),
            "{t}"
        );
    }
    // S7: metadata only.
    let list = &s(1)["structuredContent"];
    let slugs: Vec<&str> = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["slug"].as_str().unwrap())
        .collect();
    assert_eq!(slugs, SLUGS);
    let bindings = list["project"]["bindings"].as_array().unwrap();
    assert_eq!(bindings.len(), 4, "{list}");
    assert!(bindings.iter().all(|b| b["status"] == "ok"), "{list}");
    let status = &s(2)["structuredContent"];
    assert_eq!(status["bindings_resolved"], 4, "{status}");
    assert_eq!(status["plaintext_env_lines"], 0, "{status}");
    assert_eq!(status["vault"], "unlocked");
    assert_eq!(status["coverage"], Value::Null);
    assert!(
        status["unavailable"]
            .as_array()
            .unwrap()
            .iter()
            .any(|u| u["feature"] == "usage_summary" && u["milestone"] == "M4"),
        "{status}"
    );
    let new = &s(3)["structuredContent"];
    assert_eq!(new["command"], "envcloak add stripe");
    // S8: pending first, with the person's instruction; then the run.
    let first = &s(4)["structuredContent"];
    assert_eq!(first["status"], "approval_required", "{first}");
    let message = first["message"].as_str().unwrap();
    for part in [
        "`envcloak pending`",
        "terminal of their own",
        "outside this host's sandbox",
    ] {
        assert!(message.contains(part), "{part}: {message}");
    }
    let ran = &s(6)["structuredContent"];
    assert_eq!(ran["status"], "completed", "{ran}");
    assert_eq!(ran["exit_code"], 0, "{ran}");
    let out = ran["stdout"].as_str().unwrap();
    check_digests(out, &emitters, &values);
    let err_text = ran["stderr"].as_str().unwrap();
    assert!(
        err_text.contains("DONE\n") || ran["stderr_left_out"].as_u64() > Some(0),
        "{err_text}"
    );
    for slug in ["openai/acme-web", "stripe/acme-web", "github/acme-web"] {
        assert!(
            format!("{out}{err_text}").contains(&format!("[envcloak:{slug}]")),
            "{slug}"
        );
    }
    let after = &s(7)["structuredContent"];
    assert_eq!(after["pending_requests"], json!([]), "{after}");
    assert_eq!(after["grants"].as_array().unwrap().len(), 1, "{after}");
    assert_eq!(s(8)["structuredContent"]["change"], "added");
    // No reveal or doctor tool; hostile arguments refused unechoed.
    for i in [9, 10] {
        assert_eq!(steps[&i]["error"]["code"], -32602, "{}", steps[&i]);
    }
    for (i, want) in [(11, "invalid_params"), (12, "value_on_argv")] {
        let r = s(i);
        assert_eq!(r["isError"], true, "{r}");
        let t: Value = serde_json::from_str(r["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(t["error"], want, "{t}");
    }
    h.assert_swept("S7 and S8 (SDK client)");
}

/// S7 and S8 with Claude Code on the scripted model; see the module
/// documentation.
///
/// Mutation checked: the claude-code default wait at the host's cutoff
/// plus 2 s: the first answer comes after the cutoff and the host gives
/// up on the call, so the pending request is not in what it sends its
/// model.
#[test]
fn s7_s8_claude_code_calls_the_tools_and_the_person_approves() {
    let found = Installed::find(&versions_toml(), Host::ClaudeCode.id(), "native");
    let Some(installed) = require(found, "S7 and S8 (Claude Code)") else {
        return;
    };
    let Story {
        mut h,
        repo,
        emitters,
        values,
    } = story();
    let dir = repo.to_str().unwrap().to_owned();
    let agent = AgentHome::within(&h.home, Host::ClaudeCode, installed);
    // Registered with Claude Code's own CLI, as the installer will
    // (M2-08), with the per-server timeout it writes.
    let host = tool_timeouts::host("claude-code").unwrap();
    let timeout_ms = u64::try_from(host.tool_timeout.as_millis()).unwrap();
    let entry = json!({"command": h.cli().to_str().unwrap(),
                       "args": ["mcp", "--host", "claude-code"],
                       "timeout": timeout_ms});
    let added = agent.host_cli(&[
        "mcp",
        "add-json",
        "--scope",
        "user",
        "envcloak",
        &entry.to_string(),
    ]);
    assert!(added.status.success(), "{}", text(&added));
    let control = Canary::new(
        "POSITIVE_CONTROL",
        format!("ecctl-{:016x}{:016x}", fresh_seed(), fresh_seed()),
    );
    let mut models = Vec::new();

    // S7: the metadata tools. A call made before the host has connected
    // the server gets the host's error instead (M2-04's measurement): the
    // run is tried up to three times.
    let s7 = json!({"steps": [
        {"tool": "mcp__envcloak__list_secrets", "input": {"project_dir": dir}},
        {"tool": "mcp__envcloak__project_status", "input": {"project_dir": dir}},
        {"tool": "mcp__envcloak__request_new_secret", "input": {"provider": "stripe"}},
        {"say": control.as_str()},
    ]});
    let flags = HostFlags::claude(
        "default",
        &[
            "mcp__envcloak__list_secrets",
            "mcp__envcloak__project_status",
            "mcp__envcloak__request_new_secret",
        ],
    );
    let mut tries = 0;
    let run = loop {
        tries += 1;
        let run = agent.run(&s7, "What keys does this project have?", &flags, &repo);
        h.record("the host's stdout (S7)", &run.output.stdout);
        h.record("the host's stderr (S7)", &run.output.stderr);
        for r in &run.model.requests {
            h.record(
                &format!("the host's request {} to its model (S7)", r.seq),
                &r.body,
            );
        }
        assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
        let answer = after_step(&run.model.requests, "step 1");
        if serde_json::from_str::<Value>(&answer).is_ok_and(|v| v.get("items").is_some()) {
            break run;
        }
        assert!(
            tries < 3,
            "the server never answered list_secrets: {answer}"
        );
    };
    // What the host offered its model: EnvCloak's five tools, by its own
    // naming, and no reveal, doctor or usage tool.
    let first = run
        .model
        .model_calls()
        .first()
        .map(|r| serde_json::from_slice::<Value>(&r.body).unwrap())
        .unwrap();
    let offered: Vec<String> = first["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["name"].as_str())
        .filter(|n| n.starts_with("mcp__envcloak__"))
        .map(str::to_owned)
        .collect();
    let want: Vec<String> = TOOLS
        .iter()
        .map(|t| format!("mcp__envcloak__{t}"))
        .collect();
    let mut sorted = offered.clone();
    sorted.sort();
    let mut want_sorted = want.clone();
    want_sorted.sort();
    assert_eq!(sorted, want_sorted, "{offered:?}");
    let list: Value = serde_json::from_str(&after_step(&run.model.requests, "step 1")).unwrap();
    let slugs: Vec<&str> = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["slug"].as_str().unwrap())
        .collect();
    assert_eq!(slugs, SLUGS);
    let status: Value = serde_json::from_str(&after_step(&run.model.requests, "step 2")).unwrap();
    assert_eq!(status["bindings_resolved"], 4, "{status}");
    let new: Value = serde_json::from_str(&after_step(&run.model.requests, "step 3")).unwrap();
    assert_eq!(new["command"], "envcloak add stripe", "{new}");
    models.push(run.model);

    // S8: the person allows run_with_secrets for this step. The first
    // call answers with the pending request within the host's cutoff; the
    // person approves from a terminal of their own; the model's next turn,
    // held until then, calls again.
    let call = json!({"project_dir": dir, "argv": ["./emit", "--quick"]});
    let s8 = json!({"steps": [
        {"tool": "mcp__envcloak__list_secrets", "input": {}},
        {"tool": "mcp__envcloak__run_with_secrets", "input": call},
        {"tool": "mcp__envcloak__run_with_secrets", "input": call, "after": "approved"},
        {"say": "done"},
    ]});
    let flags = HostFlags::claude(
        "default",
        &[
            "mcp__envcloak__list_secrets",
            "mcp__envcloak__run_with_secrets",
        ],
    );
    let mut running = agent.spawn(&s8, "Run ./emit with the project's keys.", &flags, &repo);
    let held = running.model.wait_for("step 2", &mut running.child);
    h.record(
        "the host's request to its model (S8, first run)",
        &held.body,
    );
    let first: Value =
        serde_json::from_str(&last_tool_output(&String::from_utf8_lossy(&held.body)))
            .unwrap_or_else(|_| panic!("the first run's answer is not EnvCloak's"));
    assert_eq!(first["status"], "approval_required", "{first}");
    let message = first["message"].as_str().unwrap();
    for part in [
        "`envcloak pending`",
        "terminal of their own",
        "outside this host's sandbox",
    ] {
        assert!(message.contains(part), "{part}: {message}");
    }
    let ids = pending(&mut h, &repo);
    assert_eq!(ids.len(), 1, "{ids:?}");
    assert_eq!(json!(ids[0]), first["request"]);
    approve_after_a_wrong_passphrase(&mut h, &repo, &ids[0]);
    running.model.release("approved");
    let run = running.wait();
    h.record("the host's stdout (S8)", &run.output.stdout);
    h.record("the host's stderr (S8)", &run.output.stderr);
    for r in &run.model.requests {
        h.record(
            &format!("the host's request {} to its model (S8)", r.seq),
            &r.body,
        );
    }
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    // The first answer came before the host's cutoff, after the wait.
    let at = |pick: &str| {
        run.model
            .requests
            .iter()
            .find(|r| r.pick.as_deref() == Some(pick))
            .map(|r| r.at_ms)
            .unwrap()
    };
    let took = Duration::from_millis(at("step 2").saturating_sub(at("step 1")));
    let wait = tool_timeouts::person_wait(tool_timeouts::default_wait(Some("claude-code")));
    assert!(
        took >= wait && took < host.tool_timeout,
        "the pending answer came after {took:?} (waiting {wait:?} for the person, cutoff {:?})",
        host.tool_timeout
    );
    println!(
        "measurement: S8 run_with_secrets under Claude Code {}: pending answer after {:.1} s, \
         cutoff {} s",
        agent.installed.pin.version,
        took.as_secs_f64(),
        host.tool_timeout.as_secs()
    );
    let ran: Value = serde_json::from_str(&after_step(&run.model.requests, "step 3"))
        .unwrap_or_else(|_| panic!("the rerun's answer is not EnvCloak's"));
    keep_output(&mut h, "the rerun's answer (S8)", &ran);
    assert_eq!(ran["status"], "completed", "{ran}");
    assert_eq!(ran["exit_code"], 0, "{ran}");
    check_digests(ran["stdout"].as_str().unwrap(), &emitters, &values);
    models.push(run.model);
    agent.check_pinned();
    agent.check_isolated();

    // The sweep: every capture, every daemon log, the home, and the host's
    // stores, with the positive control the model said in S7.
    h.assert_swept("S7 and S8 (Claude Code)");
    let mut cs = h.canaries.clone();
    cs.push(control);
    let refs: Vec<&_> = models.iter().collect();
    let hits = Sweep::host_stores(&agent, &cs, &refs);
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

/// The last tool result in the request the script answered with `pick`:
/// what the call before it returned, as the host sent it to its model.
fn after_step(requests: &[envcloak_testkit::agents::ModelRequest], pick: &str) -> String {
    requests
        .iter()
        .find(|r| r.pick.as_deref() == Some(pick))
        .map(|r| last_tool_output(&String::from_utf8_lossy(&r.body)))
        .unwrap_or_else(|| panic!("no request for {pick}"))
}
