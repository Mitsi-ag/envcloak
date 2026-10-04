//! Gate 38's CI half (M2 plan task M2-09): the coverage probes
//! (`envcloak_agents::probe`) against the pinned Claude Code and Codex in
//! an isolated home with EnvCloak installed by `envcloak agents install`,
//! what `envcloak agents status --json` then reports from their results,
//! and the probes' own controls.
//!
//! - Each pinned host is probed on every surface and for EnvCloak's server;
//!   each surface's outcome is the one integrations/compat/matrix.toml
//!   publishes for this host version and system, and `agents status`
//!   reports, from the cached results and the home's real configuration,
//!   exactly the matrix's states and tokens, which are what the probes
//!   observed (the test fails if a claim differs from the observation),
//!   with `outside_host_sandbox` and the sentinel's evidence on EnvCloak's
//!   server line in both the human and the `--json` report.
//! - Each hook surface's probe fails when EnvCloak's hook for it is taken
//!   out of the installed configuration; Claude Code's `@.env` case fails
//!   when the `Read(**/.env*)` deny rule is; Codex's hooks, left untrusted
//!   (no trust bypass), fail every hook probe and read `degraded
//!   (fails_open_on_timeout, hooks_untrusted; probe=failed)`.
//! - A hook that outlives the host's timeout lets the prompt it would block
//!   through, on both hosts: `fails_open_on_timeout` is what the pinned
//!   hosts do.
//! - A stand-in host (`ec-fake-host`) failing each control or each probe
//!   gives the outcome, state and reasons it must, and one pointed at a
//!   dead base URL fails every probe through its control.
#![allow(clippy::unwrap_used)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use envcloak_agents::coverage::{
    self, Cache, ConfigSet, HookState, Hooks, Outcome, Probed, Reason, Sentinel, ServerFacts,
    State, Surface,
};
use envcloak_agents::hook::Host as Agent;
use envcloak_agents::locations::Locations;
use envcloak_agents::probe::{
    self, Approver, HostFlags, OutputFixture, ProbeHome, ProbeHost, ProbeReport,
};
use envcloak_e2e::{Harness, Person, age, quoted, versions_toml, write_script};
use envcloak_testkit::agents::{AgentHome, Host, Installed, probe_model_exe, require};
use envcloak_testkit::{Canary, TEST_PATH, fresh_seed, labels, testkit_bin};
use serde_json::{Value, json};

/// The story runs with the network CI says (`ENVCLOAK_TEST_NETWORK`).
#[test]
fn the_network_is_what_ci_says() {
    envcloak_e2e::check_network();
}

fn agent_of(host: Host) -> Agent {
    match host {
        Host::ClaudeCode => Agent::ClaudeCode,
        Host::Codex => Agent::Codex,
    }
}

fn os() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

/// The person approving the probes' requests from a terminal of their own:
/// `envcloak pending --json` until one waits, then `envcloak approve <id>
/// --for 1h` with the passphrase typed.
struct Approve<'p> {
    person: &'p Person,
    cwd: PathBuf,
    typed: String,
    given: AtomicUsize,
}

impl Approver for Approve<'_> {
    fn approve(&self, deadline: Instant, stop: &AtomicBool) -> Result<(), String> {
        while Instant::now() < deadline && !stop.load(Ordering::SeqCst) {
            let listed = self
                .person
                .run(
                    &self.cwd,
                    &["pending", "--json"],
                    &[],
                    Duration::from_secs(60),
                )
                .ok_or("pending did not finish")?;
            let v: Value = serde_json::from_slice(&listed.stdout).unwrap_or(Value::Null);
            let id = v["requests"]
                .as_array()
                .and_then(|r| r.first())
                .and_then(|r| r["request"].as_str())
                .map(str::to_owned);
            if let Some(id) = id {
                let done = self
                    .person
                    .run(
                        &self.cwd,
                        &["approve", &id, "--for", "1h"],
                        &[("Vault passphrase to approve this: ", &self.typed)],
                        Duration::from_secs(120),
                    )
                    .ok_or("approve did not finish")?;
                if done.code != 0 {
                    return Err(format!("approve exited {}", done.code));
                }
                self.given.fetch_add(1, Ordering::SeqCst);
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(300));
        }
        Err("no request was pending".to_owned())
    }
}

/// One host in a home with a vault, EnvCloak installed, and the probe's
/// projects.
struct Site {
    h: Harness,
    agent: AgentHome,
    host: Host,
    /// `claude` or `codex` starting the pinned build: the person's `PATH`.
    bin: PathBuf,
    probe_project: PathBuf,
    output_project: PathBuf,
    sentinel_project: PathBuf,
    /// The output emitter's non-secret marker.
    marker: String,
    /// The values the output project binds.
    values: Vec<Vec<u8>>,
}

/// `envcloak <args>` by the person, with the hosts on `PATH` and Claude
/// Code's temporary directory where the harness keeps it.
fn person_with_hosts(s: &mut Site, cwd: &Path, args: &[&str]) -> envcloak_e2e::Human {
    let path = format!("PATH={}:{TEST_PATH}", s.bin.display());
    let tmp = format!("CLAUDE_CODE_TMPDIR={}", s.agent.claude_tmp().display());
    let cli = s.h.cli();
    let mut argv = vec![
        "/usr/bin/env",
        path.as_str(),
        tmp.as_str(),
        cli.to_str().unwrap(),
    ];
    argv.extend_from_slice(args);
    s.h.human_argv(cwd, &argv, &[], &[])
}

fn site(host: Host, test: &str) -> Option<Site> {
    let found = Installed::find(&versions_toml(), host.id(), "native");
    let installed = require(found, test)?;
    let mut h = Harness::start();
    let root = h.home.root().to_path_buf();
    let home = h.home.home();
    // The person's vault, created on a terminal of their own.
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
    // The output probe's project: one key, imported from its .env (then
    // deleted), and an emitter that prints a marker and the key, as it is,
    // base64 and hexadecimal.
    let output_project = root.join("acme");
    std::fs::create_dir_all(&output_project).unwrap();
    let value = h.value(labels::OPENAI_API_KEY).to_vec();
    std::fs::write(
        output_project.join(".env"),
        format!("OPENAI_API_KEY={}\n", String::from_utf8_lossy(&value)),
    )
    .unwrap();
    // Written before the person's session: not one a program has open.
    age(&output_project.join(".env"), Duration::from_secs(600));
    h.allow_plaintext(output_project.join(".env"));
    let marker = format!(
        "ecp-emit-{:04x}-{:04x}",
        fresh_seed() & 0xffff,
        fresh_seed() & 0xffff
    );
    let (a, b) = marker.split_at(marker.len() / 2);
    write_script(
        &output_project.join("emit"),
        &format!(
            "#!/bin/sh\nprintf '%s%s\\n' {} {}\nprintf '%s\\n' \"$OPENAI_API_KEY\"\n\
             printf '%s' \"$OPENAI_API_KEY\" | base64\nprintf '%s' \"$OPENAI_API_KEY\" | od -An \
             -tx1 | tr -d ' \\n'\necho\n",
            quoted(a),
            quoted(b)
        ),
    );
    let imported = h.human(&output_project, &["init", "--import", "--yes"], &[], &[]);
    assert_eq!(imported.code, 0, "{}", imported.all());
    let confirmed = h.human(
        &output_project,
        &["recovery", "confirm", "--kit-fd", "4"],
        &[(4, &kit, true)],
        &[],
    );
    assert_eq!(confirmed.code, 0, "{}", confirmed.all());
    let deleted = h.human(&output_project, &["init", "--delete-plaintext"], &[], &[]);
    assert_eq!(deleted.code, 0, "{}", deleted.all());
    h.allow_no_plaintext();
    // The sentinel probe's project: a manifest that binds nothing.
    let sentinel_project = root.join("sentinel");
    std::fs::create_dir_all(&sentinel_project).unwrap();
    std::fs::write(
        sentinel_project.join("envcloak.toml"),
        "[project]\nname = \"probe-sentinel\"\n",
    )
    .unwrap();
    let probe_project = home.join("probe");
    std::fs::create_dir_all(&probe_project).unwrap();
    let agent = AgentHome::within(&h.home, host, installed);
    let bin = root.join("host-bin");
    std::fs::create_dir_all(&bin).unwrap();
    let name = match host {
        Host::ClaudeCode => "claude",
        Host::Codex => "codex",
    };
    write_script(
        &bin.join(name),
        &format!(
            "#!/bin/sh\nexec {} \"$@\"\n",
            quoted(agent.installed.exe.to_str().unwrap())
        ),
    );
    let mut s = Site {
        h,
        agent,
        host,
        bin,
        probe_project,
        output_project,
        sentinel_project,
        marker,
        values: vec![value],
    };
    // EnvCloak installed for the host, as the person does: on macOS with
    // consent to Codex's socket allowance (K-01).
    let mut args = vec!["agents", "install", "--agent", host.id(), "--yes", "--json"];
    if cfg!(target_os = "macos") && host == Host::Codex {
        args.push("--consent-sandbox-sockets");
    }
    let home = s.h.home.home();
    let out = person_with_hosts(&mut s, &home, &args);
    assert_eq!(out.code, 0, "{}", out.all());
    Some(s)
}

impl Site {
    /// The host's environment in the probe home: the home's own variables,
    /// with Claude Code's temporary directory and Codex's directory where
    /// the harness keeps them.
    fn env(&self) -> Vec<(OsString, OsString)> {
        let mut env: Vec<(OsString, OsString)> = self
            .h
            .home
            .vars()
            .into_iter()
            .map(|(k, v)| (OsString::from(k), v))
            .collect();
        match self.host {
            Host::ClaudeCode => {
                env.push(("CLAUDE_CODE_TMPDIR".into(), self.agent.claude_tmp().into()))
            }
            Host::Codex => env.push(("CODEX_HOME".into(), self.agent.codex_home().into())),
        }
        env
    }

    fn probe_host(&self) -> ProbeHost {
        ProbeHost {
            host: agent_of(self.host),
            exe: self.agent.installed.exe.clone(),
            version: self.agent.installed.pin.version.clone(),
        }
    }

    /// The flags the probe home adds: Codex's trust bypass, standing for
    /// the person's trust in `/hooks` (labelled; never written anywhere).
    fn flags(&self, trusted: bool) -> HostFlags {
        HostFlags {
            args: if self.host == Host::Codex && trusted {
                vec!["--dangerously-bypass-hook-trust".to_owned()]
            } else {
                Vec::new()
            },
        }
    }

    /// Probes `surfaces` (and with `server`, EnvCloak's server), the person
    /// approving what the probes ask for.
    fn probe(&mut self, surfaces: &[Surface], server: bool, trusted: bool) -> ProbeReport {
        let person = self.h.person();
        let typed = format!(
            "{}\r",
            String::from_utf8_lossy(self.h.value(labels::VAULT_PASSPHRASE))
        );
        let approve = Approve {
            person: &person,
            cwd: self.h.home.home(),
            typed,
            given: AtomicUsize::new(0),
        };
        let home = ProbeHome {
            root: self.h.home.root().to_path_buf(),
            home: self.h.home.home(),
            env: self.env(),
            project: self.probe_project.clone(),
            model_exe: probe_model_exe(),
            envcloak: self.h.cli(),
            mcp_fixture: Some(testkit_bin("ec-mcp-fixture")),
            sentinel_project: Some(self.sentinel_project.clone()),
            output: Some(OutputFixture {
                project: self.output_project.clone(),
                command: vec!["./emit".to_owned()],
                marker: self.marker.clone(),
                values: self
                    .values
                    .iter()
                    .map(|v| zeroize::Zeroizing::new(v.clone()))
                    .collect(),
            }),
            approver: Some(&approve),
            run_limit: Duration::from_secs(180),
        };
        let report = probe::run_surfaces(
            &self.probe_host(),
            &home,
            &self.flags(trusted),
            surfaces,
            server,
        );
        drop(home);
        self.h.keep_person(&person);
        for r in &report.runs {
            println!(
                "measurement: probe {} {} {}: run {:?} flags {:?}: exit {:?}, timed out {}, {} \
                 requests, clean {}, approved {:?}, {:?}",
                self.host.id(),
                self.agent.installed.pin.version,
                os(),
                r.name,
                r.flags,
                r.exit,
                r.timed_out,
                r.requests,
                r.clean,
                r.approved,
                r.elapsed
            );
        }
        for s in &report.surfaces {
            println!(
                "measurement: probe {} {} {}: {} {} {:?}",
                self.host.id(),
                self.agent.installed.pin.version,
                os(),
                s.surface.name(),
                s.outcome.name(),
                s.checks
                    .iter()
                    .map(|c| (c.name, c.passed))
                    .collect::<Vec<_>>()
            );
        }
        println!(
            "measurement: probe {} {} {}: EnvCloak server {} sentinel {} control denied {} {:?}",
            self.host.id(),
            self.agent.installed.pin.version,
            os(),
            report.server.outcome.name(),
            report.server.sentinel.name(),
            report.server.control_denied,
            report
                .server
                .checks
                .iter()
                .map(|c| (c.name, c.passed))
                .collect::<Vec<_>>()
        );
        report
    }

    /// The configuration `agents status` reads in `HOME`, and its digest.
    fn config(&self) -> ConfigSet {
        let env = self.env();
        let lookup = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        let l = Locations::new(&lookup).unwrap();
        let home = std::fs::canonicalize(self.h.home.home()).unwrap();
        ConfigSet::read(
            agent_of(self.host),
            &l,
            &coverage::claude_managed_dir(),
            &home,
            &lookup,
        )
    }

    /// The SHA-256 `agents status` keys the cache by: the host's file on
    /// `PATH`, resolved.
    fn exe_sha256(&self) -> String {
        let name = match self.host {
            Host::ClaudeCode => "claude",
            Host::Codex => "codex",
        };
        coverage::file_sha256(&std::fs::canonicalize(self.bin.join(name)).unwrap()).unwrap()
    }

    /// Keeps `report` in the cache as `agents status --probe` will (M2-28).
    fn cache(&self, report: &ProbeReport) {
        let path = Cache::path(&self.h.data_dir());
        let mut c = Cache::load(&path);
        c.put(report.record(&self.exe_sha256(), &self.config().digest()));
        c.store(&path).unwrap();
    }

    /// `envcloak agents status [--json]` in `HOME`.
    fn status(&mut self, json: bool) -> envcloak_e2e::Human {
        let home = self.h.home.home();
        let mut args = vec!["agents", "status"];
        if json {
            args.push("--json");
        }
        person_with_hosts(self, &home, &args)
    }
}

/// The published matrix's row for `host` at `version` on this system:
/// surface name (and `envcloak_server`) to the state as `agents status`
/// prints it.
fn matrix(host: &str, version: &str) -> Vec<(String, String)> {
    let text = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../integrations/compat/matrix.toml"),
    )
    .unwrap();
    let doc: toml_edit::DocumentMut = text.parse().unwrap();
    let rows = doc["host"].as_array_of_tables().unwrap();
    let row = rows
        .iter()
        .find(|t| t["id"].as_str() == Some(host) && t["version"].as_str() == Some(version))
        .unwrap_or_else(|| panic!("matrix.toml has no row for {host} {version}"));
    let os = row[os()].as_table().unwrap();
    os.iter()
        .map(|(k, v)| (k.to_owned(), v.as_str().unwrap().to_owned()))
        .collect()
}

/// A surface or the server line as `--json` reports it, written as the
/// human report writes it.
fn shown(v: &Value) -> String {
    let reasons: Vec<&str> = v["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap())
        .collect();
    if let Some(a) = v.get("availability") {
        let sentinel = v["sentinel"].as_str().unwrap();
        let mut s = a.as_str().unwrap().to_owned();
        for r in &reasons {
            s.push_str(&format!("; {r}"));
        }
        s.push_str(&format!(" (probe={}", v["probe"].as_str().unwrap()));
        if sentinel != "not_run" {
            s.push_str(&format!(", sentinel {}", sentinel.replace('_', " ")));
        }
        s.push(')');
        return s;
    }
    let mut s = format!("{} (", v["state"].as_str().unwrap());
    if !reasons.is_empty() {
        s.push_str(&reasons.join(", "));
        s.push_str("; ");
    }
    s.push_str(&format!("probe={})", v["probe"].as_str().unwrap()));
    s
}

/// The whole probe of one pinned host: see the module documentation.
///
/// Mutations checked: `assemble` reporting `active` for Claude Code's
/// prompt guard (`Outcome::Passed` read as `active` whatever degrades
/// it): the status's prompt guard is not the matrix's `degraded (...)`
/// and this fails; `outside_host_sandbox` reported without running the
/// sentinel probe (`Prober::sentinel` answering passed and appeared at
/// once): no sentinel is on disk and this fails; the transcript's outcome
/// taken from the prompt probe without the stores' sweep: Claude Code's
/// transcript reads passed, not the matrix's `unsupported
/// (persists_blocked_prompt; probe=failed)`, and this fails.
fn whole_probe(host: Host, test: &str) {
    let Some(mut s) = site(host, test) else {
        return;
    };
    let report = s.probe(&Surface::ALL, true, true);
    // The sentinel's evidence, read on disk apart from the probe's report:
    // the probe's directory in HOME, the shell's write absent and the one
    // `run_with_secrets` started there.
    let home = s.h.home.home();
    let dirs: Vec<PathBuf> = std::fs::read_dir(&home)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with(".ecp-sentinel-"))
        })
        .collect();
    assert_eq!(
        dirs.len(),
        1,
        "the sentinel probe left no directory of its own"
    );
    assert_eq!(
        dirs[0].join("mcp").exists(),
        report.server.sentinel == Sentinel::Appeared,
        "the report's sentinel is not what is on disk"
    );
    assert_eq!(
        !dirs[0].join("shell").exists(),
        report.server.control_denied,
        "the report's control is not what is on disk"
    );
    let version = s.agent.installed.pin.version.clone();
    let row = matrix(host.id(), &version);
    // What the probes observed, against what the matrix publishes.
    let observed = |surface: Surface| report.surface(surface).unwrap().outcome;
    for (name, want) in &row {
        if name == "envcloak_server" {
            assert!(
                want.contains(&format!("probe={}", report.server.outcome.name())),
                "server: {want} but the probe {}",
                report.server.outcome.name()
            );
            continue;
        }
        let surface = Surface::from_name(name).unwrap();
        assert!(
            want.ends_with(&format!("probe={})", observed(surface).name())),
            "{name}: the matrix says {want}, the probe {}",
            observed(surface).name()
        );
    }
    // What `agents status` reports from them, against both.
    s.cache(&report);
    let out = s.status(true);
    assert_eq!(out.code, 0, "{}", out.all());
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    let a = v["agents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["agent"] == host.id())
        .unwrap_or_else(|| panic!("{v}"))
        .clone();
    assert_eq!(a["probed"], "current", "{a}");
    let cs = s.config();
    let record = report.record(&s.exe_sha256(), &cs.digest());
    let expected = coverage::assemble(agent_of(host), &version, &cs, Probed::Current(&record));
    for (name, want) in &row {
        let got = if name == "envcloak_server" {
            shown(&a["envcloak_server"])
        } else {
            let entry = a["surfaces"]
                .as_array()
                .unwrap()
                .iter()
                .find(|x| x["surface"] == name.as_str())
                .unwrap();
            let surface = Surface::from_name(name).unwrap();
            // The claim is the observation: the reported probe outcome is
            // the probe's own.
            assert_eq!(
                entry["probe"].as_str(),
                Some(observed(surface).name()),
                "{name}"
            );
            assert_eq!(
                Some(shown(entry)),
                expected.surface(surface).map(ToString::to_string),
                "{name}"
            );
            shown(entry)
        };
        assert_eq!(&got, want, "{name}: reported {got}, the matrix says {want}");
    }
    // A failed probe is listed first.
    let surfaces = a["surfaces"].as_array().unwrap();
    let first_passed = surfaces.iter().position(|x| x["probe"] != "failed");
    if let Some(i) = first_passed {
        assert!(surfaces[i..].iter().all(|x| x["probe"] != "failed"), "{a}");
    }
    // The human report says the same, the server line with its evidence.
    let human = s.status(false);
    assert_eq!(human.code, 0, "{}", human.all());
    let text = human.out();
    for (name, want) in &row {
        assert!(
            text.contains(want.as_str()),
            "{name}: {want} not in\n{text}"
        );
    }
    assert!(text.contains("outside_host_sandbox"), "{text}");
    s.agent.check_pinned();
    s.h.assert_swept(&format!("M2-09 probes ({})", host.id()));
}

#[test]
fn claude_code_coverage_is_what_its_probes_observe() {
    whole_probe(Host::ClaudeCode, "M2-09 probes (Claude Code)");
}

#[test]
fn codex_coverage_is_what_its_probes_observe() {
    whole_probe(Host::Codex, "M2-09 probes (Codex)");
}

/// EnvCloak's hook groups for `event` taken out of the JSON hook file at
/// `path` (Claude Code's settings or Codex's hooks.json); with `matcher`,
/// only that group.
fn remove_hook(path: &Path, event: &str, matcher: Option<&str>) {
    let mut v: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let groups = v["hooks"][event].as_array_mut().unwrap();
    let before = groups.len();
    groups.retain(|g| {
        let ours = g["hooks"].as_array().unwrap().iter().any(|h| {
            h["command"]
                .as_str()
                .is_some_and(|c| c.contains(" hook --host "))
        });
        let this = matcher.is_none_or(|m| g["matcher"].as_str() == Some(m));
        !(ours && this)
    });
    assert!(
        groups.len() < before,
        "no EnvCloak hook for {event} {matcher:?}"
    );
    std::fs::write(path, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
}

/// One per surface: with EnvCloak's hook for it taken out of the installed
/// configuration, its probe fails (and the others it does not rest on
/// still pass, so the failure is the hook's).
fn without_hooks(host: Host, test: &str) {
    let Some(mut s) = site(host, test) else {
        return;
    };
    let (file, tools, mcp) = match host {
        Host::ClaudeCode => (
            s.h.home.home().join(".claude/settings.json"),
            envcloak_agents::hosts::claude::TOOL_MATCHER,
            envcloak_agents::hosts::claude::MCP_MATCHER,
        ),
        Host::Codex => (s.agent.codex_home().join("hooks.json"), "Bash", "mcp__.*"),
    };
    let original = std::fs::read(&file).unwrap();
    for (event, matcher, hit, kept) in [
        (
            "UserPromptSubmit",
            None,
            &[Surface::PromptToModel, Surface::Transcript][..],
            Surface::Shell,
        ),
        (
            "PreToolUse",
            Some(tools),
            &[Surface::FileRead, Surface::Shell][..],
            Surface::Mcp,
        ),
        ("PreToolUse", Some(mcp), &[Surface::Mcp][..], Surface::Shell),
    ] {
        std::fs::write(&file, &original).unwrap();
        remove_hook(&file, event, matcher);
        let mut surfaces = hit.to_vec();
        surfaces.push(kept);
        let report = s.probe(&surfaces, false, true);
        for surface in hit {
            assert_eq!(
                report.surface(*surface).unwrap().outcome,
                Outcome::Failed,
                "{event} {matcher:?} removed: {surface:?} {:?}",
                report.surface(*surface)
            );
        }
        // Claude Code's transcript probe needs the prompt blocked first:
        // without the hook it fails, and never as a kept blocked prompt.
        if hit.contains(&Surface::Transcript) {
            assert!(!report.surface(Surface::Transcript).unwrap().persisted);
        }
        assert_eq!(
            report.surface(kept).unwrap().outcome,
            Outcome::Passed,
            "{event} {matcher:?} removed: {kept:?} {:?}",
            report.surface(kept)
        );
    }
    std::fs::write(&file, &original).unwrap();
    s.h.assert_swept(&format!("M2-09 hooks removed ({})", host.id()));
}

#[test]
fn claude_code_probes_fail_without_their_hooks() {
    without_hooks(Host::ClaudeCode, "M2-09 hooks removed (Claude Code)");
}

#[test]
fn codex_probes_fail_without_their_hooks() {
    without_hooks(Host::Codex, "M2-09 hooks removed (Codex)");
}

/// Claude Code's `@.env` case rests on the `Read(**/.env*)` deny rule
/// alone: with the rule taken out of the installed settings, the file
/// read probe fails on that case, while the `Read` tool's denial (the
/// hook's) still holds.
#[test]
fn claude_code_at_env_fails_without_the_deny_rule() {
    let Some(mut s) = site(Host::ClaudeCode, "M2-09 @.env (Claude Code)") else {
        return;
    };
    let path = s.h.home.home().join(".claude/settings.json");
    let report = s.probe(&[Surface::FileRead], false, true);
    assert_eq!(
        report.surface(Surface::FileRead).unwrap().outcome,
        Outcome::Passed,
        "{:?}",
        report.surface(Surface::FileRead)
    );
    let mut v: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    v["permissions"]["deny"]
        .as_array_mut()
        .unwrap()
        .retain(|r| r.as_str() != Some(envcloak_agents::hosts::claude::READ_DENY));
    std::fs::write(&path, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
    let report = s.probe(&[Surface::FileRead], false, true);
    let probe = report.surface(Surface::FileRead).unwrap();
    assert_eq!(probe.outcome, Outcome::Failed, "{probe:?}");
    let failed: Vec<&str> = probe
        .checks
        .iter()
        .filter(|c| !c.passed)
        .map(|c| c.name)
        .collect();
    assert_eq!(failed, ["the @.env file's content never does"], "{probe:?}");
    s.h.assert_swept("M2-09 @.env (Claude Code)");
}

/// Codex's hooks, untrusted (no trust bypass): they do not run, so every
/// hook probe fails, and `agents status` says `hooks_untrusted` with the
/// failed probe first.
///
/// Mutation checked: `degraders` without the trust gate (`Some(Host::
/// Codex) => {}`): the status lacks `hooks_untrusted` and this fails.
#[test]
fn codex_untrusted_hooks_read_degraded_with_failed_probes() {
    let Some(mut s) = site(Host::Codex, "M2-09 untrusted hooks (Codex)") else {
        return;
    };
    let hook_surfaces = [
        Surface::PromptToModel,
        Surface::FileRead,
        Surface::Shell,
        Surface::Mcp,
    ];
    let report = s.probe(&hook_surfaces, false, false);
    for surface in hook_surfaces {
        assert_eq!(
            report.surface(surface).unwrap().outcome,
            Outcome::Failed,
            "{surface:?}: {:?}",
            report.surface(surface)
        );
    }
    s.cache(&report);
    let out = s.status(true);
    assert_eq!(out.code, 0, "{}", out.all());
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    let a = v["agents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["agent"] == "codex")
        .unwrap()
        .clone();
    for surface in hook_surfaces {
        let e = a["surfaces"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["surface"] == surface.name())
            .unwrap();
        let want = if surface == Surface::Shell && cfg!(target_os = "linux") {
            "unsupported (sandbox_blocks_socket; probe=failed)"
        } else {
            "degraded (fails_open_on_timeout, hooks_untrusted; probe=failed)"
        };
        assert_eq!(shown(e), want, "{surface:?}");
    }
    let first: Vec<&str> = a["surfaces"]
        .as_array()
        .unwrap()
        .iter()
        .take(4)
        .map(|x| x["probe"].as_str().unwrap())
        .collect();
    assert_eq!(first, ["failed"; 4], "{a}");
    s.h.assert_swept("M2-09 untrusted hooks (Codex)");
}

/// A `UserPromptSubmit` hook that would block the prompt but outlives the
/// host's timeout: the prompt, holding a key-shaped token, goes on to the
/// model. This is the `fails_open_on_timeout` the coverage report gives
/// every hook surface of both pinned hosts.
fn hook_past_its_timeout(host: Host, test: &str) {
    let Some(s) = site(host, test) else {
        return;
    };
    let slow = s.h.home.root().join("slow-hook");
    write_script(&slow, "#!/bin/sh\nsleep 20\necho blocked >&2\nexit 2\n");
    let hook = json!({"type": "command", "command": slow.to_str().unwrap(), "timeout": 2});
    let file = match host {
        Host::ClaudeCode => s.h.home.home().join(".claude/settings.json"),
        Host::Codex => s.agent.codex_home().join("hooks.json"),
    };
    // The person's own hook, in place of EnvCloak's, for this run.
    let mut v: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    v["hooks"]["UserPromptSubmit"] = json!([{"hooks": [hook]}]);
    std::fs::write(&file, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
    let token = format!("ecpk{:016x}{:016x}", fresh_seed(), fresh_seed());
    let flags = s.flags(true);
    let mut args = match host {
        Host::ClaudeCode => envcloak_testkit::agents::HostFlags::claude("default", &[]),
        Host::Codex => envcloak_testkit::agents::HostFlags::codex("read-only", "never"),
    };
    args.args.extend(flags.args);
    let start = Instant::now();
    let run = s.agent.run(
        &json!({"steps": [{"say": "done"}]}),
        &format!("Deploy with {token} now."),
        &args,
        &s.probe_project,
    );
    let elapsed = start.elapsed();
    let reached = run
        .model
        .requests
        .iter()
        .any(|r| r.status == 200 && String::from_utf8_lossy(&r.body).contains(&token));
    println!(
        "measurement: {} {} {}: a UserPromptSubmit hook that would block, past its 2 s \
         timeout: the prompt reached the model: {reached} (after {elapsed:?})",
        host.id(),
        s.agent.installed.pin.version,
        os()
    );
    assert!(reached, "the hook's timeout stopped the prompt: {run:?}");
    assert!(elapsed >= Duration::from_secs(2), "{elapsed:?}");
    assert!(
        elapsed < Duration::from_secs(20),
        "the host waited for the hook: {elapsed:?}"
    );
}

#[test]
fn claude_code_hook_past_its_timeout_fails_open() {
    hook_past_its_timeout(Host::ClaudeCode, "M2-09 hook timeout (Claude Code)");
}

#[test]
fn codex_hook_past_its_timeout_fails_open() {
    hook_past_its_timeout(Host::Codex, "M2-09 hook timeout (Codex)");
}

// ---------------------------------------------------------------------------
// The stand-in host.

/// A home for `ec-fake-host` set to `mode`, and the probe's directories.
struct Fake {
    _dir: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    project: PathBuf,
}

fn fake(mode: &Value) -> Fake {
    let dir = tempfile::Builder::new()
        .prefix("ecz")
        .tempdir_in("/tmp")
        .unwrap();
    let root = dir.path().to_path_buf();
    let home = root.join("home");
    let project = home.join("probe");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(root.join("tmp")).unwrap();
    std::fs::write(home.join(".ec-fake-host.json"), mode.to_string()).unwrap();
    Fake {
        _dir: dir,
        root,
        home,
        project,
    }
}

fn fake_probe(mode: &Value) -> ProbeReport {
    let f = fake(mode);
    let home = ProbeHome {
        root: f.root.clone(),
        home: f.home.clone(),
        env: vec![
            ("HOME".into(), f.home.clone().into()),
            ("PATH".into(), TEST_PATH.into()),
            ("TMPDIR".into(), f.root.join("tmp").into()),
            ("CLAUDE_CODE_TMPDIR".into(), f.root.join("tmp").into()),
        ],
        project: f.project.clone(),
        model_exe: probe_model_exe(),
        envcloak: PathBuf::from("/nonexistent/envcloak"),
        mcp_fixture: Some(PathBuf::from("/nonexistent/fixture")),
        sentinel_project: None,
        output: None,
        approver: None,
        run_limit: Duration::from_secs(60),
    };
    let host = ProbeHost {
        host: Agent::ClaudeCode,
        exe: PathBuf::from(env!("CARGO_BIN_EXE_ec-fake-host")),
        version: "2.1.280".to_owned(),
    };
    probe::run(&host, &home, &HostFlags::default())
}

/// The configuration of a host with EnvCloak installed and nothing
/// switched off: what the stand-ins' results are read with.
fn installed() -> ConfigSet {
    ConfigSet {
        host: "claude-code".to_owned(),
        linux: false,
        hooks: Hooks {
            prompt: HookState::Present,
            tools: HookState::Present,
            mcp: HookState::Present,
        },
        read_deny: true,
        server: ServerFacts {
            registered: true,
            run_with_secrets_approved: Some(false),
        },
        ..ConfigSet::default()
    }
}

fn outcomes(r: &ProbeReport) -> Vec<(Surface, Outcome)> {
    r.surfaces.iter().map(|s| (s.surface, s.outcome)).collect()
}

/// A host whose guards all hold passes every probe it can run here; the
/// output probe, with no terminal to approve from, is skipped
/// (`probe_needs_terminal`), and with no sentinel project the server
/// probe is skipped: neither is ever passed.
#[test]
fn a_stand_in_that_holds_passes_every_probe_it_runs() {
    let r = fake_probe(&json!({}));
    assert_eq!(
        outcomes(&r),
        [
            (Surface::PromptToModel, Outcome::Passed),
            (Surface::Transcript, Outcome::Passed),
            (Surface::FileRead, Outcome::Passed),
            (Surface::Shell, Outcome::Passed),
            (Surface::Mcp, Outcome::Passed),
            (Surface::Output, Outcome::Skipped),
        ],
        "{r:#?}"
    );
    assert_eq!(
        r.surface(Surface::Output).unwrap().why,
        [Reason::ProbeNeedsTerminal]
    );
    assert_eq!(r.server.outcome, Outcome::Skipped);
    assert_eq!(r.server.sentinel, Sentinel::NotRun);
    let c = coverage::assemble(
        Agent::ClaudeCode,
        "2.1.280",
        &installed(),
        Probed::Current(&r.record("x", "y")),
    );
    assert_eq!(
        c.surface(Surface::Output).map(ToString::to_string),
        Some("unverified (probe_needs_terminal; probe=skipped)".to_owned())
    );
    assert_eq!(
        c.surface(Surface::Transcript).map(|s| s.state),
        Some(State::Degraded)
    );
}

/// Pointed at a dead base URL, the host never reaches the model: every
/// probe fails through its control, none passes, and every surface reads
/// `probe=failed`, listed first.
///
/// Mutation checked: the prompt probe without its control (`blocked`
/// alone deciding): a host that sends nothing passes the prompt guard and
/// this fails.
#[test]
fn a_dead_base_url_fails_every_probe_through_its_control() {
    let r = fake_probe(&json!({"url": "dead"}));
    for (surface, outcome) in outcomes(&r) {
        if surface == Surface::Output {
            continue;
        }
        assert_eq!(outcome, Outcome::Failed, "{surface:?}: {r:#?}");
        let s = r.surface(surface).unwrap();
        assert!(
            s.checks.iter().any(|c| c.control && !c.passed),
            "{surface:?}: no failed control: {s:?}"
        );
    }
    let c = coverage::assemble(
        Agent::ClaudeCode,
        "2.1.280",
        &installed(),
        Probed::Current(&r.record("x", "y")),
    );
    for s in c.surfaces.iter().take(5) {
        assert_eq!(s.probe, Outcome::Failed, "{s}");
        assert_ne!(s.state, State::Active, "{s}");
    }
}

/// Each control failing alone, and each probe failing alone, gives that
/// surface `failed` (through the check that failed), and its state never
/// `active`.
#[test]
fn a_stand_in_failing_each_control_or_probe_fails_that_probe() {
    struct Case {
        mode: Value,
        failed: &'static [Surface],
        check: &'static str,
    }
    let cases = [
        Case {
            mode: json!({"prompt": "leak"}),
            failed: &[Surface::PromptToModel, Surface::Transcript],
            check: "a prompt holding a key-shaped token never reaches it",
        },
        Case {
            mode: json!({"persist": "all"}),
            failed: &[Surface::Transcript],
            check: "the blocked prompt is in none of them",
        },
        Case {
            mode: json!({"persist": "none"}),
            failed: &[Surface::Transcript],
            check: "the control prompt is in the host's stores",
        },
        Case {
            mode: json!({"tools": "plain"}),
            failed: &[Surface::FileRead, Surface::Shell, Surface::Mcp],
            check: "the probe call is denied with EnvCloak's marker",
        },
        Case {
            mode: json!({"tools": "run"}),
            failed: &[Surface::FileRead, Surface::Shell, Surface::Mcp],
            check: "nothing it would have read reaches the model",
        },
        Case {
            mode: json!({"control": "fail"}),
            failed: &[Surface::FileRead, Surface::Shell, Surface::Mcp],
            check: "the control call runs and its result reaches the model",
        },
        Case {
            mode: json!({"mention": "all"}),
            failed: &[Surface::FileRead],
            check: "the @.env file's content never does",
        },
        Case {
            mode: json!({"exit": 1}),
            failed: &[
                Surface::PromptToModel,
                Surface::Transcript,
                Surface::FileRead,
                Surface::Shell,
                Surface::Mcp,
            ],
            check: "",
        },
    ];
    for case in cases {
        let r = fake_probe(&case.mode);
        for surface in [
            Surface::PromptToModel,
            Surface::Transcript,
            Surface::FileRead,
            Surface::Shell,
            Surface::Mcp,
        ] {
            let s = r.surface(surface).unwrap();
            let want = if case.failed.contains(&surface) {
                Outcome::Failed
            } else {
                Outcome::Passed
            };
            assert_eq!(s.outcome, want, "{}: {surface:?}: {s:?}", case.mode);
            if want == Outcome::Failed && !case.check.is_empty() {
                assert!(
                    s.checks.iter().any(|c| !c.passed && c.name == case.check)
                        || surface == Surface::Transcript,
                    "{}: {surface:?}: {s:?}",
                    case.mode
                );
            }
        }
        let c = coverage::assemble(
            Agent::ClaudeCode,
            "2.1.280",
            &installed(),
            Probed::Current(&r.record("x", "y")),
        );
        for surface in case.failed {
            let s = c.surface(*surface).unwrap();
            assert_eq!(s.probe, Outcome::Failed, "{}: {s}", case.mode);
            assert_ne!(s.state, State::Active, "{}: {s}", case.mode);
        }
        // A blocked prompt kept on disk is the documented gap, said so.
        if case.mode == json!({"persist": "all"}) {
            assert_eq!(
                c.surface(Surface::Transcript).map(ToString::to_string),
                Some("unsupported (persists_blocked_prompt; probe=failed)".to_owned())
            );
        }
    }
}

/// A host version outside the scripted model's qualified table is not
/// probed: every outcome is `not_qualified`, never `failed` or `passed`,
/// and nothing is run.
#[test]
fn an_unqualified_version_is_not_probed() {
    let f = fake(&json!({}));
    let home = ProbeHome {
        root: f.root.clone(),
        home: f.home.clone(),
        env: vec![("HOME".into(), f.home.clone().into())],
        project: f.project.clone(),
        model_exe: probe_model_exe(),
        envcloak: PathBuf::from("/nonexistent/envcloak"),
        mcp_fixture: None,
        sentinel_project: None,
        output: None,
        approver: None,
        run_limit: Duration::from_secs(60),
    };
    let host = ProbeHost {
        host: Agent::ClaudeCode,
        exe: PathBuf::from(env!("CARGO_BIN_EXE_ec-fake-host")),
        version: "9.9.9".to_owned(),
    };
    let r = probe::run(&host, &home, &HostFlags::default());
    assert!(r.runs.is_empty());
    assert!(
        r.surfaces
            .iter()
            .all(|s| s.outcome == Outcome::NotQualified)
    );
    assert_eq!(r.server.outcome, Outcome::NotQualified);
}
