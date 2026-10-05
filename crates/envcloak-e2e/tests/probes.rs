//! Gate 38's CI half (M2 plan task M2-09): the coverage probes
//! (`envcloak_agents::probe`) against the pinned Claude Code and Codex in
//! an isolated home with EnvCloak installed by `envcloak agents install`,
//! what `envcloak agents status --json` then reports from their results,
//! and the probes' own controls.
//!
//! - Each pinned host is probed on every surface; each surface's outcome is
//!   the one integrations/compat/matrix.toml publishes for this host
//!   version and system, and `agents status` reports, from the cached
//!   results and the home's real configuration, exactly the matrix's
//!   states and tokens, which are what the probes observed (the test fails
//!   if a claim differs from the observation). The result is kept under the
//!   identity the probe measured (the binary it ran, which `PATH` leads to
//!   by a link, and the probe context of the directory the hosts ran in,
//!   the same before and after), which is what `agents status` reads
//!   there; another directory, a launcher script in place of the binary or
//!   a project setting there makes it stale.
//! - Each pinned host's sentinel probe, its evidence read on disk, gives
//!   the matrix's server line with `outside_host_sandbox` in both the human
//!   and the `--json` report; on Linux it runs again outside CI's user
//!   namespace, inside which Claude Code's sandboxed shell cannot start and
//!   the probe must fail through its shell's run witness.
//! - Each hook surface's probe fails when EnvCloak's hook for it is taken
//!   out of the installed configuration, while the rule's cases still pass,
//!   refused by EnvCloak's host rules in the hosts' own words; Claude
//!   Code's `@.env` case fails when the `Read(**/.env*)` deny rule is taken
//!   out; Codex's hooks, left untrusted (no trust bypass), fail every hook
//!   probe and read `degraded (fails_open_on_timeout, hooks_untrusted;
//!   probe=failed)`; a block Codex reports beside a prompt hook of
//!   another's is not counted as EnvCloak's.
//! - A hook that outlives the host's timeout lets the prompt it would block
//!   through, on both hosts: `fails_open_on_timeout` is what the pinned
//!   hosts do.
//! - A stand-in host (`ec-fake-host`) failing each control or each probe
//!   gives the outcome, state and reasons it must (the prompt probe's
//!   session not kept or not found, its run ending without sending anything
//!   or blocked by another hook, the session not going on; a store it
//!   cannot read, or one behind a link out of the stores), one the model
//!   does not wholly serve fails every probe, and one pointed at a dead
//!   base URL fails every probe through its control; its output probe
//!   passes only redacted, its sentinel needs its shell to run and write,
//!   its file read takes the hook where the rule leaves it and counts no
//!   refusal under a rule not known to be EnvCloak's, and a mention it does
//!   not expand is reported skipped.
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
    // The person's `PATH` leads to the pinned build by a link, as a
    // native install's does: `agents status` and the probe resolve it to
    // the same binary (Codex review of M2-09: a launcher script was hashed
    // in place of the binary probed).
    let bin = root.join("host-bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::os::unix::fs::symlink(&agent.installed.exe, bin.join(host_name(host))).unwrap();
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

    /// The host as the person's `PATH` has it: what `agents status` hashes
    /// is what the probe runs.
    fn probe_host(&self) -> ProbeHost {
        ProbeHost {
            host: agent_of(self.host),
            exe: self.bin.join(host_name(self.host)),
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
                    .map(|c| (c.name, c.passed, c.why))
                    .collect::<Vec<_>>()
            );
        }
        println!(
            "measurement: probe {} {} {} (user namespace {}): EnvCloak server {} sentinel {} \
             shell ran {} allowed write {} control denied {} {:?}",
            self.host.id(),
            self.agent.installed.pin.version,
            os(),
            envcloak_e2e::k01::user_namespace(),
            report.server.outcome.name(),
            report.server.sentinel.name(),
            report.server.control_ran,
            report.server.allowed_write,
            report.server.control_denied,
            report
                .server
                .checks
                .iter()
                .map(|c| (c.name, c.passed, c.why))
                .collect::<Vec<_>>()
        );
        report
    }

    /// The configuration `agents status` reads in the probe's directory,
    /// where the hosts ran.
    fn config(&self) -> ConfigSet {
        let env = self.env();
        let lookup = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        let l = Locations::new(&lookup).unwrap();
        ConfigSet::read(
            agent_of(self.host),
            &l,
            &coverage::claude_managed_dir(),
            &self.probe_project,
            &lookup,
        )
    }

    /// The SHA-256 `agents status` keys the cache by: the host's file on
    /// `PATH`, resolved.
    fn exe_sha256(&self) -> String {
        coverage::file_sha256(&std::fs::canonicalize(self.bin.join(host_name(self.host))).unwrap())
            .unwrap()
    }

    /// The probe context's fingerprint `agents status` keys the cache by,
    /// with the `envcloak` it runs.
    fn fingerprint(&self) -> String {
        self.config().fingerprint(&self.h.cli()).unwrap()
    }

    /// Keeps `report` in the cache as `agents status --probe` will (M2-28):
    /// under the identity the probe measured, which is what `agents
    /// status` reads in the probe's directory.
    fn cache(&self, report: &ProbeReport) {
        assert_eq!(report.exe_sha256, self.exe_sha256(), "the binary probed");
        assert_eq!(
            report.config_digest,
            self.fingerprint(),
            "the probe context the hosts ran in, unchanged while probed"
        );
        let path = Cache::path(&self.h.data_dir());
        let mut c = Cache::load(&path);
        c.put(report.record());
        c.store(&path).unwrap();
    }

    /// `envcloak agents status [--json]` in the probe's directory.
    fn status(&mut self, json: bool) -> envcloak_e2e::Human {
        let dir = self.probe_project.clone();
        self.status_in(&dir, json)
    }

    /// `envcloak agents status [--json]` in `dir`.
    fn status_in(&mut self, dir: &Path, json: bool) -> envcloak_e2e::Human {
        let mut args = vec!["agents", "status"];
        if json {
            args.push("--json");
        }
        person_with_hosts(self, dir, &args)
    }

    /// What `agents status --json` in `dir` says the host's results rest
    /// on: `current`, `changed_since_probe` or `not_probed`.
    fn probed_in(&mut self, dir: &Path) -> String {
        let out = self.status_in(dir, true);
        assert_eq!(out.code, 0, "{}", out.all());
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        v["agents"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["agent"] == self.host.id())
            .unwrap_or_else(|| panic!("{v}"))["probed"]
            .as_str()
            .unwrap()
            .to_owned()
    }
}

fn host_name(host: Host) -> &'static str {
    match host {
        Host::ClaudeCode => "claude",
        Host::Codex => "codex",
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

/// The whole probe of one pinned host's six surfaces: see the module
/// documentation (EnvCloak's server line is [`sentinel_probe`]'s).
///
/// Mutations checked: `assemble` reporting `active` for Claude Code's
/// prompt guard (`Outcome::Passed` read as `active` whatever degrades
/// it): the status's prompt guard is not the matrix's `degraded (...)`
/// and this fails; the transcript's outcome taken from the prompt probe
/// without the stores' sweep: Claude Code's transcript reads passed, not
/// the matrix's `unsupported (persists_blocked_prompt; probe=failed)`,
/// and this fails; Claude Code's file-read hook case reading the
/// project's `.env` (`claude_code_file_read_with_and_without_the_deny_
/// rule`'s mutation): its probe reads failed, not the matrix's passed,
/// and this fails.
fn whole_probe(host: Host, test: &str) {
    let Some(mut s) = site(host, test) else {
        return;
    };
    // The probe context a result is kept for is the one it ran in: the
    // host changes none of it while it is probed (the probe reads it
    // before and after, and keeps no identity when they differ).
    let report = s.probe(&Surface::ALL, false, true);
    assert!(
        !report.config_digest.is_empty() && !report.exe_sha256.is_empty(),
        "the probe kept no identity: its context changed or could not be read"
    );
    let version = s.agent.installed.pin.version.clone();
    let row: Vec<(String, String)> = matrix(host.id(), &version)
        .into_iter()
        .filter(|(name, _)| name != "envcloak_server")
        .collect();
    assert_eq!(row.len(), Surface::ALL.len());
    // What the probes observed, against what the matrix publishes.
    let observed = |surface: Surface| report.surface(surface).unwrap().outcome;
    for (name, want) in &row {
        let surface = Surface::from_name(name).unwrap();
        assert!(
            want.contains(&format!("probe={}", observed(surface).name())),
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
    assert_eq!(a["identified_by"], "version", "{a}");
    let cs = s.config();
    let record = report.record();
    let expected = coverage::assemble(agent_of(host), &version, &cs, Probed::Current(&record));
    for (name, want) in &row {
        let entry = a["surfaces"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["surface"] == name.as_str())
            .unwrap();
        let surface = Surface::from_name(name).unwrap();
        // The claim is the observation: the reported probe outcome is the
        // probe's own.
        assert_eq!(
            entry["probe"].as_str(),
            Some(observed(surface).name()),
            "{name}"
        );
        let got = shown(entry);
        assert_eq!(
            Some(got.clone()),
            expected.surface(surface).map(ToString::to_string),
            "{name}"
        );
        assert_eq!(&got, want, "{name}: reported {got}, the matrix says {want}");
    }
    assert_eq!(
        a["envcloak_server"]["reasons"],
        json!(["outside_host_sandbox"]),
        "{a}"
    );
    // A failed probe is listed first.
    let surfaces = a["surfaces"].as_array().unwrap();
    let first_passed = surfaces.iter().position(|x| x["probe"] != "failed");
    if let Some(i) = first_passed {
        assert!(surfaces[i..].iter().all(|x| x["probe"] != "failed"), "{a}");
    }
    // The human report says the same.
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
    // The result is current only for what was probed (Codex review of
    // M2-09): another directory, a launcher that is not the binary probed,
    // another configuration in the probe's directory each read stale, and
    // putting each back reads current again (the controls).
    let probe_dir = s.probe_project.clone();
    let home_dir = s.h.home.home();
    assert_eq!(s.probed_in(&probe_dir), "current");
    assert_eq!(
        s.probed_in(&home_dir),
        "changed_since_probe",
        "another directory"
    );
    let link = s.bin.join(host_name(host));
    std::fs::remove_file(&link).unwrap();
    write_script(
        &link,
        &format!(
            "#!/bin/sh\nexec {} \"$@\"\n",
            quoted(s.agent.installed.exe.to_str().unwrap())
        ),
    );
    assert_eq!(
        s.probed_in(&probe_dir),
        "changed_since_probe",
        "a launcher script"
    );
    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(&s.agent.installed.exe, &link).unwrap();
    assert_eq!(s.probed_in(&probe_dir), "current", "the link put back");
    let (dir, file, text) = match host {
        Host::ClaudeCode => (".claude", "settings.json", "{}\n"),
        Host::Codex => (".codex", "config.toml", "# the person's\n"),
    };
    std::fs::create_dir_all(probe_dir.join(dir)).unwrap();
    std::fs::write(probe_dir.join(dir).join(file), text).unwrap();
    assert_eq!(
        s.probed_in(&probe_dir),
        "changed_since_probe",
        "a project setting"
    );
    std::fs::remove_file(probe_dir.join(dir).join(file)).unwrap();
    assert_eq!(s.probed_in(&probe_dir), "current", "the setting taken out");
    s.agent.check_pinned();
    s.h.assert_swept(&format!("M2-09 probes ({})", host.id()));
}

/// EnvCloak's server line on one pinned host: the sentinel probe, its
/// evidence read on disk apart from its report, and what `agents status`
/// then says in the human and the `--json` report, held to the matrix.
/// On Linux inside CI's user namespace Claude Code's sandboxed shell
/// cannot start (K-01; docs/AGENTS.md): there the probe must fail through
/// its shell's run witness, never pass, and the matrix's row is measured
/// outside it, as a person's machine runs it (the CI step "Probe
/// sentinels outside a user namespace").
///
/// Mutation checked: `outside_host_sandbox` reported without running the
/// sentinel probe (`Prober::sentinel` answering passed and appeared at
/// once): no sentinel is on disk and this fails.
fn sentinel_probe(host: Host, test: &str) {
    let Some(mut s) = site(host, test) else {
        return;
    };
    let report = s.probe(&[], true, true);
    // The sentinel's evidence, read on disk apart from the report: the
    // probe's directory in HOME, the shell's denied write absent and the
    // one `run_with_secrets` started there.
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
    if report.server.control_denied {
        assert!(
            !dirs[0].join("shell").exists(),
            "the report's control is not what is on disk"
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
        .find(|a| a["agent"] == host.id())
        .unwrap_or_else(|| panic!("{v}"))
        .clone();
    let line = shown(&a["envcloak_server"]);
    let human = s.status(false);
    assert_eq!(human.code, 0, "{}", human.all());
    let text = human.out();
    assert!(text.contains(&line), "{line} not in\n{text}");
    assert!(text.contains("outside_host_sandbox"), "{text}");
    if host == Host::ClaudeCode && envcloak_e2e::k01::user_namespace() {
        // The shell never ran: failed, through its run witness.
        assert_eq!(
            report.server.outcome,
            Outcome::Failed,
            "{:?}",
            report.server
        );
        assert!(!report.server.control_ran, "{:?}", report.server);
        assert!(!report.server.control_denied, "{:?}", report.server);
        assert!(line.contains("(probe=failed"), "{line}");
    } else {
        let want = matrix(host.id(), &s.agent.installed.pin.version)
            .into_iter()
            .find(|(name, _)| name == "envcloak_server")
            .map(|(_, w)| w)
            .unwrap();
        assert!(
            want.contains(&format!("probe={}", report.server.outcome.name())),
            "the matrix says {want}, the probe {}",
            report.server.outcome.name()
        );
        assert_eq!(line, want, "reported {line}, the matrix says {want}");
    }
    s.h.assert_swept(&format!("M2-09 sentinel ({})", host.id()));
}

#[test]
fn claude_code_sentinel_is_what_its_probe_observes() {
    sentinel_probe(Host::ClaudeCode, "M2-09 sentinel (Claude Code)");
}

#[test]
fn codex_sentinel_is_what_its_probe_observes() {
    sentinel_probe(Host::Codex, "M2-09 sentinel (Codex)");
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
/// still pass, so the failure is the hook's): each probe's hook case is a
/// call EnvCloak's host rules leave to the hook, so no rule passes it in
/// the hook's place.
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
        // The rule's cases stand without the hook: EnvCloak's host rules
        // refuse them, in the host's own words.
        if hit.contains(&Surface::FileRead) {
            let by = match host {
                Host::ClaudeCode => {
                    "the host's own permission settings, under EnvCloak's deny rule"
                }
                Host::Codex => "Codex's exec policy, under EnvCloak's forbidden rule",
            };
            let mut with_rule = vec![Surface::FileRead];
            if host == Host::Codex {
                with_rule.push(Surface::Shell);
            }
            for surface in with_rule {
                let rule = report
                    .surface(surface)
                    .unwrap()
                    .checks
                    .iter()
                    .find(|c| c.name == "the call EnvCloak's host rule covers is refused")
                    .copied()
                    .unwrap();
                assert!(rule.passed && rule.why == by, "{surface:?}: {rule:?}");
            }
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

/// Claude Code's file read with the `Read(**/.env*)` deny rule and
/// without it. As installed, the rule refuses the `Read` of the project's
/// `.env` (named by its resolved path, the one the host's working
/// directory is) before EnvCloak's hook, in the host's own words: the
/// rule's case, which passes; the `.env` outside the working directory,
/// which the rule does not match, reaches the hook, whose marker the
/// model gets: the hook's case, which passes; the probe passes. With the
/// rule taken out, the hook refuses both `Read`s, marker and all, and only
/// the `@.env` case, which the rule alone covers, fails. With the hook for
/// the file tools taken out as well, the file reaches the model.
///
/// Mutation checked: the hook's case reading the project's `.env` (the
/// `ELSEWHERE` folder's replaced by the project in `file_read`): as
/// installed the rule refuses it first, without the marker, the probe
/// fails and this fails (as does `claude_code_coverage_is_what_its_probes_
/// observe`'s matrix check).
#[test]
fn claude_code_file_read_with_and_without_the_deny_rule() {
    const AT_ENV: &str = "the @.env file's content never does";
    const MARKED: &str = "the probe call is denied with EnvCloak's marker";
    const RULE: &str = "the call EnvCloak's host rule covers is refused";
    const NOTHING: &str = "nothing it would have read reaches the model";
    const BY_RULE: &str = "the host's own permission settings, under EnvCloak's deny rule";
    const BY_HOOK: &str = "EnvCloak's hook, with its marker";
    let Some(mut s) = site(Host::ClaudeCode, "M2-09 @.env (Claude Code)") else {
        return;
    };
    let failed = |p: &probe::SurfaceProbe| -> Vec<&'static str> {
        p.checks
            .iter()
            .filter(|c| !c.passed)
            .map(|c| c.name)
            .collect()
    };
    // What refused the rule's case, named from the probe's fixed list.
    let rule_by = |p: &probe::SurfaceProbe| -> &'static str {
        p.checks
            .iter()
            .find(|c| c.name == RULE)
            .map_or("not run", |c| c.why)
    };
    let hook_by = |p: &probe::SurfaceProbe| -> &'static str {
        p.checks
            .iter()
            .find(|c| c.name == MARKED)
            .map_or("not run", |c| if c.passed { BY_HOOK } else { c.why })
    };
    let path = s.h.home.home().join(".claude/settings.json");
    let with = s.probe(&[Surface::FileRead], false, true);
    let with = with.surface(Surface::FileRead).unwrap().clone();
    assert_eq!(with.outcome, Outcome::Passed, "{with:?}");
    assert_eq!(rule_by(&with), BY_RULE, "{with:?}");
    assert_eq!(hook_by(&with), BY_HOOK, "{with:?}");

    let mut v: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    v["permissions"]["deny"]
        .as_array_mut()
        .unwrap()
        .retain(|r| r.as_str() != Some(envcloak_agents::hosts::claude::READ_DENY));
    std::fs::write(&path, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
    let without = s.probe(&[Surface::FileRead], false, true);
    let without = without.surface(Surface::FileRead).unwrap().clone();
    assert_eq!(without.outcome, Outcome::Failed, "{without:?}");
    assert_eq!(
        failed(&without),
        [AT_ENV],
        "without the deny rule: {without:?}"
    );
    assert_eq!(rule_by(&without), BY_HOOK, "{without:?}");

    remove_hook(
        &path,
        "PreToolUse",
        Some(envcloak_agents::hosts::claude::TOOL_MATCHER),
    );
    let neither = s.probe(&[Surface::FileRead], false, true);
    let neither = neither.surface(Surface::FileRead).unwrap().clone();
    let failed_neither = failed(&neither);
    assert!(
        failed_neither.contains(&MARKED)
            && failed_neither.contains(&RULE)
            && failed_neither.contains(&NOTHING),
        "without the deny rule or the hook: {neither:?}"
    );
    println!(
        "measurement: Claude Code {} {}: as installed, Read of the project's .env refused by: \
         {}; of a .env outside the working directory: {}; without the Read(**/.env*) deny \
         rule: {} and {}; without the rule or EnvCloak's file-tool hook: {} and {} (the file \
         reached the model: {})",
        s.agent.installed.pin.version,
        os(),
        rule_by(&with),
        hook_by(&with),
        rule_by(&without),
        hook_by(&without),
        rule_by(&neither),
        hook_by(&neither),
        failed_neither.contains(&NOTHING),
    );
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

/// Codex reports a prompt hook's block naming no hook: beside a prompt hook
/// of the person's, in the file it reads hooks from, the block is not
/// known to be EnvCloak's and the prompt probe fails through its witness,
/// though the token is kept from the model (the class of the verifier's
/// round-2 finding: a refusal taken as EnvCloak's without its provenance).
/// Without that hook, the control, it passes.
///
/// Mutation checked: the witness counted whatever hook gave it (`ours`
/// answering true for Codex): the probe passes and this fails.
#[test]
fn codex_block_beside_another_prompt_hook_is_not_counted() {
    const REPORTED: &str = "the host reports EnvCloak's hook blocked the prompt";
    let Some(mut s) = site(Host::Codex, "M2-09 another prompt hook (Codex)") else {
        return;
    };
    let file = s.agent.codex_home().join("hooks.json");
    let installed = std::fs::read(&file).unwrap();
    let mut v: Value = serde_json::from_slice(&installed).unwrap();
    v["hooks"]["UserPromptSubmit"]
        .as_array_mut()
        .unwrap()
        .push(json!({"hooks": [{"type": "command", "command": "/usr/bin/true"}]}));
    std::fs::write(&file, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
    let report = s.probe(&[Surface::PromptToModel], false, true);
    let p = report.surface(Surface::PromptToModel).unwrap().clone();
    assert_eq!(p.outcome, Outcome::Failed, "{p:?}");
    let failed: Vec<(&str, &str)> = p
        .checks
        .iter()
        .filter(|c| !c.passed)
        .map(|c| (c.name, c.why))
        .collect();
    assert_eq!(
        failed,
        [(
            REPORTED,
            "a prompt hook blocked it, not known to be EnvCloak's"
        )],
        "{p:?}"
    );
    std::fs::write(&file, &installed).unwrap();
    let report = s.probe(&[Surface::PromptToModel], false, true);
    let p = report.surface(Surface::PromptToModel).unwrap();
    assert_eq!(p.outcome, Outcome::Passed, "the control: {p:?}");
    s.h.assert_swept("M2-09 another prompt hook (Codex)");
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
    // The settings the stand-in's home holds, as EnvCloak's installer
    // leaves them: its `Read(**/.env*)` deny rule, which the stand-in's
    // `rule` mode acts out; a mode's `settings` in their place.
    let settings = mode.get("settings").cloned().unwrap_or_else(
        || json!({"permissions": {"deny": [envcloak_agents::hosts::claude::READ_DENY]}}),
    );
    std::fs::create_dir_all(home.join(".claude")).unwrap();
    std::fs::write(home.join(".claude/settings.json"), settings.to_string()).unwrap();
    Fake {
        _dir: dir,
        root,
        home,
        project,
    }
}

fn fake_probe(mode: &Value) -> ProbeReport {
    fake_probe_with(mode, false)
}

/// An approver for the stand-in, whose `run_with_secrets` asks no daemon.
struct Yes;

impl Approver for Yes {
    fn approve(&self, _: Instant, _: &AtomicBool) -> Result<(), String> {
        Ok(())
    }
}

/// The stand-in probed on every surface and, with `server`, for EnvCloak's
/// server (with an approver and a sentinel project, which the surface
/// probes then do not have: the output probe needs a terminal).
fn fake_probe_with(mode: &Value, server: bool) -> ProbeReport {
    let f = fake(mode);
    let yes = Yes;
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
        sentinel_project: server.then(|| f.root.join("sentinel")),
        output: None,
        approver: server.then_some(&yes as &dyn Approver),
        run_limit: Duration::from_secs(60),
    };
    let host = ProbeHost {
        host: Agent::ClaudeCode,
        exe: PathBuf::from(env!("CARGO_BIN_EXE_ec-fake-host")),
        version: "2.1.280".to_owned(),
    };
    if server {
        probe::run_surfaces(&host, &home, &HostFlags::default(), &[], true)
    } else {
        probe::run(&host, &home, &HostFlags::default())
    }
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
        Probed::Current(&r.record()),
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
        Probed::Current(&r.record()),
    );
    for s in c.surfaces.iter().take(5) {
        assert_eq!(s.probe, Outcome::Failed, "{s}");
        assert_ne!(s.state, State::Active, "{s}");
    }
}

/// Each control failing alone, and each probe failing alone, gives that
/// surface `failed` (through the check that failed), and its state never
/// `active`.
///
/// Mutations checked: the prompt probe without the host's report of the
/// block (`reported && ours` replaced by `true`): the run that ends
/// without sending anything (`prompt: drop`) passes and this fails; the
/// session's next turn without the control's (`reached(&rc.requests,
/// &ctl)` dropped): a fresh session after the block passes and this
/// fails; the transcript without its sweep's completeness (`swept.complete`
/// replaced by `true`, the verifier's round-2 finding): the locked store
/// and the linked one pass and this fails.
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
        // A host that keeps no session cannot be resumed: the probe's
        // session is not found, and both fail through that control.
        Case {
            mode: json!({"persist": "none"}),
            failed: &[Surface::PromptToModel, Surface::Transcript],
            check: "the control's session is found in the host's store",
        },
        Case {
            mode: json!({"session": "lost"}),
            failed: &[Surface::PromptToModel, Surface::Transcript],
            check: "the control's session is found in the host's store",
        },
        // Codex's finding: only the probe's run ends without sending
        // anything, and without the host reporting a block.
        Case {
            mode: json!({"prompt": "drop"}),
            failed: &[Surface::PromptToModel, Surface::Transcript],
            check: "the host reports EnvCloak's hook blocked the prompt",
        },
        // Another hook's block, without EnvCloak's marker.
        Case {
            mode: json!({"prompt": "other"}),
            failed: &[Surface::PromptToModel, Surface::Transcript],
            check: "the host reports EnvCloak's hook blocked the prompt",
        },
        // The session does not go on after the block.
        Case {
            mode: json!({"resume": "fresh"}),
            failed: &[Surface::PromptToModel, Surface::Transcript],
            check: "the session goes on after the block, the control's turn in it",
        },
        // A store that cannot be read whole, or one behind a link out of
        // the stores that holds the blocked prompt: no clean sweep.
        Case {
            mode: json!({"locked": true}),
            failed: &[Surface::Transcript],
            check: "the host's stores were read whole",
        },
        Case {
            mode: json!({"persist": "linked"}),
            failed: &[Surface::Transcript],
            check: "the host's stores were read whole",
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
                // The transcript fails through its own check where the
                // case is the transcript's, else through the prompt's.
                let own = case.failed == [Surface::Transcript];
                assert!(
                    s.checks.iter().any(|c| !c.passed && c.name == case.check)
                        || (surface == Surface::Transcript && !own),
                    "{}: {surface:?}: {s:?}",
                    case.mode
                );
                if surface == Surface::Transcript && own {
                    let failed: Vec<&str> = s
                        .checks
                        .iter()
                        .filter(|c| !c.passed)
                        .map(|c| c.name)
                        .collect();
                    assert_eq!(failed, [case.check], "{}: {s:?}", case.mode);
                }
            }
        }
        let c = coverage::assemble(
            Agent::ClaudeCode,
            "2.1.280",
            &installed(),
            Probed::Current(&r.record()),
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

/// The sentinel probe on the stand-in: it passes only when the host's own
/// shell ran its control (its marker came back), wrote where its sandbox
/// lets it, was denied the write beside the sentinel's, and the command
/// `run_with_secrets` started made that write. A shell that never ran (a
/// sandbox that cannot start, as Claude Code's inside CI's user namespace;
/// a hook refusing the command before it runs) fails it, never reads as a
/// denied write, and the server line `agents status` gives from the
/// record says `probe=failed` (Codex F-133).
///
/// Mutations checked: the shell's run witness dropped (`control_ran` taken
/// from the run being usable alone): the dead sandbox passes and this
/// fails; on the pinned Claude Code the same mutation passed the
/// verifier's `printenv`-prefixed control, which EnvCloak's hook refused
/// before it ran. The allowed write dropped (`allowed_write` set to
/// `control_ran`): the closed sandbox passes and this fails.
#[test]
fn a_stand_in_sentinel_needs_its_shell_to_run_and_write() {
    const RAN: &str = "the host's own shell ran the control";
    const WROTE: &str = "the host's own shell wrote where its sandbox lets it";
    const DENIED: &str = "the host's own shell is denied the write beside the sentinel's";
    const MADE: &str = "a command run_with_secrets started made the write";
    let r = fake_probe_with(&json!({}), true);
    assert_eq!(r.server.outcome, Outcome::Passed, "{:#?}", r.server);
    assert!(r.server.control_ran && r.server.allowed_write && r.server.control_denied);
    assert_eq!(r.server.sentinel, Sentinel::Appeared);
    let line = |r: &ProbeReport| {
        coverage::assemble(
            Agent::ClaudeCode,
            "2.1.280",
            &installed(),
            Probed::Current(&r.record()),
        )
        .envcloak_server
        .map(|l| l.to_string())
        .unwrap_or_default()
    };
    assert_eq!(
        line(&r),
        "needs_host_approval; outside_host_sandbox (probe=passed, sentinel appeared)"
    );
    for (mode, failed) in [
        (json!({"sandbox": "dead"}), &[RAN, WROTE, DENIED][..]),
        (json!({"sandbox": "closed"}), &[WROTE, DENIED][..]),
        (json!({"sandbox": "open"}), &[DENIED][..]),
        (json!({"server": "inside"}), &[MADE][..]),
    ] {
        let r = fake_probe_with(&mode, true);
        assert_eq!(r.server.outcome, Outcome::Failed, "{mode}: {:#?}", r.server);
        let got: Vec<&str> = r
            .server
            .checks
            .iter()
            .filter(|c| !c.passed)
            .map(|c| c.name)
            .collect();
        assert_eq!(got, failed, "{mode}: {:#?}", r.server);
        assert!(line(&r).contains("(probe=failed"), "{mode}: {}", line(&r));
    }
    // A shell that never ran is not a denied write.
    let r = fake_probe_with(&json!({"sandbox": "dead"}), true);
    assert!(
        !r.server.control_ran && !r.server.control_denied,
        "{:#?}",
        r.server
    );
    // Pointed at a dead base URL, nothing ran: failed through its control.
    let r = fake_probe_with(&json!({"url": "dead"}), true);
    assert_eq!(r.server.outcome, Outcome::Failed);
    assert!(r.server.checks.iter().any(|c| c.control && !c.passed));
}

/// The file read's hook case is a call EnvCloak's host rule leaves to the
/// hook: with the stand-in's `Read(**/.env*)` rule refusing the project's
/// `.env` first (as the pinned Claude Code does), the probe still passes
/// on the hook's marker for the `.env` outside the working directory, and
/// the rule's case passes on the rule's refusal; with the rule off, the
/// hook refuses both; with the hook's marker gone, the probe fails
/// through its hook case alone.
///
/// Mutations checked: the hook's case reading the project's `.env` (the
/// `ELSEWHERE` folder's replaced by the project in `file_read`): the rule
/// refuses it without the marker and this fails; the rule's provenance
/// not checked (`rule_is_ours` answering true): the person's own deny
/// rule passes the rule's case and this fails.
#[test]
fn a_stand_in_file_read_takes_the_hook_where_the_rule_leaves_it() {
    const MARKED: &str = "the probe call is denied with EnvCloak's marker";
    const RULE: &str = "the call EnvCloak's host rule covers is refused";
    let failed = |r: &ProbeReport| -> Vec<&'static str> {
        r.surface(Surface::FileRead)
            .unwrap()
            .checks
            .iter()
            .filter(|c| !c.passed)
            .map(|c| c.name)
            .collect()
    };
    for mode in [json!({}), json!({"rule": "off"})] {
        let r = fake_probe(&mode);
        let file = r.surface(Surface::FileRead).unwrap();
        assert_eq!(file.outcome, Outcome::Passed, "{mode}: {file:?}");
        assert!(file.checks.iter().any(|c| c.name == RULE && c.passed));
    }
    let r = fake_probe(&json!({"tools": "plain"}));
    assert_eq!(failed(&r), [MARKED], "{:?}", r.surface(Surface::FileRead));
    // Both the rule and the hook gone: the file reaches the model.
    let r = fake_probe(&json!({"rule": "off", "tools": "run"}));
    let f = failed(&r);
    assert!(f.contains(&MARKED) && f.contains(&RULE), "{f:?}");
    // The host's words name no rule: beside a deny rule of the person's
    // for the file tools, or without EnvCloak's, the refusal is not known
    // to be EnvCloak's rule's, and the rule's case fails (the verifier's
    // round-2 finding, for M2-28's machines).
    let read_deny = envcloak_agents::hosts::claude::READ_DENY;
    for settings in [
        json!({"permissions": {"deny": [read_deny, "Read(./secrets/**)"]}}),
        json!({}),
    ] {
        let r = fake_probe(&json!({"settings": settings}));
        assert_eq!(
            failed(&r),
            [RULE],
            "{settings}: {:?}",
            r.surface(Surface::FileRead)
        );
        let why = r
            .surface(Surface::FileRead)
            .unwrap()
            .checks
            .iter()
            .find(|c| c.name == RULE)
            .unwrap()
            .why;
        assert_eq!(
            why,
            "the host refused it under a rule not known to be EnvCloak's"
        );
    }
}

/// A host that does not expand `@` mentions under `-p`: the file read's
/// outcome is its other cases', and the `@` case is reported apart, `at_
/// mention skipped`, in the report and in what `agents status` says, never
/// as a check that passed.
///
/// Mutation checked: the case kept as a passed check (`mentions`
/// returning a passing check and no skipped case): nothing says the case
/// was not run and this fails.
#[test]
fn a_mention_the_host_does_not_expand_is_reported_skipped() {
    let r = fake_probe(&json!({"mention": "none"}));
    let file = r.surface(Surface::FileRead).unwrap();
    assert_eq!(file.outcome, Outcome::Passed, "{file:?}");
    assert_eq!(file.skipped, [coverage::Case::AtMention], "{file:?}");
    assert!(
        !file.checks.iter().any(|c| c.name.contains('@')),
        "{file:?}"
    );
    let c = coverage::assemble(
        Agent::ClaudeCode,
        "2.1.280",
        &installed(),
        Probed::Current(&r.record()),
    );
    assert_eq!(
        c.surface(Surface::FileRead).map(ToString::to_string),
        Some(
            "degraded (fails_open_on_timeout, workspace_untrusted; probe=passed, at_mention \
             skipped)"
                .to_owned()
        )
    );
    // The control: a host that expands them runs the case.
    let r = fake_probe(&json!({}));
    assert!(r.surface(Surface::FileRead).unwrap().skipped.is_empty());
}

/// A host that also sends the model a request it does not serve (an
/// unknown route) makes every run of its probes unfit to read: each
/// probe fails, through a control, never passes (the verifier's round-2
/// finding: nothing failed without `usable`'s check of the model's run).
///
/// Mutation checked: `HostRun::usable` without `self.clean`: every probe
/// passes and this fails.
#[test]
fn a_stand_in_the_model_does_not_wholly_serve_fails_every_probe() {
    let r = fake_probe(&json!({"stray": true}));
    for surface in [
        Surface::PromptToModel,
        Surface::Transcript,
        Surface::FileRead,
        Surface::Shell,
        Surface::Mcp,
    ] {
        let s = r.surface(surface).unwrap();
        assert_eq!(s.outcome, Outcome::Failed, "{surface:?}: {s:?}");
        assert!(
            s.checks.iter().any(|c| c.control && !c.passed),
            "{surface:?}: {s:?}"
        );
    }
    assert!(r.runs.iter().all(|run| !run.clean), "{:?}", r.runs);
    // The control: the same host without the stray request passes.
    let r = fake_probe(&json!({}));
    assert!(r.runs.iter().all(|run| run.clean), "{:?}", r.runs);
}

/// The output probe on the stand-in, with an emitter in place of
/// `envcloak run`'s command and a runner in place of `envcloak`: it
/// passes only when the emitter's marker reached the model and no value
/// in any form did. A value as it is, base64 or hexadecimal fails it; an
/// emitter that prints no marker, or a run `envcloak` refused, fails it
/// through its control (Codex review of M2-09: no test made the output
/// probe or its control fail).
///
/// Mutations checked: the leak check dropped (`!leaked` replaced by
/// `true`): the three leaks pass and this fails; the control dropped
/// (`ran` replaced by `true`): the emitter with no marker and the refused
/// run pass and this fails.
#[test]
fn a_stand_in_output_probe_needs_its_marker_and_no_value() {
    const VALUE: &str = "ecp-value-6d2a-91c4-0e7b-55f3";
    const MARKER: &str = "ecp-emit-3c1d-8a02";
    let b64 = base64_of(VALUE.as_bytes());
    let hex: String = VALUE.bytes().map(|b| format!("{b:02x}")).collect();
    let (a, b) = MARKER.split_at(MARKER.len() / 2);
    let marker = format!("printf '%s%s\\n' '{a}' '{b}'\n");
    let cases: [(&str, String, bool, Option<&str>); 6] = [
        ("redacted", marker.clone(), true, None),
        (
            "the value as it is",
            format!("{marker}printf '%s\\n' '{VALUE}'\n"),
            true,
            Some("no value reached the model in any form"),
        ),
        (
            "base64",
            format!("{marker}printf '%s\\n' '{b64}'\n"),
            true,
            Some("no value reached the model in any form"),
        ),
        (
            "hexadecimal",
            format!("{marker}printf '%s\\n' '{hex}'\n"),
            true,
            Some("no value reached the model in any form"),
        ),
        (
            "no marker",
            "printf '%s\\n' 'nothing here'\n".to_owned(),
            true,
            Some("the emitter ran under envcloak run and its marker reached the model"),
        ),
        (
            "a run envcloak refused",
            marker,
            false,
            Some("the emitter ran under envcloak run and its marker reached the model"),
        ),
    ];
    for (name, emitter, runs, failing) in cases {
        let r = fake_output_probe(&format!("#!/bin/sh\n{emitter}"), runs, VALUE, MARKER);
        let out = r.surface(Surface::Output).unwrap();
        let failed: Vec<&str> = out
            .checks
            .iter()
            .filter(|c| !c.passed)
            .map(|c| c.name)
            .collect();
        match failing {
            None => assert_eq!(out.outcome, Outcome::Passed, "{name}: {out:?}"),
            Some(check) => {
                assert_eq!(out.outcome, Outcome::Failed, "{name}: {out:?}");
                assert_eq!(failed, [check], "{name}: {out:?}");
            }
        }
        assert_eq!(
            r.runs
                .iter()
                .find(|run| run.name == "output")
                .and_then(|run| run.approved),
            Some(true),
            "{name}"
        );
    }
}

/// Base64, standard alphabet, padded.
fn base64_of(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(A[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The stand-in probed on its output surface: `emitter` the command a
/// stand-in `envcloak` runs (`runs`), or refuses with
/// `approval_required` (not `runs`); the project binds `value`.
fn fake_output_probe(emitter: &str, runs: bool, value: &str, marker: &str) -> ProbeReport {
    let f = fake(&json!({}));
    let project = f.root.join("acme");
    std::fs::create_dir_all(&project).unwrap();
    write_script(&project.join("emit"), emitter);
    let runner = f.root.join("bin").join("envcloak");
    std::fs::create_dir_all(runner.parent().unwrap()).unwrap();
    write_script(
        &runner,
        if runs {
            "#!/bin/sh\nwhile [ \"$1\" != \"--\" ]; do shift; done\nshift\nexec \"$@\"\n"
        } else {
            "#!/bin/sh\necho 'envcloak: approval_required request=x' >&2\nexit 125\n"
        },
    );
    let yes = Yes;
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
        envcloak: runner,
        mcp_fixture: None,
        sentinel_project: None,
        output: Some(OutputFixture {
            project,
            command: vec!["./emit".to_owned()],
            marker: marker.to_owned(),
            values: vec![zeroize::Zeroizing::new(value.as_bytes().to_vec())],
        }),
        approver: Some(&yes),
        run_limit: Duration::from_secs(60),
    };
    let host = ProbeHost {
        host: Agent::ClaudeCode,
        exe: PathBuf::from(env!("CARGO_BIN_EXE_ec-fake-host")),
        version: "2.1.280".to_owned(),
    };
    probe::run_surfaces(
        &host,
        &home,
        &HostFlags::default(),
        &[Surface::Output],
        false,
    )
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
