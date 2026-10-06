//! `envcloak agents install | uninstall | status | migrate-mcp` (SPEC §6.6,
//! §7, §7.1, §7.2).
//!
//! - `install [--global] [--project] [--agent ID]...
//!   [--consent-sandbox-sockets] [--yes] [--json]` teaches the agent hosts
//!   EnvCloak (M2 plan M2-08; `envcloak_agents::install`): for each
//!   tier-1 host found on `PATH` (Claude Code and Codex, or those named
//!   with `--agent`), the instruction block, the hooks, the deny rules and
//!   sandbox settings, and EnvCloak's MCP server; with `--project`, the
//!   instruction block in the project's own instruction file. Without
//!   `--yes` it lists every file and every change and writes nothing.
//!   With it, the daemon must be running and unlocked: every file is backed
//!   up, as a backup v2 the daemon seals, before it is changed.
//! - `uninstall [--global] [--project] [--agent ID]... [--yes] [--json]`
//!   takes out exactly what `install` added.
//! - `status [--json]` (SPEC §7.1; M2 plan M2-09) reports, for each
//!   tier-1 host found on `PATH` (and the hosts whose documentation leaves
//!   a surface no contract, `envcloak_agents::coverage::STATIC_HOSTS`),
//!   its version and six surfaces, each with its state, its reason
//!   tokens and its probe outcome, failed probes first, and EnvCloak's
//!   own MCP server line (`outside_host_sandbox`, with the sentinel
//!   probe's evidence). States rest on the probe results kept for this
//!   host binary (its SHA-256), version and probe context (the
//!   fingerprint of the configuration facts, every configuration file the
//!   host reads for a session in the working directory, the parts of the
//!   files it rewrites that register EnvCloak's server, the programs
//!   EnvCloak's hooks run and this `envcloak` build;
//!   `<data>/agents/coverage.json`), recomputed here from the person's
//!   real configuration, read-only: a result for anything else,
//!   or when the binary or the context cannot be wholly identified, reads
//!   `unverified (changed_since_probe)`, none at all `unverified
//!   (not_probed)`, and only a passed probe that nothing degrades reads
//!   `active`. A host told only by the name of an executable on `PATH`
//!   (Copilot CLI, OpenCode, Goose) is said to be not identified
//!   (`identified_by`). Exit 0 once the report is printed. Before it, a double
//!   install is refused (exit 1, `double_install`): EnvCloak's Claude
//!   Code plugin enabled (in the user's settings, or the working
//!   directory's project or local settings) while EnvCloak's own hooks
//!   (in one of those files) or an MCP server named `envcloak` (in
//!   `.claude.json`) are there too, so each hook runs twice; the message
//!   names both (M2-08).
//! - `status --probe [--agent ID]... [--json]` (M2 plan M2-28) runs the
//!   coverage probes on this machine first, for each tier-1 host found on
//!   `PATH` (or those named), and then prints the report above, which
//!   rests on what they found. Each host is probed in a probe home of its
//!   own (`envcloak_agents::probe::local`): a short private directory under
//!   `/tmp`, a probe-only daemon and throwaway vault, EnvCloak installed
//!   there by this build, the person's own host binary run there against
//!   the scripted model, and the probe's requests approved from this
//!   process's own terminal with the probe passphrase (with no terminal,
//!   or run by an agent, nothing is approved and the output probe reads
//!   `probe_needs_terminal`). The person's own daemon is never connected
//!   to, and their files are only read: the switches that degrade a
//!   surface are read from them, as `status` reads them. A host version
//!   the scripted model is not qualified for is not probed: every outcome
//!   is `not_qualified`, and the line says which versions CI results are
//!   published for. A result is kept (`<data>/agents/coverage.json`) only
//!   under the identity it measured: the binary the person's `PATH` leads
//!   to and the person's configuration, unchanged while the probe ran, with
//!   their hooks running this `envcloak` and their configuration of the
//!   probe home's shape (`ConfigSet::shape`: EnvCloak's entries as written,
//!   the facts the probes act out, the stores); otherwise the report says
//!   why it was not kept. Each host is asked its version in a probe home of
//!   its own too, never with the person's `HOME`. Exit 0 once the report is printed; 1 with
//!   `probe_unavailable` when a host's probe could not be set up (the
//!   programs it needs are not beside this `envcloak`, or its probe home,
//!   daemon, vault or install could not be made), after the report.
//! - `migrate-mcp` (M2-20) is not in this build: it exits 125 with
//!   `not_in_this_build`, reading no argument.
//!
//! Exit 0 when every change was made (or was there already); otherwise 1
//! with `agents_incomplete`, after the report says which file was refused
//! and why. No argument is echoed.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::SystemTime;

use envcloak_agents::coverage::{
    self, Cache, ConfigSet, Coverage, Identity, ProbeStatus, Probed, Surface,
};
use envcloak_agents::detect::{self, DetectError};
use envcloak_agents::hook::Host;
use envcloak_agents::install::{
    self, Context, HostReport, Note, Options, Plan, Report, Step, StepKind, StepResult, host_name,
};
use envcloak_agents::locations::Locations;
use envcloak_agents::probe;
use envcloak_agents::writer::{DaemonBackups, Journal, Outcome, StateFile, Writer};
use envcloak_client::claims::claims;
use envcloak_client::fail::{FAILURE, Failure, refuse_if_traced, usage};
use envcloak_client::render::print_json;
use envcloak_policy::{escape_for_display, find_manifest};
use serde_json::{Value, json};

use super::require_unlocked;

const USAGE_TEXT: &str = "envcloak agents install [--global] [--project] [--agent claude-code|codex]... [--consent-sandbox-sockets] [--yes] [--json]
       envcloak agents uninstall [--global] [--project] [--agent claude-code|codex]... [--yes] [--json]
       envcloak agents status [--json]
       envcloak agents status --probe [--agent claude-code|codex]... [--json]
       envcloak agents migrate-mcp (not in this build)";

#[derive(Debug, Default)]
struct Args {
    opts: Options,
    project: bool,
    yes: bool,
    json: bool,
}

fn parse(args: &[&str], install: bool) -> Option<Args> {
    let mut a = Args::default();
    let mut it = args.iter();
    while let Some(&arg) = it.next() {
        match arg {
            "--global" if !a.opts.global => a.opts.global = true,
            "--project" if !a.project => a.project = true,
            "--agent" => {
                let h = Host::from_id(it.next()?)?;
                if a.opts.hosts.contains(&h) {
                    return None;
                }
                a.opts.hosts.push(h);
            }
            "--consent-sandbox-sockets" if install && !a.opts.consent_sockets => {
                a.opts.consent_sockets = true;
            }
            "--yes" if !a.yes => a.yes = true,
            "--json" if !a.json => a.json = true,
            _ => return None,
        }
    }
    Some(a)
}

pub fn run(args: &[&str]) -> ExitCode {
    match args {
        ["status", rest @ ..] => run_status(rest),
        ["migrate-mcp", ..] => super::not_in_this_build("`envcloak agents migrate-mcp`"),
        [cmd @ ("install" | "uninstall"), rest @ ..] => {
            if rest == ["--help"] || rest == ["-h"] {
                println!("usage: {USAGE_TEXT}");
                return ExitCode::SUCCESS;
            }
            let install = *cmd == "install";
            let Some(a) = parse(rest, install) else {
                return usage(USAGE_TEXT);
            };
            // The agents' configs can hold literal keys (an `env` block,
            // an MCP server's `env`), and planning reads them: nothing is
            // read under a tracer (SPEC §5; the Codex review).
            if let Err(f) = refuse_if_traced() {
                return f.report(FAILURE);
            }
            let done = if install {
                run_install(a)
            } else {
                run_uninstall(a)
            };
            done.unwrap_or_else(|f| f.report(FAILURE))
        }
        _ => usage(USAGE_TEXT),
    }
}

/// `agents status [--json]`: the double-install check (M2 plan M2-08;
/// Codex review: a direct install followed by the plugin left both hook
/// sets and both servers, and nothing said so), then the coverage report
/// (M2-09).
fn run_status(args: &[&str]) -> ExitCode {
    if args.contains(&"--probe") {
        return status_probe(args);
    }
    let json = match args {
        [] => false,
        ["--json"] => true,
        ["--help"] | ["-h"] => {
            println!("usage: {USAGE_TEXT}");
            return ExitCode::SUCCESS;
        }
        _ => return usage(USAGE_TEXT),
    };
    // The settings it reads can hold literal keys (SPEC §5).
    if let Err(f) = refuse_if_traced() {
        return f.report(FAILURE);
    }
    if let Some(text) = double_install() {
        return Failure::new("double_install", text).report(FAILURE);
    }
    match coverage_report(&|host, path| detect::detect(host, path, &env)) {
        Ok(rows) => {
            print_coverage(&rows, json);
            ExitCode::SUCCESS
        }
        Err(f) => f.report(FAILURE),
    }
}

/// The parsed options of `status --probe`.
#[derive(Debug, Default, PartialEq, Eq)]
struct ProbeArgs {
    hosts: Vec<Host>,
    json: bool,
}

fn parse_probe(args: &[&str]) -> Option<ProbeArgs> {
    let mut a = ProbeArgs::default();
    let mut probe = false;
    let mut it = args.iter();
    while let Some(&arg) = it.next() {
        match arg {
            "--probe" if !probe => probe = true,
            "--json" if !a.json => a.json = true,
            "--agent" => {
                let h = Host::from_id(it.next()?)?;
                if a.hosts.contains(&h) {
                    return None;
                }
                a.hosts.push(h);
            }
            _ => return None,
        }
    }
    probe.then_some(a)
}

/// `agents status --probe [--agent ID]... [--json]`: see the module
/// documentation.
pub fn status_probe(args: &[&str]) -> ExitCode {
    let Some(a) = parse_probe(args) else {
        return usage(USAGE_TEXT);
    };
    // The settings it reads can hold literal keys, and it holds the probe
    // passphrase (SPEC §5).
    if let Err(f) = refuse_if_traced() {
        return f.report(FAILURE);
    }
    if let Some(text) = double_install() {
        return Failure::new("double_install", text).report(FAILURE);
    }
    match run_probe(&a) {
        Ok(code) => code,
        Err(f) => f.report(FAILURE),
    }
}

/// What `--probe` did for one host.
struct HostProbe {
    host: Host,
    version: Option<String>,
    /// The probe's run, or why it could not be set up.
    run: Result<probe::local::LocalRun, &'static str>,
    /// Whether its result is kept, or why not.
    kept: Result<(), &'static str>,
}

fn unavailable(message: &'static str) -> Failure {
    Failure::new("probe_unavailable", message)
}

fn run_probe(a: &ProbeArgs) -> Result<ExitCode, Failure> {
    let me = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|_| Failure::new("io", "the path of this envcloak could not be read"))?;
    let dir = me
        .parent()
        .ok_or_else(|| Failure::new("io", "the path of this envcloak could not be read"))?;
    let envcloakd = dir.join("envcloakd");
    let model = dir.join("envcloak-probe-model");
    if !envcloakd.is_file() || !model.is_file() {
        return Err(unavailable(
            "the probes need envcloakd and envcloak-probe-model installed beside this envcloak; \
             nothing was probed",
        ));
    }
    let mcp = Some(dir.join("envcloak-probe-mcp")).filter(|p| p.is_file());
    let me_sha = coverage::file_sha256(&me).unwrap_or_default();
    // Probe homes earlier runs left (a run killed before it removed its
    // own), whose runs have ended.
    let swept = probe::home::sweep(Path::new(probe::home::TMP));
    let locations = Locations::from_env().map_err(|_| {
        Failure::new(
            "no_home",
            "HOME is not set to an absolute path, so the agents' files cannot be found",
        )
    })?;
    let data_dir = envcloak_core::vault::VaultPaths::for_user()
        .map_err(|_| {
            Failure::new(
                "no_home",
                "HOME is not set to an absolute path, so EnvCloak's data directory cannot be found",
            )
        })?
        .data_dir;
    let cache_path = Cache::path(&data_dir);
    let path = env("PATH").unwrap_or_default();
    let cwd = working_dir()?;
    let claims = claims();
    let markers: Vec<(OsString, OsString)> = claims
        .iter()
        .filter_map(|m| env(m).map(|v| (OsString::from(m), v)))
        .collect();
    let person_socket = envcloak_ipc::RunPaths::for_user().ok().map(|p| p.socket);
    // The hosts are asked their versions in a probe home of their own, as
    // they are probed (Codex review of M2-28): a host, or a launcher in
    // its place, that reads or writes its home as it answers reaches
    // nothing of the person's, nor their working directory.
    let version_home =
        probe::home::ProbeHome::create_in(Path::new(probe::home::TMP), person_socket.as_deref())
            .map_err(|e| unavailable(e.message()))?;
    let mut version_env = version_home.env();
    version_env.push(("PATH".into(), path.clone()));
    let hosts: Vec<Host> = if a.hosts.is_empty() {
        install::TIER_1.to_vec()
    } else {
        a.hosts.clone()
    };
    let read = |host: Host| {
        ConfigSet::read(
            host,
            &locations,
            &coverage::claude_managed_dir(),
            &cwd,
            &env,
        )
    };
    let mut done: Vec<HostProbe> = Vec::new();
    let mut kept_any = false;
    let mut cache = Cache::load(&cache_path);
    for host in hosts {
        let d = match detect::detect_with(host, &path, &version_env) {
            Ok(d) => d,
            Err(DetectError::NotFound) if a.hosts.is_empty() => continue,
            Err(e) => {
                done.push(HostProbe {
                    host,
                    version: None,
                    run: Err(e.message()),
                    kept: Err("the host was not probed"),
                });
                continue;
            }
        };
        let exe_sha = std::fs::canonicalize(&d.exe)
            .ok()
            .and_then(|p| coverage::file_sha256(&p))
            .unwrap_or_default();
        let before = read(host).fingerprint(&me);
        let opts = probe::local::LocalOptions {
            envcloak: me.clone(),
            envcloakd: envcloakd.clone(),
            model_exe: model.clone(),
            mcp_fixture: mcp.clone(),
            path: probe_path(&d.exe, &me, &path),
            markers: markers.clone(),
            claims: claims.clone(),
            tmp: PathBuf::from(probe::home::TMP),
            person_socket: person_socket.clone(),
            run_limit: probe::local::RUN_LIMIT,
        };
        let host_exe = probe::ProbeHost {
            host,
            exe: d.exe.clone(),
            version: d.version.clone(),
        };
        let run = probe::local::probe_host(&host_exe, &opts);
        let after_set = read(host);
        let after = after_set.fingerprint(&me);
        let shape = after_set.shape(locations.home(), &me);
        let (run, kept) = match run {
            Ok(r) => {
                let person = probe::local::PersonIdentity {
                    exe_sha256: &exe_sha,
                    before: before.as_deref(),
                    after: after.as_deref(),
                    programs: &after_set.context.programs,
                    envcloak_sha256: &me_sha,
                    shape: shape.as_deref(),
                };
                let kept = match probe::local::keep_record(&r, &person) {
                    Ok(record) => {
                        cache.put(record);
                        kept_any = true;
                        Ok(())
                    }
                    Err(why) => Err(why.message()),
                };
                (Ok(r), kept)
            }
            Err(e) => (Err(e.message()), Err("the host was not probed")),
        };
        done.push(HostProbe {
            host,
            version: Some(d.version),
            run,
            kept,
        });
    }
    if kept_any && cache.store(&cache_path).is_err() {
        for h in &mut done {
            if h.kept.is_ok() {
                h.kept = Err("the result could not be written to EnvCloak's data directory");
            }
        }
    }
    let rows = coverage_report(&|host, path| detect::detect_with(host, path, &version_env));
    // Its own, emptied whatever was said: nothing of it is the person's.
    let removed = version_home.remove().is_ok();
    let rows = rows?;
    if !removed {
        return Err(unavailable(
            "the probe home the hosts were asked their versions in could not be removed; the \
             next run removes it",
        ));
    }
    print_probes(&done, &swept, &rows, a.json);
    if done.iter().any(|h| h.run.is_err()) {
        return Err(unavailable(
            "a host's probe could not be set up, so it was not probed; the lines above say which \
             and why",
        ));
    }
    Ok(ExitCode::SUCCESS)
}

/// `PATH` in the probe home: the directory the host was found in (where
/// its own commands, `claude mcp` and the like, are), this `envcloak`'s,
/// then the person's own absolute entries, in their order, each once.
fn probe_path(host: &Path, me: &Path, person: &std::ffi::OsStr) -> OsString {
    let mut dirs: Vec<PathBuf> = Vec::new();
    for d in [host.parent(), me.parent()].into_iter().flatten() {
        dirs.push(d.to_path_buf());
    }
    dirs.extend(
        std::env::split_paths(person)
            .filter(|d| d.is_absolute())
            .collect::<Vec<_>>(),
    );
    let mut seen: Vec<PathBuf> = Vec::new();
    for d in dirs {
        if !seen.contains(&d) {
            seen.push(d);
        }
    }
    std::env::join_paths(seen).unwrap_or_default()
}

/// One probe outcome as `--probe` prints it.
fn outcome_text(
    outcome: coverage::Outcome,
    why: &[coverage::Reason],
    skipped: &[coverage::Case],
) -> String {
    let mut out = outcome.name().to_owned();
    let mut parts: Vec<String> = why.iter().map(|r| r.name().to_owned()).collect();
    parts.extend(skipped.iter().map(|c| format!("{} skipped", c.name())));
    if !parts.is_empty() {
        out.push_str(&format!(" ({})", parts.join(", ")));
    }
    out
}

fn print_probes(done: &[HostProbe], swept: &probe::home::Swept, rows: &[Row], json: bool) {
    if json {
        let probes: Vec<Value> = done.iter().map(probe_json).collect();
        let home = Locations::from_env()
            .map(|l| l.home().to_path_buf())
            .unwrap_or_default();
        let agents: Vec<Value> = rows.iter().map(|r| row_json(&home, r)).collect();
        print_json(&json!({
            "probes": probes,
            "swept": {
                "removed": swept.removed,
                "in_use": swept.in_use,
                "failed": swept.failed.len(),
            },
            "agents": agents,
        }));
        return;
    }
    if swept.removed > 0 {
        println!(
            "Removed {} probe home(s) earlier runs that were stopped had left in {}.",
            swept.removed,
            probe::home::TMP
        );
    }
    for p in &swept.failed {
        println!(
            "Could not remove {}, a probe home an earlier run left: remove it yourself.",
            escape_for_display(&p.display().to_string())
        );
    }
    let width = Surface::ALL
        .iter()
        .map(|s| s.shown().len())
        .chain(["EnvCloak server".len()])
        .max()
        .unwrap_or(0);
    for h in done {
        let name = host_name(h.host);
        let version = h.version.as_deref().map(escape_for_display);
        match (&h.run, version) {
            (Err(why), Some(v)) => println!("{name} {v}: not probed: {why}"),
            (Err(why), None) => println!("{name}: not probed: {why}"),
            (Ok(r), Some(v)) if !r.qualification.is_qualified() => println!(
                "{name} {v}: {}",
                escape_for_display(&probe::qualify::not_qualified_line(
                    h.host,
                    &r.report.version,
                    &r.qualification
                ))
            ),
            (Ok(r), v) => {
                println!(
                    "{name} {}: probed on this machine, in a probe home of its own (your files \
                     were only read)",
                    v.unwrap_or_default()
                );
                for s in &r.report.surfaces {
                    println!(
                        "  {:width$}  {}",
                        s.surface.shown(),
                        outcome_text(s.outcome, &s.why, &s.skipped)
                    );
                }
                let server = &r.report.server;
                let sentinel = match server.sentinel {
                    coverage::Sentinel::NotRun => String::new(),
                    s => format!(" (sentinel {})", s.name().replace('_', " ")),
                };
                println!(
                    "  {:width$}  {}{sentinel}",
                    "EnvCloak server",
                    server.outcome.name()
                );
                if r.needs_terminal {
                    println!(
                        "  No approval was given: the probe needs a terminal of yours, with no \
                         agent in it, to approve its requests (probe_needs_terminal)."
                    );
                }
            }
        }
        match &h.kept {
            Ok(()) => println!("  Kept for this binary, version and configuration."),
            Err(why) => println!("  Not kept: {why}."),
        }
    }
    print_coverage(rows, false);
}

fn probe_json(h: &HostProbe) -> Value {
    let mut v = json!({
        "agent": h.host.id(),
        "name": host_name(h.host),
        "version": h.version,
        "kept": h.kept.is_ok(),
        "not_kept": h.kept.err(),
    });
    match &h.run {
        Err(why) => {
            v["probed"] = json!(false);
            v["not_probed"] = json!(why);
        }
        Ok(r) => {
            let q = &r.qualification;
            v["probed"] = json!(q.is_qualified());
            v["qualified"] = json!(q.is_qualified());
            v["qualified_versions"] = json!(q.qualified_versions());
            if !q.is_qualified() {
                v["message"] = json!(probe::qualify::not_qualified_line(
                    h.host,
                    &r.report.version,
                    q
                ));
            }
            v["surfaces"] = Value::Array(
                r.report
                    .surfaces
                    .iter()
                    .map(|s| {
                        json!({
                            "surface": s.surface,
                            "probe": s.outcome,
                            "why": s.why,
                            "skipped": s.skipped,
                            "checks": s.checks.iter().map(|c| json!({
                                "name": c.name,
                                "control": c.control,
                                "passed": c.passed,
                                "why": c.why,
                            })).collect::<Vec<_>>(),
                        })
                    })
                    .collect(),
            );
            v["server"] = json!({
                "probe": r.report.server.outcome,
                "sentinel": r.report.server.sentinel,
                "control_ran": r.report.server.control_ran,
                "allowed_write": r.report.server.allowed_write,
                "control_denied": r.report.server.control_denied,
            });
            v["flags"] = json!(r.report.flags);
            v["runs"] = json!(r.report.runs.len());
            v["approvals"] = json!(r.approvals);
            v["needs_terminal"] = json!(r.needs_terminal);
            v["home_removed"] = json!(r.home_removed);
        }
    }
    v
}

/// One host's row of the coverage report.
struct Row {
    name: &'static str,
    tier: u8,
    /// Where the host's executable is, when it is one EnvCloak found.
    exe: Option<PathBuf>,
    /// `current`, `changed_since_probe` or `not_probed`: what the states
    /// rest on.
    probed: ProbeStatus,
    /// How the host was told: `version` (its version line, read the way
    /// the catalog reads the host's), or `executable_name` (an executable
    /// of that name on `PATH`, which another program can have: the
    /// verifier's finding, `goose` is also a database migration tool).
    identified_by: Identity,
    coverage: Coverage,
}

/// The report: each tier-1 host found on `PATH`, then each host whose
/// documentation leaves a surface no contract.
/// How a host's version is asked: [`detect::detect`] for `status`,
/// [`detect::detect_with`] a probe home's environment for `status --probe`.
type Detector<'a> = dyn Fn(Host, &std::ffi::OsStr) -> Result<detect::Detected, DetectError> + 'a;

fn coverage_report(detect: &Detector<'_>) -> Result<Vec<Row>, Failure> {
    let locations = Locations::from_env().map_err(|_| {
        Failure::new(
            "no_home",
            "HOME is not set to an absolute path, so the agents' files cannot be found",
        )
    })?;
    let data_dir = envcloak_core::vault::VaultPaths::for_user()
        .map_err(|_| {
            Failure::new(
                "no_home",
                "HOME is not set to an absolute path, so EnvCloak's data directory cannot be found",
            )
        })?
        .data_dir;
    let cache = Cache::load(&Cache::path(&data_dir));
    let path = env("PATH").unwrap_or_default();
    // The configuration of a session in this directory, as each host reads
    // it from where it runs (Codex review of M2-09: the nearest manifest's
    // directory was read, and a nested directory's settings were not).
    let cwd = working_dir()?;
    let mut rows = Vec::new();
    for host in install::TIER_1 {
        let detected = detect(host, &path);
        let d = match detected {
            Ok(d) => d,
            Err(DetectError::NotFound) => continue,
            Err(_) => {
                // Found, but its version could not be read: no probe result
                // can be for it.
                let cs = ConfigSet::read(
                    host,
                    &locations,
                    &coverage::claude_managed_dir(),
                    &cwd,
                    &env,
                );
                let mut c = coverage::assemble(host, "", &cs, Probed::None);
                c.version = None;
                rows.push(Row {
                    name: host_name(host),
                    tier: 1,
                    exe: detect::find_on_path(detect::exe_name(host), &path),
                    probed: ProbeStatus::NotProbed,
                    identified_by: Identity::ExecutableName,
                    coverage: c,
                });
                continue;
            }
        };
        // A binary that cannot be read, or a context not wholly identified
        // (`ConfigSet::fingerprint`), is an identity no record matches:
        // an empty value never does (`ProbeRecord::is_for`).
        let sha = std::fs::canonicalize(&d.exe)
            .ok()
            .and_then(|p| coverage::file_sha256(&p))
            .unwrap_or_default();
        let cs = ConfigSet::read(
            host,
            &locations,
            &coverage::claude_managed_dir(),
            &cwd,
            &env,
        );
        let fingerprint = std::env::current_exe()
            .ok()
            .and_then(|me| cs.fingerprint(&me))
            .unwrap_or_default();
        let probed = cache.probed(host.id(), &sha, &d.version, &fingerprint);
        rows.push(Row {
            name: host_name(host),
            tier: 1,
            exe: Some(d.exe.clone()),
            probed: probed.status(),
            identified_by: Identity::Version,
            coverage: coverage::assemble(host, &d.version, &cs, probed),
        });
    }
    for (id, exe) in coverage::STATIC_HOSTS {
        let Some(found) = detect::find_on_path(exe, &path) else {
            continue;
        };
        let Some(surfaces) = coverage::static_rows(id) else {
            continue;
        };
        rows.push(Row {
            name: static_name(id),
            tier: 2,
            exe: Some(found),
            probed: ProbeStatus::NotProbed,
            identified_by: Identity::ExecutableName,
            coverage: Coverage {
                agent: id.to_owned(),
                version: None,
                surfaces,
                envcloak_server: None,
            }
            .sorted(),
        });
    }
    Ok(rows)
}

fn static_name(id: &str) -> &'static str {
    match id {
        "copilot" => "Copilot CLI",
        "opencode" => "OpenCode",
        "goose" => "Goose",
        _ => "an agent host",
    }
}

fn print_coverage(rows: &[Row], json: bool) {
    let home = Locations::from_env()
        .map(|l| l.home().to_path_buf())
        .unwrap_or_default();
    if json {
        let agents: Vec<Value> = rows.iter().map(|r| row_json(&home, r)).collect();
        print_json(&json!({ "agents": agents }));
        return;
    }
    if rows.is_empty() {
        println!("No agent host found on PATH.");
        return;
    }
    let width = Surface::ALL
        .iter()
        .map(|s| s.shown().len())
        .chain(["EnvCloak server".len()])
        .max()
        .unwrap_or(0);
    for r in rows {
        let exe = r
            .exe
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|n| escape_for_display(&n.to_string_lossy()))
            .unwrap_or_default();
        match &r.coverage.version {
            Some(v) => println!("{} {}", r.name, escape_for_display(v)),
            None if r.tier == 1 => println!("{} (version not read)", r.name),
            None => println!(
                "{} (not identified: an executable named {exe} is on PATH, which may be another \
                 program)",
                r.name
            ),
        }
        for s in &r.coverage.surfaces {
            println!("  {:width$}  {s}", s.surface.shown());
        }
        if let Some(line) = &r.coverage.envcloak_server {
            println!(
                "  {:width$}  {line}: commands that run_with_secrets starts run outside {}'s \
                 sandbox and hold the keys injected into them while they run",
                "EnvCloak server", r.name
            );
        }
        match r.probed {
            ProbeStatus::Current => {}
            ProbeStatus::ChangedSinceProbe => println!(
                "  The probe results kept are for another binary, version or configuration of \
                 {}: they are not used.",
                r.name
            ),
            ProbeStatus::NotProbed => println!(
                "  No probe has run on this machine for this binary, version and configuration \
                 of {}.",
                r.name
            ),
        }
    }
}

/// One host's row of the report, as `--json` has it.
fn row_json(home: &Path, r: &Row) -> Value {
    let mut v = serde_json::to_value(&r.coverage).unwrap_or(Value::Null);
    v["name"] = json!(r.name);
    v["tier"] = json!(r.tier);
    v["exe"] = json!(r.exe.as_ref().map(|p| shown(home, p)));
    v["probed"] = json!(r.probed.name());
    v["identified_by"] = json!(r.identified_by.name());
    v
}

/// What makes a double install, said as the refusal says it, or `None`:
/// EnvCloak's plugin enabled in a settings file Claude Code reads here (the
/// user's, the working directory's project or local settings) while
/// EnvCloak's own hooks are in one of them, or an MCP server named
/// `envcloak` is in Claude Code's `.claude.json`.
fn double_install() -> Option<String> {
    use envcloak_agents::hosts::claude;
    let locations = Locations::from_env().ok()?;
    let home = locations.home().to_path_buf();
    let mut files = vec![locations.claude_settings()];
    if let Ok(cwd) = std::env::current_dir() {
        files.push(cwd.join(".claude").join("settings.json"));
        files.push(cwd.join(".claude").join("settings.local.json"));
    }
    files.dedup();
    let read: Vec<(PathBuf, Value)> = files
        .into_iter()
        .filter_map(|p| install::read_json(&p).map(|v| (p, v)))
        .collect();
    let plugin: Vec<String> = read
        .iter()
        .filter(|(_, v)| claude::plugin_enabled(v))
        .map(|(p, _)| shown(&home, p))
        .collect();
    if plugin.is_empty() {
        return None;
    }
    let mut own: Vec<String> = read
        .iter()
        .filter(|(_, v)| claude::envcloak_hooks(v))
        .map(|(p, _)| format!("its own hooks in {}", shown(&home, p)))
        .collect();
    if install::claude_json_has_server(locations.claude_json()) {
        own.push(format!(
            "an MCP server named `envcloak` in {}",
            shown(&home, locations.claude_json())
        ));
    }
    if own.is_empty() {
        return None;
    }
    // `agents install` reads the user's settings for the plugin: what it
    // can resolve, and what only the person can.
    let user_plugin = install::read_json(&locations.claude_settings())
        .is_some_and(|v| claude::plugin_enabled(&v));
    let fix = if user_plugin {
        "Run `envcloak agents install`, which takes out its own hooks and server while the \
         plugin is enabled in your user settings, or disable the plugin"
    } else {
        "The plugin is enabled for this project only, while EnvCloak's own install covers every \
         project: disable the plugin here, or run `envcloak agents uninstall` and enable the \
         plugin in your user settings"
    };
    Some(format!(
        "EnvCloak's Claude Code plugin is enabled ({}) and EnvCloak is installed without it too \
         ({}): what both carry runs twice. {fix}",
        plugin.join(", "),
        own.join("; ")
    ))
}

/// The working directory, resolved.
fn working_dir() -> Result<PathBuf, Failure> {
    std::env::current_dir()
        .and_then(std::fs::canonicalize)
        .map_err(|_| Failure::new("io", "the working directory could not be read"))
}

/// The project's directory: where the nearest manifest is, or here.
fn project_dir() -> Result<PathBuf, Failure> {
    let cwd = || Failure::new("io", "the working directory could not be read");
    match find_manifest(Path::new(".")).map_err(|_| cwd())? {
        Some(m) => m.parent().map(Path::to_path_buf).ok_or_else(cwd),
        None => std::fs::canonicalize(".").map_err(|_| cwd()),
    }
}

fn env(k: &str) -> Option<OsString> {
    std::env::var_os(k)
}

fn context() -> Result<Context<'static>, Failure> {
    let locations = Locations::from_env().map_err(|_| {
        Failure::new(
            "no_home",
            "HOME is not set to an absolute path, so the agents' files cannot be found",
        )
    })?;
    let socket = envcloak_client::connect::run_paths()?.socket;
    let data_dir = envcloak_core::vault::VaultPaths::for_user()
        .map_err(|_| {
            Failure::new(
                "no_home",
                "HOME is not set to an absolute path, so EnvCloak's data directory cannot be found",
            )
        })?
        .data_dir;
    let exe = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|_| Failure::new("io", "the path of this envcloak could not be read"))?;
    // The hooks and the MCP entries name it by its link on PATH, which an
    // upgrade keeps, where there is one.
    let envcloak = install::stable_exe(&exe, &env("PATH").unwrap_or_default());
    Ok(Context {
        locations,
        envcloak,
        data_dir,
        socket,
        path: env("PATH").unwrap_or_default(),
        env: &env,
    })
}

/// A path as it is shown: the home as `~` (also when the path has the
/// home's directories resolved, as a registration's key has), and
/// escaped.
fn shown(home: &Path, p: &Path) -> String {
    let resolved = std::fs::canonicalize(home).ok();
    let rest = p
        .strip_prefix(home)
        .ok()
        .or_else(|| resolved.as_deref().and_then(|h| p.strip_prefix(h).ok()));
    let text = match rest {
        Some(rest) => format!("~/{}", rest.display()),
        None => p.display().to_string(),
    };
    escape_for_display(&text)
}

fn outcome_word(o: &Outcome) -> (&'static str, Option<&str>, Option<String>, Option<&str>) {
    match o {
        Outcome::Unchanged => ("unchanged", None, None, None),
        Outcome::Changed {
            created: true,
            backup,
        } => ("created", None, None, backup.as_deref()),
        Outcome::Changed { backup, .. } => ("changed", None, None, backup.as_deref()),
        Outcome::Removed { backup } => ("removed", None, None, backup.as_deref()),
        Outcome::Partial {
            made,
            backup,
            failed,
        } => (
            made.word(),
            Some(failed.name),
            Some(failed.message.clone()),
            backup.as_deref(),
        ),
        Outcome::Refused(r) => ("refused", Some(r.name), Some(r.message.clone()), None),
    }
}

fn result_json(home: &Path, r: &StepResult) -> Value {
    let (outcome, reason, message, backup) = outcome_word(&r.outcome);
    json!({
        "path": shown(home, &r.path),
        "what": r.what,
        "outcome": outcome,
        "reason": reason,
        "message": message,
        "backup": backup,
    })
}

fn notes_json(notes: &[Note]) -> Value {
    Value::Array(
        notes
            .iter()
            .map(|n| json!({"name": n.name, "text": n.text}))
            .collect(),
    )
}

fn host_line(
    h: Host,
    found: &Result<envcloak_agents::detect::Detected, envcloak_agents::detect::DetectError>,
) -> String {
    match found {
        Ok(d) => format!("{} {}", host_name(h), escape_for_display(&d.version)),
        Err(e) => format!("{}: {}", host_name(h), e.message()),
    }
}

/// A planned step as a person reads it: a change asked for and withheld
/// says so, and why.
fn step_line(home: &Path, s: &Step) -> String {
    match &s.kind {
        StepKind::Withheld(r) => format!(
            "{}: not written: {} ({}): {}",
            shown(home, &s.path),
            s.what,
            r.name,
            r.message
        ),
        _ => format!("{}: {}", shown(home, &s.path), s.what),
    }
}

fn step_json(home: &Path, s: &Step) -> Value {
    let withheld = match &s.kind {
        StepKind::Withheld(r) => json!({"reason": r.name, "message": r.message}),
        _ => Value::Null,
    };
    json!({"path": shown(home, &s.path), "what": s.what, "withheld": withheld})
}

fn print_plan(home: &Path, plan: &Plan, json: bool) {
    if json {
        let hosts: Vec<Value> = plan
            .hosts
            .iter()
            .map(|h| {
                json!({
                    "host": h.host.id(),
                    "version": h.found.as_ref().ok().map(|d| d.version.clone()),
                    "found": h.found.as_ref().map_or_else(|e| e.name(), |_| "installed"),
                    "changes": h.steps.iter().map(|s| step_json(home, s)).collect::<Vec<_>>(),
                    "notes": notes_json(&h.notes),
                })
            })
            .collect();
        let project = plan.project.as_ref().map(|p| {
            json!({
                "dir": escape_for_display(&p.dir.display().to_string()),
                "changes": p.steps.iter().map(|s| step_json(home, s)).collect::<Vec<_>>(),
                "notes": notes_json(&p.notes),
            })
        });
        print_json(&json!({"hosts": hosts, "project": project, "applied": false}));
        return;
    }
    for h in &plan.hosts {
        println!("{}", host_line(h.host, &h.found));
        for s in &h.steps {
            println!("  {}", step_line(home, s));
        }
        for n in &h.notes {
            println!("  note ({}): {}", n.name, n.text);
        }
    }
    if let Some(p) = &plan.project {
        println!(
            "Project {}",
            escape_for_display(&p.dir.display().to_string())
        );
        for s in &p.steps {
            println!("  {}", step_line(home, s));
        }
        for n in &p.notes {
            println!("  note ({}): {}", n.name, n.text);
        }
    }
    println!("Nothing was changed: run this again with --yes to write it.");
}

fn print_results(home: &Path, results: &[StepResult]) {
    for r in results {
        let (outcome, _, message, backup) = outcome_word(&r.outcome);
        let mut line = format!("  {}: {outcome}", shown(home, &r.path));
        if let Some(b) = backup {
            line.push_str(&format!(" (backup {})", escape_for_display(b)));
        }
        if let Some(m) = message {
            line.push_str(&format!(": {m}"));
        }
        println!("{line}");
    }
}

fn print_report(home: &Path, report: &Report, json: bool, install: bool, saved: bool) {
    if json {
        let hosts: Vec<Value> = report
            .hosts
            .iter()
            .map(|h: &HostReport| {
                json!({
                    "host": h.host.id(),
                    "version": h.found.as_ref().ok().map(|d| d.version.clone()),
                    "found": if install {
                        Value::from(h.found.as_ref().map_or_else(|e| e.name(), |_| "installed"))
                    } else {
                        Value::Null
                    },
                    "changes": h.results.iter().map(|r| result_json(home, r)).collect::<Vec<_>>(),
                    "notes": notes_json(&h.notes),
                })
            })
            .collect();
        let project = report.project.as_ref().map(|p| {
            json!({
                "dir": escape_for_display(&p.dir.display().to_string()),
                "changes": p.results.iter().map(|r| result_json(home, r)).collect::<Vec<_>>(),
                "notes": notes_json(&p.notes),
            })
        });
        print_json(&json!({
            "hosts": hosts,
            "project": project,
            "leftovers": report.leftovers.iter().map(|p| shown(home, p)).collect::<Vec<_>>(),
            "cleanup_unconfirmed": report
                .cleanup_unconfirmed
                .iter()
                .map(|p| shown(home, p))
                .collect::<Vec<_>>(),
            "applied": true,
            "complete": report.complete() && saved,
        }));
        return;
    }
    for h in &report.hosts {
        if install {
            println!("{}", host_line(h.host, &h.found));
        } else {
            println!("{}", host_name(h.host));
        }
        if h.results.is_empty() && install && h.found.is_ok() {
            println!("  nothing to change");
        }
        if !install && h.results.is_empty() {
            println!("  nothing of EnvCloak's to take out");
        }
        print_results(home, &h.results);
        for n in &h.notes {
            println!("  note ({}): {}", n.name, n.text);
        }
    }
    if let Some(p) = &report.project {
        println!(
            "Project {}",
            escape_for_display(&p.dir.display().to_string())
        );
        print_results(home, &p.results);
        for n in &p.notes {
            println!("  note ({}): {}", n.name, n.text);
        }
    }
    print_leftovers(home, &report.leftovers);
    print_unconfirmed(home, &report.cleanup_unconfirmed);
}

/// The places whose cleanup could not be confirmed (F123): places to look,
/// never files to remove.
fn print_unconfirmed(home: &Path, unconfirmed: &[PathBuf]) {
    for p in unconfirmed {
        println!(
            "Cleanup not confirmed: {}: EnvCloak could not look in this directory (or remove \
             the one it made), so what an earlier run left there may still be there; give \
             yourself access to it again and run this again",
            shown(home, p)
        );
    }
}

/// The files an earlier write left under EnvCloak's temporary names and
/// that were left there (lesson L-08: each may hold part of a config).
fn print_leftovers(home: &Path, leftovers: &[PathBuf]) {
    for p in leftovers {
        println!(
            "Left beside a config: {}: a file under EnvCloak's temporary name for it, which a \
             stopped run may have left holding part of that config (a literal key included); \
             EnvCloak could not tell it is its own, so it is still there: look at it, and \
             remove it",
            shown(home, p)
        );
    }
}

/// `envcloak init --agents-note`: the project scope's instruction block in
/// `dir`, written as `agents install --project --yes` writes it, its
/// results printed after init's report.
pub fn project_note(dir: &Path, json: bool) -> Result<(), Failure> {
    let ctx = context()?;
    let home = ctx.locations.home().to_path_buf();
    let plan = Plan {
        hosts: Vec::new(),
        project: Some(install::project_plan(dir, &install::TIER_1, &ctx.locations)),
    };
    let mut client = envcloak_client::connect::connect()?;
    require_unlocked(&mut client)?;
    let mut backups = DaemonBackups::new(client, claims());
    let (mut file, mut state) = StateFile::open(&ctx.data_dir).map_err(|r| state_failure(&r))?;
    let report = {
        let mut w = Writer {
            state: &mut state,
            journal: &mut file,
            backups: &mut backups,
            now: SystemTime::now(),
        };
        install::apply(&ctx, &plan, &mut w)
    };
    // The results are printed whatever the last save says: a file changed
    // above is reported as changed (L-08; the verifier's finding: the save
    // came first here, and its failure hid what was changed).
    let saved = file.save(&state);
    let complete = report.complete();
    let leftovers = report.leftovers;
    let unconfirmed = report.cleanup_unconfirmed;
    let (results, notes) = report
        .project
        .map(|p| (p.results, p.notes))
        .unwrap_or_default();
    if json {
        print_json(&json!({
            "agents_note": results.iter().map(|r| result_json(&home, r)).collect::<Vec<_>>(),
            "notes": notes_json(&notes),
            "leftovers": leftovers.iter().map(|p| shown(&home, p)).collect::<Vec<_>>(),
            "cleanup_unconfirmed": unconfirmed.iter().map(|p| shown(&home, p)).collect::<Vec<_>>(),
            "complete": saved.is_ok() && complete,
        }));
    } else {
        println!("Agent note:");
        print_results(&home, &results);
        for n in &notes {
            println!("  note ({}): {}", n.name, n.text);
        }
        print_leftovers(&home, &leftovers);
        print_unconfirmed(&home, &unconfirmed);
    }
    saved.map_err(|r| state_failure(&r))?;
    if !complete {
        return Err(incomplete());
    }
    Ok(())
}

fn incomplete() -> Failure {
    Failure::new(
        "agents_incomplete",
        "not every change was made: the lines above say which file was left as it was, and why",
    )
}

fn state_failure(r: &envcloak_agents::writer::Refusal) -> Failure {
    let _ = r.name;
    Failure::new("agents_incomplete", r.message.clone())
}

fn run_install(mut a: Args) -> Result<ExitCode, Failure> {
    if a.project {
        a.opts.project = Some(project_dir()?);
    }
    let ctx = context()?;
    let home = ctx.locations.home().to_path_buf();
    let plan = install::plan(&ctx, &a.opts);
    if !a.yes {
        print_plan(&home, &plan, a.json);
        return Ok(ExitCode::SUCCESS);
    }
    let mut client = envcloak_client::connect::connect()?;
    require_unlocked(&mut client)?;
    let mut backups = DaemonBackups::new(client, claims());
    let (mut file, mut state) = StateFile::open(&ctx.data_dir).map_err(|r| state_failure(&r))?;
    let report = {
        let mut w = Writer {
            state: &mut state,
            journal: &mut file,
            backups: &mut backups,
            now: SystemTime::now(),
        };
        install::apply(&ctx, &plan, &mut w)
    };
    // The report is printed whatever the last save says: a file changed
    // above is reported as changed (L-08).
    let saved = file.save(&state);
    print_report(&home, &report, a.json, true, saved.is_ok());
    saved.map_err(|r| state_failure(&r))?;
    if report.complete() {
        Ok(ExitCode::SUCCESS)
    } else {
        Err(incomplete())
    }
}

fn run_uninstall(mut a: Args) -> Result<ExitCode, Failure> {
    if a.project {
        a.opts.project = Some(project_dir()?);
    }
    let ctx = context()?;
    let home = ctx.locations.home().to_path_buf();
    if !a.yes {
        let (_file, state) = StateFile::open(&ctx.data_dir).map_err(|r| state_failure(&r))?;
        let hosts: Vec<Host> = if a.opts.hosts.is_empty() {
            install::TIER_1.to_vec()
        } else {
            a.opts.hosts.clone()
        };
        let global = a.opts.global || a.opts.project.is_none();
        let project = a
            .opts
            .project
            .as_ref()
            .map(|d| d.to_string_lossy().into_owned());
        let mut listed: Vec<Value> = state
            .files
            .iter()
            .filter(|(_, r)| {
                global && r.scope == "global" && hosts.iter().any(|h| h.id() == r.host)
            })
            .map(|(p, r)| json!({"path": shown(&home, Path::new(p)), "host": r.host}))
            .collect();
        // A project's file is taken out once no host its block was
        // installed for is left; one another still reads is kept.
        if let Some(scope) = project.as_deref() {
            for (p, left) in install::project_shares(&state, scope, &hosts) {
                listed.push(json!({
                    "path": shown(&home, Path::new(&p)),
                    "host": "project",
                    "kept_for": left,
                }));
            }
        }
        // Every file EnvCloak registered its MCP server in, wherever
        // `CLAUDE_CONFIG_DIR` points now.
        let servers: Vec<String> = if global && hosts.contains(&Host::ClaudeCode) {
            install::claude_registrations(&state)
                .iter()
                .map(|k| shown(&home, Path::new(k)))
                .collect()
        } else {
            Vec::new()
        };
        let mcp = !servers.is_empty();
        if a.json {
            print_json(&json!({
                "files": listed,
                "mcp_server": mcp,
                "mcp_servers": servers,
                "applied": false,
            }));
        } else {
            for f in &listed {
                let path = f["path"].as_str().unwrap_or_default();
                let kept: Vec<Host> = f["kept_for"]
                    .as_array()
                    .map(|a| {
                        install::TIER_1
                            .into_iter()
                            .filter(|h| a.iter().any(|v| v.as_str() == Some(h.id())))
                            .collect()
                    })
                    .unwrap_or_default();
                if kept.is_empty() {
                    println!("  {path}: take out what EnvCloak added");
                } else {
                    let names: Vec<&str> = kept.into_iter().map(host_name).collect();
                    println!(
                        "  {path}: keep EnvCloak's block, which it was installed for {} to read \
                         too",
                        names.join(" and ")
                    );
                }
            }
            for p in &servers {
                println!(
                    "  {p}: remove Claude Code's MCP server envcloak with `claude mcp remove`"
                );
            }
            if listed.is_empty() && !mcp {
                println!("Nothing of EnvCloak's is installed here.");
            }
            println!("Nothing was changed: run this again with --yes to take it out.");
        }
        return Ok(ExitCode::SUCCESS);
    }
    let mut client = envcloak_client::connect::connect()?;
    require_unlocked(&mut client)?;
    let mut backups = DaemonBackups::new(client, claims());
    let (mut file, mut state) = StateFile::open(&ctx.data_dir).map_err(|r| state_failure(&r))?;
    let report = {
        let mut w = Writer {
            state: &mut state,
            journal: &mut file,
            backups: &mut backups,
            now: SystemTime::now(),
        };
        install::uninstall(&a.opts, &mut w)
    };
    // The report is printed whatever the last save says: a file changed
    // above is reported as changed (L-08).
    let saved = file.save(&state);
    print_report(&home, &report, a.json, false, saved.is_ok());
    saved.map_err(|r| state_failure(&r))?;
    if report.complete() {
        Ok(ExitCode::SUCCESS)
    } else {
        Err(incomplete())
    }
}
