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
//! - `status` makes one check in this build (M2 plan M2-08): EnvCloak's
//!   Claude Code plugin enabled (in the user's settings, or the working
//!   directory's project or local settings) while EnvCloak's own hooks
//!   (in one of those files) or an MCP server named `envcloak` (in
//!   `.claude.json`) are there too, so each hook runs twice: refused,
//!   exit 1 with `double_install`, naming both. Otherwise the coverage
//!   report (M2-09, M2-28) is not in this build: exit 125 with
//!   `not_in_this_build`. It reads no argument.
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

use envcloak_agents::hook::Host;
use envcloak_agents::install::{
    self, Context, HostReport, Note, Options, Plan, Report, Step, StepKind, StepResult, host_name,
};
use envcloak_agents::locations::Locations;
use envcloak_agents::writer::{DaemonBackups, Journal, Outcome, StateFile, Writer};
use envcloak_client::claims::claims;
use envcloak_client::fail::{FAILURE, Failure, refuse_if_traced, usage};
use envcloak_client::render::print_json;
use envcloak_policy::{escape_for_display, find_manifest};
use serde_json::{Value, json};

use super::require_unlocked;

const USAGE_TEXT: &str = "envcloak agents install [--global] [--project] [--agent claude-code|codex]... [--consent-sandbox-sockets] [--yes] [--json]
       envcloak agents uninstall [--global] [--project] [--agent claude-code|codex]... [--yes] [--json]
       envcloak agents status | migrate-mcp (not in this build)";

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
        ["status", ..] => run_status(),
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

/// `agents status` in this build: the double-install check (M2 plan
/// M2-08; Codex review: a direct install followed by the plugin left both
/// hook sets and both servers, and nothing said so), then
/// `not_in_this_build` for the coverage report. No argument is read.
fn run_status() -> ExitCode {
    // The settings it reads can hold literal keys (SPEC §5).
    if let Err(f) = refuse_if_traced() {
        return f.report(FAILURE);
    }
    match double_install() {
        Some(text) => Failure::new("double_install", text).report(FAILURE),
        None => super::not_in_this_build("`envcloak agents status`"),
    }
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
        let listed: Vec<Value> = state
            .files
            .iter()
            .filter(|(_, r)| {
                (global && r.scope == "global" && hosts.iter().any(|h| h.id() == r.host))
                    || project.as_deref() == Some(r.scope.as_str())
            })
            .map(|(p, r)| json!({"path": shown(&home, Path::new(p)), "host": r.host}))
            .collect();
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
                println!(
                    "  {}: take out what EnvCloak added",
                    f["path"].as_str().unwrap_or_default()
                );
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
