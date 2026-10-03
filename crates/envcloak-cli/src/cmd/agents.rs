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
//! - `status` (M2-09, M2-28) and `migrate-mcp` (M2-20) are not in this
//!   build: each exits 125 with `not_in_this_build`, reading no argument.
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
use envcloak_client::fail::{FAILURE, Failure, usage};
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
        ["status", ..] => super::not_in_this_build("`envcloak agents status`"),
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

/// A path as it is shown: the home as `~`, and escaped.
fn shown(home: &Path, p: &Path) -> String {
    let text = match p.strip_prefix(home) {
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => p.display().to_string(),
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
            })
        });
        print_json(&json!({
            "hosts": hosts,
            "project": project,
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
        project: Some(install::project_plan(dir)),
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
    let results = report.project.map(|p| p.results).unwrap_or_default();
    if json {
        print_json(&json!({
            "agents_note": results.iter().map(|r| result_json(&home, r)).collect::<Vec<_>>(),
            "complete": saved.is_ok() && results.iter().all(|r| {
                !matches!(r.outcome, Outcome::Refused(_) | Outcome::Partial { .. })
            }),
        }));
    } else {
        println!("Agent note:");
        print_results(&home, &results);
    }
    saved.map_err(|r| state_failure(&r))?;
    if results
        .iter()
        .any(|r| matches!(r.outcome, Outcome::Refused(_) | Outcome::Partial { .. }))
    {
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
        let mcp = global
            && hosts.contains(&Host::ClaudeCode)
            && (state.mcp.contains_key(Host::ClaudeCode.id())
                || state.mcp_intent.contains_key(Host::ClaudeCode.id()));
        if a.json {
            print_json(&json!({"files": listed, "mcp_server": mcp, "applied": false}));
        } else {
            for f in &listed {
                println!(
                    "  {}: take out what EnvCloak added",
                    f["path"].as_str().unwrap_or_default()
                );
            }
            if mcp {
                println!("  Claude Code's MCP server envcloak: remove it with `claude mcp remove`");
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
        install::uninstall(&ctx, &a.opts, &mut w)
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
