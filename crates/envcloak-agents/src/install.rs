//! `envcloak agents install` and `uninstall` (SPEC §7, §7.2; M2 plan
//! M2-08): what to write for each detected host and scope ([`plan`]),
//! writing it ([`apply`]) and taking it out again ([`uninstall`]).
//!
//! A plan names every file and every change before anything is written;
//! `--yes` applies it. The global scope teaches each detected tier-1 host
//! (Claude Code, Codex: [`crate::hosts`]); the project scope (`--project`,
//! and `envcloak init --agents-note`, SPEC §6.4 step 4) writes the
//! instruction block into the project's own instruction file, following
//! Map C §6: into `CLAUDE.md` and `AGENTS.md` where they exist, else into a
//! new `AGENTS.md` (which Codex reads, and Claude Code reads when there is
//! no `CLAUDE.md`), never creating a `CLAUDE.md` or `CLAUDE.local.md`
//! beside a lone `AGENTS.md`.
//!
//! Uninstall takes out exactly what install added, by EnvCloak's state
//! ([`crate::writer::State`]): a file still as EnvCloak left it gets its
//! bytes back; one changed since loses only EnvCloak's block, entries and
//! keys; a file EnvCloak created and nothing else is in is removed. The
//! MCP server is removed through Claude Code's own command while it is the
//! entry EnvCloak registered.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use envcloak_scan::{ScanErrorKind, open_root, read_plain};
use serde_json::Value;

use crate::blocks;
use crate::detect::{self, DetectError, Detected};
use crate::hook::Host;
use crate::hosts::{claude, codex};
use crate::jsonedit::Doc;
use crate::locations::Locations;
use crate::writer::{Edit, Edited, Outcome, Refusal, Target, Undo, Writer, sha256_hex};

/// What the installer needs to know of the machine.
pub struct Context<'a> {
    pub locations: Locations,
    /// The `envcloak` the hooks and the MCP entries run: absolute.
    pub envcloak: PathBuf,
    /// EnvCloak's data directory.
    pub data_dir: PathBuf,
    /// The daemon's socket, as the daemon names it.
    pub socket: PathBuf,
    /// The person's `PATH`, where the hosts are looked for.
    pub path: OsString,
    /// The person's environment.
    pub env: &'a dyn Fn(&str) -> Option<OsString>,
}

impl std::fmt::Debug for Context<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context")
            .field("envcloak", &self.envcloak)
            .finish_non_exhaustive()
    }
}

/// What to install, and where.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// The hosts named with `--agent`; none: every tier-1 host found.
    pub hosts: Vec<Host>,
    /// The global scope (the default).
    pub global: bool,
    /// The project scope, with the project's directory.
    pub project: Option<PathBuf>,
    /// `--consent-sandbox-sockets`: on macOS, Codex's bounded socket
    /// allowance, which turns on command networking limited to EnvCloak's
    /// socket.
    pub consent_sockets: bool,
}

/// A remark a report carries beside its changes: a value-free name and
/// its text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    pub name: &'static str,
    pub text: String,
}

fn note(name: &'static str, text: impl Into<String>) -> Note {
    Note {
        name,
        text: text.into(),
    }
}

/// One change to make.
#[derive(Debug, Clone)]
pub struct Step {
    /// What it does, for a person.
    pub what: String,
    pub path: PathBuf,
    pub kind: StepKind,
}

#[derive(Debug, Clone)]
pub enum StepKind {
    /// EnvCloak's instruction block in a Markdown file.
    Block,
    /// Elements added to arrays of a JSON settings file.
    Json {
        host_owned: bool,
        additions: Vec<(Vec<String>, Value)>,
    },
    /// Settings in a TOML file.
    Toml {
        host_owned: bool,
        settings: Vec<codex::Setting>,
    },
    /// A file that is EnvCloak's whole.
    OwnFile { content: String },
    /// EnvCloak's MCP server, registered with `claude mcp add-json`.
    ClaudeMcp { exe: PathBuf, entry: Value },
}

/// What to do for one host.
#[derive(Debug, Clone)]
pub struct HostPlan {
    pub host: Host,
    /// Named with `--agent` (so its absence is a failure).
    pub requested: bool,
    pub found: Result<Detected, DetectError>,
    pub steps: Vec<Step>,
    pub notes: Vec<Note>,
}

/// What to do for a project.
#[derive(Debug, Clone)]
pub struct ProjectPlan {
    pub dir: PathBuf,
    pub steps: Vec<Step>,
    pub notes: Vec<Note>,
}

/// Everything an install would do.
#[derive(Debug, Clone)]
pub struct Plan {
    pub hosts: Vec<HostPlan>,
    pub project: Option<ProjectPlan>,
}

/// The display name of a host.
pub fn host_name(host: Host) -> &'static str {
    match host {
        Host::ClaudeCode => "Claude Code",
        Host::Codex => "Codex",
    }
}

/// The tier-1 hosts, in report order.
pub const TIER_1: [Host; 2] = [Host::ClaudeCode, Host::Codex];

/// The socket's path with its directories' symlinks resolved, as Claude
/// Code's sandbox compares it (M2-04: `/tmp/...` is not allowed by a rule
/// naming `/private/tmp/...`, and the other way round). A part that does
/// not exist yet is kept as written.
pub fn resolved(p: &Path) -> PathBuf {
    let mut existing = p.to_path_buf();
    let mut rest = Vec::new();
    while !existing.exists() {
        match (existing.parent(), existing.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name.to_owned());
                existing = parent.to_path_buf();
            }
            _ => return p.to_path_buf(),
        }
    }
    let mut out = std::fs::canonicalize(&existing).unwrap_or(existing);
    for name in rest.iter().rev() {
        out.push(name);
    }
    out
}

fn strings(p: &[&str]) -> Vec<String> {
    p.iter().map(|s| (*s).to_owned()).collect()
}

/// Reads a small JSON file for a decision, if it is there and is JSON.
fn read_json(path: &Path) -> Option<Value> {
    let root = open_root(path.parent()?).ok()?;
    let (bytes, _) =
        read_plain(&root, Path::new(path.file_name()?), crate::writer::MAX_FILE).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// What an install with `opts` would do.
pub fn plan(ctx: &Context<'_>, opts: &Options) -> Plan {
    let requested = !opts.hosts.is_empty();
    let hosts: Vec<Host> = if requested {
        opts.hosts.clone()
    } else {
        TIER_1.to_vec()
    };
    let global = opts.global || opts.project.is_none();
    let mut out = Plan {
        hosts: Vec::new(),
        project: opts.project.as_ref().map(|d| project_plan(d)),
    };
    if !global {
        return out;
    }
    for host in hosts {
        let found = detect::detect(host, &ctx.path, ctx.env);
        let mut hp = HostPlan {
            host,
            requested,
            found: found.clone(),
            steps: Vec::new(),
            notes: Vec::new(),
        };
        if let Ok(d) = &found {
            match host {
                Host::ClaudeCode => claude_plan(ctx, d, &mut hp),
                Host::Codex => codex_plan(ctx, opts, &mut hp),
            }
        }
        out.hosts.push(hp);
    }
    out
}

fn claude_plan(ctx: &Context<'_>, d: &Detected, hp: &mut HostPlan) {
    let l = &ctx.locations;
    hp.steps.push(Step {
        what: "add EnvCloak's instruction block".to_owned(),
        path: l.claude_instructions(),
        kind: StepKind::Block,
    });
    let settings = l.claude_settings();
    if read_json(&settings).is_some_and(|v| claude::plugin_enabled(&v)) {
        hp.notes.push(note(
            "plugin_enabled",
            "the EnvCloak plugin is enabled in Claude Code: its hooks and MCP server are already \
             there, so only the instruction block is written (installing them again would run \
             each hook twice)",
        ));
        return;
    }
    let macos = cfg!(target_os = "macos");
    let socket = macos.then(|| resolved(&ctx.socket));
    let additions = claude::settings_additions(&ctx.envcloak, socket.as_deref(), &ctx.data_dir)
        .into_iter()
        .map(|(p, v)| (strings(&p), v))
        .collect();
    hp.steps.push(Step {
        what: format!(
            "add hooks (UserPromptSubmit; PreToolUse for {} and {}; SessionStart), the deny rule \
             {}, sandbox deny entries for EnvCloak's vault and backups{}",
            claude::TOOL_MATCHER,
            claude::MCP_MATCHER,
            claude::READ_DENY,
            if macos {
                ", and EnvCloak's socket to the sandbox's allowed Unix sockets"
            } else {
                ""
            }
        ),
        path: settings,
        kind: StepKind::Json {
            host_owned: true,
            additions,
        },
    });
    hp.steps.push(Step {
        what: "register EnvCloak's MCP server with `claude mcp add-json --scope user` (per-server \
               timeout 60 s; no approval setting for any EnvCloak tool)"
            .to_owned(),
        path: l.claude_json().to_path_buf(),
        kind: StepKind::ClaudeMcp {
            exe: d.exe.clone(),
            entry: claude::mcp_entry(&ctx.envcloak),
        },
    });
    if !macos {
        hp.notes.push(note(
            "sandbox_blocks_socket",
            "Claude Code's sandboxed Bash cannot reach EnvCloak on Linux in this build, so no \
             socket allowance is written: commands that need keys run through EnvCloak's MCP \
             server or outside the sandbox",
        ));
    }
    hp.notes.push(note(
        "outside_host_sandbox",
        "commands EnvCloak's run_with_secrets tool starts run outside Claude Code's sandbox; \
         Claude Code asks before each call, and the installer pre-approves none",
    ));
}

fn codex_plan(ctx: &Context<'_>, opts: &Options, hp: &mut HostPlan) {
    let l = &ctx.locations;
    if l.codex_instructions_override().exists() {
        hp.notes.push(note(
            "override_file",
            "~/.codex/AGENTS.override.md exists and Codex reads it instead of AGENTS.md, so the \
             instruction block was not written: add it to the override yourself, or remove the \
             override and run this again",
        ));
    } else {
        hp.steps.push(Step {
            what: "add EnvCloak's instruction block".to_owned(),
            path: l.codex_instructions(),
            kind: StepKind::Block,
        });
    }
    hp.steps.push(Step {
        what: "add hooks (UserPromptSubmit; PreToolUse for Bash and mcp__.*; SessionStart)"
            .to_owned(),
        path: l.codex_hooks(),
        kind: StepKind::Json {
            host_owned: false,
            additions: codex::hooks_additions(&ctx.envcloak)
                .into_iter()
                .map(|(p, v)| (strings(&p), v))
                .collect(),
        },
    });
    hp.steps.push(Step {
        what: "write forbidden prefix rules for commands that print secrets".to_owned(),
        path: l.codex_rules(),
        kind: StepKind::OwnFile {
            content: codex::RULES.to_owned(),
        },
    });
    let linux = !cfg!(target_os = "macos");
    let socket = (!linux && opts.consent_sockets).then_some(ctx.socket.as_path());
    hp.steps.push(Step {
        what: format!(
            "add [mcp_servers.envcloak] (tool_timeout_sec 60; no approval setting){}",
            if socket.is_some() {
                ", and, with your consent, command networking limited to EnvCloak's socket \
                 (network_access, the network proxy with no domain and one unix_sockets rule)"
            } else {
                ""
            }
        ),
        path: l.codex_config(),
        kind: StepKind::Toml {
            host_owned: true,
            settings: codex::config_settings(&ctx.envcloak, linux, socket),
        },
    });
    hp.notes.push(note(
        "hooks_untrusted",
        "Codex runs these hooks only once you trust them: open /hooks in Codex and trust \
         EnvCloak's",
    ));
    if linux {
        hp.notes.push(note(
            "sandbox_blocks_socket",
            "Codex's sandboxed shell cannot reach EnvCloak on Linux in this build, so no socket \
             allowance or network setting is written, with or without consent",
        ));
    } else if !opts.consent_sockets {
        hp.notes.push(note(
            "consent_needed",
            "Codex's sandboxed shell reaches EnvCloak only with a socket allowance, which turns \
             on command networking limited to EnvCloak's socket: run again with \
             --consent-sandbox-sockets to write it",
        ));
    }
    hp.notes.push(note(
        "shell_environment_policy",
        "Codex passes its own environment to the commands it runs, names holding KEY, SECRET or \
         TOKEN included, unless shell_environment_policy in config.toml says otherwise; \
         EnvCloak gives a project's keys only to `envcloak run`",
    ));
    hp.notes.push(note(
        "needs_host_approval",
        "Codex asks before each call of EnvCloak's run_with_secrets tool (it runs commands \
         outside Codex's sandbox), and under `codex exec` with approval policy never refuses it; \
         the installer pre-approves no EnvCloak tool",
    ));
}

/// The project scope's steps (Map C §6).
pub fn project_plan(dir: &Path) -> ProjectPlan {
    let claude_md = dir.join("CLAUDE.md");
    let agents_md = dir.join("AGENTS.md");
    let mut steps = Vec::new();
    let present = |p: &Path| std::fs::symlink_metadata(p).is_ok();
    if present(&claude_md) {
        steps.push(Step {
            what: "add EnvCloak's instruction block".to_owned(),
            path: claude_md.clone(),
            kind: StepKind::Block,
        });
    }
    if present(&agents_md) || !present(&claude_md) {
        steps.push(Step {
            what: "add EnvCloak's instruction block".to_owned(),
            path: agents_md,
            kind: StepKind::Block,
        });
    }
    ProjectPlan {
        dir: dir.to_path_buf(),
        steps,
        notes: Vec::new(),
    }
}

/// The result of one step.
#[derive(Debug, Clone)]
pub struct StepResult {
    pub what: String,
    pub path: PathBuf,
    pub outcome: Outcome,
}

/// What happened for one host.
#[derive(Debug, Clone)]
pub struct HostReport {
    pub host: Host,
    pub requested: bool,
    pub found: Result<Detected, DetectError>,
    pub results: Vec<StepResult>,
    pub notes: Vec<Note>,
}

/// What happened for a project.
#[derive(Debug, Clone)]
pub struct ProjectReport {
    pub dir: PathBuf,
    pub results: Vec<StepResult>,
}

/// What an install or uninstall did.
#[derive(Debug, Clone)]
pub struct Report {
    pub hosts: Vec<HostReport>,
    pub project: Option<ProjectReport>,
}

impl Report {
    /// Every change was made (or was there already), and every host named
    /// with `--agent` was found.
    pub fn complete(&self) -> bool {
        let ok = |r: &StepResult| !matches!(r.outcome, Outcome::Refused(_));
        self.hosts
            .iter()
            .all(|h| h.results.iter().all(ok) && (h.found.is_ok() || !h.requested))
            && self
                .project
                .as_ref()
                .is_none_or(|p| p.results.iter().all(ok))
    }
}

fn target(
    path: &Path,
    host: &'static str,
    scope: String,
    host_owned: bool,
    name: &'static str,
) -> Target {
    Target {
        path: path.to_path_buf(),
        host,
        scope,
        host_owned,
        host_name: name,
    }
}

/// The edit of one step, given the file's contents.
fn edit_for<'a>(
    kind: &'a StepKind,
    owned: &'a [Edit],
    known: bool,
) -> impl FnMut(Option<&[u8]>) -> Result<Edited, Refusal> + 'a {
    move |before: Option<&[u8]>| match kind {
        StepKind::Block => match blocks::insert(before.unwrap_or_default()) {
            Ok(blocks::Change::Unchanged) => Ok(None),
            Ok(blocks::Change::New(t)) => Ok(Some((t.into_bytes(), vec![Edit::Block]))),
            Err(e) => Err(Refusal::new(e.name(), e.message())),
        },
        StepKind::Json { additions, .. } => {
            let mut doc = match before {
                Some(b) => Doc::parse(b).map_err(|e| Refusal::new(e.name(), e.message()))?,
                None => Doc::empty(),
            };
            let mut edits = Vec::new();
            for (path, value) in additions {
                let p: Vec<&str> = path.iter().map(String::as_str).collect();
                if let Some(created) = doc
                    .add_to_array(&p, value)
                    .map_err(|e| Refusal::new(e.name(), e.message()))?
                {
                    edits.push(Edit::JsonElement {
                        path: path.clone(),
                        value: value.clone(),
                        created,
                    });
                }
            }
            if edits.is_empty() {
                return Ok(None);
            }
            Ok(Some((doc.text().as_bytes().to_vec(), edits)))
        }
        StepKind::Toml { settings, .. } => codex::apply(before, settings, owned),
        StepKind::OwnFile { content } => match before {
            Some(b) if b == content.as_bytes() => Ok(None),
            Some(_) if !known => Err(Refusal::new(
                "conflict",
                "a file of this name is already there, and EnvCloak did not write it",
            )),
            _ => Ok(Some((content.as_bytes().to_vec(), vec![Edit::WholeFile]))),
        },
        StepKind::ClaudeMcp { .. } => Ok(None),
    }
}

fn run_step(ctx: &Context<'_>, w: &mut Writer<'_>, step: &Step, t: Target) -> StepResult {
    let outcome = match &step.kind {
        StepKind::ClaudeMcp { exe, entry } => register_claude_mcp(ctx, w, exe, entry),
        kind => {
            let rec = w.state.files.get(&crate::writer::key(&step.path));
            let owned = rec.map(|r| r.edits.clone()).unwrap_or_default();
            let known = rec.is_some();
            let mut edit = edit_for(kind, &owned, known);
            w.change(&t, &mut edit)
        }
    };
    StepResult {
        what: step.what.clone(),
        path: step.path.clone(),
        outcome,
    }
}

/// Writes `plan`.
pub fn apply(ctx: &Context<'_>, plan: &Plan, w: &mut Writer<'_>) -> Report {
    let mut report = Report {
        hosts: Vec::new(),
        project: None,
    };
    for hp in &plan.hosts {
        let mut results = Vec::new();
        for step in &hp.steps {
            let host_owned = matches!(
                step.kind,
                StepKind::Json {
                    host_owned: true,
                    ..
                } | StepKind::Toml {
                    host_owned: true,
                    ..
                }
            );
            let t = target(
                &step.path,
                hp.host.id(),
                "global".to_owned(),
                host_owned,
                host_name(hp.host),
            );
            results.push(run_step(ctx, w, step, t));
        }
        report.hosts.push(HostReport {
            host: hp.host,
            requested: hp.requested,
            found: hp.found.clone(),
            results,
            notes: hp.notes.clone(),
        });
    }
    if let Some(pp) = &plan.project {
        let scope = pp.dir.to_string_lossy().into_owned();
        let results = pp
            .steps
            .iter()
            .map(|step| {
                let t = target(&step.path, "project", scope.clone(), false, "the agent");
                run_step(ctx, w, step, t)
            })
            .collect();
        report.project = Some(ProjectReport {
            dir: pp.dir.clone(),
            results,
        });
    }
    report
}

/// The entry registered, and the file's bytes and permission bits.
type Registered = (Option<Value>, Option<(Vec<u8>, u32)>);

/// The user-scope MCP entries in `~/.claude.json`, read beneath its
/// directory: `None` when there is no file.
fn claude_registered(ctx: &Context<'_>) -> Result<Registered, Refusal> {
    let path = ctx.locations.claude_json();
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return Ok((None, None));
    };
    let Ok(root) = open_root(dir) else {
        return Ok((None, None));
    };
    match read_plain(&root, Path::new(name), 64 * 1024 * 1024) {
        Ok((bytes, stamp)) => Ok((claude::registered(&bytes)?, Some((bytes, stamp.mode)))),
        Err(e) if e.kind == ScanErrorKind::NotFound => Ok((None, None)),
        Err(e) => Err(Refusal::new(e.kind.token(), e.kind.message())),
    }
}

fn register_claude_mcp(
    ctx: &Context<'_>,
    w: &mut Writer<'_>,
    exe: &Path,
    entry: &Value,
) -> Outcome {
    match try_register(ctx, w, exe, entry) {
        Ok(o) => o,
        Err(r) => Outcome::Refused(r),
    }
}

fn cli_failed(what: &str) -> Refusal {
    Refusal::new(
        "host_cli_failed",
        format!("Claude Code's `claude mcp {what}` did not succeed"),
    )
}

fn try_register(
    ctx: &Context<'_>,
    w: &mut Writer<'_>,
    exe: &Path,
    entry: &Value,
) -> Result<Outcome, Refusal> {
    let host = Host::ClaudeCode.id();
    let (current, file) = claude_registered(ctx)?;
    if current.as_ref() == Some(entry) {
        w.state.mcp.insert(host.to_owned(), entry.clone());
        return Ok(Outcome::Unchanged);
    }
    let ours = current.is_some() && w.state.mcp.get(host) == current.as_ref();
    if current.is_some() && !ours {
        return Err(Refusal::new(
            "conflict",
            "an MCP server named `envcloak` is already registered in Claude Code, and EnvCloak \
             did not register it; remove or rename it first",
        ));
    }
    // Claude Code changes its own file; EnvCloak backs it up first.
    let path = ctx.locations.claude_json();
    let backup = match &file {
        Some((bytes, mode)) => Some(w.backups.back_up(path, bytes, *mode)?),
        None => None,
    };
    if current.is_some() {
        let out = claude::run(
            exe,
            &["mcp", "remove", "--scope", "user", claude::SERVER],
            ctx.env,
        )?;
        if !out.status.success() {
            return Err(cli_failed("remove"));
        }
    }
    let json = serde_json::to_string(entry).map_err(|_| cli_failed("add-json"))?;
    let out = claude::run(
        exe,
        &["mcp", "add-json", "--scope", "user", claude::SERVER, &json],
        ctx.env,
    )?;
    if !out.status.success() {
        return Err(cli_failed("add-json"));
    }
    let out = claude::run(exe, &["mcp", "get", claude::SERVER], ctx.env)?;
    let (now, after) = claude_registered(ctx)?;
    if !out.status.success() || now.as_ref() != Some(entry) {
        return Err(Refusal::new(
            "host_cli_failed",
            "after `claude mcp add-json`, `claude mcp get` does not show EnvCloak's server as \
             written",
        ));
    }
    if let (Some(id), Some((bytes, _))) = (&backup, &after) {
        w.backups.record(id, bytes)?;
    }
    w.state.mcp.insert(host.to_owned(), entry.clone());
    Ok(Outcome::Changed {
        created: file.is_none(),
        backup,
    })
}

fn unregister_claude_mcp(ctx: &Context<'_>, w: &mut Writer<'_>) -> Option<StepResult> {
    let host = Host::ClaudeCode.id();
    let recorded = w.state.mcp.get(host).cloned()?;
    let path = ctx.locations.claude_json().to_path_buf();
    let outcome = (|| -> Result<Outcome, Refusal> {
        let (current, file) = claude_registered(ctx)?;
        if current.as_ref() != Some(&recorded) {
            // Gone, or changed since: not EnvCloak's to remove.
            w.state.mcp.remove(host);
            return Ok(Outcome::Unchanged);
        }
        let exe = detect::detect(Host::ClaudeCode, &ctx.path, ctx.env)
            .map_err(|e| Refusal::new(e.name(), e.message()))?
            .exe;
        let backup = match &file {
            Some((bytes, mode)) => Some(w.backups.back_up(&path, bytes, *mode)?),
            None => None,
        };
        let out = claude::run(
            &exe,
            &["mcp", "remove", "--scope", "user", claude::SERVER],
            ctx.env,
        )?;
        let (now, after) = claude_registered(ctx)?;
        if !out.status.success() || now.is_some() {
            return Err(cli_failed("remove"));
        }
        if let (Some(id), Some((bytes, _))) = (&backup, &after) {
            w.backups.record(id, bytes)?;
        }
        w.state.mcp.remove(host);
        Ok(Outcome::Removed { backup })
    })();
    Some(StepResult {
        what: "remove EnvCloak's MCP server with `claude mcp remove --scope user`".to_owned(),
        path,
        outcome: outcome.unwrap_or_else(Outcome::Refused),
    })
}

/// Takes EnvCloak's edits out of a file changed since its last write.
pub fn structural(current: &[u8], edits: &[Edit], created: bool) -> Result<Undo, Refusal> {
    if edits.contains(&Edit::WholeFile) {
        return Ok(Undo::Remove);
    }
    if edits.contains(&Edit::Block) {
        return match blocks::remove(current) {
            Ok(blocks::Change::Unchanged) => Ok(Undo::Nothing),
            Ok(blocks::Change::New(t)) if created && t.trim().is_empty() => Ok(Undo::Remove),
            Ok(blocks::Change::New(t)) => Ok(Undo::Rewrite(t.into_bytes())),
            Err(e) => Err(Refusal::new(e.name(), e.message())),
        };
    }
    if edits.iter().any(|e| matches!(e, Edit::TomlValue { .. })) {
        return codex::undo(current, edits, created);
    }
    let mut doc = Doc::parse(current).map_err(|e| Refusal::new(e.name(), e.message()))?;
    let mut changed = false;
    for e in edits.iter().rev() {
        if let Edit::JsonElement {
            path,
            value,
            created,
        } = e
        {
            let p: Vec<&str> = path.iter().map(String::as_str).collect();
            changed |= doc
                .remove_from_array(&p, value, *created)
                .map_err(|e| Refusal::new(e.name(), e.message()))?;
        }
    }
    if created
        && doc
            .value()
            .as_object()
            .is_some_and(serde_json::Map::is_empty)
    {
        return Ok(Undo::Remove);
    }
    if !changed {
        return Ok(Undo::Nothing);
    }
    Ok(Undo::Rewrite(doc.text().as_bytes().to_vec()))
}

/// Takes out what EnvCloak installed for `opts`'s hosts and scopes.
pub fn uninstall(ctx: &Context<'_>, opts: &Options, w: &mut Writer<'_>) -> Report {
    let hosts: Vec<Host> = if opts.hosts.is_empty() {
        TIER_1.to_vec()
    } else {
        opts.hosts.clone()
    };
    let global = opts.global || opts.project.is_none();
    let mut report = Report {
        hosts: Vec::new(),
        project: None,
    };
    let undo_files = |w: &mut Writer<'_>, host: &'static str, scope: &str, name: &'static str| {
        let paths: Vec<(String, bool)> = w
            .state
            .files
            .iter()
            .filter(|(_, r)| r.host == host && r.scope == scope)
            .map(|(p, r)| {
                (
                    p.clone(),
                    r.edits
                        .iter()
                        .any(|e| matches!(e, Edit::JsonElement { .. } | Edit::TomlValue { .. })),
                )
            })
            .collect();
        paths
            .into_iter()
            .map(|(p, json_or_toml)| {
                let path = PathBuf::from(&p);
                let host_owned = json_or_toml
                    && (path.ends_with("settings.json") || path.ends_with("config.toml"));
                let t = target(&path, host, scope.to_owned(), host_owned, name);
                let outcome = w.undo(&t, &mut structural);
                StepResult {
                    what: "take out what EnvCloak added".to_owned(),
                    path,
                    outcome,
                }
            })
            .collect::<Vec<_>>()
    };
    if global {
        for host in hosts {
            let mut results = undo_files(w, host.id(), "global", host_name(host));
            if host == Host::ClaudeCode {
                results.extend(unregister_claude_mcp(ctx, w));
            }
            report.hosts.push(HostReport {
                host,
                requested: false,
                found: Err(DetectError::NotFound),
                results,
                notes: Vec::new(),
            });
        }
    }
    if let Some(dir) = &opts.project {
        let scope = dir.to_string_lossy().into_owned();
        report.project = Some(ProjectReport {
            dir: dir.clone(),
            results: undo_files(w, "project", &scope, "the agent"),
        });
    }
    report
}

/// The SHA-256 of a file's bytes as the state keeps them, for tests and
/// reports.
pub fn digest(b: &[u8]) -> String {
    sha256_hex(b)
}
